"""
============================================================================
ensemble_predictor.py — Clase de inferencia del Ensemble
============================================================================
Carga los modelos serializados y realiza predicciones sobre DataFrames
de flujos de red en tiempo real.
============================================================================
"""

import json
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from feature_adapter import normalize_protocol
from feature_contract import MODEL_FEATURES, build_common_features, schema_hash
from feature_contract_v4_native import (
    MODEL_FEATURES as V4_MODEL_FEATURES,
    build_native_features,
    schema_hash as v4_schema_hash,
)

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parent / "models"


# ── Arquitectura del Autoencoder (debe coincidir con model_trainer.py) ─────
class DeepAnomalyAE(nn.Module):
    def __init__(self, d):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(d, 32), nn.LeakyReLU(),
            nn.Linear(32, 16), nn.LeakyReLU(),
            nn.Linear(16, 8))
        self.decoder = nn.Sequential(
            nn.Linear(8, 16), nn.LeakyReLU(),
            nn.Linear(16, 32), nn.LeakyReLU(),
            nn.Linear(32, d))

    def forward(self, x):
        return self.decoder(self.encoder(x))


class EnsemblePredictor:
    """
    Predictor de anomalías de red basado en el ensemble no supervisado
    de la tesis (EIF + Autoencoder + LOF).

    Uso básico:
        pred = EnsemblePredictor()
        pred.load_models()
        results = pred.predict(df_flows)
    """

    def __init__(self, models_dir: Path = MODELS_DIR, device: str = "auto"):
        self.models_dir = models_dir
        if device not in {"auto", "cpu", "cuda"}:
            raise ValueError("device debe ser auto, cpu o cuda")
        if device == "cuda" and not torch.cuda.is_available():
            raise RuntimeError("CUDA fue solicitado, pero no está disponible")
        selected_device = "cuda" if device == "auto" and torch.cuda.is_available() else device
        self.device     = torch.device("cpu" if selected_device == "auto" else selected_device)
        self.loaded     = False

        # Componentes del ensemble
        self.scaler    = None
        self.encoders  = None
        self.pca       = None
        self.eif       = None
        self.lof       = None
        self.ae        = None
        self.meta      = None
        self.score_reference = None

    # ── Carga de modelos ───────────────────────────────────────────────────
    def load_models(self) -> None:
        logger.info(f"Cargando modelos desde {self.models_dir}")

        self.scaler   = joblib.load(self.models_dir / "scaler.pkl")
        self.encoders = joblib.load(self.models_dir / "encoders.pkl")
        self.pca      = joblib.load(self.models_dir / "pca.pkl")
        self.eif      = joblib.load(self.models_dir / "eif_model.pkl")
        self.lof      = joblib.load(self.models_dir / "lof_model.pkl")
        self.meta     = json.loads((self.models_dir / "meta.json").read_text())

        if self.meta.get("schema_version") not in (2, 3, 4):
            raise RuntimeError(
                "El modelo usa un esquema anterior sin calibración fija. "
                "Reentrena con training/train_model_v2.py."
            )
        if self.meta.get("schema_version") == 3:
            if self.meta.get("feature_schema_hash") != schema_hash():
                raise RuntimeError(
                    "El contrato de caracteristicas del sensor no coincide "
                    "con el utilizado para entrenar el modelo v3-common."
                )
            if self.meta.get("feature_names") != MODEL_FEATURES:
                raise RuntimeError(
                    "El orden de caracteristicas del modelo v3-common es incompatible."
                )
        if self.meta.get("schema_version") == 4:
            if self.meta.get("feature_schema_hash") != v4_schema_hash():
                raise RuntimeError(
                    "El contrato temporal nativo no coincide con el del modelo v4."
                )
            if self.meta.get("feature_names") != V4_MODEL_FEATURES:
                raise RuntimeError(
                    "El orden de caracteristicas del modelo v4-native es incompatible."
                )
        reference_path = self.models_dir / self.meta["score_reference_file"]
        with np.load(reference_path) as reference_data:
            self.score_reference = {
                "if": np.sort(reference_data["score_if"].astype(float)),
                "ae": np.sort(reference_data["score_ae"].astype(float)),
                "lof": np.sort(reference_data["score_lof"].astype(float)),
            }

        # Autoencoder
        ae_data    = torch.load(self.models_dir / "autoencoder.pt",
                                map_location=self.device)
        self.ae    = DeepAnomalyAE(ae_data["input_dim"]).to(self.device)
        self.ae.load_state_dict(ae_data["model_state"])
        self.ae.eval()

        self.loaded = True
        test_auc = self.meta.get("test_metrics", {}).get("auc_roc")
        auc_text = f" | AUC test: {test_auc:.4f}" if test_auc is not None else ""
        logger.info(
            f"✅ Modelo {self.meta.get('model_version', 'sin-versión')} cargado"
            f" | umbral: {self.meta['threshold']:.6f}{auc_text}"
        )

    # ── Feature engineering (replicar pipeline del notebook) ──────────────
    def _feature_engineering(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        # Features derivadas
        df["bytes_ratio"]        = df.get("sbytes", 0) / (df.get("dbytes", 0) + 1)
        df["packet_ratio"]       = df.get("spkts", 0)  / (df.get("dpkts", 0) + 1)
        df["duration_intensity"] = df.get("ct_srv_dst", 0) / (df.get("dur", 0) + 0.001)
        df["load_ratio"]         = df.get("sload", 0) / (df.get("dload", 0) + 1)
        df["sbytes_per_pkt"]     = df.get("sbytes", 0) / (df.get("spkts", 0) + 1)
        df["dbytes_per_pkt"]     = df.get("dbytes", 0) / (df.get("dpkts", 0) + 1)
        return df

    def _encode_categoricals(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        semantic_fallbacks = {"proto": "any", "service": "-", "state": "no"}
        unknown_token = self.meta.get("unknown_category_token", "__unknown__")
        for col, le in self.encoders.items():
            if col in df.columns:
                if col == "proto":
                    df[col] = df[col].map(normalize_protocol)
                known = set(le.classes_)
                fallback = semantic_fallbacks.get(col, le.classes_[0])
                if fallback not in known:
                    fallback = unknown_token if unknown_token in known else le.classes_[0]
                df[col] = df[col].astype(str).apply(
                    lambda x: x if x in known else fallback)
                df[col] = le.transform(df[col])
            else:
                fallback = semantic_fallbacks.get(col, le.classes_[0])
                if fallback not in le.classes_:
                    fallback = unknown_token if unknown_token in le.classes_ else le.classes_[0]
                df[col] = le.transform([fallback])[0]
        return df

    def _preprocess(self, df: pd.DataFrame) -> tuple:
        """
        Preprocesa un DataFrame de flujos raw y devuelve
        (X_scaled, X_pca, df_enc) listos para inferencia.
        """
        if self.meta.get("schema_version") == 3:
            # En v3 no se permite completar columnas silenciosamente. El
            # contrato compartido calcula las derivadas tanto en train como
            # en produccion.
            X = build_common_features(df, strict=True)
        elif self.meta.get("schema_version") == 4:
            X = build_native_features(df, strict=True)
        else:
            drop_cols = [c for c in ["id", "label", "attack_cat", "src_ip",
                                      "dst_ip", "timestamp"] if c in df.columns]
            X = df.drop(columns=drop_cols, errors="ignore").copy()
            X = self._feature_engineering(X)
        X = self._encode_categoricals(X)

        # Alinear con las features esperadas por el scaler
        expected = self.meta["feature_names"]
        if self.meta.get("schema_version") != 3:
            for col in expected:
                if col not in X.columns:
                    X[col] = 0
        X = X[expected]

        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(0, inplace=True)

        X_scaled = self.scaler.transform(X)
        X_pca    = self.pca.transform(X_scaled)

        return X_scaled, X_pca, X

    @staticmethod
    def _reference_percentile(scores: np.ndarray,
                              reference: np.ndarray) -> np.ndarray:
        """Mapea scores crudos contra una ECDF fija aprendida en validación."""
        if reference.ndim != 1 or reference.size == 0:
            raise RuntimeError("Distribución de referencia inválida")
        return np.searchsorted(reference, scores, side="right") / reference.size

    def _raw_scores(self, X_scaled: np.ndarray,
                    X_pca: np.ndarray) -> dict[str, np.ndarray]:
        scores_if = np.asarray(self.eif.predict(X_scaled), dtype=float)
        with torch.no_grad():
            tensor = torch.as_tensor(X_pca, dtype=torch.float32, device=self.device)
            reconstruction = self.ae(tensor)
            scores_ae = torch.mean(
                (tensor - reconstruction) ** 2, dim=1
            ).cpu().numpy()
        scores_lof = np.asarray(-self.lof.decision_function(X_pca), dtype=float)
        return {"if": scores_if, "ae": scores_ae, "lof": scores_lof}

    # ── Inferencia ─────────────────────────────────────────────────────────
    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Analiza un DataFrame de flujos de red.

        Returns:
            DataFrame con columnas adicionales:
              score_if, score_ae, score_lof,
              ensemble_score, is_anomaly
        """
        if not self.loaded:
            raise RuntimeError("Llama a load_models() primero")
        if df.empty:
            return df.copy()

        X_scaled, X_pca, _ = self._preprocess(df)
        raw = self._raw_scores(X_scaled, X_pca)
        percentiles = {
            name: self._reference_percentile(raw[name], self.score_reference[name])
            for name in ("if", "ae", "lof")
        }

        w = self.meta["weights"]
        scores_ens = (
            w["w_if"] * percentiles["if"]
            + w["w_ae"] * percentiles["ae"]
            + w["w_lof"] * percentiles["lof"]
        )

        threshold  = self.meta["threshold"]
        is_anomaly = (scores_ens >= threshold).astype(int)

        result = df.copy()
        result["score_if"]       = raw["if"]
        result["score_ae"]       = raw["ae"]
        result["score_lof"]      = raw["lof"]
        result["percentile_if"]  = percentiles["if"]
        result["percentile_ae"]  = percentiles["ae"]
        result["percentile_lof"] = percentiles["lof"]
        result["ensemble_score"] = scores_ens
        result["is_anomaly"]     = is_anomaly

        return result

    # ── Formato de alerta JSON para Wazuh ──────────────────────────────────
    def format_alert(self, flow: dict, score: float,
                     evasion_attempt: bool = False) -> dict:
        """
        Genera un dict JSON compatible con el decoder de Wazuh.
        Se escribe como línea a /var/log/ensemble/alerts.json
        """
        threshold = float(self.meta["threshold"])
        score_range = max(1.0 - threshold, np.finfo(float).eps)
        relative_excess = (float(score) - threshold) / score_range
        if relative_excess >= 0.80:
            severity = "critical"
        elif relative_excess >= 0.40:
            severity = "high"
        else:
            severity = "suspicious"

        return {
            "source":          "ensemble",
            "model_version":   self.meta.get("model_version", "unknown"),
            "run_id":          str(flow.get("run_id", "unassigned")),
            "timestamp":       pd.Timestamp.now(tz="UTC").isoformat(),
            "score":           round(float(score), 4),
            "threshold":       round(threshold, 4),
            "severity":        severity,
            "src_ip":          str(flow.get("src_ip", "unknown")),
            "dst_ip":          str(flow.get("dst_ip", "unknown")),
            "src_port":        int(flow.get("sport", 0)),
            "dst_port":        int(flow.get("dport", 0)),
            "protocol":        str(flow.get("proto", "unknown")),
            "duration_ms":     float(flow.get("dur", 0)) * 1000,
            "bytes_in":        int(flow.get("sbytes", 0)),
            "bytes_out":       int(flow.get("dbytes", 0)),
            "evasion_attempt": evasion_attempt,
        }
