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
from scipy.stats import rankdata

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

    def __init__(self, models_dir: Path = MODELS_DIR):
        self.models_dir = models_dir
        self.device     = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.loaded     = False

        # Componentes del ensemble
        self.scaler    = None
        self.encoders  = None
        self.pca       = None
        self.eif       = None
        self.lof       = None
        self.ae        = None
        self.meta      = None

    # ── Carga de modelos ───────────────────────────────────────────────────
    def load_models(self) -> None:
        logger.info(f"Cargando modelos desde {self.models_dir}")

        self.scaler   = joblib.load(self.models_dir / "scaler.pkl")
        self.encoders = joblib.load(self.models_dir / "encoders.pkl")
        self.pca      = joblib.load(self.models_dir / "pca.pkl")
        self.eif      = joblib.load(self.models_dir / "eif_model.pkl")
        self.lof      = joblib.load(self.models_dir / "lof_model.pkl")
        self.meta     = json.loads((self.models_dir / "meta.json").read_text())

        # Autoencoder
        ae_data    = torch.load(self.models_dir / "autoencoder.pt",
                                map_location=self.device)
        self.ae    = DeepAnomalyAE(ae_data["input_dim"]).to(self.device)
        self.ae.load_state_dict(ae_data["model_state"])
        self.ae.eval()

        self.loaded = True
        logger.info(f"✅ Modelos cargados | AUC entrenamiento: {self.meta['auc_ensemble']:.4f}")

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
        for col, le in self.encoders.items():
            if col in df.columns:
                known = set(le.classes_)
                df[col] = df[col].astype(str).apply(
                    lambda x: x if x in known else le.classes_[0])
                df[col] = le.transform(df[col])
            else:
                df[col] = 0
        return df

    def _preprocess(self, df: pd.DataFrame) -> tuple:
        """
        Preprocesa un DataFrame de flujos raw y devuelve
        (X_scaled, X_pca, df_enc) listos para inferencia.
        """
        # Quitar columnas de meta que no son features
        drop_cols = [c for c in ["id", "label", "attack_cat", "src_ip",
                                  "dst_ip", "timestamp"] if c in df.columns]
        X = df.drop(columns=drop_cols, errors="ignore").copy()

        X = self._feature_engineering(X)
        X = self._encode_categoricals(X)

        # Alinear con las features esperadas por el scaler
        expected = self.meta["feature_names"]
        for col in expected:
            if col not in X.columns:
                X[col] = 0
        X = X[expected]

        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(0, inplace=True)

        X_scaled = self.scaler.transform(X)
        X_pca    = self.pca.transform(X_scaled)

        return X_scaled, X_pca, X

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
        n = len(X_scaled)

        # ── EIF ────────────────────────────────────────────────────────────
        scores_if = self.eif.predict(X_scaled)

        # ── Autoencoder ────────────────────────────────────────────────────
        with torch.no_grad():
            t_    = torch.FloatTensor(X_pca).to(self.device)
            recon = self.ae(t_)
            scores_ae = torch.mean((t_ - recon)**2, dim=1).cpu().numpy()

        # ── LOF ────────────────────────────────────────────────────────────
        scores_lof = -self.lof.decision_function(X_pca)

        # ── Score Ranking + Ensemble Ponderado ─────────────────────────────
        rank_if  = rankdata(scores_if)  / n
        rank_ae  = rankdata(scores_ae)  / n
        rank_lof = rankdata(scores_lof) / n

        w = self.meta["weights"]
        scores_ens = (w["w_if"]*rank_if + w["w_ae"]*rank_ae + w["w_lof"]*rank_lof)

        threshold  = self.meta["threshold"]
        is_anomaly = (scores_ens >= threshold).astype(int)

        result = df.copy()
        result["score_if"]       = scores_if
        result["score_ae"]       = scores_ae
        result["score_lof"]      = scores_lof
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
        return {
            "source":          "ensemble",
            "timestamp":       pd.Timestamp.now().isoformat(),
            "score":           round(float(score), 4),
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
