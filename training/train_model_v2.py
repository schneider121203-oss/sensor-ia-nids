"""Entrenamiento reproducible del ensemble no supervisado, esquema v2.

Principios metodológicos:
- el dataset oficial de test no participa en ninguna decisión;
- encoders, scaler y modelos se ajustan únicamente con train;
- hiperparámetros y pesos se eligen únicamente con validation;
- los scores se convierten a percentiles contra referencias benignas fijas;
- el umbral se calibra para un FPR objetivo sobre validation benigno.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from copy import deepcopy
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from isotree import IsolationForest as EIF
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import LabelEncoder, StandardScaler
from torch.utils.data import DataLoader, TensorDataset


SCRIPT_DIR = Path(__file__).resolve().parent
PACKAGE_DIR = SCRIPT_DIR.parent
SENSOR_DIR = PACKAGE_DIR / "sensor"
sys.path.insert(0, str(SENSOR_DIR))

from feature_adapter import normalize_protocol


RANDOM_STATE = 42
SCHEMA_VERSION = 2
MODEL_VERSION = "unsw-nb15-ensemble-v2-fixed-ecdf"
FEATURE_SCHEMA_NAME = None
FEATURE_SCHEMA_HASH = None
FEATURE_DEFINITIONS = None
CATEGORICAL_COLUMNS = ["proto", "service", "state"]
DROP_COLUMNS = ["id", "label", "attack_cat"]
SEMANTIC_FALLBACKS = {"proto": "any", "service": "-", "state": "no"}
UNKNOWN_CATEGORY = "__unknown__"


def software_versions() -> dict[str, str]:
    packages = ("numpy", "pandas", "scikit-learn", "torch", "isotree", "nfstream")
    result = {"python": sys.version.split()[0]}
    for package in packages:
        try:
            result[package] = version(package)
        except PackageNotFoundError:
            result[package] = "not-installed"
    return result


class DeepAnomalyAE(nn.Module):
    def __init__(self, dimension: int):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(dimension, 32),
            nn.LeakyReLU(),
            nn.Linear(32, 16),
            nn.LeakyReLU(),
            nn.Linear(16, 8),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.LeakyReLU(),
            nn.Linear(16, 32),
            nn.LeakyReLU(),
            nn.Linear(32, dimension),
        )

    def forward(self, values):
        return self.decoder(self.encoder(values))


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


def add_derived_features(frame: pd.DataFrame) -> pd.DataFrame:
    result = frame.copy()
    result["bytes_ratio"] = result["sbytes"] / (result["dbytes"] + 1)
    result["packet_ratio"] = result["spkts"] / (result["dpkts"] + 1)
    result["duration_intensity"] = result["ct_srv_dst"] / (result["dur"] + 0.001)
    result["load_ratio"] = result["sload"] / (result["dload"] + 1)
    result["sbytes_per_pkt"] = result["sbytes"] / (result["spkts"] + 1)
    result["dbytes_per_pkt"] = result["dbytes"] / (result["dpkts"] + 1)
    return result


def fit_encoders(frame: pd.DataFrame) -> dict[str, LabelEncoder]:
    encoders = {}
    for column in CATEGORICAL_COLUMNS:
        values = frame[column].astype(str)
        if column == "proto":
            values = values.map(normalize_protocol)
        encoder = LabelEncoder()
        encoder.fit(values)
        # Se agrega después del fit para no desplazar los índices aprendidos.
        if UNKNOWN_CATEGORY not in encoder.classes_:
            encoder.classes_ = np.append(
                encoder.classes_.astype(object), UNKNOWN_CATEGORY
            )
        encoders[column] = encoder
    return encoders


def transform_features(frame: pd.DataFrame, encoders: dict[str, LabelEncoder],
                       feature_names: list[str] | None = None) -> pd.DataFrame:
    result = add_derived_features(frame.drop(columns=DROP_COLUMNS, errors="ignore"))
    for column, encoder in encoders.items():
        values = result[column].astype(str)
        if column == "proto":
            values = values.map(normalize_protocol)
        known = set(encoder.classes_)
        fallback = SEMANTIC_FALLBACKS[column]
        if fallback not in known:
            fallback = UNKNOWN_CATEGORY
        values = values.map(lambda value: value if value in known else fallback)
        result[column] = encoder.transform(values)

    result.replace([np.inf, -np.inf], np.nan, inplace=True)
    result.fillna(0, inplace=True)
    if feature_names is not None:
        result = result[feature_names]
    return result


def autoencoder_scores(model: DeepAnomalyAE, values: np.ndarray,
                       device: torch.device, batch_size: int = 4096) -> np.ndarray:
    model.eval()
    scores = []
    with torch.no_grad():
        for start in range(0, len(values), batch_size):
            batch = torch.as_tensor(values[start:start + batch_size],
                                    dtype=torch.float32, device=device)
            reconstructed = model(batch)
            score = torch.mean((batch - reconstructed) ** 2, dim=1)
            scores.append(score.cpu().numpy())
    return np.concatenate(scores) if scores else np.empty(0, dtype=float)


def train_autoencoder_candidate(train_values: np.ndarray, stop_values: np.ndarray,
                                dimension: int, learning_rate: float,
                                weight_decay: float, device: torch.device,
                                seed: int) -> tuple[DeepAnomalyAE, dict]:
    seed_everything(seed)
    model = DeepAnomalyAE(dimension).to(device)
    loader = DataLoader(
        TensorDataset(torch.as_tensor(train_values, dtype=torch.float32)),
        batch_size=256,
        shuffle=True,
        generator=torch.Generator().manual_seed(seed),
    )
    stop_tensor = torch.as_tensor(stop_values, dtype=torch.float32, device=device)
    optimizer = optim.Adam(model.parameters(), lr=learning_rate,
                           weight_decay=weight_decay)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=5
    )
    criterion = nn.MSELoss()
    best_loss = float("inf")
    best_state = None
    patience = 0
    epochs_ran = 0

    for epoch in range(100):
        model.train()
        for (batch_cpu,) in loader:
            batch = batch_cpu.to(device)
            optimizer.zero_grad()
            loss = criterion(model(batch), batch)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            stop_loss = criterion(model(stop_tensor), stop_tensor).item()
        scheduler.step(stop_loss)
        epochs_ran = epoch + 1
        if stop_loss < best_loss - 1e-7:
            best_loss = stop_loss
            best_state = deepcopy(model.state_dict())
            patience = 0
        else:
            patience += 1
        if patience >= 15:
            break

    model.load_state_dict(best_state)
    return model, {"epochs": epochs_ran, "benign_stop_loss": best_loss}


def raw_scores(eif, autoencoder, lof, full_values: np.ndarray,
               pca_values: np.ndarray, device: torch.device) -> dict[str, np.ndarray]:
    return {
        "if": np.asarray(eif.predict(full_values), dtype=float),
        "ae": autoencoder_scores(autoencoder, pca_values, device),
        "lof": np.asarray(-lof.decision_function(pca_values), dtype=float),
    }


def reference_percentiles(scores: np.ndarray, reference: np.ndarray) -> np.ndarray:
    reference = np.asarray(reference, dtype=float)
    if reference.ndim != 1 or reference.size == 0:
        raise ValueError("La distribución de referencia debe ser un vector no vacío")
    return np.searchsorted(reference, scores, side="right") / reference.size


def ensemble_scores(raw: dict[str, np.ndarray], references: dict[str, np.ndarray],
                    weights: dict[str, float]) -> np.ndarray:
    return sum(
        weights[name] * reference_percentiles(raw[name], references[name])
        for name in ("if", "ae", "lof")
    )


def select_weights_for_target_fpr(
    raw: dict[str, np.ndarray],
    references: dict[str, np.ndarray],
    labels: np.ndarray,
    target_fpr: float,
) -> tuple[dict[str, float], float, dict, list[dict]]:
    """Selecciona pesos solo en validación maximizando recall a FPR fijo.

    Se exige al menos 0.10 para cada componente para conservar la naturaleza
    ensemble. La malla avanza en pasos de 0.05 y usa AUC como desempate.
    """
    percentiles = {
        name: reference_percentiles(raw[name], references[name])
        for name in ("if", "ae", "lof")
    }
    normal_mask = labels == 0
    trials = []
    best = None

    # Unidades de 0.05; mínimo 2 unidades (0.10) por componente.
    for if_units in range(2, 17):
        for ae_units in range(2, 19 - if_units):
            lof_units = 20 - if_units - ae_units
            if lof_units < 2:
                continue
            weights = {
                "if": if_units / 20,
                "ae": ae_units / 20,
                "lof": lof_units / 20,
            }
            scores = sum(weights[name] * percentiles[name]
                         for name in ("if", "ae", "lof"))
            threshold = float(np.quantile(
                scores[normal_mask], 1 - target_fpr, method="higher"
            ))
            metrics = binary_metrics(labels, scores, threshold)
            trial = {
                "weights": weights,
                "threshold": threshold,
                "recall": metrics["recall"],
                "f1": metrics["f1"],
                "auc_roc": metrics["auc_roc"],
                "false_positive_rate": metrics["false_positive_rate"],
            }
            trials.append(trial)
            selection_key = (metrics["recall"], metrics["f1"], metrics["auc_roc"])
            if best is None or selection_key > best[0]:
                best = (selection_key, weights, threshold, metrics)

    _, weights, threshold, metrics = best
    return weights, threshold, metrics, trials


def binary_metrics(labels: np.ndarray, scores: np.ndarray,
                   threshold: float) -> dict:
    predictions = (scores >= threshold).astype(int)
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    return {
        "auc_roc": float(roc_auc_score(labels, scores)),
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "confusion_matrix": matrix.tolist(),
        "normal_count": int((labels == 0).sum()),
        "attack_count": int((labels == 1).sum()),
    }


def per_category_recall(categories: pd.Series, labels: np.ndarray,
                        scores: np.ndarray, threshold: float) -> dict:
    predictions = scores >= threshold
    result = {}
    for category in sorted(categories[labels == 1].dropna().unique()):
        mask = (categories.to_numpy() == category) & (labels == 1)
        result[str(category)] = {
            "count": int(mask.sum()),
            "recall": float(predictions[mask].mean()) if mask.any() else None,
        }
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=f"Entrena el ensemble esquema v{SCHEMA_VERSION} sin fuga de test"
    )
    default_data = PACKAGE_DIR.parent / "TesisFinal" / "Data"
    parser.add_argument("--train-csv", type=Path,
                        default=default_data / "UNSW_NB15_training-set.csv")
    parser.add_argument("--test-csv", type=Path,
                        default=default_data / "UNSW_NB15_testing-set.csv")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=SENSOR_DIR / f"models_v{SCHEMA_VERSION}_candidate",
    )
    parser.add_argument("--validation-size", type=float, default=0.20)
    parser.add_argument("--target-fpr", type=float, default=0.02)
    parser.add_argument("--seed", type=int, default=RANDOM_STATE)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not 0 < args.validation_size < 0.5:
        raise ValueError("--validation-size debe estar entre 0 y 0.5")
    if not 0 < args.target_fpr < 1:
        raise ValueError("--target-fpr debe estar entre 0 y 1")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    seed_everything(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    started = time.time()

    print("[1/9] Cargando datasets y creando train/validation/test...")
    official_train = pd.read_csv(args.train_csv)
    test_frame = pd.read_csv(args.test_csv)
    train_frame, validation_frame = train_test_split(
        official_train,
        test_size=args.validation_size,
        random_state=args.seed,
        stratify=official_train["label"],
    )
    train_frame = train_frame.reset_index(drop=True)
    validation_frame = validation_frame.reset_index(drop=True)
    test_frame = test_frame.reset_index(drop=True)
    y_train = train_frame["label"].to_numpy()
    y_validation = validation_frame["label"].to_numpy()
    y_test = test_frame["label"].to_numpy()
    print(f"  train={len(train_frame):,}, validation={len(validation_frame):,}, "
          f"test={len(test_frame):,}")

    print("[2/9] Ajustando encoders y scaler exclusivamente con train...")
    train_raw = train_frame.drop(columns=DROP_COLUMNS)
    encoders = fit_encoders(train_raw)
    train_encoded = transform_features(train_frame, encoders)
    feature_names = train_encoded.columns.tolist()
    validation_encoded = transform_features(validation_frame, encoders, feature_names)
    test_encoded = transform_features(test_frame, encoders, feature_names)

    scaler = StandardScaler()
    scaler.fit(train_encoded.loc[y_train == 0])
    train_scaled = scaler.transform(train_encoded)
    validation_scaled = scaler.transform(validation_encoded)
    test_scaled = scaler.transform(test_encoded)
    train_normal = train_scaled[y_train == 0]

    print("[3/9] Purificando tráfico benigno y ajustando PCA...")
    cleaner = IsolationForest(n_estimators=100, contamination=0.01,
                              random_state=args.seed, n_jobs=-1)
    clean_mask = cleaner.fit_predict(train_normal) == 1
    train_normal_clean = train_normal[clean_mask]
    pca = PCA(n_components=0.95, random_state=args.seed)
    train_normal_pca = pca.fit_transform(train_normal_clean)
    validation_pca = pca.transform(validation_scaled)
    test_pca = pca.transform(test_scaled)
    print(f"  benignos limpios={len(train_normal_clean):,}; PCA={pca.n_components_}")

    print("[4/9] Seleccionando hiperparámetros EIF con validation...")
    best_eif = None
    best_eif_auc = -np.inf
    best_eif_params = None
    eif_trials = []
    for trees in (100, 200, 300):
        candidate = EIF(ndim=2, ntrees=trees, random_seed=args.seed, nthreads=-1)
        candidate.fit(train_normal_clean)
        candidate_scores = candidate.predict(validation_scaled)
        auc = roc_auc_score(y_validation, candidate_scores)
        eif_trials.append({"ntrees": trees, "validation_auc": float(auc)})
        print(f"  EIF ntrees={trees}: AUC={auc:.4f}")
        if auc > best_eif_auc:
            best_eif, best_eif_auc = candidate, auc
            best_eif_params = {"ntrees": trees, "ndim": 2}

    print("[5/9] Seleccionando hiperparámetros Autoencoder con validation...")
    ae_train, ae_stop = train_test_split(
        train_normal_pca, test_size=0.10, random_state=args.seed
    )
    best_autoencoder = None
    best_ae_auc = -np.inf
    best_ae_params = None
    ae_trials = []
    for learning_rate, weight_decay in ((0.001, 0.0), (0.001, 1e-5),
                                         (0.002, 0.0), (0.002, 1e-5)):
        candidate, training_info = train_autoencoder_candidate(
            ae_train, ae_stop, pca.n_components_, learning_rate,
            weight_decay, device, args.seed
        )
        scores = autoencoder_scores(candidate, validation_pca, device)
        auc = roc_auc_score(y_validation, scores)
        trial = {
            "learning_rate": learning_rate,
            "weight_decay": weight_decay,
            "validation_auc": float(auc),
            **training_info,
        }
        ae_trials.append(trial)
        print(f"  AE lr={learning_rate}, wd={weight_decay}: AUC={auc:.4f}, "
              f"epochs={training_info['epochs']}")
        if auc > best_ae_auc:
            best_autoencoder, best_ae_auc = candidate, auc
            best_ae_params = trial

    print("[6/9] Seleccionando hiperparámetros LOF con validation...")
    best_lof = None
    best_lof_auc = -np.inf
    best_lof_params = None
    lof_trials = []
    for neighbors in (20, 50, 100):
        for contamination in (0.01, 0.05):
            for metric in ("euclidean", "manhattan"):
                candidate = LocalOutlierFactor(
                    n_neighbors=neighbors,
                    contamination=contamination,
                    metric=metric,
                    novelty=True,
                    n_jobs=-1,
                )
                candidate.fit(train_normal_pca)
                scores = -candidate.decision_function(validation_pca)
                auc = roc_auc_score(y_validation, scores)
                trial = {
                    "n_neighbors": neighbors,
                    "contamination": contamination,
                    "metric": metric,
                    "validation_auc": float(auc),
                }
                lof_trials.append(trial)
                print(f"  LOF k={neighbors}, c={contamination}, {metric}: AUC={auc:.4f}")
                if auc > best_lof_auc:
                    best_lof, best_lof_auc = candidate, auc
                    best_lof_params = trial

    print("[7/9] Construyendo referencias fijas y calibrando umbral...")
    validation_raw = raw_scores(
        best_eif, best_autoencoder, best_lof,
        validation_scaled, validation_pca, device
    )
    validation_normal = y_validation == 0
    references = {
        name: np.sort(scores[validation_normal])
        for name, scores in validation_raw.items()
    }
    component_auc = {
        name: float(roc_auc_score(y_validation, scores))
        for name, scores in validation_raw.items()
    }
    weights, threshold, validation_metrics, weight_trials = (
        select_weights_for_target_fpr(
            validation_raw, references, y_validation, args.target_fpr
        )
    )
    validation_ensemble = ensemble_scores(validation_raw, references, weights)
    print(f"  weights={weights}")
    print(f"  threshold={threshold:.6f}; validation FPR="
          f"{validation_metrics['false_positive_rate']:.4f}")

    print("[8/9] Evaluando una sola vez sobre test oficial intacto...")
    test_raw = raw_scores(
        best_eif, best_autoencoder, best_lof,
        test_scaled, test_pca, device
    )
    test_ensemble = ensemble_scores(test_raw, references, weights)
    test_metrics = binary_metrics(y_test, test_ensemble, threshold)
    category_metrics = per_category_recall(
        test_frame["attack_cat"], y_test, test_ensemble, threshold
    )
    print(json.dumps(test_metrics, indent=2))

    print("[9/9] Guardando artefactos versionados...")
    joblib.dump(scaler, args.output_dir / "scaler.pkl")
    joblib.dump(encoders, args.output_dir / "encoders.pkl")
    joblib.dump(pca, args.output_dir / "pca.pkl")
    joblib.dump(best_eif, args.output_dir / "eif_model.pkl")
    joblib.dump(best_lof, args.output_dir / "lof_model.pkl")
    torch.save({
        "model_state": best_autoencoder.state_dict(),
        "input_dim": int(pca.n_components_),
    }, args.output_dir / "autoencoder.pt")
    np.savez_compressed(
        args.output_dir / "score_reference.npz",
        score_if=references["if"],
        score_ae=references["ae"],
        score_lof=references["lof"],
    )

    report = {
        "schema_version": SCHEMA_VERSION,
        "model_version": MODEL_VERSION,
        "feature_schema": FEATURE_SCHEMA_NAME,
        "feature_schema_hash": FEATURE_SCHEMA_HASH,
        "feature_definitions": FEATURE_DEFINITIONS,
        "random_state": args.seed,
        "software_versions": software_versions(),
        "elapsed_seconds": time.time() - started,
        "split": {
            "official_train_rows": len(official_train),
            "train_rows": len(train_frame),
            "validation_rows": len(validation_frame),
            "test_rows": len(test_frame),
            "validation_fraction": args.validation_size,
            "test_source": str(args.test_csv),
        },
        "target_fpr": args.target_fpr,
        "threshold": threshold,
        "weights": weights,
        "component_validation_auc": component_auc,
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
        "test_recall_by_attack_category": category_metrics,
        "selected_hyperparameters": {
            "eif": best_eif_params,
            "autoencoder": best_ae_params,
            "lof": best_lof_params,
            "weight_selection": {
                "criterion": "maximum_validation_recall_at_target_fpr",
                "grid_step": 0.05,
                "minimum_component_weight": 0.10,
            },
        },
        "trials": {
            "eif": eif_trials,
            "autoencoder": ae_trials,
            "lof": lof_trials,
            "weights": weight_trials,
        },
    }
    (args.output_dir / "training_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    meta = {
        "schema_version": SCHEMA_VERSION,
        "model_version": MODEL_VERSION,
        "software_versions": software_versions(),
        "feature_schema": FEATURE_SCHEMA_NAME,
        "feature_schema_hash": FEATURE_SCHEMA_HASH,
        "feature_names": feature_names,
        "categorical_cols": CATEGORICAL_COLUMNS,
        "unknown_category_token": UNKNOWN_CATEGORY,
        "n_features": len(feature_names),
        "pca_components": int(pca.n_components_),
        "score_transform": "fixed_benign_validation_ecdf",
        "score_reference_file": "score_reference.npz",
        "threshold": threshold,
        "target_fpr": args.target_fpr,
        "weights": {
            "w_if": weights["if"],
            "w_ae": weights["ae"],
            "w_lof": weights["lof"],
        },
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
    }
    (args.output_dir / "meta.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )
    print(f"Artefactos guardados en {args.output_dir}")


if __name__ == "__main__":
    main()
