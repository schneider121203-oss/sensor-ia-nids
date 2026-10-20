"""Entrena v4-native solo con flujos benignos NFStream y split temporal.

Los ataques no se cargan aquí: se reservan para una evaluación posterior.
La configuración (EIF=200, LOF=50, pesos iguales) está predefinida para no
seleccionar hiperparámetros mirando datos ofensivos.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from importlib.metadata import version
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
from isotree import IsolationForest as EIF
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import LabelEncoder, StandardScaler


SCRIPT_DIR = Path(__file__).resolve().parent
SENSOR_DIR = SCRIPT_DIR.parent / "sensor"
sys.path.insert(0, str(SENSOR_DIR))

from feature_adapter import normalize_protocol
from feature_contract_v4_native import (  # noqa: E402
    BASE_COLUMNS, CATEGORICAL_COLUMNS, FEATURE_DEFINITIONS, MODEL_FEATURES, SCHEMA_NAME,
    build_native_features, schema_hash,
)
from train_model_v2 import (  # noqa: E402
    DeepAnomalyAE, autoencoder_scores, raw_scores, seed_everything,
    train_autoencoder_candidate,
)


MODEL_VERSION = "nfstream-native-ensemble-v4-60s"
TARGET_FPR = 0.02
WEIGHTS = {"w_if": 1 / 3, "w_ae": 1 / 3, "w_lof": 1 / 3}
RANDOM_STATE = 42


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, nargs="+", required=True,
                        help="Uno o más NDJSON benignos producidos por collect_native_flows.py")
    parser.add_argument("--output-dir", type=Path,
                        default=SENSOR_DIR / "models_v4_native_candidate")
    parser.add_argument("--target-fpr", type=float, default=TARGET_FPR)
    parser.add_argument("--seed", type=int, default=RANDOM_STATE)
    return parser.parse_args()


def load_benign(paths: list[Path]) -> pd.DataFrame:
    rows = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(path)
        rows.extend(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line)
    frame = pd.DataFrame(rows)
    # Las ocho variables derivadas se calculan dentro de build_native_features;
    # el recolector solo debe aportar las columnas base observables.
    required = {"event_time_ms", "capture_label", *BASE_COLUMNS}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError("NDJSON sin columnas requeridas: " + ", ".join(sorted(missing)))
    if not (frame["capture_label"] == "benign").all():
        raise ValueError("El entrenamiento v4 acepta exclusivamente capture_label=benign")
    frame["event_time_ms"] = pd.to_numeric(frame["event_time_ms"], errors="raise")
    frame = frame.sort_values("event_time_ms", kind="stable").reset_index(drop=True)
    if len(frame) < 1000:
        raise ValueError("Se requieren al menos 1000 flujos benignos para entrenar v4-native")
    return frame


def split_temporal(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    n = len(frame)
    train_end, validation_end = int(n * 0.70), int(n * 0.85)
    return frame.iloc[:train_end], frame.iloc[train_end:validation_end], frame.iloc[validation_end:]


def fit_encoders(frame: pd.DataFrame) -> dict[str, LabelEncoder]:
    encoders = {}
    for column in CATEGORICAL_COLUMNS:
        encoder = LabelEncoder()
        encoder.fit(frame[column].astype(str).map(normalize_protocol))
        if "__unknown__" not in encoder.classes_:
            encoder.classes_ = np.append(encoder.classes_.astype(object), "__unknown__")
        encoders[column] = encoder
    return encoders


def transform(frame: pd.DataFrame, encoders: dict[str, LabelEncoder]) -> pd.DataFrame:
    result = build_native_features(frame, strict=True)
    for column, encoder in encoders.items():
        values = result[column].astype(str).map(normalize_protocol)
        known = set(encoder.classes_)
        fallback = "any" if "any" in known else "__unknown__"
        result[column] = encoder.transform(values.map(lambda value: value if value in known else fallback))
    return result[MODEL_FEATURES]


def percentile(scores: np.ndarray, reference: np.ndarray) -> np.ndarray:
    return np.searchsorted(reference, scores, side="right") / len(reference)


def ensemble(raw: dict[str, np.ndarray], references: dict[str, np.ndarray]) -> np.ndarray:
    return sum(WEIGHTS[f"w_{name}"] * percentile(raw[name], references[name]) for name in ("if", "ae", "lof"))


def main() -> None:
    args = parse_args()
    if not 0 < args.target_fpr < 1:
        raise ValueError("--target-fpr debe estar entre 0 y 1")
    seed_everything(args.seed)
    started = time.time()
    frame = load_benign(args.input)
    train, validation, test = split_temporal(frame)
    print(f"Flujos benignos: train={len(train)}, validation={len(validation)}, test={len(test)}")

    encoders = fit_encoders(train)
    train_encoded = transform(train, encoders)
    validation_encoded = transform(validation, encoders)
    test_encoded = transform(test, encoders)
    scaler = StandardScaler().fit(train_encoded)
    train_scaled = scaler.transform(train_encoded)
    validation_scaled = scaler.transform(validation_encoded)
    test_scaled = scaler.transform(test_encoded)

    cleaner = IsolationForest(n_estimators=100, contamination=0.01,
                              random_state=args.seed, n_jobs=-1)
    clean_mask = cleaner.fit_predict(train_scaled) == 1
    clean_train = train_scaled[clean_mask]
    pca = PCA(n_components=0.95, random_state=args.seed).fit(clean_train)
    clean_train_pca = pca.transform(clean_train)
    validation_pca, test_pca = pca.transform(validation_scaled), pca.transform(test_scaled)

    eif = EIF(ndim=2, ntrees=200, random_seed=args.seed, nthreads=-1).fit(clean_train)
    lof = LocalOutlierFactor(n_neighbors=50, contamination=0.02, metric="euclidean",
                             novelty=True, n_jobs=-1).fit(clean_train_pca)
    inner_cut = max(1, int(len(clean_train_pca) * 0.10))
    ae, ae_info = train_autoencoder_candidate(
        clean_train_pca[:-inner_cut], clean_train_pca[-inner_cut:], pca.n_components_,
        learning_rate=0.001, weight_decay=1e-5,
        device=torch.device("cuda" if torch.cuda.is_available() else "cpu"), seed=args.seed,
    )
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    train_raw = raw_scores(eif, ae, lof, train_scaled, pca.transform(train_scaled), device)
    references = {name: np.sort(values) for name, values in train_raw.items()}
    validation_raw = raw_scores(eif, ae, lof, validation_scaled, validation_pca, device)
    validation_scores = ensemble(validation_raw, references)
    threshold = float(np.quantile(validation_scores, 1 - args.target_fpr, method="higher"))
    test_raw = raw_scores(eif, ae, lof, test_scaled, test_pca, device)
    test_scores = ensemble(test_raw, references)

    args.output_dir.mkdir(parents=True, exist_ok=False)
    joblib.dump(scaler, args.output_dir / "scaler.pkl")
    joblib.dump(encoders, args.output_dir / "encoders.pkl")
    joblib.dump(pca, args.output_dir / "pca.pkl")
    joblib.dump(eif, args.output_dir / "eif_model.pkl")
    joblib.dump(lof, args.output_dir / "lof_model.pkl")
    torch.save({"model_state": ae.state_dict(), "input_dim": int(pca.n_components_)}, args.output_dir / "autoencoder.pt")
    np.savez_compressed(args.output_dir / "score_reference.npz", **{f"score_{name}": values for name, values in references.items()})
    report = {
        "schema_version": 4, "model_version": MODEL_VERSION, "feature_schema": SCHEMA_NAME,
        "feature_schema_hash": schema_hash(), "feature_definitions": FEATURE_DEFINITIONS,
        "feature_names": MODEL_FEATURES, "threshold": threshold, "target_fpr": args.target_fpr,
        "weights": WEIGHTS, "score_reference_file": "score_reference.npz",
        "split": {"strategy": "chronological 70/15/15", "train_rows": len(train), "validation_rows": len(validation), "test_rows": len(test)},
        "validation_metrics": {"false_positive_rate": float(np.mean(validation_scores >= threshold))},
        "test_metrics": {"false_positive_rate": float(np.mean(test_scores >= threshold))},
        "pre_registered_hyperparameters": {"eif_ntrees": 200, "lof_neighbors": 50, "weights": "equal"},
        "autoencoder": ae_info, "random_state": args.seed,
        "software_versions": {name: version(name) for name in ("numpy", "pandas", "scikit-learn", "torch", "isotree", "nfstream")},
        "elapsed_seconds": time.time() - started,
    }
    (args.output_dir / "meta.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    (args.output_dir / "training_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"output": str(args.output_dir), "threshold": threshold, "test_fpr": report["test_metrics"]["false_positive_rate"]}, indent=2))


if __name__ == "__main__":
    main()
