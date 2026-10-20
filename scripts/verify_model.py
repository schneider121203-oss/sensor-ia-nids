#!/usr/bin/env python3
"""Verifica versión, umbral y hashes del modelo promovido."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

EXPECTED_VERSION = "nfstream-native-ensemble-v4-60s"
EXPECTED_THRESHOLD = 0.9343915343915343


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(models_dir: Path) -> dict:
    manifest_path = models_dir / "freeze_manifest.json"
    meta_path = models_dir / "meta.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    errors = []
    if manifest.get("status") != "frozen_for_evaluation":
        errors.append("freeze_manifest no está marcado frozen_for_evaluation")
    if meta.get("model_version") != EXPECTED_VERSION:
        errors.append(f"model_version inesperado: {meta.get('model_version')}")
    if manifest.get("model_version") != EXPECTED_VERSION:
        errors.append("model_version no coincide en freeze_manifest")
    if float(meta.get("threshold", -1)) != EXPECTED_THRESHOLD:
        errors.append(f"umbral inesperado: {meta.get('threshold')}")
    if float(manifest.get("threshold", -1)) != EXPECTED_THRESHOLD:
        errors.append("umbral no coincide en freeze_manifest")
    for filename, expected in manifest.get("model_files_sha256", {}).items():
        path = models_dir / filename
        if not path.is_file():
            errors.append(f"falta {filename}")
        elif sha256(path) != expected:
            errors.append(f"hash inválido: {filename}")
    if errors:
        raise ValueError("; ".join(errors))
    return {
        "verified": True,
        "model_version": EXPECTED_VERSION,
        "threshold": EXPECTED_THRESHOLD,
        "files_verified": len(manifest["model_files_sha256"]),
        "freeze_manifest_sha256": sha256(manifest_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--models-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.models_dir), indent=2))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
