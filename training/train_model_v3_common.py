"""Entrena v3-common reutilizando el protocolo estadistico validado de v2.

La unica diferencia experimental es el contrato de caracteristicas. Los
splits, la seleccion en validacion, las ECDF fijas y el test oficial intacto
se mantienen para que la comparacion v2-full/v3-common sea interpretable.
"""

from __future__ import annotations

import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SENSOR_DIR = SCRIPT_DIR.parent / "sensor"
sys.path.insert(0, str(SENSOR_DIR))

import train_model_v2 as training
from feature_contract import (
    CATEGORICAL_COLUMNS,
    FEATURE_DEFINITIONS,
    SCHEMA_NAME,
    build_common_features,
    schema_hash,
)


def common_feature_builder(frame):
    return build_common_features(frame, strict=True)


training.SCHEMA_VERSION = 3
training.MODEL_VERSION = "unsw-nb15-ensemble-v3-common-fixed-ecdf"
training.FEATURE_SCHEMA_NAME = SCHEMA_NAME
training.FEATURE_SCHEMA_HASH = schema_hash()
training.FEATURE_DEFINITIONS = FEATURE_DEFINITIONS
training.CATEGORICAL_COLUMNS = CATEGORICAL_COLUMNS
training.SEMANTIC_FALLBACKS = {"proto": "any"}
training.add_derived_features = common_feature_builder


if __name__ == "__main__":
    training.main()
