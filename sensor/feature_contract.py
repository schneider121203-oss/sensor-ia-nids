"""Contrato reproducible de caracteristicas para el modelo ``v3-common``.

El contrato contiene solamente variables presentes en UNSW-NB15 que el
sensor puede observar, o variables derivadas con exactamente la misma formula
en entrenamiento e inferencia.  Las direcciones IP y los puertos se conservan
como metadatos de alerta, nunca como entradas del modelo.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable

import numpy as np
import pandas as pd

from feature_adapter import normalize_protocol


SCHEMA_NAME = "unsw-nfstream-common-v1"
CONTEXT_WINDOW_SIZE = 100

# Columnas que deben existir antes de calcular las variables derivadas.
BASE_COLUMNS = [
    "dur",
    "proto",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "sttl",
    "dttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "ct_src_ltm",
    "is_sm_ips_ports",
]

DERIVED_COLUMNS = [
    "flow_packet_rate",
    "src_load_bps",
    "dst_load_bps",
    "src_mean_packet_bytes",
    "dst_mean_packet_bytes",
    "bytes_ratio",
    "packet_ratio",
    "load_ratio",
]

MODEL_FEATURES = BASE_COLUMNS + DERIVED_COLUMNS
CATEGORICAL_COLUMNS = ["proto"]
NUMERIC_COLUMNS = [column for column in MODEL_FEATURES if column != "proto"]

FEATURE_DEFINITIONS = {
    "dur": "Duracion bidireccional del flujo en segundos.",
    "proto": "Protocolo IP normalizado a nombre IANA en minusculas.",
    "spkts": "Paquetes observados en la direccion origen-destino.",
    "dpkts": "Paquetes observados en la direccion destino-origen.",
    "sbytes": "Bytes observados en la direccion origen-destino.",
    "dbytes": "Bytes observados en la direccion destino-origen.",
    "sttl": "TTL/hop-limit del primer paquete origen-destino.",
    "dttl": "TTL/hop-limit del primer paquete destino-origen; 0 si no existe.",
    "ct_dst_ltm": "Flujos al mismo destino dentro de una ventana de 100, incluido el actual.",
    "ct_src_dport_ltm": "Flujos con mismo origen y puerto destino en la ventana.",
    "ct_dst_sport_ltm": "Flujos con mismo destino y puerto origen en la ventana.",
    "ct_dst_src_ltm": "Flujos con el mismo par origen-destino en la ventana.",
    "ct_src_ltm": "Flujos del mismo origen dentro de la ventana.",
    "is_sm_ips_ports": "1 cuando IP origen=destino y puerto origen=destino; 0 en otro caso.",
    "flow_packet_rate": "(spkts + dpkts) / dur, en paquetes por segundo.",
    "src_load_bps": "8 * sbytes / dur, en bits por segundo.",
    "dst_load_bps": "8 * dbytes / dur, en bits por segundo.",
    "src_mean_packet_bytes": "sbytes / spkts.",
    "dst_mean_packet_bytes": "dbytes / dpkts.",
    "bytes_ratio": "sbytes / (dbytes + 1).",
    "packet_ratio": "spkts / (dpkts + 1).",
    "load_ratio": "src_load_bps / (dst_load_bps + 1).",
}


def schema_hash() -> str:
    """Huella estable del orden, formulas y ventana del contrato."""
    payload = {
        "schema": SCHEMA_NAME,
        "window_size": CONTEXT_WINDOW_SIZE,
        "features": MODEL_FEATURES,
        "definitions": FEATURE_DEFINITIONS,
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_divide(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    numerator = pd.to_numeric(numerator, errors="coerce").astype(float)
    denominator = pd.to_numeric(denominator, errors="coerce").astype(float)
    result = np.zeros(len(numerator), dtype=float)
    valid = denominator.to_numpy() > 0
    np.divide(
        numerator.to_numpy(),
        denominator.to_numpy(),
        out=result,
        where=valid,
    )
    return pd.Series(result, index=numerator.index)


def build_common_features(frame: pd.DataFrame, *, strict: bool = True) -> pd.DataFrame:
    """Construye la matriz v3 con las mismas formulas en train y produccion.

    ``strict=True`` evita la antigua conducta de inventar columnas ausentes con
    cero. Los ceros que devuelve esta funcion provienen exclusivamente de una
    division sin denominador (por ejemplo, un flujo sin respuesta).
    """
    missing = [column for column in BASE_COLUMNS if column not in frame.columns]
    if missing and strict:
        raise ValueError(
            "Faltan columnas obligatorias del contrato v3-common: "
            + ", ".join(missing)
        )

    result = frame.copy()
    for column in missing:
        result[column] = 0

    result["proto"] = result["proto"].map(normalize_protocol)
    for column in NUMERIC_COLUMNS:
        if column in result.columns:
            result[column] = pd.to_numeric(result[column], errors="coerce")

    duration = result["dur"]
    result["flow_packet_rate"] = _safe_divide(
        result["spkts"] + result["dpkts"], duration
    )
    result["src_load_bps"] = _safe_divide(8.0 * result["sbytes"], duration)
    result["dst_load_bps"] = _safe_divide(8.0 * result["dbytes"], duration)
    result["src_mean_packet_bytes"] = _safe_divide(
        result["sbytes"], result["spkts"]
    )
    result["dst_mean_packet_bytes"] = _safe_divide(
        result["dbytes"], result["dpkts"]
    )
    result["bytes_ratio"] = result["sbytes"] / (result["dbytes"] + 1.0)
    result["packet_ratio"] = result["spkts"] / (result["dpkts"] + 1.0)
    result["load_ratio"] = result["src_load_bps"] / (
        result["dst_load_bps"] + 1.0
    )

    output = result[MODEL_FEATURES].copy()
    output.replace([np.inf, -np.inf], np.nan, inplace=True)
    if strict and output.isna().any().any():
        bad = output.columns[output.isna().any()].tolist()
        raise ValueError("Valores no numericos o ausentes en: " + ", ".join(bad))
    output.fillna(0, inplace=True)
    return output


@dataclass
class FlowContextWindow:
    """Contadores UNSW ``*_ltm`` sobre 100 flujos incluido el actual."""

    window_size: int = CONTEXT_WINDOW_SIZE
    _previous: deque[dict[str, Any]] = field(init=False)

    def __post_init__(self) -> None:
        if self.window_size < 1:
            raise ValueError("window_size debe ser mayor que cero")
        # Se guardan 99 anteriores: al sumar el actual la ventana contiene 100.
        self._previous = deque(maxlen=self.window_size - 1)

    @staticmethod
    def _count(rows: Iterable[dict[str, Any]], **conditions: Any) -> int:
        return sum(
            all(row.get(key) == value for key, value in conditions.items())
            for row in rows
        )

    def enrich(self, metadata: dict[str, Any]) -> dict[str, int]:
        src_ip = str(metadata.get("src_ip", ""))
        dst_ip = str(metadata.get("dst_ip", ""))
        sport = int(metadata.get("sport", 0) or 0)
        dport = int(metadata.get("dport", 0) or 0)

        counts = {
            "ct_dst_ltm": 1 + self._count(self._previous, dst_ip=dst_ip),
            "ct_src_dport_ltm": 1 + self._count(
                self._previous, src_ip=src_ip, dport=dport
            ),
            "ct_dst_sport_ltm": 1 + self._count(
                self._previous, dst_ip=dst_ip, sport=sport
            ),
            "ct_dst_src_ltm": 1 + self._count(
                self._previous, src_ip=src_ip, dst_ip=dst_ip
            ),
            "ct_src_ltm": 1 + self._count(self._previous, src_ip=src_ip),
        }
        self._previous.append(
            {"src_ip": src_ip, "dst_ip": dst_ip, "sport": sport, "dport": dport}
        )
        return counts
