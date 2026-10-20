"""Contrato v4-native: variables observables y contexto temporal NFStream.

Este contrato no es compatible con v3-common. Sustituye los contadores
``ct_*`` basados en cantidad de flujos por contadores con ventana explícita de
60 segundos. Su propósito es entrenar y evaluar exclusivamente con flujos
extraídos por el mismo sensor que se desplegará.
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


SCHEMA_NAME = "nfstream-native-v4-60s"
CONTEXT_WINDOW_SECONDS = 60

BASE_COLUMNS = [
    "dur", "proto", "spkts", "dpkts", "sbytes", "dbytes", "sttl", "dttl",
    "ct_dst_60s", "ct_src_dport_60s", "ct_dst_sport_60s", "ct_dst_src_60s",
    "ct_src_60s", "is_sm_ips_ports",
]
DERIVED_COLUMNS = [
    "flow_packet_rate", "src_load_bps", "dst_load_bps", "src_mean_packet_bytes",
    "dst_mean_packet_bytes", "bytes_ratio", "packet_ratio", "load_ratio",
]
MODEL_FEATURES = BASE_COLUMNS + DERIVED_COLUMNS
CATEGORICAL_COLUMNS = ["proto"]
NUMERIC_COLUMNS = [column for column in MODEL_FEATURES if column != "proto"]

FEATURE_DEFINITIONS = {
    "ct_dst_60s": "Flujos al mismo destino cuyo fin ocurrió dentro de los últimos 60 s.",
    "ct_src_dport_60s": "Flujos del mismo origen hacia el mismo puerto destino en 60 s.",
    "ct_dst_sport_60s": "Flujos hacia el mismo destino con igual puerto origen en 60 s.",
    "ct_dst_src_60s": "Flujos del mismo par origen-destino en 60 s.",
    "ct_src_60s": "Flujos del mismo origen en 60 s.",
    "dur": "Duración bidireccional NFStream en segundos.",
    "proto": "Protocolo IP normalizado a nombre IANA en minúsculas.",
    "spkts": "Paquetes NFStream origen-destino.",
    "dpkts": "Paquetes NFStream destino-origen.",
    "sbytes": "Bytes NFStream origen-destino.",
    "dbytes": "Bytes NFStream destino-origen.",
    "sttl": "TTL/hop-limit del primer paquete origen-destino.",
    "dttl": "TTL/hop-limit del primer paquete destino-origen; 0 sin respuesta.",
    "is_sm_ips_ports": "1 si IP y puerto origen/destino coinciden; 0 en otro caso.",
    "flow_packet_rate": "(spkts + dpkts) / dur.",
    "src_load_bps": "8*sbytes/dur.",
    "dst_load_bps": "8*dbytes/dur.",
    "src_mean_packet_bytes": "sbytes/spkts.",
    "dst_mean_packet_bytes": "dbytes/dpkts.",
    "bytes_ratio": "sbytes/(dbytes+1).",
    "packet_ratio": "spkts/(dpkts+1).",
    "load_ratio": "src_load_bps/(dst_load_bps+1).",
}


def schema_hash() -> str:
    payload = {
        "schema": SCHEMA_NAME,
        "window_seconds": CONTEXT_WINDOW_SECONDS,
        "features": MODEL_FEATURES,
        "definitions": FEATURE_DEFINITIONS,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _safe_divide(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    numerator = pd.to_numeric(numerator, errors="coerce").astype(float)
    denominator = pd.to_numeric(denominator, errors="coerce").astype(float)
    output = np.zeros(len(numerator), dtype=float)
    np.divide(numerator, denominator, out=output, where=denominator.to_numpy() > 0)
    return pd.Series(output, index=numerator.index)


def build_native_features(frame: pd.DataFrame, *, strict: bool = True) -> pd.DataFrame:
    missing = [column for column in BASE_COLUMNS if column not in frame.columns]
    if missing and strict:
        raise ValueError("Faltan columnas obligatorias del contrato v4-native: " + ", ".join(missing))
    result = frame.copy()
    for column in missing:
        result[column] = 0
    result["proto"] = result["proto"].map(normalize_protocol)
    for column in NUMERIC_COLUMNS:
        if column in result.columns:
            result[column] = pd.to_numeric(result[column], errors="coerce")

    result["flow_packet_rate"] = _safe_divide(result["spkts"] + result["dpkts"], result["dur"])
    result["src_load_bps"] = _safe_divide(8.0 * result["sbytes"], result["dur"])
    result["dst_load_bps"] = _safe_divide(8.0 * result["dbytes"], result["dur"])
    result["src_mean_packet_bytes"] = _safe_divide(result["sbytes"], result["spkts"])
    result["dst_mean_packet_bytes"] = _safe_divide(result["dbytes"], result["dpkts"])
    result["bytes_ratio"] = result["sbytes"] / (result["dbytes"] + 1.0)
    result["packet_ratio"] = result["spkts"] / (result["dpkts"] + 1.0)
    result["load_ratio"] = result["src_load_bps"] / (result["dst_load_bps"] + 1.0)
    output = result[MODEL_FEATURES].copy()
    output.replace([np.inf, -np.inf], np.nan, inplace=True)
    if strict and output.isna().any().any():
        raise ValueError("Valores no numéricos o ausentes en: " + ", ".join(output.columns[output.isna().any()]))
    return output.fillna(0)


@dataclass
class TimeWindowFlowContext:
    """Contadores temporales calculados al cerrar cada flujo NFStream."""

    window_seconds: int = CONTEXT_WINDOW_SECONDS
    _previous: deque[dict[str, Any]] = field(default_factory=deque, init=False)

    def _purge(self, event_time_ms: int) -> None:
        cutoff = event_time_ms - self.window_seconds * 1000
        while self._previous and self._previous[0]["event_time_ms"] < cutoff:
            self._previous.popleft()

    @staticmethod
    def _count(rows: Iterable[dict[str, Any]], **conditions: Any) -> int:
        return sum(all(row.get(key) == value for key, value in conditions.items()) for row in rows)

    def enrich(self, metadata: dict[str, Any], event_time_ms: int) -> dict[str, int]:
        if event_time_ms < 0:
            raise ValueError("event_time_ms debe ser positivo")
        self._purge(event_time_ms)
        src_ip, dst_ip = str(metadata["src_ip"]), str(metadata["dst_ip"])
        sport, dport = int(metadata["sport"]), int(metadata["dport"])
        rows = self._previous
        counts = {
            "ct_dst_60s": 1 + self._count(rows, dst_ip=dst_ip),
            "ct_src_dport_60s": 1 + self._count(rows, src_ip=src_ip, dport=dport),
            "ct_dst_sport_60s": 1 + self._count(rows, dst_ip=dst_ip, sport=sport),
            "ct_dst_src_60s": 1 + self._count(rows, src_ip=src_ip, dst_ip=dst_ip),
            "ct_src_60s": 1 + self._count(rows, src_ip=src_ip),
        }
        self._previous.append({**metadata, "event_time_ms": event_time_ms})
        return counts
