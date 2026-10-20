"""Extractor NFStream para captura de dataset nativo v4."""

from __future__ import annotations

from typing import Any

from nfstream_extractor import FirstTTLPlugin
from feature_adapter import normalize_protocol
from feature_contract_v4_native import TimeWindowFlowContext


class NFStreamNativeExtractor:
    def __init__(self, context: TimeWindowFlowContext | None = None):
        self.context = context or TimeWindowFlowContext()

    @staticmethod
    def _value(flow: Any, name: str, default: Any = 0) -> Any:
        value = getattr(flow, name, default)
        return default if value is None else value

    def extract_raw(self, flow: Any) -> dict[str, Any]:
        metadata = {
            "src_ip": str(self._value(flow, "src_ip", "")),
            "dst_ip": str(self._value(flow, "dst_ip", "")),
            "sport": int(self._value(flow, "src_port", 0) or 0),
            "dport": int(self._value(flow, "dst_port", 0) or 0),
        }
        event_time_ms = int(self._value(flow, "bidirectional_last_seen_ms", 0) or 0)
        if event_time_ms <= 0:
            raise ValueError("NFStream no entregó bidirectional_last_seen_ms")
        udps = getattr(flow, "udps", None)
        sttl = int(getattr(udps, "src2dst_first_ttl", 0) or 0)
        dttl = int(getattr(udps, "dst2src_first_ttl", 0) or 0)
        return {
            **metadata,
            "event_time_ms": event_time_ms,
            "dur": float(self._value(flow, "bidirectional_duration_ms", 0)) / 1000.0,
            "proto": normalize_protocol(self._value(flow, "protocol", 0)),
            "spkts": int(self._value(flow, "src2dst_packets", 0)),
            "dpkts": int(self._value(flow, "dst2src_packets", 0)),
            "sbytes": int(self._value(flow, "src2dst_bytes", 0)),
            "dbytes": int(self._value(flow, "dst2src_bytes", 0)),
            "sttl": sttl,
            "dttl": dttl,
            "is_sm_ips_ports": int(metadata["src_ip"] == metadata["dst_ip"] and metadata["sport"] == metadata["dport"]),
        }

    def enrich_context(self, record: dict[str, Any]) -> dict[str, Any]:
        """Añade contexto cuando el llamador ya garantizó orden temporal."""
        metadata = {key: record[key] for key in ("src_ip", "dst_ip", "sport", "dport")}
        return {
            **record,
            **self.context.enrich(metadata, int(record["event_time_ms"])),
        }

    def extract(self, flow: Any) -> dict[str, Any]:
        """API directa para PCAPs ya ordenados y pruebas unitarias."""
        return self.enrich_context(self.extract_raw(flow))
