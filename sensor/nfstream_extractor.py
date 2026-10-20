"""Extractor unico NFStream -> contrato UNSW/NFStream v3-common."""

from __future__ import annotations

from typing import Any

import dpkt
from nfstream import NFPlugin

from feature_adapter import normalize_protocol
from feature_contract import FlowContextWindow


class FirstTTLPlugin(NFPlugin):
    """Expone el primer TTL/hop-limit observado en cada direccion del flujo."""

    @staticmethod
    def _ttl(packet) -> int:
        try:
            if packet.ip_version == 4:
                return int(dpkt.ip.IP(packet.ip_packet).ttl)
            if packet.ip_version == 6:
                return int(dpkt.ip6.IP6(packet.ip_packet).hlim)
        except (dpkt.UnpackError, ValueError, AttributeError):
            return 0
        return 0

    def on_init(self, packet, flow) -> None:
        flow.udps.src2dst_first_ttl = 0
        flow.udps.dst2src_first_ttl = 0
        self._record(packet, flow)

    def on_update(self, packet, flow) -> None:
        self._record(packet, flow)

    def _record(self, packet, flow) -> None:
        ttl = self._ttl(packet)
        if packet.direction == 0 and flow.udps.src2dst_first_ttl == 0:
            flow.udps.src2dst_first_ttl = ttl
        elif packet.direction == 1 and flow.udps.dst2src_first_ttl == 0:
            flow.udps.dst2src_first_ttl = ttl


class NFStreamFeatureExtractor:
    """Convierte tanto PCAP como captura viva mediante una sola implementacion."""

    def __init__(self, context: FlowContextWindow | None = None):
        self.context = context or FlowContextWindow()

    @staticmethod
    def _value(flow: Any, name: str, default: Any = 0) -> Any:
        value = getattr(flow, name, default)
        return default if value is None else value

    def extract(self, flow: Any) -> dict[str, Any]:
        metadata = {
            "src_ip": str(self._value(flow, "src_ip", "")),
            "dst_ip": str(self._value(flow, "dst_ip", "")),
            "sport": int(self._value(flow, "src_port", 0) or 0),
            "dport": int(self._value(flow, "dst_port", 0) or 0),
        }
        udps = getattr(flow, "udps", None)
        sttl = int(getattr(udps, "src2dst_first_ttl", 0) or 0)
        dttl = int(getattr(udps, "dst2src_first_ttl", 0) or 0)
        record = {
            **metadata,
            "dur": float(self._value(flow, "bidirectional_duration_ms", 0)) / 1000.0,
            "proto": normalize_protocol(self._value(flow, "protocol", 0)),
            "spkts": int(self._value(flow, "src2dst_packets", 0)),
            "dpkts": int(self._value(flow, "dst2src_packets", 0)),
            "sbytes": int(self._value(flow, "src2dst_bytes", 0)),
            "dbytes": int(self._value(flow, "dst2src_bytes", 0)),
            "sttl": sttl,
            "dttl": dttl,
            "is_sm_ips_ports": int(
                metadata["src_ip"] == metadata["dst_ip"]
                and metadata["sport"] == metadata["dport"]
            ),
            **self.context.enrich(metadata),
        }
        return record
