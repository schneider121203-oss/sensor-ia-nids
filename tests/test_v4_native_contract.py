import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

import pandas as pd


SENSOR_DIR = Path(__file__).resolve().parents[1] / "sensor"
sys.path.insert(0, str(SENSOR_DIR))

from feature_contract_v4_native import (  # noqa: E402
    MODEL_FEATURES,
    TimeWindowFlowContext,
    build_native_features,
    schema_hash,
)
from nfstream_native_extractor import NFStreamNativeExtractor  # noqa: E402


class NativeV4ContractTests(unittest.TestCase):
    def _metadata(self, src="10.0.0.1", dst="10.0.0.2", sport=40000, dport=80):
        return {"src_ip": src, "dst_ip": dst, "sport": sport, "dport": dport}

    def test_context_expires_by_time_not_by_global_flow_volume(self):
        context = TimeWindowFlowContext(window_seconds=60)
        first = context.enrich(self._metadata(), 1_000)
        second = context.enrich(self._metadata(), 30_000)
        expired = context.enrich(self._metadata(), 61_001)
        self.assertEqual(first["ct_src_dport_60s"], 1)
        self.assertEqual(second["ct_src_dport_60s"], 2)
        self.assertEqual(expired["ct_src_dport_60s"], 2)

    def test_native_extractor_and_contract_are_complete(self):
        flow = SimpleNamespace(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=40000, dst_port=80,
            protocol=6, bidirectional_last_seen_ms=1000, bidirectional_duration_ms=250,
            src2dst_packets=3, dst2src_packets=2, src2dst_bytes=180, dst2src_bytes=120,
            udps=SimpleNamespace(src2dst_first_ttl=64, dst2src_first_ttl=63),
        )
        row = NFStreamNativeExtractor().extract(flow)
        features = build_native_features(pd.DataFrame([row]))
        self.assertEqual(features.columns.tolist(), MODEL_FEATURES)
        self.assertFalse(features.isna().any().any())
        self.assertEqual(row["ct_dst_src_60s"], 1)
        self.assertEqual(features.loc[0, "proto"], "tcp")
        self.assertEqual(len(schema_hash()), 64)


if __name__ == "__main__":
    unittest.main()
