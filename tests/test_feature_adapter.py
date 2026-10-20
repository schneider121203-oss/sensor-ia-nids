import sys
import unittest
from pathlib import Path

import pandas as pd


SENSOR_DIR = Path(__file__).resolve().parents[1] / "sensor"
sys.path.insert(0, str(SENSOR_DIR))

from ensemble_predictor import EnsemblePredictor
from feature_adapter import normalize_protocol


def deployable_flow(**overrides):
    row = {
        "proto": 6,
        "dur": 0.2,
        "spkts": 4,
        "dpkts": 3,
        "sbytes": 450,
        "dbytes": 220,
        "sttl": 64,
        "dttl": 64,
        "ct_dst_60s": 1,
        "ct_src_dport_60s": 1,
        "ct_dst_sport_60s": 1,
        "ct_dst_src_60s": 1,
        "ct_src_60s": 1,
        "is_sm_ips_ports": 0,
    }
    row.update(overrides)
    return row


class ProtocolNormalizationTests(unittest.TestCase):
    def test_common_protocol_numbers(self):
        self.assertEqual(normalize_protocol(6), "tcp")
        self.assertEqual(normalize_protocol("17"), "udp")
        self.assertEqual(normalize_protocol(b"1"), "icmp")

    def test_protocol_names_and_aliases(self):
        self.assertEqual(normalize_protocol(" TCP "), "tcp")
        self.assertEqual(normalize_protocol("icmpv6"), "ipv6-icmp")
        self.assertEqual(normalize_protocol(253), "253")

    def test_predictor_encodes_nfstream_tcp_as_training_tcp(self):
        predictor = EnsemblePredictor()
        predictor.load_models()
        _, _, encoded = predictor._preprocess(
            pd.DataFrame([deployable_flow()])
        )

        expected = predictor.encoders["proto"].transform(["tcp"])[0]
        self.assertEqual(encoded.loc[0, "proto"], expected)

    def test_unknown_values_use_semantic_fallbacks(self):
        predictor = EnsemblePredictor()
        predictor.load_models()
        encoded = predictor._encode_categoricals(pd.DataFrame([{"proto": 253}]))

        classes = set(predictor.encoders["proto"].classes_)
        fallback = "any" if "any" in classes else "__unknown__"
        self.assertEqual(encoded.loc[0, "proto"], predictor.encoders["proto"].transform([fallback])[0])

    def test_score_does_not_depend_on_batch_companions(self):
        predictor = EnsemblePredictor()
        predictor.load_models()
        target = pd.DataFrame([deployable_flow()])
        companions = pd.DataFrame([
            deployable_flow(
                proto=17, dur=0.01 + index / 10,
                spkts=1 + index, dpkts=1,
                sbytes=80 + index * 100, dbytes=40,
                sttl=32, dttl=128,
            )
            for index in range(20)
        ])

        score_alone = predictor.predict(target)["ensemble_score"].iloc[0]
        score_in_batch = predictor.predict(
            pd.concat([target, companions], ignore_index=True)
        )["ensemble_score"].iloc[0]
        self.assertEqual(score_alone, score_in_batch)

    def test_alert_severity_is_relative_to_model_threshold(self):
        predictor = EnsemblePredictor()
        predictor.load_models()
        threshold = predictor.meta["threshold"]
        suspicious = predictor.format_alert({}, threshold)
        high = predictor.format_alert({}, threshold + 0.5 * (1 - threshold))
        critical = predictor.format_alert({}, threshold + 0.9 * (1 - threshold))
        self.assertEqual(suspicious["severity"], "suspicious")
        self.assertEqual(high["severity"], "high")
        self.assertEqual(critical["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
