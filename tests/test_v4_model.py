import sys
import unittest
from pathlib import Path

import pandas as pd


SENSOR_DIR = Path(__file__).resolve().parents[1] / "sensor"
sys.path.insert(0, str(SENSOR_DIR))

from ensemble_predictor import EnsemblePredictor  # noqa: E402


class V4ModelTests(unittest.TestCase):
    def test_promoted_model_loads_and_scores_native_rows_on_cpu(self):
        model_dir = SENSOR_DIR / "models"
        rows = []
        for index in range(10):
            rows.append({
                "dur": 0.1 + index / 100,
                "proto": "tcp",
                "spkts": 2 + index,
                "dpkts": 1,
                "sbytes": 120 + index * 10,
                "dbytes": 80,
                "sttl": 64,
                "dttl": 64,
                "ct_dst_60s": index + 1,
                "ct_src_dport_60s": index + 1,
                "ct_dst_sport_60s": 1,
                "ct_dst_src_60s": index + 1,
                "ct_src_60s": index + 1,
                "is_sm_ips_ports": 0,
            })
        predictor = EnsemblePredictor(model_dir, device="cpu")
        predictor.load_models()
        result = predictor.predict(pd.DataFrame(rows))
        self.assertEqual(len(result), 10)
        self.assertTrue(result["ensemble_score"].between(0, 1).all())
        self.assertEqual(predictor.meta["schema_version"], 4)
        self.assertEqual(str(predictor.device), "cpu")


if __name__ == "__main__":
    unittest.main()
