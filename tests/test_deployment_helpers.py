import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


configure_module = load_script(
    "configure_wazuh_agent",
    ROOT / "scripts/configure_wazuh_agent.py",
)
verify_module = load_script("verify_model", ROOT / "scripts/verify_model.py")


class WazuhConfigurationTests(unittest.TestCase):
    BASE = """<ossec_config>
  <client><server><address>old-manager</address></server></client>
</ossec_config>
"""

    def test_configuration_is_idempotent(self):
        once = configure_module.configure(
            self.BASE, "192.168.10.50", "/var/log/ensemble/alerts.json"
        )
        twice = configure_module.configure(
            once, "192.168.10.50", "/var/log/ensemble/alerts.json"
        )
        self.assertEqual(once, twice)
        self.assertEqual(once.count(configure_module.START), 1)
        self.assertIn("<address>192.168.10.50</address>", once)
        self.assertIn("<log_format>json</log_format>", once)

    def test_remove_only_our_localfile_block(self):
        configured = configure_module.configure(
            self.BASE, "wazuh.fisi.local", "/var/log/ensemble/alerts.json"
        )
        removed = configure_module.remove_localfile(configured)
        self.assertNotIn(configure_module.START, removed)
        self.assertIn("<client>", removed)


class FrozenModelTests(unittest.TestCase):
    def test_promoted_model_matches_freeze_manifest(self):
        result = verify_module.verify(ROOT / "sensor/models")
        self.assertTrue(result["verified"])
        self.assertEqual(result["model_version"], "nfstream-native-ensemble-v4-60s")
        self.assertEqual(result["files_verified"], 9)

    def test_meta_declares_cpu_compatible_schema(self):
        meta = json.loads((ROOT / "sensor/models/meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["schema_version"], 4)
        self.assertEqual(len(meta["feature_names"]), 22)


if __name__ == "__main__":
    unittest.main()
