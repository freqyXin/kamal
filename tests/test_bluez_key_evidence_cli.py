"""CLI tests for BlueZ protected key-evidence analysis."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

ADAPTER = "AA:BB:CC:DD:EE:01"
TARGET = "AA:BB:CC:DD:EE:FF"
NOW = "2026-09-26T08:30:00Z"
LTK = "00112233445566778899AABBCCDDEEFF"
IRK = "FFEEDDCCBBAA99887766554433221100"

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "kamal-analyze-bluez-keys"
SPEC = importlib.util.spec_from_file_location("kamal_analyze_bluez_keys_cli", CLI)
if SPEC is None or SPEC.loader is None:
    from importlib.machinery import SourceFileLoader

    loader = SourceFileLoader("kamal_analyze_bluez_keys_cli", str(CLI))
    SPEC = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class BlueZKeyEvidenceCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bluez = self.root / "bluetooth"
        self.adapter = self.bluez / ADAPTER
        self.device = self.adapter / TARGET
        self.device.mkdir(parents=True)
        for path in (self.bluez, self.adapter, self.device):
            os.chmod(path, 0o700)
        self.info = self.device / "info"
        self.info.write_text(
            "[General]\nAddressType=public\n"
            "[LongTermKey]\n"
            f"Key={LTK}\nAuthenticated=0\nEncSize=16\n"
            "[IdentityResolvingKey]\n"
            f"Key={IRK}\n",
            encoding="utf-8",
        )
        os.chmod(self.info, 0o600)
        self.output = self.root / "keys.json"

    def argv(self):
        return [
            "--adapter",
            ADAPTER,
            "--target",
            TARGET,
            "--engagement-id",
            "engagement:test",
            "--authorization-ref",
            "auth:test-security",
            "--pairing-session-ref",
            "pairing:test-001",
            "--bluez-root",
            str(self.bluez),
            "--observed-at-utc",
            NOW,
            "--json",
            str(self.output),
        ]

    def test_writes_redacted_analysis_report(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = module.main(self.argv())
        self.assertEqual(rc, 0)
        payload = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(payload["record_type"], "bluez_key_analysis_report")
        self.assertEqual(payload["summary"]["key_count"], 2)
        self.assertEqual(payload["secret_artifact"]["storage_state"], "os_protected_source")
        self.assertFalse(payload["execution"]["rf_performed"])
        self.assertFalse(payload["execution"]["network_performed"])
        self.assertFalse(payload["execution"]["mutated_bluez_state"])
        serialized = self.output.read_text(encoding="utf-8")
        self.assertNotIn(LTK, serialized)
        self.assertNotIn(IRK, serialized)
        self.assertIn(hashlib.sha256(bytes.fromhex(LTK)).hexdigest(), serialized)
        output = stdout.getvalue()
        self.assertNotIn(LTK, output)
        self.assertNotIn(IRK, output)
        self.assertIn("not printed, copied, or persisted", output)
        self.assertIn("No RF or network operations", output)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_refuses_existing_output(self):
        self.output.write_text("existing", encoding="utf-8")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = module.main(self.argv())
        self.assertEqual(rc, 1)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "existing")

    def test_missing_key_material_does_not_create_output(self):
        self.info.write_text("[General]\nAddressType=public\n", encoding="utf-8")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = module.main(self.argv())
        self.assertEqual(rc, 1)
        self.assertFalse(self.output.exists())
        self.assertIn("no recognized", stderr.getvalue())

    def test_malformed_key_error_does_not_echo_secret_text(self):
        bad = "NOT-A-VALID-SECRET"
        self.info.write_text(
            "[General]\nAddressType=public\n"
            "[LongTermKey]\n"
            f"Key={bad}\n",
            encoding="utf-8",
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = module.main(self.argv())
        self.assertEqual(rc, 1)
        self.assertFalse(self.output.exists())
        self.assertNotIn(bad, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
