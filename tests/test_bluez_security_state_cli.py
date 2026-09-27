"""CLI tests for read-only BlueZ persistent security-state inspection."""

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

ADAPTER = "88:A2:9E:C6:E9:09"
TARGET = "00:1C:4D:45:DE:3F"
NOW = "2026-09-26T07:00:00Z"

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "kamal-inspect-bluez-state"
SPEC = importlib.util.spec_from_file_location("kamal_inspect_bluez_state_cli", CLI)
if SPEC is None or SPEC.loader is None:
    from importlib.machinery import SourceFileLoader

    loader = SourceFileLoader("kamal_inspect_bluez_state_cli", str(CLI))
    SPEC = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class BlueZSecurityStateCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bluez = self.root / "bluetooth"
        self.adapter = self.bluez / ADAPTER
        self.cache = self.adapter / "cache"
        self.cache.mkdir(parents=True)
        for path in (self.bluez, self.adapter, self.cache):
            os.chmod(path, 0o700)
        (self.cache / TARGET).write_text(
            "[General]\nName=go dawgs\nAddressType=public\n",
            encoding="utf-8",
        )
        self.output = self.root / "state.json"

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
            "--bluez-root",
            str(self.bluez),
            "--observed-at-utc",
            NOW,
            "--json",
            str(self.output),
        ]

    def test_writes_read_only_report(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = module.main(self.argv())
        self.assertEqual(rc, 0)
        payload = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(payload["record_type"], "bluez_security_state_report")
        self.assertFalse(payload["execution"]["rf_performed"])
        self.assertFalse(payload["execution"]["network_performed"])
        self.assertFalse(payload["execution"]["mutated_bluez_state"])
        self.assertIn("Raw Bluetooth key values were not emitted", stdout.getvalue())
        self.assertIn("No RF or network operations", stdout.getvalue())

    def test_refuses_existing_output(self):
        self.output.write_text("existing", encoding="utf-8")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = module.main(self.argv())
        self.assertEqual(rc, 1)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "existing")

    def test_missing_target_does_not_create_output(self):
        (self.cache / TARGET).unlink()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = module.main(self.argv())
        self.assertEqual(rc, 1)
        self.assertFalse(self.output.exists())
        self.assertIn("not present", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
