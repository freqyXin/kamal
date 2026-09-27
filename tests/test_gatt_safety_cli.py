import importlib.util
import hashlib
import json
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

from kamal.gatt_safety import acquire_active_run

SCRIPT = Path(__file__).resolve().parents[1] / "bin" / "kamal-resolve-gatt-unsafe"
loader = SourceFileLoader("kamal_resolve_gatt_unsafe_cli", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


class SafetyCLITests(unittest.TestCase):
    def test_parser_requires_state_and_request(self):
        with self.assertRaises(SystemExit):
            module.parser().parse_args([])

    def test_cli_records_recovery_without_rf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            acquire_active_run(
                state,
                plan_id="plan-1",
                plan_sha256="1" * 64,
                authorization_sha256="2" * 64,
                output_dir=root / "out",
                targets=[],
            )
            request = {
                "schema_version": "0.12.0",
                "record_type": "gatt_safety_recovery_request",
                "recovery_id": "recovery-cli",
                "operator": "Tester",
                "confirmed_at_utc": "2026-09-25T12:00:00Z",
                "basis": "Lab recovery verified.",
                "confirmations": {
                    "no_active_ble_session": True,
                    "target_state_reviewed": True,
                },
                "evidence": ["lab-note:cli"],
            }
            request_path = root / "request.json"
            request_path.write_text(json.dumps(request), encoding="utf-8")
            self.assertEqual(
                module.main(["--state-dir", str(state), "--request", str(request_path)]),
                0,
            )
            self.assertFalse((state / "active-run.json").exists())
            resolutions = list((state / "resolutions").glob("*.json"))
            self.assertEqual(len(resolutions), 1)
            artifact = json.loads(resolutions[0].read_text())
            self.assertEqual(
                artifact["request_sha256"],
                hashlib.sha256(request_path.read_bytes()).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
