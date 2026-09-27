"""CLI tests for non-executing Bluetooth pairing plan construction."""

import importlib.util
import json
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin" / "kamal-plan-pairing"
loader = SourceFileLoader("kamal_plan_pairing_cli", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)

TARGET = "AA:BB:CC:DD:EE:FF"


def authorization():
    return {
        "schema_version": "0.12.0",
        "record_type": "bluetooth_pairing_authorization",
        "authorization_id": "pair-auth-cli",
        "engagement_id": "eng-cli",
        "owner": "Lab",
        "operator": "Tester",
        "location": "Controlled lab",
        "issued_at_utc": "2026-01-01T00:00:00Z",
        "not_before_utc": "2026-01-01T00:00:00Z",
        "expires_at_utc": "2099-01-01T00:00:00Z",
        "target": {
            "protocol": "ble",
            "address": TARGET,
            "address_type": "public",
            "label": "target",
        },
        "allowed_operations": ["pair_target", "establish_bond"],
        "constraints": {
            "max_attempts": 1,
            "max_discovery_seconds": 20,
            "max_pairing_seconds": 90,
            "max_disconnect_seconds": 10,
            "require_disconnect_after": True,
            "require_unpaired_before": True,
            "require_unbonded_before": True,
            "allowed_agent_modes": ["no_input_no_output"],
        },
        "approval": {
            "approver": "Owner",
            "approved_at_utc": "2026-01-01T00:00:00Z",
            "basis": "owned lab target",
        },
    }


def request():
    return {
        "schema_version": "0.12.0",
        "record_type": "bluetooth_pairing_request",
        "plan_id": "pair-plan-cli",
        "pairing_session_id": "pair-session-cli",
        "target": {"address": TARGET, "address_type": "public"},
        "request_bond": True,
        "agent_mode": "no_input_no_output",
        "timeouts": {
            "discovery_seconds": 5,
            "pairing_seconds": 10,
            "disconnect_seconds": 3,
        },
    }


class PairingContractCLITests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.auth_path = self.root / "authorization.json"
        self.request_path = self.root / "request.json"
        self.output_path = self.root / "plan.json"
        self.auth_path.write_text(json.dumps(authorization()), encoding="utf-8")
        self.request_path.write_text(json.dumps(request()), encoding="utf-8")

    def args(self, output=None):
        return [
            "--authorization",
            str(self.auth_path),
            "--request",
            str(self.request_path),
            "--json",
            str(output or self.output_path),
        ]

    def test_writes_hash_bound_plan_without_rf(self):
        with mock.patch("builtins.print"):
            result = module.main(self.args())
        self.assertEqual(result, 0)
        plan = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(plan["target"]["address"], TARGET)
        self.assertTrue(plan["requested"]["pair"])
        self.assertTrue(plan["requested"]["bond"])
        self.assertEqual(
            plan["execution"],
            {
                "execution_domain": "active_rf",
                "transmit_capable": True,
                "mutates_security_state": True,
            },
        )
        self.assertEqual(len(plan["authorization"]["sha256"]), 64)
        self.assertEqual(len(plan["request"]["sha256"]), 64)

    def test_refuses_existing_output(self):
        self.output_path.write_text("existing", encoding="utf-8")
        with mock.patch("sys.stderr"):
            result = module.main(self.args())
        self.assertEqual(result, 1)
        self.assertEqual(self.output_path.read_text(encoding="utf-8"), "existing")

    def test_refuses_output_path_that_is_input(self):
        original = self.auth_path.read_bytes()
        with mock.patch("sys.stderr"):
            result = module.main(self.args(self.auth_path))
        self.assertEqual(result, 1)
        self.assertEqual(self.auth_path.read_bytes(), original)

    def test_invalid_authorization_does_not_create_output(self):
        payload = authorization()
        payload["allowed_operations"] = ["pair_target"]
        self.auth_path.write_text(json.dumps(payload), encoding="utf-8")
        with mock.patch("sys.stderr"):
            result = module.main(self.args())
        self.assertEqual(result, 1)
        self.assertFalse(self.output_path.exists())


if __name__ == "__main__":
    unittest.main()
