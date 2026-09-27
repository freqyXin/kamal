"""CLI tests for non-executing GATT operation plan construction."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "kamal-plan-gatt"
SPEC = importlib.util.spec_from_file_location("kamal_plan_gatt_cli", CLI)
if SPEC is None or SPEC.loader is None:
    from importlib.machinery import SourceFileLoader

    loader = SourceFileLoader("kamal_plan_gatt_cli", str(CLI))
    SPEC = importlib.util.spec_from_loader("kamal_plan_gatt_cli", loader)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def authorization():
    return {
        "schema_version": "0.12.0",
        "record_type": "authorization_scope",
        "authorization_id": "auth:cli",
        "engagement_id": "engagement:cli",
        "owner": "Example Owner",
        "operator": "freqy",
        "location": "authorized lab",
        "issued_at_utc": "2026-09-25T03:00:00Z",
        "not_before_utc": "2026-09-25T04:00:00Z",
        "expires_at_utc": "2099-09-25T06:00:00Z",
        "targets": [
            {
                "protocol": "ble",
                "address": "AA:BB:CC:DD:EE:FF",
                "address_type": "public",
            }
        ],
        "allowed_operations": ["read_characteristic"],
        "constraints": {
            "max_operations": 2,
            "max_payload_bytes": 16,
            "max_timeout_seconds": 5,
            "max_subscription_seconds": 10,
            "allow_writes": False,
            "allow_write_without_response": False,
        },
        "approval": {
            "approver": "Example Owner",
            "approved_at_utc": "2026-09-25T03:30:00Z",
            "basis": "TEST-CLI",
        },
    }


def operation_request():
    return {
        "schema_version": "0.12.0",
        "record_type": "gatt_operation_request",
        "plan_id": "plan:cli",
        "operations": [
            {
                "operation_id": "op:read",
                "operation_type": "read_characteristic",
                "target": {
                    "address": "AA:BB:CC:DD:EE:FF",
                    "address_type": "public",
                },
                "selector": {"handle": 7},
                "timeout_seconds": 5,
            }
        ],
    }


class ActiveContractCLITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.auth_path = self.root / "authorization.json"
        self.request_path = self.root / "operations.json"
        self.output_path = self.root / "plan.json"
        self.auth_path.write_text(json.dumps(authorization()), encoding="utf-8")
        self.request_path.write_text(json.dumps(operation_request()), encoding="utf-8")

    def test_writes_plan_without_rf(self):
        result = module.main(
            [
                "--authorization",
                str(self.auth_path),
                "--operations",
                str(self.request_path),
                "--json",
                str(self.output_path),
            ]
        )
        self.assertEqual(result, 0)
        payload = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertFalse(payload["execution"]["rf_performed"])
        self.assertEqual(payload["integrity"]["operation_count"], 1)
        self.assertEqual(payload["authorization_ref"], "auth:cli")
        self.assertEqual(len(payload["authorization_provenance"]["sha256"]), 64)
        self.assertEqual(len(payload["request_provenance"]["sha256"]), 64)

    def test_refuses_existing_output(self):
        self.output_path.write_text("existing", encoding="utf-8")
        with mock.patch("sys.stderr"):
            result = module.main(
                [
                    "--authorization",
                    str(self.auth_path),
                    "--operations",
                    str(self.request_path),
                    "--json",
                    str(self.output_path),
                ]
            )
        self.assertEqual(result, 1)
        self.assertEqual(self.output_path.read_text(encoding="utf-8"), "existing")

    def test_refuses_output_path_that_is_input(self):
        original = self.auth_path.read_bytes()
        with mock.patch("sys.stderr"):
            result = module.main(
                [
                    "--authorization",
                    str(self.auth_path),
                    "--operations",
                    str(self.request_path),
                    "--json",
                    str(self.auth_path),
                ]
            )
        self.assertEqual(result, 1)
        self.assertEqual(self.auth_path.read_bytes(), original)

    def test_invalid_scope_does_not_create_output(self):
        payload = authorization()
        payload["expires_at_utc"] = "2020-01-01T00:00:00Z"
        self.auth_path.write_text(json.dumps(payload), encoding="utf-8")
        with mock.patch("sys.stderr"):
            result = module.main(
                [
                    "--authorization",
                    str(self.auth_path),
                    "--operations",
                    str(self.request_path),
                    "--json",
                    str(self.output_path),
                ]
            )
        self.assertEqual(result, 1)
        self.assertFalse(self.output_path.exists())


if __name__ == "__main__":
    unittest.main()
