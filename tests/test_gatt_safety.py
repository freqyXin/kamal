import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from kamal.gatt_safety import (
    SafetyInterlockError,
    acquire_active_run,
    assert_execution_allowed,
    latch_unsafe_stop,
    resolve_interlock,
)


def recovery_request():
    return {
        "schema_version": "0.12.0",
        "record_type": "gatt_safety_recovery_request",
        "recovery_id": "recovery-1",
        "operator": "Tester",
        "confirmed_at_utc": "2026-09-25T12:00:00Z",
        "basis": "Verified the device is disconnected and reviewed target state.",
        "confirmations": {
            "no_active_ble_session": True,
            "target_state_reviewed": True,
        },
        "evidence": ["lab-note:recovery-1"],
    }


class SafetyStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "safety"

    def acquire(self):
        return acquire_active_run(
            self.state,
            plan_id="plan-1",
            plan_sha256="1" * 64,
            authorization_sha256="2" * 64,
            output_dir=Path(self.tmp.name) / "out",
            targets=[{"address": "AA:BB:CC:DD:EE:FF", "address_type": "public"}],
        )

    def test_active_run_blocks_concurrent_execution(self):
        self.acquire()
        with self.assertRaises(SafetyInterlockError):
            assert_execution_allowed(self.state)

    def test_unsafe_latch_replaces_active_run(self):
        self.acquire()
        latch_unsafe_stop(
            self.state,
            plan_id="plan-1",
            reason="disconnect unconfirmed",
            cleanup={"attempted": True, "completed": False, "error": "timeout"},
            output_dir=Path(self.tmp.name) / "out",
            current_target={"address": "AA:BB:CC:DD:EE:FF", "address_type": "public"},
        )
        self.assertFalse((self.state / "active-run.json").exists())
        self.assertTrue((self.state / "unsafe-stop.json").exists())
        with self.assertRaises(SafetyInterlockError):
            assert_execution_allowed(self.state)

    def test_recovery_requires_explicit_confirmations(self):
        self.acquire()
        request = recovery_request()
        request["confirmations"]["no_active_ble_session"] = False
        with self.assertRaises(SafetyInterlockError):
            resolve_interlock(self.state, request, request_sha256="3" * 64)
        self.assertTrue((self.state / "active-run.json").exists())

    def test_recovery_clears_orphaned_active_run_and_records_artifact(self):
        self.acquire()
        request = recovery_request()
        raw = json.dumps(request, sort_keys=True).encode()
        artifact, path = resolve_interlock(
            self.state,
            request,
            request_sha256=hashlib.sha256(raw).hexdigest(),
        )
        self.assertEqual(artifact["source_kind"], "orphaned_active_run")
        self.assertTrue(path.exists())
        self.assertFalse((self.state / "active-run.json").exists())
        assert_execution_allowed(self.state)

    def test_recovery_clears_unsafe_latch(self):
        self.acquire()
        latch_unsafe_stop(
            self.state,
            plan_id="plan-1",
            reason="unsubscribe uncertain",
            cleanup={"attempted": True, "completed": False, "error": "timeout"},
            output_dir=Path(self.tmp.name) / "out",
        )
        request = recovery_request()
        raw = json.dumps(request, sort_keys=True).encode()
        artifact, _ = resolve_interlock(
            self.state,
            request,
            request_sha256=hashlib.sha256(raw).hexdigest(),
        )
        self.assertEqual(artifact["source_kind"], "unsafe_stop")
        self.assertFalse((self.state / "unsafe-stop.json").exists())
        assert_execution_allowed(self.state)


if __name__ == "__main__":
    unittest.main()
