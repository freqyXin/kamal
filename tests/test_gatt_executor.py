import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from kamal.active_contracts import build_gatt_operation_plan
from kamal.gatt_executor import ExecutionError, UnsafeStopError, execute_plan
from kamal.gatt_safety import SafetyInterlockError


def auth():
    return {
        "schema_version": "0.12.0",
        "record_type": "authorization_scope",
        "authorization_id": "auth-1",
        "engagement_id": "eng-1",
        "owner": "Lab",
        "operator": "Tester",
        "location": "Lab",
        "issued_at_utc": "2026-01-01T00:00:00Z",
        "not_before_utc": "2026-01-01T00:00:00Z",
        "expires_at_utc": "2099-01-01T00:00:00Z",
        "targets": [
            {
                "protocol": "ble",
                "address": "AA:BB:CC:DD:EE:FF",
                "address_type": "public",
            }
        ],
        "allowed_operations": [
            "read_characteristic",
            "read_descriptor",
            "write_characteristic",
            "subscribe_notifications",
        ],
        "constraints": {
            "max_operations": 8,
            "max_payload_bytes": 32,
            "max_timeout_seconds": 5,
            "max_subscription_seconds": 5,
            "allow_writes": True,
            "allow_write_without_response": False,
        },
        "approval": {
            "approver": "Owner",
            "approved_at_utc": "2026-01-01T00:00:00Z",
            "basis": "owned lab device",
        },
    }


def request(operations):
    if isinstance(operations, dict):
        operations = [operations]
    return {
        "schema_version": "0.12.0",
        "record_type": "gatt_operation_request",
        "plan_id": "plan-1",
        "operations": operations,
    }


def op(kind="read_characteristic", operation_id="op-1"):
    d = {
        "operation_id": operation_id,
        "operation_type": kind,
        "target": {
            "address": "AA:BB:CC:DD:EE:FF",
            "address_type": "public",
        },
        "selector": {"handle": 3},
        "timeout_seconds": 1,
    }
    if kind == "write_characteristic":
        d.update(payload_hex="0102", write_mode="request")
    if kind == "subscribe_notifications":
        d.update(duration_seconds=1)
    return d


def plan(kind="read_characteristic", operations=None):
    a = auth()
    raw = b"auth"
    ops = operations if operations is not None else [op(kind)]
    return (
        build_gatt_operation_plan(
            a,
            request(ops),
            authorization_sha256=hashlib.sha256(raw).hexdigest(),
            request_sha256="1" * 64,
        ),
        a,
        hashlib.sha256(raw).hexdigest(),
    )


class FakeChar:
    handle = 3
    uuid = "1234"
    descriptors = []


class FakeService:
    uuid = "1800"
    characteristics = [FakeChar()]


class FakeClient:
    def __init__(
        self,
        *,
        disconnect_stuck=False,
        stop_error=False,
        read_error=None,
        disconnect_after_read=False,
    ):
        self.is_connected = False
        self.services = [FakeService()]
        self.disconnect_stuck = disconnect_stuck
        self.stop_error = stop_error
        self.read_error = read_error
        self.disconnect_after_read = disconnect_after_read
        self.writes = []

    async def connect(self):
        self.is_connected = True

    async def disconnect(self):
        self.is_connected = self.disconnect_stuck

    async def read_gatt_char(self, x):
        if self.read_error:
            raise self.read_error
        if self.disconnect_after_read:
            self.is_connected = False
        return b"abc"

    async def read_gatt_descriptor(self, h):
        return b"def"

    async def write_gatt_char(self, x, payload, response=True):
        self.writes.append((bytes(payload), response))

    async def start_notify(self, x, cb):
        cb(x, b"z")

    async def stop_notify(self, x):
        if self.stop_error:
            raise RuntimeError("stop failed")


class Backend:
    def __init__(self, client, *, prepare_error=None):
        self.c = client
        self.prepare_error = prepare_error
        self.discover_calls = 0

    def prepare(self):
        if self.prepare_error is not None:
            raise self.prepare_error

    async def discover(self, *a, **k):
        self.discover_calls += 1
        return SimpleNamespace(address="AA:BB:CC:DD:EE:FF"), SimpleNamespace()

    def client(self, *a, **k):
        return self.c


class ExecTests(unittest.TestCase):
    def run_case(self, kind="read_characteristic", client=None):
        p, a, sha = plan(kind)
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        final = asyncio.run(
            execute_plan(
                p,
                a,
                authorization_sha256=sha,
                plan_sha256="2" * 64,
                output_dir=root / "out",
                safety_state_dir=root / "safety",
                backend=Backend(client or FakeClient()),
            )
        )
        return final, root / "out", root / "safety"

    def test_read_persists_incrementally(self):
        final, out, safety = self.run_case()
        self.assertTrue(final["complete"])
        self.assertTrue((out / "run-start.json").exists())
        self.assertTrue((out / "operation-001.json").exists())
        self.assertTrue((out / "run-final.json").exists())
        self.assertFalse((safety / "active-run.json").exists())
        self.assertFalse((safety / "unsafe-stop.json").exists())
        result = json.loads((out / "operation-001.json").read_text())
        self.assertEqual(result["effect_semantics"]["transport"]["state"], "succeeded")
        self.assertEqual(result["effect_semantics"]["protocol"]["state"], "value_received")
        self.assertEqual(
            result["effect_semantics"]["security_effect"]["state"], "not_assessed"
        )
        self.assertEqual(final["transport_success_count"], 1)
        self.assertEqual(final["higher_effects_assessed_count"], 0)
        self.assertEqual(final["safety_interlock"]["state"], "clear")

    def test_write_executes_bounded_payload(self):
        c = FakeClient()
        final, out, _ = self.run_case("write_characteristic", c)
        self.assertEqual(c.writes, [(b"\x01\x02", True)])
        result = json.loads((out / "operation-001.json").read_text())
        self.assertEqual(
            result["effect_semantics"]["protocol"]["state"],
            "write_request_completed",
        )
        self.assertEqual(
            result["effect_semantics"]["application_acknowledgment"]["state"],
            "not_assessed",
        )
        self.assertEqual(result["application_effect"], "not_assessed")
        self.assertEqual(final["successful_operations"], 1)

    def test_notification_cleanup(self):
        self.run_case("subscribe_notifications")

    def test_notification_cleanup_failure_latches_recovery(self):
        p, a, sha = plan("subscribe_notifications")
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        with self.assertRaises(UnsafeStopError):
            asyncio.run(
                execute_plan(
                    p,
                    a,
                    authorization_sha256=sha,
                    plan_sha256="2" * 64,
                    output_dir=root / "out",
                    safety_state_dir=root / "safety",
                    backend=Backend(FakeClient(stop_error=True)),
                )
            )
        self.assertTrue((root / "safety" / "unsafe-stop.json").exists())
        final = json.loads((root / "out" / "run-final.json").read_text())
        self.assertTrue(final["recovery_required"])

    def test_unsafe_disconnect_latches_recovery_requirement(self):
        p, a, sha = plan()
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        with self.assertRaises(UnsafeStopError):
            asyncio.run(
                execute_plan(
                    p,
                    a,
                    authorization_sha256=sha,
                    plan_sha256="2" * 64,
                    output_dir=root / "out",
                    safety_state_dir=root / "safety",
                    backend=Backend(FakeClient(disconnect_stuck=True)),
                )
            )
        self.assertTrue((root / "safety" / "unsafe-stop.json").exists())
        self.assertFalse((root / "safety" / "active-run.json").exists())
        final = json.loads((root / "out" / "run-final.json").read_text())
        self.assertTrue(final["unsafe_stop"])
        self.assertTrue(final["recovery_required"])

    def test_unsafe_latch_blocks_followup_before_rf(self):
        p, a, sha = plan()
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        with self.assertRaises(UnsafeStopError):
            asyncio.run(
                execute_plan(
                    p,
                    a,
                    authorization_sha256=sha,
                    plan_sha256="2" * 64,
                    output_dir=root / "first",
                    safety_state_dir=root / "safety",
                    backend=Backend(FakeClient(disconnect_stuck=True)),
                )
            )
        backend = Backend(FakeClient())
        with self.assertRaises(SafetyInterlockError):
            asyncio.run(
                execute_plan(
                    p,
                    a,
                    authorization_sha256=sha,
                    plan_sha256="3" * 64,
                    output_dir=root / "second",
                    safety_state_dir=root / "safety",
                    backend=backend,
                )
            )
        self.assertEqual(backend.discover_calls, 0)
        self.assertFalse((root / "second").exists())

    def test_backend_prepare_failure_is_recorded_before_rf(self):
        p, a, sha = plan()
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        backend = Backend(
            FakeClient(),
            prepare_error=ModuleNotFoundError("No module named 'bleak'"),
        )
        with self.assertRaises(ExecutionError):
            asyncio.run(
                execute_plan(
                    p,
                    a,
                    authorization_sha256=sha,
                    plan_sha256="2" * 64,
                    output_dir=root / "out",
                    safety_state_dir=root / "safety",
                    backend=backend,
                )
            )
        result = json.loads((root / "out" / "operation-001.json").read_text())
        final = json.loads((root / "out" / "run-final.json").read_text())
        self.assertFalse(result["rf_attempted"])
        self.assertFalse(final["rf_performed"])
        self.assertEqual(backend.discover_calls, 0)
        self.assertIn("No module named 'bleak'", result["error"])
        self.assertFalse(final["recovery_required"])
        self.assertFalse((root / "safety" / "active-run.json").exists())
        self.assertFalse((root / "safety" / "unsafe-stop.json").exists())

    def test_operation_failure_preserves_evidence_and_releases_safe_interlock(self):
        p, a, sha = plan()
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        with self.assertRaises(ExecutionError):
            asyncio.run(
                execute_plan(
                    p,
                    a,
                    authorization_sha256=sha,
                    plan_sha256="2" * 64,
                    output_dir=root / "out",
                    safety_state_dir=root / "safety",
                    backend=Backend(FakeClient(read_error=RuntimeError("read failed"))),
                )
            )
        result = json.loads((root / "out" / "operation-001.json").read_text())
        final = json.loads((root / "out" / "run-final.json").read_text())
        self.assertIn("read failed", result["error"])
        self.assertEqual(final["failed_operations"], 1)
        self.assertFalse(final["recovery_required"])
        self.assertFalse((root / "safety" / "active-run.json").exists())
        self.assertFalse((root / "safety" / "unsafe-stop.json").exists())

    def test_connection_loss_after_operation_stops_before_next_operation(self):
        ops = [op(operation_id="op-1"), op(operation_id="op-2")]
        p, a, sha = plan(operations=ops)
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        with self.assertRaises(ExecutionError):
            asyncio.run(
                execute_plan(
                    p,
                    a,
                    authorization_sha256=sha,
                    plan_sha256="2" * 64,
                    output_dir=root / "out",
                    safety_state_dir=root / "safety",
                    backend=Backend(FakeClient(disconnect_after_read=True)),
                )
            )
        self.assertTrue((root / "out" / "operation-001.json").exists())
        self.assertFalse((root / "out" / "operation-002.json").exists())
        final = json.loads((root / "out" / "run-final.json").read_text())
        self.assertEqual(final["successful_operations"], 1)
        self.assertEqual(final["unattempted_operations"], 1)
        self.assertFalse(final["recovery_required"])

    def test_authorization_hash_mismatch_fails_before_output(self):
        p, a, sha = plan()
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        out = root / "out"
        with self.assertRaises(ExecutionError):
            asyncio.run(
                execute_plan(
                    p,
                    a,
                    authorization_sha256="0" * 64,
                    plan_sha256="2" * 64,
                    output_dir=out,
                    safety_state_dir=root / "safety",
                    backend=Backend(FakeClient()),
                )
            )
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
