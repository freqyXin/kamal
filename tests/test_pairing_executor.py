import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from kamal.pairing_contracts import build_pairing_plan
from kamal.pairing_executor import (
    BlueZPairingBackend,
    PairingExecutionError,
    execute_pairing_plan,
)


TARGET = "AA:BB:CC:DD:EE:FF"


def auth():
    return {
        "schema_version": "0.12.0",
        "record_type": "bluetooth_pairing_authorization",
        "authorization_id": "pair-auth-1",
        "engagement_id": "eng-1",
        "owner": "Lab",
        "operator": "Tester",
        "location": "Controlled lab",
        "issued_at_utc": "2026-01-01T00:00:00Z",
        "not_before_utc": "2026-01-01T00:00:00Z",
        "expires_at_utc": "2099-01-01T00:00:00Z",
        "target": {"protocol": "ble", "address": TARGET, "address_type": "public"},
        "allowed_operations": ["pair_target", "establish_bond"],
        "constraints": {
            "max_attempts": 1,
            "max_discovery_seconds": 20,
            "max_pairing_seconds": 90,
            "max_disconnect_seconds": 10,
            "require_disconnect_after": True,
            "require_unpaired_before": True,
            "require_unbonded_before": True,
            "allowed_agent_modes": ["external_default", "no_input_no_output"],
        },
        "approval": {
            "approver": "Owner",
            "approved_at_utc": "2026-01-01T00:00:00Z",
            "basis": "owned lab target",
        },
    }


def request(*, bond=True):
    return {
        "schema_version": "0.12.0",
        "record_type": "bluetooth_pairing_request",
        "plan_id": "pair-plan-1",
        "pairing_session_id": "pair-session-1",
        "target": {"address": TARGET, "address_type": "public"},
        "request_bond": bond,
        "agent_mode": "no_input_no_output",
        "timeouts": {
            "discovery_seconds": 5,
            "pairing_seconds": 10,
            "disconnect_seconds": 3,
        },
    }


def plan(*, bond=True):
    a = auth()
    auth_sha = hashlib.sha256(b"auth").hexdigest()
    p = build_pairing_plan(
        a,
        request(bond=bond),
        authorization_sha256=auth_sha,
        request_sha256=hashlib.sha256(b"request").hexdigest(),
        created_at_utc="2026-09-26T12:00:00Z",
    )
    return p, a, auth_sha


class FakeBackend:
    supports_pair_without_bond = True

    def __init__(
        self,
        *,
        found=True,
        before=None,
        pair_error=None,
        bonded=True,
        cancel_error=None,
        disconnect_ok=True,
        scanner_stop_error=None,
        close_error=None,
        prepare_error=None,
        trusted_after=None,
    ):
        self.found = found
        self.state = dict(
            before
            or {
                "address": TARGET,
                "address_type": "public",
                "paired": False,
                "bonded": False,
                "trusted": False,
                "connected": False,
            }
        )
        self.pair_error = pair_error
        self.bonded = bonded
        self.cancel_error = cancel_error
        self.disconnect_ok = disconnect_ok
        self.scanner_stop_error = scanner_stop_error
        self.close_error = close_error
        self.prepare_error = prepare_error
        self.trusted_after = trusted_after
        self.pair_calls = 0
        self.cancel_calls = 0
        self.disconnect_calls = 0
        self.stop_calls = 0
        self.agent_events = []

    def prepare(self):
        if self.prepare_error:
            raise self.prepare_error

    async def discover(self, address, adapter, timeout):
        if not self.found:
            return None
        return SimpleNamespace(address=address, path="/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF")

    async def get_state(self, _device):
        return dict(self.state)

    async def pair(self, _device, *, agent_mode, timeout):
        self.pair_calls += 1
        self.agent_events.append("pair_called_with_" + agent_mode)
        if self.pair_error:
            raise self.pair_error
        self.state.update(
            {
                "paired": True,
                "bonded": self.bonded,
                "connected": True,
            }
        )
        if self.trusted_after is not None:
            self.state["trusted"] = self.trusted_after

    async def cancel_pairing(self, _device):
        self.cancel_calls += 1
        if self.cancel_error:
            raise self.cancel_error

    async def disconnect(self, _device, *, timeout):
        self.disconnect_calls += 1
        if self.disconnect_ok:
            self.state["connected"] = False
            return True
        return False

    async def stop_discovery(self):
        self.stop_calls += 1
        if self.scanner_stop_error:
            raise self.scanner_stop_error

    async def close(self):
        if self.close_error:
            raise self.close_error


class PairingExecutorTests(unittest.TestCase):
    def run_case(self, backend, *, bond=True):
        p, a, auth_sha = plan(bond=bond)
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        out = root / "out"
        safety = root / "safety"
        final = asyncio.run(
            execute_pairing_plan(
                p,
                a,
                authorization_sha256=auth_sha,
                plan_sha256=hashlib.sha256(b"plan").hexdigest(),
                output_dir=out,
                safety_state_dir=safety,
                backend=backend,
            )
        )
        return final, out, safety

    def run_failure(self, backend, *, bond=True):
        p, a, auth_sha = plan(bond=bond)
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        out = root / "out"
        safety = root / "safety"
        with self.assertRaises(PairingExecutionError):
            asyncio.run(
                execute_pairing_plan(
                    p,
                    a,
                    authorization_sha256=auth_sha,
                    plan_sha256=hashlib.sha256(b"plan").hexdigest(),
                    output_dir=out,
                    safety_state_dir=safety,
                    backend=backend,
                )
            )
        return out, safety

    def test_success_records_pair_and_bond_without_trusting(self):
        backend = FakeBackend()
        final, out, safety = self.run_case(backend)
        self.assertTrue(final["complete"])
        self.assertEqual(backend.pair_calls, 1)
        self.assertEqual(backend.disconnect_calls, 1)
        self.assertTrue(final["state_after"]["paired"])
        self.assertTrue(final["state_after"]["bonded"])
        self.assertFalse(final["state_after"]["trusted"])
        self.assertFalse(final["state_after"]["connected"])
        self.assertEqual(final["safety_interlock"]["state"], "clear")
        self.assertFalse((safety / "active-run.json").exists())
        self.assertFalse((safety / "unsafe-stop.json").exists())
        session = json.loads((out / "pairing-session.json").read_text())
        self.assertEqual(session["status"], "completed")
        self.assertTrue(session["observed"]["paired_after"])
        self.assertTrue(session["observed"]["bonded_after"])


    def test_bluez_backend_refuses_pair_only_before_output(self):
        p, a, auth_sha = plan(bond=False)
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        backend = BlueZPairingBackend()
        with self.assertRaisesRegex(PairingExecutionError, "cannot guarantee pair-only"):
            asyncio.run(
                execute_pairing_plan(
                    p,
                    a,
                    authorization_sha256=auth_sha,
                    plan_sha256=hashlib.sha256(b"plan").hexdigest(),
                    output_dir=root / "out",
                    safety_state_dir=root / "safety",
                    backend=backend,
                )
            )
        self.assertFalse((root / "out").exists())
        self.assertFalse((root / "safety").exists())

    def test_pair_only_can_complete_without_bond(self):
        backend = FakeBackend(bonded=False)
        final, _, _ = self.run_case(backend, bond=False)
        self.assertTrue(final["complete"])
        self.assertTrue(final["state_after"]["paired"])
        self.assertFalse(final["state_after"]["bonded"])

    def test_unrequested_trusted_change_is_failure(self):
        out, safety = self.run_failure(FakeBackend(trusted_after=True))
        final = json.loads((out / "run-final.json").read_text())
        self.assertIn("Trusted state", final["error"])
        self.assertTrue(final["state_after"]["trusted"])
        self.assertEqual(final["safety_interlock"]["state"], "clear")
        self.assertFalse((safety / "unsafe-stop.json").exists())

    def test_requested_bond_not_observed_fails_but_cleans_safely(self):
        out, safety = self.run_failure(FakeBackend(bonded=False))
        final = json.loads((out / "run-final.json").read_text())
        self.assertIn("requested bond", final["error"])
        self.assertEqual(final["safety_interlock"]["state"], "clear")
        self.assertFalse((safety / "unsafe-stop.json").exists())

    def test_preexisting_pairing_fails_precondition_before_pair_call(self):
        backend = FakeBackend(
            before={
                "address": TARGET,
                "address_type": "public",
                "paired": True,
                "bonded": True,
                "trusted": False,
                "connected": False,
            }
        )
        out, safety = self.run_failure(backend)
        final = json.loads((out / "run-final.json").read_text())
        self.assertEqual(backend.pair_calls, 0)
        self.assertIn("Paired must be false", final["precondition_error"])
        self.assertEqual(final["safety_interlock"]["state"], "clear")
        self.assertFalse((safety / "unsafe-stop.json").exists())

    def test_target_not_found_fails_without_pairing(self):
        backend = FakeBackend(found=False)
        out, safety = self.run_failure(backend)
        final = json.loads((out / "run-final.json").read_text())
        self.assertFalse(final["pairing_attempted"])
        self.assertIn("target not found", final["error"])
        self.assertEqual(final["safety_interlock"]["state"], "clear")
        self.assertFalse((safety / "unsafe-stop.json").exists())

    def test_pair_failure_cancels_and_releases_when_cleanup_confirmed(self):
        backend = FakeBackend(pair_error=RuntimeError("pair rejected"))
        out, safety = self.run_failure(backend)
        final = json.loads((out / "run-final.json").read_text())
        self.assertEqual(backend.cancel_calls, 1)
        self.assertTrue(final["cleanup"]["cancel_pairing"]["completed"])
        self.assertEqual(final["safety_interlock"]["state"], "clear")
        self.assertFalse((safety / "unsafe-stop.json").exists())

    def test_cancel_failure_latches_recovery(self):
        backend = FakeBackend(
            pair_error=RuntimeError("pair timeout"),
            cancel_error=RuntimeError("cancel failed"),
        )
        out, safety = self.run_failure(backend)
        final = json.loads((out / "run-final.json").read_text())
        self.assertEqual(final["safety_interlock"]["state"], "recovery_required")
        self.assertTrue((safety / "unsafe-stop.json").exists())
        self.assertFalse((safety / "active-run.json").exists())

    def test_disconnect_failure_latches_recovery(self):
        backend = FakeBackend(disconnect_ok=False)
        out, safety = self.run_failure(backend)
        final = json.loads((out / "run-final.json").read_text())
        self.assertEqual(final["safety_interlock"]["state"], "recovery_required")
        self.assertTrue((safety / "unsafe-stop.json").exists())

    def test_scanner_stop_failure_latches_recovery(self):
        backend = FakeBackend(scanner_stop_error=RuntimeError("scanner stuck"))
        out, safety = self.run_failure(backend)
        final = json.loads((out / "run-final.json").read_text())
        self.assertEqual(final["safety_interlock"]["state"], "recovery_required")
        self.assertTrue((safety / "unsafe-stop.json").exists())

    def test_prepare_failure_is_before_rf_and_releases_interlock(self):
        backend = FakeBackend(prepare_error=RuntimeError("missing backend"))
        out, safety = self.run_failure(backend)
        final = json.loads((out / "run-final.json").read_text())
        self.assertFalse(final["rf_attempted"])
        self.assertEqual(final["safety_interlock"]["state"], "clear")
        self.assertFalse((safety / "active-run.json").exists())
        self.assertFalse((safety / "unsafe-stop.json").exists())

    def test_agent_events_are_metadata_only(self):
        backend = FakeBackend()
        final, _, _ = self.run_case(backend)
        self.assertEqual(final["agent_events"], ["pair_called_with_no_input_no_output"])

    def test_bluez_pair_calls_device1_pair_without_trust_set(self):
        backend = BlueZPairingBackend()
        backend.register_agent = mock.AsyncMock(return_value=None)
        backend._call = mock.AsyncMock(return_value=SimpleNamespace())
        device = SimpleNamespace(path="/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF")
        asyncio.run(
            backend.pair(device, agent_mode="no_input_no_output", timeout=1)
        )
        backend.register_agent.assert_awaited_once_with("no_input_no_output")
        backend._call.assert_awaited_once_with(
            path=device.path,
            interface="org.bluez.Device1",
            member="Pair",
        )

    def test_kamal_agent_registration_never_requests_default_agent(self):
        class FakeBus:
            def export(self, path, agent):
                self.exported = (path, agent)

            def unexport(self, path, agent):
                return None

        backend = BlueZPairingBackend()
        backend._bus = FakeBus()
        backend._ensure_bus = mock.AsyncMock(return_value=backend._bus)
        backend._make_no_io_agent = mock.Mock(return_value=object())
        backend._call = mock.AsyncMock(return_value=SimpleNamespace())
        asyncio.run(backend.register_agent("no_input_no_output"))
        calls = [item.kwargs["member"] for item in backend._call.await_args_list]
        self.assertEqual(calls, ["RegisterAgent"])
        self.assertNotIn("RequestDefaultAgent", calls)

    def test_no_io_agent_accepts_only_pairing_authorization(self):
        class FakeServiceInterface:
            def __init__(self, name):
                self.name = name

        class FakeDBusError(RuntimeError):
            def __init__(self, name, message):
                super().__init__(message)
                self.name = name

        def fake_method():
            def decorate(function):
                return function
            return decorate

        backend = BlueZPairingBackend()
        backend._service_interface = FakeServiceInterface
        backend._method = fake_method
        backend._dbus_error = FakeDBusError
        agent = backend._make_no_io_agent()

        self.assertIsNone(agent.RequestAuthorization("/device"))
        for method_name, args in (
            ("RequestPinCode", ("/device",)),
            ("DisplayPinCode", ("/device", "123456")),
            ("RequestPasskey", ("/device",)),
            ("DisplayPasskey", ("/device", 123456, 0)),
            ("RequestConfirmation", ("/device", 123456)),
            ("AuthorizeService", ("/device", "00001800-0000-1000-8000-00805f9b34fb")),
        ):
            with self.assertRaises(FakeDBusError):
                getattr(agent, method_name)(*args)

        self.assertEqual(
            backend.agent_events,
            [
                "pairing_authorization_accepted",
                "pin_code_requested_rejected",
                "pin_code_display_requested_rejected",
                "passkey_requested_rejected",
                "passkey_display_requested_rejected",
                "numeric_confirmation_rejected",
                "service_authorization_rejected",
            ],
        )

    def test_hash_mismatch_fails_before_output(self):
        p, a, _ = plan()
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        with self.assertRaises(Exception):
            asyncio.run(
                execute_pairing_plan(
                    p,
                    a,
                    authorization_sha256="f" * 64,
                    plan_sha256="2" * 64,
                    output_dir=root / "out",
                    safety_state_dir=root / "safety",
                    backend=FakeBackend(),
                )
            )
        self.assertFalse((root / "out").exists())


if __name__ == "__main__":
    unittest.main()
