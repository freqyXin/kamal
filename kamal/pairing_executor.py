"""Explicit, authorized Bluetooth pairing execution for BlueZ/Linux.

Pairing is intentionally separate from the GATT executor.  The implementation
calls BlueZ ``org.bluez.Device1.Pair`` directly rather than using Bleak's
pairing convenience path, because Bleak's BlueZ backend also sets ``Trusted``
before pairing.  K'amal records ``Trusted`` but does not mutate it here.
"""

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from kamal.bluetooth_security import validate_pairing_session
from kamal.evidence_contracts import atomic_create_json
from kamal.gatt_safety import (
    SafetyInterlockError,
    acquire_active_run,
    latch_unsafe_stop,
    mark_rf_started,
    release_active_run,
)
from kamal.pairing_contracts import (
    PairingContractError,
    validate_pairing_plan,
)


PAIRING_EXECUTOR_VERSION = "0.12.0"


class PairingExecutionError(RuntimeError):
    """Raised after pairing evidence is persisted for an unsuccessful run."""


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _artifact_ref(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }


def _safe_error(exc):
    text = str(exc).strip()
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _target_payload(plan):
    return {
        "address": plan["target"]["address"],
        "address_type": plan["target"]["address_type"],
    }


def _normalize_live_state(value):
    value = value or {}
    return {
        "address": value.get("address"),
        "address_type": value.get("address_type"),
        "paired": value.get("paired"),
        "bonded": value.get("bonded"),
        "trusted": value.get("trusted"),
        "connected": value.get("connected"),
    }


def _pairing_session(plan, auth, *, started, completed, status, before, after, evidence, limitations):
    before = _normalize_live_state(before)
    after = _normalize_live_state(after)
    raw = {
        "schema_version": PAIRING_EXECUTOR_VERSION,
        "record_type": "bluetooth_pairing_session",
        "pairing_session_id": plan["pairing_session_id"],
        "engagement_id": auth["engagement_id"],
        "authorization_ref": auth["authorization_id"],
        "target": _target_payload(plan),
        "started_at_utc": started,
        "completed_at_utc": completed,
        "status": status,
        "requested": dict(plan["requested"]),
        "observed": {
            "paired_before": before["paired"],
            "bonded_before": before["bonded"],
            "trusted_before": before["trusted"],
            "paired_after": after["paired"],
            "bonded_after": after["bonded"],
            "trusted_after": after["trusted"],
            "connected_after": after["connected"],
            "encrypted_after": None,
        },
        "security": {
            "authenticated": None,
            "secure_connections": None,
            "encryption_size": None,
            "association_model": None,
        },
        "evidence": list(evidence),
        "limitations": list(limitations),
    }
    return validate_pairing_session(raw)


class BlueZPairingBackend:
    """Lazy BlueZ backend using Bleak only for live discovery.

    Pairing itself is a direct Device1.Pair D-Bus call.  The optional K'amal
    NoInputNoOutput agent is registered on the same D-Bus connection as the
    Pair call so it is application-scoped; it is not made the system default.
    """

    AGENT_PATH = "/org/kamal/PairingAgent"

    supports_pair_without_bond = False

    def __init__(self):
        self._scanner_class = None
        self._scanner = None
        self._bus_class = None
        self._bus_type = None
        self._message = None
        self._message_type = None
        self._service_interface = None
        self._method = None
        self._dbus_error = None
        self._bus = None
        self._agent = None
        self._agent_events = []

    def prepare(self):
        """Load runtime dependencies without initiating RF or D-Bus mutation."""
        if self._scanner_class is not None:
            return
        from bleak import BleakScanner
        from dbus_fast import Message
        from dbus_fast.aio import MessageBus
        from dbus_fast.constants import BusType, MessageType
        from dbus_fast.errors import DBusError
        from dbus_fast.service import ServiceInterface
        try:
            from dbus_fast.service import dbus_method as method
        except ImportError:  # dbus-fast < 2.46 compatibility
            from dbus_fast.service import method

        self._scanner_class = BleakScanner
        self._bus_class = MessageBus
        self._bus_type = BusType
        self._message = Message
        self._message_type = MessageType
        self._service_interface = ServiceInterface
        self._method = method
        self._dbus_error = DBusError

    async def discover(self, address, adapter, timeout):
        self.prepare()
        wanted = address.upper()
        event = asyncio.Event()
        holder = {}

        def detected(device, advertisement):
            if device.address.upper() == wanted and "device" not in holder:
                holder["device"] = device
                holder["advertisement"] = advertisement
                event.set()

        self._scanner = self._scanner_class(
            detection_callback=detected,
            bluez={"adapter": adapter},
        )
        await self._scanner.start()
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        device = holder["device"]
        details = getattr(device, "details", None) or {}
        path = details.get("path")
        if not isinstance(path, str) or not path.startswith("/org/bluez/"):
            raise PairingExecutionError("discovered target does not expose a BlueZ Device1 path")
        return SimpleNamespace(
            address=device.address.upper(),
            path=path,
            device=device,
            advertisement=holder.get("advertisement"),
        )

    async def stop_discovery(self):
        if self._scanner is None:
            return
        scanner = self._scanner
        self._scanner = None
        await scanner.stop()

    async def _ensure_bus(self):
        self.prepare()
        if self._bus is None:
            self._bus = await self._bus_class(bus_type=self._bus_type.SYSTEM).connect()
        return self._bus

    async def _call(self, *, path, interface, member, signature=None, body=None, tolerate=()):
        bus = await self._ensure_bus()
        kwargs = {
            "destination": "org.bluez",
            "path": path,
            "interface": interface,
            "member": member,
        }
        if signature is not None:
            kwargs["signature"] = signature
        if body is not None:
            kwargs["body"] = body
        reply = await bus.call(self._message(**kwargs))
        if reply.message_type == self._message_type.ERROR:
            name = reply.error_name or "org.bluez.Error.Failed"
            if name in tolerate:
                return reply
            detail = reply.body[0] if reply.body else name
            raise PairingExecutionError(f"BlueZ D-Bus error {name}: {detail}")
        return reply

    def _make_no_io_agent(self):
        ServiceInterface = self._service_interface
        method = self._method
        DBusError = self._dbus_error
        events = self._agent_events

        class KamalNoInputNoOutputAgent(ServiceInterface):
            def __init__(self):
                super().__init__("org.bluez.Agent1")

            @method()
            def Release(self):
                events.append("release")

            @method()
            def RequestPinCode(self, device: "o") -> "s":
                events.append("pin_code_requested_rejected")
                raise DBusError(
                    "org.bluez.Error.Rejected",
                    "K'amal NoInputNoOutput agent cannot supply a PIN code",
                )

            @method()
            def DisplayPinCode(self, device: "o", pincode: "s"):
                events.append("pin_code_display_requested_rejected")
                raise DBusError(
                    "org.bluez.Error.Rejected",
                    "K'amal NoInputNoOutput agent cannot display a PIN code",
                )

            @method()
            def RequestPasskey(self, device: "o") -> "u":
                events.append("passkey_requested_rejected")
                raise DBusError(
                    "org.bluez.Error.Rejected",
                    "K'amal NoInputNoOutput agent cannot supply a passkey",
                )

            @method()
            def DisplayPasskey(self, device: "o", passkey: "u", entered: "q"):
                events.append("passkey_display_requested_rejected")
                raise DBusError(
                    "org.bluez.Error.Rejected",
                    "K'amal NoInputNoOutput agent cannot display a passkey",
                )

            @method()
            def RequestConfirmation(self, device: "o", passkey: "u"):
                events.append("numeric_confirmation_rejected")
                raise DBusError(
                    "org.bluez.Error.Rejected",
                    "K'amal NoInputNoOutput agent cannot confirm a displayed number",
                )

            @method()
            def RequestAuthorization(self, device: "o"):
                events.append("pairing_authorization_accepted")

            @method()
            def AuthorizeService(self, device: "o", uuid: "s"):
                events.append("service_authorization_rejected")
                raise DBusError(
                    "org.bluez.Error.Rejected",
                    "K'amal pairing authorization does not authorize service access",
                )

            @method()
            def Cancel(self):
                events.append("cancel")

        return KamalNoInputNoOutputAgent()

    async def register_agent(self, mode):
        self._agent_events = []
        if mode == "external_default":
            return
        if mode != "no_input_no_output":
            raise PairingExecutionError(f"unsupported agent mode: {mode}")
        bus = await self._ensure_bus()
        self._agent = self._make_no_io_agent()
        bus.export(self.AGENT_PATH, self._agent)
        try:
            await self._call(
                path="/org/bluez",
                interface="org.bluez.AgentManager1",
                member="RegisterAgent",
                signature="os",
                body=[self.AGENT_PATH, "NoInputNoOutput"],
            )
        except Exception:
            bus.unexport(self.AGENT_PATH, self._agent)
            self._agent = None
            raise

    async def unregister_agent(self):
        if self._agent is None:
            return
        agent = self._agent
        self._agent = None
        try:
            await self._call(
                path="/org/bluez",
                interface="org.bluez.AgentManager1",
                member="UnregisterAgent",
                signature="o",
                body=[self.AGENT_PATH],
                tolerate=("org.bluez.Error.DoesNotExist",),
            )
        finally:
            if self._bus is not None:
                self._bus.unexport(self.AGENT_PATH, agent)

    async def get_state(self, device):
        reply = await self._call(
            path=device.path,
            interface="org.freedesktop.DBus.Properties",
            member="GetAll",
            signature="s",
            body=["org.bluez.Device1"],
        )
        values = reply.body[0] if reply.body else {}

        def val(name):
            item = values.get(name)
            return None if item is None else item.value

        address_type = val("AddressType")
        if isinstance(address_type, str):
            address_type = address_type.lower()
        return {
            "address": val("Address"),
            "address_type": address_type,
            "paired": val("Paired"),
            "bonded": val("Bonded"),
            "trusted": val("Trusted"),
            "connected": val("Connected"),
        }

    async def pair(self, device, *, agent_mode, timeout):
        await self.register_agent(agent_mode)
        await asyncio.wait_for(
            self._call(
                path=device.path,
                interface="org.bluez.Device1",
                member="Pair",
            ),
            timeout=timeout,
        )

    async def cancel_pairing(self, device):
        await self._call(
            path=device.path,
            interface="org.bluez.Device1",
            member="CancelPairing",
            tolerate=("org.bluez.Error.DoesNotExist",),
        )

    async def disconnect(self, device, *, timeout):
        state = await self.get_state(device)
        if state.get("connected") is False:
            return True
        await asyncio.wait_for(
            self._call(
                path=device.path,
                interface="org.bluez.Device1",
                member="Disconnect",
                tolerate=("org.bluez.Error.NotConnected",),
            ),
            timeout=timeout,
        )
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            state = await self.get_state(device)
            if state.get("connected") is False:
                return True
            if asyncio.get_running_loop().time() >= deadline:
                return False
            await asyncio.sleep(0.1)

    @property
    def agent_events(self):
        return list(self._agent_events)

    async def close(self):
        errors = []
        try:
            await self.unregister_agent()
        except Exception as exc:  # best-effort cleanup; caller records uncertainty
            errors.append(_safe_error(exc))
        if self._bus is not None:
            bus = self._bus
            self._bus = None
            try:
                bus.disconnect()
            except Exception as exc:
                errors.append(_safe_error(exc))
        if errors:
            raise PairingExecutionError("; ".join(errors))


def _verify_plan(plan, authorization, authorization_sha256):
    normalized, auth = validate_pairing_plan(
        plan,
        authorization,
        authorization_sha256=authorization_sha256,
    )
    if normalized != plan:
        raise PairingExecutionError("pairing plan is not in canonical validated form")
    return auth


async def execute_pairing_plan(
    plan,
    authorization,
    *,
    authorization_sha256,
    plan_sha256,
    output_dir,
    safety_state_dir,
    adapter="hci0",
    backend=None,
):
    """Execute one exact pairing plan and persist conservative evidence."""
    auth = _verify_plan(plan, authorization, authorization_sha256)
    if not isinstance(plan_sha256, str) or len(plan_sha256) != 64:
        raise PairingExecutionError("plan_sha256 must be a SHA-256 hexadecimal digest")
    try:
        int(plan_sha256, 16)
    except ValueError as exc:
        raise PairingExecutionError("plan_sha256 must be a SHA-256 hexadecimal digest") from exc

    if not isinstance(adapter, str) or not adapter.strip():
        raise PairingExecutionError("adapter must be a non-empty string")

    backend = backend or BlueZPairingBackend()
    if (
        plan["requested"]["bond"] is False
        and not bool(getattr(backend, "supports_pair_without_bond", False))
    ):
        raise PairingExecutionError(
            "selected pairing backend cannot guarantee pair-only execution; "
            "request_bond=true with establish_bond authorization is required"
        )

    out = Path(output_dir).expanduser().resolve()
    state_dir = Path(safety_state_dir).expanduser().resolve()
    if out.exists():
        raise PairingExecutionError(f"output directory already exists: {out}")
    out.mkdir(parents=True)

    started = utc_now()
    target = _target_payload(plan)
    acquire_active_run(
        state_dir,
        plan_id=plan["plan_id"],
        plan_sha256=plan_sha256,
        authorization_sha256=authorization_sha256,
        output_dir=out,
        targets=[target],
    )

    run_start = {
        "schema_version": PAIRING_EXECUTOR_VERSION,
        "record_type": "bluetooth_pairing_run_start",
        "plan_id": plan["plan_id"],
        "pairing_session_id": plan["pairing_session_id"],
        "started_at_utc": started,
        "target": target,
        "authorization_id": auth["authorization_id"],
        "authorization_sha256": authorization_sha256,
        "plan_sha256": plan_sha256.lower(),
        "adapter": adapter.strip(),
        "agent_mode": plan["agent_mode"],
        "requested": dict(plan["requested"]),
        "rf_started_at_publication": False,
        "safety_state_dir": str(state_dir),
        "shared_interlock_compatibility": (
            "v0.12 pairing reuses the existing active-run.json/unsafe-stop.json "
            "BLE safety lease so pairing and active GATT cannot overlap"
        ),
    }
    atomic_create_json(out / "run-start.json", run_start)

    rf_started = False
    device = None
    before = {}
    after = {}
    pairing_attempted = False
    pairing_call_completed = False
    pairing_error = None
    precondition_error = None
    cancel_attempted = False
    cancel_completed = None
    disconnect_attempted = False
    disconnect_completed = None
    scanner_stop_attempted = False
    scanner_stop_completed = None
    backend_close_completed = None
    agent_events = []
    unsafe_reason = None
    session_status = "failed"
    limitations = [
        "BlueZ Device1 Paired/Bonded properties are host-observed state and do not establish the SMP association model.",
        "Secure Connections, MITM/authentication status, encryption size, and OTA packet semantics require separate evidence.",
        "Pairing may cause the target identity address to replace a pre-pair resolvable private address.",
    ]
    evidence = [f"plan-sha256:{plan_sha256.lower()}"]

    try:
        backend.prepare()

        mark_rf_started(state_dir)
        rf_started = True
        device = await backend.discover(
            plan["target"]["address"],
            adapter.strip(),
            plan["timeouts"]["discovery_seconds"],
        )
        if device is None:
            pairing_error = "target not found during bounded pairing discovery"
        else:
            before = await backend.get_state(device)
            evidence.append("bluez-dbus:pre-pair-state")
            if (
                plan["preconditions"]["require_unpaired_before"]
                and before.get("paired") is not False
            ):
                precondition_error = (
                    "pairing precondition failed: Paired must be false before execution"
                )
            elif (
                plan["preconditions"]["require_unbonded_before"]
                and before.get("bonded") is not False
            ):
                precondition_error = (
                    "pairing precondition failed: Bonded must be false before execution"
                )
            else:
                pairing_attempted = True
                try:
                    await backend.pair(
                        device,
                        agent_mode=plan["agent_mode"],
                        timeout=plan["timeouts"]["pairing_seconds"],
                    )
                    pairing_call_completed = True
                except Exception as exc:
                    pairing_error = _safe_error(exc)
                    cancel_attempted = True
                    try:
                        await backend.cancel_pairing(device)
                        cancel_completed = True
                    except Exception as cancel_exc:
                        cancel_completed = False
                        unsafe_reason = (
                            "pairing failed and CancelPairing cleanup was not confirmed: "
                            + _safe_error(cancel_exc)
                        )

                try:
                    after = await backend.get_state(device)
                    evidence.append("bluez-dbus:post-pair-state")
                except Exception as state_exc:
                    if pairing_error is None:
                        pairing_error = "post-pair state unavailable: " + _safe_error(state_exc)
                    if pairing_attempted:
                        unsafe_reason = unsafe_reason or (
                            "pairing was attempted but post-pair BlueZ state could not be confirmed"
                        )

                if pairing_error is None:
                    if after.get("paired") is not True:
                        pairing_error = "BlueZ Pair returned without Paired=true"
                    elif plan["requested"]["bond"] and after.get("bonded") is not True:
                        pairing_error = (
                            "pairing completed but requested bond was not observed as Bonded=true"
                        )
                    elif (
                        before.get("trusted") is not None
                        and after.get("trusted") != before.get("trusted")
                    ):
                        pairing_error = (
                            "pairing changed BlueZ Trusted state without trust authorization"
                        )
                    else:
                        session_status = "completed"

        if device is not None:
            try:
                current = await backend.get_state(device)
            except Exception:
                current = after
            if current.get("connected") is not False:
                disconnect_attempted = True
                try:
                    disconnect_completed = await backend.disconnect(
                        device,
                        timeout=plan["timeouts"]["disconnect_seconds"],
                    )
                except Exception as exc:
                    disconnect_completed = False
                    unsafe_reason = unsafe_reason or (
                        "post-pair disconnect cleanup failed: " + _safe_error(exc)
                    )
                if disconnect_completed is not True:
                    unsafe_reason = unsafe_reason or (
                        "post-pair disconnect could not be confirmed"
                    )
            else:
                disconnect_completed = True

            try:
                after = await backend.get_state(device)
                if "bluez-dbus:post-cleanup-state" not in evidence:
                    evidence.append("bluez-dbus:post-cleanup-state")
            except Exception:
                if pairing_attempted:
                    unsafe_reason = unsafe_reason or (
                        "final BlueZ state could not be confirmed after pairing attempt"
                    )

    except Exception as exc:
        if pairing_error is None and precondition_error is None:
            pairing_error = _safe_error(exc)
        if rf_started and pairing_attempted:
            unsafe_reason = unsafe_reason or (
                "unexpected executor failure after pairing may have changed remote security state"
            )
    finally:
        scanner_stop_attempted = True
        try:
            await backend.stop_discovery()
            scanner_stop_completed = True
        except Exception as exc:
            scanner_stop_completed = False
            if rf_started:
                unsafe_reason = unsafe_reason or (
                    "pairing discovery scanner cleanup failed: " + _safe_error(exc)
                )
        try:
            agent_events = list(getattr(backend, "agent_events", []))
        except Exception:
            agent_events = []
        try:
            await backend.close()
            backend_close_completed = True
        except Exception as exc:
            backend_close_completed = False
            if rf_started:
                unsafe_reason = unsafe_reason or (
                    "pairing D-Bus/agent cleanup failed: " + _safe_error(exc)
                )

    completed = utc_now()
    terminal_error = precondition_error or pairing_error
    if terminal_error and session_status == "completed":
        session_status = "failed"
    if session_status == "completed" and disconnect_completed is not True:
        session_status = "failed"
        terminal_error = terminal_error or "disconnect cleanup was not confirmed"

    session = _pairing_session(
        plan,
        auth,
        started=started,
        completed=completed,
        status=session_status,
        before=before,
        after=after,
        evidence=evidence,
        limitations=limitations,
    )
    atomic_create_json(out / "pairing-session.json", session)

    cleanup = {
        "cancel_pairing": {
            "attempted": cancel_attempted,
            "completed": cancel_completed,
        },
        "disconnect": {
            "attempted": disconnect_attempted,
            "completed": disconnect_completed,
        },
        "scanner_stop": {
            "attempted": scanner_stop_attempted,
            "completed": scanner_stop_completed,
        },
        "backend_close": {"completed": backend_close_completed},
    }

    safety_state = "clear"
    if unsafe_reason is not None:
        safety_state = "recovery_required"
        latch_unsafe_stop(
            state_dir,
            plan_id=plan["plan_id"],
            reason=unsafe_reason,
            cleanup=cleanup,
            output_dir=out,
            current_target=target,
        )
    else:
        try:
            release_active_run(state_dir)
        except SafetyInterlockError as exc:
            safety_state = "recovery_required"
            unsafe_reason = "safety lease could not be confirmed clear: " + _safe_error(exc)
            latch_unsafe_stop(
                state_dir,
                plan_id=plan["plan_id"],
                reason=unsafe_reason,
                cleanup=cleanup,
                output_dir=out,
                current_target=target,
            )

    final = {
        "schema_version": PAIRING_EXECUTOR_VERSION,
        "record_type": "bluetooth_pairing_run_final",
        "plan_id": plan["plan_id"],
        "pairing_session_id": plan["pairing_session_id"],
        "started_at_utc": started,
        "completed_at_utc": completed,
        "target": target,
        "requested": dict(plan["requested"]),
        "agent_mode": plan["agent_mode"],
        "rf_attempted": rf_started,
        "pairing_attempted": pairing_attempted,
        "pairing_call_completed": pairing_call_completed,
        "precondition_error": precondition_error,
        "error": terminal_error,
        "state_before": _normalize_live_state(before),
        "state_after": _normalize_live_state(after),
        "agent_events": agent_events,
        "cleanup": cleanup,
        "pairing_session": _artifact_ref(out / "pairing-session.json"),
        "safety_interlock": {
            "state_dir": str(state_dir),
            "state": safety_state,
            "reason": unsafe_reason,
        },
        "complete": session_status == "completed" and safety_state == "clear",
        "limitations": limitations,
    }
    atomic_create_json(out / "run-final.json", final)

    # run-start.json is intentionally immutable and records the state at
    # publication. run-final.json is authoritative for whether RF actually began.
    if not final["complete"]:
        reason = terminal_error or unsafe_reason or "pairing execution did not complete"
        raise PairingExecutionError(reason)
    return final


def load_pairing_execution_inputs(plan_path, authorization_path):
    """Load exact JSON source bytes and return payloads plus SHA-256 digests."""
    def load(path):
        path = Path(path).expanduser().resolve()
        raw = path.read_bytes()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise PairingExecutionError(f"JSON source must be an object: {path}")
        return value, hashlib.sha256(raw).hexdigest(), path

    plan, plan_sha, plan_path = load(plan_path)
    auth, auth_sha, auth_path = load(authorization_path)
    return plan, plan_sha, plan_path, auth, auth_sha, auth_path
