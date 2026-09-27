"""Persistent safety interlock for active BLE GATT execution.

The safety directory is intentionally separate from per-run evidence.  It
serializes active execution, survives process crashes, and requires an explicit
operator recovery acknowledgement after an unsafe or orphaned run.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from kamal.evidence_contracts import AtomicCreateError, atomic_create_json

SAFETY_STATE_VERSION = "0.12.0"
ACTIVE_RUN_FILE = "active-run.json"
UNSAFE_STOP_FILE = "unsafe-stop.json"


class SafetyInterlockError(RuntimeError):
    """Raised when active BLE execution is blocked by safety state."""


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_nonempty(value, field):
    if not isinstance(value, str) or not value.strip():
        raise SafetyInterlockError(f"{field} must be a non-empty string")
    return value.strip()


def _sha256(value, field):
    value = _require_nonempty(value, field).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SafetyInterlockError(f"{field} must be a SHA-256 hexadecimal digest")
    return value


def _load_json_bytes(path):
    path = Path(path)
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SafetyInterlockError(f"invalid safety-state JSON at {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SafetyInterlockError(f"safety-state artifact at {path} must be an object")
    return payload, hashlib.sha256(raw).hexdigest()


def _fsync_directory(path):
    fd = os.open(Path(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _unlink_durable(path):
    path = Path(path)
    try:
        path.unlink()
    except FileNotFoundError:
        return
    _fsync_directory(path.parent)


def _state_paths(state_dir):
    state_dir = Path(state_dir).expanduser().resolve()
    return state_dir, state_dir / ACTIVE_RUN_FILE, state_dir / UNSAFE_STOP_FILE


def assert_execution_allowed(state_dir):
    """Fail closed if an unsafe latch or active/stale run already exists."""
    state_dir, active_path, unsafe_path = _state_paths(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    if unsafe_path.exists():
        raise SafetyInterlockError(
            f"active GATT execution blocked: recovery required for {unsafe_path}"
        )
    if active_path.exists():
        raise SafetyInterlockError(
            f"active GATT execution blocked: active or interrupted run recorded at {active_path}"
        )
    return state_dir


def acquire_active_run(
    state_dir,
    *,
    plan_id,
    plan_sha256,
    authorization_sha256,
    output_dir,
    targets,
):
    """Acquire a durable single-executor lease before RF activity."""
    state_dir = assert_execution_allowed(state_dir)
    active_path = state_dir / ACTIVE_RUN_FILE
    payload = {
        "schema_version": SAFETY_STATE_VERSION,
        "record_type": "gatt_active_run",
        "started_at_utc": _utc_now(),
        "plan_id": _require_nonempty(plan_id, "plan_id"),
        "plan_sha256": _sha256(plan_sha256, "plan_sha256"),
        "authorization_sha256": _sha256(
            authorization_sha256, "authorization_sha256"
        ),
        "output_dir": str(Path(output_dir).expanduser().resolve()),
        "targets": targets,
        "rf_started": False,
        "recovery_required_if_orphaned": True,
    }
    try:
        atomic_create_json(active_path, payload)
    except FileExistsError as exc:
        raise SafetyInterlockError(
            f"active GATT execution blocked by existing {active_path}"
        ) from exc
    except AtomicCreateError as exc:
        raise SafetyInterlockError(
            f"could not durably acquire active GATT safety lease: {exc}"
        ) from exc
    return payload


def replace_active_run(state_dir, payload):
    """Durably replace lease metadata before first RF activity.

    This is only used to change rf_started from false to true.  Replacement is
    deliberately implemented via a temporary same-directory file and rename;
    the lease path itself remains continuously present.
    """
    state_dir, active_path, unsafe_path = _state_paths(state_dir)
    if unsafe_path.exists():
        raise SafetyInterlockError("cannot update active run while unsafe latch exists")
    if not active_path.exists():
        raise SafetyInterlockError("active-run lease disappeared before RF activity")
    if not isinstance(payload, dict) or payload.get("record_type") != "gatt_active_run":
        raise SafetyInterlockError("invalid active-run payload")

    temporary = state_dir / f".{ACTIVE_RUN_FILE}.{os.getpid()}.tmp"
    if temporary.exists():
        raise SafetyInterlockError(f"temporary safety-state path already exists: {temporary}")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, active_path)
        _fsync_directory(state_dir)
    finally:
        temporary.unlink(missing_ok=True)


def mark_rf_started(state_dir):
    """Record that RF activity may have begun for the active run."""
    state_dir, active_path, _ = _state_paths(state_dir)
    payload, _ = _load_json_bytes(active_path)
    payload["rf_started"] = True
    payload["rf_started_at_utc"] = _utc_now()
    replace_active_run(state_dir, payload)
    return payload


def release_active_run(state_dir):
    """Release the active-run lease after cleanup is confirmed safe."""
    state_dir, active_path, unsafe_path = _state_paths(state_dir)
    if unsafe_path.exists():
        raise SafetyInterlockError("unsafe latch exists; active run cannot be released as safe")
    if not active_path.exists():
        raise SafetyInterlockError("active-run lease is missing; safety state cannot be confirmed clear")
    _unlink_durable(active_path)


def latch_unsafe_stop(
    state_dir,
    *,
    plan_id,
    reason,
    cleanup,
    output_dir,
    current_target=None,
):
    """Persist a recovery-required latch before releasing the active lease."""
    state_dir, active_path, unsafe_path = _state_paths(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)

    active_sha256 = None
    active_payload = None
    if active_path.exists():
        active_payload, active_sha256 = _load_json_bytes(active_path)

    payload = {
        "schema_version": SAFETY_STATE_VERSION,
        "record_type": "gatt_unsafe_stop",
        "latched_at_utc": _utc_now(),
        "plan_id": _require_nonempty(plan_id, "plan_id"),
        "reason": _require_nonempty(reason, "reason"),
        "cleanup": cleanup,
        "output_dir": str(Path(output_dir).expanduser().resolve()),
        "current_target": current_target,
        "active_run_sha256": active_sha256,
        "rf_started": bool((active_payload or {}).get("rf_started")),
        "recovery_required": True,
    }

    if not unsafe_path.exists():
        try:
            atomic_create_json(unsafe_path, payload)
        except AtomicCreateError as exc:
            # If publication happened, the unsafe latch is still authoritative.
            if not exc.published:
                raise SafetyInterlockError(
                    f"failed to publish unsafe-stop latch; active-run lease retained: {exc}"
                ) from exc
    # Only remove the active lease after an unsafe latch is visibly present.
    if unsafe_path.exists():
        _unlink_durable(active_path)
    return payload


def _validate_recovery_request(request):
    if not isinstance(request, dict):
        raise SafetyInterlockError("recovery request must be an object")
    allowed = {
        "schema_version",
        "record_type",
        "recovery_id",
        "operator",
        "confirmed_at_utc",
        "basis",
        "confirmations",
        "evidence",
    }
    unknown = sorted(set(request) - allowed)
    if unknown:
        raise SafetyInterlockError(
            "recovery request contains unsupported fields: " + ", ".join(unknown)
        )
    if request.get("schema_version") != SAFETY_STATE_VERSION:
        raise SafetyInterlockError("unsupported recovery request schema_version")
    if request.get("record_type") != "gatt_safety_recovery_request":
        raise SafetyInterlockError(
            "recovery request record_type must be gatt_safety_recovery_request"
        )
    normalized = {
        "schema_version": SAFETY_STATE_VERSION,
        "record_type": "gatt_safety_recovery_request",
        "recovery_id": _require_nonempty(request.get("recovery_id"), "recovery_id"),
        "operator": _require_nonempty(request.get("operator"), "operator"),
        "confirmed_at_utc": _require_nonempty(
            request.get("confirmed_at_utc"), "confirmed_at_utc"
        ),
        "basis": _require_nonempty(request.get("basis"), "basis"),
    }
    try:
        confirmed = datetime.fromisoformat(
            normalized["confirmed_at_utc"].replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise SafetyInterlockError("confirmed_at_utc must be ISO-8601 UTC") from exc
    if not normalized["confirmed_at_utc"].endswith("Z") or confirmed.utcoffset() != timezone.utc.utcoffset(confirmed):
        raise SafetyInterlockError("confirmed_at_utc must use UTC and end with Z")

    confirmations = request.get("confirmations")
    required_confirmations = {
        "no_active_ble_session": True,
        "target_state_reviewed": True,
    }
    if confirmations != required_confirmations:
        raise SafetyInterlockError(
            "recovery confirmations must explicitly confirm no_active_ble_session and target_state_reviewed"
        )
    evidence = request.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise SafetyInterlockError("recovery evidence must contain at least one reference")
    normalized["confirmations"] = dict(required_confirmations)
    normalized["evidence"] = [
        _require_nonempty(item, "recovery evidence") for item in evidence
    ]
    return normalized


def resolve_interlock(state_dir, request, *, request_sha256):
    """Record explicit operator recovery and clear a blocking safety latch.

    This function does not inspect hardware.  It only records the operator's
    explicit confirmation that recovery has already been performed and reviewed.
    """
    state_dir, active_path, unsafe_path = _state_paths(state_dir)
    request = _validate_recovery_request(request)
    request_sha256 = _sha256(request_sha256, "request_sha256")

    if unsafe_path.exists():
        source_path = unsafe_path
        source_kind = "unsafe_stop"
    elif active_path.exists():
        source_path = active_path
        source_kind = "orphaned_active_run"
    else:
        raise SafetyInterlockError("no active or unsafe GATT safety interlock exists")

    source_payload, source_sha256 = _load_json_bytes(source_path)
    artifact = {
        "schema_version": SAFETY_STATE_VERSION,
        "record_type": "gatt_safety_recovery",
        "resolved_at_utc": _utc_now(),
        "source_kind": source_kind,
        "source_sha256": source_sha256,
        "source_record_type": source_payload.get("record_type"),
        "request_sha256": request_sha256,
        "recovery": request,
        "limitations": [
            "K'amal does not independently verify the physical recovery statements in this artifact.",
            "Clearing the interlock records operator acknowledgement; it does not prove device state.",
        ],
    }
    resolutions = state_dir / "resolutions"
    resolutions.mkdir(parents=True, exist_ok=True)
    resolution_path = resolutions / f"{source_sha256}.json"
    if resolution_path.exists():
        existing, _ = _load_json_bytes(resolution_path)
        if existing.get("source_sha256") != source_sha256 or existing.get("request_sha256") != request_sha256:
            raise SafetyInterlockError(
                f"existing recovery artifact conflicts with request: {resolution_path}"
            )
    else:
        atomic_create_json(resolution_path, artifact)

    # Remove active first; if interrupted, the primary unsafe latch remains and
    # the same recovery artifact can be reused on retry.
    _unlink_durable(active_path)
    _unlink_durable(unsafe_path)
    return artifact, resolution_path
