"""Pure authorization and planning contracts for explicit Bluetooth pairing.

This module performs validation and plan construction only.  It deliberately
has no Bluetooth, D-Bus, packet-capture, or networking dependency.
"""

from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime, timezone


PAIRING_CONTRACT_VERSION = "0.12.0"
PAIRING_OPERATION = "pair_target"
BOND_OPERATION = "establish_bond"
PAIRING_AUTHORIZED_OPERATIONS = frozenset({PAIRING_OPERATION, BOND_OPERATION})
PAIRING_AGENT_MODES = frozenset({"external_default", "no_input_no_output"})

HARD_MAX_DISCOVERY_SECONDS = 30
HARD_MAX_PAIRING_SECONDS = 120
HARD_MAX_DISCONNECT_SECONDS = 15

_ADDRESS_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_SHA256_RE = re.compile(r"^[0-9A-Fa-f]{64}$")

_AUTH_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "authorization_id",
        "engagement_id",
        "owner",
        "operator",
        "location",
        "issued_at_utc",
        "not_before_utc",
        "expires_at_utc",
        "target",
        "allowed_operations",
        "constraints",
        "approval",
    }
)
_TARGET_FIELDS = frozenset({"protocol", "address", "address_type", "label"})
_CONSTRAINT_FIELDS = frozenset(
    {
        "max_attempts",
        "max_discovery_seconds",
        "max_pairing_seconds",
        "max_disconnect_seconds",
        "require_disconnect_after",
        "require_unpaired_before",
        "require_unbonded_before",
        "allowed_agent_modes",
    }
)
_APPROVAL_FIELDS = frozenset({"approver", "approved_at_utc", "basis"})
_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "plan_id",
        "pairing_session_id",
        "target",
        "request_bond",
        "agent_mode",
        "timeouts",
    }
)
_REQUEST_TARGET_FIELDS = frozenset({"address", "address_type"})
_TIMEOUT_FIELDS = frozenset({"discovery_seconds", "pairing_seconds", "disconnect_seconds"})
_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "plan_id",
        "pairing_session_id",
        "created_at_utc",
        "authorization",
        "request",
        "target",
        "requested",
        "agent_mode",
        "timeouts",
        "preconditions",
        "cleanup",
        "execution",
    }
)


class PairingContractError(ValueError):
    """Raised when pairing authorization or plan data fails closed."""


def _object(value, field):
    if not isinstance(value, dict):
        raise PairingContractError(f"{field} must be an object")
    return value


def _list(value, field):
    if not isinstance(value, list):
        raise PairingContractError(f"{field} must be an array")
    return value


def _reject_unknown(value, allowed, field):
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise PairingContractError(
            f"{field} contains unsupported field(s): {', '.join(unknown)}"
        )


def _nonempty(value, field):
    if not isinstance(value, str) or not value.strip():
        raise PairingContractError(f"{field} must be a non-empty string")
    return value.strip()


def _boolean(value, field):
    if not isinstance(value, bool):
        raise PairingContractError(f"{field} must be a boolean")
    return value


def _bounded_int(value, field, *, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        raise PairingContractError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise PairingContractError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return value


def _sha256(value, field):
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise PairingContractError(f"{field} must be a SHA-256 hexadecimal digest")
    return value.lower()


def _parse_utc(value, field):
    text = _nonempty(value, field)
    if not text.endswith("Z"):
        raise PairingContractError(f"{field} must use UTC and end with Z")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise PairingContractError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise PairingContractError(f"{field} must use UTC")
    return parsed, parsed.isoformat().replace("+00:00", "Z")


def _now(at_utc):
    if at_utc is None:
        return datetime.now(timezone.utc)
    if isinstance(at_utc, datetime):
        if at_utc.tzinfo is None or at_utc.utcoffset() != timezone.utc.utcoffset(at_utc):
            raise PairingContractError("at_utc must be timezone-aware UTC")
        return at_utc
    parsed, _ = _parse_utc(at_utc, "at_utc")
    return parsed


def _address(value, field):
    text = _nonempty(value, field)
    if not _ADDRESS_RE.fullmatch(text):
        raise PairingContractError(f"{field} must be a colon-delimited BLE address")
    return text.upper()


def _address_type(value, field):
    text = _nonempty(value, field).lower()
    if text not in {"public", "random", "unknown"}:
        raise PairingContractError(f"{field} must be public, random, or unknown")
    return text


def _target(value, field, *, allow_label):
    value = _object(value, field)
    _reject_unknown(value, _TARGET_FIELDS if allow_label else _REQUEST_TARGET_FIELDS, field)
    protocol = value.get("protocol", "ble") if allow_label else "ble"
    if protocol != "ble":
        raise PairingContractError(f"{field}.protocol must be ble")
    normalized = {
        "protocol": "ble",
        "address": _address(value.get("address"), f"{field}.address"),
        "address_type": _address_type(value.get("address_type"), f"{field}.address_type"),
    }
    if allow_label and "label" in value:
        normalized["label"] = _nonempty(value["label"], f"{field}.label")
    return normalized


def _target_key(value):
    return value["address"], value["address_type"]


def validate_pairing_authorization(authorization, *, at_utc=None):
    """Validate an exact-target authorization for state-changing pairing work."""
    authorization = _object(authorization, "authorization")
    _reject_unknown(authorization, _AUTH_FIELDS, "authorization")
    missing = sorted(_AUTH_FIELDS - set(authorization))
    if missing:
        raise PairingContractError(
            "authorization missing required field(s): " + ", ".join(missing)
        )
    if authorization["schema_version"] != PAIRING_CONTRACT_VERSION:
        raise PairingContractError(
            f"authorization.schema_version must be {PAIRING_CONTRACT_VERSION}"
        )
    if authorization["record_type"] != "bluetooth_pairing_authorization":
        raise PairingContractError(
            "authorization.record_type must be bluetooth_pairing_authorization"
        )

    issued, issued_text = _parse_utc(authorization["issued_at_utc"], "authorization.issued_at_utc")
    not_before, not_before_text = _parse_utc(authorization["not_before_utc"], "authorization.not_before_utc")
    expires, expires_text = _parse_utc(authorization["expires_at_utc"], "authorization.expires_at_utc")
    if not issued <= not_before < expires:
        raise PairingContractError(
            "authorization validity must satisfy issued_at_utc <= not_before_utc < expires_at_utc"
        )
    now = _now(at_utc)
    if now < not_before:
        raise PairingContractError("authorization is not yet valid")
    if now >= expires:
        raise PairingContractError("authorization is expired")

    target = _target(authorization["target"], "authorization.target", allow_label=True)
    if target["address_type"] == "unknown":
        raise PairingContractError(
            "pairing authorization requires an explicit public or random address_type"
        )

    raw_operations = _list(authorization["allowed_operations"], "authorization.allowed_operations")
    if not raw_operations:
        raise PairingContractError("authorization.allowed_operations must not be empty")
    operations = []
    seen = set()
    for index, item in enumerate(raw_operations):
        item = _nonempty(item, f"authorization.allowed_operations[{index}]")
        if item not in PAIRING_AUTHORIZED_OPERATIONS:
            raise PairingContractError(f"unsupported pairing operation class: {item}")
        if item in seen:
            raise PairingContractError(
                "authorization.allowed_operations contains duplicate operation"
            )
        seen.add(item)
        operations.append(item)
    if PAIRING_OPERATION not in seen:
        raise PairingContractError("pair_target must be explicitly authorized")

    constraints = _object(authorization["constraints"], "authorization.constraints")
    _reject_unknown(constraints, _CONSTRAINT_FIELDS, "authorization.constraints")
    missing = sorted(_CONSTRAINT_FIELDS - set(constraints))
    if missing:
        raise PairingContractError(
            "authorization.constraints missing required field(s): " + ", ".join(missing)
        )
    max_attempts = _bounded_int(
        constraints["max_attempts"],
        "authorization.constraints.max_attempts",
        minimum=1,
        maximum=1,
    )
    max_discovery = _bounded_int(
        constraints["max_discovery_seconds"],
        "authorization.constraints.max_discovery_seconds",
        minimum=1,
        maximum=HARD_MAX_DISCOVERY_SECONDS,
    )
    max_pairing = _bounded_int(
        constraints["max_pairing_seconds"],
        "authorization.constraints.max_pairing_seconds",
        minimum=1,
        maximum=HARD_MAX_PAIRING_SECONDS,
    )
    max_disconnect = _bounded_int(
        constraints["max_disconnect_seconds"],
        "authorization.constraints.max_disconnect_seconds",
        minimum=1,
        maximum=HARD_MAX_DISCONNECT_SECONDS,
    )
    disconnect_after = _boolean(
        constraints["require_disconnect_after"],
        "authorization.constraints.require_disconnect_after",
    )
    if not disconnect_after:
        raise PairingContractError("v0.12 pairing requires disconnect_after=true")
    require_unpaired = _boolean(
        constraints["require_unpaired_before"],
        "authorization.constraints.require_unpaired_before",
    )
    require_unbonded = _boolean(
        constraints["require_unbonded_before"],
        "authorization.constraints.require_unbonded_before",
    )
    raw_agents = _list(
        constraints["allowed_agent_modes"],
        "authorization.constraints.allowed_agent_modes",
    )
    if not raw_agents:
        raise PairingContractError(
            "authorization.constraints.allowed_agent_modes must not be empty"
        )
    agents = []
    seen_agents = set()
    for index, item in enumerate(raw_agents):
        item = _nonempty(item, f"authorization.constraints.allowed_agent_modes[{index}]")
        if item not in PAIRING_AGENT_MODES:
            raise PairingContractError(f"unsupported pairing agent mode: {item}")
        if item in seen_agents:
            raise PairingContractError(
                "authorization.constraints.allowed_agent_modes contains duplicate mode"
            )
        seen_agents.add(item)
        agents.append(item)

    approval = _object(authorization["approval"], "authorization.approval")
    _reject_unknown(approval, _APPROVAL_FIELDS, "authorization.approval")
    missing = sorted(_APPROVAL_FIELDS - set(approval))
    if missing:
        raise PairingContractError(
            "authorization.approval missing required field(s): " + ", ".join(missing)
        )
    approved, approved_text = _parse_utc(
        approval["approved_at_utc"], "authorization.approval.approved_at_utc"
    )
    if not issued <= approved <= not_before:
        raise PairingContractError(
            "authorization approval time must satisfy issued_at_utc <= approved_at_utc <= not_before_utc"
        )

    return {
        "schema_version": PAIRING_CONTRACT_VERSION,
        "record_type": "bluetooth_pairing_authorization",
        "authorization_id": _nonempty(authorization["authorization_id"], "authorization.authorization_id"),
        "engagement_id": _nonempty(authorization["engagement_id"], "authorization.engagement_id"),
        "owner": _nonempty(authorization["owner"], "authorization.owner"),
        "operator": _nonempty(authorization["operator"], "authorization.operator"),
        "location": _nonempty(authorization["location"], "authorization.location"),
        "issued_at_utc": issued_text,
        "not_before_utc": not_before_text,
        "expires_at_utc": expires_text,
        "target": target,
        "allowed_operations": sorted(operations),
        "constraints": {
            "max_attempts": max_attempts,
            "max_discovery_seconds": max_discovery,
            "max_pairing_seconds": max_pairing,
            "max_disconnect_seconds": max_disconnect,
            "require_disconnect_after": True,
            "require_unpaired_before": require_unpaired,
            "require_unbonded_before": require_unbonded,
            "allowed_agent_modes": sorted(agents),
        },
        "approval": {
            "approver": _nonempty(approval["approver"], "authorization.approval.approver"),
            "approved_at_utc": approved_text,
            "basis": _nonempty(approval["basis"], "authorization.approval.basis"),
        },
    }


def _normalize_timeouts(value, authorization):
    value = _object(value, "request.timeouts")
    _reject_unknown(value, _TIMEOUT_FIELDS, "request.timeouts")
    missing = sorted(_TIMEOUT_FIELDS - set(value))
    if missing:
        raise PairingContractError(
            "request.timeouts missing required field(s): " + ", ".join(missing)
        )
    mapping = {
        "discovery_seconds": "max_discovery_seconds",
        "pairing_seconds": "max_pairing_seconds",
        "disconnect_seconds": "max_disconnect_seconds",
    }
    normalized = {}
    for field, limit_field in mapping.items():
        normalized[field] = _bounded_int(
            value[field],
            f"request.timeouts.{field}",
            minimum=1,
            maximum=authorization["constraints"][limit_field],
        )
    return normalized


def build_pairing_plan(
    authorization,
    request,
    *,
    authorization_sha256,
    request_sha256,
    created_at_utc=None,
):
    """Build a hash-bound pairing plan without performing Bluetooth activity."""
    authorization_sha256 = _sha256(authorization_sha256, "authorization_sha256")
    request_sha256 = _sha256(request_sha256, "request_sha256")
    if created_at_utc is None:
        created_dt = datetime.now(timezone.utc)
        created_text = created_dt.isoformat().replace("+00:00", "Z")
    elif isinstance(created_at_utc, datetime):
        created_dt = _now(created_at_utc)
        created_text = created_dt.isoformat().replace("+00:00", "Z")
    else:
        created_dt, created_text = _parse_utc(created_at_utc, "created_at_utc")

    auth = validate_pairing_authorization(authorization, at_utc=created_dt)
    request = _object(request, "request")
    _reject_unknown(request, _REQUEST_FIELDS, "request")
    missing = sorted(_REQUEST_FIELDS - set(request))
    if missing:
        raise PairingContractError("request missing required field(s): " + ", ".join(missing))
    if request["schema_version"] != PAIRING_CONTRACT_VERSION:
        raise PairingContractError(
            f"request.schema_version must be {PAIRING_CONTRACT_VERSION}"
        )
    if request["record_type"] != "bluetooth_pairing_request":
        raise PairingContractError(
            "request.record_type must be bluetooth_pairing_request"
        )

    target = _target(request["target"], "request.target", allow_label=False)
    if _target_key(target) != _target_key(auth["target"]):
        raise PairingContractError("request.target is outside authorization scope")
    request_bond = _boolean(request["request_bond"], "request.request_bond")
    if request_bond and BOND_OPERATION not in auth["allowed_operations"]:
        raise PairingContractError(
            "request_bond=true requires establish_bond authorization"
        )
    agent_mode = _nonempty(request["agent_mode"], "request.agent_mode")
    if agent_mode not in PAIRING_AGENT_MODES:
        raise PairingContractError(f"unsupported pairing agent mode: {agent_mode}")
    if agent_mode not in auth["constraints"]["allowed_agent_modes"]:
        raise PairingContractError("request.agent_mode is not authorized")
    timeouts = _normalize_timeouts(request["timeouts"], auth)

    return {
        "schema_version": PAIRING_CONTRACT_VERSION,
        "record_type": "bluetooth_pairing_plan",
        "plan_id": _nonempty(request["plan_id"], "request.plan_id"),
        "pairing_session_id": _nonempty(
            request["pairing_session_id"], "request.pairing_session_id"
        ),
        "created_at_utc": created_text,
        "authorization": {
            "authorization_id": auth["authorization_id"],
            "sha256": authorization_sha256,
        },
        "request": {"sha256": request_sha256},
        "target": {
            "address": target["address"],
            "address_type": target["address_type"],
        },
        "requested": {"pair": True, "bond": request_bond},
        "agent_mode": agent_mode,
        "timeouts": timeouts,
        "preconditions": {
            "require_unpaired_before": auth["constraints"]["require_unpaired_before"],
            "require_unbonded_before": auth["constraints"]["require_unbonded_before"],
        },
        "cleanup": {"disconnect_after": True},
        "execution": {
            "execution_domain": "active_rf",
            "transmit_capable": True,
            "mutates_security_state": True,
        },
    }


def validate_pairing_plan(plan, authorization, *, authorization_sha256, at_utc=None):
    """Validate an existing plan against the exact authorization artifact."""
    plan = _object(plan, "plan")
    _reject_unknown(plan, _PLAN_FIELDS, "plan")
    missing = sorted(_PLAN_FIELDS - set(plan))
    if missing:
        raise PairingContractError("plan missing required field(s): " + ", ".join(missing))
    if plan["schema_version"] != PAIRING_CONTRACT_VERSION:
        raise PairingContractError("unsupported pairing plan schema_version")
    if plan["record_type"] != "bluetooth_pairing_plan":
        raise PairingContractError("plan.record_type must be bluetooth_pairing_plan")

    auth_sha = _sha256(authorization_sha256, "authorization_sha256")
    auth = validate_pairing_authorization(authorization, at_utc=at_utc)
    auth_ref = _object(plan["authorization"], "plan.authorization")
    _reject_unknown(auth_ref, {"authorization_id", "sha256"}, "plan.authorization")
    if auth_ref.get("authorization_id") != auth["authorization_id"]:
        raise PairingContractError("plan authorization_id does not match authorization")
    if _sha256(auth_ref.get("sha256"), "plan.authorization.sha256") != auth_sha:
        raise PairingContractError("plan authorization hash does not match authorization")

    request_ref = _object(plan["request"], "plan.request")
    _reject_unknown(request_ref, {"sha256"}, "plan.request")
    request_sha = _sha256(request_ref.get("sha256"), "plan.request.sha256")

    target = _target(plan["target"], "plan.target", allow_label=False)
    if _target_key(target) != _target_key(auth["target"]):
        raise PairingContractError("plan.target is outside authorization scope")

    requested = _object(plan["requested"], "plan.requested")
    _reject_unknown(requested, {"pair", "bond"}, "plan.requested")
    if _boolean(requested.get("pair"), "plan.requested.pair") is not True:
        raise PairingContractError("plan.requested.pair must be true")
    bond = _boolean(requested.get("bond"), "plan.requested.bond")
    if bond and BOND_OPERATION not in auth["allowed_operations"]:
        raise PairingContractError("plan requests bond without establish_bond authorization")

    agent_mode = _nonempty(plan["agent_mode"], "plan.agent_mode")
    if agent_mode not in auth["constraints"]["allowed_agent_modes"]:
        raise PairingContractError("plan.agent_mode is not authorized")

    timeouts = _normalize_timeouts(plan["timeouts"], auth)
    preconditions = _object(plan["preconditions"], "plan.preconditions")
    _reject_unknown(
        preconditions,
        {"require_unpaired_before", "require_unbonded_before"},
        "plan.preconditions",
    )
    expected_preconditions = {
        "require_unpaired_before": auth["constraints"]["require_unpaired_before"],
        "require_unbonded_before": auth["constraints"]["require_unbonded_before"],
    }
    normalized_preconditions = {
        key: _boolean(preconditions.get(key), f"plan.preconditions.{key}")
        for key in expected_preconditions
    }
    if normalized_preconditions != expected_preconditions:
        raise PairingContractError("plan preconditions do not match authorization")

    cleanup = _object(plan["cleanup"], "plan.cleanup")
    _reject_unknown(cleanup, {"disconnect_after"}, "plan.cleanup")
    if _boolean(cleanup.get("disconnect_after"), "plan.cleanup.disconnect_after") is not True:
        raise PairingContractError("plan.cleanup.disconnect_after must be true")

    execution = _object(plan["execution"], "plan.execution")
    expected_execution = {
        "execution_domain": "active_rf",
        "transmit_capable": True,
        "mutates_security_state": True,
    }
    if execution != expected_execution:
        raise PairingContractError("plan.execution policy is invalid")

    _, created_text = _parse_utc(plan["created_at_utc"], "plan.created_at_utc")
    normalized = {
        "schema_version": PAIRING_CONTRACT_VERSION,
        "record_type": "bluetooth_pairing_plan",
        "plan_id": _nonempty(plan["plan_id"], "plan.plan_id"),
        "pairing_session_id": _nonempty(
            plan["pairing_session_id"], "plan.pairing_session_id"
        ),
        "created_at_utc": created_text,
        "authorization": {
            "authorization_id": auth["authorization_id"],
            "sha256": auth_sha,
        },
        "request": {"sha256": request_sha},
        "target": {"address": target["address"], "address_type": target["address_type"]},
        "requested": {"pair": True, "bond": bond},
        "agent_mode": agent_mode,
        "timeouts": timeouts,
        "preconditions": normalized_preconditions,
        "cleanup": {"disconnect_after": True},
        "execution": deepcopy(expected_execution),
    }
    return normalized, auth
