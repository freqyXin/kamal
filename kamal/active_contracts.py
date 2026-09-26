"""Authorization and typed operation contracts for bounded active BLE GATT work.

This module performs validation and plan construction only. It does not import
radio libraries, open adapters, connect to devices, or execute GATT operations.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path


ACTIVE_CONTRACT_VERSION = "0.12.0"

SUPPORTED_OPERATIONS = frozenset(
    {
        "read_characteristic",
        "read_descriptor",
        "write_characteristic",
        "subscribe_notifications",
    }
)
GATT_METADATA_OPERATION = "enumerate_gatt_metadata"
AUTHORIZED_OPERATIONS = SUPPORTED_OPERATIONS | frozenset({GATT_METADATA_OPERATION})
WRITE_OPERATIONS = frozenset({"write_characteristic"})

HARD_MAX_OPERATIONS = 64
HARD_MAX_PAYLOAD_BYTES = 512
HARD_MAX_TIMEOUT_SECONDS = 30
HARD_MAX_SUBSCRIPTION_SECONDS = 300

_ADDRESS_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_UUID16_RE = re.compile(r"^[0-9A-Fa-f]{4}$")
_UUID32_RE = re.compile(r"^[0-9A-Fa-f]{8}$")
_UUID128_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
_HEX_RE = re.compile(r"^[0-9A-Fa-f]*$")

_AUTHORIZATION_FIELDS = frozenset(
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
        "targets",
        "allowed_operations",
        "constraints",
        "approval",
    }
)
_TARGET_FIELDS = frozenset({"protocol", "address", "address_type", "label"})
_CONSTRAINT_FIELDS = frozenset(
    {
        "max_operations",
        "max_payload_bytes",
        "max_timeout_seconds",
        "max_subscription_seconds",
        "allow_writes",
        "allow_write_without_response",
    }
)
_APPROVAL_FIELDS = frozenset({"approver", "approved_at_utc", "basis"})
_REQUEST_FIELDS = frozenset({"schema_version", "record_type", "plan_id", "operations"})
_OPERATION_COMMON_FIELDS = frozenset(
    {"operation_id", "operation_type", "target", "selector", "timeout_seconds"}
)
_OPERATION_WRITE_FIELDS = frozenset({"payload_hex", "write_mode"})
_OPERATION_SUBSCRIBE_FIELDS = frozenset({"duration_seconds"})
_SELECTOR_FIELDS = frozenset(
    {"handle", "service_uuid", "characteristic_uuid", "descriptor_uuid"}
)
_OPERATION_TARGET_FIELDS = frozenset({"address", "address_type"})


class ContractValidationError(ValueError):
    """Raised when an authorization or operation contract fails closed."""


def _reject_unknown_fields(value, allowed, field):
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise ContractValidationError(
            f"{field} contains unsupported field(s): {', '.join(unknown)}"
        )


def _require_object(value, field):
    if not isinstance(value, dict):
        raise ContractValidationError(f"{field} must be an object")
    return value


def _require_list(value, field):
    if not isinstance(value, list):
        raise ContractValidationError(f"{field} must be an array")
    return value


def _require_string(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ContractValidationError(f"{field} must be a non-empty string")
    return value.strip()


def _require_bool(value, field):
    if not isinstance(value, bool):
        raise ContractValidationError(f"{field} must be a boolean")
    return value


def _require_bounded_int(value, field, *, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractValidationError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ContractValidationError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return value


def _parse_utc(value, field):
    text = _require_string(value, field)
    if not text.endswith("Z"):
        raise ContractValidationError(f"{field} must use UTC and end with Z")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ContractValidationError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ContractValidationError(f"{field} must use UTC")
    return parsed, parsed.isoformat().replace("+00:00", "Z")


def _normalize_address(value, field):
    text = _require_string(value, field)
    if not _ADDRESS_RE.fullmatch(text):
        raise ContractValidationError(f"{field} must be a colon-delimited BLE address")
    return text.upper()


def _normalize_address_type(value, field):
    text = _require_string(value, field).lower()
    if text not in {"public", "random", "unknown"}:
        raise ContractValidationError(
            f"{field} must be one of: public, random, unknown"
        )
    return text


def _normalize_uuid(value, field):
    text = _require_string(value, field)
    if text.lower().startswith("0x"):
        text = text[2:]
    if _UUID16_RE.fullmatch(text) or _UUID32_RE.fullmatch(text):
        return text.lower()
    if _UUID128_RE.fullmatch(text):
        return text.lower()
    raise ContractValidationError(
        f"{field} must be a 16-bit, 32-bit, or canonical 128-bit UUID"
    )


def _normalize_target(value, field, *, allow_label):
    target = _require_object(value, field)
    allowed = _TARGET_FIELDS if allow_label else _OPERATION_TARGET_FIELDS
    _reject_unknown_fields(target, allowed, field)

    protocol = target.get("protocol", "ble") if allow_label else "ble"
    if protocol != "ble":
        raise ContractValidationError(f"{field}.protocol must be ble")

    normalized = {
        "protocol": "ble",
        "address": _normalize_address(target.get("address"), f"{field}.address"),
        "address_type": _normalize_address_type(
            target.get("address_type"), f"{field}.address_type"
        ),
    }
    if allow_label and "label" in target:
        normalized["label"] = _require_string(target["label"], f"{field}.label")
    return normalized


def _target_key(target):
    return target["address"], target["address_type"]


def _normalize_selector(value, field, operation_type):
    selector = _require_object(value, field)
    _reject_unknown_fields(selector, _SELECTOR_FIELDS, field)

    has_handle = "handle" in selector
    uuid_fields = [
        name
        for name in ("service_uuid", "characteristic_uuid", "descriptor_uuid")
        if name in selector
    ]
    if has_handle and uuid_fields:
        raise ContractValidationError(
            f"{field} must use either handle or UUID path, not both"
        )

    if has_handle:
        return {
            "handle": _require_bounded_int(
                selector["handle"], f"{field}.handle", minimum=1, maximum=0xFFFF
            )
        }

    if operation_type == "read_descriptor":
        required = ("service_uuid", "characteristic_uuid", "descriptor_uuid")
    else:
        required = ("service_uuid", "characteristic_uuid")
        if "descriptor_uuid" in selector:
            raise ContractValidationError(
                f"{field}.descriptor_uuid is only valid for descriptor operations"
            )

    missing = [name for name in required if name not in selector]
    if missing:
        raise ContractValidationError(
            f"{field} missing required field(s): {', '.join(missing)}"
        )

    return {
        name: _normalize_uuid(selector[name], f"{field}.{name}")
        for name in required
    }


def _normalize_constraints(value):
    constraints = _require_object(value, "authorization.constraints")
    _reject_unknown_fields(constraints, _CONSTRAINT_FIELDS, "authorization.constraints")

    required = _CONSTRAINT_FIELDS
    missing = sorted(required - set(constraints))
    if missing:
        raise ContractValidationError(
            "authorization.constraints missing required field(s): " + ", ".join(missing)
        )

    normalized = {
        "max_operations": _require_bounded_int(
            constraints["max_operations"],
            "authorization.constraints.max_operations",
            minimum=1,
            maximum=HARD_MAX_OPERATIONS,
        ),
        "max_payload_bytes": _require_bounded_int(
            constraints["max_payload_bytes"],
            "authorization.constraints.max_payload_bytes",
            minimum=0,
            maximum=HARD_MAX_PAYLOAD_BYTES,
        ),
        "max_timeout_seconds": _require_bounded_int(
            constraints["max_timeout_seconds"],
            "authorization.constraints.max_timeout_seconds",
            minimum=1,
            maximum=HARD_MAX_TIMEOUT_SECONDS,
        ),
        "max_subscription_seconds": _require_bounded_int(
            constraints["max_subscription_seconds"],
            "authorization.constraints.max_subscription_seconds",
            minimum=1,
            maximum=HARD_MAX_SUBSCRIPTION_SECONDS,
        ),
        "allow_writes": _require_bool(
            constraints["allow_writes"], "authorization.constraints.allow_writes"
        ),
        "allow_write_without_response": _require_bool(
            constraints["allow_write_without_response"],
            "authorization.constraints.allow_write_without_response",
        ),
    }
    if normalized["allow_write_without_response"] and not normalized["allow_writes"]:
        raise ContractValidationError(
            "allow_write_without_response requires allow_writes=true"
        )
    return normalized


def validate_authorization_scope(authorization, *, at_utc=None):
    """Validate and normalize one active BLE authorization record.

    ``at_utc`` controls validity-window evaluation for deterministic tests. When
    omitted, the current UTC time is used. The returned object is detached from
    caller-owned input.
    """
    authorization = _require_object(authorization, "authorization")
    _reject_unknown_fields(authorization, _AUTHORIZATION_FIELDS, "authorization")

    required = _AUTHORIZATION_FIELDS
    missing = sorted(required - set(authorization))
    if missing:
        raise ContractValidationError(
            "authorization missing required field(s): " + ", ".join(missing)
        )

    if authorization["schema_version"] != ACTIVE_CONTRACT_VERSION:
        raise ContractValidationError(
            f"authorization.schema_version must be {ACTIVE_CONTRACT_VERSION}"
        )
    if authorization["record_type"] != "authorization_scope":
        raise ContractValidationError(
            "authorization.record_type must be authorization_scope"
        )

    issued, issued_text = _parse_utc(
        authorization["issued_at_utc"], "authorization.issued_at_utc"
    )
    not_before, not_before_text = _parse_utc(
        authorization["not_before_utc"], "authorization.not_before_utc"
    )
    expires, expires_text = _parse_utc(
        authorization["expires_at_utc"], "authorization.expires_at_utc"
    )
    if not issued <= not_before < expires:
        raise ContractValidationError(
            "authorization validity must satisfy issued_at_utc <= not_before_utc < expires_at_utc"
        )

    if at_utc is None:
        now = datetime.now(timezone.utc)
    elif isinstance(at_utc, datetime):
        if at_utc.tzinfo is None or at_utc.utcoffset() != timezone.utc.utcoffset(at_utc):
            raise ContractValidationError("at_utc must be timezone-aware UTC")
        now = at_utc
    else:
        now, _ = _parse_utc(at_utc, "at_utc")

    if now < not_before:
        raise ContractValidationError("authorization is not yet valid")
    if now >= expires:
        raise ContractValidationError("authorization is expired")

    targets = _require_list(authorization["targets"], "authorization.targets")
    if not targets:
        raise ContractValidationError("authorization.targets must not be empty")
    normalized_targets = []
    seen_targets = set()
    for index, target in enumerate(targets):
        normalized = _normalize_target(
            target, f"authorization.targets[{index}]", allow_label=True
        )
        key = _target_key(normalized)
        if key in seen_targets:
            raise ContractValidationError("authorization contains duplicate BLE target")
        seen_targets.add(key)
        normalized_targets.append(normalized)

    allowed_operations = _require_list(
        authorization["allowed_operations"], "authorization.allowed_operations"
    )
    if not allowed_operations:
        raise ContractValidationError(
            "authorization.allowed_operations must not be empty"
        )
    normalized_operations = []
    seen_operations = set()
    for index, operation in enumerate(allowed_operations):
        operation = _require_string(
            operation, f"authorization.allowed_operations[{index}]"
        )
        if operation not in AUTHORIZED_OPERATIONS:
            raise ContractValidationError(
                f"Unsupported active operation class: {operation}"
            )
        if operation in seen_operations:
            raise ContractValidationError(
                "authorization.allowed_operations contains duplicate operation"
            )
        seen_operations.add(operation)
        normalized_operations.append(operation)

    constraints = _normalize_constraints(authorization["constraints"])
    if WRITE_OPERATIONS.intersection(normalized_operations) and not constraints["allow_writes"]:
        raise ContractValidationError(
            "write operation class requires authorization.constraints.allow_writes=true"
        )

    approval = _require_object(authorization["approval"], "authorization.approval")
    _reject_unknown_fields(approval, _APPROVAL_FIELDS, "authorization.approval")
    missing_approval = sorted(_APPROVAL_FIELDS - set(approval))
    if missing_approval:
        raise ContractValidationError(
            "authorization.approval missing required field(s): "
            + ", ".join(missing_approval)
        )
    approved, approved_text = _parse_utc(
        approval["approved_at_utc"], "authorization.approval.approved_at_utc"
    )
    if not issued <= approved <= not_before:
        raise ContractValidationError(
            "authorization approval time must satisfy "
            "issued_at_utc <= approved_at_utc <= not_before_utc"
        )

    return {
        "schema_version": ACTIVE_CONTRACT_VERSION,
        "record_type": "authorization_scope",
        "authorization_id": _require_string(
            authorization["authorization_id"], "authorization.authorization_id"
        ),
        "engagement_id": _require_string(
            authorization["engagement_id"], "authorization.engagement_id"
        ),
        "owner": _require_string(authorization["owner"], "authorization.owner"),
        "operator": _require_string(
            authorization["operator"], "authorization.operator"
        ),
        "location": _require_string(
            authorization["location"], "authorization.location"
        ),
        "issued_at_utc": issued_text,
        "not_before_utc": not_before_text,
        "expires_at_utc": expires_text,
        "targets": normalized_targets,
        "allowed_operations": sorted(normalized_operations),
        "constraints": constraints,
        "approval": {
            "approver": _require_string(
                approval["approver"], "authorization.approval.approver"
            ),
            "approved_at_utc": approved_text,
            "basis": _require_string(
                approval["basis"], "authorization.approval.basis"
            ),
        },
    }


def validate_gatt_survey_authorization(
    authorization,
    *,
    target_addresses=None,
    timeout_seconds,
    max_targets=None,
    at_utc=None,
):
    """Validate authorization for read-only GATT metadata enumeration.

    The survey discovery path currently preserves BLE addresses but not a
    trustworthy public/random address type.  Survey execution therefore only
    accepts targets explicitly scoped with ``address_type=unknown``; this keeps
    the type uncertainty visible instead of silently weakening exact target
    matching.
    """
    import math

    normalized = validate_authorization_scope(authorization, at_utc=at_utc)

    if GATT_METADATA_OPERATION not in normalized["allowed_operations"]:
        raise ContractValidationError(
            f"operation class {GATT_METADATA_OPERATION} is not authorized"
        )

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or not 1 <= timeout_seconds <= normalized["constraints"]["max_timeout_seconds"]
    ):
        raise ContractValidationError(
            "survey timeout exceeds authorization.constraints.max_timeout_seconds"
        )

    if max_targets is not None:
        if (
            isinstance(max_targets, bool)
            or not isinstance(max_targets, int)
            or max_targets < 1
        ):
            raise ContractValidationError("survey max_targets must be a positive integer")
        if max_targets > normalized["constraints"]["max_operations"]:
            raise ContractValidationError(
                "survey target limit exceeds authorization.constraints.max_operations"
            )

    if target_addresses is not None:
        if not isinstance(target_addresses, (list, tuple, set, frozenset)):
            raise ContractValidationError("survey target_addresses must be a collection")

        selected = []
        seen = set()
        for index, address in enumerate(target_addresses):
            normalized_address = _normalize_address(
                address, f"survey.target_addresses[{index}]"
            )
            if normalized_address in seen:
                raise ContractValidationError("survey contains duplicate target address")
            seen.add(normalized_address)
            selected.append(normalized_address)

        if len(selected) > normalized["constraints"]["max_operations"]:
            raise ContractValidationError(
                "survey target count exceeds authorization.constraints.max_operations"
            )

        authorized_unknown = {
            target["address"]
            for target in normalized["targets"]
            if target["address_type"] == "unknown"
        }
        missing = sorted(set(selected) - authorized_unknown)
        if missing:
            raise ContractValidationError(
                "survey target is outside authorization scope or is not scoped "
                f"with address_type=unknown: {missing[0]}"
            )

    return normalized


def _normalize_operation(operation, index, authorization):
    field = f"request.operations[{index}]"
    operation = _require_object(operation, field)
    operation_type = _require_string(
        operation.get("operation_type"), f"{field}.operation_type"
    )
    if operation_type not in SUPPORTED_OPERATIONS:
        raise ContractValidationError(f"Unsupported active operation class: {operation_type}")

    allowed_fields = set(_OPERATION_COMMON_FIELDS)
    if operation_type == "write_characteristic":
        allowed_fields.update(_OPERATION_WRITE_FIELDS)
    if operation_type == "subscribe_notifications":
        allowed_fields.update(_OPERATION_SUBSCRIBE_FIELDS)
    _reject_unknown_fields(operation, allowed_fields, field)

    required = set(_OPERATION_COMMON_FIELDS)
    if operation_type == "write_characteristic":
        required.update(_OPERATION_WRITE_FIELDS)
    if operation_type == "subscribe_notifications":
        required.update(_OPERATION_SUBSCRIBE_FIELDS)
    missing = sorted(required - set(operation))
    if missing:
        raise ContractValidationError(
            f"{field} missing required field(s): {', '.join(missing)}"
        )

    if operation_type not in authorization["allowed_operations"]:
        raise ContractValidationError(
            f"operation class {operation_type} is not authorized"
        )

    target = _normalize_target(operation["target"], f"{field}.target", allow_label=False)
    if _target_key(target) not in {
        _target_key(item) for item in authorization["targets"]
    }:
        raise ContractValidationError(f"{field}.target is outside authorization scope")

    selector = _normalize_selector(
        operation["selector"], f"{field}.selector", operation_type
    )
    timeout_seconds = _require_bounded_int(
        operation["timeout_seconds"],
        f"{field}.timeout_seconds",
        minimum=1,
        maximum=authorization["constraints"]["max_timeout_seconds"],
    )

    normalized = {
        "operation_id": _require_string(
            operation["operation_id"], f"{field}.operation_id"
        ),
        "operation_type": operation_type,
        "target": {
            "address": target["address"],
            "address_type": target["address_type"],
        },
        "selector": selector,
        "timeout_seconds": timeout_seconds,
    }

    if operation_type == "write_characteristic":
        if not authorization["constraints"]["allow_writes"]:
            raise ContractValidationError("write operations are not authorized")
        payload_hex = operation["payload_hex"]
        if not isinstance(payload_hex, str) or len(payload_hex) % 2:
            raise ContractValidationError(f"{field}.payload_hex must contain whole bytes")
        if not _HEX_RE.fullmatch(payload_hex):
            raise ContractValidationError(f"{field}.payload_hex must be hexadecimal")
        payload_bytes = len(payload_hex) // 2
        if payload_bytes > authorization["constraints"]["max_payload_bytes"]:
            raise ContractValidationError(
                f"{field}.payload_hex exceeds authorized payload limit"
            )

        write_mode = _require_string(operation["write_mode"], f"{field}.write_mode")
        if write_mode not in {"request", "command"}:
            raise ContractValidationError(
                f"{field}.write_mode must be request or command"
            )
        if (
            write_mode == "command"
            and not authorization["constraints"]["allow_write_without_response"]
        ):
            raise ContractValidationError(
                "write-without-response is not authorized"
            )
        normalized.update(
            {
                "payload_hex": payload_hex.lower(),
                "payload_bytes": payload_bytes,
                "write_mode": write_mode,
            }
        )

    if operation_type == "subscribe_notifications":
        duration_seconds = _require_bounded_int(
            operation["duration_seconds"],
            f"{field}.duration_seconds",
            minimum=1,
            maximum=authorization["constraints"]["max_subscription_seconds"],
        )
        normalized["duration_seconds"] = duration_seconds
        normalized["cleanup"] = {"unsubscribe_required": True}

    return normalized


def build_gatt_operation_plan(
    authorization,
    request,
    *,
    authorization_sha256,
    request_sha256,
    created_at_utc=None,
):
    """Build a validated, non-executing GATT operation plan.

    The caller supplies SHA-256 digests for the exact authorization and request
    file bytes. The returned artifact is suitable for later consumption by a
    separate executor; constructing it performs no BLE or RF activity.
    """
    if not isinstance(authorization_sha256, str) or not re.fullmatch(
        r"[0-9A-Fa-f]{64}", authorization_sha256
    ):
        raise ContractValidationError(
            "authorization_sha256 must contain 64 hexadecimal characters"
        )
    if not isinstance(request_sha256, str) or not re.fullmatch(
        r"[0-9A-Fa-f]{64}", request_sha256
    ):
        raise ContractValidationError(
            "request_sha256 must contain 64 hexadecimal characters"
        )

    if created_at_utc is None:
        created_dt = datetime.now(timezone.utc)
        created_text = created_dt.isoformat().replace("+00:00", "Z")
    elif isinstance(created_at_utc, datetime):
        if (
            created_at_utc.tzinfo is None
            or created_at_utc.utcoffset() != timezone.utc.utcoffset(created_at_utc)
        ):
            raise ContractValidationError("created_at_utc must be timezone-aware UTC")
        created_dt = created_at_utc
        created_text = created_dt.isoformat().replace("+00:00", "Z")
    else:
        created_dt, created_text = _parse_utc(created_at_utc, "created_at_utc")

    normalized_authorization = validate_authorization_scope(
        authorization, at_utc=created_dt
    )

    request = _require_object(request, "request")
    _reject_unknown_fields(request, _REQUEST_FIELDS, "request")
    required = _REQUEST_FIELDS
    missing = sorted(required - set(request))
    if missing:
        raise ContractValidationError(
            "request missing required field(s): " + ", ".join(missing)
        )
    if request["schema_version"] != ACTIVE_CONTRACT_VERSION:
        raise ContractValidationError(
            f"request.schema_version must be {ACTIVE_CONTRACT_VERSION}"
        )
    if request["record_type"] != "gatt_operation_request":
        raise ContractValidationError(
            "request.record_type must be gatt_operation_request"
        )

    operations = _require_list(request["operations"], "request.operations")
    if not operations:
        raise ContractValidationError("request.operations must not be empty")
    if len(operations) > normalized_authorization["constraints"]["max_operations"]:
        raise ContractValidationError("request exceeds authorized operation count")

    normalized_operations = []
    seen_operation_ids = set()
    for index, operation in enumerate(operations):
        normalized = _normalize_operation(
            operation, index, normalized_authorization
        )
        if normalized["operation_id"] in seen_operation_ids:
            raise ContractValidationError("request contains duplicate operation_id")
        seen_operation_ids.add(normalized["operation_id"])
        normalized_operations.append(normalized)

    write_count = sum(
        item["operation_type"] in WRITE_OPERATIONS for item in normalized_operations
    )

    return {
        "schema_version": ACTIVE_CONTRACT_VERSION,
        "record_type": "gatt_operation_plan",
        "plan_id": _require_string(request["plan_id"], "request.plan_id"),
        "created_at_utc": created_text,
        "protocol": "ble",
        "collection_mode": "active",
        "authorization_ref": normalized_authorization["authorization_id"],
        "authorization_provenance": {
            "sha256": authorization_sha256.lower(),
            "engagement_id": normalized_authorization["engagement_id"],
            "operator": normalized_authorization["operator"],
            "owner": normalized_authorization["owner"],
            "location": normalized_authorization["location"],
            "not_before_utc": normalized_authorization["not_before_utc"],
            "expires_at_utc": normalized_authorization["expires_at_utc"],
        },
        "request_provenance": {
            "sha256": request_sha256.lower(),
        },
        "operations": normalized_operations,
        "integrity": {
            "operation_count": len(normalized_operations),
            "write_operation_count": write_count,
            "all_targets_authorized": True,
            "authorization_validated_at_utc": created_text,
        },
        "execution": {
            "status": "contract_only",
            "rf_performed": False,
            "executor_required": True,
        },
    }


def load_json_source(path):
    """Load a JSON source and return parsed content plus exact-byte SHA-256."""
    path = Path(path).resolve()
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ContractValidationError(f"Invalid JSON in {path}: {exc}") from exc
    return payload, hashlib.sha256(raw).hexdigest(), path


def detached_copy(value):
    """Return a defensive copy for callers that retain normalized contracts."""
    return deepcopy(value)
