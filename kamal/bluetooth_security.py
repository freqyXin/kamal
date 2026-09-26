"""Pure contracts for Bluetooth security-state and key-aware evidence.

This module is deliberately non-executing. It has no Bluetooth client, BlueZ,
packet-capture, or networking dependency. It validates already-collected
security evidence and defines the operation taxonomy that later execution code
must explicitly authorize.
"""

from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime, timezone


BLUETOOTH_SECURITY_CONTRACT_VERSION = "0.12.0"

BLUETOOTH_SECURITY_OPERATION_POLICY = {
    "inspect_security_state": {
        "execution_domain": "local",
        "transmit_capable": False,
        "mutates_security_state": False,
        "requires_secret_access": False,
    },
    "pair_target": {
        "execution_domain": "active_rf",
        "transmit_capable": True,
        "mutates_security_state": True,
        "requires_secret_access": False,
    },
    "establish_bond": {
        "execution_domain": "active_rf",
        "transmit_capable": True,
        "mutates_security_state": True,
        "requires_secret_access": False,
    },
    "remove_bond": {
        "execution_domain": "local",
        "transmit_capable": False,
        "mutates_security_state": True,
        "requires_secret_access": True,
    },
    "reset_pairing_state": {
        "execution_domain": "local",
        "transmit_capable": False,
        "mutates_security_state": True,
        "requires_secret_access": True,
    },
    "capture_pairing_ota": {
        "execution_domain": "passive_rf",
        "transmit_capable": False,
        "mutates_security_state": False,
        "requires_secret_access": False,
    },
    "analyze_key_material": {
        "execution_domain": "local",
        "transmit_capable": False,
        "mutates_security_state": False,
        "requires_secret_access": True,
    },
    "decrypt_capture": {
        "execution_domain": "local",
        "transmit_capable": False,
        "mutates_security_state": False,
        "requires_secret_access": True,
    },
    "resolve_rpa": {
        "execution_domain": "local",
        "transmit_capable": False,
        "mutates_security_state": False,
        "requires_secret_access": True,
    },
}

BLUETOOTH_SECURITY_OPERATION_CLASSES = frozenset(
    BLUETOOTH_SECURITY_OPERATION_POLICY
)

KEY_CLASSES = frozenset({"ltk", "irk", "csrk", "link_key"})
KEY_SOURCE_KINDS = frozenset(
    {"bluez_store", "bluez_mgmt", "pairing_capture", "authorized_import"}
)
SECURITY_STATE_SOURCE_KINDS = frozenset(
    {"bluez_dbus", "bluez_mgmt", "bluez_store", "packet_capture", "authorized_import"}
)
PAIRING_STATUS = frozenset({"planned", "attempted", "completed", "failed", "cancelled"})
ASSOCIATION_MODELS = frozenset(
    {"just_works", "numeric_comparison", "passkey_entry", "oob", "unknown"}
)
PACKET_PROTOCOLS = frozenset({"ll", "l2cap", "smp", "att", "gatt"})
PACKET_DIRECTIONS = frozenset(
    {"initiator_to_responder", "responder_to_initiator", "unknown"}
)

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_ADDRESS_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

_FORBIDDEN_RAW_SECRET_FIELDS = frozenset(
    {
        "raw_key",
        "raw_key_hex",
        "key_hex",
        "ltk_hex",
        "irk_hex",
        "csrk_hex",
        "link_key_hex",
        "secret_hex",
        "secret_bytes",
        "key_material_hex",
    }
)


class BluetoothSecurityContractError(ValueError):
    """Raised when Bluetooth security evidence violates the contract."""


def _reject_unknown_fields(value, allowed, field):
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise BluetoothSecurityContractError(
            f"{field} contains unsupported field(s): {', '.join(unknown)}"
        )


def _object(value, field):
    if not isinstance(value, dict):
        raise BluetoothSecurityContractError(f"{field} must be an object")
    return value


def _list(value, field):
    if not isinstance(value, list):
        raise BluetoothSecurityContractError(f"{field} must be an array")
    return value


def _nonempty(value, field):
    if not isinstance(value, str) or not value.strip():
        raise BluetoothSecurityContractError(f"{field} must be a non-empty string")
    return value.strip()


def _bool(value, field):
    if not isinstance(value, bool):
        raise BluetoothSecurityContractError(f"{field} must be a boolean")
    return value


def _nullable_bool(value, field):
    if value is None:
        return None
    return _bool(value, field)


def _bounded_int(value, field, *, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        raise BluetoothSecurityContractError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise BluetoothSecurityContractError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return value


def _nullable_bounded_int(value, field, *, minimum, maximum):
    if value is None:
        return None
    return _bounded_int(value, field, minimum=minimum, maximum=maximum)


def _enum(value, field, allowed):
    value = _nonempty(value, field)
    if value not in allowed:
        raise BluetoothSecurityContractError(
            f"{field} must be one of: {', '.join(sorted(allowed))}"
        )
    return value


def _nullable_enum(value, field, allowed):
    if value is None:
        return None
    return _enum(value, field, allowed)


def _sha256(value, field):
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise BluetoothSecurityContractError(
            f"{field} must be a SHA-256 hexadecimal digest"
        )
    return value.lower()


def _utc(value, field):
    value = _nonempty(value, field)
    if not value.endswith("Z"):
        raise BluetoothSecurityContractError(f"{field} must use UTC and end with Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BluetoothSecurityContractError(
            f"{field} must be an ISO-8601 UTC timestamp"
        ) from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise BluetoothSecurityContractError(f"{field} must use UTC")
    return parsed.isoformat().replace("+00:00", "Z")


def _nullable_utc(value, field):
    if value is None:
        return None
    return _utc(value, field)


def _target(value, field="target"):
    value = _object(value, field)
    _reject_unknown_fields(value, {"address", "address_type"}, field)
    address = _nonempty(value.get("address"), f"{field}.address")
    if not _ADDRESS_RE.fullmatch(address):
        raise BluetoothSecurityContractError(
            f"{field}.address must be a colon-delimited BLE address"
        )
    address_type = _enum(
        value.get("address_type"),
        f"{field}.address_type",
        {"public", "random", "unknown"},
    )
    return {"address": address.upper(), "address_type": address_type}


def _refs(value, field, *, allow_empty=False):
    values = _list(value, field)
    if not allow_empty and not values:
        raise BluetoothSecurityContractError(f"{field} must not be empty")
    return [_nonempty(item, f"{field}[]") for item in values]


def _reject_raw_secret_fields(value, field="record"):
    if isinstance(value, dict):
        forbidden = sorted(set(value) & _FORBIDDEN_RAW_SECRET_FIELDS)
        if forbidden:
            raise BluetoothSecurityContractError(
                f"{field} contains raw secret field(s): {', '.join(forbidden)}"
            )
        for key, item in value.items():
            _reject_raw_secret_fields(item, f"{field}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_raw_secret_fields(item, f"{field}[{index}]")


def _contract_header(value, record_type):
    if value.get("schema_version") != BLUETOOTH_SECURITY_CONTRACT_VERSION:
        raise BluetoothSecurityContractError("unsupported schema_version")
    if value.get("record_type") != record_type:
        raise BluetoothSecurityContractError(
            f"record_type must be {record_type}"
        )


def operation_policy(operation_class):
    """Return detached policy metadata for a proposed security operation class.

    This taxonomy does not grant authorization and is intentionally not wired
    into the active GATT planner/executor.
    """
    operation_class = _nonempty(operation_class, "operation_class")
    try:
        return deepcopy(BLUETOOTH_SECURITY_OPERATION_POLICY[operation_class])
    except KeyError as exc:
        raise BluetoothSecurityContractError(
            f"unsupported Bluetooth security operation: {operation_class}"
        ) from exc


def validate_pairing_session(value):
    value = _object(value, "pairing_session")
    _reject_raw_secret_fields(value, "pairing_session")
    allowed = {
        "schema_version",
        "record_type",
        "pairing_session_id",
        "engagement_id",
        "authorization_ref",
        "target",
        "started_at_utc",
        "completed_at_utc",
        "status",
        "requested",
        "observed",
        "security",
        "evidence",
        "limitations",
    }
    _reject_unknown_fields(value, allowed, "pairing_session")
    _contract_header(value, "bluetooth_pairing_session")

    status = _enum(value.get("status"), "status", PAIRING_STATUS)
    started = _utc(value.get("started_at_utc"), "started_at_utc")
    completed = _nullable_utc(value.get("completed_at_utc"), "completed_at_utc")
    terminal = status in {"completed", "failed", "cancelled"}
    if terminal and completed is None:
        raise BluetoothSecurityContractError(
            f"completed_at_utc is required when status={status}"
        )
    if not terminal and completed is not None:
        raise BluetoothSecurityContractError(
            f"completed_at_utc must be null when status={status}"
        )
    if completed is not None:
        started_dt = datetime.fromisoformat(started[:-1] + "+00:00")
        completed_dt = datetime.fromisoformat(completed[:-1] + "+00:00")
        if completed_dt < started_dt:
            raise BluetoothSecurityContractError(
                "completed_at_utc must not precede started_at_utc"
            )

    requested = _object(value.get("requested"), "requested")
    _reject_unknown_fields(requested, {"pair", "bond"}, "requested")
    pair = _bool(requested.get("pair"), "requested.pair")
    bond = _bool(requested.get("bond"), "requested.bond")
    if bond and not pair:
        raise BluetoothSecurityContractError("requested.bond requires requested.pair")
    if not pair and not bond:
        raise BluetoothSecurityContractError(
            "pairing session must request pair and/or bond"
        )

    observed_fields = {
        "paired_before",
        "bonded_before",
        "trusted_before",
        "paired_after",
        "bonded_after",
        "trusted_after",
        "connected_after",
        "encrypted_after",
    }
    observed = _object(value.get("observed"), "observed")
    _reject_unknown_fields(observed, observed_fields, "observed")
    normalized_observed = {
        field: _nullable_bool(observed.get(field), f"observed.{field}")
        for field in sorted(observed_fields)
    }

    security = _object(value.get("security"), "security")
    security_fields = {
        "authenticated",
        "secure_connections",
        "encryption_size",
        "association_model",
    }
    _reject_unknown_fields(security, security_fields, "security")
    normalized_security = {
        "authenticated": _nullable_bool(
            security.get("authenticated"), "security.authenticated"
        ),
        "secure_connections": _nullable_bool(
            security.get("secure_connections"), "security.secure_connections"
        ),
        "encryption_size": _nullable_bounded_int(
            security.get("encryption_size"),
            "security.encryption_size",
            minimum=7,
            maximum=16,
        ),
        "association_model": _nullable_enum(
            security.get("association_model"),
            "security.association_model",
            ASSOCIATION_MODELS,
        ),
    }

    evidence = _refs(value.get("evidence"), "evidence", allow_empty=(status == "planned"))
    limitations = _refs(value.get("limitations"), "limitations", allow_empty=True)

    return {
        "schema_version": BLUETOOTH_SECURITY_CONTRACT_VERSION,
        "record_type": "bluetooth_pairing_session",
        "pairing_session_id": _nonempty(
            value.get("pairing_session_id"), "pairing_session_id"
        ),
        "engagement_id": _nonempty(value.get("engagement_id"), "engagement_id"),
        "authorization_ref": _nonempty(
            value.get("authorization_ref"), "authorization_ref"
        ),
        "target": _target(value.get("target")),
        "started_at_utc": started,
        "completed_at_utc": completed,
        "status": status,
        "requested": {"pair": pair, "bond": bond},
        "observed": normalized_observed,
        "security": normalized_security,
        "evidence": evidence,
        "limitations": limitations,
    }


def validate_bluetooth_security_state(value):
    value = _object(value, "security_state")
    _reject_raw_secret_fields(value, "security_state")
    allowed = {
        "schema_version",
        "record_type",
        "security_state_id",
        "engagement_id",
        "authorization_ref",
        "target",
        "observed_at_utc",
        "source",
        "state",
        "key_evidence_refs",
        "limitations",
    }
    _reject_unknown_fields(value, allowed, "security_state")
    _contract_header(value, "bluetooth_security_state")

    source = _object(value.get("source"), "source")
    _reject_unknown_fields(source, {"kind", "artifact_ref"}, "source")
    source = {
        "kind": _enum(source.get("kind"), "source.kind", SECURITY_STATE_SOURCE_KINDS),
        "artifact_ref": _nonempty(source.get("artifact_ref"), "source.artifact_ref"),
    }

    state_fields = {"paired", "bonded", "trusted", "connected", "encrypted"}
    state = _object(value.get("state"), "state")
    _reject_unknown_fields(state, state_fields, "state")
    normalized_state = {
        field: _nullable_bool(state.get(field), f"state.{field}")
        for field in sorted(state_fields)
    }

    return {
        "schema_version": BLUETOOTH_SECURITY_CONTRACT_VERSION,
        "record_type": "bluetooth_security_state",
        "security_state_id": _nonempty(
            value.get("security_state_id"), "security_state_id"
        ),
        "engagement_id": _nonempty(value.get("engagement_id"), "engagement_id"),
        "authorization_ref": _nonempty(
            value.get("authorization_ref"), "authorization_ref"
        ),
        "target": _target(value.get("target")),
        "observed_at_utc": _utc(value.get("observed_at_utc"), "observed_at_utc"),
        "source": source,
        "state": normalized_state,
        "key_evidence_refs": _refs(
            value.get("key_evidence_refs"), "key_evidence_refs", allow_empty=True
        ),
        "limitations": _refs(value.get("limitations"), "limitations", allow_empty=True),
    }


def validate_bluetooth_key_evidence(value):
    value = _object(value, "key_evidence")
    _reject_raw_secret_fields(value, "key_evidence")
    allowed = {
        "schema_version",
        "record_type",
        "key_evidence_id",
        "engagement_id",
        "authorization_ref",
        "target",
        "pairing_session_ref",
        "key_class",
        "key_bytes",
        "key_fingerprint_sha256",
        "authenticated",
        "secure_connections",
        "encryption_size",
        "debug_key",
        "source",
        "secret_artifact_ref",
        "raw_key_embedded",
        "limitations",
    }
    _reject_unknown_fields(value, allowed, "key_evidence")
    _contract_header(value, "bluetooth_key_evidence")

    source = _object(value.get("source"), "source")
    _reject_unknown_fields(source, {"kind", "artifact_ref"}, "source")
    source = {
        "kind": _enum(source.get("kind"), "source.kind", KEY_SOURCE_KINDS),
        "artifact_ref": _nonempty(source.get("artifact_ref"), "source.artifact_ref"),
    }

    key_class = _enum(value.get("key_class"), "key_class", KEY_CLASSES)
    key_bytes = _bounded_int(value.get("key_bytes"), "key_bytes", minimum=16, maximum=16)
    encryption_size = _nullable_bounded_int(
        value.get("encryption_size"), "encryption_size", minimum=7, maximum=16
    )
    if key_class != "ltk" and encryption_size is not None:
        raise BluetoothSecurityContractError(
            "encryption_size is only valid for ltk evidence"
        )

    raw_embedded = _bool(value.get("raw_key_embedded"), "raw_key_embedded")
    if raw_embedded:
        raise BluetoothSecurityContractError(
            "raw_key_embedded must be false; raw secret material belongs in a protected artifact"
        )

    return {
        "schema_version": BLUETOOTH_SECURITY_CONTRACT_VERSION,
        "record_type": "bluetooth_key_evidence",
        "key_evidence_id": _nonempty(value.get("key_evidence_id"), "key_evidence_id"),
        "engagement_id": _nonempty(value.get("engagement_id"), "engagement_id"),
        "authorization_ref": _nonempty(
            value.get("authorization_ref"), "authorization_ref"
        ),
        "target": _target(value.get("target")),
        "pairing_session_ref": _nonempty(
            value.get("pairing_session_ref"), "pairing_session_ref"
        ),
        "key_class": key_class,
        "key_bytes": key_bytes,
        "key_fingerprint_sha256": _sha256(
            value.get("key_fingerprint_sha256"), "key_fingerprint_sha256"
        ),
        "authenticated": _nullable_bool(value.get("authenticated"), "authenticated"),
        "secure_connections": _nullable_bool(
            value.get("secure_connections"), "secure_connections"
        ),
        "encryption_size": encryption_size,
        "debug_key": _nullable_bool(value.get("debug_key"), "debug_key"),
        "source": source,
        "secret_artifact_ref": _nonempty(
            value.get("secret_artifact_ref"), "secret_artifact_ref"
        ),
        "raw_key_embedded": False,
        "limitations": _refs(value.get("limitations"), "limitations", allow_empty=True),
    }


def validate_secret_evidence_artifact(value):
    value = _object(value, "secret_artifact")
    _reject_raw_secret_fields(value, "secret_artifact")
    allowed = {
        "schema_version",
        "record_type",
        "artifact_id",
        "engagement_id",
        "path",
        "sha256",
        "byte_size",
        "sensitivity",
        "secret_classes",
        "storage_state",
        "contains_secret_material",
        "raw_secret_embedded_in_metadata",
        "limitations",
    }
    _reject_unknown_fields(value, allowed, "secret_artifact")
    _contract_header(value, "secret_evidence_artifact")

    secret_classes = _list(value.get("secret_classes"), "secret_classes")
    if not secret_classes:
        raise BluetoothSecurityContractError("secret_classes must not be empty")
    normalized_classes = []
    for item in secret_classes:
        normalized_classes.append(_enum(item, "secret_classes[]", KEY_CLASSES))
    if len(set(normalized_classes)) != len(normalized_classes):
        raise BluetoothSecurityContractError("secret_classes must be unique")

    if value.get("sensitivity") != "highly_restricted":
        raise BluetoothSecurityContractError(
            "secret evidence sensitivity must be highly_restricted"
        )
    storage_state = _enum(
        value.get("storage_state"),
        "storage_state",
        {"encrypted_at_rest", "os_protected_source", "transient_memory_only"},
    )
    contains = _bool(value.get("contains_secret_material"), "contains_secret_material")
    if not contains:
        raise BluetoothSecurityContractError(
            "secret evidence artifact must declare contains_secret_material=true"
        )
    raw_in_metadata = _bool(
        value.get("raw_secret_embedded_in_metadata"),
        "raw_secret_embedded_in_metadata",
    )
    if raw_in_metadata:
        raise BluetoothSecurityContractError(
            "raw_secret_embedded_in_metadata must be false"
        )

    return {
        "schema_version": BLUETOOTH_SECURITY_CONTRACT_VERSION,
        "record_type": "secret_evidence_artifact",
        "artifact_id": _nonempty(value.get("artifact_id"), "artifact_id"),
        "engagement_id": _nonempty(value.get("engagement_id"), "engagement_id"),
        "path": _nonempty(value.get("path"), "path"),
        "sha256": _sha256(value.get("sha256"), "sha256"),
        "byte_size": _bounded_int(
            value.get("byte_size"), "byte_size", minimum=1, maximum=2**63 - 1
        ),
        "sensitivity": "highly_restricted",
        "secret_classes": normalized_classes,
        "storage_state": storage_state,
        "contains_secret_material": True,
        "raw_secret_embedded_in_metadata": False,
        "limitations": _refs(value.get("limitations"), "limitations", allow_empty=True),
    }


def validate_packet_observation(value):
    value = _object(value, "packet_observation")
    _reject_raw_secret_fields(value, "packet_observation")
    allowed = {
        "schema_version",
        "record_type",
        "packet_observation_id",
        "source_capture_sha256",
        "frame_number",
        "protocol",
        "direction",
        "decrypted",
        "decryption_derivation_ref",
        "directly_observed",
        "opcode",
        "error_code",
        "summary",
    }
    _reject_unknown_fields(value, allowed, "packet_observation")
    _contract_header(value, "bluetooth_packet_observation")

    decrypted = _bool(value.get("decrypted"), "decrypted")
    derivation_ref = value.get("decryption_derivation_ref")
    if decrypted:
        derivation_ref = _nonempty(derivation_ref, "decryption_derivation_ref")
    elif derivation_ref is not None:
        raise BluetoothSecurityContractError(
            "decryption_derivation_ref is only valid when decrypted=true"
        )

    directly_observed = _bool(value.get("directly_observed"), "directly_observed")
    if not directly_observed:
        raise BluetoothSecurityContractError(
            "packet observations must be directly observed in capture evidence"
        )

    error_code = value.get("error_code")
    if error_code is not None:
        error_code = _nonempty(error_code, "error_code")

    return {
        "schema_version": BLUETOOTH_SECURITY_CONTRACT_VERSION,
        "record_type": "bluetooth_packet_observation",
        "packet_observation_id": _nonempty(
            value.get("packet_observation_id"), "packet_observation_id"
        ),
        "source_capture_sha256": _sha256(
            value.get("source_capture_sha256"), "source_capture_sha256"
        ),
        "frame_number": _bounded_int(
            value.get("frame_number"), "frame_number", minimum=1, maximum=2**31 - 1
        ),
        "protocol": _enum(value.get("protocol"), "protocol", PACKET_PROTOCOLS),
        "direction": _enum(value.get("direction"), "direction", PACKET_DIRECTIONS),
        "decrypted": decrypted,
        "decryption_derivation_ref": derivation_ref,
        "directly_observed": True,
        "opcode": _nonempty(value.get("opcode"), "opcode"),
        "error_code": error_code,
        "summary": _nonempty(value.get("summary"), "summary"),
    }


def validate_decryption_derivation(value):
    value = _object(value, "decryption_derivation")
    _reject_raw_secret_fields(value, "decryption_derivation")
    allowed = {
        "schema_version",
        "record_type",
        "derivation_id",
        "engagement_id",
        "authorization_ref",
        "created_at_utc",
        "source_capture",
        "key_evidence",
        "decoder",
        "result",
        "packet_observation_refs",
        "execution",
        "limitations",
    }
    _reject_unknown_fields(value, allowed, "decryption_derivation")
    _contract_header(value, "bluetooth_decryption_derivation")

    capture = _object(value.get("source_capture"), "source_capture")
    _reject_unknown_fields(capture, {"artifact_ref", "sha256"}, "source_capture")
    capture = {
        "artifact_ref": _nonempty(capture.get("artifact_ref"), "source_capture.artifact_ref"),
        "sha256": _sha256(capture.get("sha256"), "source_capture.sha256"),
    }

    key_evidence = _list(value.get("key_evidence"), "key_evidence")
    if not key_evidence:
        raise BluetoothSecurityContractError("key_evidence must not be empty")
    normalized_keys = []
    for index, item in enumerate(key_evidence):
        field = f"key_evidence[{index}]"
        item = _object(item, field)
        _reject_unknown_fields(
            item, {"key_evidence_ref", "key_fingerprint_sha256"}, field
        )
        normalized_keys.append(
            {
                "key_evidence_ref": _nonempty(
                    item.get("key_evidence_ref"), f"{field}.key_evidence_ref"
                ),
                "key_fingerprint_sha256": _sha256(
                    item.get("key_fingerprint_sha256"),
                    f"{field}.key_fingerprint_sha256",
                ),
            }
        )

    decoder = _object(value.get("decoder"), "decoder")
    _reject_unknown_fields(decoder, {"tool", "version"}, "decoder")
    decoder = {
        "tool": _enum(decoder.get("tool"), "decoder.tool", {"wireshark", "tshark", "nrfutil"}),
        "version": _nonempty(decoder.get("version"), "decoder.version"),
    }

    result = _object(value.get("result"), "result")
    _reject_unknown_fields(
        result, {"attempted", "succeeded", "frames_decrypted", "error"}, "result"
    )
    attempted = _bool(result.get("attempted"), "result.attempted")
    succeeded = _bool(result.get("succeeded"), "result.succeeded")
    if succeeded and not attempted:
        raise BluetoothSecurityContractError("result.succeeded requires result.attempted")
    frames = _bounded_int(
        result.get("frames_decrypted"), "result.frames_decrypted", minimum=0, maximum=2**31 - 1
    )
    error = result.get("error")
    if succeeded:
        if error is not None:
            raise BluetoothSecurityContractError(
                "successful decryption result must not carry error"
            )
    elif attempted:
        error = _nonempty(error, "result.error")
    elif error is not None:
        raise BluetoothSecurityContractError(
            "unattempted decryption result must not carry error"
        )
    if not succeeded and frames != 0:
        raise BluetoothSecurityContractError(
            "frames_decrypted must be zero unless decryption succeeded"
        )

    execution = _object(value.get("execution"), "execution")
    _reject_unknown_fields(execution, {"status", "rf_performed", "network_performed"}, "execution")
    if execution.get("status") != "offline_derivation":
        raise BluetoothSecurityContractError(
            "execution.status must be offline_derivation"
        )
    if _bool(execution.get("rf_performed"), "execution.rf_performed"):
        raise BluetoothSecurityContractError("decryption derivation must not perform RF")
    if _bool(execution.get("network_performed"), "execution.network_performed"):
        raise BluetoothSecurityContractError(
            "decryption derivation must not perform network operations"
        )

    return {
        "schema_version": BLUETOOTH_SECURITY_CONTRACT_VERSION,
        "record_type": "bluetooth_decryption_derivation",
        "derivation_id": _nonempty(value.get("derivation_id"), "derivation_id"),
        "engagement_id": _nonempty(value.get("engagement_id"), "engagement_id"),
        "authorization_ref": _nonempty(
            value.get("authorization_ref"), "authorization_ref"
        ),
        "created_at_utc": _utc(value.get("created_at_utc"), "created_at_utc"),
        "source_capture": capture,
        "key_evidence": normalized_keys,
        "decoder": decoder,
        "result": {
            "attempted": attempted,
            "succeeded": succeeded,
            "frames_decrypted": frames,
            "error": error,
        },
        "packet_observation_refs": _refs(
            value.get("packet_observation_refs"),
            "packet_observation_refs",
            allow_empty=True,
        ),
        "execution": {
            "status": "offline_derivation",
            "rf_performed": False,
            "network_performed": False,
        },
        "limitations": _refs(value.get("limitations"), "limitations", allow_empty=True),
    }
