"""Read-only BlueZ persistent security-state inspection.

This module inspects already-persisted BlueZ filesystem state. It performs no
Bluetooth discovery, connection, pairing, controller management, or network
activity. Raw secret values are never returned in the report.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from kamal.bluetooth_security import validate_bluetooth_security_state


BLUEZ_SECURITY_STATE_VERSION = "0.12.0"
DEFAULT_BLUEZ_ROOT = Path("/var/lib/bluetooth")
MAX_BLUEZ_METADATA_BYTES = 1024 * 1024

_ADDRESS_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_SECTION_RE = re.compile(r"^\[([^\]\r\n]+)\]$")

_RECOGNIZED_KEY_SECTIONS = {
    "LinkKey": "link_key",
    "LongTermKey": "ltk",
    "PeripheralLongTermKey": "ltk",
    "SlaveLongTermKey": "ltk",
    "IdentityResolvingKey": "irk",
    "LocalSignatureKey": "csrk",
    "RemoteSignatureKey": "csrk",
}

_SAFE_GENERAL_FIELDS = {
    "Name": "name",
    "Alias": "alias",
    "AddressType": "address_type",
    "Trusted": "trusted",
    "Blocked": "blocked",
    "WakeAllowed": "wake_allowed",
    "SupportedTechnologies": "supported_technologies",
    "Appearance": "appearance",
}

_SAFE_KEY_METADATA_FIELDS = {
    "Authenticated": "authenticated",
    "EncSize": "encryption_size",
    "EDiv": "ediv",
    "Rand": "rand",
    "Type": "type",
    "PINLength": "pin_length",
    "Counter": "counter",
    "Encrypted": "encrypted",
    "Size": "size",
    "Rank": "rank",
}


class BlueZSecurityStateError(ValueError):
    """Raised when BlueZ state cannot be inspected safely or consistently."""


def _nonempty(value, field):
    if not isinstance(value, str) or not value.strip():
        raise BlueZSecurityStateError(f"{field} must be a non-empty string")
    return value.strip()


def _address(value, field):
    value = _nonempty(value, field)
    if not _ADDRESS_RE.fullmatch(value):
        raise BlueZSecurityStateError(
            f"{field} must be a colon-delimited Bluetooth address"
        )
    return value.upper()


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc(value, field):
    value = _nonempty(value, field)
    if not value.endswith("Z"):
        raise BlueZSecurityStateError(f"{field} must use UTC and end with Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BlueZSecurityStateError(
            f"{field} must be an ISO-8601 UTC timestamp"
        ) from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise BlueZSecurityStateError(f"{field} must use UTC")
    return parsed.isoformat().replace("+00:00", "Z")


def _mtime_utc(st):
    return datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _dir_metadata(path):
    path = Path(path)
    try:
        st = path.lstat()
    except OSError as exc:
        raise BlueZSecurityStateError(f"unable to stat directory {path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise BlueZSecurityStateError(f"refusing symbolic-link directory: {path}")
    if not stat.S_ISDIR(st.st_mode):
        raise BlueZSecurityStateError(f"expected directory: {path}")
    return {
        "path": str(path.absolute()),
        "mode": f"{stat.S_IMODE(st.st_mode):04o}",
        "uid": st.st_uid,
        "gid": st.st_gid,
        "modified_at_utc": _mtime_utc(st),
    }


def _read_regular_file(path):
    path = Path(path)
    try:
        lst = path.lstat()
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        raise BlueZSecurityStateError(f"unable to stat BlueZ record {path}: {exc}") from exc
    if stat.S_ISLNK(lst.st_mode):
        raise BlueZSecurityStateError(f"refusing symbolic-link BlueZ record: {path}")
    if not stat.S_ISREG(lst.st_mode):
        raise BlueZSecurityStateError(f"expected regular BlueZ record: {path}")
    if lst.st_size > MAX_BLUEZ_METADATA_BYTES:
        raise BlueZSecurityStateError(
            f"BlueZ record exceeds {MAX_BLUEZ_METADATA_BYTES} byte limit: {path}"
        )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise BlueZSecurityStateError(f"unable to open BlueZ record {path}: {exc}") from exc

    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise BlueZSecurityStateError(f"expected regular BlueZ record: {path}")
        if (opened.st_dev, opened.st_ino) != (lst.st_dev, lst.st_ino):
            raise BlueZSecurityStateError(f"BlueZ record changed before open: {path}")
        if opened.st_size > MAX_BLUEZ_METADATA_BYTES:
            raise BlueZSecurityStateError(
                f"BlueZ record exceeds {MAX_BLUEZ_METADATA_BYTES} byte limit: {path}"
            )

        chunks = []
        remaining = MAX_BLUEZ_METADATA_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_BLUEZ_METADATA_BYTES:
            raise BlueZSecurityStateError(
                f"BlueZ record exceeds {MAX_BLUEZ_METADATA_BYTES} byte limit: {path}"
            )

        final = os.fstat(fd)
        if (
            final.st_size != opened.st_size
            or final.st_mtime_ns != opened.st_mtime_ns
            or final.st_ctime_ns != opened.st_ctime_ns
        ):
            raise BlueZSecurityStateError(f"BlueZ record changed during read: {path}")
    finally:
        os.close(fd)

    artifact = {
        "path": str(path.absolute()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "mode": f"{stat.S_IMODE(final.st_mode):04o}",
        "uid": final.st_uid,
        "gid": final.st_gid,
        "modified_at_utc": _mtime_utc(final),
    }
    return raw, artifact


def _parse_bool(value):
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    return None


def _normalize_address_type(value):
    if value is None:
        return "unknown"
    normalized = value.strip().lower()
    if normalized == "public":
        return "public"
    if normalized in {
        "random",
        "static",
        "resolvable",
        "non-resolvable",
        "nonresolvable",
    }:
        return "random"
    return "unknown"


def _key_section_class(section):
    if section in _RECOGNIZED_KEY_SECTIONS:
        return _RECOGNIZED_KEY_SECTIONS[section]
    if section.startswith("SetIdentityResolvingKey#"):
        return "irk"
    return None


def _parse_bluez_record(raw, *, field):
    if raw is None:
        return {
            "general": {},
            "key_sections": [],
            "redacted_secret_value_fields": 0,
            "unrecognized_sections": [],
        }
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BlueZSecurityStateError(f"{field} is not valid UTF-8") from exc

    general = {}
    sections = {}
    current = None
    secret_count = 0
    section_names = []

    for lineno, source_line in enumerate(text.splitlines(), start=1):
        line = source_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        match = _SECTION_RE.fullmatch(line)
        if match:
            current = match.group(1)
            if current in sections:
                raise BlueZSecurityStateError(
                    f"{field} contains duplicate section [{current}] at line {lineno}"
                )
            sections[current] = {}
            section_names.append(current)
            continue
        if current is None:
            raise BlueZSecurityStateError(
                f"{field} contains data before a section header at line {lineno}"
            )
        if "=" not in line:
            raise BlueZSecurityStateError(
                f"{field} contains malformed line {lineno}"
            )
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise BlueZSecurityStateError(f"{field} contains empty key at line {lineno}")

        # BlueZ uses Key= for the raw Link Key/LTK/IRK/CSRK material. Never
        # retain or return the value, even if it appears in an unexpected section.
        if key.lower() == "key":
            secret_count += 1
            sections[current]["__key_field_present__"] = True
            continue
        sections[current][key] = value

    general_source = sections.get("General", {})
    for source_name, output_name in _SAFE_GENERAL_FIELDS.items():
        if source_name not in general_source:
            continue
        value = general_source[source_name]
        if source_name in {"Trusted", "Blocked", "WakeAllowed"}:
            general[output_name] = _parse_bool(value)
        elif source_name == "AddressType":
            general[output_name] = _normalize_address_type(value)
            general["address_type_raw"] = value
        else:
            general[output_name] = value

    key_sections = []
    for section in section_names:
        key_class = _key_section_class(section)
        if key_class is None:
            continue
        source = sections[section]
        metadata = {}
        for source_name, output_name in _SAFE_KEY_METADATA_FIELDS.items():
            if source_name in source:
                metadata[output_name] = source[source_name]
        key_sections.append(
            {
                "section": section,
                "key_class": key_class,
                "key_field_present": bool(source.get("__key_field_present__", False)),
                "metadata": metadata,
            }
        )

    recognized_names = {item["section"] for item in key_sections}
    unrecognized_sections = sorted(
        name for name in section_names if name not in recognized_names and name != "General"
    )

    return {
        "general": general,
        "key_sections": key_sections,
        "redacted_secret_value_fields": secret_count,
        "unrecognized_sections": unrecognized_sections,
    }


def _record_view(path, *, field):
    raw, artifact = _read_regular_file(path)
    if raw is None:
        return {
            "present": False,
            "artifact": None,
            "general": {},
            "key_sections": [],
            "redacted_secret_value_fields": 0,
            "unrecognized_sections": [],
        }
    parsed = _parse_bluez_record(raw, field=field)
    return {
        "present": True,
        "artifact": artifact,
        **parsed,
    }


def _source_artifact_ref(cache_record, persistent_record):
    preferred = persistent_record if persistent_record["present"] else cache_record
    artifact = preferred.get("artifact")
    if artifact is None:
        raise BlueZSecurityStateError("target has no usable BlueZ source artifact")
    return f"sha256:{artifact['sha256']}"


def _derive_bonded_state(persistent_record, limitations):
    if not persistent_record["present"]:
        limitations.append(
            "No persistent BlueZ info record exists for this exact adapter/target path; "
            "that establishes absence of stored state at this path, not that the device "
            "has never paired or bonded elsewhere."
        )
        return None

    key_sections = persistent_record["key_sections"]
    key_fields = [item for item in key_sections if item["key_field_present"]]
    if key_fields:
        return True
    if key_sections:
        limitations.append(
            "Recognized security-key section(s) exist without a Key field; persisted "
            "bond state is therefore not established by this source."
        )
        return None
    return False


def inspect_bluez_target(
    bluez_root,
    *,
    adapter_address,
    target_address,
    engagement_id,
    authorization_ref,
    observed_at_utc=None,
):
    """Inspect one exact BlueZ cache/persistent-store target without RF activity."""

    root = Path(bluez_root)
    adapter_address = _address(adapter_address, "adapter_address")
    target_address = _address(target_address, "target_address")
    engagement_id = _nonempty(engagement_id, "engagement_id")
    authorization_ref = _nonempty(authorization_ref, "authorization_ref")
    observed_at_utc = _utc(
        observed_at_utc if observed_at_utc is not None else _utc_now(),
        "observed_at_utc",
    )

    root_meta = _dir_metadata(root)
    adapter_dir = root / adapter_address
    adapter_meta = _dir_metadata(adapter_dir)

    cache_dir = adapter_dir / "cache"
    if cache_dir.exists() or cache_dir.is_symlink():
        _dir_metadata(cache_dir)
    device_dir = adapter_dir / target_address
    if device_dir.exists() or device_dir.is_symlink():
        _dir_metadata(device_dir)

    cache_record = _record_view(
        cache_dir / target_address,
        field="BlueZ cache record",
    )
    persistent_record = _record_view(
        device_dir / "info",
        field="BlueZ persistent info record",
    )

    if not cache_record["present"] and not persistent_record["present"]:
        raise BlueZSecurityStateError(
            f"target {target_address} is not present in BlueZ cache or persistent store"
        )

    address_type = (
        persistent_record["general"].get("address_type")
        or cache_record["general"].get("address_type")
        or "unknown"
    )
    target = {"address": target_address, "address_type": address_type}

    key_sections = persistent_record["key_sections"]
    key_classes_present = sorted(
        {item["key_class"] for item in key_sections if item["key_field_present"]}
    )
    recognized_key_sections_present = sorted(
        item["section"] for item in key_sections
    )
    key_material_field_count = sum(
        1 for item in key_sections if item["key_field_present"]
    )

    limitations = [
        "Persistent BlueZ filesystem state does not establish current connection or "
        "link-encryption state.",
        "This inspection does not establish SMP association model, Secure Connections, "
        "or application-level authorization unless separately evidenced.",
    ]
    bonded = _derive_bonded_state(persistent_record, limitations)
    trusted = persistent_record["general"].get("trusted")
    if persistent_record["present"] and "trusted" not in persistent_record["general"]:
        limitations.append("Persistent BlueZ record did not expose a parseable Trusted value.")

    state_record = validate_bluetooth_security_state(
        {
            "schema_version": BLUEZ_SECURITY_STATE_VERSION,
            "record_type": "bluetooth_security_state",
            "security_state_id": (
                f"security-state:bluez-store:{adapter_address}:{target_address}:"
                f"{observed_at_utc}"
            ),
            "engagement_id": engagement_id,
            "authorization_ref": authorization_ref,
            "target": target,
            "observed_at_utc": observed_at_utc,
            "source": {
                "kind": "bluez_store",
                "artifact_ref": _source_artifact_ref(cache_record, persistent_record),
            },
            "state": {
                "paired": None,
                "bonded": bonded,
                "trusted": trusted,
                "connected": None,
                "encrypted": None,
            },
            "key_evidence_refs": [],
            "limitations": limitations,
        }
    )

    report_seed = "|".join(
        [
            adapter_address,
            target_address,
            observed_at_utc,
            cache_record["artifact"]["sha256"] if cache_record["artifact"] else "none",
            (
                persistent_record["artifact"]["sha256"]
                if persistent_record["artifact"]
                else "none"
            ),
        ]
    ).encode("utf-8")
    report_id = "bluez-security-report:" + hashlib.sha256(report_seed).hexdigest()

    return {
        "schema_version": BLUEZ_SECURITY_STATE_VERSION,
        "record_type": "bluez_security_state_report",
        "report_id": report_id,
        "engagement_id": engagement_id,
        "authorization_ref": authorization_ref,
        "observed_at_utc": observed_at_utc,
        "execution": {
            "status": "local_read_only_inspection",
            "rf_performed": False,
            "network_performed": False,
            "mutated_bluez_state": False,
        },
        "bluez": {
            "root": root_meta,
            "adapter": {
                "address": adapter_address,
                "directory": adapter_meta,
            },
        },
        "target": target,
        "records": {
            "cache": cache_record,
            "persistent": persistent_record,
        },
        "persistent_security": {
            "persistent_record_present": persistent_record["present"],
            "recognized_key_sections_present": recognized_key_sections_present,
            "key_classes_with_material_present": key_classes_present,
            "key_material_field_count": key_material_field_count,
            "le_ltk_present": "ltk" in key_classes_present,
            "br_edr_link_key_present": "link_key" in key_classes_present,
            "irk_present": "irk" in key_classes_present,
            "signing_key_present": "csrk" in key_classes_present,
        },
        "security_state": state_record,
        "limitations": list(limitations),
    }
