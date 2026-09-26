"""Read-only analysis of Bluetooth key material in the BlueZ persistent store.

This module is intentionally local-only. It reads one exact BlueZ ``info``
record, derives redacted analytical key evidence and SHA-256 fingerprints in
memory, and leaves the raw key values in the existing operating-system
protected source. It performs no Bluetooth discovery, connection, pairing,
controller management, RF activity, or network access.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from kamal.bluetooth_security import (
    validate_bluetooth_key_evidence,
    validate_secret_evidence_artifact,
)


BLUEZ_KEY_EVIDENCE_VERSION = "0.12.0"
DEFAULT_BLUEZ_ROOT = Path("/var/lib/bluetooth")
MAX_BLUEZ_SECRET_SOURCE_BYTES = 1024 * 1024

_ADDRESS_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_SECTION_RE = re.compile(r"^\[([^\]\r\n]+)\]$")
_KEY_HEX_RE = re.compile(r"^[0-9A-Fa-f]{32}$")

_RECOGNIZED_KEY_SECTIONS = {
    "LinkKey": "link_key",
    "LongTermKey": "ltk",
    "PeripheralLongTermKey": "ltk",
    "SlaveLongTermKey": "ltk",
    "IdentityResolvingKey": "irk",
    "LocalSignatureKey": "csrk",
    "RemoteSignatureKey": "csrk",
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


class BlueZKeyEvidenceError(ValueError):
    """Raised when BlueZ key material cannot be analyzed safely."""


def _nonempty(value, field):
    if not isinstance(value, str) or not value.strip():
        raise BlueZKeyEvidenceError(f"{field} must be a non-empty string")
    return value.strip()


def _address(value, field):
    value = _nonempty(value, field)
    if not _ADDRESS_RE.fullmatch(value):
        raise BlueZKeyEvidenceError(
            f"{field} must be a colon-delimited Bluetooth address"
        )
    return value.upper()


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc(value, field):
    value = _nonempty(value, field)
    if not value.endswith("Z"):
        raise BlueZKeyEvidenceError(f"{field} must use UTC and end with Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BlueZKeyEvidenceError(
            f"{field} must be an ISO-8601 UTC timestamp"
        ) from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise BlueZKeyEvidenceError(f"{field} must use UTC")
    return parsed.isoformat().replace("+00:00", "Z")


def _mtime_utc(st):
    return datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _validate_directory(path, field):
    path = Path(path)
    try:
        st = path.lstat()
    except OSError as exc:
        raise BlueZKeyEvidenceError(f"unable to stat {field} {path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise BlueZKeyEvidenceError(f"refusing symbolic-link {field}: {path}")
    if not stat.S_ISDIR(st.st_mode):
        raise BlueZKeyEvidenceError(f"expected directory for {field}: {path}")
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise BlueZKeyEvidenceError(
            f"{field} is not access-restricted enough for os_protected_source: "
            f"{path} mode={mode:04o}"
        )
    return st


def _read_regular_secret_source(path):
    """Read one bounded, non-symlink file and bind metadata to exact bytes."""

    path = Path(path)
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise BlueZKeyEvidenceError(
            f"BlueZ persistent info record does not exist: {path}"
        ) from exc
    except OSError as exc:
        raise BlueZKeyEvidenceError(
            f"unable to stat BlueZ persistent info record {path}: {exc}"
        ) from exc

    if stat.S_ISLNK(before.st_mode):
        raise BlueZKeyEvidenceError(
            f"refusing symbolic-link BlueZ persistent info record: {path}"
        )
    if not stat.S_ISREG(before.st_mode):
        raise BlueZKeyEvidenceError(
            f"expected regular BlueZ persistent info record: {path}"
        )
    before_mode = stat.S_IMODE(before.st_mode)
    if before_mode & 0o077:
        raise BlueZKeyEvidenceError(
            "BlueZ persistent info record is not access-restricted enough for "
            f"os_protected_source: {path} mode={before_mode:04o}"
        )
    if before.st_size > MAX_BLUEZ_SECRET_SOURCE_BYTES:
        raise BlueZKeyEvidenceError(
            "BlueZ persistent info record exceeds "
            f"{MAX_BLUEZ_SECRET_SOURCE_BYTES} byte limit: {path}"
        )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise BlueZKeyEvidenceError(
            f"unable to open BlueZ persistent info record {path}: {exc}"
        ) from exc

    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise BlueZKeyEvidenceError(
                f"expected regular BlueZ persistent info record: {path}"
            )
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise BlueZKeyEvidenceError(
                f"BlueZ persistent info record changed before open: {path}"
            )
        if opened.st_size > MAX_BLUEZ_SECRET_SOURCE_BYTES:
            raise BlueZKeyEvidenceError(
                "BlueZ persistent info record exceeds "
                f"{MAX_BLUEZ_SECRET_SOURCE_BYTES} byte limit: {path}"
            )

        chunks = []
        remaining = MAX_BLUEZ_SECRET_SOURCE_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_BLUEZ_SECRET_SOURCE_BYTES:
            raise BlueZKeyEvidenceError(
                "BlueZ persistent info record exceeds "
                f"{MAX_BLUEZ_SECRET_SOURCE_BYTES} byte limit: {path}"
            )

        final = os.fstat(fd)
        if (
            final.st_size != opened.st_size
            or final.st_mtime_ns != opened.st_mtime_ns
            or final.st_ctime_ns != opened.st_ctime_ns
        ):
            raise BlueZKeyEvidenceError(
                f"BlueZ persistent info record changed during read: {path}"
            )
    finally:
        os.close(fd)

    return raw, {
        "path": str(path.absolute()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "mode": f"{stat.S_IMODE(final.st_mode):04o}",
        "uid": final.st_uid,
        "gid": final.st_gid,
        "modified_at_utc": _mtime_utc(final),
    }


def _key_section_class(section):
    if section in _RECOGNIZED_KEY_SECTIONS:
        return _RECOGNIZED_KEY_SECTIONS[section]
    if section.startswith("SetIdentityResolvingKey#"):
        return "irk"
    return None


def _parse_info_with_keys(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BlueZKeyEvidenceError(
            "BlueZ persistent info record is not valid UTF-8"
        ) from exc

    sections = {}
    section_order = []
    current = None

    for lineno, source_line in enumerate(text.splitlines(), start=1):
        line = source_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        match = _SECTION_RE.fullmatch(line)
        if match:
            current = match.group(1)
            if current in sections:
                raise BlueZKeyEvidenceError(
                    f"BlueZ persistent info record contains duplicate section "
                    f"[{current}] at line {lineno}"
                )
            sections[current] = {}
            section_order.append(current)
            continue
        if current is None:
            raise BlueZKeyEvidenceError(
                "BlueZ persistent info record contains data before a section "
                f"header at line {lineno}"
            )
        if "=" not in line:
            raise BlueZKeyEvidenceError(
                f"BlueZ persistent info record contains malformed line {lineno}"
            )
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            raise BlueZKeyEvidenceError(
                f"BlueZ persistent info record contains empty key at line {lineno}"
            )
        if key in sections[current]:
            raise BlueZKeyEvidenceError(
                f"BlueZ persistent info record contains duplicate field {key} "
                f"inside [{current}]"
            )
        sections[current][key] = value.strip()

    address_type = "unknown"
    general = sections.get("General", {})
    raw_address_type = general.get("AddressType", "").strip().lower()
    if raw_address_type == "public":
        address_type = "public"
    elif raw_address_type in {
        "random",
        "static",
        "resolvable",
        "non-resolvable",
        "nonresolvable",
    }:
        address_type = "random"

    keys = []
    unrecognized_key_sections = []
    for section in section_order:
        values = sections[section]
        if "Key" not in values:
            continue
        key_class = _key_section_class(section)
        if key_class is None:
            unrecognized_key_sections.append(section)
            continue

        key_text = values["Key"]
        if not _KEY_HEX_RE.fullmatch(key_text):
            raise BlueZKeyEvidenceError(
                f"recognized BlueZ key section [{section}] contains malformed "
                "128-bit Key material"
            )
        raw_key = bytes.fromhex(key_text)
        metadata = {}
        for source_name, output_name in _SAFE_KEY_METADATA_FIELDS.items():
            if source_name in values:
                metadata[output_name] = values[source_name]
        keys.append(
            {
                "section": section,
                "key_class": key_class,
                "raw_key": raw_key,
                "metadata": metadata,
            }
        )

    return {
        "address_type": address_type,
        "keys": keys,
        "unrecognized_key_sections": sorted(unrecognized_key_sections),
    }


def _parse_optional_bool(value):
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    return None


def _parse_encryption_size(value):
    if value is None:
        return None
    try:
        result = int(value, 0)
    except (TypeError, ValueError):
        return None
    if 7 <= result <= 16:
        return result
    return None


def _pattern_flags(raw_key):
    flags = []
    if all(byte == 0x00 for byte in raw_key):
        flags.append("all_zero")
    if all(byte == 0xFF for byte in raw_key):
        flags.append("all_ff")
    if len(set(raw_key)) == 1:
        flags.append("single_repeated_byte")
    for period in (2, 4, 8):
        if len(raw_key) % period == 0:
            chunk = raw_key[:period]
            if chunk * (len(raw_key) // period) == raw_key:
                flags.append(f"repeated_{period}_byte_pattern")
    if raw_key == bytes(range(len(raw_key))):
        flags.append("ascending_sequence")
    if raw_key == bytes(reversed(range(len(raw_key)))):
        flags.append("descending_sequence")
    return flags


def _key_evidence_id(source_sha256, target_address, section, fingerprint):
    seed = "|".join(
        [source_sha256, target_address, section, fingerprint]
    ).encode("utf-8")
    return "key-evidence:bluez-store:" + hashlib.sha256(seed).hexdigest()


def analyze_bluez_keys(
    bluez_root,
    *,
    adapter_address,
    target_address,
    engagement_id,
    authorization_ref,
    pairing_session_ref=None,
    observed_at_utc=None,
):
    """Analyze persisted BlueZ key material without copying or printing secrets."""

    root = Path(bluez_root)
    adapter_address = _address(adapter_address, "adapter_address")
    target_address = _address(target_address, "target_address")
    engagement_id = _nonempty(engagement_id, "engagement_id")
    authorization_ref = _nonempty(authorization_ref, "authorization_ref")
    if pairing_session_ref is not None:
        pairing_session_ref = _nonempty(pairing_session_ref, "pairing_session_ref")
    observed_at_utc = _utc(
        observed_at_utc if observed_at_utc is not None else _utc_now(),
        "observed_at_utc",
    )

    _validate_directory(root, "BlueZ root")
    adapter_dir = root / adapter_address
    _validate_directory(adapter_dir, "BlueZ adapter directory")
    device_dir = adapter_dir / target_address
    _validate_directory(device_dir, "BlueZ device directory")

    info_path = device_dir / "info"
    raw, source_artifact = _read_regular_secret_source(info_path)
    parsed = _parse_info_with_keys(raw)
    key_items = parsed["keys"]

    if not key_items:
        raise BlueZKeyEvidenceError(
            "BlueZ persistent info record contains no recognized 128-bit key material"
        )

    source_ref = "sha256:" + source_artifact["sha256"]
    target = {
        "address": target_address,
        "address_type": parsed["address_type"],
    }

    key_classes = sorted({item["key_class"] for item in key_items})
    secret_artifact = validate_secret_evidence_artifact(
        {
            "schema_version": BLUEZ_KEY_EVIDENCE_VERSION,
            "record_type": "secret_evidence_artifact",
            "artifact_id": "secret-artifact:bluez-store:" + source_artifact["sha256"],
            "engagement_id": engagement_id,
            "path": source_artifact["path"],
            "sha256": source_artifact["sha256"],
            "byte_size": source_artifact["size_bytes"],
            "sensitivity": "highly_restricted",
            "secret_classes": key_classes,
            "storage_state": "os_protected_source",
            "contains_secret_material": True,
            "raw_secret_embedded_in_metadata": False,
            "limitations": [
                "Raw key values remain in the original operating-system-protected "
                "BlueZ source; this command does not create a second plaintext copy.",
                "The BlueZ source may change or disappear when bond state changes; "
                "verify its SHA-256 before later secret-dependent analysis.",
            ],
        }
    )

    fingerprints = [hashlib.sha256(item["raw_key"]).hexdigest() for item in key_items]
    fingerprint_counts = Counter(fingerprints)

    key_evidence = []
    analysis = []
    for item, fingerprint in zip(key_items, fingerprints):
        metadata = item["metadata"]
        limitations = [
            "Secure Connections and debug-key state are not established from this "
            "BlueZ persistent-store key record alone."
        ]
        if pairing_session_ref is None:
            limitations.append(
                "The pairing session that created this persisted key is not established."
            )

        authenticated = None
        encryption_size = None
        if item["key_class"] == "ltk":
            authenticated = _parse_optional_bool(metadata.get("authenticated"))
            encryption_size = _parse_encryption_size(metadata.get("encryption_size"))
            if "authenticated" in metadata and authenticated is None:
                limitations.append(
                    "BlueZ Authenticated metadata was present but not parseable as boolean."
                )
            if "encryption_size" in metadata and encryption_size is None:
                limitations.append(
                    "BlueZ EncSize metadata was present but not a supported 7-16 byte value."
                )

        evidence = validate_bluetooth_key_evidence(
            {
                "schema_version": BLUEZ_KEY_EVIDENCE_VERSION,
                "record_type": "bluetooth_key_evidence",
                "key_evidence_id": _key_evidence_id(
                    source_artifact["sha256"],
                    target_address,
                    item["section"],
                    fingerprint,
                ),
                "engagement_id": engagement_id,
                "authorization_ref": authorization_ref,
                "target": target,
                "pairing_session_ref": pairing_session_ref,
                "key_class": item["key_class"],
                "key_bytes": len(item["raw_key"]),
                "key_fingerprint_sha256": fingerprint,
                "authenticated": authenticated,
                "secure_connections": None,
                "encryption_size": encryption_size,
                "debug_key": None,
                "source": {
                    "kind": "bluez_store",
                    "artifact_ref": source_ref,
                    "section": item["section"],
                },
                "secret_artifact_ref": secret_artifact["artifact_id"],
                "raw_key_embedded": False,
                "limitations": limitations,
            }
        )
        key_evidence.append(evidence)
        analysis.append(
            {
                "key_evidence_ref": evidence["key_evidence_id"],
                "source_section": item["section"],
                "key_class": item["key_class"],
                "pattern_flags": _pattern_flags(item["raw_key"]),
                "duplicate_fingerprint_within_source": fingerprint_counts[fingerprint] > 1,
                "bluez_metadata": dict(sorted(metadata.items())),
            }
        )

    duplicate_groups = sum(1 for count in fingerprint_counts.values() if count > 1)
    report_seed = "|".join(
        [adapter_address, target_address, observed_at_utc, source_artifact["sha256"]]
    ).encode("utf-8")

    report_limitations = [
        "This report contains cryptographic fingerprints and metadata but no raw key values.",
        "Fingerprint duplication within one BlueZ source is an observation, not by itself "
        "evidence of insecure key reuse across independently paired devices.",
        "A visually simple single key is not sufficient evidence of defective randomness."
    ]
    if parsed["unrecognized_key_sections"]:
        report_limitations.append(
            "Unrecognized section(s) contained Key fields and were not classified or "
            "fingerprinted: " + ", ".join(parsed["unrecognized_key_sections"])
        )

    return {
        "schema_version": BLUEZ_KEY_EVIDENCE_VERSION,
        "record_type": "bluez_key_analysis_report",
        "report_id": "bluez-key-analysis:" + hashlib.sha256(report_seed).hexdigest(),
        "engagement_id": engagement_id,
        "authorization_ref": authorization_ref,
        "pairing_session_ref": pairing_session_ref,
        "observed_at_utc": observed_at_utc,
        "target": target,
        "execution": {
            "status": "local_secret_analysis",
            "rf_performed": False,
            "network_performed": False,
            "mutated_bluez_state": False,
            "raw_secret_values_read": True,
            "raw_secret_values_persisted_by_command": False,
            "raw_secret_values_printed": False,
        },
        "source_artifact": source_artifact,
        "secret_artifact": secret_artifact,
        "key_evidence": key_evidence,
        "analysis": analysis,
        "summary": {
            "key_count": len(key_evidence),
            "key_classes": key_classes,
            "duplicate_fingerprint_groups_within_source": duplicate_groups,
            "unrecognized_key_sections": parsed["unrecognized_key_sections"],
        },
        "limitations": report_limitations,
    }
