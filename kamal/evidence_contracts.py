"""Shared evidence contracts for K'amal assessment records.

This module deliberately does not perform RF operations. It normalizes
already-collected evidence and provides persistence helpers for immutable
assessment artifacts.
"""

import json
import os
import tempfile
from pathlib import Path


EVIDENCE_CONTRACT_VERSION = "0.12.0"

COLLECTION_MODES = {
    "passive_ble": "passive",
    "active_gatt": "active",
}


class AtomicCreateError(OSError):
    """Persistence error with explicit publication-state metadata."""

    def __init__(self, message, *, path, published):
        super().__init__(message)
        self.path = Path(path)
        self.published = bool(published)


def _require_nonempty_string(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _validate_sha256(value):
    _require_nonempty_string(value, "sha256")
    if len(value) != 64:
        raise ValueError("sha256 must contain 64 hexadecimal characters")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError("sha256 must contain 64 hexadecimal characters") from exc
    return value.lower()


def build_source_record(source):
    """Normalize provenance for an already-loaded source report."""
    if not isinstance(source, dict):
        raise ValueError("source must be an object")

    source_id = _require_nonempty_string(source.get("source_id"), "source_id")
    sha256 = _validate_sha256(source.get("sha256"))
    expected_source_id = f"sha256:{sha256}"
    if source_id != expected_source_id:
        raise ValueError("source_id must match sha256")

    evidence_type = _require_nonempty_string(
        source.get("evidence_type"),
        "evidence_type",
    )
    if evidence_type not in COLLECTION_MODES:
        raise ValueError(f"Unsupported evidence type: {evidence_type}")

    schema_version = _require_nonempty_string(
        source.get("schema_version"),
        "schema_version",
    )
    path = _require_nonempty_string(source.get("path"), "path")

    return {
        "record_type": "evidence_source",
        "contract_version": EVIDENCE_CONTRACT_VERSION,
        "source_id": source_id,
        "path": path,
        "sha256": sha256,
        "evidence_type": evidence_type,
        "schema_version": schema_version,
        "collection_mode": COLLECTION_MODES[evidence_type],
    }


def build_observation_record(source, *, protocol="ble", authorization_ref=None):
    """Normalize one source report as an assessment observation.

    Device identity is intentionally not inferred here. Authorization
    references are carried when a producer has one; historic reports may
    legitimately have no authorization reference recorded.
    """
    if not isinstance(source, dict):
        raise ValueError("source must be an object")
    source_record = build_source_record(source)
    report = source.get("report")
    if not isinstance(report, dict):
        raise ValueError("source.report must be an object")

    protocol = _require_nonempty_string(protocol, "protocol")
    if authorization_ref is not None:
        _require_nonempty_string(authorization_ref, "authorization_ref")

    return {
        "record_type": "observation",
        "contract_version": EVIDENCE_CONTRACT_VERSION,
        "observation_id": f"observation:{source_record['source_id']}",
        "source_id": source_record["source_id"],
        "protocol": protocol,
        "collection_mode": source_record["collection_mode"],
        "authorization_ref": authorization_ref,
        "evidence_type": source_record["evidence_type"],
        "report": report,
    }


def atomic_create_json(path, payload):
    """Atomically create JSON without replacing an existing destination.

    The completed temporary file is hard-linked into place. On POSIX
    filesystems, link creation is atomic and fails if the destination already
    exists. This preserves K'amal's no-overwrite evidence behavior while
    avoiding a partially-written final artifact.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.link(temporary, path)
        temporary.unlink()
        temporary = None

        directory_fd = None
        directory_error = None
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
            os.fsync(directory_fd)
        except OSError as exc:
            directory_error = exc
        finally:
            if directory_fd is not None:
                try:
                    os.close(directory_fd)
                except OSError as exc:
                    if directory_error is None:
                        directory_error = exc

        if directory_error is not None:
            raise AtomicCreateError(
                f"artifact published at {path}, but parent directory sync failed: "
                f"{directory_error}",
                path=path,
                published=True,
            ) from directory_error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
