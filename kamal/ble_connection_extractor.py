"""Offline extraction of legacy BLE CONNECT_IND evidence from existing PCAPs.

This module invokes TShark only against an already-existing capture. It performs
no RF or network operations and does not schedule receivers. Candidate packets
are normalized by :mod:`kamal.ble_connection_context`; malformed or CRC-invalid
candidates are retained only as rejected diagnostics, never as connection
context evidence.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from kamal.ble_connection_context import (
    BLEConnectionContextError,
    CONNECT_IND_TSHARK_FIELDS,
    LEGACY_CONNECT_IND_PDU_TYPE,
    parse_legacy_connect_ind,
)
from kamal.ble_nordic_sidecar import (
    BLENordicSidecarError,
    load_nordic_connect_req_sidecar,
    reconcile_connect_ind_fields,
    verify_nordic_connect_req_sidecar_unchanged,
)


BLE_CONNECTION_EXTRACTION_VERSION = "0.12.0"
CONNECT_IND_DISPLAY_FILTER = (
    f"btle.advertising_header.pdu_type == {LEGACY_CONNECT_IND_PDU_TYPE}"
)
CONNECT_IND_EXTRACTOR_TSHARK_FIELDS = (
    *CONNECT_IND_TSHARK_FIELDS[:4],
    "nordic_ble.packet_counter",
    *CONNECT_IND_TSHARK_FIELDS[4:],
)


class BLEConnectionExtractionError(ValueError):
    """Raised when an offline PCAP extraction cannot be completed safely."""


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _run_tshark(runner, command):
    try:
        result = runner(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise BLEConnectionExtractionError(
            f"TShark executable not found: {command[0]}"
        ) from exc
    except OSError as exc:
        raise BLEConnectionExtractionError(
            f"Unable to execute TShark: {exc}"
        ) from exc

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        detail = f": {stderr}" if stderr else ""
        raise BLEConnectionExtractionError(
            f"TShark exited with status {result.returncode}{detail}"
        )
    return result


def _tshark_version(runner, tshark):
    result = _run_tshark(runner, [str(tshark), "--version"])
    first_line = (result.stdout or "").splitlines()
    if not first_line or not first_line[0].strip():
        raise BLEConnectionExtractionError(
            "TShark version output was empty"
        )
    return first_line[0].strip()


def _candidate_command(tshark, pcap_path, fields):
    command = [
        str(tshark),
        "-r",
        str(pcap_path),
        "-Y",
        CONNECT_IND_DISPLAY_FILTER,
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "occurrence=f",
    ]
    for field in fields:
        command.extend(["-e", field])
    return command


def extract_legacy_connect_ind_report(
    pcap_path,
    *,
    tshark="tshark",
    runner=None,
    nordic_control_log=None,
):
    """Extract contract-grade legacy CONNECT_IND records from one existing PCAP.

    The source capture is SHA-256 hashed before and after decoder execution. Any
    change aborts the extraction rather than binding records to unstable bytes.
    """

    runner = subprocess.run if runner is None else runner

    try:
        source = Path(pcap_path).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BLEConnectionExtractionError(
            f"Source capture is unavailable: {pcap_path}"
        ) from exc

    if not source.is_file():
        raise BLEConnectionExtractionError(
            f"Source capture is not a regular file: {source}"
        )

    size_before = source.stat().st_size
    if size_before <= 0:
        raise BLEConnectionExtractionError(
            f"Source capture is empty: {source}"
        )

    sha_before = _sha256_file(source)
    decoder_version = _tshark_version(runner, tshark)

    sidecar = None
    if nordic_control_log is not None:
        try:
            sidecar = load_nordic_connect_req_sidecar(nordic_control_log)
        except BLENordicSidecarError as exc:
            raise BLEConnectionExtractionError(str(exc)) from exc

    decoder_fields = (
        CONNECT_IND_EXTRACTOR_TSHARK_FIELDS
        if sidecar is not None
        else CONNECT_IND_TSHARK_FIELDS
    )
    result = _run_tshark(
        runner,
        _candidate_command(tshark, source, decoder_fields),
    )

    accepted = []
    rejected = []
    candidate_count = 0
    reconciled_count = 0

    for raw_line in (result.stdout or "").splitlines():
        if not raw_line:
            continue
        candidate_count += 1
        columns = raw_line.split("\t")

        if len(columns) != len(decoder_fields):
            rejected.append(
                {
                    "frame_number": columns[0].strip() if columns else None,
                    "reason": (
                        "decoder field-count mismatch: "
                        f"expected {len(decoder_fields)}, "
                        f"received {len(columns)}"
                    ),
                }
            )
            continue

        fields = dict(zip(decoder_fields, columns))
        frame_number = fields.get("frame.number")
        frame_number = frame_number.strip() if isinstance(frame_number, str) else None

        try:
            record = parse_legacy_connect_ind(
                fields,
                source_capture_path=str(source),
                source_capture_sha256=sha_before,
            )
        except BLEConnectionContextError as exc:
            original_reason = str(exc)
            if sidecar is None:
                rejected.append(
                    {
                        "frame_number": frame_number or None,
                        "reason": original_reason,
                    }
                )
                continue

            try:
                reconciled_fields, reconciliation = reconcile_connect_ind_fields(
                    fields,
                    sidecar["records"],
                )
                record = parse_legacy_connect_ind(
                    reconciled_fields,
                    source_capture_path=str(source),
                    source_capture_sha256=sha_before,
                )
            except (BLEConnectionContextError, BLENordicSidecarError) as reconcile_exc:
                rejected.append(
                    {
                        "frame_number": frame_number or None,
                        "reason": (
                            f"{original_reason}; Nordic sidecar reconciliation "
                            f"failed: {reconcile_exc}"
                        ),
                    }
                )
                continue

            reconciliation["source"] = dict(sidecar["source"])
            reconciliation["pcap_rejection_reason"] = original_reason
            record["evidence_reconciliation"] = reconciliation
            reconciled_count += 1

        accepted.append(record)

    size_after = source.stat().st_size
    sha_after = _sha256_file(source)
    if size_after != size_before or sha_after != sha_before:
        raise BLEConnectionExtractionError(
            "Source capture changed during extraction; no report is trustworthy"
        )

    if sidecar is not None:
        try:
            verify_nordic_connect_req_sidecar_unchanged(sidecar)
        except BLENordicSidecarError as exc:
            raise BLEConnectionExtractionError(str(exc)) from exc

    return {
        "schema_version": BLE_CONNECTION_EXTRACTION_VERSION,
        "record_type": "ble_connection_context_extraction",
        "source_capture": {
            "path": str(source),
            "sha256": sha_before,
            "size_bytes": size_before,
        },
        "decoder": {
            "tool": "tshark",
            "version": decoder_version,
            "display_filter": CONNECT_IND_DISPLAY_FILTER,
            "fields": list(decoder_fields),
        },
        "summary": {
            "candidate_count": candidate_count,
            "accepted_count": len(accepted),
            "rejected_count": len(rejected),
        },
        "reconciliation": {
            "accepted_via_nordic_sidecar_count": reconciled_count,
        },
        "supplemental_sources": (
            [] if sidecar is None else [dict(sidecar["source"])]
        ),
        "connection_contexts": accepted,
        "rejected_candidates": rejected,
        "execution": {
            "status": "offline_pcap_extraction",
            "rf_performed": False,
            "network_performed": False,
        },
        "limitations": [
            "legacy CONNECT_IND only; AUX_CONNECT_REQ and related extended establishment are not extracted",
            "only fields exposed by the installed TShark dissector are considered",
            "rejected candidates are diagnostic records and are not connection-context evidence",
            "actual data-channel anchor, event counter, and channel-selection algorithm are not inferred",
        ],
    }
