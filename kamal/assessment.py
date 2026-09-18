"""Offline assessment construction from existing K'amal reports."""

import hashlib
from copy import deepcopy
import json
from datetime import datetime, timezone
from pathlib import Path

from kamal.report_validation import validate_report
from kamal.findings import validate_findings
from kamal.ble_intelligence import analyze_gatt_observation


SCHEMA_VERSION = "0.9.0"

SUPPORTED_REPORTS = {
    ("passive_ble", "0.6.0"),
    ("active_gatt", "0.7.0"),
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def classify_report(report):
    """Identify a supported report without inferring device identity."""

    schema = report.get("schema_version")

    if (
        schema == "0.6.0"
        and "advertisers" in report
        and "source_pcap" in report
    ):
        return "passive_ble"

    if (
        schema == "0.7.0"
        and report.get("evidence_type") == "active_gatt"
    ):
        return "active_gatt"

    raise ValueError("Unsupported K'amal report type or schema version")


def load_source(path):
    """Load a source report and retain its original-byte provenance."""

    path = Path(path).resolve()
    raw = path.read_bytes()
    report = json.loads(raw)

    if not isinstance(report, dict):
        raise ValueError(f"Report must be a JSON object: {path}")

    evidence_type = classify_report(report)
    schema = report["schema_version"]

    if (evidence_type, schema) not in SUPPORTED_REPORTS:
        raise ValueError(f"Unsupported report schema: {schema}")

    validate_report(report, evidence_type)

    digest = hashlib.sha256(raw).hexdigest()

    return {
        "source_id": f"sha256:{digest}",
        "path": str(path),
        "sha256": digest,
        "evidence_type": evidence_type,
        "schema_version": schema,
        "report": report,
    }


def build_assessment(sources, *, assessment_id, created_at_utc=None, findings=None):
    """Build an assessment without merging or modifying source evidence."""

    if not assessment_id or not assessment_id.strip():
        raise ValueError("assessment_id must not be empty")

    if not sources:
        raise ValueError("At least one source report is required")

    source_records = []
    observations = []
    seen = set()

    for source in sources:
        source_id = source["source_id"]

        if source_id in seen:
            raise ValueError(f"Duplicate source report: {source_id}")

        seen.add(source_id)

        source_records.append({
            "source_id": source_id,
            "path": source["path"],
            "sha256": source["sha256"],
            "evidence_type": source["evidence_type"],
            "schema_version": source["schema_version"],
        })

        observations.append({
            "observation_id": f"observation:{source_id}",
            "source_id": source_id,
            "protocol": "ble",
            "evidence_type": source["evidence_type"],
            "report": source["report"],
        })

    source_records.sort(key=lambda item: item["source_id"])
    observations.sort(key=lambda item: item["observation_id"])
    observation_reports = {
        item["observation_id"]: item["report"]
        for item in observations
    }
    if findings is None:
        findings = []
        for observation in observations:
            findings.extend(analyze_gatt_observation(observation))

    validated_findings = validate_findings(
        findings,
        observation_reports,
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "assessment_id": assessment_id,
        "created_at_utc": created_at_utc or utc_now(),
        "sources": source_records,
        "observations": observations,
        "relationships": [],
        "findings": deepcopy(validated_findings),
        "integrity": {
            "source_count": len(source_records),
            "observation_count": len(observations),
            "finding_count": len(validated_findings),
            "warnings": [],
        },
    }
