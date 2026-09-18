"""Evidence-backed security finding validation."""

SEVERITIES = frozenset({
    "informational", "low", "medium", "high", "critical"
})
CONFIDENCES = frozenset({"low", "medium", "high"})
STATUSES = frozenset({"potential", "confirmed"})


def validate_finding(finding, observation_reports):
    """Validate a finding against known assessment observations."""
    if not isinstance(finding, dict):
        raise ValueError("Finding must be an object")

    for field in (
        "finding_id", "rule_id", "title",
        "description", "interpretation", "limitations",
    ):
        if not isinstance(finding.get(field), str) or not finding[field].strip():
            raise ValueError(f"Invalid finding field: {field}")

    for field, allowed in (
        ("severity", SEVERITIES),
        ("confidence", CONFIDENCES),
        ("status", STATUSES),
    ):
        if finding.get(field) not in allowed:
            raise ValueError(f"Invalid finding {field}")

    evidence = finding.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("Finding requires evidence")

    for reference in evidence:
        if not isinstance(reference, dict):
            raise ValueError("Invalid evidence reference")
        observation_id = reference.get("observation_id")
        if not isinstance(observation_id, str) or not observation_id.strip():
            raise ValueError("Invalid evidence observation ID")
        if observation_id not in observation_reports:
            raise ValueError("Unknown evidence observation")
        path = reference.get("path")
        resolve_evidence_path(observation_reports[observation_id], path)

    return finding


def resolve_evidence_path(report, path):
    """Resolve a JSON Pointer relative to a preserved source report."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("Invalid evidence path")

    current = report

    for raw_token in path[1:].split("/"):
        for index, char in enumerate(raw_token):
            if char == "~" and (
                index + 1 >= len(raw_token)
                or raw_token[index + 1] not in "01"
            ):
                raise ValueError("Invalid JSON Pointer escape")

        token = raw_token.replace("~1", "/").replace("~0", "~")

        if isinstance(current, dict):
            if token not in current:
                raise ValueError("Evidence path does not resolve")
            current = current[token]

        elif isinstance(current, list):
            if not token.isascii() or not token.isdecimal():
                raise ValueError("Invalid evidence array index")
            if len(token) > 1 and token.startswith("0"):
                raise ValueError("Invalid evidence array index")

            index = int(token)
            if index >= len(current):
                raise ValueError("Evidence path does not resolve")

            current = current[index]

        else:
            raise ValueError("Evidence path does not resolve")

    return current


def validate_findings(findings, observation_reports):
    """Validate a collection of findings and reject duplicate IDs."""
    if not isinstance(findings, list):
        raise ValueError("Findings must be a list")

    seen = set()

    for finding in findings:
        validate_finding(finding, observation_reports)

        finding_id = finding["finding_id"]
        if finding_id in seen:
            raise ValueError(f"Duplicate finding ID: {finding_id}")

        seen.add(finding_id)

    return findings
