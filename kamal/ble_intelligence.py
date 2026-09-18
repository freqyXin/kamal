"""Conservative, metadata-only BLE security observations."""


def analyze_gatt_observation(observation):
    """Identify GATT properties that warrant further security review."""
    if observation.get("evidence_type") != "active_gatt":
        return []

    report = observation["report"]
    gatt = report.get("gatt", {})

    if not gatt.get("enumerated") or gatt.get("error") is not None:
        return []

    findings = []

    for service_index, service in enumerate(gatt["services"]):
        for characteristic_index, characteristic in enumerate(
            service["characteristics"]
        ):
            if "write-without-response" not in characteristic["properties"]:
                continue

            path = (
                f"/gatt/services/{service_index}"
                f"/characteristics/{characteristic_index}/properties"
            )

            findings.append({
                "finding_id": (
                    f"finding:BLE-GATT-001:"
                    f"{observation['observation_id']}:"
                    f"{service_index}:{characteristic_index}"
                ),
                "rule_id": "BLE-GATT-001",
                "title": "Write Without Response characteristic requires review",
                "severity": "informational",
                "confidence": "low",
                "status": "potential",
                "evidence": [{
                    "observation_id": observation["observation_id"],
                    "path": path,
                }],
                "description": (
                    "GATT metadata advertises a characteristic with "
                    "the write-without-response property."
                ),
                "interpretation": (
                    "Review whether the characteristic accepts "
                    "security-sensitive commands and whether appropriate "
                    "access controls are enforced."
                ),
                "limitations": (
                    "Characteristic properties do not establish whether "
                    "writes succeed, require authentication or encryption, "
                    "or affect security-sensitive functionality. "
                    "No characteristic writes or pairing tests were performed."
                ),
            })

    return findings
