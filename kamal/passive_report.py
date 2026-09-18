"""Structured evidence for passive BLE advertiser inventories."""

SCHEMA_VERSION = "0.6.0"


def build_report(
    *,
    source_pcap,
    source_metadata,
    devices,
    skipped,
    integrity,
    warnings,
    scan_request_targets,
    registries,
):
    """Build a passive inventory report from already-processed observations."""

    registry_metadata = {
        name: {
            "source": registry.get("source"),
            "source_commit": registry.get("source_commit"),
            "source_file": registry.get("source_file"),
            "generated_at_utc": registry.get("generated_at_utc"),
        }
        for name, registry in (
            ("company_identifiers", registries["company"]),
            ("service_uuids", registries["service"]),
            ("member_uuids", registries["member"]),
        )
    }

    return {
        "identifier_registries": registry_metadata,
        "schema_version": SCHEMA_VERSION,
        "source_pcap": str(source_pcap),
        "source_metadata": (
            str(source_metadata) if source_metadata is not None else None
        ),
        "advertiser_count": len(devices),
        "skipped_ambiguous_packets": skipped,
        "integrity": {
            "scope": "frames with advertising address",
            **integrity,
        },
        "warnings": warnings,
        "advertisers": devices,
        "scan_request_targets": scan_request_targets,
    }
