"""Synthetic reports produced by K'amal's real report builders."""

from kamal.gatt_report import new_report
from kamal.passive_report import build_report


def passive_report(*, devices=None):
    registries = {
        name: {
            "source": "Synthetic Bluetooth SIG registry",
            "source_commit": "a" * 40,
            "source_file": f"{name}.yaml",
            "generated_at_utc": "2026-09-17T00:00:00+00:00",
        }
        for name in ("company", "service", "member")
    }

    return build_report(
        source_pcap="/tmp/synthetic.pcap",
        source_metadata=None,
        devices=[] if devices is None else devices,
        skipped=0,
        integrity={"valid": 0, "invalid": 0, "unknown": 0},
        warnings=[],
        scan_request_targets=[],
        registries=registries,
    )


def active_report(*, target="AA:BB:CC:DD:EE:FF"):
    report = new_report(target, "hci0")

    # A failed connection is legitimate evidence.
    report["connection"]["attempted"] = True
    report["connection"]["error"] = "Synthetic connection failure"

    return report
