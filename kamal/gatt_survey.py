"""Target selection policy for authorized BLE surveys."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SurveyTargetPolicy:
    mode: str
    allowlist: frozenset[str] | None = None
    acknowledge_scope: bool = False

    def __post_init__(self):
        if self.mode == "allowlist":
            if self.acknowledge_scope:
                raise ValueError(
                    "Scope acknowledgment is only valid for all-discovered mode"
                )
            if not self.allowlist:
                raise ValueError("Allowlist mode requires at least one target")
            if any(
                not isinstance(address, str) or not address.strip()
                for address in self.allowlist
            ):
                raise ValueError("Allowlist contains an invalid target")

        elif self.mode == "all_discovered":
            if self.allowlist is not None:
                raise ValueError(
                    "All-discovered mode cannot include an allowlist"
                )
            if not self.acknowledge_scope:
                raise ValueError(
                    "All-discovered mode requires scope acknowledgment"
                )

        else:
            raise ValueError(f"Unsupported survey mode: {self.mode}")

    def permits(self, address: str) -> bool:
        """Return whether an advertised address passes this policy."""
        if not isinstance(address, str) or not address.strip():
            return False

        if self.mode == "all_discovered":
            return True

        return address.upper() in {
            target.upper() for target in self.allowlist
        }


def build_target_queue(
    discovered_addresses,
    policy: SurveyTargetPolicy,
    max_devices: int,
) -> list[str]:
    """Build a bounded, deterministic queue of permitted BLE addresses."""
    if isinstance(max_devices, bool) or not isinstance(max_devices, int):
        raise ValueError("max_devices must be a positive integer")

    if max_devices < 1:
        raise ValueError("max_devices must be a positive integer")

    if not isinstance(policy, SurveyTargetPolicy):
        raise TypeError("policy must be a SurveyTargetPolicy")

    permitted = {
        address.upper()
        for address in discovered_addresses
        if policy.permits(address)
    }

    return sorted(permitted)[:max_devices]


def validate_discovery_settings(discover_seconds, max_devices):
    """Reject invalid survey limits before starting discovery."""
    import math

    if (
        isinstance(discover_seconds, bool)
        or not isinstance(discover_seconds, (int, float))
        or not math.isfinite(discover_seconds)
        or not 1 <= discover_seconds <= 60
    ):
        raise ValueError("discover_seconds must be between 1 and 60")

    if (
        isinstance(max_devices, bool)
        or not isinstance(max_devices, int)
        or not 1 <= max_devices <= 100
    ):
        raise ValueError("max_devices must be between 1 and 100")


async def discover_target_records(
    *,
    policy: SurveyTargetPolicy,
    adapter: str,
    discover_seconds: float = 30,
    max_devices: int = 50,
    scanner=None,
):
    """Discover once and preserve objects for selected permitted targets."""
    validate_discovery_settings(discover_seconds, max_devices)

    if not isinstance(policy, SurveyTargetPolicy):
        raise TypeError("policy must be a SurveyTargetPolicy")

    if not isinstance(adapter, str) or not adapter.strip():
        raise ValueError("adapter must be a nonempty string")

    if scanner is None:
        from bleak import BleakScanner
        scanner = BleakScanner

    discovered = await scanner.discover(
        timeout=discover_seconds,
        return_adv=True,
        bluez={"adapter": adapter},
    )

    normalized = {
        address.upper(): value
        for address, value in discovered.items()
        if isinstance(address, str) and address.strip()
    }

    summary = summarize_discovery(
        normalized.keys(),
        policy,
        max_devices,
    )

    records = [
        {
            "address": address,
            "device": normalized[address][0],
            "advertisement": normalized[address][1],
        }
        for address in summary["targets"]
    ]

    return summary, records


async def discover_target_queue(
    *,
    policy: SurveyTargetPolicy,
    adapter: str,
    discover_seconds: float = 30,
    max_devices: int = 50,
    scanner=None,
):
    """Discover once and return serializable survey accounting."""
    summary, _ = await discover_target_records(
        policy=policy,
        adapter=adapter,
        discover_seconds=discover_seconds,
        max_devices=max_devices,
        scanner=scanner,
    )
    return summary

def summarize_discovery(discovered_addresses, policy, max_devices):
    """Account for discovery, scope filtering, and the selection cap."""
    if not isinstance(policy, SurveyTargetPolicy):
        raise TypeError("policy must be a SurveyTargetPolicy")

    # Validate the cap even when discovery returns no devices.
    build_target_queue([], policy, max_devices)

    unique = {
        address.upper()
        for address in discovered_addresses
        if isinstance(address, str) and address.strip()
    }

    permitted = {
        address for address in unique if policy.permits(address)
    }

    selected = build_target_queue(permitted, policy, max_devices)

    return {
        "discovered_count": len(unique),
        "permitted_count": len(permitted),
        "target_count": len(selected),
        "omitted_by_cap": len(permitted) - len(selected),
        "targets": selected,
    }
