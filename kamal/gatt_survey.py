"""Target selection policy for authorized BLE surveys."""

import asyncio
from dataclasses import dataclass
from pathlib import Path


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


def _records_from_discovered(discovered, policy, max_devices):
    """Freeze one discovery snapshot into deterministic survey records."""
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

    return _records_from_discovered(
        discovered,
        policy,
        max_devices,
    )


async def start_live_target_record_discovery(
    *,
    policy: SurveyTargetPolicy,
    adapter: str,
    discover_seconds: float = 30,
    max_devices: int = 50,
    scanner_factory=None,
    sleep=asyncio.sleep,
):
    """Freeze a target snapshot while leaving the scanner active.

    BlueZ may remove transient device objects when discovery stops.  Active
    surveys therefore keep the scanner that created the BLEDevice objects
    alive until the sequential connection phase is complete.  The returned
    records are a frozen snapshot; later advertisements do not expand the
    authorized queue.
    """
    validate_discovery_settings(discover_seconds, max_devices)

    if not isinstance(policy, SurveyTargetPolicy):
        raise TypeError("policy must be a SurveyTargetPolicy")

    if not isinstance(adapter, str) or not adapter.strip():
        raise ValueError("adapter must be a nonempty string")

    if scanner_factory is None:
        from bleak import BleakScanner
        scanner_factory = BleakScanner

    scanner = scanner_factory(
        bluez={"adapter": adapter},
    )
    started = False

    try:
        await scanner.start()
        started = True
        await sleep(discover_seconds)
        discovered = dict(
            scanner.discovered_devices_and_advertisement_data
        )
        summary, records = _records_from_discovered(
            discovered,
            policy,
            max_devices,
        )
        return scanner, summary, records
    except Exception:
        if started:
            try:
                await scanner.stop()
            except Exception as stop_exc:
                raise RuntimeError(
                    "live discovery failed and scanner cleanup also failed: "
                    f"{type(stop_exc).__name__}: {stop_exc}"
                ) from stop_exc
        raise


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


class SurveyAbortedError(RuntimeError):
    """Unexpected inspection failure with completed outcomes preserved."""

    def __init__(self, address, outcomes, cause):
        self.address = address
        self.outcomes = list(outcomes)
        self.cause = cause
        super().__init__(
            f"Survey aborted at {address}: "
            f"{type(cause).__name__}: {cause}"
        )



async def run_survey_records(
    records,
    inspect,
    output_dir=None,
    on_outcome=None,
):
    """Inspect sequentially; persist and checkpoint before the next target."""
    outcomes = []

    for record in records:
        address = record["address"]

        try:
            report, status = await inspect(record)
        except Exception as exc:
            raise SurveyAbortedError(address, outcomes, exc) from exc

        try:
            connection = report["connection"]
            disconnect = report["disconnect"]

            if not isinstance(connection, dict):
                raise ValueError("Invalid connection lifecycle state")
            if not isinstance(disconnect, dict):
                raise ValueError("Invalid disconnect lifecycle state")

            for key in ("attempted", "completed"):
                if not isinstance(disconnect[key], bool):
                    raise ValueError(f"Invalid disconnect {key} state")

            if disconnect["completed"] and not disconnect["attempted"]:
                raise ValueError("Disconnect completed without an attempt")

            if not isinstance(connection.get("client_created"), bool):
                raise ValueError("Missing or invalid client creation state")

            if not isinstance(status, int) or isinstance(status, bool):
                raise ValueError("Invalid inspection status")

            if not isinstance(report, dict):
                raise ValueError("Invalid evidence report")

            if output_dir is not None:
                destination = (
                    Path(output_dir)
                    / f"device-{len(outcomes) + 1:03d}.json"
                )
                if destination.exists():
                    raise FileExistsError(
                        f"Refusing to overwrite evidence: {destination}"
                    )
                atomic_json_write(destination, report)

            outcome = {
                "address": address,
                "status": status,
                "report": report,
            }
            outcomes.append(outcome)

            if on_outcome is not None:
                on_outcome(list(outcomes))

        except Exception as exc:
            raise SurveyAbortedError(address, outcomes, exc) from exc

        if not cleanup_is_safe(report):
            break

    return outcomes



def persist_survey_reports(outcomes, output_dir):
    """Write one JSON evidence report per completed inspection."""
    import json
    from pathlib import Path

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    entries = []

    for index, outcome in enumerate(outcomes, start=1):
        filename = f"device-{index:03d}.json"
        path = output_dir / filename

        path.write_text(
            json.dumps(
                outcome["report"],
                indent=2,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )

        entries.append(
            {
                "address": outcome["address"],
                "status": outcome["status"],
                "report_path": filename,
            }
        )

    return entries



def summarize_survey_execution(target_count, outcomes):
    """Summarize progress and conservatively classify unsafe cleanup."""
    if target_count < 0 or len(outcomes) > target_count:
        raise ValueError("Invalid survey execution counts")

    inspected = len(outcomes)
    successful = sum(item["status"] == 0 for item in outcomes)
    stopped_unsafe = any(
        not cleanup_is_safe(item["report"])
        for item in outcomes
    )

    return {
        "target_count": target_count,
        "inspected_count": inspected,
        "successful_count": successful,
        "failed_count": inspected - successful,
        "not_inspected_count": target_count - inspected,
        "stopped_unsafe": stopped_unsafe,
        "complete": inspected == target_count and not stopped_unsafe,
    }


def build_execution_manifest(
    target_count,
    outcomes,
    abort_error=None,
    *,
    abort_cleanup_confirmed=False,
):
    """Build serializable execution state for the survey manifest."""
    summary = summarize_survey_execution(target_count, outcomes)

    execution = {
        **summary,
        "aborted": abort_error is not None,
        "abort": None,
        "results": [
            {
                "address": outcome["address"],
                "status": outcome["status"],
                "report_path": f"device-{index:03d}.json",
            }
            for index, outcome in enumerate(outcomes, start=1)
        ],
    }

    if abort_error is not None:
        execution["complete"] = False
        execution["abort"] = {
            "address": abort_error.address,
            "error": f"{type(abort_error.cause).__name__}: {abort_error.cause}",
            "cleanup_confirmed": bool(abort_cleanup_confirmed),
        }

    return execution

def atomic_json_write(path, payload):
    """Atomically replace a JSON checkpoint without leaving partial JSON."""
    import json
    import os
    import tempfile

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

        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def cleanup_is_safe(report):
    """Only a confirmed disconnect or pre-client failure permits continuation."""
    connection = report["connection"]
    disconnect = report["disconnect"]

    constructor_failed = (
        connection.get("client_created") is False
        and connection.get("error") is not None
        and disconnect["attempted"] is False
        and disconnect["completed"] is False
    )

    disconnected = (
        disconnect.get("attempted", True) is True
        and disconnect.get("completed") is True
        and disconnect.get("error") is None
    )

    return constructor_failed or disconnected


def validate_survey_timeout(timeout):
    import math

    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 1 <= timeout <= 30
    ):
        raise ValueError("timeout must be between 1 and 30 seconds")
