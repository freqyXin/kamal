#!/usr/bin/env python3
"""Generate offline Bluetooth identifier registries from Bluetooth SIG YAML."""

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml


SOURCES = {
    "company_identifiers": {
        "path": "assigned_numbers/company_identifiers/company_identifiers.yaml",
        "collection": "company_identifiers",
        "key": "value",
    },
    "service_uuids": {
        "path": "assigned_numbers/uuids/service_uuids.yaml",
        "collection": "uuids",
        "key": "uuid",
    },
    "member_uuids": {
        "path": "assigned_numbers/uuids/member_uuids.yaml",
        "collection": "uuids",
        "key": "uuid",
    },
}


def git_revision(repo):
    return subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        text=True,
    ).strip()


def import_registry(repo, specification, revision, generated_at):
    source = repo / specification["path"]

    with source.open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream)

    entries = document[specification["collection"]]

    if not isinstance(entries, list):
        raise ValueError(f"Expected a list in {source}")

    identifiers = {}

    for entry in entries:
        value = entry[specification["key"]]
        name = entry["name"]

        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError(f"Invalid identifier: {value!r}")

        number = int(value, 0) if isinstance(value, str) else value

        if not 0 <= number <= 0xFFFF:
            raise ValueError(f"Identifier outside 16-bit range: {value!r}")

        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"Invalid name for {value!r}")

        identifier = f"0x{number:04x}"

        if identifier in identifiers:
            raise ValueError(f"Duplicate identifier: {identifier}")

        identifiers[identifier] = name

    if not identifiers:
        raise ValueError(f"No identifiers found in {source}")

    return {
        "schema_version": "1.0.0",
        "source": "Bluetooth SIG Assigned Numbers",
        "source_repository": "https://bitbucket.org/bluetooth-SIG/public.git",
        "source_file": specification["path"],
        "source_commit": revision,
        "generated_at_utc": generated_at,
        "identifiers": dict(sorted(identifiers.items())),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("/tmp/bluetooth-sig-public"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/bluetooth"),
    )
    args = parser.parse_args()

    repo = args.source.resolve()
    revision = git_revision(repo)
    generated_at = datetime.now(timezone.utc).isoformat()

    # Validate both registries before writing either output.
    registries = {
        name: import_registry(repo, spec, revision, generated_at)
        for name, spec in SOURCES.items()
    }

    args.output.mkdir(parents=True, exist_ok=True)

    for name, registry in registries.items():
        destination = args.output / f"{name}.json"

        destination.write_text(
            json.dumps(registry, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        print(
            f"{destination}: "
            f"{len(registry['identifiers'])} identifiers"
        )

    print(f"Bluetooth SIG revision: {revision}")


if __name__ == "__main__":
    main()
