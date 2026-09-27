#!/usr/bin/env python3
"""Build reproducible local Bluetooth SIG Assigned Numbers catalogs."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


IMPORTER_VERSION = "2.0.0"
SOURCE_REPOSITORY = "https://bitbucket.org/bluetooth-SIG/public.git"
REVISION_RE = re.compile(r"^[0-9a-fA-F]{40}$")

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
    "characteristic_uuids": {
        "path": "assigned_numbers/uuids/characteristic_uuids.yaml",
        "collection": "uuids",
        "key": "uuid",
    },
    "descriptor_uuids": {
        "path": "assigned_numbers/uuids/descriptors.yaml",
        "collection": "uuids",
        "key": "uuid",
    },
}


def _json_bytes(value):
    return (
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")


def _sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_revision(value):
    if not isinstance(value, str) or not REVISION_RE.fullmatch(value):
        raise ValueError("revision must be a full 40-character Git commit hash")
    return value.lower()


def _git(repo, *args):
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), *args],
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(detail or f"git {' '.join(args)} failed") from exc


def fetch_source(repo):
    subprocess.run(
        ["git", "-C", str(repo), "fetch", "--prune", "origin"],
        check=True,
    )


def verify_commit(repo, revision):
    revision = validate_revision(revision)
    _git(repo, "cat-file", "-e", f"{revision}^{{commit}}")
    resolved = _git(repo, "rev-parse", f"{revision}^{{commit}}").decode().strip()
    if resolved.lower() != revision:
        raise ValueError("requested revision did not resolve to the exact commit")
    return revision


def git_file_bytes(repo, revision, source_path):
    revision = validate_revision(revision)
    return _git(repo, "show", f"{revision}:{source_path}")


def git_commit_timestamp(repo, revision):
    revision = validate_revision(revision)
    value = _git(repo, "show", "-s", "--format=%cI", revision).decode().strip()
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("upstream commit timestamp is missing a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def _parse_yaml_bytes(raw, source_name):
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "PyYAML is required only for Bluetooth SIG catalog import"
        ) from exc

    try:
        return yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Unable to parse {source_name}") from exc


def import_registry_document(
    document,
    specification,
    revision,
    generated_at,
    source_sha256,
):
    if not isinstance(document, dict):
        raise ValueError(f"Expected a mapping in {specification['path']}")

    entries = document.get(specification["collection"])
    if not isinstance(entries, list):
        raise ValueError(f"Expected a list in {specification['path']}")

    identifiers = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(f"Invalid entry in {specification['path']}")

        value = entry.get(specification["key"])
        name = entry.get("name")

        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError(f"Invalid identifier: {value!r}")

        try:
            number = int(value, 0) if isinstance(value, str) else value
        except ValueError as exc:
            raise ValueError(f"Invalid identifier: {value!r}") from exc

        if not 0 <= number <= 0xFFFF:
            raise ValueError(f"Identifier outside 16-bit range: {value!r}")

        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"Invalid name for {value!r}")

        identifier = f"0x{number:04x}"
        if identifier in identifiers:
            raise ValueError(f"Duplicate identifier: {identifier}")
        identifiers[identifier] = name

    if not identifiers:
        raise ValueError(f"No identifiers found in {specification['path']}")

    return {
        "schema_version": "1.1.0",
        "importer_version": IMPORTER_VERSION,
        "source": "Bluetooth SIG Assigned Numbers",
        "source_repository": SOURCE_REPOSITORY,
        "source_file": specification["path"],
        "source_commit": revision,
        "source_sha256": source_sha256,
        "generated_at_utc": generated_at,
        "identifiers": dict(sorted(identifiers.items())),
    }


def import_registry(repo, specification, revision, generated_at):
    raw = git_file_bytes(repo, revision, specification["path"])
    document = _parse_yaml_bytes(raw, specification["path"])
    return import_registry_document(
        document,
        specification,
        revision,
        generated_at,
        _sha256_bytes(raw),
    )


def _manifest_registry_entry(name, registry_bytes, registry):
    return {
        "filename": f"{name}.json",
        "identifier_count": len(registry["identifiers"]),
        "normalized_sha256": _sha256_bytes(registry_bytes),
        "source_file": registry["source_file"],
        "source_sha256": registry["source_sha256"],
    }


def _load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_snapshot(snapshot_dir, revision):
    snapshot_dir = Path(snapshot_dir)
    manifest_path = snapshot_dir / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"snapshot is missing manifest: {snapshot_dir}")

    manifest = _load_json(manifest_path)
    if manifest.get("schema_version") != "1.0.0":
        raise ValueError("snapshot manifest has an unsupported schema")
    if manifest.get("source_commit") != revision:
        raise ValueError("snapshot manifest source commit does not match path")
    if manifest.get("importer_version") != IMPORTER_VERSION:
        raise ValueError("snapshot was produced by a different importer version")

    registries = manifest.get("registries")
    if not isinstance(registries, dict) or set(registries) != set(SOURCES):
        raise ValueError("snapshot manifest registry set is incomplete")

    for name in sorted(SOURCES):
        entry = registries[name]
        if not isinstance(entry, dict):
            raise ValueError(f"invalid manifest entry for {name}")
        filename = entry.get("filename")
        if filename != f"{name}.json":
            raise ValueError(f"invalid snapshot filename for {name}")
        registry_path = snapshot_dir / filename
        if not registry_path.is_file():
            raise ValueError(f"snapshot is missing {filename}")
        if _sha256_file(registry_path) != entry.get("normalized_sha256"):
            raise ValueError(f"snapshot hash mismatch for {filename}")

        registry = _load_json(registry_path)
        if registry.get("source_commit") != revision:
            raise ValueError(f"registry source commit mismatch for {filename}")
        if registry.get("source_sha256") != entry.get("source_sha256"):
            raise ValueError(f"registry source hash mismatch for {filename}")

    return manifest


def create_snapshot(repo, output, revision, imported_at=None):
    repo = Path(repo).resolve()
    output = Path(output).resolve()
    revision = verify_commit(repo, revision)
    generated_at = git_commit_timestamp(repo, revision)

    snapshots_dir = output / "snapshots"
    snapshot_dir = snapshots_dir / revision
    if snapshot_dir.exists():
        return snapshot_dir, verify_snapshot(snapshot_dir, revision), False

    registries = {
        name: import_registry(repo, spec, revision, generated_at)
        for name, spec in SOURCES.items()
    }
    registry_bytes = {
        name: _json_bytes(registry)
        for name, registry in registries.items()
    }

    if imported_at is None:
        imported_at = datetime.now(timezone.utc).isoformat()

    manifest = {
        "schema_version": "1.0.0",
        "importer_version": IMPORTER_VERSION,
        "source": "Bluetooth SIG Assigned Numbers",
        "source_repository": SOURCE_REPOSITORY,
        "source_commit": revision,
        "source_commit_time_utc": generated_at,
        "imported_at_utc": imported_at,
        "registries": {
            name: _manifest_registry_entry(
                name,
                registry_bytes[name],
                registries[name],
            )
            for name in sorted(SOURCES)
        },
    }

    snapshots_dir.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=f".{revision}.", dir=snapshots_dir))
    published = False
    try:
        for name in sorted(SOURCES):
            (temp_dir / f"{name}.json").write_bytes(registry_bytes[name])
        (temp_dir / "manifest.json").write_bytes(_json_bytes(manifest))

        try:
            os.rename(temp_dir, snapshot_dir)
            published = True
        except OSError:
            if snapshot_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
                return snapshot_dir, verify_snapshot(snapshot_dir, revision), False
            raise
    finally:
        if not published and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)

    verify_snapshot(snapshot_dir, revision)
    return snapshot_dir, manifest, True


def _write_temp_bytes(parent, name, content):
    fd, temp_name = tempfile.mkstemp(prefix=f".{name}.", dir=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise
    return Path(temp_name)


def activate_snapshot(snapshot_dir, output):
    snapshot_dir = Path(snapshot_dir).resolve()
    output = Path(output).resolve()
    revision = snapshot_dir.name
    verify_snapshot(snapshot_dir, revision)
    output.mkdir(parents=True, exist_ok=True)

    destinations = {
        name: output / f"{name}.json"
        for name in sorted(SOURCES)
    }
    previous = {
        name: path.read_bytes() if path.exists() else None
        for name, path in destinations.items()
    }
    staged = {}
    try:
        for name in sorted(SOURCES):
            staged[name] = _write_temp_bytes(
                output,
                f"{name}.json",
                (snapshot_dir / f"{name}.json").read_bytes(),
            )
    except BaseException:
        for temp_path in staged.values():
            temp_path.unlink(missing_ok=True)
        raise

    replaced = []
    try:
        for name in sorted(SOURCES):
            os.replace(staged[name], destinations[name])
            replaced.append(name)
    except BaseException as exc:
        rollback_errors = []
        for name in reversed(replaced):
            try:
                old = previous[name]
                if old is None:
                    destinations[name].unlink(missing_ok=True)
                else:
                    restore = _write_temp_bytes(
                        output,
                        f"rollback-{name}.json",
                        old,
                    )
                    os.replace(restore, destinations[name])
            except BaseException as rollback_exc:
                rollback_errors.append(f"{name}: {rollback_exc}")

        if rollback_errors:
            raise RuntimeError(
                "activation failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        raise
    finally:
        for temp_path in staged.values():
            temp_path.unlink(missing_ok=True)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Build a reproducible Bluetooth SIG registry snapshot."
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("/tmp/bluetooth-sig-public"),
        help="Existing clone of the Bluetooth SIG public repository.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/bluetooth"),
        help="K'amal Bluetooth data directory.",
    )
    parser.add_argument(
        "--revision",
        required=True,
        help="Full 40-character Bluetooth SIG Git commit to import.",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Explicitly fetch origin before resolving the requested commit.",
    )
    parser.add_argument(
        "--activate",
        action="store_true",
        help="Publish the completed snapshot as the active flat registries.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    repo = args.source.resolve()
    output = args.output.resolve()
    revision = validate_revision(args.revision)

    if args.fetch:
        fetch_source(repo)

    snapshot_dir, manifest, created = create_snapshot(
        repo,
        output,
        revision,
    )

    state = "created" if created else "verified existing"
    print(f"Snapshot {state}: {snapshot_dir}")
    for name in sorted(manifest["registries"]):
        entry = manifest["registries"][name]
        print(
            f"{entry['filename']}: "
            f"{entry['identifier_count']} identifiers "
            f"sha256:{entry['normalized_sha256']}"
        )

    if args.activate:
        activate_snapshot(snapshot_dir, output)
        print(f"Activated Bluetooth SIG revision: {revision}")
    else:
        print("Active registries unchanged (use --activate to publish).")

    print(f"Bluetooth SIG revision: {revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
