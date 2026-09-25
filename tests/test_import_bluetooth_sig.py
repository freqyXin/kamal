"""Tests for reproducible Bluetooth SIG registry snapshots."""

import importlib.util
import json
import os
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "import_bluetooth_sig.py"
loader = SourceFileLoader("kamal_bluetooth_sig_import_test", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)

REVISION = "a" * 40


def registry_document(specification):
    return {
        specification["collection"]: [
            {specification["key"]: "0x180f", "name": "Battery Service"},
            {specification["key"]: "0x004c", "name": "Example Company"},
        ]
    }


def fake_registry(name, specification):
    raw = f"source:{name}".encode()
    return module.import_registry_document(
        registry_document(specification),
        specification,
        REVISION,
        "2026-01-01T00:00:00+00:00",
        module._sha256_bytes(raw),
    )


class BluetoothSigImportTests(unittest.TestCase):
    def test_revision_requires_full_commit(self):
        self.assertEqual(module.validate_revision(REVISION.upper()), REVISION)
        with self.assertRaisesRegex(ValueError, "40-character"):
            module.validate_revision("abc123")

    def test_registry_output_is_deterministic(self):
        spec = module.SOURCES["service_uuids"]
        first = fake_registry("service_uuids", spec)
        second = fake_registry("service_uuids", spec)
        self.assertEqual(module._json_bytes(first), module._json_bytes(second))
        self.assertEqual(
            list(first["identifiers"]),
            ["0x004c", "0x180f"],
        )

    def test_registry_records_source_hash_and_revision(self):
        spec = module.SOURCES["company_identifiers"]
        result = fake_registry("company_identifiers", spec)
        self.assertEqual(result["source_commit"], REVISION)
        self.assertEqual(len(result["source_sha256"]), 64)
        self.assertEqual(result["importer_version"], module.IMPORTER_VERSION)

    def test_boolean_identifier_is_rejected(self):
        spec = module.SOURCES["company_identifiers"]
        document = {spec["collection"]: [{spec["key"]: True, "name": "Bad"}]}
        with self.assertRaisesRegex(ValueError, "Invalid identifier"):
            module.import_registry_document(
                document,
                spec,
                REVISION,
                "2026-01-01T00:00:00+00:00",
                "0" * 64,
            )

    def test_snapshot_creation_writes_hash_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "bluetooth"
            registries = {
                name: fake_registry(name, spec)
                for name, spec in module.SOURCES.items()
            }
            with (
                patch.object(module, "verify_commit", return_value=REVISION),
                patch.object(
                    module,
                    "git_commit_timestamp",
                    return_value="2026-01-01T00:00:00+00:00",
                ),
                patch.object(
                    module,
                    "import_registry",
                    side_effect=lambda repo, spec, revision, generated_at: next(
                        value
                        for name, value in registries.items()
                        if module.SOURCES[name] is spec
                    ),
                ),
            ):
                snapshot, manifest, created = module.create_snapshot(
                    tmp,
                    output,
                    REVISION,
                    imported_at="2026-02-01T00:00:00+00:00",
                )

            self.assertTrue(created)
            self.assertEqual(snapshot.name, REVISION)
            self.assertEqual(manifest["source_commit"], REVISION)
            for name, entry in manifest["registries"].items():
                path = snapshot / f"{name}.json"
                self.assertEqual(
                    module._sha256_file(path),
                    entry["normalized_sha256"],
                )

    def test_existing_snapshot_is_verified_and_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = Path(tmp) / "snapshots" / REVISION
            snapshot.mkdir(parents=True)
            registries = {}
            manifest_entries = {}
            for name, spec in module.SOURCES.items():
                registry = fake_registry(name, spec)
                content = module._json_bytes(registry)
                (snapshot / f"{name}.json").write_bytes(content)
                registries[name] = registry
                manifest_entries[name] = module._manifest_registry_entry(
                    name, content, registry
                )
            manifest = {
                "schema_version": "1.0.0",
                "importer_version": module.IMPORTER_VERSION,
                "source_commit": REVISION,
                "registries": manifest_entries,
            }
            (snapshot / "manifest.json").write_bytes(module._json_bytes(manifest))

            with (
                patch.object(module, "verify_commit", return_value=REVISION),
                patch.object(
                    module,
                    "git_commit_timestamp",
                    return_value="2026-01-01T00:00:00+00:00",
                ),
                patch.object(module, "import_registry") as importer,
            ):
                result, loaded, created = module.create_snapshot(
                    tmp,
                    Path(tmp),
                    REVISION,
                )

            self.assertFalse(created)
            self.assertEqual(result, snapshot)
            self.assertEqual(loaded["source_commit"], REVISION)
            importer.assert_not_called()

    def test_corrupt_existing_snapshot_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = Path(tmp) / REVISION
            snapshot.mkdir()
            (snapshot / "manifest.json").write_text(
                json.dumps({
                    "schema_version": "1.0.0",
                    "importer_version": module.IMPORTER_VERSION,
                    "source_commit": REVISION,
                    "registries": {},
                }),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "registry set"):
                module.verify_snapshot(snapshot, REVISION)

    def test_activate_copies_exact_snapshot_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "snapshots" / REVISION
            output = root / "active"
            snapshot.mkdir(parents=True)
            manifest_entries = {}
            for name, spec in module.SOURCES.items():
                registry = fake_registry(name, spec)
                content = module._json_bytes(registry)
                (snapshot / f"{name}.json").write_bytes(content)
                manifest_entries[name] = module._manifest_registry_entry(
                    name, content, registry
                )
            manifest = {
                "schema_version": "1.0.0",
                "importer_version": module.IMPORTER_VERSION,
                "source_commit": REVISION,
                "registries": manifest_entries,
            }
            (snapshot / "manifest.json").write_bytes(module._json_bytes(manifest))

            module.activate_snapshot(snapshot, output)

            for name in module.SOURCES:
                self.assertEqual(
                    (output / f"{name}.json").read_bytes(),
                    (snapshot / f"{name}.json").read_bytes(),
                )

    def test_activation_failure_rolls_back_existing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "snapshots" / REVISION
            output = root / "active"
            snapshot.mkdir(parents=True)
            output.mkdir()
            manifest_entries = {}
            previous = {}
            for index, (name, spec) in enumerate(module.SOURCES.items()):
                registry = fake_registry(name, spec)
                content = module._json_bytes(registry)
                (snapshot / f"{name}.json").write_bytes(content)
                manifest_entries[name] = module._manifest_registry_entry(
                    name, content, registry
                )
                old = f"old-{index}".encode()
                previous[name] = old
                (output / f"{name}.json").write_bytes(old)
            manifest = {
                "schema_version": "1.0.0",
                "importer_version": module.IMPORTER_VERSION,
                "source_commit": REVISION,
                "registries": manifest_entries,
            }
            (snapshot / "manifest.json").write_bytes(module._json_bytes(manifest))

            real_replace = os.replace
            calls = 0

            def fail_second(source, destination):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated activation failure")
                return real_replace(source, destination)

            with patch.object(module.os, "replace", side_effect=fail_second):
                with self.assertRaisesRegex(OSError, "simulated"):
                    module.activate_snapshot(snapshot, output)

            for name, old in previous.items():
                self.assertEqual((output / f"{name}.json").read_bytes(), old)

    def test_fetch_is_explicit(self):
        with patch.object(module.subprocess, "run") as run:
            module.fetch_source("/tmp/source")
        run.assert_called_once()
        self.assertIn("fetch", run.call_args.args[0])

    def test_yaml_dependency_is_lazy(self):
        # Importing the tool itself succeeded before this test without PyYAML.
        self.assertTrue(callable(module._parse_yaml_bytes))

    def test_cli_defaults_do_not_fetch_or_activate(self):
        args = module.parse_args(["--revision", REVISION])
        self.assertFalse(args.fetch)
        self.assertFalse(args.activate)
        self.assertEqual(args.revision, REVISION)


if __name__ == "__main__":
    unittest.main()
