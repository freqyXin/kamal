import asyncio
import importlib.util
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "bin" / "kamal-gatt"
loader = SourceFileLoader("kamal_gatt_registry_test", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


def registry(revision="test-commit"):
    return {
        "source_commit": revision,
        "source_file": "test.yaml",
        "generated_at_utc": "2026-09-17T00:00:00+00:00",
        "identifiers": {},
    }


class GattRegistryLoadingTests(unittest.TestCase):
    def test_matching_revisions(self):
        with patch.object(module, "load_registry", return_value=registry()):
            registries, provenance = module.load_gatt_registries()

        self.assertEqual(
            set(registries),
            {"service", "characteristic", "descriptor"},
        )
        self.assertEqual(provenance["source_commit"], "test-commit")

    def test_mismatched_revisions(self):
        with patch.object(
            module,
            "load_registry",
            side_effect=[
                registry("revision-a"),
                registry("revision-b"),
                registry("revision-a"),
            ],
        ):
            with self.assertRaisesRegex(ValueError, "different source revisions"):
                module.load_gatt_registries()

    def test_missing_registry(self):
        with patch.object(
            module,
            "load_registry",
            side_effect=FileNotFoundError("descriptor registry missing"),
        ):
            with self.assertRaises(FileNotFoundError):
                module.load_gatt_registries()

    def test_missing_registry_prevents_discovery(self):
        with (
            patch.object(
                module,
                "load_gatt_registries",
                side_effect=FileNotFoundError("registry missing"),
            ),
            patch.object(module, "parse_args") as args,
            patch.object(module, "inspect_target") as inspect,
        ):
            args.return_value.target = "AA:BB:CC:DD:EE:FF"
            args.return_value.adapter = "hci0"
            args.return_value.timeout = 3
            args.return_value.json_path = None

            status = asyncio.run(module.async_main())

        self.assertEqual(status, 7)
        inspect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
