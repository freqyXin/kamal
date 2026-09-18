import asyncio
import importlib.util
from importlib.machinery import SourceFileLoader
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "bin" / "kamal-gatt"


def load_cli_module():
    loader = SourceFileLoader("kamal_gatt_cli", str(CLI))
    spec = importlib.util.spec_from_loader("kamal_gatt_cli", loader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GattSurveyCLITests(unittest.TestCase):
    def setUp(self):
        self.cli = load_cli_module()

    def run_async_main(self, args):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = asyncio.run(self.cli.async_main(args))

        return status, stdout.getvalue(), stderr.getvalue()

    def test_all_discovered_requires_acknowledgment(self):
        status, _, stderr = self.run_async_main([
            "survey",
            "--all-discovered",
            "--output-dir",
            "/tmp/kamal-survey-test",
        ])

        self.assertEqual(status, 8)
        self.assertIn(
            "All-discovered mode requires scope acknowledgment",
            stderr,
        )

    def test_all_discovered_writes_discovery_manifest(self):
        with tempfile.TemporaryDirectory() as tempdir:
            output_dir = Path(tempdir) / "results"

            fake_discovery = AsyncMock(return_value={
                "discovered_count": 3,
                "permitted_count": 3,
                "target_count": 2,
                "omitted_by_cap": 1,
                "targets": [
                    "AA:BB:CC:DD:EE:01",
                    "AA:BB:CC:DD:EE:02",
                ],
            })

            with patch(
                "kamal.gatt_survey.discover_target_queue",
                fake_discovery,
            ):
                status, stdout, stderr = self.run_async_main([
                    "survey",
                    "--all-discovered",
                    "--acknowledge-scope",
                    "--discover-seconds",
                    "5",
                    "--max-devices",
                    "10",
                    "--output-dir",
                    str(output_dir),
                ])

            self.assertEqual(status, 0)
            self.assertEqual(stderr, "")

            manifest_path = output_dir / "survey-manifest.json"
            self.assertTrue(manifest_path.exists())

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

            self.assertEqual(manifest["schema_version"], "0.10.0")
            self.assertEqual(manifest["phase"], "discovery_only")
            self.assertEqual(manifest["policy"]["mode"], "all_discovered")
            self.assertTrue(manifest["policy"]["scope_acknowledged"])
            self.assertEqual(manifest["discovery"]["target_count"], 2)
            self.assertEqual(
                manifest["discovery"]["targets"],
                [
                    "AA:BB:CC:DD:EE:01",
                    "AA:BB:CC:DD:EE:02",
                ],
            )

            printed = json.loads(stdout)
            self.assertEqual(printed, manifest)

            fake_discovery.assert_awaited_once()

    def test_allowlist_writes_discovery_manifest(self):
        with tempfile.TemporaryDirectory() as tempdir:
            tempdir = Path(tempdir)
            allowlist = tempdir / "allowlist.json"
            output_dir = tempdir / "results"

            allowlist.write_text(
                json.dumps(["AA:BB:CC:DD:EE:FF"]),
                encoding="utf-8",
            )

            fake_discovery = AsyncMock(return_value={
                "discovered_count": 2,
                "permitted_count": 1,
                "target_count": 1,
                "omitted_by_cap": 0,
                "targets": ["AA:BB:CC:DD:EE:FF"],
            })

            with patch(
                "kamal.gatt_survey.discover_target_queue",
                fake_discovery,
            ):
                status, _, stderr = self.run_async_main([
                    "survey",
                    "--allowlist",
                    str(allowlist),
                    "--output-dir",
                    str(output_dir),
                ])

            self.assertEqual(status, 0)
            self.assertEqual(stderr, "")

            manifest = json.loads(
                (output_dir / "survey-manifest.json").read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(manifest["policy"]["mode"], "allowlist")
            self.assertEqual(manifest["policy"]["allowlist_count"], 1)
            self.assertFalse(manifest["policy"]["scope_acknowledged"])
            self.assertEqual(
                manifest["discovery"]["targets"],
                ["AA:BB:CC:DD:EE:FF"],
            )

    def test_invalid_duration_fails_before_discovery(self):
        fake_discovery = AsyncMock()

        with patch(
            "kamal.gatt_survey.discover_target_queue",
            fake_discovery,
        ):
            status, _, stderr = self.run_async_main([
                "survey",
                "--all-discovered",
                "--acknowledge-scope",
                "--discover-seconds",
                "0",
                "--output-dir",
                "/tmp/kamal-survey-test",
            ])

        self.assertEqual(status, 8)
        self.assertIn("discover_seconds", stderr)
        fake_discovery.assert_not_awaited()

    def test_invalid_device_cap_fails_before_discovery(self):
        fake_discovery = AsyncMock()

        with patch(
            "kamal.gatt_survey.discover_target_queue",
            fake_discovery,
        ):
            status, _, stderr = self.run_async_main([
                "survey",
                "--all-discovered",
                "--acknowledge-scope",
                "--max-devices",
                "0",
                "--output-dir",
                "/tmp/kamal-survey-test",
            ])

        self.assertEqual(status, 8)
        self.assertIn("max_devices", stderr)
        fake_discovery.assert_not_awaited()

    def test_allowlist_must_be_json_array(self):
        with tempfile.TemporaryDirectory() as tempdir:
            allowlist = Path(tempdir) / "allowlist.json"
            allowlist.write_text(
                json.dumps({"target": "AA:BB:CC:DD:EE:FF"}),
                encoding="utf-8",
            )

            status, _, stderr = self.run_async_main([
                "survey",
                "--allowlist",
                str(allowlist),
                "--output-dir",
                str(Path(tempdir) / "results"),
            ])

        self.assertEqual(status, 8)
        self.assertIn("Allowlist must be a JSON array", stderr)

    def test_allowlist_rejects_scope_acknowledgment(self):
        with tempfile.TemporaryDirectory() as tempdir:
            allowlist = Path(tempdir) / "allowlist.json"
            allowlist.write_text(
                json.dumps(["AA:BB:CC:DD:EE:FF"]),
                encoding="utf-8",
            )

            status, _, stderr = self.run_async_main([
                "survey",
                "--allowlist",
                str(allowlist),
                "--acknowledge-scope",
                "--output-dir",
                str(Path(tempdir) / "results"),
            ])

        self.assertEqual(status, 8)
        self.assertIn(
            "Scope acknowledgment is only valid for all-discovered mode",
            stderr,
        )

    def test_malformed_allowlist_json_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as tempdir:
            allowlist = Path(tempdir) / "allowlist.json"
            allowlist.write_text("[", encoding="utf-8")

            status, _, _ = self.run_async_main([
                "survey",
                "--allowlist",
                str(allowlist),
                "--output-dir",
                str(Path(tempdir) / "results"),
            ])

        self.assertEqual(status, 8)

    def test_inspect_parser_remains_compatible(self):
        args = self.cli.parse_args([
            "inspect",
            "AA:BB:CC:DD:EE:FF",
            "--adapter",
            "hci1",
            "--timeout",
            "7",
        ])

        self.assertEqual(args.command, "inspect")
        self.assertEqual(args.target, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(args.adapter, "hci1")
        self.assertEqual(args.timeout, 7.0)


if __name__ == "__main__":
    unittest.main()
