import asyncio
import importlib.util
from importlib.machinery import SourceFileLoader
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
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

    def write_survey_authorization(self, root, addresses):
        path = Path(root) / "authorization.json"
        payload = {
            "schema_version": "0.12.0",
            "record_type": "authorization_scope",
            "authorization_id": "auth:survey-test",
            "engagement_id": "engagement:survey-test",
            "owner": "Test Owner",
            "operator": "Tester",
            "location": "authorized lab",
            "issued_at_utc": "2020-01-01T00:00:00Z",
            "not_before_utc": "2020-01-01T00:00:00Z",
            "expires_at_utc": "2099-01-01T00:00:00Z",
            "targets": [
                {
                    "protocol": "ble",
                    "address": address,
                    "address_type": "unknown",
                    "label": "authorized survey target",
                }
                for address in addresses
            ],
            "allowed_operations": ["enumerate_gatt_metadata"],
            "constraints": {
                "max_operations": len(addresses),
                "max_payload_bytes": 0,
                "max_timeout_seconds": 5,
                "max_subscription_seconds": 1,
                "allow_writes": False,
                "allow_write_without_response": False,
            },
            "approval": {
                "approver": "Test Owner",
                "approved_at_utc": "2020-01-01T00:00:00Z",
                "basis": "synthetic authorized survey",
            },
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def successful_report(self, address, authorization_provenance):
        report = self.cli.new_report(
            address,
            "hci0",
            authorization=authorization_provenance,
        )
        report["connection"].update({
            "attempted": True,
            "connected": True,
            "error": None,
            "client_created": True,
        })
        report["gatt"].update({
            "enumeration_attempted": True,
            "enumerated": True,
            "error": None,
            "services": [],
        })
        report["disconnect"].update({
            "attempted": True,
            "completed": True,
            "error": None,
        })
        return report

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

    def test_active_survey_requires_authorization_and_safety_state(self):
        with tempfile.TemporaryDirectory() as tempdir:
            tempdir = Path(tempdir)
            allowlist = tempdir / "allowlist.json"
            allowlist.write_text(
                json.dumps(["AA:BB:CC:DD:EE:FF"]),
                encoding="utf-8",
            )

            status, _, stderr = self.run_async_main([
                "survey",
                "--allowlist",
                str(allowlist),
                "--execute",
                "--output-dir",
                str(tempdir / "results"),
            ])

        self.assertEqual(status, 8)
        self.assertIn("--authorization", stderr)

    def test_active_survey_binds_authorization_and_releases_safety_state(self):
        address = "AA:BB:CC:DD:EE:FF"

        with tempfile.TemporaryDirectory() as tempdir:
            tempdir = Path(tempdir)
            allowlist = tempdir / "allowlist.json"
            allowlist.write_text(json.dumps([address]), encoding="utf-8")
            authorization = self.write_survey_authorization(tempdir, [address])
            output_dir = tempdir / "results"
            safety_dir = tempdir / "safety"

            device = SimpleNamespace(address=address)
            advertisement = SimpleNamespace()
            scanner = SimpleNamespace(stop=AsyncMock())
            fake_discovery = AsyncMock(return_value=(
                scanner,
                {
                    "discovered_count": 1,
                    "permitted_count": 1,
                    "target_count": 1,
                    "omitted_by_cap": 0,
                    "targets": [address],
                },
                [{
                    "address": address,
                    "device": device,
                    "advertisement": advertisement,
                }],
            ))

            async def inspect(**kwargs):
                self.assertEqual(scanner.stop.await_count, 0)
                return (
                    self.successful_report(
                        kwargs["device"].address,
                        kwargs["authorization_provenance"],
                    ),
                    0,
                )

            with patch(
                "kamal.gatt_survey.start_live_target_record_discovery",
                fake_discovery,
            ), patch.object(
                self.cli,
                "load_gatt_registries",
                return_value=({}, {}),
            ), patch.object(
                self.cli,
                "inspect_discovered_device",
                new=AsyncMock(side_effect=inspect),
            ):
                status, stdout, stderr = self.run_async_main([
                    "survey",
                    "--allowlist",
                    str(allowlist),
                    "--execute",
                    "--authorization",
                    str(authorization),
                    "--safety-state-dir",
                    str(safety_dir),
                    "--discover-seconds",
                    "1",
                    "--max-devices",
                    "1",
                    "--timeout",
                    "5",
                    "--output-dir",
                    str(output_dir),
                ])

            self.assertEqual(status, 0)
            self.assertEqual(stderr, "")
            manifest = json.loads(
                (output_dir / "survey-manifest.json").read_text()
            )
            digest = hashlib.sha256(authorization.read_bytes()).hexdigest()
            self.assertEqual(manifest["phase"], "completed")
            self.assertEqual(
                manifest["authorization"]["authorization_id"],
                "auth:survey-test",
            )
            self.assertEqual(manifest["authorization"]["sha256"], digest)
            self.assertEqual(
                manifest["authorization"]["operation_class"],
                "enumerate_gatt_metadata",
            )
            self.assertEqual(manifest["safety_interlock"]["state"], "clear")
            self.assertEqual(
                manifest["scanner_lifecycle"],
                {
                    "kept_active_through_execution": True,
                    "stop_attempted": True,
                    "stop_completed": True,
                    "error": None,
                },
            )
            scanner.stop.assert_awaited_once()
            self.assertTrue((output_dir / "survey-execution-request.json").exists())
            report = json.loads((output_dir / "device-001.json").read_text())
            self.assertEqual(report["authorization"]["sha256"], digest)
            self.assertFalse((safety_dir / "active-run.json").exists())
            self.assertFalse((safety_dir / "unsafe-stop.json").exists())
            self.assertEqual(json.loads(stdout), manifest)

    def test_active_survey_rejects_discovered_target_outside_scope_before_connection(self):
        authorized = "AA:BB:CC:DD:EE:FF"
        discovered = "11:22:33:44:55:66"

        with tempfile.TemporaryDirectory() as tempdir:
            tempdir = Path(tempdir)
            authorization = self.write_survey_authorization(
                tempdir, [authorized]
            )
            output_dir = tempdir / "results"
            safety_dir = tempdir / "safety"
            fake_discovery = AsyncMock(return_value=(
                SimpleNamespace(stop=AsyncMock()),
                {
                    "discovered_count": 1,
                    "permitted_count": 1,
                    "target_count": 1,
                    "omitted_by_cap": 0,
                    "targets": [discovered],
                },
                [{
                    "address": discovered,
                    "device": SimpleNamespace(address=discovered),
                    "advertisement": SimpleNamespace(),
                }],
            ))
            inspect = AsyncMock()

            with patch(
                "kamal.gatt_survey.start_live_target_record_discovery",
                fake_discovery,
            ), patch.object(
                self.cli,
                "load_gatt_registries",
                return_value=({}, {}),
            ), patch.object(
                self.cli,
                "inspect_discovered_device",
                new=inspect,
            ):
                status, _, stderr = self.run_async_main([
                    "survey",
                    "--all-discovered",
                    "--acknowledge-scope",
                    "--execute",
                    "--authorization",
                    str(authorization),
                    "--safety-state-dir",
                    str(safety_dir),
                    "--discover-seconds",
                    "1",
                    "--max-devices",
                    "1",
                    "--timeout",
                    "5",
                    "--output-dir",
                    str(output_dir),
                ])

            self.assertEqual(status, 9)
            self.assertIn("outside authorization scope", stderr)
            inspect.assert_not_awaited()
            manifest = json.loads(
                (output_dir / "survey-manifest.json").read_text()
            )
            self.assertEqual(manifest["phase"], "authorization_failed")
            self.assertEqual(manifest["safety_interlock"]["state"], "clear")
            self.assertFalse((safety_dir / "active-run.json").exists())
            self.assertFalse((safety_dir / "unsafe-stop.json").exists())

    def test_active_all_discovered_scope_allows_rotated_address(self):
        authorized = "AA:BB:CC:DD:EE:FF"
        discovered = "11:22:33:44:55:66"

        with tempfile.TemporaryDirectory() as tempdir:
            tempdir = Path(tempdir)
            authorization = self.write_survey_authorization(
                tempdir, [authorized]
            )
            payload = json.loads(authorization.read_text(encoding="utf-8"))
            payload["survey_scope"] = {
                "mode": "all_discovered",
                "scope_acknowledged": True,
            }
            authorization.write_text(
                json.dumps(payload),
                encoding="utf-8",
            )

            output_dir = tempdir / "results"
            safety_dir = tempdir / "safety"
            fake_discovery = AsyncMock(return_value=(
                SimpleNamespace(stop=AsyncMock()),
                {
                    "discovered_count": 1,
                    "permitted_count": 1,
                    "target_count": 1,
                    "omitted_by_cap": 0,
                    "targets": [discovered],
                },
                [{
                    "address": discovered,
                    "device": SimpleNamespace(address=discovered),
                    "advertisement": SimpleNamespace(),
                }],
            ))

            async def inspect(**kwargs):
                return (
                    self.successful_report(
                        kwargs["device"].address,
                        kwargs["authorization_provenance"],
                    ),
                    0,
                )

            with patch(
                "kamal.gatt_survey.start_live_target_record_discovery",
                fake_discovery,
            ), patch.object(
                self.cli,
                "load_gatt_registries",
                return_value=({}, {}),
            ), patch.object(
                self.cli,
                "inspect_discovered_device",
                new=AsyncMock(side_effect=inspect),
            ):
                status, stdout, stderr = self.run_async_main([
                    "survey",
                    "--all-discovered",
                    "--acknowledge-scope",
                    "--execute",
                    "--authorization",
                    str(authorization),
                    "--safety-state-dir",
                    str(safety_dir),
                    "--discover-seconds",
                    "1",
                    "--max-devices",
                    "1",
                    "--timeout",
                    "5",
                    "--output-dir",
                    str(output_dir),
                ])

            self.assertEqual(status, 0)
            self.assertEqual(stderr, "")
            manifest = json.loads(
                (output_dir / "survey-manifest.json").read_text()
            )
            self.assertEqual(manifest["phase"], "completed")
            self.assertEqual(
                manifest["authorization"]["survey_scope"],
                {
                    "mode": "all_discovered",
                    "scope_acknowledged": True,
                },
            )
            self.assertEqual(
                manifest["discovery"]["targets"],
                [discovered],
            )
            report = json.loads((output_dir / "device-001.json").read_text())
            self.assertEqual(
                report["authorization"]["survey_scope"],
                {
                    "mode": "all_discovered",
                    "scope_acknowledged": True,
                },
            )
            self.assertFalse((safety_dir / "active-run.json").exists())
            self.assertFalse((safety_dir / "unsafe-stop.json").exists())
            self.assertEqual(json.loads(stdout), manifest)

    def test_all_discovered_scope_is_rejected_with_allowlist_policy(self):
        address = "AA:BB:CC:DD:EE:FF"

        with tempfile.TemporaryDirectory() as tempdir:
            tempdir = Path(tempdir)
            allowlist = tempdir / "allowlist.json"
            allowlist.write_text(json.dumps([address]), encoding="utf-8")
            authorization = self.write_survey_authorization(
                tempdir, [address]
            )
            payload = json.loads(authorization.read_text(encoding="utf-8"))
            payload["survey_scope"] = {
                "mode": "all_discovered",
                "scope_acknowledged": True,
            }
            authorization.write_text(json.dumps(payload), encoding="utf-8")

            status, _, stderr = self.run_async_main([
                "survey",
                "--allowlist",
                str(allowlist),
                "--execute",
                "--authorization",
                str(authorization),
                "--safety-state-dir",
                str(tempdir / "safety"),
                "--discover-seconds",
                "1",
                "--max-devices",
                "1",
                "--timeout",
                "5",
                "--output-dir",
                str(tempdir / "results"),
            ])

            self.assertEqual(status, 9)
            self.assertIn(
                "requires acknowledged all-discovered survey policy",
                stderr,
            )

    def test_active_survey_unsafe_disconnect_latches_recovery(self):
        address = "AA:BB:CC:DD:EE:FF"

        with tempfile.TemporaryDirectory() as tempdir:
            tempdir = Path(tempdir)
            allowlist = tempdir / "allowlist.json"
            allowlist.write_text(json.dumps([address]), encoding="utf-8")
            authorization = self.write_survey_authorization(tempdir, [address])
            output_dir = tempdir / "results"
            safety_dir = tempdir / "safety"
            fake_discovery = AsyncMock(return_value=(
                SimpleNamespace(stop=AsyncMock()),
                {
                    "discovered_count": 1,
                    "permitted_count": 1,
                    "target_count": 1,
                    "omitted_by_cap": 0,
                    "targets": [address],
                },
                [{
                    "address": address,
                    "device": SimpleNamespace(address=address),
                    "advertisement": SimpleNamespace(),
                }],
            ))

            async def inspect(**kwargs):
                report = self.successful_report(
                    kwargs["device"].address,
                    kwargs["authorization_provenance"],
                )
                report["disconnect"].update({
                    "attempted": True,
                    "completed": False,
                    "error": "TimeoutError: disconnect uncertain",
                })
                return report, 6

            with patch(
                "kamal.gatt_survey.start_live_target_record_discovery",
                fake_discovery,
            ), patch.object(
                self.cli,
                "load_gatt_registries",
                return_value=({}, {}),
            ), patch.object(
                self.cli,
                "inspect_discovered_device",
                new=AsyncMock(side_effect=inspect),
            ):
                status, _, _ = self.run_async_main([
                    "survey",
                    "--allowlist",
                    str(allowlist),
                    "--execute",
                    "--authorization",
                    str(authorization),
                    "--safety-state-dir",
                    str(safety_dir),
                    "--discover-seconds",
                    "1",
                    "--max-devices",
                    "1",
                    "--timeout",
                    "5",
                    "--output-dir",
                    str(output_dir),
                ])

            self.assertEqual(status, 12)
            manifest = json.loads(
                (output_dir / "survey-manifest.json").read_text()
            )
            self.assertEqual(manifest["phase"], "stopped_unsafe")
            self.assertEqual(
                manifest["safety_interlock"]["state"],
                "recovery_required",
            )
            self.assertFalse((safety_dir / "active-run.json").exists())
            self.assertTrue((safety_dir / "unsafe-stop.json").exists())

    def test_active_survey_scanner_stop_failure_latches_recovery(self):
        address = "AA:BB:CC:DD:EE:FF"

        with tempfile.TemporaryDirectory() as tempdir:
            tempdir = Path(tempdir)
            allowlist = tempdir / "allowlist.json"
            allowlist.write_text(json.dumps([address]), encoding="utf-8")
            authorization = self.write_survey_authorization(tempdir, [address])
            output_dir = tempdir / "results"
            safety_dir = tempdir / "safety"
            scanner = SimpleNamespace(
                stop=AsyncMock(side_effect=RuntimeError("scanner stop failed"))
            )
            fake_discovery = AsyncMock(return_value=(
                scanner,
                {
                    "discovered_count": 1,
                    "permitted_count": 1,
                    "target_count": 1,
                    "omitted_by_cap": 0,
                    "targets": [address],
                },
                [{
                    "address": address,
                    "device": SimpleNamespace(address=address),
                    "advertisement": SimpleNamespace(),
                }],
            ))

            async def inspect(**kwargs):
                return (
                    self.successful_report(
                        kwargs["device"].address,
                        kwargs["authorization_provenance"],
                    ),
                    0,
                )

            with patch(
                "kamal.gatt_survey.start_live_target_record_discovery",
                fake_discovery,
            ), patch.object(
                self.cli,
                "load_gatt_registries",
                return_value=({}, {}),
            ), patch.object(
                self.cli,
                "inspect_discovered_device",
                new=AsyncMock(side_effect=inspect),
            ):
                status, _, stderr = self.run_async_main([
                    "survey",
                    "--allowlist",
                    str(allowlist),
                    "--execute",
                    "--authorization",
                    str(authorization),
                    "--safety-state-dir",
                    str(safety_dir),
                    "--discover-seconds",
                    "1",
                    "--max-devices",
                    "1",
                    "--timeout",
                    "5",
                    "--output-dir",
                    str(output_dir),
                ])

            self.assertEqual(status, 12)
            self.assertEqual(stderr, "")
            scanner.stop.assert_awaited_once()
            manifest = json.loads(
                (output_dir / "survey-manifest.json").read_text()
            )
            self.assertEqual(manifest["phase"], "stopped_unsafe")
            self.assertEqual(
                manifest["safety_interlock"]["state"],
                "recovery_required",
            )
            self.assertTrue(manifest["scanner_lifecycle"]["stop_attempted"])
            self.assertFalse(manifest["scanner_lifecycle"]["stop_completed"])
            self.assertIn(
                "scanner stop failed",
                manifest["scanner_lifecycle"]["error"],
            )
            self.assertFalse((safety_dir / "active-run.json").exists())
            self.assertTrue((safety_dir / "unsafe-stop.json").exists())

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
