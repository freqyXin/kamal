import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "bin" / "kamal-gatt"
PYTHON = ROOT / ".venv" / "bin" / "python"


class GattSurveyCLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [str(PYTHON), str(CLI), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

    def test_all_discovered_requires_acknowledgment(self):
        result = self.run_cli(
            "survey",
            "--all-discovered",
            "--output-dir",
            "/tmp/kamal-survey-test",
        )

        self.assertEqual(result.returncode, 8)
        self.assertIn(
            "All-discovered mode requires scope acknowledgment",
            result.stderr,
        )

    def test_all_discovered_valid_policy_stops_before_radio_activity(self):
        result = self.run_cli(
            "survey",
            "--all-discovered",
            "--acknowledge-scope",
            "--output-dir",
            "/tmp/kamal-survey-test",
        )

        self.assertEqual(result.returncode, 9)
        self.assertIn(
            "Survey mode is not implemented yet; no Bluetooth operations performed.",
            result.stderr,
        )

    def test_allowlist_valid_policy_stops_before_radio_activity(self):
        with tempfile.TemporaryDirectory() as tempdir:
            allowlist = Path(tempdir) / "allowlist.json"
            allowlist.write_text(
                json.dumps(["AA:BB:CC:DD:EE:FF"]),
                encoding="utf-8",
            )

            result = self.run_cli(
                "survey",
                "--allowlist",
                str(allowlist),
                "--output-dir",
                str(Path(tempdir) / "results"),
            )

        self.assertEqual(result.returncode, 9)
        self.assertIn(
            "Survey mode is not implemented yet; no Bluetooth operations performed.",
            result.stderr,
        )

    def test_allowlist_must_be_json_array(self):
        with tempfile.TemporaryDirectory() as tempdir:
            allowlist = Path(tempdir) / "allowlist.json"
            allowlist.write_text(
                json.dumps({"target": "AA:BB:CC:DD:EE:FF"}),
                encoding="utf-8",
            )

            result = self.run_cli(
                "survey",
                "--allowlist",
                str(allowlist),
                "--output-dir",
                str(Path(tempdir) / "results"),
            )

        self.assertEqual(result.returncode, 8)
        self.assertIn("Allowlist must be a JSON array", result.stderr)

    def test_allowlist_rejects_scope_acknowledgment(self):
        with tempfile.TemporaryDirectory() as tempdir:
            allowlist = Path(tempdir) / "allowlist.json"
            allowlist.write_text(
                json.dumps(["AA:BB:CC:DD:EE:FF"]),
                encoding="utf-8",
            )

            result = self.run_cli(
                "survey",
                "--allowlist",
                str(allowlist),
                "--acknowledge-scope",
                "--output-dir",
                str(Path(tempdir) / "results"),
            )

        self.assertEqual(result.returncode, 8)
        self.assertIn(
            "Scope acknowledgment is only valid for all-discovered mode",
            result.stderr,
        )

    def test_malformed_allowlist_json_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as tempdir:
            allowlist = Path(tempdir) / "allowlist.json"
            allowlist.write_text("[", encoding="utf-8")

            result = self.run_cli(
                "survey",
                "--allowlist",
                str(allowlist),
                "--output-dir",
                str(Path(tempdir) / "results"),
            )

        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
