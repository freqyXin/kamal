"""CLI tests for offline BLE cross-run correlation."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "kamal-correlate"


def assessment(assessment_id, address):
    return {
        "schema_version": "0.9.0",
        "evidence_contract_version": "0.12.0",
        "assessment_id": assessment_id,
        "observations": [{
            "observation_id": f"observation:{assessment_id}",
            "source_id": (
                "sha256:" + ("a" * 64 if assessment_id == "run-a" else "b" * 64)
            ),
            "protocol": "ble",
            "evidence_type": "passive_ble",
            "report": {
                "advertisers": [{
                    "address": address,
                    "address_type": "public",
                }],
            },
        }],
    }


class BLECorrelationCLITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write_assessment(self, name, payload):
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(CLI), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_writes_cross_run_candidate(self):
        first = self.write_assessment(
            "run-a.json",
            assessment("run-a", "AA:BB:CC:DD:EE:FF"),
        )
        second = self.write_assessment(
            "run-b.json",
            assessment("run-b", "aa:bb:cc:dd:ee:ff"),
        )
        output = self.root / "correlation.json"
        result = self.run_cli(
            "--input", first,
            "--input", second,
            "--json", output,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload["record_type"], "ble_cross_run_correlation")
        self.assertEqual(len(payload["identity_candidates"]), 1)
        self.assertFalse(payload["identity_candidates"][0]["stable_identity"])

    def test_refuses_existing_output(self):
        first = self.write_assessment(
            "run-a.json",
            assessment("run-a", "AA:BB:CC:DD:EE:FF"),
        )
        second = self.write_assessment(
            "run-b.json",
            assessment("run-b", "AA:BB:CC:DD:EE:FF"),
        )
        output = self.root / "correlation.json"
        output.write_text("keep", encoding="utf-8")
        result = self.run_cli(
            "--input", first,
            "--input", second,
            "--json", output,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_text(encoding="utf-8"), "keep")

    def test_refuses_output_path_that_is_an_input(self):
        first = self.write_assessment(
            "run-a.json",
            assessment("run-a", "AA:BB:CC:DD:EE:FF"),
        )
        second = self.write_assessment(
            "run-b.json",
            assessment("run-b", "AA:BB:CC:DD:EE:FF"),
        )
        result = self.run_cli(
            "--input", first,
            "--input", second,
            "--json", first,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not overwrite", result.stderr)


if __name__ == "__main__":
    unittest.main()
