"""CLI tests for offline BLE intelligence enrichment."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from catalog_fixtures import write_bluetooth_snapshot


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "kamal-enrich"


def assessment_payload():
    return {
        "schema_version": "0.9.0",
        "assessment_id": "run-a",
        "evidence_contract_version": "0.12.0",
        "observations": [{
            "observation_id": "observation:test",
            "source_id": "sha256:" + ("a" * 64),
            "protocol": "ble",
            "evidence_type": "passive_ble",
            "report": {
                "advertisers": [{
                    "manufacturer_data": [{"company_id": 76, "payload_hex": "01ff"}],
                }],
            },
        }],
    }


def catalog_payload():
    return {
        "schema_version": "0.12.0",
        "catalog_id": "test-catalog",
        "catalog_revision": "device-cli-r1",
        "records": [{
            "record_id": "company-004c",
            "match": {"kind": "bluetooth_company_id", "company_id": 76},
            "claim": {"category": "manufacturer", "value": "Example Manufacturer"},
            "state": "documented",
            "confidence": "high",
            "source": {
                "source_type": "standard_registry",
                "title": "Public source",
                "locator": "https://example.invalid/source",
            },
            "limitations": [],
        }],
    }


class DeviceIntelligenceCLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [str(CLI), *map(str, args)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_writes_enrichment_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            assessment = temp / "assessment.json"
            catalog = temp / "catalog.json"
            output = temp / "enrichment.json"
            assessment.write_text(json.dumps(assessment_payload()))
            catalog.write_text(json.dumps(catalog_payload()))

            result = self.run_cli(
                "--assessment", assessment,
                "--catalog", catalog,
                "--json", output,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output.read_text())
            self.assertEqual(payload["record_type"], "ble_device_intelligence_enrichment")
            self.assertEqual(payload["integrity"]["claim_count"], 1)
            self.assertEqual(payload["claims"][0]["state"], "documented")
            self.assertFalse(payload["claims"][0]["identity_assertion"])
            self.assertEqual(payload["claims"][0]["catalog_revision"], "device-cli-r1")
            provenance = payload["catalog_provenance"]
            self.assertEqual(len(provenance), 1)
            self.assertEqual(provenance[0]["catalog_type"], "ble_device_intelligence")
            self.assertEqual(provenance[0]["usage"], "consulted")

    def test_carries_explicit_bluetooth_snapshot_as_available(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            assessment = temp / "assessment.json"
            catalog = temp / "catalog.json"
            output = temp / "enrichment.json"
            snapshot = write_bluetooth_snapshot(temp / "snapshots")
            assessment.write_text(json.dumps(assessment_payload()))
            catalog.write_text(json.dumps(catalog_payload()))

            result = self.run_cli(
                "--assessment", assessment,
                "--catalog", catalog,
                "--bluetooth-snapshot", snapshot,
                "--json", output,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output.read_text())
            provenance = {
                item["catalog_type"]: item
                for item in payload["catalog_provenance"]
            }
            self.assertEqual(
                provenance["bluetooth_sig_assigned_numbers"]["usage"],
                "available",
            )
            self.assertEqual(
                provenance["ble_device_intelligence"]["usage"],
                "consulted",
            )

    def test_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            assessment = temp / "assessment.json"
            catalog = temp / "catalog.json"
            output = temp / "enrichment.json"
            assessment.write_text(json.dumps(assessment_payload()))
            catalog.write_text(json.dumps(catalog_payload()))
            output.write_text("keep-me")

            result = self.run_cli(
                "--assessment", assessment,
                "--catalog", catalog,
                "--json", output,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), "keep-me")

    def test_refuses_output_path_that_is_an_input(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            assessment = temp / "assessment.json"
            catalog = temp / "catalog.json"
            assessment.write_text(json.dumps(assessment_payload()))
            catalog.write_text(json.dumps(catalog_payload()))

            result = self.run_cli(
                "--assessment", assessment,
                "--catalog", catalog,
                "--json", assessment,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not overwrite an input", result.stderr)


if __name__ == "__main__":
    unittest.main()
