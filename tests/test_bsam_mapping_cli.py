"""CLI tests for offline BSAM coverage mapping."""

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "kamal-map-bsam"


def assessment_payload():
    return {
        "schema_version": "0.9.0",
        "assessment_id": "run-a",
        "evidence_contract_version": "0.12.0",
        "observations": [{
            "observation_id": "observation:passive",
            "source_id": "sha256:" + ("c" * 64),
            "protocol": "ble",
            "evidence_type": "passive_ble",
            "report": {
                "schema_version": "0.6.0",
                "advertisers": [{
                    "address": "AA:BB:CC:DD:EE:FF",
                    "address_type": "random",
                    "names": ["SensorTag"],
                }],
            },
        }],
        "findings": [],
        "catalog_provenance": [],
    }


def enrichment_payload(assessment_path, *, assessment_id="run-a"):
    raw = assessment_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    return {
        "schema_version": "0.12.0",
        "record_type": "ble_device_intelligence_enrichment",
        "contract_version": "0.12.0",
        "assessment_source": {
            "assessment_source_id": f"sha256:{digest}",
            "assessment_id": assessment_id,
            "path": str(assessment_path),
            "sha256": digest,
        },
        "catalog_provenance": [],
        "claims": [],
    }


class BSAMMappingCLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [str(CLI), *map(str, args)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_writes_offline_mapping(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            assessment = temp / "assessment.json"
            output = temp / "bsam.json"
            assessment.write_text(json.dumps(assessment_payload()))
            result = self.run_cli("--assessment", assessment, "--json", output)
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output.read_text())
            self.assertEqual(payload["record_type"], "bsam_assessment_mapping")
            self.assertEqual(payload["profile"]["control_count"], 36)
            self.assertFalse(payload["execution"]["rf_performed"])
            self.assertFalse(payload["execution"]["network_performed"])
            self.assertIn("No RF or network operations were performed.", result.stdout)

    def test_accepts_bound_enrichment(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            assessment = temp / "assessment.json"
            enrichment = temp / "enrichment.json"
            output = temp / "bsam.json"
            assessment.write_text(json.dumps(assessment_payload()))
            enrichment.write_text(json.dumps(enrichment_payload(assessment)))
            result = self.run_cli(
                "--assessment", assessment,
                "--enrichment", enrichment,
                "--json", output,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output.read_text())
            self.assertIn("enrichment_source", payload)

    def test_rejects_enrichment_for_different_assessment(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            assessment = temp / "assessment.json"
            enrichment = temp / "enrichment.json"
            output = temp / "bsam.json"
            assessment.write_text(json.dumps(assessment_payload()))
            payload = enrichment_payload(assessment, assessment_id="other")
            enrichment.write_text(json.dumps(payload))
            result = self.run_cli(
                "--assessment", assessment,
                "--enrichment", enrichment,
                "--json", output,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertIn("assessment_id does not match", result.stderr)

    def test_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            assessment = temp / "assessment.json"
            output = temp / "bsam.json"
            assessment.write_text(json.dumps(assessment_payload()))
            output.write_text("keep-me")
            result = self.run_cli("--assessment", assessment, "--json", output)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), "keep-me")

    def test_refuses_output_path_that_is_input(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            assessment = Path(temp_dir) / "assessment.json"
            assessment.write_text(json.dumps(assessment_payload()))
            result = self.run_cli("--assessment", assessment, "--json", assessment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not overwrite an input", result.stderr)


if __name__ == "__main__":
    unittest.main()
