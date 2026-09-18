"""Offline integration tests for the kamal-assess CLI."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from report_fixtures import active_report, passive_report


ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "bin" / "kamal-assess"


class AssessmentCLITests(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write_report(self, filename, report):
        path = self.root / filename
        path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(CLI), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def passive_report(self):
        return passive_report()

    def active_report(self):
        return active_report()

    def test_combines_reports_without_relationships(self):
        passive = self.write_report(
            "passive.json", self.passive_report()
        )
        active = self.write_report(
            "active.json", self.active_report()
        )
        output = self.root / "assessment.json"

        result = self.run_cli(
            "--assessment-id", "integration-test",
            "--input", passive,
            "--input", active,
            "--json", output,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.is_file())

        assessment = json.loads(output.read_text())

        self.assertEqual(
            assessment["assessment_id"], "integration-test"
        )
        self.assertEqual(assessment["schema_version"], "0.8.0")
        self.assertEqual(len(assessment["sources"]), 2)
        self.assertEqual(len(assessment["observations"]), 2)
        self.assertEqual(assessment["relationships"], [])

        # Verify original-byte provenance and preserved evidence.
        expected = {
            hashlib.sha256(path.read_bytes()).hexdigest(): json.loads(
                path.read_text(encoding="utf-8")
            )
            for path in (passive, active)
        }

        sources = {
            source["source_id"]: source
            for source in assessment["sources"]
        }

        observations = {
            observation["source_id"]: observation
            for observation in assessment["observations"]
        }

        self.assertEqual(len(sources), 2)
        self.assertEqual(set(sources), set(observations))

        for source_id, source in sources.items():
            digest = source["sha256"]

            self.assertEqual(source_id, f"sha256:{digest}")
            self.assertIn(digest, expected)
            self.assertEqual(
                observations[source_id]["report"],
                expected[digest],
            )
            self.assertEqual(
                observations[source_id]["evidence_type"],
                source["evidence_type"],
            )
            self.assertEqual(
                observations[source_id]["observation_id"],
                f"observation:{source_id}",
            )

        self.assertEqual(
            {source["evidence_type"] for source in sources.values()},
            {"passive_ble", "active_gatt"},
        )
        self.assertEqual(assessment["integrity"]["source_count"], 2)
        self.assertEqual(assessment["integrity"]["observation_count"], 2)

    def test_rejects_duplicate_inputs(self):
        source = self.write_report(
            "passive.json", self.passive_report()
        )
        output = self.root / "assessment.json"

        result = self.run_cli(
            "--assessment-id", "duplicate-test",
            "--input", source,
            "--input", source,
            "--json", output,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Duplicate source", result.stderr)
        self.assertFalse(output.exists())

    def test_rejects_malformed_report_without_creating_output(self):
        report = self.passive_report()
        report["advertiser_count"] = 5

        source = self.write_report("malformed.json", report)
        output = self.root / "assessment.json"

        result = self.run_cli(
            "--assessment-id", "malformed-test",
            "--input", source,
            "--json", output,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("advertiser_count", result.stderr)
        self.assertFalse(output.exists())

    def test_rejects_invalid_schema(self):
        source = self.write_report("invalid.json", {
            "schema_version": "99.0.0",
            "advertisers": [],
        })
        output = self.root / "assessment.json"

        result = self.run_cli(
            "--assessment-id", "invalid-test",
            "--input", source,
            "--json", output,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported", result.stderr)
        self.assertFalse(output.exists())

    def test_refuses_to_overwrite_source(self):
        source = self.write_report(
            "passive.json", self.passive_report()
        )
        original = source.read_bytes()

        result = self.run_cli(
            "--assessment-id", "overwrite-test",
            "--input", source,
            "--json", source,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not overwrite", result.stderr)
        self.assertEqual(source.read_bytes(), original)

    def test_refuses_to_overwrite_existing_output(self):
        source = self.write_report(
            "passive.json", self.passive_report()
        )
        output = self.root / "existing.json"
        output.write_text("preserve me", encoding="utf-8")

        result = self.run_cli(
            "--assessment-id", "existing-test",
            "--input", source,
            "--json", output,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_text(), "preserve me")

    def test_refuses_hard_link_to_source(self):
        source = self.write_report(
            "passive.json", self.passive_report()
        )
        output = self.root / "hardlink.json"
        output.hardlink_to(source)
        original = source.read_bytes()

        result = self.run_cli(
            "--assessment-id", "hardlink-test",
            "--input", source,
            "--json", output,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not overwrite", result.stderr)
        self.assertEqual(source.read_bytes(), original)

    def test_rejects_empty_assessment_id(self):
        source = self.write_report(
            "passive.json", self.passive_report()
        )
        output = self.root / "assessment.json"

        result = self.run_cli(
            "--assessment-id", "",
            "--input", source,
            "--json", output,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("assessment_id must not be empty", result.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
