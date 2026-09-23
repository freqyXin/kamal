"""Failure-path tests for immutable assessment JSON persistence."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kamal.evidence_contracts import atomic_create_json


class AssessmentPersistenceFailureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.destination = self.root / "assessment.json"
        self.payload = {"schema_version": "0.9.0", "assessment_id": "failure-test"}

    def assert_unpublished_and_clean(self):
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".assessment.json.*.tmp")), [])

    def test_serialization_failure_does_not_publish(self):
        with self.assertRaises(TypeError):
            atomic_create_json(self.destination, {"bad": object()})
        self.assert_unpublished_and_clean()

    def test_file_sync_failure_does_not_publish(self):
        with mock.patch(
            "kamal.evidence_contracts.os.fsync",
            side_effect=OSError("simulated fsync failure"),
        ):
            with self.assertRaisesRegex(OSError, "simulated fsync failure"):
                atomic_create_json(self.destination, self.payload)
        self.assert_unpublished_and_clean()

    def test_link_failure_does_not_publish(self):
        with mock.patch(
            "kamal.evidence_contracts.os.link",
            side_effect=OSError("simulated link failure"),
        ):
            with self.assertRaisesRegex(OSError, "simulated link failure"):
                atomic_create_json(self.destination, self.payload)
        self.assert_unpublished_and_clean()

    def test_existing_destination_is_preserved(self):
        original = b'{"original": true}\n'
        self.destination.write_bytes(original)
        with self.assertRaises(FileExistsError):
            atomic_create_json(self.destination, self.payload)
        self.assertEqual(self.destination.read_bytes(), original)
        self.assertEqual(list(self.root.glob(".assessment.json.*.tmp")), [])

    def test_success_publishes_complete_json(self):
        atomic_create_json(self.destination, self.payload)
        self.assertEqual(
            json.loads(self.destination.read_text(encoding="utf-8")),
            self.payload,
        )
        self.assertEqual(list(self.root.glob(".assessment.json.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
