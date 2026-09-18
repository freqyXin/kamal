"""Tests for JSON Pointer evidence resolution."""

import unittest

from kamal.findings import resolve_evidence_path


class EvidencePathTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "gatt": {
                "services": [
                    {"uuid": "1800"},
                    {"uuid": "1801"},
                ]
            },
            "a/b": {"~key": 42},
        }

    def test_nested_path(self):
        result = resolve_evidence_path(
            self.report, "/gatt/services/0/uuid"
        )
        self.assertEqual(result, "1800")

    def test_escaped_tokens(self):
        result = resolve_evidence_path(
            self.report, "/a~1b/~0key"
        )
        self.assertEqual(result, 42)

    def test_missing_field(self):
        with self.assertRaises(ValueError):
            resolve_evidence_path(self.report, "/gatt/missing")

    def test_out_of_range_index(self):
        with self.assertRaises(ValueError):
            resolve_evidence_path(self.report, "/gatt/services/99")

    def test_invalid_array_index(self):
        with self.assertRaises(ValueError):
            resolve_evidence_path(self.report, "/gatt/services/01")

    def test_non_numeric_array_index(self):
        with self.assertRaises(ValueError):
            resolve_evidence_path(self.report, "/gatt/services/abc")


    def test_rejects_unknown_escape(self):
        with self.assertRaisesRegex(ValueError, "Invalid JSON Pointer escape"):
            resolve_evidence_path(self.report, "/a~2b")

    def test_rejects_trailing_tilde(self):
        with self.assertRaisesRegex(ValueError, "Invalid JSON Pointer escape"):
            resolve_evidence_path(self.report, "/a~")


if __name__ == "__main__":
    unittest.main()
