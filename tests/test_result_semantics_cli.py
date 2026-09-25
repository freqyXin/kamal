import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

from kamal.result_semantics import build_initial_effect_semantics, mark_executor_success


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "kamal-review-gatt-result"
spec = importlib.util.spec_from_file_location("kamal_review_gatt_result", CLI)
if spec is None or spec.loader is None:
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader("kamal_review_gatt_result", str(CLI))
    spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def operation_result():
    semantics = mark_executor_success(
        build_initial_effect_semantics("write_characteristic", write_mode="request"),
        "write_characteristic",
        write_mode="request",
    )
    return {
        "schema_version": "0.12.0",
        "record_type": "gatt_operation_result",
        "plan_id": "plan-1",
        "operation_id": "op-1",
        "operation_type": "write_characteristic",
        "target": {"address": "AA:BB:CC:DD:EE:FF", "address_type": "public"},
        "transport_success": True,
        "application_effect": "not_assessed",
        "effect_semantics": semantics,
        "error": None,
    }


def review_request():
    return {
        "schema_version": "0.12.0",
        "record_type": "gatt_effect_review_request",
        "review_id": "review-1",
        "reviewer": "analyst-1",
        "basis": "authorized lab review",
        "stages": {
            "application_acknowledgment": {
                "state": "observed",
                "basis": "protocol-specific application ack observed",
                "evidence": ["capture:application-ack-1"],
            }
        },
    }


class ResultSemanticsCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.operation = self.root / "operation.json"
        self.review = self.root / "review.json"
        self.output = self.root / "reviewed.json"
        self.operation.write_text(json.dumps(operation_result()), encoding="utf-8")
        self.review.write_text(json.dumps(review_request()), encoding="utf-8")

    def test_writes_hash_bound_offline_review(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = module.main([
                "--operation", str(self.operation),
                "--review", str(self.review),
                "--json", str(self.output),
            ])
        self.assertEqual(rc, 0)
        payload = json.loads(self.output.read_text())
        self.assertEqual(payload["record_type"], "gatt_effect_review")
        self.assertEqual(payload["effect_semantics"]["application_acknowledgment"]["state"], "observed")
        self.assertFalse(payload["execution"]["rf_performed"])
        self.assertIn("No RF or network operations", stdout.getvalue())

    def test_refuses_existing_output(self):
        self.output.write_text("{}")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = module.main([
                "--operation", str(self.operation),
                "--review", str(self.review),
                "--json", str(self.output),
            ])
        self.assertEqual(rc, 1)
        self.assertEqual(self.output.read_text(), "{}")

    def test_refuses_output_path_that_is_input(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = module.main([
                "--operation", str(self.operation),
                "--review", str(self.review),
                "--json", str(self.operation),
            ])
        self.assertEqual(rc, 1)
        self.assertIn("output path must differ", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
