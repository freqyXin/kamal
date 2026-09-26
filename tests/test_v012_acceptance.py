import json
import tempfile
import unittest
from pathlib import Path

from kamal.v012_acceptance import AcceptanceError, run_v012_acceptance


class V012AcceptanceTests(unittest.TestCase):
    def run_acceptance(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        work = root / "work"
        report = run_v012_acceptance(work)
        return report, work

    def test_full_synthetic_acceptance_passes(self):
        report, _ = self.run_acceptance()
        self.assertEqual(report["summary"]["failed_count"], 0)
        self.assertEqual(
            report["summary"]["passed_count"], report["summary"]["check_count"]
        )
        self.assertTrue(report["summary"]["ready_for_controlled_hardware_read_acceptance"])
        self.assertFalse(report["summary"]["hardware_write_acceptance_performed"])

    def test_acceptance_is_explicitly_non_hardware(self):
        report, _ = self.run_acceptance()
        execution = report["execution"]
        self.assertEqual(execution["status"], "offline_synthetic_acceptance")
        self.assertFalse(execution["real_rf_performed"])
        self.assertFalse(execution["network_performed"])
        self.assertTrue(execution["synthetic_backend"])

    def test_cross_artifact_hash_bindings_pass(self):
        report, _ = self.run_acceptance()
        checks = report["checks"]
        for key in (
            "authorization_to_plan_hash_bound",
            "request_to_plan_hash_bound",
            "review_hash_bound_to_operation",
            "assessment_preserved_source_hash",
            "enrichment_hash_bound_to_assessment",
        ):
            self.assertTrue(checks[key], key)

    def test_executor_does_not_overclaim_write_effect(self):
        report, work = self.run_acceptance()
        self.assertTrue(report["checks"]["executor_did_not_claim_application_effect"])
        result = json.loads((work / "execution" / "operation-002.json").read_text())
        self.assertEqual(result["effect_semantics"]["protocol"]["state"], "write_request_completed")
        self.assertEqual(result["effect_semantics"]["application_acknowledgment"]["state"], "not_assessed")
        self.assertEqual(result["effect_semantics"]["state_change"]["state"], "not_assessed")
        self.assertEqual(result["effect_semantics"]["security_effect"]["state"], "not_assessed")

    def test_failure_matrix_gates_pass(self):
        report, _ = self.run_acceptance()
        for key in (
            "expired_authorization_fails_closed",
            "target_mismatch_fails_closed",
            "corrupt_plan_fails_before_rf_boundary",
            "unsafe_latch_blocks_followup_before_rf_boundary",
            "orphaned_active_run_blocks_followup_before_rf_boundary",
            "safe_failure_preserves_partial_evidence",
            "uncertain_disconnect_requires_recovery",
            "connection_loss_stops_remaining_operations",
            "artifact_no_overwrite",
        ):
            self.assertTrue(report["checks"][key], key)

    def test_bsam_remains_non_pass_fail(self):
        report, work = self.run_acceptance()
        self.assertTrue(report["checks"]["bsam_no_pass_fail_inference"])
        mapping = json.loads((work / "bsam-mapping.json").read_text())
        self.assertFalse(mapping["summary"]["pass_fail_determinations_made"])
        self.assertGreaterEqual(mapping["summary"]["candidate_concern_count"], 1)

    def test_happy_path_clears_safety_state(self):
        report, work = self.run_acceptance()
        self.assertTrue(report["checks"]["safety_interlock_clear_after_happy_path"])
        self.assertFalse((work / "safety" / "active-run.json").exists())
        self.assertFalse((work / "safety" / "unsafe-stop.json").exists())

    def test_artifact_records_have_real_hashes_and_sizes(self):
        report, _ = self.run_acceptance()
        for name, ref in report["artifacts"].items():
            self.assertEqual(len(ref["sha256"]), 64, name)
            self.assertGreater(ref["size_bytes"], 0, name)
            self.assertTrue(Path(ref["path"]).exists(), name)

    def test_existing_work_directory_fails_closed(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        work = Path(td.name) / "work"
        work.mkdir()
        with self.assertRaisesRegex(AcceptanceError, "already exists"):
            run_v012_acceptance(work)

    def test_offline_module_boundary_check_passes(self):
        report, _ = self.run_acceptance()
        self.assertTrue(report["checks"]["offline_module_boundaries"])
        self.assertIn("ble_intelligence.py", report["offline_modules_checked"])
        self.assertIn("device_intelligence.py", report["offline_modules_checked"])
        self.assertIn("bluetooth_security.py", report["offline_modules_checked"])
        self.assertIn("bluez_security_state.py", report["offline_modules_checked"])


if __name__ == "__main__":
    unittest.main()
