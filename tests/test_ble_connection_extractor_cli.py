"""CLI tests for offline legacy CONNECT_IND extraction."""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "kamal-extract-connect-ind"

loader = importlib.machinery.SourceFileLoader(
    "kamal_extract_connect_ind_cli",
    str(CLI),
)
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


def extraction_report(pcap):
    return {
        "schema_version": "0.12.0",
        "record_type": "ble_connection_context_extraction",
        "source_capture": {
            "path": str(pcap),
            "sha256": "a" * 64,
            "size_bytes": 10,
        },
        "decoder": {
            "tool": "tshark",
            "version": "TShark synthetic",
            "display_filter": "btle.advertising_header.pdu_type == 5",
            "fields": [],
        },
        "summary": {
            "candidate_count": 1,
            "accepted_count": 1,
            "rejected_count": 0,
        },
        "connection_contexts": [],
        "rejected_candidates": [],
        "execution": {
            "status": "offline_pcap_extraction",
            "rf_performed": False,
            "network_performed": False,
        },
        "limitations": [],
    }


class BLEConnectionExtractorCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pcap = self.root / "capture.pcap"
        self.pcap.write_bytes(b"synthetic")
        self.output = self.root / "contexts.json"

    def argv(self):
        return [
            "--pcap",
            str(self.pcap),
            "--json",
            str(self.output),
        ]

    def test_writes_create_only_offline_report(self):
        stdout = io.StringIO()
        with mock.patch.object(
            module,
            "extract_legacy_connect_ind_report",
            return_value=extraction_report(self.pcap),
        ) as extract:
            with contextlib.redirect_stdout(stdout):
                rc = module.main(self.argv())

        self.assertEqual(rc, 0)
        extract.assert_called_once_with(self.pcap, tshark="tshark")
        payload = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(payload["record_type"], "ble_connection_context_extraction")
        self.assertFalse(payload["execution"]["rf_performed"])
        self.assertFalse(payload["execution"]["network_performed"])
        self.assertIn("No RF or network operations", stdout.getvalue())

    def test_refuses_existing_output_before_extraction(self):
        self.output.write_text("preserve me", encoding="utf-8")
        stderr = io.StringIO()

        with mock.patch.object(
            module,
            "extract_legacy_connect_ind_report",
        ) as extract:
            with contextlib.redirect_stderr(stderr):
                rc = module.main(self.argv())

        self.assertEqual(rc, 1)
        extract.assert_not_called()
        self.assertEqual(
            self.output.read_text(encoding="utf-8"),
            "preserve me",
        )
        self.assertIn("refusing to overwrite", stderr.getvalue())

    def test_extraction_failure_does_not_create_output(self):
        stderr = io.StringIO()
        with mock.patch.object(
            module,
            "extract_legacy_connect_ind_report",
            side_effect=module.BLEConnectionExtractionError("synthetic failure"),
        ):
            with contextlib.redirect_stderr(stderr):
                rc = module.main(self.argv())

        self.assertEqual(rc, 1)
        self.assertFalse(self.output.exists())
        self.assertIn("synthetic failure", stderr.getvalue())

    def test_tshark_override_is_forwarded(self):
        argv = self.argv() + ["--tshark", "/opt/tshark"]
        with mock.patch.object(
            module,
            "extract_legacy_connect_ind_report",
            return_value=extraction_report(self.pcap),
        ) as extract:
            rc = module.main(argv)

        self.assertEqual(rc, 0)
        extract.assert_called_once_with(self.pcap, tshark="/opt/tshark")


if __name__ == "__main__":
    unittest.main()
