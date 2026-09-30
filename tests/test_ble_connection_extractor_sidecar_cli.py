"""CLI coverage for optional Nordic CONNECT_REQ sidecar forwarding."""

import contextlib
import importlib.machinery
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "kamal-extract-connect-ind"

loader = importlib.machinery.SourceFileLoader(
    "kamal_extract_connect_ind_sidecar_cli",
    str(CLI),
)
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


def report(pcap):
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
            "candidate_count": 0,
            "accepted_count": 0,
            "rejected_count": 0,
        },
        "reconciliation": {
            "accepted_via_nordic_sidecar_count": 0,
        },
        "supplemental_sources": [],
        "connection_contexts": [],
        "rejected_candidates": [],
        "execution": {
            "status": "offline_pcap_extraction",
            "rf_performed": False,
            "network_performed": False,
        },
        "limitations": [],
    }


class BLEConnectionExtractorSidecarCLITests(unittest.TestCase):
    def test_nordic_control_log_is_forwarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "capture.pcap"
            pcap.write_bytes(b"synthetic")
            control = root / "extcap-control.log"
            control.write_text("synthetic\n", encoding="utf-8")
            output = root / "contexts.json"

            stdout = io.StringIO()
            with mock.patch.object(
                module,
                "extract_legacy_connect_ind_report",
                return_value=report(pcap),
            ) as extract:
                with contextlib.redirect_stdout(stdout):
                    rc = module.main(
                        [
                            "--pcap",
                            str(pcap),
                            "--json",
                            str(output),
                            "--nordic-control-log",
                            str(control),
                        ]
                    )

            self.assertEqual(rc, 0)
            extract.assert_called_once_with(
                pcap,
                tshark="tshark",
                nordic_control_log=control,
            )
            self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
