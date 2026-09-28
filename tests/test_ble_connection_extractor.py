"""Tests for offline legacy CONNECT_IND extraction from PCAPs."""

import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path

from kamal.ble_connection_context import CONNECT_IND_TSHARK_FIELDS
from kamal.ble_connection_extractor import (
    BLEConnectionExtractionError,
    CONNECT_IND_DISPLAY_FILTER,
    extract_legacy_connect_ind_report,
)


def valid_fields():
    return {
        "frame.number": "1844",
        "frame.time_epoch": "1790616000.125000000",
        "nordic_ble.channel": "37",
        "nordic_ble.crcok": "True",
        "btle.advertising_header.pdu_type": "5",
        "btle.advertising_header.randomized_tx": "0",
        "btle.advertising_header.randomized_rx": "1",
        "btle.advertising_header.ch_sel": "1",
        "btle.initiator_address": "12:34:56:78:9a:bc",
        "btle.advertising_address": "c3:1c:4d:45:de:3f",
        "btle.link_layer_data.access_address": "0x12345678",
        "btle.link_layer_data.crc_init": "0xabcdef",
        "btle.link_layer_data.window_size": "2",
        "btle.link_layer_data.window_offset": "11",
        "btle.link_layer_data.interval": "24",
        "btle.link_layer_data.latency": "0",
        "btle.link_layer_data.timeout": "200",
        "btle.link_layer_data.channel_map": "ff:ff:ff:ff:1f",
        "btle.link_layer_data.hop": "5",
        "btle.link_layer_data.sleep_clock_accuracy": "1",
    }


def row(fields):
    return "\t".join(fields.get(field, "") for field in CONNECT_IND_TSHARK_FIELDS)


class FakeRunner:
    def __init__(self, stdout="", *, version="TShark (Wireshark) 4.4.18", returncode=0):
        self.stdout = stdout
        self.version = version
        self.returncode = returncode
        self.calls = []

    def __call__(self, command, *, capture_output, text, check):
        self.calls.append(list(command))
        if command[1:] == ["--version"]:
            return subprocess.CompletedProcess(
                command, 0, stdout=self.version + "\n", stderr=""
            )
        return subprocess.CompletedProcess(
            command,
            self.returncode,
            stdout=self.stdout,
            stderr="synthetic tshark failure" if self.returncode else "",
        )


class BLEConnectionExtractorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pcap = self.root / "capture.pcap"
        self.pcap.write_bytes(b"synthetic-pcap-bytes")

    def extract(self, runner):
        return extract_legacy_connect_ind_report(
            self.pcap,
            tshark="/usr/bin/tshark",
            runner=runner,
        )

    def test_valid_candidate_is_hash_bound_and_accepted(self):
        runner = FakeRunner(row(valid_fields()) + "\n")
        report = self.extract(runner)

        digest = hashlib.sha256(self.pcap.read_bytes()).hexdigest()
        self.assertEqual(report["source_capture"]["sha256"], digest)
        self.assertEqual(report["summary"], {
            "candidate_count": 1,
            "accepted_count": 1,
            "rejected_count": 0,
        })
        self.assertEqual(len(report["connection_contexts"]), 1)
        self.assertEqual(
            report["connection_contexts"][0]["source_capture"]["sha256"],
            digest,
        )
        self.assertFalse(report["execution"]["rf_performed"])
        self.assertFalse(report["execution"]["network_performed"])

    def test_tshark_command_uses_exact_contract_field_order(self):
        runner = FakeRunner(row(valid_fields()) + "\n")
        self.extract(runner)

        command = runner.calls[1]
        self.assertIn("-r", command)
        self.assertIn("-Y", command)
        self.assertEqual(command[command.index("-Y") + 1], CONNECT_IND_DISPLAY_FILTER)

        extracted_fields = [
            command[index + 1]
            for index, value in enumerate(command[:-1])
            if value == "-e"
        ]
        self.assertEqual(extracted_fields, list(CONNECT_IND_TSHARK_FIELDS))

    def test_crc_bad_candidate_is_rejected_not_promoted(self):
        fields = valid_fields()
        fields["nordic_ble.crcok"] = "False"
        report = self.extract(FakeRunner(row(fields) + "\n"))

        self.assertEqual(report["summary"]["candidate_count"], 1)
        self.assertEqual(report["summary"]["accepted_count"], 0)
        self.assertEqual(report["summary"]["rejected_count"], 1)
        self.assertEqual(report["connection_contexts"], [])
        self.assertIn("crcok=true", report["rejected_candidates"][0]["reason"])

    def test_missing_required_field_is_rejected_not_promoted(self):
        fields = valid_fields()
        fields["btle.link_layer_data.access_address"] = ""
        report = self.extract(FakeRunner(row(fields) + "\n"))

        self.assertEqual(report["summary"]["accepted_count"], 0)
        self.assertEqual(report["summary"]["rejected_count"], 1)
        self.assertIn(
            "missing required decoded field",
            report["rejected_candidates"][0]["reason"],
        )

    def test_decoder_field_count_mismatch_is_diagnostic_rejection(self):
        malformed = "\t".join(row(valid_fields()).split("\t")[:-1]) + "\n"
        report = self.extract(FakeRunner(malformed))

        self.assertEqual(report["summary"]["candidate_count"], 1)
        self.assertEqual(report["summary"]["accepted_count"], 0)
        self.assertEqual(report["summary"]["rejected_count"], 1)
        self.assertIn("field-count mismatch", report["rejected_candidates"][0]["reason"])

    def test_zero_candidates_is_successful_offline_report(self):
        report = self.extract(FakeRunner(""))
        self.assertEqual(report["summary"], {
            "candidate_count": 0,
            "accepted_count": 0,
            "rejected_count": 0,
        })
        self.assertEqual(report["connection_contexts"], [])
        self.assertEqual(report["rejected_candidates"], [])

    def test_tshark_failure_aborts_extraction(self):
        with self.assertRaisesRegex(BLEConnectionExtractionError, "status 2"):
            self.extract(FakeRunner(returncode=2))

    def test_missing_tshark_is_reported(self):
        def missing(command, *, capture_output, text, check):
            raise FileNotFoundError(command[0])

        with self.assertRaisesRegex(BLEConnectionExtractionError, "not found"):
            self.extract(missing)

    def test_empty_source_capture_is_rejected_before_tshark(self):
        self.pcap.write_bytes(b"")
        runner = FakeRunner(row(valid_fields()) + "\n")
        with self.assertRaisesRegex(BLEConnectionExtractionError, "empty"):
            self.extract(runner)
        self.assertEqual(runner.calls, [])

    def test_source_mutation_during_extraction_aborts(self):
        pcap = self.pcap

        class MutatingRunner(FakeRunner):
            def __call__(self, command, *, capture_output, text, check):
                result = super().__call__(
                    command,
                    capture_output=capture_output,
                    text=text,
                    check=check,
                )
                if command[1:] != ["--version"]:
                    pcap.write_bytes(b"changed-source-bytes")
                return result

        runner = MutatingRunner(row(valid_fields()) + "\n")
        with self.assertRaisesRegex(BLEConnectionExtractionError, "changed during extraction"):
            self.extract(runner)

    def test_decoder_version_is_recorded(self):
        report = self.extract(
            FakeRunner(
                row(valid_fields()) + "\n",
                version="TShark (Wireshark) 4.4.18",
            )
        )
        self.assertEqual(
            report["decoder"]["version"],
            "TShark (Wireshark) 4.4.18",
        )


if __name__ == "__main__":
    unittest.main()
