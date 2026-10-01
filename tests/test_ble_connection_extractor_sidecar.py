"""Tests for CONNECT_IND extraction with Nordic-native supplemental evidence."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from kamal.ble_connection_context import CONNECT_IND_TSHARK_FIELDS
from kamal.ble_connection_extractor import (
    CONNECT_IND_EXTRACTOR_TSHARK_FIELDS,
    extract_legacy_connect_ind_report,
)


def fields():
    return {
        "frame.number": "725",
        "frame.time_epoch": "1790738821.304145000",
        "nordic_ble.channel": "39",
        "nordic_ble.crcok": "True",
        "nordic_ble.packet_counter": "21471",
        "btle.advertising_header.pdu_type": "0x05",
        "btle.advertising_header.randomized_tx": "False",
        "btle.advertising_header.randomized_rx": "False",
        "btle.advertising_header.ch_sel": "False",
        "btle.initiator_address": "88:a2:9e:c6:e9:09",
        "btle.advertising_address": "00:1c:4d:45:de:3f",
        "btle.link_layer_data.access_address": "0x50656a5e",
        "btle.link_layer_data.crc_init": "0xcec7fe",
        "btle.link_layer_data.window_size": "3",
        "btle.link_layer_data.window_offset": "12",
        "btle.link_layer_data.interval": "30",
        "btle.link_layer_data.latency": "0",
        "btle.link_layer_data.timeout": "600",
        "btle.link_layer_data.channel_map": "1fff000000",
        "btle.link_layer_data.hop": "1",
        "btle.link_layer_data.sleep_clock_accuracy": "0",
    }


def row(values, field_names=CONNECT_IND_EXTRACTOR_TSHARK_FIELDS):
    return "\t".join(values.get(name, "") for name in field_names)


def control_line(*, access_address=1348823646, packet_counter=21471):
    return (
        "1790738821.304500\tT\tcontrol=0\tcommand=2\tdata="
        "Packet { header: Header { id: PacketId(2), "
        f"packet_counter: {packet_counter}, protocol_version: VersionX(3) }}, "
        "BleRadioPacket { header: EventAdvertising, payload: ConnectReq("
        "ConnectReqPayload { adv_type: ADV_TYPE_CONNECT_REQ, "
        "initiator_address: BleAddress(88:a2:9e:c6:e9:09 public), "
        "advertising_address: BleAddress(00:1c:4d:45:de:3f public), "
        f"access_address: {access_address}, "
        "crc_init: 13551614, win_size: 3, win_offset: 12, interval: 30, "
        "latency: 0, timeout: 600, channel_map: 1099511627551, "
        "hop_length: 8, sca: 1 }) }\n"
    )


class FakeRunner:
    def __init__(self, stdout):
        self.stdout = stdout

    def __call__(self, command, *, capture_output, text, check):
        if command[1:] == ["--version"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="TShark (Wireshark) 4.4.18\n",
                stderr="",
            )
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=self.stdout,
            stderr="",
        )


class BLEConnectionExtractorSidecarTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.pcap = root / "capture.pcap"
        self.pcap.write_bytes(b"synthetic-pcap")
        self.control = root / "extcap-control.log"
        self.control.write_text(control_line(), encoding="utf-8")
        self.runner = FakeRunner(row(fields()) + "\n")

    def test_without_sidecar_corrupted_hop_remains_rejected(self):
        report = extract_legacy_connect_ind_report(
            self.pcap,
            tshark="/usr/bin/tshark",
            runner=FakeRunner(
                row(fields(), CONNECT_IND_TSHARK_FIELDS) + "\n"
            ),
        )

        self.assertEqual(report["summary"]["accepted_count"], 0)
        self.assertEqual(report["summary"]["rejected_count"], 1)
        self.assertIn(
            "range 5..16",
            report["rejected_candidates"][0]["reason"],
        )

    def test_matching_sidecar_produces_explicit_reconciled_context(self):
        report = extract_legacy_connect_ind_report(
            self.pcap,
            tshark="/usr/bin/tshark",
            runner=self.runner,
            nordic_control_log=self.control,
        )

        self.assertEqual(report["summary"]["accepted_count"], 1)
        self.assertEqual(report["summary"]["rejected_count"], 0)
        self.assertEqual(
            report["reconciliation"]["accepted_via_nordic_sidecar_count"],
            1,
        )
        self.assertEqual(len(report["supplemental_sources"]), 1)

        context = report["connection_contexts"][0]
        ll = context["observation"]["link_layer"]
        self.assertEqual(ll["channel_map_hex"], "ffffffff1f")
        self.assertEqual(ll["hop_increment"], 8)
        self.assertEqual(ll["sleep_clock_accuracy_code"], 1)

        reconciliation = context["evidence_reconciliation"]
        self.assertEqual(
            reconciliation["status"],
            "nordic_native_sidecar_reconciliation",
        )
        self.assertEqual(
            reconciliation["source_record"]["match_method"],
            "packet_counter",
        )
        self.assertEqual(
            reconciliation["source_record"]["packet_counter"],
            21471,
        )
        self.assertEqual(
            reconciliation["source_record"]["pcap_packet_counter"],
            21471,
        )
        self.assertIn(
            "range 5..16",
            reconciliation["pcap_rejection_reason"],
        )
        self.assertEqual(
            reconciliation["source"]["sha256"],
            report["supplemental_sources"][0]["sha256"],
        )

    def test_packet_counter_reconciles_when_pcap_timestamp_is_shifted(self):
        shifted = fields()
        shifted["frame.time_epoch"] = "1790738836.200529000"
        self.runner = FakeRunner(row(shifted) + "\n")

        report = extract_legacy_connect_ind_report(
            self.pcap,
            tshark="/usr/bin/tshark",
            runner=self.runner,
            nordic_control_log=self.control,
        )

        self.assertEqual(report["summary"]["accepted_count"], 1)
        reconciliation = report["connection_contexts"][0]["evidence_reconciliation"]
        self.assertEqual(
            reconciliation["source_record"]["match_method"],
            "packet_counter",
        )
        self.assertGreater(
            float(reconciliation["source_record"]["match_time_delta_seconds"]),
            2.0,
        )

    def test_mismatched_sidecar_does_not_promote_candidate(self):
        self.control.write_text(
            control_line(access_address=0x12345678),
            encoding="utf-8",
        )
        report = extract_legacy_connect_ind_report(
            self.pcap,
            tshark="/usr/bin/tshark",
            runner=self.runner,
            nordic_control_log=self.control,
        )

        self.assertEqual(report["summary"]["accepted_count"], 0)
        self.assertEqual(report["summary"]["rejected_count"], 1)
        self.assertIn(
            "sidecar reconciliation failed",
            report["rejected_candidates"][0]["reason"],
        )


if __name__ == "__main__":
    unittest.main()
