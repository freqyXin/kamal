"""Tests for Nordic-native CONNECT_REQ sidecar reconciliation."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from kamal.ble_nordic_sidecar import (
    BLENordicSidecarError,
    load_nordic_connect_req_sidecar,
    reconcile_connect_ind_fields,
)


def control_line(*, access_address=1348823646, timestamp="1790738821.304500"):
    return (
        f"{timestamp}\tT\tcontrol=0\tcommand=2\tdata="
        "BleRadioPacket { header: EventAdvertising, payload: ConnectReq("
        "ConnectReqPayload { adv_type: ADV_TYPE_CONNECT_REQ, "
        "initiator_address: BleAddress(88:a2:9e:c6:e9:9 public), "
        "advertising_address: BleAddress(0:1c:4d:45:de:3f public), "
        f"access_address: {access_address}, "
        "crc_init: 13551614, win_size: 3, win_offset: 12, interval: 30, "
        "latency: 0, timeout: 600, channel_map: 1099511627551, "
        "hop_length: 8, sca: 1 }) }\n"
    )


def pcap_fields():
    return {
        "frame.time_epoch": "1790738821.304145000",
        "btle.initiator_address": "88:a2:9e:c6:e9:09",
        "btle.advertising_address": "00:1c:4d:45:de:3f",
        "btle.advertising_header.randomized_tx": "False",
        "btle.advertising_header.randomized_rx": "False",
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


class BLENordicSidecarTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "extcap-control.log"
        self.path.write_text(control_line(), encoding="utf-8")

    def test_loads_hash_bound_native_connect_req(self):
        sidecar = load_nordic_connect_req_sidecar(self.path)
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()

        self.assertEqual(sidecar["source"]["sha256"], digest)
        self.assertEqual(len(sidecar["records"]), 1)
        record = sidecar["records"][0]
        self.assertEqual(record["initiator"], "88:A2:9E:C6:E9:09")
        self.assertEqual(record["advertiser"], "00:1C:4D:45:DE:3F")
        self.assertEqual(record["channel_map_hex"], "ffffffff1f")
        self.assertEqual(record["hop_increment"], 8)
        self.assertEqual(record["sleep_clock_accuracy_code"], 1)

    def test_rejects_malformed_native_address(self):
        self.path.write_text(
            control_line().replace(
                "88:a2:9e:c6:e9:9",
                "88:a2:9e:c6:e9:999",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            BLENordicSidecarError,
            "six-octet Bluetooth address",
        ):
            load_nordic_connect_req_sidecar(self.path)

    def test_reconciles_only_serialization_disagreement_fields(self):
        fields = pcap_fields()
        sidecar = load_nordic_connect_req_sidecar(self.path)

        reconciled, metadata = reconcile_connect_ind_fields(
            fields,
            sidecar["records"],
        )

        self.assertEqual(
            reconciled["btle.link_layer_data.channel_map"],
            "ffffffff1f",
        )
        self.assertEqual(reconciled["btle.link_layer_data.hop"], "8")
        self.assertEqual(
            reconciled["btle.link_layer_data.sleep_clock_accuracy"],
            "1",
        )
        self.assertEqual(
            reconciled["btle.link_layer_data.access_address"],
            fields["btle.link_layer_data.access_address"],
        )
        self.assertEqual(
            metadata["status"],
            "nordic_native_sidecar_reconciliation",
        )
        self.assertEqual(
            set(metadata["supplemented_fields"]),
            {
                "btle.link_layer_data.channel_map",
                "btle.link_layer_data.hop",
                "btle.link_layer_data.sleep_clock_accuracy",
            },
        )

    def test_shared_field_mismatch_fails_closed(self):
        fields = pcap_fields()
        fields["btle.link_layer_data.access_address"] = "0x12345678"
        sidecar = load_nordic_connect_req_sidecar(self.path)

        with self.assertRaisesRegex(
            BLENordicSidecarError,
            "no Nordic native CONNECT_REQ matches",
        ):
            reconcile_connect_ind_fields(fields, sidecar["records"])

    def test_out_of_window_record_fails_closed(self):
        self.path.write_text(
            control_line(timestamp="1790738830.000000"),
            encoding="utf-8",
        )
        sidecar = load_nordic_connect_req_sidecar(self.path)

        with self.assertRaisesRegex(
            BLENordicSidecarError,
            "no Nordic native CONNECT_REQ matches",
        ):
            reconcile_connect_ind_fields(pcap_fields(), sidecar["records"])


if __name__ == "__main__":
    unittest.main()
