"""Tests for offline BLE legacy CONNECT_IND evidence normalization."""

import copy
import unittest

from kamal.ble_connection_context import (
    BLE_CONNECTION_CONTEXT_CONTRACT_VERSION,
    BLEConnectionContextError,
    CONNECT_IND_TSHARK_FIELDS,
    parse_legacy_connect_ind,
)


DIGEST = "a" * 64


def decoded_connect_ind():
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


class BLEConnectionContextTests(unittest.TestCase):
    def test_field_contract_includes_direct_connect_ind_inputs(self):
        required = {
            "frame.number",
            "frame.time_epoch",
            "nordic_ble.channel",
            "nordic_ble.crcok",
            "btle.advertising_header.pdu_type",
            "btle.advertising_header.randomized_tx",
            "btle.advertising_header.randomized_rx",
            "btle.advertising_header.ch_sel",
            "btle.initiator_address",
            "btle.advertising_address",
            "btle.link_layer_data.access_address",
            "btle.link_layer_data.crc_init",
            "btle.link_layer_data.window_size",
            "btle.link_layer_data.window_offset",
            "btle.link_layer_data.interval",
            "btle.link_layer_data.latency",
            "btle.link_layer_data.timeout",
            "btle.link_layer_data.channel_map",
            "btle.link_layer_data.hop",
            "btle.link_layer_data.sleep_clock_accuracy",
        }
        self.assertEqual(set(CONNECT_IND_TSHARK_FIELDS), required)

    def test_valid_connect_ind_is_hash_bound_and_direct(self):
        record = parse_legacy_connect_ind(
            decoded_connect_ind(),
            source_capture_path="/evidence/ch37.pcap",
            source_capture_sha256=DIGEST,
        )

        self.assertEqual(
            record["schema_version"],
            BLE_CONNECTION_CONTEXT_CONTRACT_VERSION,
        )
        self.assertEqual(record["record_type"], "ble_legacy_connect_ind")
        self.assertEqual(record["source_capture"]["sha256"], DIGEST)
        self.assertEqual(record["source_capture"]["frame_number"], 1844)
        self.assertTrue(record["observation"]["directly_observed"])
        self.assertTrue(record["observation"]["crc_valid"])
        self.assertEqual(record["observation"]["pdu_type"], "CONNECT_IND")
        self.assertEqual(record["observation"]["advertising_channel"], 37)
        self.assertEqual(
            record["observation"]["initiator"],
            {
                "address": "12:34:56:78:9A:BC",
                "address_type": "public",
            },
        )
        self.assertEqual(
            record["observation"]["advertiser"],
            {
                "address": "C3:1C:4D:45:DE:3F",
                "address_type": "random",
            },
        )

    def test_link_layer_values_are_normalized_without_scheduler_derivation(self):
        record = parse_legacy_connect_ind(
            decoded_connect_ind(),
            source_capture_path="/evidence/ch37.pcap",
            source_capture_sha256=DIGEST,
        )

        ll = record["observation"]["link_layer"]
        self.assertEqual(ll["access_address"], "0x12345678")
        self.assertEqual(ll["crc_init"], "0xabcdef")
        self.assertEqual(ll["channel_map_hex"], "ffffffff1f")
        self.assertEqual(ll["hop_increment"], 5)

        serialized_keys = repr(record).lower()
        self.assertNotIn("'anchor':", serialized_keys)
        self.assertNotIn("'event_counter':", serialized_keys)
        self.assertNotIn("'channel_selection_algorithm':", serialized_keys)
        self.assertNotIn("'scheduler':", serialized_keys)

    def test_execution_is_explicitly_offline(self):
        record = parse_legacy_connect_ind(
            decoded_connect_ind(),
            source_capture_path="/evidence/ch37.pcap",
            source_capture_sha256=DIGEST,
        )
        self.assertEqual(record["execution"]["status"], "offline_normalization")
        self.assertFalse(record["execution"]["rf_performed"])
        self.assertFalse(record["execution"]["network_performed"])

    def test_input_is_not_mutated(self):
        fields = decoded_connect_ind()
        before = copy.deepcopy(fields)
        parse_legacy_connect_ind(
            fields,
            source_capture_path="/evidence/ch37.pcap",
            source_capture_sha256=DIGEST,
        )
        self.assertEqual(fields, before)

    def test_rejects_crc_invalid_candidate(self):
        fields = decoded_connect_ind()
        fields["nordic_ble.crcok"] = "False"
        with self.assertRaisesRegex(BLEConnectionContextError, "crcok=true"):
            parse_legacy_connect_ind(
                fields,
                source_capture_path="/evidence/ch37.pcap",
                source_capture_sha256=DIGEST,
            )

    def test_rejects_non_connect_ind_pdu(self):
        fields = decoded_connect_ind()
        fields["btle.advertising_header.pdu_type"] = "0"
        with self.assertRaisesRegex(BLEConnectionContextError, "not a legacy CONNECT_IND"):
            parse_legacy_connect_ind(
                fields,
                source_capture_path="/evidence/ch37.pcap",
                source_capture_sha256=DIGEST,
            )

    def test_rejects_non_primary_channel(self):
        fields = decoded_connect_ind()
        fields["nordic_ble.channel"] = "15"
        with self.assertRaisesRegex(BLEConnectionContextError, "37, 38, or 39"):
            parse_legacy_connect_ind(
                fields,
                source_capture_path="/evidence/ch37.pcap",
                source_capture_sha256=DIGEST,
            )

    def test_rejects_missing_required_link_layer_field(self):
        fields = decoded_connect_ind()
        del fields["btle.link_layer_data.channel_map"]
        with self.assertRaisesRegex(BLEConnectionContextError, "missing required decoded field"):
            parse_legacy_connect_ind(
                fields,
                source_capture_path="/evidence/ch37.pcap",
                source_capture_sha256=DIGEST,
            )

    def test_rejects_invalid_capture_digest(self):
        with self.assertRaisesRegex(BLEConnectionContextError, "SHA-256"):
            parse_legacy_connect_ind(
                decoded_connect_ind(),
                source_capture_path="/evidence/ch37.pcap",
                source_capture_sha256="not-a-digest",
            )

    def test_rejects_malformed_channel_map(self):
        fields = decoded_connect_ind()
        fields["btle.link_layer_data.channel_map"] = "ff:ff"
        with self.assertRaisesRegex(BLEConnectionContextError, "five-byte"):
            parse_legacy_connect_ind(
                fields,
                source_capture_path="/evidence/ch37.pcap",
                source_capture_sha256=DIGEST,
            )

    def test_requires_valid_packet_timestamp(self):
        fields = decoded_connect_ind()
        fields["frame.time_epoch"] = ""
        with self.assertRaisesRegex(BLEConnectionContextError, "frame.time_epoch"):
            parse_legacy_connect_ind(
                fields,
                source_capture_path="/evidence/ch37.pcap",
                source_capture_sha256=DIGEST,
            )

    def test_rejects_invalid_connect_ind_timing_ranges(self):
        cases = (
            ("btle.link_layer_data.window_size", "0", "range 1..8"),
            ("btle.link_layer_data.interval", "5", "range 6..3200"),
            ("btle.link_layer_data.latency", "500", "range 0..499"),
            ("btle.link_layer_data.timeout", "9", "range 10..3200"),
            ("btle.link_layer_data.hop", "4", "range 5..16"),
            ("btle.link_layer_data.sleep_clock_accuracy", "8", "range 0..7"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                fields = decoded_connect_ind()
                fields[field] = value
                with self.assertRaisesRegex(BLEConnectionContextError, message):
                    parse_legacy_connect_ind(
                        fields,
                        source_capture_path="/evidence/ch37.pcap",
                        source_capture_sha256=DIGEST,
                    )

    def test_rejects_transmit_window_larger_than_interval_allows(self):
        fields = decoded_connect_ind()
        fields["btle.link_layer_data.interval"] = "6"
        fields["btle.link_layer_data.window_offset"] = "0"
        fields["btle.link_layer_data.window_size"] = "6"
        with self.assertRaisesRegex(BLEConnectionContextError, "transmit-window limit"):
            parse_legacy_connect_ind(
                fields,
                source_capture_path="/evidence/ch37.pcap",
                source_capture_sha256=DIGEST,
            )

    def test_rejects_window_offset_beyond_interval(self):
        fields = decoded_connect_ind()
        fields["btle.link_layer_data.window_offset"] = "25"
        with self.assertRaisesRegex(BLEConnectionContextError, "must not exceed interval"):
            parse_legacy_connect_ind(
                fields,
                source_capture_path="/evidence/ch37.pcap",
                source_capture_sha256=DIGEST,
            )

    def test_rejects_supervision_timeout_relationship_violation(self):
        fields = decoded_connect_ind()
        fields["btle.link_layer_data.interval"] = "40"
        fields["btle.link_layer_data.latency"] = "9"
        fields["btle.link_layer_data.timeout"] = "100"
        with self.assertRaisesRegex(BLEConnectionContextError, "supervision timeout"):
            parse_legacy_connect_ind(
                fields,
                source_capture_path="/evidence/ch37.pcap",
                source_capture_sha256=DIGEST,
            )

    def test_rejects_channel_map_reserved_bits(self):
        fields = decoded_connect_ind()
        fields["btle.link_layer_data.channel_map"] = "ff:ff:ff:ff:ff"
        with self.assertRaisesRegex(BLEConnectionContextError, "reserved bits"):
            parse_legacy_connect_ind(
                fields,
                source_capture_path="/evidence/ch37.pcap",
                source_capture_sha256=DIGEST,
            )

    def test_rejects_channel_map_with_fewer_than_two_used_channels(self):
        fields = decoded_connect_ind()
        fields["btle.link_layer_data.channel_map"] = "01:00:00:00:00"
        with self.assertRaisesRegex(BLEConnectionContextError, "at least two data channels"):
            parse_legacy_connect_ind(
                fields,
                source_capture_path="/evidence/ch37.pcap",
                source_capture_sha256=DIGEST,
            )


if __name__ == "__main__":
    unittest.main()
