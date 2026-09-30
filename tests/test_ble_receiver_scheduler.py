"""Tests for the offline BLE receiver-scheduler contract."""

import copy
import unittest

from kamal.ble_receiver_scheduler import (
    BLE_RECEIVER_SCHEDULER_CONTRACT_VERSION,
    BLEReceiverSchedulerContractError,
    build_receiver_scheduler_plan,
)


DIGEST = "a" * 64


def connection_context(*, frame_number=1844, source_sha=DIGEST):
    return {
        "schema_version": "0.12.0",
        "record_type": "ble_legacy_connect_ind",
        "connection_context_id": (
            f"ble-legacy-connect-ind:sha256:{source_sha}:frame:{frame_number}"
        ),
        "source_capture": {
            "path": "/evidence/ch37.pcap",
            "sha256": source_sha,
            "frame_number": frame_number,
        },
        "observation": {
            "directly_observed": True,
            "pdu_type": "CONNECT_IND",
            "pdu_type_code": 5,
            "crc_valid": True,
            "advertising_channel": 37,
            "packet_time_epoch": "1790616000.125000000",
            "connect_ind_chsel": True,
            "initiator": {
                "address": "12:34:56:78:9A:BC",
                "address_type": "public",
            },
            "advertiser": {
                "address": "C3:1C:4D:45:DE:3F",
                "address_type": "random",
            },
            "link_layer": {
                "access_address": "0x12345678",
                "crc_init": "0xabcdef",
                "window_size": 2,
                "window_offset": 11,
                "interval": 24,
                "latency": 0,
                "timeout": 200,
                "channel_map_hex": "ffffffff1f",
                "hop_increment": 5,
                "sleep_clock_accuracy_code": 1,
            },
        },
        "execution": {
            "status": "offline_normalization",
            "rf_performed": False,
            "network_performed": False,
        },
        "limitations": [
            "legacy CONNECT_IND only",
            "actual data-channel connection anchor is not established",
            "connection event counter is not inferred",
            "channel selection algorithm is not inferred",
        ],
    }


def extraction_report(*, contexts=None, rejected=None):
    contexts = [] if contexts is None else contexts
    rejected = [] if rejected is None else rejected
    return {
        "schema_version": "0.12.0",
        "record_type": "ble_connection_context_extraction",
        "source_capture": {
            "path": "/evidence/ch37.pcap",
            "sha256": DIGEST,
            "size_bytes": 4096,
        },
        "decoder": {
            "tool": "tshark",
            "version": "TShark 4.x",
            "display_filter": "btle.advertising_header.pdu_type == 5",
            "fields": [],
        },
        "summary": {
            "candidate_count": len(contexts) + len(rejected),
            "accepted_count": len(contexts),
            "rejected_count": len(rejected),
        },
        "connection_contexts": contexts,
        "rejected_candidates": rejected,
        "execution": {
            "status": "offline_pcap_extraction",
            "rf_performed": False,
            "network_performed": False,
        },
        "limitations": [],
    }


class BLEReceiverSchedulerContractTests(unittest.TestCase):
    def test_no_context_does_not_guess_assignment(self):
        plan = build_receiver_scheduler_plan(extraction_report())

        self.assertEqual(
            plan["schema_version"],
            BLE_RECEIVER_SCHEDULER_CONTRACT_VERSION,
        )
        self.assertEqual(plan["record_type"], "ble_receiver_scheduler_plan")
        self.assertEqual(plan["scheduler"]["status"], "no_context")
        self.assertFalse(plan["scheduler"]["receiver_assignments_performed"])
        self.assertEqual(
            plan["scheduler"]["blockers"],
            ["no_accepted_connection_context"],
        )
        self.assertEqual(plan["assignment_decisions"], [])

    def test_rejected_candidates_are_never_scheduler_inputs(self):
        report = extraction_report(
            rejected=[{"frame_number": "7", "reason": "crcok=false"}]
        )
        plan = build_receiver_scheduler_plan(report)

        self.assertEqual(plan["scheduler"]["status"], "no_context")
        self.assertEqual(plan["assignment_decisions"], [])
        self.assertEqual(
            plan["source_extraction"]["rejected_candidate_count"],
            1,
        )

    def test_accepted_context_records_fail_closed_assignment_decision(self):
        plan = build_receiver_scheduler_plan(
            extraction_report(contexts=[connection_context()])
        )

        self.assertEqual(plan["scheduler"]["status"], "blocked")
        self.assertFalse(plan["scheduler"]["receiver_assignments_performed"])
        self.assertEqual(len(plan["assignment_decisions"]), 1)

        decision = plan["assignment_decisions"][0]
        self.assertEqual(decision["decision"], "not_assigned")
        self.assertIsNone(decision["receiver_id"])
        self.assertIsNone(decision["data_channel"])
        self.assertEqual(
            decision["blockers"],
            [
                "missing_verified_data_channel_control",
                "missing_data_channel_anchor",
                "missing_connection_event_counter",
                "missing_channel_selection_algorithm",
            ],
        )

    def test_decision_carries_only_directly_evidenced_connect_ind_inputs(self):
        plan = build_receiver_scheduler_plan(
            extraction_report(contexts=[connection_context()])
        )
        inputs = plan["assignment_decisions"][0]["evidenced_inputs"]

        self.assertEqual(inputs["access_address"], "0x12345678")
        self.assertEqual(inputs["crc_init"], "0xabcdef")
        self.assertEqual(inputs["channel_map_hex"], "ffffffff1f")
        self.assertEqual(inputs["hop_increment"], 5)
        self.assertEqual(inputs["interval"], 24)
        self.assertNotIn("anchor", inputs)
        self.assertNotIn("event_counter", inputs)
        self.assertNotIn("channel_selection_algorithm", inputs)

    def test_execution_is_explicitly_offline_and_control_free(self):
        plan = build_receiver_scheduler_plan(
            extraction_report(contexts=[connection_context()])
        )
        execution = plan["execution"]

        self.assertEqual(execution["status"], "offline_contract_evaluation")
        self.assertFalse(execution["rf_performed"])
        self.assertFalse(execution["receiver_control_performed"])
        self.assertFalse(execution["network_performed"])

    def test_input_is_not_mutated(self):
        report = extraction_report(contexts=[connection_context()])
        before = copy.deepcopy(report)

        build_receiver_scheduler_plan(report)

        self.assertEqual(report, before)

    def test_rejects_summary_count_mismatch(self):
        report = extraction_report(contexts=[connection_context()])
        report["summary"]["accepted_count"] = 0

        with self.assertRaisesRegex(
            BLEReceiverSchedulerContractError,
            "accepted_count",
        ):
            build_receiver_scheduler_plan(report)

    def test_rejects_context_source_hash_mismatch(self):
        report = extraction_report(
            contexts=[connection_context(source_sha="b" * 64)]
        )

        with self.assertRaisesRegex(
            BLEReceiverSchedulerContractError,
            "does not match extraction report",
        ):
            build_receiver_scheduler_plan(report)

    def test_rejects_non_direct_context(self):
        context = connection_context()
        context["observation"]["directly_observed"] = False

        with self.assertRaisesRegex(
            BLEReceiverSchedulerContractError,
            "directly observed",
        ):
            build_receiver_scheduler_plan(
                extraction_report(contexts=[context])
            )

    def test_rejects_crc_invalid_context(self):
        context = connection_context()
        context["observation"]["crc_valid"] = False

        with self.assertRaisesRegex(
            BLEReceiverSchedulerContractError,
            "CRC-valid",
        ):
            build_receiver_scheduler_plan(
                extraction_report(contexts=[context])
            )

    def test_rejects_duplicate_context_id(self):
        first = connection_context()
        second = copy.deepcopy(first)

        with self.assertRaisesRegex(
            BLEReceiverSchedulerContractError,
            "duplicate connection_context_id",
        ):
            build_receiver_scheduler_plan(
                extraction_report(contexts=[first, second])
            )

    def test_orders_decisions_by_source_frame(self):
        later = connection_context(frame_number=200)
        earlier = connection_context(frame_number=100)

        plan = build_receiver_scheduler_plan(
            extraction_report(contexts=[later, earlier])
        )

        self.assertEqual(
            [
                item["connection_context_id"]
                for item in plan["assignment_decisions"]
            ],
            [
                earlier["connection_context_id"],
                later["connection_context_id"],
            ],
        )


if __name__ == "__main__":
    unittest.main()
