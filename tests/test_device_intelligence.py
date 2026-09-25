"""Tests for offline BLE device-intelligence enrichment."""

import json
import tempfile
import unittest
from pathlib import Path

from catalog_fixtures import write_bluetooth_snapshot

from kamal.catalog_provenance import load_bluetooth_snapshot
from kamal.device_intelligence import (
    build_ble_intelligence_enrichment,
    extract_observed_intelligence_facts,
    load_intelligence_catalog,
)


ASSESSMENT_DIGEST = "a" * 64
CATALOG_DIGEST = "b" * 64


def passive_observation():
    return {
        "observation_id": "observation:passive",
        "source_id": "sha256:" + ("c" * 64),
        "protocol": "ble",
        "evidence_type": "passive_ble",
        "report": {
            "advertisers": [{
                "address": "AA:BB:CC:DD:EE:FF",
                "names": ["SensorTag"],
                "manufacturer_data": [{
                    "company_id": 76,
                    "payload_hex": "0215AABBCCDD",
                }],
                "service_uuids_16": ["180F"],
            }],
        },
    }


def active_observation():
    return {
        "observation_id": "observation:active",
        "source_id": "sha256:" + ("d" * 64),
        "protocol": "ble",
        "evidence_type": "active_gatt",
        "report": {
            "gatt": {
                "services": [{
                    "uuid": "180F",
                    "characteristics": [{
                        "uuid": "2A19",
                        "descriptors": [{"uuid": "2902"}],
                    }],
                }],
            },
        },
    }


def assessment_source(*observations, catalog_provenance=None):
    assessment = {
        "schema_version": "0.9.0",
        "assessment_id": "run-a",
        "evidence_contract_version": "0.12.0",
        "observations": list(observations),
    }
    if catalog_provenance is not None:
        assessment["catalog_provenance"] = catalog_provenance
    return {
        "assessment_source_id": "sha256:" + ASSESSMENT_DIGEST,
        "path": "/tmp/assessment.json",
        "sha256": ASSESSMENT_DIGEST,
        "assessment_id": "run-a",
        "assessment": assessment,
    }


def record(
    record_id,
    *,
    match,
    category,
    value,
    state="documented",
    confidence="high",
    validation=None,
):
    item = {
        "record_id": record_id,
        "match": match,
        "claim": {"category": category, "value": value},
        "state": state,
        "confidence": confidence,
        "source": {
            "source_type": "standard_registry",
            "title": "Public source",
            "locator": "https://example.invalid/source",
        },
        "limitations": ["Context only; not stable device identity."],
    }
    if validation is not None:
        item["validation"] = validation
    return item


def catalog_source(*records):
    return {
        "catalog_source_id": "sha256:" + CATALOG_DIGEST,
        "path": "/tmp/catalog.json",
        "sha256": CATALOG_DIGEST,
        "catalog_id": "test-catalog",
        "catalog_revision": "device-test-r1",
        "schema_version": "0.12.0",
        "records": list(records),
    }


class DeviceIntelligenceTests(unittest.TestCase):
    def test_extracts_passive_observed_facts(self):
        facts = extract_observed_intelligence_facts(
            assessment_source(passive_observation())["assessment"]
        )
        kinds = [fact["fact_kind"] for fact in facts]
        self.assertIn("advertised_name", kinds)
        self.assertIn("bluetooth_company_id", kinds)
        self.assertIn("manufacturer_data", kinds)
        self.assertIn("gatt_uuid", kinds)
        self.assertTrue(all(fact["state"] == "observed" for fact in facts))
        self.assertTrue(all(fact["confidence"] == "high" for fact in facts))

    def test_company_identifier_produces_documented_manufacturer_claim(self):
        catalog = catalog_source(record(
            "company-004c",
            match={"kind": "bluetooth_company_id", "company_id": "0x004c"},
            category="manufacturer",
            value="Example Manufacturer",
        ))
        # Catalog sources are normally normalized by load_intelligence_catalog.
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "catalog.json"
            path.write_text(json.dumps({
                "schema_version": "0.12.0",
                "catalog_id": "test-catalog",
                "records": catalog["records"],
            }))
            normalized = load_intelligence_catalog(path)
        result = build_ble_intelligence_enrichment(
            assessment_source(passive_observation()), normalized
        )
        claims = result["claims"]
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["category"], "manufacturer")
        self.assertEqual(claims[0]["state"], "documented")
        self.assertFalse(claims[0]["identity_assertion"])
        self.assertFalse(claims[0]["stable_identity"])
        self.assertNotIn("asset_id", claims[0])
        self.assertTrue(claims[0]["catalog_revision"].startswith("sha256:"))
        provenance = result["catalog_provenance"]
        self.assertEqual(len(provenance), 1)
        self.assertEqual(provenance[0]["catalog_type"], "ble_device_intelligence")
        self.assertEqual(provenance[0]["usage"], "consulted")

    def test_manufacturer_prefix_can_remain_inferred_chipset_hint(self):
        catalog = catalog_source(record(
            "payload-chipset-hint",
            match={
                "kind": "manufacturer_data_prefix",
                "company_id": 76,
                "payload_prefix_hex": "0215aa",
            },
            category="chipset",
            value="Example SoC family",
            state="inferred",
            confidence="medium",
        ))
        result = build_ble_intelligence_enrichment(
            assessment_source(passive_observation()), catalog
        )
        self.assertEqual(len(result["claims"]), 1)
        claim = result["claims"][0]
        self.assertEqual(claim["category"], "chipset")
        self.assertEqual(claim["state"], "inferred")
        self.assertEqual(claim["confidence"], "medium")

    def test_gatt_uuid_matches_attribute_type(self):
        catalog = catalog_source(
            record(
                "battery-service",
                match={
                    "kind": "gatt_uuid",
                    "uuid": "180F",
                    "attribute_type": "service",
                },
                category="gatt_service_purpose",
                value="Battery Service",
            ),
            record(
                "battery-level",
                match={
                    "kind": "gatt_uuid",
                    "uuid": "2A19",
                    "attribute_type": "characteristic",
                },
                category="gatt_characteristic_purpose",
                value="Battery Level",
            ),
        )
        result = build_ble_intelligence_enrichment(
            assessment_source(active_observation()), catalog
        )
        self.assertEqual(
            [(item["category"], item["value"]) for item in result["claims"]],
            [
                ("gatt_characteristic_purpose", "Battery Level"),
                ("gatt_service_purpose", "Battery Service"),
            ],
        )

    def test_advertised_name_match_does_not_become_identity(self):
        catalog = catalog_source(record(
            "name-family-hint",
            match={"kind": "advertised_name_exact", "name": "SensorTag"},
            category="device_family",
            value="Example sensor family",
            state="inferred",
            confidence="low",
        ))
        claim = build_ble_intelligence_enrichment(
            assessment_source(passive_observation()), catalog
        )["claims"][0]
        self.assertFalse(claim["identity_assertion"])
        self.assertFalse(claim["stable_identity"])

    def test_conflicting_claims_are_retained_with_warning(self):
        catalog = catalog_source(
            record(
                "name-one",
                match={"kind": "advertised_name_exact", "name": "SensorTag"},
                category="product_model",
                value="Model A",
                state="inferred",
            ),
            record(
                "name-two",
                match={"kind": "advertised_name_exact", "name": "SensorTag"},
                category="product_model",
                value="Model B",
                state="inferred",
            ),
        )
        result = build_ble_intelligence_enrichment(
            assessment_source(passive_observation()), catalog
        )
        self.assertEqual(len(result["claims"]), 2)
        warning = result["integrity"]["warnings"][0]
        self.assertEqual(warning["code"], "conflicting_intelligence_claims")
        self.assertEqual(warning["values"], ["Model A", "Model B"])

    def test_invalid_observed_company_identifier_becomes_warning(self):
        obs = passive_observation()
        obs["report"]["advertisers"][0]["manufacturer_data"][0]["company_id"] = "bad"
        result = build_ble_intelligence_enrichment(
            assessment_source(obs), catalog_source()
        )
        self.assertEqual(result["claims"], [])
        self.assertIn(
            "invalid_company_identifier",
            [item["code"] for item in result["integrity"]["warnings"]],
        )

    def test_validated_catalog_record_requires_validation_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "catalog.json"
            path.write_text(json.dumps({
                "schema_version": "0.12.0",
                "catalog_id": "test-catalog",
                "records": [record(
                    "validated-without-review",
                    match={"kind": "advertised_name_exact", "name": "SensorTag"},
                    category="device_family",
                    value="Example sensor family",
                    state="validated",
                )],
            }))
            with self.assertRaisesRegex(ValueError, "require validation metadata"):
                load_intelligence_catalog(path)

    def test_validated_claim_preserves_review_metadata(self):
        validation = {
            "reviewer": "analyst-1",
            "validated_at_utc": "2026-09-23T20:00:00Z",
            "basis": "Compared against vendor documentation and lab hardware.",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "catalog.json"
            path.write_text(json.dumps({
                "schema_version": "0.12.0",
                "catalog_id": "test-catalog",
                "records": [record(
                    "validated-family",
                    match={"kind": "advertised_name_exact", "name": "SensorTag"},
                    category="device_family",
                    value="Example sensor family",
                    state="validated",
                    validation=validation,
                )],
            }))
            catalog = load_intelligence_catalog(path)
        claim = build_ble_intelligence_enrichment(
            assessment_source(passive_observation()), catalog
        )["claims"][0]
        self.assertEqual(claim["state"], "validated")
        self.assertEqual(claim["validation"], validation)

    def test_catalog_resolved_assessment_requires_bluetooth_pin(self):
        observation = passive_observation()
        observation["report"]["identifier_registries"] = {}
        with self.assertRaisesRegex(
            ValueError,
            "requires pinned Bluetooth catalog provenance",
        ):
            build_ble_intelligence_enrichment(
                assessment_source(observation),
                catalog_source(),
            )

    def test_catalog_revision_is_preserved_when_explicit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "catalog.json"
            path.write_text(json.dumps({
                "schema_version": "0.12.0",
                "catalog_id": "test-catalog",
                "catalog_revision": "reviewed-2026-09-24",
                "records": [],
            }))
            catalog = load_intelligence_catalog(path)
        self.assertEqual(catalog["catalog_revision"], "reviewed-2026-09-24")

    def test_enrichment_carries_assessment_bluetooth_provenance(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot = load_bluetooth_snapshot(
                write_bluetooth_snapshot(Path(temp_dir) / "snapshots")
            )["provenance"]
        snapshot["usage"] = "consulted"
        source = assessment_source(
            passive_observation(),
            catalog_provenance=[snapshot],
        )
        result = build_ble_intelligence_enrichment(source, catalog_source())
        provenance = {item["catalog_type"]: item for item in result["catalog_provenance"]}
        self.assertEqual(
            provenance["bluetooth_sig_assigned_numbers"]["usage"],
            "consulted",
        )
        self.assertEqual(
            provenance["ble_device_intelligence"]["revision"],
            "device-test-r1",
        )
        self.assertEqual(
            provenance["ble_device_intelligence"]["usage"],
            "consulted",
        )

    def test_catalog_output_is_deterministic_across_record_order(self):
        first = record(
            "company",
            match={"kind": "bluetooth_company_id", "company_id": 76},
            category="manufacturer",
            value="Example Manufacturer",
        )
        second = record(
            "name",
            match={"kind": "advertised_name_exact", "name": "SensorTag"},
            category="device_function",
            value="Environmental sensing",
            state="inferred",
        )
        source = assessment_source(passive_observation())
        left = build_ble_intelligence_enrichment(source, catalog_source(first, second))
        right = build_ble_intelligence_enrichment(source, catalog_source(second, first))
        self.assertEqual(left, right)


if __name__ == "__main__":
    unittest.main()
