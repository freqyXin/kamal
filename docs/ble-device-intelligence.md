# v0.12 BLE device-context intelligence enrichment

K'amal enriches existing BLE assessment artifacts offline from a local,
provenance-bearing intelligence catalog. The enrichment path performs no scan,
connection, GATT write, fuzzing, or other RF action.

## Relationship to assigned-number resolution

K'amal already resolves Bluetooth SIG company identifiers and assigned GATT
UUIDs in its capture/reporting layer. This enrichment layer does not replace or
reinterpret those registries. Instead, it consumes immutable assessment
evidence and a separate local intelligence catalog for higher-level context such
as documented product families, chipset hints, device functions, and GATT
purpose. Assigned-number names remain namespace evidence, not physical-device
identity.

## Evidence states

The intelligence layer keeps four states separate:

- `observed`: a fact directly present in an assessment artifact, such as a
  Bluetooth Company Identifier, advertised name, manufacturer payload, or GATT
  UUID;
- `documented`: a catalog claim backed by a cited public registry, vendor
  document, or other source;
- `inferred`: an analyst-curated interpretation whose evidence supports a hint
  but not a documented fact, for example a payload prefix associated with a
  likely device family or chipset;
- `validated`: a claim previously reviewed by an identified analyst, with
  reviewer, validation time, and validation basis recorded.

Enrichment never silently upgrades one state to another. Catalog claims always
retain their source metadata and confidence. Source metadata records what the
catalog cites; K'amal does not independently fetch or verify that public source
during enrichment.

## Identity boundary

Manufacturer identifiers, advertised names, vendor payload prefixes, and GATT
UUIDs are useful context but are not stable device identity. Every generated
claim therefore records `identity_assertion: false` and `stable_identity: false`.
K'amal does not create an asset ID, confirm a vulnerability, or initiate an
active operation from enrichment data.

If multiple catalog records make different claims for the same observation and
claim category, both claims are retained and an integrity warning is emitted.
K'amal does not choose a winner automatically.

## Catalog format

Catalog JSON uses schema `0.12.0` and contains a `catalog_id` plus `records`.
Supported match kinds are:

- `bluetooth_company_id` with `company_id`;
- `advertised_name_exact` with `name`;
- `manufacturer_data_prefix` with `company_id` and `payload_prefix_hex`;
- `gatt_uuid` with `uuid` and `attribute_type` (`advertised_service`, `service`,
  `characteristic`, or `descriptor`).

Each record contains a `claim` with a supported category and value, a state,
confidence, source type/title/locator, and optional limitations. `validated`
records additionally require explicit validation metadata.

Example record:

```json
{
  "record_id": "sig-company-004c",
  "match": {
    "kind": "bluetooth_company_id",
    "company_id": 76
  },
  "claim": {
    "category": "manufacturer",
    "value": "Example Manufacturer"
  },
  "state": "documented",
  "confidence": "high",
  "source": {
    "source_type": "standard_registry",
    "title": "Example public registry",
    "locator": "https://example.invalid/registry"
  },
  "limitations": [
    "A company identifier identifies an assigned namespace, not a physical device."
  ]
}
```

Catalog population from Bluetooth SIG and vendor/public sources is a separate
workflow. Keeping source acquisition separate from assessment execution allows
engagement evidence to remain reproducible even when public sources later
change.

## CLI

```text
bin/kamal-enrich \
  --assessment assessment.json \
  --catalog ble-intelligence.json \
  --json enrichment.json
```

The assessment and catalog are hashed from their original bytes. Output uses
K'amal's atomic, no-overwrite JSON persistence primitive.
