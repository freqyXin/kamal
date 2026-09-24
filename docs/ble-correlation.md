# v0.12 BLE cross-run correlation

K'amal v0.12 correlates existing assessment artifacts offline. Correlation does
not perform discovery, connection, GATT operations, or any other RF action.

## Identity model

A Bluetooth address is an observed identifier, not a stable asset identity.
`kamal-correlate` creates an `asset_identity_link_candidate` only when the same
normalized BLE address appears in at least two distinct assessment runs.

Each candidate records:

- the exact identifier and deterministic candidate ID;
- the matching method (`exact_identifier_match`);
- `match_confidence`, which describes confidence that the recorded identifier
  text matches;
- `asset_identity_confidence`, which separately describes the weaker inference
  that observations may refer to the same physical asset;
- `status: needs_review` and `stable_identity: false`;
- evidence references back to the hashed assessment artifact, observation,
  original report source, and JSON evidence path;
- limitations explaining why the address is insufficient as stable identity.

An explicitly public address can raise asset-identity confidence only to
`medium`. Random/private, conflicting, unknown, or missing address-type evidence
remains `low`. Exact address equality never creates an `asset_id`, never
confirms a finding, and never initiates an active operation.

## Provenance

Every input assessment is hashed from its original bytes and recorded as an
`assessment_source_id` of `sha256:<digest>`. The correlation artifact records
that hash, original path, and assessment ID. Inputs must use evidence contract
version `0.12.0`.

The output is deterministic for the same assessment bytes regardless of input
ordering. Invalid BLE address text is not silently converted into an identity
claim; it is retained as an integrity warning with its assessment, observation,
and evidence path.

## CLI

Example:

```text
bin/kamal-correlate \
  --input assessment-run-1.json \
  --input assessment-run-2.json \
  --json ble-correlation.json
```

At least two distinct assessment IDs are required. Output uses the same atomic,
no-overwrite persistence primitive as `kamal-assess`.
