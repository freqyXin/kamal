# v0.12 evidence contracts

K'amal v0.12 introduces an additive evidence-contract layer around existing
source reports.

## Contract version

The initial contract version is `0.12.0`. It is independent of producer report
schema versions and the assessment schema version.

## Evidence source record

Each imported source is represented with:

- `record_type`: `evidence_source`
- `contract_version`
- `source_id`
- `path`
- `sha256`
- `evidence_type`
- `schema_version`
- `collection_mode`

`source_id` must be `sha256:<digest>` and must match the recorded digest.

The source record does not replace the original source file. The original file
must be retained for independent hash verification.

## Observation record

Each current source report maps to one report-level observation with:

- `record_type`: `observation`
- `contract_version`
- `observation_id`
- `source_id`
- `protocol`
- `collection_mode`
- `authorization_ref`
- `evidence_type`
- `report`

Historic source reports may have `authorization_ref: null` because the older
schemas did not record an authorization object. Future active security-test
evidence must carry an authorization reference.

No stable `device_id` or `asset_id` is created from a Bluetooth address by this
contract.

## Collection modes

Current mappings are:

| Evidence type | Collection mode |
| --- | --- |
| `passive_ble` | `passive` |
| `active_gatt` | `active` |

Future security-test evidence types will be added explicitly rather than
silently treated as ordinary GATT enumeration.

## Persistence

`kamal-assess` uses `atomic_create_json()` for immutable assessment artifacts.

The function writes and fsyncs a temporary file in the destination directory,
then atomically creates the final pathname using a hard link. If the final path
already exists, creation fails and the existing file is preserved.

If the final pathname has already been created but syncing the parent directory
then fails, `atomic_create_json()` raises `AtomicCreateError` with
`published=True` and the destination `path`. Callers must treat that state as
"published, durability not confirmed" rather than retrying as though no artifact
exists.

This differs intentionally from survey checkpoint persistence, where replacing
an earlier checkpoint is expected behavior.
