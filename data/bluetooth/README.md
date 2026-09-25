# Offline Bluetooth identifier registries

K'amal resolves Bluetooth company identifiers, standard 16-bit service
UUIDs, member-assigned 16-bit UUIDs, GATT characteristic UUIDs, and GATT
descriptor UUIDs using locally generated JSON files.

The generated registries are excluded from Git. K'amal imports them from a
specific, full Bluetooth SIG Git commit and preserves an immutable local
snapshot before any registry is activated for scanning.

## Setup

Clone the Bluetooth SIG Assigned Numbers source repository:

    git clone https://bitbucket.org/bluetooth-SIG/public.git /tmp/bluetooth-sig-public

Create an isolated Python environment for the importer:

    python3 -m venv /tmp/kamal-registry-venv
    /tmp/kamal-registry-venv/bin/python -m pip install PyYAML

PyYAML is required only by the importer. It is not a K'amal scanner runtime
dependency.

## Reproducible snapshot import

Choose the full 40-character upstream commit that the assessment should use.
For example, the revision historically used for K'amal v0.5.0 was:

    4904c3c7317045c40513890645e7d5910bf46308

From the K'amal repository root, create or verify the immutable snapshot:

    /tmp/kamal-registry-venv/bin/python tools/import_bluetooth_sig.py \
        --source /tmp/bluetooth-sig-public \
        --revision 4904c3c7317045c40513890645e7d5910bf46308

The importer reads YAML directly from that Git object with `git show`; the
state of the source repository working tree therefore cannot silently change
the imported data. A short branch, tag, or abbreviated commit is rejected.

The resulting snapshot is stored under:

    data/bluetooth/snapshots/<full-source-commit>/

It contains the five normalized registries and `manifest.json`. The manifest
records the upstream commit and commit timestamp, the importer version, the
actual local import time, each upstream source-file SHA-256, each normalized
registry SHA-256, and identifier counts.

Normalized registry JSON uses the upstream commit timestamp as
`generated_at_utc`, so importing the same source commit with the same importer
version produces the same registry bytes. The wall-clock import time is kept
only in the snapshot manifest.

An existing snapshot is never overwritten. It is hash-verified and reused; a
missing, incomplete, or modified snapshot causes the import to fail.

## Updating the source clone

Network access is opt-in. The importer does not fetch by default. To fetch the
configured `origin` before importing a known full commit, add `--fetch`:

    /tmp/kamal-registry-venv/bin/python tools/import_bluetooth_sig.py \
        --source /tmp/bluetooth-sig-public \
        --revision <40-character-commit> \
        --fetch

Fetching updates the local source clone only. It does not activate the new
catalog in K'amal.

## Activating a snapshot

Snapshot creation alone leaves the active flat registries unchanged. After a
snapshot has been created and reviewed, publish that exact snapshot with
`--activate`:

    /tmp/kamal-registry-venv/bin/python tools/import_bluetooth_sig.py \
        --source /tmp/bluetooth-sig-public \
        --revision <40-character-commit> \
        --activate

Activation publishes these existing scanner inputs:

- data/bluetooth/company_identifiers.json
- data/bluetooth/service_uuids.json
- data/bluetooth/member_uuids.json
- data/bluetooth/characteristic_uuids.json
- data/bluetooth/descriptor_uuids.json

The five files are staged before publication. If publication fails partway
through, the importer attempts to restore the previously active set instead
of intentionally leaving a mixed revision.

Each active registry retains its exact `source_commit`, `source_file`,
`source_sha256`, and importer version. Existing K'amal reports therefore keep
the Bluetooth SIG source revision used for offline identifier resolution.

## Interpretation

Assigned company identifiers do not confirm the physical manufacturer of a
device.

Advertised UUIDs do not establish that GATT services were enumerated.

Unknown identifiers mean they were not found in the applicable local registry
snapshot.

Active GATT reports resolve service, characteristic, and descriptor UUIDs
against their respective Bluetooth SIG namespaces. The observed UUID remains
in the report unchanged. Only 16-bit identifiers represented directly or
through the Bluetooth Base UUID are resolved; vendor-specific and 32-bit UUIDs
are not reduced or used for identity inference.

Active GATT reports include the Bluetooth SIG source revision and registry
provenance used for offline identifier resolution.
