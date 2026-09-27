# Catalog provenance and pinning

K'amal v0.12 records the immutable catalog inputs that were available to, or
actually consulted by, offline assessment and enrichment workflows. Catalog
provenance is evidence metadata; it is not a device-identity assertion.

## Bluetooth SIG snapshots

`tools/import_bluetooth_sig.py` creates immutable snapshots under
`data/bluetooth/snapshots/<commit>/`. `kamal-assess --bluetooth-snapshot`
verifies the snapshot before using it. The resulting assessment records:

- the full 40-character Bluetooth SIG source commit;
- the SHA-256 of `manifest.json`;
- normalized SHA-256 and upstream source SHA-256 for every registry;
- the exact upstream source file represented by each registry;
- whether the snapshot was merely `available` or was `consulted` by source
  evidence.

Passive reports that contain identifier-registry metadata are bound to the
snapshot by source commit, source file, source label, and generated timestamp.
Existing GATT `resolution` objects are recomputed from the pinned snapshot and
must match exactly. A mismatch fails closed rather than silently combining
catalog revisions.

The normal `kamal-assess` CLI requires `--bluetooth-snapshot` when the input
contains catalog-resolved BLE evidence. This keeps newly generated assessment
artifacts reproducible even after the active flat registries are updated.

## Device-intelligence catalogs

`kamal-enrich` always records the device-intelligence catalog it consults. The
record contains the catalog ID, byte SHA-256, and a revision. A catalog may
provide an explicit `catalog_revision`; otherwise K'amal uses
`sha256:<catalog-file-sha256>` as the immutable revision.

Each emitted intelligence claim also carries that catalog revision. This makes
it possible to distinguish two enrichment runs that used different versions of
a catalog even when their human-readable catalog IDs are the same.

`kamal-enrich --bluetooth-snapshot` can verify and bind a Bluetooth SIG snapshot
to an older assessment. If the assessment already carries Bluetooth catalog
provenance, K'amal reconciles the immutable hashes and revisions. Conflicting
revisions or hashes are rejected.

## Available versus consulted

Every catalog-provenance record has a `usage` value:

- `available` means the immutable catalog was supplied and verified but no
  evidence or enrichment result depended on it;
- `consulted` means the catalog participated in resolution, source binding, or
  enrichment.

When the same immutable catalog appears in multiple stages, `consulted` wins
over `available`. This is a usage-state merge only: differing revisions,
manifest hashes, registry hashes, or catalog hashes are never merged.

## Reproducibility boundary

Catalog pinning does not claim that a public source is correct, nor does it turn
manufacturer, UUID, advertised-name, chipset, or product hints into stable
physical-device identity. It records exactly which immutable local catalog
bytes and upstream revision informed the artifact so later review can reproduce
the same resolution context.
