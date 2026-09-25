# BSAM-aligned evidence coverage mapping

K'amal v0.12 can map already-collected BLE assessment evidence to the public
Bluetooth Security Assessment Methodology (BSAM) control structure. This layer
is deliberately offline and non-executing. It does not initiate discovery,
pairing, GATT access, writes, notification subscriptions, packet injection, or
any other RF operation.

The embedded K'amal profile contains the 36 BSAM control identifiers and titles
organized into the seven BSAM groups: information gathering, discovery,
pairing, authentication, encryption, services, and application. BSAM is an
external, evolving methodology maintained by Tarlogic Security. K'amal records
its own profile version and a SHA-256 of the embedded control catalog so an
artifact can identify exactly which K'amal mapping profile produced it. The
profile also records that no upstream BSAM revision is pinned.

Upstream control index: `https://www.tarlogic.com/bsam/controls/`

## Command

```text
bin/kamal-map-bsam \
  --assessment assessment.json \
  --enrichment enrichment.json \
  --json bsam-mapping.json
```

`--enrichment` is optional. When supplied, K'amal requires the enrichment to be
cryptographically bound to the exact assessment bytes by assessment SHA-256 and
assessment ID. The output is atomically created and existing files are never
replaced.

## Coverage is not a pass/fail result

Each BSAM control is always present in the mapping artifact. A control starts as
`coverage_state=not_assessed`. Directly relevant evidence can move it to
`evidence_available`, but evidence presence alone never produces a BSAM pass or
fail result.

The separate `review_state` is one of:

- `no_conclusion`: no mapped K'amal finding determines a concern;
- `candidate_concern`: a `potential` K'amal finding maps to the control; or
- `confirmed_finding`: a K'amal finding already marked `confirmed` maps to the
  control.

Even `confirmed_finding` is not automatically a BSAM control failure. It only
preserves K'amal's source finding state. Increment 9 does not invent a new
review or validation step.

K'amal never interprets an empty finding list as "no issue observed". A control
without sufficient evidence remains `not_assessed` or `no_conclusion`.

## Current automatic evidence mappings

The initial mapper is intentionally conservative. It recognizes evidence that
is useful to review these controls:

- `BSAM-DI-01`: evidence that BLE operation was observed;
- `BSAM-DI-03`: advertised/local device names;
- `BSAM-DI-04`: public manufacturer, service, or service-UUID discovery data;
- `BSAM-DI-05`: devices observed during BLE advertising/discovery;
- `BSAM-DI-06`: recorded Bluetooth address type;
- `BSAM-SE-02`: successful normal-path GATT service enumeration; and
- `BSAM-SE-03`: GATT metadata relevant to service access-control review.

Normal-path GATT enumeration does not establish that no hidden services exist.
Likewise, a recorded `random` address type does not establish address rotation,
resolvability, or privacy behavior. The mapping statements preserve those
limitations.

The existing `BLE-GATT-001` rule maps to `BSAM-SE-03` as a candidate concern
when its source finding remains `potential`. The rule still does not initiate a
read or write and does not prove that access control is weak.

## Device-intelligence context

Optional enrichment claims can be attached as control context. Their original
states are preserved exactly as `documented`, `inferred`, or `validated`.
Context never changes a control from `not_assessed` to `evidence_available` by
itself and never establishes stable device identity.

Manufacturer/product/chipset context can support later BSAM information-
gathering work. GATT purpose, device-function, and security-context claims can
support service access-control review. The analyst still has to perform the
BSAM control and evaluate the evidence appropriate to the device.

## Provenance and safety

The output records:

- SHA-256 provenance for the exact assessment bytes;
- optional SHA-256 provenance for the exact enrichment bytes;
- catalog provenance already carried by those artifacts;
- the K'amal BSAM profile version and control-catalog SHA-256;
- all evidence references used for mapping; and
- explicit `rf_performed=false` and `network_performed=false` execution state.

Bluetooth addresses remain observation/scope data, not stable identity.
Assessment rules still cannot create authorization or active operation plans.
