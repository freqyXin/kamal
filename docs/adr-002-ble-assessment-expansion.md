# ADR-002: BLE assessment expansion and authorized GATT testing

Status: Accepted for v0.12 implementation

## Context

K'amal v0.11 combines existing passive BLE and active GATT reports into an
offline assessment. The assessment engine preserves source reports, records
their SHA-256 digests, creates evidence-backed review findings, and does not
perform radio operations.

v0.12 extends that foundation with common evidence contracts, cross-run
comparison, evidence-backed device intelligence, BSAM-aligned assessment
coverage, and a separately authorized GATT security-test workflow.

## Decisions

### Preserve the offline assessment boundary

Rules and assessment construction remain offline. A rule may produce a
candidate or review prompt, but may not initiate a BLE connection, read, write,
pairing request, notification subscription, or other RF operation.

### Preserve source evidence

Historic source reports retain their existing schemas. v0.12 introduces a
common evidence contract around those reports rather than rewriting them.
Source records continue to carry the digest of the original file bytes.

### Do not infer stable device identity from an address

Passive and active observations remain separate unless later correlation logic
has sufficient evidence to create an explicit relationship. Bluetooth address
equality alone is not a stable device-identity assertion.

### Distinguish collection mode

Evidence records explicitly identify passive versus active collection. Future
active security-test records must also reference the authorization governing
the operation.

### Separate observed, documented, inferred, and validated information

Device-intelligence records added later in v0.12 will distinguish direct
observation from public documentation and analyst-supported inference. A
vendor string, UUID, company identifier, or model hint is not by itself a
confirmed product, firmware, chipset, or vulnerability identification.

### Keep active GATT testing authorization-gated

The future executor will accept typed, bounded test specifications only after
local authorization checks. Read, write request, write command, notification,
and pairing-related operations are separate operation classes. State-changing
operations are not triggered automatically by assessment findings.

Malformed payload generation and fuzzing are outside the default automated
workflow and remain a separately controlled lab workflow.

### Feed test results back into offline assessment

Authorized tests produce evidence artifacts. Those artifacts are ingested and
assessed offline. A transport-level ATT/GATT success response is evidence of a
successful protocol operation, not proof that an application-level state change
occurred.

### Use atomic no-overwrite persistence for immutable assessment artifacts

Survey checkpoints may legitimately use replace semantics. Assessments and
other immutable evidence artifacts must instead be fully written and synced
before their final pathname is created, and creation must fail if that pathname
already exists.

## v0.12 implementation sequence

1. Shared evidence contracts and compatibility tests.
2. Cross-run comparison and evidence-backed device intelligence.
3. BSAM mapping and coverage representation.
4. Authorization and typed GATT test contracts.
5. Bounded executor and owned-device laboratory validation.
6. Failure, interruption, cleanup, and multi-target integration tests.

## Compatibility

v0.12 continues to accept:

- passive BLE report schema `0.6.0`;
- active GATT report schema `0.7.0`; and
- assessment schema `0.9.0`.

The initial v0.12 evidence contract is additive. It does not reinterpret
historic reports as having authorization metadata they never recorded.

## Deferred

- automatic stable device identity correlation;
- automatic CVE confirmation from vendor or model metadata;
- unrestricted or rule-triggered GATT writes;
- automated BLE fuzzing;
- claims of full BSAM coverage before explicit mapping and gap review are
  implemented and validated.
