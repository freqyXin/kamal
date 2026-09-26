# ADR-003: Authorization-gated typed BLE GATT operation contracts

**Status:** Accepted for v0.12 contract implementation; executor integration is deferred.

## Context

K'amal already supports bounded BLE discovery/GATT metadata survey and an
offline assessment pipeline. The next active-assessment capabilities require a
stable boundary between evidence/rules and RF execution. Discovery, an
assessment candidate, or an analyst's desire to test a characteristic must not
be treated as permission to perform an active operation.

## Decision

K'amal will use an explicit `authorization_scope` plus a separate typed
`gatt_operation_request`. A non-executing planner validates both and emits a
`gatt_operation_plan` carrying the SHA-256 of the exact authorization artifact.
The planner performs no RF activity.

The typed `gatt_operation_request` taxonomy is:

- `read_characteristic`
- `read_descriptor`
- `write_characteristic`
- `subscribe_notifications`

Authorization scopes also recognize `enumerate_gatt_metadata` for the bounded
read-only active survey path. That class authorizes service/characteristic/
descriptor metadata enumeration only; it is not a typed attribute operation and
cannot appear in a `gatt_operation_request` or executor plan.

Metadata survey authorization normally remains exact-target. For explicitly
controlled environments where every observable BLE device is authorized and
address rotation makes a pre-discovery allowlist unstable, the authorization may
carry an acknowledged `survey_scope.mode=all_discovered`. That dynamic scope is
valid only for `enumerate_gatt_metadata`, cannot coexist with typed characteristic
operations or write permissions, must match the CLI's acknowledged
all-discovered policy, and remains bounded by the authorization's operation-count
and timeout limits.

All other operation classes fail closed. Writes require layered opt-in. A
write-without-response (`command`) requires an additional explicit permission.
Operation count, payload size, timeouts, and subscription duration have both
scope-selected bounds and hard K'amal ceilings.

BLE addresses are scope selectors, not stable asset identifiers. Later executor
work must revalidate authorization time and target scope immediately before RF
activity and must record lifecycle/cleanup outcomes.

Rules, enrichers, and assessment code cannot execute operations or create
permission. They may eventually propose reviewable requests only.

## Consequences

The contract can be tested, reviewed, and versioned before a radio executor
exists. Future executors have a narrow input surface and can fail closed on
expired or mismatched authorization. Fuzzing, replay, pairing attacks, arbitrary
ATT primitives, and disruptive testing remain outside the automated default
scope.

This ADR records structured approval metadata but does not implement or claim
cryptographic signature verification. If signed authorization envelopes are
added later, signature verification will wrap rather than replace these scope
semantics.
