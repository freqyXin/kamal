# Bounded GATT executor

`kamal-execute-gatt` is the RF-capable consumer of an Increment 8 `gatt_operation_plan`.
It requires the original authorization artifact, verifies its exact SHA-256 against the plan, and revalidates authorization immediately before connection and before every operation. Expired or mismatched authorization fails closed.

The executor supports only the typed operation classes already present in the plan: characteristic read, descriptor read, characteristic write, and bounded notification subscription. It does not accept ad-hoc operations and does not implement fuzzing.

Results are persisted incrementally in a newly-created output directory. `run-start.json` is written before RF work, each completed/failed operation is written once as `operation-NNN.json`, and `run-final.json` records completion and cleanup state. Artifacts are never overwritten.

## Result semantics

Each operation result contains explicit `effect_semantics`. The executor records
only what it can establish through the Bleak client API: transport completion and
the narrow protocol-visible outcome. It does **not** infer application
acknowledgment, device state change, or security effect.

For example, successful completion of a write request is recorded as a completed
GATT write request, with direct ATT-PDU observation set to false. A write command
is recorded only as submitted because no response is expected. In both cases,
application acknowledgment, state change, and security effect remain
`not_assessed`.

The legacy `transport_success` field remains as a compatibility mirror. The
legacy `application_effect` field remains `not_assessed`; consumers should use
`effect_semantics` for new work. See `docs/gatt-result-semantics.md` for the full
model and the offline `kamal-review-gatt-result` workflow.

Notification capture is bounded to 256 events and 65536 bytes. Subscription cleanup is mandatory. An unconfirmed unsubscribe or disconnect marks an unsafe stop and prevents continuation.
