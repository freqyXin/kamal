# Bounded GATT executor

`kamal-execute-gatt` is the RF-capable consumer of an Increment 8 `gatt_operation_plan`.
It requires the original authorization artifact, verifies its exact SHA-256 against the plan, and revalidates authorization immediately before connection and before every operation. Expired or mismatched authorization fails closed.

The executor supports only the typed operation classes already present in the plan: characteristic read, descriptor read, characteristic write, and bounded notification subscription. It does not accept ad-hoc operations and does not implement fuzzing.

Results are persisted incrementally in a newly-created output directory. `run-start.json` is written before RF work, each completed/failed operation is written once as `operation-NNN.json`, and `run-final.json` records completion and cleanup state. Artifacts are never overwritten.

A successful ATT/GATT call is recorded as `transport_success: true`; writes and subscriptions retain `application_effect: not_assessed`. Transport success is not treated as proof of application state change or security impact.

Notification capture is bounded to 256 events and 65536 bytes. Subscription cleanup is mandatory. An unconfirmed unsubscribe or disconnect marks an unsafe stop and prevents continuation.
