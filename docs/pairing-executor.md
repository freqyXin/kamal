# Explicit Bluetooth pairing executor

K'amal v0.12 treats pairing and bond creation as separately authorized,
state-changing BLE operations. They are not GATT operations and are not enabled
by an ordinary GATT authorization.

The workflow has two commands:

- `kamal-plan-pairing` validates one exact pairing authorization and one exact
  request, hash-binds both source artifacts, and writes a plan without RF;
- `kamal-execute-pairing` executes that validated plan through BlueZ and writes
  conservative pairing/session evidence.

## Authorization boundary

A `bluetooth_pairing_authorization` applies to exactly one BLE address and an
explicit `public` or `random` address type. `unknown` is rejected. The
authorization must explicitly contain `pair_target`; a requested persistent bond
also requires `establish_bond`.

The v0.12 hard limits are deliberately narrow:

- one pairing attempt maximum;
- bounded discovery, pairing, and disconnect timeouts;
- mandatory post-run disconnect;
- optional fail-closed preconditions requiring `Paired=false` and
  `Bonded=false` before the Pair call; and
- an explicit allowlist of pairing-agent modes.

Existing `authorization_scope` artifacts for GATT reads/writes do not authorize
this executor.

## BlueZ execution semantics

The Linux backend uses Bleak only to maintain bounded live discovery long enough
to obtain the target's BlueZ Device1 object. Pairing itself calls
`org.bluez.Device1.Pair` directly over the system D-Bus.

K'amal deliberately does not use Bleak's BlueZ pairing convenience path and does
not set the BlueZ `Trusted` property. `Paired`, `Bonded`, `Trusted`, and
`Connected` are read back as distinct host-observed properties.

For the real BlueZ backend, v0.12 requires `request_bond=true`. The Device1 Pair
method does not expose a control that lets K'amal guarantee a pair-only,
non-persistent result, so a pair-only plan is refused before output creation or
RF rather than risk an unrequested bond. The pure contract can still represent
pair-only behavior for a future backend that can guarantee that semantic.

## Agent modes

`external_default` does not register a K'amal agent. BlueZ therefore uses the
existing default agent, if one exists.

`no_input_no_output` registers an application-scoped Agent1 with BlueZ's
`NoInputNoOutput` capability. It is not made the system default. The agent:

- accepts only the pairing-authorization callback used for Just Works-style
  authorization;
- rejects PIN entry, PIN display, passkey entry, passkey display, and numeric
  confirmation callbacks;
- rejects service-authorization requests because this pairing authorization does
  not authorize application/profile service access; and
- records only event names, never PIN/passkey values.

The selected agent capability is evidence about the local host's declared I/O
capability. It is not proof of the negotiated SMP association model. OTA packet
capture remains necessary to establish Just Works, Numeric Comparison, Secure
Connections, key-distribution flags, and related protocol facts.

## Evidence and result semantics

The executor writes immutable incremental artifacts under `--output-dir`:

- `run-start.json` — pre-RF publication snapshot;
- `pairing-session.json` — normalized `bluetooth_pairing_session`; and
- `run-final.json` — final execution/cleanup/safety result.

The session records independently observed before/after values for pairing,
bonding, trust, and connection state. It leaves authentication, Secure
Connections, encryption size, association model, and current encryption state
`null` unless another evidence source establishes them.

A successful Pair D-Bus reply is not enough for completion. K'amal requires
`Paired=true`, requires `Bonded=true` when a bond was requested, rejects an
observed change to `Trusted` because trust is not authorized by this plan, and
confirms the post-run disconnect before reporting a complete run. It records an
unexpected trust change rather than attempting to undo it implicitly.

## Shared active-BLE safety interlock

For v0.12, pairing intentionally reuses the existing persistent
`active-run.json` / `unsafe-stop.json` safety lease that was introduced for GATT.
This makes pairing and active GATT execution mutually exclusive without adding a
second competing lock before release.

If pairing fails after it was attempted, K'amal calls `CancelPairing` and then
performs disconnect, scanner-stop, and D-Bus/agent cleanup. Uncertainty in
required cleanup latches `unsafe-stop.json` and blocks later active BLE work
until explicit operator recovery is recorded.

The state-file record types still use the legacy `gatt_*` names in v0.12. That
is a compatibility detail of the shared interlock, not a claim that pairing is a
GATT operation.

## Planning example

`authorization.json` and `request.json` are separate evidence inputs. Planning
performs no RF:

```bash
.venv/bin/python bin/kamal-plan-pairing \
  --authorization authorization.json \
  --request request.json \
  --json pairing-plan.json
```

## Execution example

Execution is active RF and state-changing:

```bash
.venv/bin/python bin/kamal-execute-pairing \
  --plan pairing-plan.json \
  --authorization authorization.json \
  --output-dir pairing-run \
  --safety-state-dir /var/lib/kamal/ble-safety \
  --adapter hci0
```

For hardware acceptance, start the dedicated OTA capture before this command so
the pairing/security transition can later be correlated with the host-observed
BlueZ evidence.
