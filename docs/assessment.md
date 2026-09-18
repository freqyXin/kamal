# Offline BLE assessments

K'amal combines existing passive BLE inventory and active GATT JSON reports into a unified, offline assessment. The assessment command processes existing files; it does not perform radio operations or initiate BLE connections.

## Supported inputs

| Evidence | Report schema | Producer |
| --- | --- | --- |
| Passive BLE inventory | `0.6.0` | `kamal-scan` |
| Active GATT enumeration | `0.7.0` | `kamal-gatt` |

The assessment output uses schema `0.9.0`. Application versions and report schema versions are independent.

## Workflow

Generate a passive report from an existing capture (requires the passive tooling and its dependencies):

```bash
bin/kamal-scan ble --input capture.pcap --json passive.json
```

Optionally, enumerate an explicitly selected, authorized BLE target (requires BlueZ, Bleak, a suitable adapter, and the relevant identifier registries):

```bash
bin/kamal-gatt inspect AA:BB:CC:DD:EE:FF --adapter hci0 --timeout 10 --json active.json
```

Once the input files exist, combine them offline:

```bash
bin/kamal-assess --assessment-id ble-assessment-001 --input passive.json --input active.json --json assessment.json
```

Repeat `--input` for additional reports. A passive-only assessment is supported:

```bash
bin/kamal-assess --assessment-id passive-assessment-001 --input passive.json --json assessment.json
```

These commands are examples, not a setup script: substitute paths to reports you have actually generated. The output path must not already exist; the CLI refuses to overwrite existing files, including source reports.

## Evidence and provenance

The assessment records its identifier and creation timestamp, source metadata, report-level observations, and an initially empty relationships list. Each source receives a `sha256:<digest>` identifier computed from the original JSON file bytes. The parsed report is preserved in the assessment, but the original file bytes are not embedded; retain source files for independent hash verification. Identical source bytes cannot be imported twice into the same assessment.

Passive and active observations remain separate, even if Bluetooth addresses match. Address equality alone does not establish physical device identity. K'amal does not automatically correlate reports or establish device identity. Its intelligence rules generate review findings, not confirmed vulnerability determinations. Each assessment observation represents a source report, not an individual advertiser or GATT service.

## BLE intelligence findings

Assessment schema `0.9.0` introduces evidence-backed findings. The assessment
builder generates findings automatically when its `findings` argument is omitted.
Passing `findings=[]` explicitly suppresses automatic generation; supplying a
nonempty findings list uses those findings instead.

Each finding includes a rule identifier, severity, confidence, status, and
evidence references. Evidence identifies an assessment observation and a JSON
Pointer path into its preserved source report. The assessment integrity section
records `finding_count`.

### BLE-GATT-001: Write Without Response characteristic requires review

**Trigger:** A successfully enumerated active GATT report contains a
characteristic whose properties include `write-without-response`. Reports with
unsuccessful enumeration or a non-null GATT error do not trigger this rule.
Passive BLE reports do not trigger it.

**Classification:** Informational severity, low confidence, potential status.

**Evidence:** The characteristic's advertised properties, referenced through
a path such as `/gatt/services/0/characteristics/0/properties`.

**Interpretation:** Review whether the characteristic accepts security-sensitive
commands and whether appropriate access controls are enforced.

**Limitations:** Advertised characteristic properties do not establish whether
writes succeed, require authentication or encryption, or affect security-sensitive
functionality. This rule performs no characteristic writes or pairing tests.
Its findings are review prompts, not confirmed vulnerabilities.

Finding identifiers are deterministic for identical assessment inputs, but
include service and characteristic positions; they are not stable identifiers
across different enumeration orderings.

## Validation and limitations

Import performs baseline structural validation of supported schemas: selected required fields and types, passive advertiser counts, nested GATT structures, and certain connection-state relationships. Malformed or unsupported reports are rejected. Reports documenting failed discovery, connection, or enumeration remain valid evidence when structurally correct.

This is not exhaustive JSON Schema validation. Some nested passive advertiser fields and optional GATT resolution metadata are not checked exhaustively. Validation does not prove report authenticity, capture completeness, or the correctness of security claims. Additional report fields are preserved.

## Requirements and authorization

`kamal-assess` operates offline without Bluetooth hardware, tshark, BlueZ, or Bleak. Generating source reports can require those dependencies; consult the BLE tooling section in the project README and `data/bluetooth/README.md` for registry generation.

Collect and assess only systems and radio environments for which you have appropriate authorization.
