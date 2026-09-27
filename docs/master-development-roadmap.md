# K’amal — Master Development Roadmap

**Document version:** 1.4 (planning revision — merged v0.12 BLE foundation, three-channel advertising plane, data-channel receiver R&D, operator UX)
**Date:** 2026-09-26
**Status:** Living implementation roadmap. Implemented/validated capabilities are identified explicitly; proposed capabilities remain design targets until completed and verified.
**Current software baseline:** merged `main` checkpoint `3676ce33a6ba8557df67de12ef1aa60ace214706` (`merge: v0.12 BLE assessment expansion`); active development branch `feature/v0.12-ble-data-channel` starts from that commit and is pushed to origin; v0.12 release/tag not yet cut
**Next implementation milestone:** develop BLE connection-context extraction and a dynamic data-channel receiver architecture while closing the remaining v0.12 release gates: runtime entrypoint packaging, successful pairing/key-aware OTA evidence, positive-write HIL, IRK/RPA work, and the WWR release decision
**Owner:** Project maintainers; review and approve architecture decisions before implementation

> **Purpose.** A durable, implementation-oriented plan for K’amal as a modular, distributed wireless and network security assessment, monitoring, evidence-management, and visualization platform. This document distinguishes verified project state from proposed work, specifies interfaces and safety boundaries, and provides release gates and an actionable backlog. The roadmap is intentionally updated from the actual development/HIL checkpoint rather than from the older v0.10 planning baseline; unimplemented versioned capabilities remain planning targets, not release commitments.

## 1. Executive direction

K’amal will combine **edge collectors** (portable or fixed Raspberry Pi-based nodes), **protocol-specific capture and analysis adapters**, an **evidence and assessment pipeline**, and a **fleet/dashboard control plane**. A local-first edge node must remain useful offline; the dashboard aggregates authorized nodes when connectivity is available. Every observation must retain its provenance, uncertainty, timestamps, and explicit distinction between passive observation, active interrogation, inferred identity, and verified security findings.

**Mission outcomes:** inventory authorized wireless/network assets; collect defensible RF/network evidence; identify configuration drift and review candidates; support distributed monitoring and incident response; explore heterogeneous radios without locking the platform to one vendor; let analysts drill from fleet → site → node → capture → asset → observation → evidence; show authorized node locations on a GPS-enabled map. The system is not intended to geolocate people or collect arbitrary third-party traffic.

### 1.1 Established baseline vs new proposals

**Released baseline:** v0.10.0 established bounded allowlisted BLE GATT survey behavior, evidence manifests, identifier resolution, and cleanup accounting.

**Current verified development checkpoint (`3676ce3`, merged to `main`):** the codebase has advanced materially beyond the v1.3 roadmap checkpoint. Implemented and regression-tested capabilities include evidence contracts and assessment integration; atomic publication handling; offline BLE cross-run correlation; device-context intelligence; reproducible/pinned Bluetooth SIG catalogs; typed and bounded authorized GATT operation contracts; BSAM mapping; a bounded authorized GATT executor; result/effect semantics; persistent safety interlock/recovery; synthetic v0.12 acceptance; authorization-gated active metadata surveys; dynamic `all_discovered` metadata authorization; BlueZ live-scanner lifecycle handling; BLE security-state contracts; read-only BlueZ security-state inspection; protected/redacted analysis of existing BlueZ key material; explicit bounded pairing/bond execution; corrected Nordic sniffer CLI mappings; and a production-validated three-receiver fixed advertising-channel observation plane.

**Current regression state:** 446 tests pass with one intentional/optional skip, and the v0.12 synthetic acceptance gate passes 22/22. These results verify the current software checkpoint, not every future adapter, host OS, controller, RF environment, or unimplemented decryption/data-channel path.

**Current HIL evidence:** the earlier dynamic all-discovered metadata survey, bounded Device Name read, and contained ATT `Insufficient Authorization (0x08)` same-value write remain valid evidence. The explicit pairing executor has also been exercised against the authorized `go dawgs` fixture: the one bounded BlueZ `Device1.Pair` attempt returned `AuthenticationFailed`, no stable bond was established, and the result is retained as a controlled failure-path HIL rather than a successful pairing claim. Nordic wrapper compatibility was hardware-validated after mapping K’amal's public options to the installed `nrfutil ble-sniffer` interface.

**Three-channel advertising-plane HIL:** three nRF52840/PCA10059 receivers are persistently assigned to primary advertising channels 37, 38, and 39. K’amal installs a narrow fixed-advertising `LD_PRELOAD` adapter because current `nrfutil` does not expose the required one-entry advertising hop sequence directly. The production `kamal-capture ble-adv3` path was validated for a 45-second steady-state run: CH37 captured 12 packets, CH38 31, CH39 28; every receiver reported zero off-channel packets, exactly one hop-sequence mutation, exactly one follow request, clean stop status, and no lingering sniffer process. An earlier CH38 acquisition timeout failed closed and exposed failure-reporting defects; those were fixed and regression-tested before the successful production rerun.

**Current BlueZ HIL baseline:** on the test Pi, `/var/lib/bluetooth` contained the expected adapter directory and 25 cached discovery records, including the `go dawgs` target, but zero persistent per-device `info` records at the pre-pair inspection checkpoint. This is host-specific evidence only. The later pairing attempt did not establish a persistent bond, so a successful pairing/key-material HIL remains outstanding.

**Known v0.12 release-hardening issues:** direct execution of Python entrypoints still depends on invoking the project virtual environment because the executable shebang/system Python path lacks Bleak in the tested image; a successful real pairing/bond plus synchronized OTA/key-aware decode has not yet been demonstrated; deterministic live IRK/RPA resolution remains pending; a positive successful bounded response-required write plus independent verification read remains pending; and the v0.12 WWR hardware-HIL requirement still needs an explicit release decision. The Nordic CLI mapping issue is closed, and the three-channel advertising observation plane is implemented and hardware-validated.

**Confirmed hardware correction:** K’amal Raspberry Pi nodes use **NVMe storage, not SD cards**. NVMe drive model, boot chain, encryption support and power-loss behavior remain to be inventoried and tested.

**Earlier project direction retained:** modular BLE, Wi-Fi, IEEE 802.15.4/Zigbee/Thread, SDR, LoRa, and broader RF/network tools; Raspberry Pi edge hardware, optional Sixfab/Telit LE910C4-NF LTE backhaul, Wi-Fi preferred/LTE failover, Tailscale/SSH; dedicated nRF52840 passive BLE sniffer so onboard Bluetooth can remain independent; local-first PCAP capture and a stable `kamal-capture` interface. Historical scope also includes Z-Wave, Bluetooth Classic, NFC/RFID, cellular, proprietary RF, DMR/LMR, asset/firmware inventory, baselining, SIEM, and wireless incident response. These remain requirements or aspirations unless specifically implemented and verified.

**Roadmap additions by planning revision:** v1.0 added dashboard/GPS/shared schema/fleet/data-governance direction; v1.1 added the Remote Tool Gateway and peripheral orchestration; v1.2 added NVMe/client-data protection and hybrid AI; v1.3 added BLE security-state evidence, explicit pairing/bonding authorization, protected Bluetooth key-material handling, key analysis, IRK-based identity validation, synchronized nRF/Wireshark packet correlation, and a revised v0.12 completion/release gate; **v1.4 records the merged v0.12 BLE foundation, the hardware-validated three-channel advertising observation plane, the current data-channel receiver research track, a late-stage human-friendly operator control UI goal, and a policy that the roadmap checkpoint/progress state is updated alongside meaningful pushed development checkpoints.**

## 2. Product principles and non-negotiable guardrails

1. **Authorization first.** All active work requires an explicit scope record (targets, allowed operations, owner, location, window, expiration, operator). Acknowledgment or device discovery alone does not confer authorization. Active jobs fail closed when scope is absent, expired, or ambiguous.
2. **Passive by default.** Separate passive collection from active connection, reads, writes, injection, fuzzing, replay, or transmission. Never silently escalate operation class. Destructive or disruptive testing is a separate manual lab workflow, not an automatic fleet feature.
3. **Local-first and resilient.** Buffer evidence on encrypted NVMe storage; survive WAN loss; upload with integrity verification and deduplication. Never discard the sole verified evidence copy solely because upload fails; enforce explicit storage limits and a safe-stop policy when limits are reached.
4. **Evidence before conclusions.** Distinguish raw observation, normalized fact, heuristic candidate, analyst-validated finding, and remediation status. A writable GATT property or unknown UUID is not itself a vulnerability.
5. **Privacy and minimization.** Scope filters at collection, pseudonymization/redaction for exports, retention tiers, role-based access, no default tracking of personal devices or people. MAC addresses, GPS, RF captures, and device identifiers are sensitive operational data.
6. **Separation of concerns.** Capture adapters cannot directly mutate assessment findings; rule engines cannot initiate RF operations; UI cannot bypass authorization services.
7. **Reproducibility.** Versioned schemas, tool versions, hardware/firmware metadata, rule versions, capture parameters, checksums, clock quality, and immutable audit trail.
8. **Resource discipline.** Explicit scan duration, rate, channel, storage, CPU, battery, data-budget, and concurrency limits. Prioritize reliable cleanup, cancellation, and safe-stop semantics.
9. **Open interfaces.** Favor documented file formats (PCAP/PCAPNG, JSON, CSV, GeoJSON where suitable) and replaceable capture backends. Preserve native capture files rather than lossy conversion.
10. **No false precision.** RSSI is not distance; node GPS is not the location of every observed radio. Location confidence and source must be visible.
11. **Secret-bearing evidence is first-class evidence.** Bluetooth LTKs, IRKs, CSRKs, BR/EDR link keys, credentials, and analogous secrets may be operationally necessary for authorized security analysis. Raw secret values must be separated from ordinary reports/logs, protected at rest, access-controlled, provenance-bound, and exposed only to explicitly authorized analysis paths.
12. **Prefer OTA corroboration when available.** Host-stack success/failure, directly observed protocol traffic, application acknowledgment, state change, and validated security effect are distinct evidence layers. A host API result must never be represented as a directly observed ATT/SMP/Link Layer event unless a capture actually supports that claim.


## 3. Personas and primary workflows

- **Field researcher:** enroll a node, verify scope, run passive surveys, optionally perform bounded authorized checks, annotate observations, preserve evidence offline.
- **Security analyst:** inspect inventory, filter by protocol/site/time, review evidence and rule rationale, validate findings, compare baselines, export reports.
- **Fleet operator:** see node health and location, connectivity, sensor capability, software version, queue/storage status; schedule approved jobs and update nodes safely.
- **Incident responder:** correlate time-bounded RF/network anomalies, preserve chain of custody, create cases, attach PCAP and notes, send sanitized alerts to SIEM.
- **Administrator/data steward:** manage users, scopes, retention, geolocation access, encryption, audit, tenant separation, and deletion requests.

End-to-end: create engagement/site and authorization → enroll node → calibrate clock/location → collect → validate and hash evidence → normalize → correlate → evaluate rules → analyst review → visualize/report → retain/archive/delete under policy.

## 4. Target architecture

```text
Authorized RF / wired environment
  │
  ├── BLE (Pi adapter + fixed nRF52840 CH37/38/39 advertising plane + future dynamic data receivers + optional key-aware decode)
  ├── Wi-Fi (compatible monitor-mode adapter)
  ├── 802.15.4 (supported sniffer/coordinator hardware)
  ├── SDR (supported IQ/spectrum-capable receiver)
  ├── optional LoRa / Z-Wave / NFC / Classic BT / cellular / wired
  │
[Edge node: Raspberry Pi]
  capture adapters → local spool (PCAP/PCAPNG/IQ/JSON)
  BLE security-state/key evidence → protected secret store + redacted analytical evidence
  metadata normalization → policy/scope enforcement → job supervisor
  integrity hashes + event journal + bounded local assessment
  node health + GPS source/quality + encrypted outbound sync
  │ Wi-Fi preferred; optional LTE failover; offline queue
  ▼
[Ingestion/control plane]
  node enrollment + auth → event intake → validation/dedup
  immutable evidence/object storage + metadata DB + job/audit DB
  normalization/correlation → versioned rule engine → findings/cases
  │
[API and dashboard]
  fleet/map | sites | inventory | captures | spectrum/time series
  GATT/protocol drill-down | comparisons | findings | reports | admin
  │
  SIEM/webhook/export integrations (explicitly configured)
```

**Deployment profiles:** (A) standalone offline Pi + local CLI; (B) single-node local web UI; (C) centrally managed multi-node fleet; (D) research-lab workstation with higher-bandwidth SDR. All use common schemas; heavy IQ processing may be deferred to a workstation/server. The dashboard must not be a prerequisite for edge capture or evidence integrity.

### 4.1 Component boundaries

| Component | Responsibility | Explicitly not responsible for |
|---|---|---|
| `kamal-capture` adapters | RF/network acquisition and capture metadata | Declaring vulnerabilities |
| Survey/job supervisor | Authorization, bounds, lifecycle, cancellation, cleanup | Protocol-specific parsing |
| Evidence store | Content-addressed files, hashes, manifests, retention | Modifying source evidence |
| Normalizer | Map native outputs to common event/asset schemas | Hiding uncertain identity matches |
| Assessment engine | Pure offline rules and explainable observations | Initiating connections/transmissions |
| Correlation engine | Link events/assets with confidence and provenance | Assuming rotating addresses imply one device |
| BLE security-state service | Pairing/bond state, key provenance, key fingerprints, IRK resolution, decryption inputs | Printing/exporting raw keys by default or claiming security properties not evidenced |
| Packet correlation/decryption | Bind immutable captures to authorized key evidence and derived protocol observations | Rewriting raw PCAP as if originally cleartext or promoting host-stack results to OTA observations |
| Fleet service | Enrollment, health, updates, scoped jobs, GPS | Unapproved active scans |
| API/dashboard | Query, visualization, analyst workflows | Bypassing policy or directly controlling radios |

### 4.2 Storage choices and decision gates

**Phase 1:** local files + SQLite metadata, JSON schemas, content hashes; SQLite or lightweight API suitable for one node. **Fleet phase:** relational metadata DB with geospatial support (PostgreSQL/PostGIS is a candidate), object storage for PCAP/IQ, optional time-series rollups, message queue only when load justifies it. Do not prematurely mandate a particular framework. Evaluate SQLite→PostgreSQL migration, backup/restore, and object-store costs using real workload tests. Define stable repository/API boundaries before introducing distributed infrastructure. Add a distinct protected-secret storage boundary for cryptographic key evidence: ordinary assessment JSON contains fingerprints/metadata and references, while raw key material lives in a restricted artifact or keystore with explicit access, retention, encryption and audit controls.

## 5. Shared data model and contracts

All records: `schema_version`, globally unique `record_id`, `engagement_id`, `site_id`, `node_id`, `job_id`, UTC `observed_at` and `ingested_at`, monotonic time when available, `clock_source`/offset/uncertainty, `protocol`, `collection_mode`, `authorization_ref`, `source_tool`/version, `adapter_id`, `confidence`, `sensitivity`, and evidence references. Fields may be null only with an explicit reason; never invent coordinates or identity.

**Core entities:** Engagement, AuthorizationScope, Site, Node, Sensor/Adapter, NodePosition, Job, CaptureSession, EvidenceArtifact, **SecretEvidenceArtifact, PairingSession, BluetoothSecurityState, BluetoothKeyEvidence, PacketObservation, DecryptionDerivation**, Observation, Asset, AssetIdentityLink, ProtocolEntity, Baseline, AssessmentRun, Rule, Finding, Case, Annotation, User/Role, AuditEvent, Export. Define IDs and cardinalities; use stable node IDs distinct from MAC/IP and changing modem identifiers.

**EvidenceArtifact:** content hash (SHA-256), byte size, MIME/type, path/object key, collection start/end, parser version, encryption/retention class, chain-of-custody events. Raw evidence immutable; derived data references original hash. Preserve PCAPNG interface metadata and timestamps; IQ requires sample rate, center frequency, gain, sample format, clock, antenna, and calibration notes.

**SecretEvidenceArtifact / BluetoothKeyEvidence:** separate raw secret material from normal analytical records. Analytical records may include key class (LTK/IRK/CSRK/link key), byte length, SHA-256 fingerprint, pairing/session provenance, authenticated/unauthenticated state when evidenced, Secure Connections/legacy classification when evidenced, negotiated encryption size, EDIV/Rand/counters where applicable, storage source, first/last observed time, and access/retention classification. Raw key bytes are never embedded in ordinary reports, console summaries, fixtures, CI logs, or AI prompts. The protected secret artifact must support explicit access auditing and later encrypted-at-rest integration with the NVMe evidence design.

**DecryptionDerivation / PacketObservation:** preserve the original capture unchanged and represent key-assisted decoding as derived evidence: source capture hash, key-evidence reference/fingerprint, decoder/tool/version, configuration, whether decryption was attempted/succeeded, frame/packet references, protocol/opcode/error fields, and limitations. `att_pdu_directly_observed=true` is valid only when the exact ATT PDU is present in the captured/decrypted evidence, not when Bleak or BlueZ merely reports an equivalent outcome.


**Asset identity:** observations of BLE address, Wi-Fi BSSID/SSID, 802.15.4 PAN/extended address, IP/MAC, vendor strings, etc. are distinct identifiers. Link to an asset only with confidence, method, time bounds, and analyst override. Rotating BLE addresses and spoofable MACs are not stable identity by default.

**Location model:** `node_id`, timestamp, latitude/longitude, optional altitude, horizontal accuracy (meters), fix type, provider (GNSS/manual/site), age, geofence/site association, privacy classification. Distinguish **node location** from **observation location**; never infer target coordinates from one RSSI reading. Manual site locations must be labeled manual. Use optional geospatial indexing; normalize coordinates to WGS84 and handle missing/invalid fixes.

**Assessment output:** rule ID/version, input artifact IDs/hashes, matched entity path, observation type, factual evidence, rationale, confidence, status (`candidate`, `needs_review`, `validated`, `false_positive`, `accepted_risk`), severity only when justified and separately reviewed, timestamps, reviewer and decision history. A rule result is not automatically a vulnerability.

**Contracts:** publish JSON Schema and sample fixtures; semantic versioning; additive migrations first; compatibility matrix (edge ↔ API ↔ dashboard ↔ rule packs); deterministic offline processing; idempotent ingestion; signed/checksummed manifests; tests for old schema reading and corrupted files.

## 6. Protocol capability roadmap

### 6.1 BLE / Bluetooth

**Implemented/validated foundation:** BLE discovery and GATT metadata; Bluetooth SIG identifier resolution with reproducible/pinned catalogs; active metadata survey under explicit authorization; dynamic `all_discovered` metadata scope with acknowledgment; frozen execution queues with live BlueZ scanner lifetime; typed/bounded `read_characteristic`, `read_descriptor`, `write_characteristic`, and `subscribe_notifications` contracts; layered write/WWR authorization; bounded executor; conservative result/effect semantics; persistent RF safety interlock/recovery; offline correlation/device intelligence/BSAM mapping; synthetic acceptance; read-only BlueZ security-state inspection; redacted local analysis of existing BlueZ key material; explicit bounded pairing/bond execution; corrected Nordic sniffer CLI integration; single-radio BLE capture; and a hardware-validated three-radio fixed CH37/38/39 advertising observation plane.

**Current v0.12 development focus:** extract connection-establishment context from the stable advertising plane and define a dynamic data-channel receiver architecture without assuming the advertising-hop command can pin BLE data channels 0–36. In parallel, complete the remaining release gates: one successful authorized pairing/bond with synchronized OTA evidence when a suitable target permits it; key-aware packet correlation/decode; deterministic IRK/RPA resolution; a safe positive response-required write HIL with an independent verification read; runtime/entrypoint packaging; and the explicit WWR release decision.

**Generalized passive BLE capture:** the fixed primary-advertising plane is now implemented. Remaining generalized work includes extended-advertisement coverage, connection-context extraction, data-channel receiver scheduling/reconstruction, capture-loss/timestamp quality metrics, discovery↔GATT correlation with uncertainty, advertisement drift, address-rotation/privacy handling, and explainable BLE IDS features/datasets. The current data-channel branch is research/implementation work; if the slice grows too large to stabilize safely for v0.12, the remainder moves to v0.13 rather than weakening the v0.12 release gate.

**Later BLE/BR-EDR:** BR/EDR discovery/metadata through supported adapters; capture imports from specialist analyzers; expanded SMP/GATT security tests; optional approved destructive/fuzz workflows only in attended lab modes. Raw writable metadata remains a review signal, not a vulnerability.


#### 6.1B Fixed advertising plane and dynamic data-channel receiver track

**Validated advertising plane:** K’amal reserves three nRF52840 sniffers for primary advertising channels 37, 38, and 39 using serial-bound udev aliases. `kamal-capture ble-adv3` starts them in a staggered follow-request sequence, then records a concurrent steady-state interval into three independent PCAPs plus a manifest. The follow-request marker is host-command evidence only and never substitutes for proof that the target was acquired over RF.

**Current hardware/tool boundary:** the validated Nordic firmware command used by K’amal to force the primary advertising hop sequence is specific to channels 37–39. K’amal must not assume that command can pin arbitrary data channels 0–36. Data-channel support requires a separately verified firmware/API/control mechanism.

**Current research sequence:**
1. Parse directly observed `CONNECT_IND` and, where supported by the capture/tool chain, `AUX_CONNECT_REQ`/related connection-establishment evidence from the fixed advertising plane.
2. Persist scheduling inputs with provenance: access address, CRCInit, channel map, connection interval, hop/CSA information, PHY, timing anchor/event-counter context where actually observable, and uncertainty/coverage limitations.
3. Define a receiver-scheduler contract that consumes only evidenced connection context and records assignment decisions.
4. Add two or more extra nRF52840 receivers as a dynamic pool only after an arbitrary-data-channel control path is verified.
5. Experimentally determine how many receivers materially improve reconstruction; do not assume one receiver per BLE channel is necessary.
6. Correlate receiver outputs into derived connection evidence while preserving every raw PCAP independently and recording loss/timestamp limitations.

**Acceptance boundary:** the fixed CH37/38/39 plane remains independently useful even if dynamic data-channel work is incomplete. A data-channel feature is not considered supported until channel control, timing behavior, cleanup, evidence provenance, and repeatability are hardware-validated.

#### 6.1A BLE security-state, pairing/bonding and key-aware OTA evidence

**Product goal:** make Bluetooth security state and cryptographic evidence usable in authorized assessments without conflating secret possession with vulnerability. Pairing, bond creation/removal, key capture, decryption, and identity resolution are explicit operations with their own authorization, evidence, cleanup, and retention semantics.

**Authorization taxonomy (proposed names; final CLI/schema names require ADR):**
- `inspect_security_state` — read-only BlueZ/D-Bus/MGMT/persistent-store metadata.
- `pair_target` — explicitly initiate pairing with bounded timeout and documented pairing policy.
- `establish_bond` — allow persistence of negotiated key material where the stack/device supports it; may be combined with pairing only if the contract says so explicitly.
- `remove_bond` / `reset_pairing_state` — destructive-to-state cleanup operation requiring separate authorization and evidence.
- `capture_pairing_ota` — start synchronized passive nRF capture before pairing and retain immutable capture evidence.
- `analyze_key_material` — local/offline analysis of authorized secret artifacts.
- `decrypt_capture` — derive a decrypted/dissected view from immutable capture + authorized key evidence.
- `resolve_rpa` — locally test observed RPAs against authorized IRKs and emit validated identity links only on cryptographic match.

Discovery of a device, possession of an LTK/IRK, or a general GATT authorization never implicitly grants pairing, bond removal, key export, decryption, or another active class.

**Security-state evidence sources:** BlueZ D-Bus device properties where available; BlueZ MGMT pairing/key events; `/var/lib/bluetooth/<adapter>/<device>/info` and cache metadata under root-controlled access; controller/host pairing results; nRF capture of SMP/LL traffic; Wireshark/TShark/nRF dissector output. Record source and confidence separately because cached state, persisted bond state, and live connection security are not interchangeable.

**Key evidence and analysis:** support LE LTK, IRK, CSRK/signing material and later BR/EDR Link Key evidence. Record fingerprints and metadata in ordinary evidence, while raw bytes remain in protected secret artifacts. Useful checks include key type and length/encryption size; authenticated vs unauthenticated state when supported by evidence; Legacy vs LE Secure Connections; debug/default key conditions; all-zero/all-`ff`/simple repeated patterns; duplicate key fingerprints across independently paired devices within the authorized analysis corpus; IRK reuse; CSRK counter/signing-state anomalies; unexpected persistence; bond-store permission/segregation; and mismatch between negotiated security and sensitive GATT behavior. Do **not** claim weak randomness from a single apparently low-entropy 128-bit key; randomness/derivation claims require an appropriate multi-sample corpus or known pathological construction.

**IRK and identity:** an IRK that cryptographically resolves an observed Resolvable Private Address may upgrade an asset relationship from heuristic/candidate correlation to a validated identity relationship with method `ble_rpa_resolution`, time bounds, observed RPA, identity address/reference, IRK fingerprint, and source evidence. Never expose the raw IRK in the normal identity graph.

**Key-aware nRF/Wireshark pipeline:** preserve the original nRF PCAP/PCAPNG unchanged; derive packet-level evidence using the appropriate authorized LTK/other pairing inputs supported by the capture tooling; record capture SHA-256, key-evidence ID/fingerprint, tool and version, command/configuration metadata, frame numbers, decryption counts/success, and protocol observations. A decrypted ATT Write Request/Error Response may corroborate a Bleak result and set `att_pdu_directly_observed=true`; it does not by itself prove application state change or a security vulnerability.

**Pairing capture:** begin passive capture before the pairing attempt when feasible. Extract evidence such as SMP IO capabilities, authentication-request flags, bonding/MITM/Secure-Connections negotiation, key-distribution flags, public/random addresses and Link Layer encryption transition. Infer association model only where the protocol evidence and IO/OOB conditions support it; otherwise record the underlying facts without overclaiming.

**Key handling controls:** raw keys are highly restricted client evidence. Default console/report output shows type/length/fingerprint and security metadata, not bytes. Store secret artifacts with restrictive permissions and explicit engagement ownership; integrate with encrypted NVMe/secret-store controls; never include raw keys in Git, ordinary JSON fixtures, debug logs, SIEM, dashboard exports, or AI prompts; access/export requires explicit authorization and audit. Cross-engagement key comparison is disabled by default unless the engagement/data-governance policy explicitly permits it.

**HIL sequence for the current `go dawgs` fixture:**
1. Preserve current unpaired baseline: read succeeds; response-required Device Name write receives ATT `0x08 Insufficient Authorization`; safe cleanup and failed-write payload provenance already validated.
2. Capture pre-pairing state: no persistent BlueZ bond record is currently present for the target on the test Pi.
3. Start synchronized nRF capture before an explicitly authorized pairing attempt.
4. Execute bounded pairing/bonding under K’amal and record host/MGMT/security-state evidence.
5. Inspect resulting BlueZ key metadata; create protected raw-key artifact plus redacted key-analysis artifact.
6. Use the resulting key information to assist authorized nRF/Wireshark/TShark decryption of subsequent encrypted traffic.
7. Retry the exact same-value response-required Device Name write under fresh authorization.
8. Correlate host-stack result with directly observed OTA ATT/SMP/LL evidence.
9. Perform a separate fresh read to verify observable application value; do not infer state change from write success alone.
10. If the paired write remains rejected, record that pairing/bonding was insufficient and investigate higher security/application authorization rather than weakening the evidence model.
11. When reproducibility requires bond removal, execute it only as a separately authorized state-reset operation and verify cleanup.

**Acceptance criteria for the BLE security-state increment:** pairing cannot occur without explicit operation authorization; secret-bearing artifacts never leak into ordinary logs/reports/tests; pairing/bond state and cleanup are durably evidenced; at least one real pairing capture is correlated with host-side state; key-assisted decode is demonstrated on an authorized encrypted connection when the capture/tooling supports it; IRK resolution has deterministic positive/negative fixtures before live use; directly observed packet semantics remain distinct from host API and application effects; failures leave the persistent safety interlock in a known state.

### 6.2 Wi-Fi (802.11)

Hardware capability probe and driver matrix → passive monitor-mode PCAPNG capture with channel/band metadata → AP/client inventory (BSSID, SSID, channel, security advertisements, observed capabilities) → baseline and drift (SSID/BSSID/security/channel changes) → evidence-backed rogue/evil-twin candidates with corroboration → authorized active configuration checks as separate opt-in workflows. Include 2.4/5/6 GHz support only where adapter/regulatory domain actually permits. Channel hopping creates observation gaps: record dwell schedule, channel, missed-frame limitations, interface mode, and capture loss. Do not claim encryption keys, payload visibility, or definitive evil-twin identification from beacon similarity alone. No automatic deauth/injection/jamming.

### 6.3 IEEE 802.15.4 / Zigbee / Thread

Supported sniffer capability matrix → passive frame capture with channel, PAN ID, addresses, LQI/RSSI when available → 802.15.4 inventory → Zigbee beacon/association/metadata parsers → Thread discovery/mesh metadata as supported → key/commissioning state only from authorized configuration evidence, not inferred from opaque ciphertext → drift and network-join anomaly candidates. Track FCS validity, capture loss, channel hopping, hardware timestamp limitations, and encryption visibility. Zigbee and Thread are distinct protocol layers atop 802.15.4; do not conflate identities or security models. No automatic join, key extraction, injection, or commissioning.

### 6.4 SDR / general RF

Device abstraction (supported SDR drivers) → calibrated sweep/spectrum snapshots → IQ capture with strict disk budgets → waterfall, occupancy, noise floor, signal/event segmentation → known-signal classification with confidence → anomaly comparison across time/sites. Track center frequency, sample rate, bandwidth, gain, antenna, calibration, units, saturation, clipping, dropped samples, time sync, and regional receive restrictions. Distinguish observed energy from decoded protocol/identified transmitter. Long-duration IQ and multi-node coherent localization are research tracks requiring measured clock/synchronization feasibility; not baseline promises. No transmit capability in standard fleet jobs.

### 6.5 LoRa / LoRaWAN

Passive metadata and compatible capture import → channel/SF/BW/RSSI/SNR inventory → gateway/network metadata where authorized → baseline and anomalies; distinguish LoRa PHY from LoRaWAN MAC. Do not assume encrypted payload readability or transmit/replay permissions.

### 6.6 Z-Wave, NFC/RFID, Bluetooth Classic, cellular, DMR/LMR, proprietary RF

Use **plugin maturity gates**: feasibility/legal review → hardware adapter → passive/import-only evidence schema → parser validation → inventory → rules → optional approved active workflow. NFC/RFID may require near-field, physically attended operation; cellular/LMR and proprietary RF carry substantial legal, privacy, encryption, and equipment constraints. Start with import and metadata from authorized instruments; avoid broad interception or decryption claims. Maintain per-protocol feature matrix showing `not planned / research / experimental / supported` and tested hardware/firmware.

### 6.7 Wired and network tools

Optional local network inventory and packet-capture adapters (Ethernet, IP, DNS, DHCP, mDNS, ARP, routing/segment context) to correlate RF assets with network services and owner-approved inventories. Passive first; authorized active reachability/service checks separately scoped and rate-limited. Preserve VLAN/interface, direction, timestamp, NAT uncertainty, and evidence. Support imports from established tools rather than recreating their entire functionality. No generic unrestricted scanner exposed to the fleet.

## 7. Assessment and detection strategy

**Pipeline:** validate report → normalize entities → run deterministic versioned rules → emit candidates with precise evidence paths → optional cross-capture correlation → analyst adjudication → reporting. Rules have IDs, descriptions, applicability, inputs, rationale, limitations, tests, and version history. Separate structural observations, hygiene recommendations, anomaly indicators, and confirmed vulnerabilities. No CVE matching by vendor/model string alone; require affected version and corroborating evidence.

**Initial BLE rule pack (v0.11):** custom/unknown UUID inventory; writable characteristic review candidates; notify/indicate-capable interfaces; characteristic property combinations; unexpected descriptor structures; missing/incomplete evidence; connection/disconnect failure accounting; known assigned UUID normalization. These are inventory/review signals, not severity-ranked findings. Support suppression with justification and expiry, and avoid double counting shared UUIDs.

**BLE security-state rule pack (v0.12+):** pairing/bond requirement observations; Legacy vs Secure Connections evidence; authenticated/unauthenticated key state; negotiated encryption-size review; debug/default/pathological-key indicators; duplicate key fingerprints within an authorized corpus; IRK/RPA validated identity links; unexpected bond persistence; failed bond cleanup; sensitive writable characteristics that differ between unpaired and paired state; discrepancies between host-stack results and directly observed ATT/SMP traffic. Rules must distinguish `observed`, `documented`, `inferred`, and `validated`; key possession or successful decryption alone is not a vulnerability.


**Cross-protocol later:** asset linkage by site/time plus independently verified IDs; Wi-Fi↔BLE co-observation, Zigbee/Thread↔IP via known border-router data, SDR energy↔decoded capture by channel/time, cellular backhaul health↔node outages. Confidence must decrease when time sync, location, identity, or coverage is weak. Detection evaluations require labeled benign/adversarial lab datasets, false-positive/false-negative analysis, drift tests, and operational alert budgets.

## 8. Dashboard, analytics, and drill-down

### 8.1 Information architecture

1. **Overview:** fleet online/offline/stale, coverage, active approved jobs, evidence volume, alerts by status, storage and sync backlog; freshness timestamps prominently shown.
2. **Fleet and GPS map:** node pins/clusters, current/last-known fix and age/accuracy, site geofences, deployment history timeline, health/connectivity, capabilities, assigned job; permission-gated exact coordinates.
3. **Sites and engagements:** authorized scope, owners, assets, sensors, time windows, coverage gaps, change history.
4. **Asset inventory:** protocol identifiers, observed services/capabilities, firmware only when evidenced, owner, confidence-linked identities, asset timeline.
5. **Capture explorer:** filter by node/site/protocol/channel/frequency/time; file metadata, checksum, downloadable authorized PCAP/IQ, packet/event drill-down where parsers support it.
6. **Protocol views:** BLE advertisements/GATT tree plus pairing/security-state timeline, redacted key metadata/fingerprints, RPA identity-resolution evidence, encrypted/decrypted packet correlation and frame references; Wi-Fi AP/client/security/channel views; 802.15.4 PAN/topology evidence; SDR spectrum/waterfall; LoRa metadata; wired/IP context.
7. **Assessment and findings:** candidate queue, evidence chain, rule rationale, compare runs, adjudication, remediation, export.
8. **Operations/admin:** scope approval, job queue and cancel, health, software/firmware inventory, storage, user roles, audit and retention.

### 8.2 Visualization requirements

Time-series event rates/RSSI/LQI/SNR, frequency occupancy heatmaps, SDR waterfall, channel utilization with sampling caveats, asset relationship graph with confidence-coded edges, GATT expandable service tree, protocol mix, coverage timeline, baseline diffs, and geospatial deployment layers. Every chart exposes time range, units, filters, aggregation, missing data, and source evidence. Use accessible palettes and tabular alternatives; virtualize large tables; server-side pagination; export filtered results with audit.

### 8.3 GPS fleet map: exact behavior

**Primary object mapped is the K’amal node**, not nearby devices. Sources: integrated GNSS, USB GNSS, modem GNSS if supported/tested, or manually assigned site location. A map pin shows last fix time, age, accuracy radius, source, node health, and connectivity; stale fixes are visually distinct. No fix → node in an **unlocated** list, never placed at `(0,0)` or a guessed site. Offline nodes retain last-known location clearly marked stale. Operators may view history only with authorized roles and retention limits. Provide map clustering, site boundaries, time playback, optional deployment routes, and GeoJSON/CSV export with coordinate redaction controls.

**Location data flow:** GNSS driver → validation (bounds, fix quality, accuracy, clock) → local position journal → encrypted, authenticated upload → geospatial DB/API → map tiles/UI. Avoid exposing precise locations in public dashboards, logs, screenshots, or default exports. Select map tile provider after licensing, offline-use, privacy, and cost review; allow self-hosted/offline tiles where practical. Do not infer transmitter geolocation from a single receiver. Future multi-sensor geolocation requires synchronization, calibration, statistical uncertainty, and explicit authorization.

### 8.4 Suggested UI implementation phases

First: static dashboard prototype driven by redacted fixtures and synthetic node coordinates; next: read-only local API and capture explorer; then: multi-node backend and map with simulated fixes; finally: authenticated live fleet, controlled jobs, role-scoped location history, SIEM exports, and an operator control surface built on the same authorization/job contracts. Prototype UI must never be mistaken for live telemetry.

### 8.5 Late-stage operator control UI

**Goal:** reduce the amount of command-line syntax an operator must memorize once K’amal's underlying protocol workflows are mature. This is deliberately a late-stage usability layer, not an immediate replacement for the CLI.

The first control surface should focus on BLE because BLE currently has the deepest operation contracts. It should support target/radio selection, passive capture modes, GATT metadata survey, authorized operation-plan construction, pairing/security-state workflows, evidence-path selection, run progress, cancellation, recovery-state visibility, and direct links to produced artifacts. It should present active/passive and state-changing boundaries before execution and require the same underlying authorization objects that the CLI requires.

**Architectural rule:** the UI does not shell out arbitrary operator text and does not bypass policy. It calls stable K’amal APIs/job contracts that in turn use the same planners, validators, safety interlocks, and evidence writers as the CLI. The CLI remains a supported automation/debug interface and implementation reference.

**Usability gate:** common supported BLE workflows can be performed without memorizing multi-line Bash commands; the UI previews the normalized operation and scope before execution; risky/state-changing operations remain explicit; progress/failure/cleanup state is visible; generated evidence is discoverable; and every UI action is reproducible or explainable in terms of the underlying K’amal contract/API.

## 9. Fleet and remote operations

**Edge reference:** Raspberry Pi with NVMe storage (not SD cards), onboard Bluetooth plus independent nRF52840 passive BLE sniffer; compatible Wi-Fi monitor adapter; optional 802.15.4 sniffer and SDR; optional Sixfab/Telit LE910C4-NF LTE. Existing backhaul direction: Wi-Fi preferred, LTE failover, Tailscale/SSH. Validate hardware-specific support and modem/GNSS compatibility before purchasing or promising functionality.

**Fleet lifecycle:** unique device identity; operator-approved enrollment; mutually authenticated encrypted channel; inventory of OS/kernel/radio firmware and calibration; heartbeat/health; policy sync; queued jobs with TTL and scope; signed updates and rollback; key rotation/revocation; decommission and secure wipe. No unsolicited inbound Internet exposure. Remote shell access is separate from analyst dashboard permissions.

**Job state machine:** proposed → authorized → queued → dispatched → acknowledged → running → completed/failed/cancelled/unsafe-stop → evidence-synced. Persist checkpoints and cleanup outcomes. Prevent concurrent operations on the same radio unless explicitly supported. Enforce RF scope locally even if control plane is compromised or unavailable. Handle reboot, clock skew, interrupted uploads, storage exhaustion, GPS loss, LTE data caps, and duplicate commands.

**Operational targets (proposed, validate in field):** zero silent scope bypasses; 100% evidence artifacts hashed; no false completion after failed cleanup; all jobs have terminal or explicitly recoverable state; backlog and last-seen age visible; test offline operation and replay; define measured latency, battery, and capture-loss SLOs per deployment profile rather than inventing one universal number.

## 9A. Remote Tool Gateway and peripheral orchestration (v1.1 addition)

**Product intent:** extend K’amal from a wireless sensor into an authorized field-operations gateway. The Raspberry Pi hosts or connects to supported peripherals; the gateway supplies managed transport, optional LTE egress, bounded jobs, local evidence capture, tool inventory and operator visibility. A peripheral's connectivity does **not** confer permission to use its capabilities. This section describes proposed features, not verified integrations.

### 9A.1 Supported topology progression

1. **Single-node central gateway (first):** one K’amal with directly attached USB/serial peripherals and optional LAN/Wi-Fi tool endpoints; private Tailscale-based remote management and existing Wi-Fi/LTE routing where validated. Keep the peripheral data plane separate from the gateway management plane.
2. **Hub-and-spoke (second):** multiple authenticated K’amal nodes or restricted tool relays connect to an authorized primary node or centralized backend. Each spoke enforces its own scope, keeps evidence locally during link loss and has its own identity, location and retrieval record. The hub must not be a single point of evidence loss.
3. **Optional mesh (research only):** evaluate Wi-Fi mesh or equivalent routing only when site geometry and resilience justify complexity. Require loop-free routing, per-hop authentication, segmentation, route/egress observability, node revocation, bounded traffic, partition/rejoin tests and a recovery mode. A mesh is **not** a prerequisite for the gateway MVP; no assumption that specialized tools themselves support mesh.

**Logical architecture:** remote operator/dashboard → authenticated control plane → K’amal gateway/job supervisor → capability-scoped tool adapter → local USB/serial/LAN/Wi-Fi peripheral; tool artifacts → local evidence spool → integrity-checked authorized upload. Network egress is a separately authorized service, not an unrestricted bridge, SOCKS proxy or general-purpose pivot by default.

### 9A.2 Peripheral integration matrix (proposed; feasibility required)

| Tool / class | Candidate interface | Initial supported workflow | Verification and constraints |
|---|---|---|---|
| Proxmark3 | USB/serial, supported host client | Inventory, explicitly approved remote session, capture/export of test artifacts | Verify exact hardware/firmware/client, USB reset behavior, RF scope and session cleanup; no assumption of remote unattended RF operations |
| Flipper Zero | USB serial/CDC and documented device interfaces | Device status, supported file transfer and approved command sessions | Validate firmware/API stability, physical-button-dependent actions and unsupported functions; never assume every onboard feature is remotely automatable |
| OMG Cable / similar networked peripherals | Vendor-supported local management interface, if available | Feasibility-only: authorized reachability and scoped transport | Confirm product-specific interfaces, licensing and authorization; no automatic payload delivery, keystroke injection, covert persistence or unrestricted Internet egress |
| SDR / Wi-Fi / 802.15.4 / BLE adapters | USB, local process, Ethernet where supported | Existing or planned capture adapters under the job supervisor | Radio ownership, power budgets, USB bandwidth, RF regulations, capture loss and clock quality |
| Serial / Ethernet lab equipment | USB serial, TCP with allowlisted endpoints | Status, bounded commands and evidence collection | Network isolation, protocol parser limits, no arbitrary host access |

**Integration contract:** each adapter declares tool type, unique instance ID, connection method, hardware/firmware/client versions, capability inventory, operation risk class, resource needs, health, supported cancellation, and artifact formats. Implement `discover → attest/identify → authorize → reserve → execute → capture → cleanup → release` with structured errors and durable audit events. Treat device names and serial numbers as sensitive evidence.

### 9A.3 Transport, egress and security design

- **Separate planes:** management/control, evidence transfer and tool traffic use explicit identities and access rules. Default deny between attached peripherals, client LAN, and Internet; allowlist destinations, protocols, ports, bandwidth and engagement window where egress is approved. Avoid automatic bridging or NAT of a client's network to LTE.
- **Access:** per-engagement roles, short-lived credentials, mutual authentication where supported, session approval for interactive commands, operator attribution, command/job logs with secret redaction, revocation and emergency stop. Remote shell and peripheral sessions require separate grants.
- **Reliability:** local queue and immutable hashes; bounded session TTL, keepalives, reconnect behavior, backpressure, LTE data caps, power monitoring, watchdogs, exclusive USB/radio locks and safe disconnect. WAN loss must not silently prolong an active job or bypass local scope.
- **Privacy:** collect only approved test traffic; distinguish tool location from target location; restrict coordinates, device IDs, captured content and session recordings; enforce engagement retention and retrieval/decommission checklists.
- **No implicit active testing:** discovery of a tool does not start it. Passive capture, interactive read, active transmission, manipulation and potentially disruptive operations are distinct policy classes; active classes require specific authorization. Unsupported or unsafe operations fail closed.

### 9A.4 Dashboard and GPS integration

Add a **node → attached tools → sessions/jobs → artifacts** drill-down. Show tool connectivity, capability/risk labels, firmware, ownership, last-seen, session operator, scope expiry, egress state and data consumption, job status, cleanup state, evidence hashes and retrieval status. Display hub/spoke links and topology health separately from geographical placement. Map only authorized **K’amal node** coordinates or approved manual indoor placements; do not infer the position of a Proxmark, Flipper, cable or RF target from the gateway's GPS. Demonstration records must be synthetic.

### 9A.5 Delivery work packages and acceptance gates

- **G0 — architecture and threat model (parallel with v0.11):** ADR for gateway vs mesh, trust boundaries, peripheral risk taxonomy, egress policy and transport selection; test with synthetic tool fixtures; no implementation dependency on BLE assessment engine.
- **G1 — single-node gateway MVP (after fleet identity/job supervisor foundations):** enumerate one supported USB/serial peripheral, opt-in approved read-only/status workflow, bounded session, clean disconnect, hashed artifact and offline recovery; demonstrate no cross-network routing by default.
- **G2 — Proxmark and Flipper adapters:** one narrowly scoped, documented workflow per tool on actual supported hardware; compatibility and failure matrix; operator review of any active RF functions.
- **G3 — egress adapter feasibility:** test one explicitly authorized peripheral's outbound path with endpoint restrictions and accounting; OMG-specific support only if vendor interface and engagement permissions are confirmed.
- **G4 — hub-and-spoke:** two authenticated nodes, offline spool, link failure/rejoin, node revocation, distinct scope enforcement and topology display.
- **G5 — optional mesh decision:** prototype only after measured coverage need and G4 success; assess cost, battery, routing reliability and recovery against a simpler cellular-backed star topology.

**Gateway MVP exit criteria:** no tool use without engagement policy; no unrestricted egress or client-LAN bridge; unique session/operator attribution; bounded operation and safe cancellation; reproducible evidence with hashes; correct behavior on WAN loss, USB disconnect, restart and expired scope; documented supported hardware and operator recovery procedure.

## 10. Security, privacy, and governance

Threat model: malicious RF inputs and malformed captures, rogue node enrollment, stolen Pi, compromised credentials, job injection, scope bypass, cross-tenant data leakage, GPS stalking, evidence tampering, unsafe updates, parser exploits, backhaul interception, denial of service, and supply-chain compromise. Controls: local allowlists and capability-based authorization; least privilege for radio processes; input validation and parser isolation; TLS/mTLS where appropriate; secrets in protected storage; encrypted disks/object storage; signed releases; audit logs; dependency/SBOM and vulnerability review; backup/restore tests; tenant isolation; access-controlled raw PCAP/IQ and exact GPS; retention/deletion workflows.

**RF/legal policy:** respect applicable local spectrum, privacy, interception, and licensing rules; explicit owner authorization for active checks; geographically scoped collection where feasible; no default deauthentication, jamming, replay, pairing, bond manipulation, key extraction/export, or disruptive fuzzing. Authorized Bluetooth security analysis may intentionally collect pairing/key material and decrypt owned/authorized traffic under an explicit operation/data policy. Capture filters are best-effort technical controls, not legal permission. Define an incident stop procedure and field operator checklist.

**Data tiers:** public documentation; internal aggregate metrics; restricted identifiers/coordinates; highly restricted raw captures/IQ/**cryptographic key material and derived cleartext**/credentials. Define retention per engagement, not one universal indefinite default. Scrub identifiers and secrets from test fixtures and CI logs; use synthetic GPS coordinates in demos; prevent Git staging of local evidence by default. Key fingerprints/metadata may appear in normal evidence only when policy permits; raw key bytes remain separately protected.

## 10A. Client Data Protection & NVMe Security (v1.2 addition; deployment release blockers)

**Status:** Design requirements, not assertions of implemented controls. The Raspberry Pi nodes use **NVMe**, not SD cards. Confirm actual NVMe models, bootloader/firmware, OS layout, PCIe adapter, power-failure behavior, hardware key capabilities, and drive sanitization support before finalizing controls. NVMe is still removable media and does not inherently encrypt client data.

### 10A.1 Data classification and threat model — SEC-01

Classify raw PCAP/PCAPNG and IQ, **Bluetooth LTK/IRK/CSRK/link-key material and key-assisted decrypted traffic**, device identifiers, credentials and secrets, access-control observations, client topology, exact GPS/indoor placement, assessment findings, logs, AI prompts/responses, and peripheral-resident artifacts. Define allowed collection, authorized destinations, sensitivity, retention, breach escalation and contract requirements for **each engagement**. Threat-model powered-off theft, powered-on seizure, NVMe removal, compromised OS, unauthorized peripheral access, cloud/AI leakage, accidental cross-engagement reuse, interrupted upload and lost connectivity. Obtain engagement-lead and organizational security/legal approval; do not assert compliance solely from this roadmap.

### 10A.2 Encrypted NVMe evidence and key management — SEC-02

- Separate OS and evidence storage logically; use a dedicated **LUKS2/dm-crypt encrypted evidence volume on NVMe** as a proposed Linux baseline. Decide whether swap, temporary files, journal, crash dumps, database caches and OS logs also require encryption or disabling; do not let plaintext spill outside the encrypted volume. Assess whole-disk encryption separately against Raspberry Pi boot constraints.
- Use unique node/engagement keys and a documented rotation, escrow, recovery and destruction process. **Do not store an unattended auto-unlock secret in plaintext on the same NVMe drive.** Evaluate remote key release and hardware-assisted sealing only after testing device identity, verified/measured boot feasibility, key-service outage and revocation behavior. A TPM/secure element is not a complete theft defense.
- Test powered-off NVMe extraction, powered-on theft, unattended reboot, network outage, power loss during writes, unexpected reset, and encrypted-volume recovery. An unlocked volume remains exposed to a compromised live host. Use per-artifact encryption to a repository-controlled public key for completed evidence where practical, while acknowledging transient plaintext during capture.
- Enforce quotas and safe-stop thresholds; document expected NVMe write endurance, SMART/health monitoring where supported, and integrity-preserving behavior on full disk or filesystem errors.

### 10A.3 Evidence lifecycle and segregation — SEC-03 / SEC-04 / SEC-05

1. **Provision:** assign unique node identity, engagement identity, permitted data classes, collection scope, encryption keys, retention policy and transfer endpoints; verify no previous engagement artifacts remain.
2. **Collect and seal:** minimize at source; confine captures, Bluetooth key artifacts, decrypted derivatives, scratch files and peripheral exports to approved encrypted locations; hash artifacts and record timestamps, tool/version, node, operator, job and authorization provenance. Preserve original encrypted/raw captures independently from key-assisted derivatives. Protect reference hashes and audit logs independently.
3. **Transfer and verify:** authenticated encrypted channel, destination allowlist, resumable transfer, end-to-end digest/receipt verification, idempotent ingestion, and explicit acknowledgment. No deletion of the sole evidence copy before receipt is verified.
4. **Retain and dispose:** delete local copies after verified ingestion according to the engagement policy; support legal holds and offline backlog. For NVMe, do not equate file deletion or filesystem formatting with reliable sanitization: assess cryptographic erase via destruction of properly isolated encryption keys, supported NVMe sanitize commands, and documented verification. Account for snapshots, swap, logs, backups, peripherals and AI stores.
5. **Reuse:** signed engagement-reset checklist, credential/key rotation, verification that old client evidence and cached identifiers are inaccessible, and independent operator signoff.

### 10A.4 Identity, isolation and audit — SEC-03 / SEC-04

Per-node identity and revocation; least-privilege radio and peripheral processes; management plane separate from client data plane; default-deny egress; scoped Tailscale/overlay ACLs and service credentials; engagement isolation in local paths, object storage, dashboard and AI Hub. Prevent a stolen node from querying other engagements or enrolling itself as a new node. Audit enrollment, job approval, collection, evidence access, export, transfer, key release, deletion, AI routing and incident response. Avoid secrets or sensitive payloads in logs. Preserve audit evidence off-node where feasible.

### 10A.5 Lost-device and incident response — SEC-06

Maintain assigned custodian, authorized physical placement, deployment/retrieval inventory, last-seen time, client contact and incident owner. On loss: mark compromised, revoke overlay identity and API credentials, stop remote key release, rotate potentially exposed secrets, revoke peripheral credentials, preserve independent logs, inventory potentially resident data and follow contractual notification/escalation procedures. Remote wipe is **best effort only** and cannot protect an offline device or guarantee erasure. Run tabletop and physical theft simulations for both powered-off and powered-on states.

### 10A.6 AI and peripheral boundaries — SEC-07

Apply classification before prompts or tool calls; send only minimum approved sanitized data to external providers. Private model hosting does not eliminate local access, retention or prompt-injection risks. Each AI prompt/response has engagement ID, model/provider, destination, redaction status and retention policy. Peripherals such as Proxmark, Flipper, SDR hosts and networked accessories require their own storage/credential inventory and reset procedure. The AI layer cannot access unrestricted shell, raw Bluetooth/cryptographic keys, protected decrypted payloads unless explicitly classified/approved, or unapproved tool actions.

### 10A.7 Mandatory client-deployment acceptance gate — SEC-08

**No unattended client deployment until:** encrypted NVMe evidence and key recovery tested; plaintext spill paths reviewed; powered-off and powered-on theft scenarios documented; per-node revocation and cross-engagement isolation tested; verified transfer and retention/sanitization demonstrated; peripheral/AI data boundaries reviewed; incident procedure rehearsed; deployment and retrieval accountability assigned; and organizational security/legal/engagement approval recorded. Record residual risks and exceptions explicitly; no unqualified guarantee that encryption prevents compromise of a running device.

## 10B. Distributed AI Infrastructure (v1.2 addition; optional, non-blocking to core assessment)

**Architecture:** lightweight field nodes use a model-independent, authenticated inference API through a policy router. Permitted destinations are (a) an approved online model provider and/or (b) a **shared private K’amal AI Hub** hosting a local model on separately sized compute. The AI Hub and the network/egress gateway are logically distinct roles even if colocated. No requirement for a model on every Raspberry Pi. Benchmark the AI Hub's hardware, concurrency, power and latency rather than assuming a Pi 5 can support the whole fleet.

**Engagement routing modes:** `private_only` (never cloud-fallback), `cloud_approved` (minimum sanitized data only), and `hybrid` (sensitivity-based routing within approved destinations). If no permitted model is available, fail safely or queue bounded **analysis-only** requests. Do not replay active tool operations after reconnection without renewed scope/time validation.

**AI work packages:** AI-01 model-independent request/response schema and evidence references; AI-02 shared private inference hub and multi-node benchmarks; AI-03 approved cloud connector with privacy review; AI-04 policy-based routing, redaction, identity, quotas and audit; AI-05 dashboard model status, queue and provenance; AI-06 adversarial input/prompt-injection, disconnection and cross-engagement tests. Start read-only: summarize validated evidence, explain node health, draft reports and propose deployment settings. All claims link to actual artifacts; model-generated vulnerability claims require analyst review. Later approved orchestration passes through deterministic authorization and explicit human approval, never unrestricted model-to-shell execution.

**AI gate:** core collection and assessment remain functional with both inference paths offline. Demonstrate no forbidden cloud fallback, no cross-engagement retrieval, no fabricated evidence IDs, prompt-injection resistance testing and complete model/data routing records before use with client data.

## 11. Release roadmap and dependency sequence

| Milestone | Scope / principal deliverable | Release gate |
|---|---|---|
| **v0.10.0 — released** | Bounded allowlisted BLE GATT survey, manifest, evidence and cleanup accounting | Existing successful single-device live run and offline tests; release published |
| **v0.11 capabilities — implemented in current development lineage** | Offline assessment engine, evidence contracts/integration, deterministic rule/evidence processing, device intelligence/correlation/catalog provenance foundations | Current regression coverage remains green; historical standalone tag/release status is not asserted by this roadmap |
| **v0.12.0 — current stabilization / release decision** | Authorized active BLE assessment plus security-state/key-evidence foundations; explicit pairing executor; corrected Nordic integration; fixed three-channel CH37/38/39 advertising plane; current experimental connection-context/data-channel receiver slice; remaining key-aware OTA, IRK/RPA, positive-write, runtime-entrypoint and WWR decisions | 446-test regression with one intentional/optional skip and 22/22 synthetic acceptance remain green; active metadata/read/rejected-write HIL retained; pairing failure path contained; three-channel production HIL passes with zero off-channel packets and clean teardown; successful pairing/key-aware OTA and positive write remain required if retained as v0.12 release blockers; clean docs/capability/release review |
| **SEC-01/SEC-02 — immediate parallel release blockers for client deployment** | Threat model, data inventory, NVMe evidence encryption and key-management prototype | Verified storage layout and theft/reboot tests; no unattended client deployment until SEC-08 |
| **v0.13.0** | Generalized BLE passive/connection capture: extended advertising, connection-context extraction, dynamic data-channel receiver scheduling/reconstruction if not completed in v0.12, capture-quality accounting, BLE IDS dataset/feature pipeline | Tested nRF52840 matrix and data-channel control mechanism; capture-loss/timestamp documentation; immutable raw-capture provenance; derived reconstruction retains uncertainty |
| **v0.14.0** | Read-only local API and dashboard alpha: inventory, GATT/security-state drill-down, capture/packet timeline, assessments | Fixture-driven UI, auth/access tests, evidence-linked drill-down; raw keys never shown by default |
| **v0.15.0** | Wi-Fi passive monitor-mode adapter and AP inventory | Driver/channel matrix, reproducible captures, privacy/regulatory checks |
| **v0.16.0** | IEEE 802.15.4 passive adapter; Zigbee/Thread metadata normalization | Tested sniffer/channel matrix; protocol distinction; golden PCAP fixtures |
| **v0.17.0** | SDR sweep/IQ metadata, spectrum and waterfall visualization | Calibration/capture-budget tests; units and limitations visible |
| **SEC-03–SEC-08 — prior to client deployment** | Engagement isolation, secure evidence/key lifecycle, sanitization, incident response, AI/peripheral data controls, independent review | All §10A.7 deployment acceptance criteria met; signed approval and residual-risk record |
| **v0.18.0** | Node enrollment, fleet health, sync and secure evidence ingestion; gateway identity and policy prerequisites | Offline replay, idempotency, revocation, recovery, tenant and tool-session trust-boundary tests |
| **v0.19.0** | GPS source abstraction, map, last-known fixes, history and role controls | Synthetic + real fix validation; stale/missing fixes; privacy and access tests |
| **v0.20.0** | Cross-protocol correlation, baseline/drift, analyst workflow and reports | Labeled evaluation and explainable identity confidence; export verification |
| **v0.21+ integration tracks** | Remote Tool Gateway G1–G4; LoRa, Z-Wave, NFC/RFID, BR/EDR, cellular/LMR/proprietary RF, wired imports, SIEM, optional authorized active plugins | Per-tool hardware validation, default-deny egress, scope/session controls, cleanup/recovery, privacy and protocol-specific gates |
| **Late pre-1.0 operator control UI** | Human-friendly control surface, BLE first: target/radio selection, capture modes, plan preview, authorized active workflows, run/cancel/recovery state and artifact navigation; later extend across mature protocol adapters | Uses stable API/job/authorization contracts rather than arbitrary shell; cannot bypass safety interlocks; common workflows require no memorized Bash syntax; every action remains auditable and reproducible |
| **AI-01–AI-06 — parallel optional track** | Model-independent AI API, shared private AI Hub, approved cloud provider, policy routing, read-only evidence assistance | Private-only no-cloud-fallback test, evidence provenance, data classification, offline continuity, AI safety tests |
| **Post-G4 optional research** | Mesh feasibility G5, only if measured deployment needs justify it | Routing, security, partition/rejoin, energy and recovery results vs hub-and-spoke |
| **v1.0.0** | Stable schemas/APIs, deployment docs, fleet hardening, restore/upgrade path, supported hardware matrix, complete operator workflow including the supported control UI and CLI fallback | End-to-end acceptance matrix, security review, reproducible release, maintenance policy |

**Sequencing note:** v0.12 intentionally pulled a narrow pairing/security-state slice and, during hardware investigation, also produced the now-validated fixed CH37/38/39 advertising plane. The current `feature/v0.12-ble-data-channel` branch may carry a narrow connection-context/data-channel increment if it can be stabilized without weakening the release gate; otherwise the generalized receiver/reconstruction work moves to v0.13. The human-friendly operator control UI remains late-stage: stable CLI/contracts come first. SEC-01/SEC-02 continue in parallel and SEC-08 blocks unattended client deployments. AI remains optional and must not block deterministic assessment. Gateway implementation still depends on identity, policy and job-supervisor foundations rather than mesh. Hardware-dependent releases may reorder after feasibility tests; no calendar deadlines are asserted.

## 12. Detailed v0.12.0 completion specification

**Goal:** turn the merged `3676ce3` v0.12 BLE foundation and current `feature/v0.12-ble-data-channel` continuation into a release-quality BLE assessment/capture foundation that distinguishes authorization, host-stack outcome, directly observed OTA behavior, application state, and validated security effect while safely handling pairing/bonding, secret-bearing evidence, and the boundary between fixed advertising observation and experimental data-channel reconstruction.

### 12.1 Already implemented and retained

- Evidence contracts, assessment integration and atomic publication semantics.
- Offline BLE cross-run correlation and device-context intelligence.
- Reproducible/pinned Bluetooth SIG registries and provenance.
- Typed/bounded GATT read/descriptor/write/notification contracts.
- Layered write authorization including separate WWR permission.
- Bounded executor with incremental evidence persistence.
- Conservative result/effect semantics.
- Persistent active-run/unsafe-stop interlock and explicit recovery.
- BSAM assessment mapping.
- Authorization-gated active metadata survey and dynamic `all_discovered` metadata scope.
- Live BlueZ scanner preservation through the frozen GATT survey queue.
- Synthetic v0.12 acceptance gate.
- BLE security-state/key evidence contracts, read-only BlueZ state inspection, redacted existing-key analysis, and explicit pairing/bond executor.
- Corrected Nordic CLI mappings for the installed `nrfutil ble-sniffer` interface.
- Three serial-bound nRF52840 fixed advertising receivers on CH37/CH38/CH39 with production `kamal-capture ble-adv3`, manifest validation, bounded shutdown and failure-preserving reporting.
- HIL validation for metadata survey, successful read, rejected response-required write, safe cleanup, failed-write payload provenance, controlled pairing failure, and the three-channel advertising plane.

### 12.2 BLE security-state work packages

**BLE-SEC-01 — contracts and ADR — implemented:** define PairingSession, BluetoothSecurityState, BluetoothKeyEvidence, SecretEvidenceArtifact, DecryptionDerivation and PacketObservation schemas; define explicit pairing/bond/reset/decrypt/RPA-resolution operation taxonomy; specify redaction/export rules and result semantics.

**BLE-SEC-02 — read-only BlueZ security-state adapter — implemented:** inspect D-Bus/MGMT/persistent store without pairing; enumerate cache vs persistent device state; capture safe metadata, file permissions, bond/key section presence, adapter/device provenance and timestamps. Unit tests use synthetic BlueZ stores; never require real `/var/lib/bluetooth` in CI.

**BLE-SEC-03 — protected key evidence — implemented for existing BlueZ key analysis/redaction boundary:** ingest authorized LTK/IRK/CSRK/link-key material into a restricted artifact boundary; ordinary JSON contains type/length/fingerprint and metadata only. Add secret-leak regression tests for console, ordinary evidence JSON, manifests, logs, exceptions, tests and exports. Integrate with NVMe encryption/retention later without changing evidence identifiers.

**BLE-SEC-04 — explicit pairing/bonding executor — implemented; successful pairing HIL still pending:** add bounded pairing under authorization rather than hidden `pair=True`; capture paired/bonded/trusted/security-level observations where the platform exposes them; persist cleanup state; handle timeout, user interaction, rejected pairing, disconnect, daemon restart and orphaned state. Bond removal is separate and opt-in.

**BLE-SEC-05 — pairing OTA capture — pending:** start the dedicated nRF capture before the authorized pairing action, bind capture and active run with timestamps/hashes, and parse SMP/LL evidence without modifying the source PCAP. Record capture quality and whether the relevant exchange was actually observed.

**BLE-SEC-06 — key-aware decode and packet correlation — pending:** supply the appropriate authorized key inputs to supported nRF/Wireshark/TShark workflows; create derived packet evidence bound to immutable capture hash + key fingerprint + decoder version; correlate exact ATT/SMP/LL frames to K’amal operations. Never expose a raw secret in command logs or generated reports.

**BLE-SEC-07 — IRK/RPA resolution — pending:** implement deterministic BLE RPA resolution against authorized IRKs with positive/negative unit vectors; emit validated identity relationships only on a cryptographic match; preserve time/address/provenance and never treat a non-match as proof of different physical identity.

**BLE-SEC-08 — key security analysis — partially implemented for existing BlueZ key material; broader corpus/live validation pending:** detect supported key/security metadata, obvious pathological raw-key patterns, known debug/default conditions where defined, duplicate fingerprints across independently paired devices within policy scope, unexpected persistence and security-state inconsistencies. Avoid unsupported entropy/randomness conclusions from isolated keys.

**BLE-SEC-09 — HIL and reproducibility — in progress:** use the current `go dawgs` target as the baseline fixture: preserve the unpaired ATT `0x08` result; pair/bond under K’amal; inspect resulting security/key state; perform key-aware capture; retry exact same-value write; independently read back the value; correlate host and OTA evidence. If the write remains rejected, retain that as valid evidence and satisfy the positive-write gate on another safe, reversible target rather than weakening authorization.

### 12.3 Release-hardening work packages

- **R-01 Runtime entrypoint:** fix packaged/direct CLI interpreter behavior so documented executables use the intended environment/dependencies rather than requiring an undocumented `.venv/bin/python` workaround.
- **R-02 Nordic CLI compatibility — completed:** wrapper mappings use the installed nRF sniffer interface (`--only-advertising`, `--follow`) and are regression/HIL validated. Continue to fail clearly on future CLI drift.
- **R-03 Positive write HIL:** one reversible response-required write succeeds under explicit authorization, followed by a separate fresh read confirming the observable value. Transport success alone cannot satisfy the gate.
- **R-04 WWR decision:** document whether write-without-response hardware HIL is a v0.12 release requirement. If no semantically safe target exists, keep WWR separately authorized and regression-tested but mark live validation deferred rather than improvising an unsafe payload.
- **R-05 Evidence sealing/release:** preserve HIL manifests outside Git; run focused/full/synthetic gates; verify clean tree/origin; update docs/changelog/capability matrix; create reviewed v0.12 tag/release only after all chosen blockers are closed.
- **R-06 Three-channel advertising observation plane — completed:** serial-bound CH37/38/39 radios, validated fixed-hop adapter, staggered startup, bounded cleanup, manifest/channel-purity checks, failure-preserving reporting, and production HIL.
- **R-07 Data-channel receiver architecture — current research:** extract evidenced connection context from the advertising plane, define scheduler inputs, verify an arbitrary-data-channel control mechanism, then experimentally scale a dynamic receiver pool. This does not become a supported feature until HIL establishes repeatable channel/timing behavior.

### 12.4 v0.12 acceptance matrix

A release candidate must demonstrate:
- authorization expiry/scope/target/write/WWR failures occur before prohibited RF;
- metadata survey can tolerate per-target operational failures without unsafe continuation;
- scanner lifecycle cleanup is deterministic and scanner-stop uncertainty latches recovery;
- successful reads preserve exact values and hashes;
- rejected writes preserve attempted payload provenance without claiming remote receipt/application effect;
- at least one successful response-required write is independently verified by a separate read;
- pairing cannot be initiated accidentally or through a normal GATT plan;
- key-bearing evidence is segregated and secret-leak tests pass;
- key-assisted packet evidence references immutable source capture and never overwrites it;
- directly observed protocol flags are set only from actual packet evidence;
- safety state is clear after safe completion and latched after uncertain cleanup;
- full regression and synthetic acceptance remain green;
- repository and release artifacts contain no client evidence or raw keys;
- fixed advertising-plane captures preserve per-radio provenance, exactly one validated hop mutation/follow request per successful receiver, and zero off-channel packets in the accepted HIL path; and
- any future data-channel reconstruction remains derived evidence tied back to immutable raw receiver captures and explicit timing/coverage limitations.

### 12.5 Deferred from v0.12 unless required by hardware evidence

General fleet service, production dashboard/control UI, Wi-Fi/802.15.4/SDR collectors, broad BLE IDS operation, generalized BR/EDR security testing, destructive BLE fuzzing, arbitrary key export, mesh networking, and AI orchestration remain outside the v0.12 implementation path. A narrow data-channel receiver experiment may continue on the current branch, but generalized receiver scheduling/reconstruction can move to v0.13 if it threatens v0.12 stability.

## 13. Dashboard and GPS design backlog (parallel track)

**D1 — UX contract:** wireframes for fleet, map, inventory, asset detail, capture detail, assessment detail; user stories and permissions matrix; navigation breadcrumbs preserving site/node/time filters.

**D2 — API contract:** OpenAPI for nodes, positions, sites, captures, observations, assessments, findings and jobs; cursor pagination, filters, sorting, rate limits, redaction, error codes, time-zone rules and API versioning.

**D3 — prototype:** read-only fixture server, synthetic coordinates, GATT tree and evidence pointer links; clearly label all simulated data. Test map with no GPS, stale GPS, multiple nodes at same coordinates, and international date/time zones.

**D4 — location ingestion:** GNSS hardware feasibility on actual Pi/modem, GPS driver, validation and position journal, offline sync, accuracy/fix provenance, PostGIS or equivalent indexing benchmark.

**D5 — access controls:** role-limited exact location and history; aggregate/coarse view for other roles; auditable export and deletion; map tile provider privacy review.

**D6 — operational visualization:** online status, battery/power if measured, CPU/temp, disk, adapter availability, backhaul, data cap, capture backlog, last sync, firmware and failed jobs.

**D7 — analysis visualization:** spectrum waterfall, channel/time occupancy, BLE GATT explorer, Wi-Fi and 802.15.4 inventory, comparison overlays, rule explanation and linked raw evidence.

**D8 — usability/performance:** accessible charts, search and filters, large dataset pagination, caching with freshness labels, offline UI where practical, automated UI/accessibility tests.

**D9 — operator control UI (late pre-1.0):** BLE-first guided control surface over stable K’amal API/job contracts. Provide target/radio selectors, passive capture presets, authorization/plan preview, active-operation confirmation, progress/cancel/recovery state, and artifact navigation. Preserve a CLI equivalent for automation/debugging; never permit the UI to bypass authorization, safety interlocks, secret boundaries, or evidence semantics.

## 14. Engineering process and quality gates

**Branching:** feature branches from main, focused commits, code review, tagged releases, changelog and migration notes. Stage explicit source paths; never `git add .` around field evidence. Keep generated surveys, local allowlists, backups, PCAP/IQ, GPS traces and credentials outside Git; add narrow ignore patterns and a secret/large-file scan in CI. Never assume ignore rules remove previously tracked secrets.

**CI matrix:** lint/type checks as adopted; unit tests; schema validation; deterministic golden fixtures; property/fuzz tests for parsers; integration tests with mocked adapters; **secret-leak tests and synthetic key fixtures**; hardware-in-loop tests only in controlled lab; dependency/security checks; packaging; docs build; backward-compatibility tests. Hardware tests must identify adapter model, firmware, kernel and environmental limitations. CI must never ingest real client keys or raw `/var/lib/bluetooth` contents.

**Release gates:** scope/policy review for active changes; safety/cancellation tests; no secret/evidence leaks; documented CLI/API changes; reproducible versioned schemas; migration/rollback; release notes; maintainer approval; signed tag/artifacts when infrastructure supports it. A single successful live test is evidence, not universal assurance.

**Definition of done:** code + tests + docs + schema/examples + privacy/security review + operational metrics + verified error paths + upgrade compatibility + artifact provenance. Maintain ADRs, issue labels (`protocol/*`, `edge`, `fleet`, `dashboard`, `security`, `data`, `research`), and a capability matrix per adapter.

**Roadmap synchronization:** treat this Master Roadmap as part of the development state, not an occasional planning artifact. Before or with each meaningful pushed checkpoint, update the current baseline/branch, implemented-vs-planned status, completed work packages, active next milestone, relevant test/HIL evidence, and revision history. The preferred sequence is: commit the implementation checkpoint locally; record that resulting implementation commit hash and progress in this roadmap; commit the roadmap update; then push both commits together. This lets the roadmap name the exact code checkpoint it describes without attempting to self-reference its own commit. A push that materially changes capability, release gates, architecture, or development goals should not leave the roadmap describing an older checkpoint. Small mechanical/fixup pushes may be rolled into the next meaningful checkpoint when they do not change roadmap state.

## 15. Risks, assumptions, and decisions to resolve

| Risk / open decision | Mitigation / decision trigger |
|---|---|
| Hardware fragmentation and driver/kernel changes | Test matrix and adapter capability negotiation; fallback import-only mode |
| LTE/GNSS support on chosen modem | Verify actual module, antenna, drivers, GNSS command/interface and location accuracy on hardware |
| RF coverage gaps and dropped frames | Capture loss metrics, channel dwell records, clock uncertainty and explicit coverage visualization |
| Storage explosion from IQ/PCAP | Quotas, rolling capture policies, compression evaluation, retention, capacity alarms; never silently truncate |
| Correlation false positives / privacy | Confidence-based links, analyst review, rotating-ID handling, pseudonymization |
| Dashboard scope creep | Read-only fixture prototype first; ship per-feature vertical slices |
| Operator UI hides safety/command semantics | Build only over stable authorization/job APIs; preview normalized operations; preserve CLI equivalence and explicit active/state-changing confirmation |
| Remote job abuse | Signed/scoped jobs, local policy enforcement, no automatic injection, audit and kill switch |
| Peripheral compromise or unrestricted egress | Isolated tool plane, default-deny forwarding, scoped destinations, per-session audit and revocation |
| Mesh complexity and loss of backhaul | Ship single gateway then hub-and-spoke; mesh only after a measured need and partition/recovery testing |
| Sensitive GPS and identifiers | RBAC, exact/coarse controls, encrypted storage, bounded retention, sanitized demos |
| Cross-protocol schema instability | Versioned contracts, fixtures, migrations, compatibility matrix |
| Map dependencies/cost | Compare licensed tile providers vs self-hosted/offline option; document terms and privacy |
| Uncertain timeline/resources | Milestone gates, capacity review each release, hardware feasibility spikes before promises |
| Research-only protocol/legal complexity | Separate experimental plugins, no unsupported capability claims |
| Bluetooth key/cleartext leakage | Separate protected secret artifacts, fingerprints in normal evidence, encrypted storage, access audit, redaction tests, no raw keys in Git/logs/AI/SIEM |
| Pairing changes persistent client/device state | Explicit operation class, bounded interaction, pre/post-state evidence, separate bond-removal authorization, cleanup/reproducibility procedure |
| Host-stack result diverges from OTA behavior | Correlate immutable nRF captures and packet-level evidence; keep host, protocol, application and security-effect stages distinct |
| Key-assisted decryption creates derived sensitive content | Preserve original capture unchanged, mark derived cleartext sensitivity, bind derivation to capture/key/tool versions and retention policy |

**Architecture decisions requiring sign-off:** single-node API framework; relational DB and object store; message bus threshold; GPS hardware/provider; map tiles; UI stack and operator-control API boundary; identity/SSO; tenant model; offline sync conflict rules; exact authorized active-operation taxonomy; **pairing/bonding and bond-reset policy; secret-evidence storage/encryption/export boundary; nRF/Wireshark key-injection mechanism and redaction strategy; IRK/RPA identity-link semantics**; capture adapter packaging; supported Pi/OS matrix. Record each as an ADR with alternatives, trade-offs, and review date.

## 16. Program management: epics, priorities, metrics

**P0 (now):** use the stable CH37/38/39 advertising plane to implement/validate connection-context extraction and the dynamic data-channel receiver architecture while closing remaining v0.12 gates: successful pairing/key-aware OTA evidence, IRK/RPA work, positive-write HIL, runtime/shebang packaging and the WWR release decision. Nordic CLI compatibility, BLE-SEC-01 through BLE-SEC-04 implementation, and the fixed advertising plane are complete.

**P1:** generalized BLE connection/data-channel reconstruction, extended advertising and BLE IDS datasets; read-only dashboard prototype including security-state/packet drill-down; SEC-01/SEC-02 NVMe encryption work; hardware feasibility for Wi-Fi/802.15.4/GNSS and Proxmark/Flipper connectivity.

**P2:** Wi-Fi and 802.15.4 collectors, SDR baseline, fleet ingestion, GPS map, mature evidence/secret lifecycle.

**P3:** controlled gateway MVP, Proxmark/Flipper adapters, scoped egress, hub-and-spoke, cross-protocol detection, SIEM/reporting, additional protocol plugins and production hardening; add the human-friendly operator control UI only after the underlying job/API contracts are stable enough that the UI cannot become a second execution path. Mesh remains conditional research. Reprioritize by verified user value, safety, evidence quality and hardware readiness, not version numbers alone.

Track: test coverage of safety paths; evidence hash verification rate; **secret-leak test rate; pairing success/failure/cleanup classifications; encrypted vs decrypted packet-correlation coverage; RPA resolution precision on deterministic vectors and authorized captures**; parser errors and capture loss; rule precision/false positives on labeled datasets; time-sync quality; storage and upload backlog; fleet uptime/last-seen; GPS fix accuracy/age; dashboard query latency; mean time to review a candidate; deployment/recovery time; privacy/access violations (target zero). Define baselines before setting numeric SLOs.

**Monthly review template:** shipped vs planned; hardware matrix changes; safety incidents/near misses; schema migrations; BLE pairing/key/decryption findings; detection quality; fleet/map privacy; open ADRs; budget/storage; top three next deliverables. Maintain a living issue tracker linked to this document; update status and dates at each release.

## 17. Immediate action checklist

- [x] Merge the completed v0.12 BLE assessment expansion through `d642acc` into `main`; merged checkpoint is `3676ce3`.
- [x] Create and push `feature/v0.12-ble-data-channel` from merged `main`.
- [x] Validate active metadata survey, live-scanner lifecycle, successful bounded read, rejected bounded write, safe cleanup, and failed-write payload provenance on controlled hardware.
- [x] Define BLE security-state/key-evidence contracts and ADR (BLE-SEC-01).
- [x] Implement read-only BlueZ security-state inspection with synthetic fixtures (BLE-SEC-02).
- [x] Implement redacted analysis of recognized existing BlueZ key material and secret-leak boundaries (BLE-SEC-03).
- [x] Implement explicit bounded pairing/bond execution with the shared persistent safety interlock (BLE-SEC-04).
- [x] Correct Nordic sniffer CLI mappings for the installed `nrfutil` interface (R-02).
- [x] Implement and production-HIL validate the fixed three-radio CH37/CH38/CH39 advertising observation plane (`kamal-capture ble-adv3`), including bounded cleanup and failure-preserving manifest/reporting.
- [x] Bring operator-facing documentation and the Master Roadmap up to the merged baseline; maintain the roadmap alongside meaningful pushed development checkpoints.
- [ ] Extract directly observed BLE connection-establishment context from advertising-plane captures and define a persisted scheduler-input contract.
- [ ] Verify a supported mechanism for selecting arbitrary BLE data channels on additional receivers; do not reuse the CH37–39 advertising-hop mechanism without evidence.
- [ ] Prototype a small dynamic data-receiver pool and measure reconstruction value, timestamp behavior, loss, and cleanup before scaling receiver count.
- [ ] Complete synchronized pairing OTA capture and key-aware Wireshark/TShark/nRF correlation on an authorized target that successfully establishes the required security state.
- [ ] Implement deterministic IRK/RPA resolution tests and evidence-backed identity-link upgrade.
- [ ] Complete positive response-required write HIL on a safe reversible target with a separate verification read.
- [ ] Decide/document the v0.12 WWR hardware-HIL requirement.
- [ ] Fix direct CLI/shebang environment behavior (R-01).
- [ ] Re-run focused/full/synthetic/HIL gates, update capability matrix/changelog/release notes, then make the explicit v0.12 tag/release decision.
- [ ] Continue SEC-01/SEC-02 NVMe encryption/key-management work in parallel; SEC-08 remains the unattended-client-deployment blocker.
- [ ] Keep the operator control UI as a late-stage goal; design it only after stable local API/job contracts exist.

## Appendix A — Sample assessment record (historical illustrative schema)

```json
{
  "schema_version": "0.11.0-draft",
  "assessment_id": "example-assessment",
  "input": {"artifact_sha256": "<actual-hash>", "schema_version": "0.7.0"},
  "rule": {"id": "BLE-GATT-WRITABLE-REVIEW", "version": "1.0"},
  "classification": "review_candidate",
  "evidence": {"json_pointer": "/gatt/services/2/characteristics/0/properties", "property": "write"},
  "rationale": "Characteristic advertises a write property; authorization and security behavior were not tested.",
  "confidence": "high-for-observed-property",
  "vulnerability_confirmed": false
}
```

The pointer is illustrative and must be generated from the actual parsed input; the placeholder hash must never appear in real evidence. This older sample is retained for traceability. Current implemented evidence/assessment contracts have evolved beyond this sketch; use repository schemas and tests at the active checkpoint as the implementation authority.

## Appendix B — Traceability and change log

**Source baseline:** original roadmap v1.2; current development/HIL state through merged checkpoint `3676ce33a6ba8557df67de12ef1aa60ace214706` on `main`, with active continuation on `feature/v0.12-ble-data-channel`; validated regression/synthetic gates and controlled BLE HIL results described in §1.1 and Appendix C. This roadmap records verified outcomes supplied during development and proposed next work; it does not claim that future successful pairing/key-aware decode, IRK/RPA, arbitrary data-channel control, or operator-UI capabilities already exist.

**v1.0 / 2026-09-18:** Initial comprehensive roadmap; expands historical RF scope with proposed dashboard, GPS fleet tracking, architecture, data contracts, release gates, and v0.11 acceptance criteria. Review and revise this document after initial repository and hardware audits.

**v1.1 / 2026-09-19:** Added Remote Tool Gateway and peripheral orchestration strategy, staged central → hub-and-spoke → optional mesh topology, Proxmark/Flipper/OMG feasibility matrix, egress and authorization controls, dashboard drill-down, gateway work packages and release dependencies. Preserved v0.11 offline assessment scope and existing baseline; no gateway integrations claimed implemented.

**v1.2 / 2026-09-20:** Corrected storage hardware to Raspberry Pi NVMe (not SD card); added detailed client data protection workstream SEC-01–SEC-08, encrypted NVMe/key-management and theft testing, evidence lifecycle, sanitization, lost-node response, deployment release gate; added hybrid AI design with shared private AI Hub and engagement-policy-controlled cloud routing.

**v1.3 / 2026-09-25:** Rebased the roadmap on the current `a372c82` v0.12 development checkpoint; documented implemented active-GATT authorization/executor/result/safety/correlation/catalog capabilities and current HIL evidence; added explicit BLE pairing/bonding and security-state architecture; introduced protected Bluetooth key evidence, LTK/IRK/CSRK/link-key analysis, IRK-based RPA validation, synchronized pairing capture, key-aware nRF/Wireshark/TShark packet correlation, secret-leak controls, revised v0.12 release gates, current runtime/sniffer-wrapper blockers, and a new immediate action plan centered on the `go dawgs` security-state fixture.

**v1.4 / 2026-09-26:** Rebased the roadmap on merged `main` checkpoint `3676ce3`; marked BLE-SEC-01 through BLE-SEC-04 and Nordic R-02 as implemented; recorded the controlled failed pairing HIL without overstating it as pairing success; documented the production-validated serial-bound CH37/CH38/CH39 advertising plane and its failure-handling lessons; added the connection-context/dynamic data-channel receiver research track and explicit firmware/API boundary; updated regression/acceptance state to 446 tests (one skip) and 22/22 synthetic acceptance; added a late-stage BLE-first operator control UI goal; and established roadmap synchronization as part of meaningful pushed development checkpoints.

## Appendix C — Current v0.12 HIL evidence summary

This appendix is an implementation-status snapshot, not a universal compatibility claim.

### C.1 Dynamic active metadata survey

- Development lineage introduced authorization-gated metadata survey and dynamic `all_discovered` scope restricted to `enumerate_gatt_metadata`.
- BlueZ live-scanner lifetime was corrected so discovery objects remain available during the frozen sequential GATT queue.
- Controlled HIL at the live-scanner checkpoint discovered 41 targets, inspected all 41, completed 14 metadata enumerations and contained 27 operational failures; safety state remained clear and scanner stop completed.
- Operational failures after the lifecycle fix were primarily reachability/timeouts and are not treated as unsafe execution.

### C.2 Successful bounded read

- Target: `00:1C:4D:45:DE:3F` (`go dawgs`).
- Standard GAP Device Name (`0x2A00`) read succeeded.
- Exact value: hex `676f206461776773`, UTF-8 `go dawgs`, 8 bytes.
- Read evidence was sealed and used to generate an exact-value write candidate.

### C.3 Rejected bounded write and provenance fix

- One response-required write of the exact freshly read value was explicitly authorized.
- Peripheral returned ATT/GATT `Insufficient Authorization (0x08)`.
- K’amal correctly recorded RF attempt, transport/protocol failure, no application acknowledgment/state-change/security-effect assessment, completed disconnect, and clear safety interlock.
- The first rejected-write HIL exposed an evidence defect: payload length/hash were populated only after successful `write_gatt_char()`.
- Commit `a372c82` (`fix: preserve failed write payload provenance`) moved attempted-payload provenance before the RF call and added regression coverage.
- Follow-on HIL reproduced the expected `0x08` rejection while correctly preserving `payload_bytes=8` and SHA-256 `aa216687df1bec4e2efdfe0d11115a15d49d2deb1316541de7deb8a9de651d96`; cleanup remained safe.

### C.4 Current BlueZ persistent-state baseline

- Adapter directory: `88:A2:9E:C6:E9:09`.
- BlueZ persistent root and adapter directories exist with root-controlled permissions.
- 25 cache records were observed.
- No per-device persistent directories or `info` files were present at inspection time.
- `go dawgs` exists in cache but has no persisted BlueZ device/bond record under that adapter at the current baseline.
- This motivates explicit pairing/bonding HIL and provides a clean pre-pair state for later comparison.

### C.5 Explicit pairing executor HIL

- BLE-SEC-04 implements a separately authorized, bounded BlueZ `Device1.Pair` path using the shared active-BLE safety interlock and does not set `Trusted`.
- One authorized attempt against the current `go dawgs` fixture returned BlueZ `AuthenticationFailed`.
- No stable bond was established. This validates the contained failure path only; it is not evidence of successful pairing or of a completed key-aware OTA workflow.
- Do not blindly repeat pairing attempts merely to satisfy a success criterion; use a suitable authorized target when successful pairing evidence is required.

### C.6 Fixed three-channel advertising observation plane

- Nordic `nrfutil 8.2.1`, BLE-sniffer plugin `0.21.0`, and nRF Sniffer firmware `4.1.1` were validated on the current Pi/nRF52840 setup.
- Persistent serial-bound aliases reserve one receiver each for CH37, CH38, and CH39.
- The installed Nordic CLI lacks a direct option for a one-entry advertising hop sequence; K’amal therefore uses a narrow `LD_PRELOAD` adapter that rewrites only the validated startup `SET_ADV_CHANNEL_HOP_SEQ` frame for the selected receiver.
- Standalone HIL established that fixed-channel behavior works while following a target and that three receivers can maintain channel purity when follow requests are staggered.
- Production `kamal-capture ble-adv3` HIL completed a 45-second steady capture with 12 CH37 packets, 31 CH38 packets, and 28 CH39 packets; each receiver recorded zero off-channel packets, exactly one hop-sequence mutation, exactly one follow request, a PCAP SHA-256, and clean shutdown.
- One prior production run timed out waiting for CH38's follow request. K’amal failed closed; follow-up fixes made shutdown/reporting nounset-safe, preserved the primary acquisition-failure status, and ensured failed HIL runs are packageable. The unchanged RF strategy then passed on rerun.
- The follow-request marker is host-command evidence, not proof of RF target acquisition.

### C.7 Current v0.12 quality gates

- Full regression: 446 tests passed; one intentional/optional skip.
- Focused capture-wrapper regression after the latest failure-reporting fix: 14/14.
- Synthetic v0.12 acceptance: 22/22.
- Three-channel production manifest acceptance: PASS; `capture_rc=0`; no lingering sniffer process.
- Merged development checkpoint: `3676ce33a6ba8557df67de12ef1aa60ace214706` on `main`; current branch `feature/v0.12-ble-data-channel` starts there.
- v0.12 remains unreleased pending the selected remaining gates in §12.

## Appendix D — BLE security/key evidence sketch

Illustrative analytical record; final field names require schema/ADR review. Raw key bytes are intentionally absent.

```json
{
  "schema_version": "0.12.0-draft",
  "record_type": "bluetooth_key_evidence",
  "engagement_id": "<engagement>",
  "node_id": "<node>",
  "adapter_id": "88:A2:9E:C6:E9:09",
  "target_ref": "<asset-or-observation-ref>",
  "pairing_session_ref": "<pairing-session-ref>",
  "key": {
    "class": "ltk",
    "bytes": 16,
    "sha256": "<fingerprint>",
    "authenticated": "<true|false|unknown>",
    "secure_connections": "<true|false|unknown>",
    "encryption_size": "<integer-or-null>",
    "debug_key": "<true|false|unknown>"
  },
  "source": {
    "kind": "<bluez_mgmt|bluez_store|other>",
    "artifact_ref": "<protected-or-redacted-source-ref>"
  },
  "secret_artifact_ref": "<restricted-reference>",
  "raw_key_embedded": false
}
```

Illustrative packet derivation:

```json
{
  "schema_version": "0.12.0-draft",
  "record_type": "decryption_derivation",
  "source_capture": {
    "sha256": "<immutable-pcap-sha256>"
  },
  "key_evidence_ref": "<bluetooth-key-evidence-id>",
  "key_fingerprint": "<sha256>",
  "decoder": {
    "tool": "<wireshark|tshark|nrfutil>",
    "version": "<exact-version>"
  },
  "result": {
    "attempted": true,
    "succeeded": true,
    "frames_decrypted": "<count>"
  },
  "packet_observations": [
    {
      "frame": 1842,
      "protocol": "ATT",
      "opcode": "Write Request",
      "att_pdu_directly_observed": true
    },
    {
      "frame": 1844,
      "protocol": "ATT",
      "opcode": "Error Response",
      "error": "Insufficient Authorization",
      "att_pdu_directly_observed": true
    }
  ]
}
```

These examples define the intended evidence separation: the immutable source capture and protected secret remain distinct from the derived packet interpretation, and packet observation still does not automatically imply application state change or vulnerability.
