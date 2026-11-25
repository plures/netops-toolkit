# Ansible and Molecule Integration — Requirements

| Field | Value |
| --- | --- |
| Author(s) | NetOps Toolkit maintainers |
| Last Updated | 2026-11-04 |
| Related | [Decisions 0001–0003](../../docs/decisions/) |

## 1. Executive Summary

Operators need scan, inventory, vault, config, health, compare/analyze and report automation without late dependencies or lost native behavior. Success requires safe consent/recovery and trustworthy results.

Observed gaps: credential caching, health facts/role mismatch, report dispatch. Support is unproven; incident/performance baselines are unmeasured.

Operators need guidance; CLI/Python consumers stable contracts; Textual users discovery/status; maintainers drift prevention/evidence.

## 2. Goals and Success Criteria

| ID | Outcome | Success criterion |
| --- | --- | --- |
| G1 | Complete readiness | Every operation has verified prerequisites or actionable non-readiness; no selected function omitted. |
| G2 | Full coverage | All seven areas have documented CLI/Textual/Python workflows with positive/negative proof. |
| G3 | Safety/compatibility | Native regressions pass; forbidden effects and sentinel-secret exposure are absent. |
| G4 | Credible delivery | Installed artifacts, advertised platforms and both Molecule tiers pass mapped tests/review. |

## 3. Non-Goals

No native replacement, HTTP service, second vault, arbitrary remote shell, universal vendor certification, automatic remediation or autonomous merge/release. Containers are optional targets, not controllers. No area is deferred.

## 4. Functional Requirements

### Readiness and public contracts

| ID | Priority | The system shall… | Goal |
| --- | --- | --- | --- |
| FR-001 | P0 | Derive installers/readiness/help/dependency docs from one extensible versioned prerequisite registry covering every toolkit function. | G1 |
| FR-002 | P0 | Plan full-toolkit installation proactively with scope/sources/changes/ownership/reuse/consent boundaries. | G1 |
| FR-003 | P0 | Provision supported user-local prerequisites with reasonable defaults under plan consent, offering full guided assistance rather than manual-install abandonment. | G1 |
| FR-004 | P0 | Require separate consent for elevation, OS/WSL/VM features, virtualization, runtime installation/service starts, reboot and security grants. | G3 |
| FR-005 | P0 | Probe actual package/executable/collection/interpreter/driver/runtime/native-library/platform readiness in the consuming context, not imports alone. | G1 |
| FR-006 | P0 | Report native/companion/enhanced readiness separately with actionable reasons; incomplete selected install scope yields explicit non-success. | G1 |
| FR-007 | P0 | Resume provisioning idempotently, preserving user state and original failures despite successful cleanup. | G1 |
| FR-008 | P0 | Preserve native defaults, schemas, exit behavior and ordered module output through explicit companion selection. | G3 |
| FR-009 | P0 | Expose all companions through CLI/Textual/Python, including unavailable-capability guidance. | G2 |
| FR-010 | P0 | Share versioned requests/outcomes with scope/context/mode/input/plan/artifact provenance and safe categorized errors. | G2 |
| FR-011 | P0 | Distinguish per-target/step succeeded/failed/blocked/unsupported/cancelled/not-requested, aggregate partial and independent changed/cleanup state. | G3 |
| FR-012 | P0 | Separate findings from connectivity; selected failures/partial work/failed health policy prevent CLI success. | G3 |
| FR-013 | P0 | Keep preview/check connection-free and write-free, returning in-memory would-change/write results or unmet-observation preconditions. | G3 |
| FR-014 | P0 | Observe only explicitly selected targets/context, persisting local artifacts only on explicit output intent. | G3 |
| FR-015 | P0 | Bind fresh apply/rollback consent to targets/plan/inputs/controller/preconditions, separate from installer consent. | G3 |

### Seven companion areas

| ID | Priority | The system shall… | Goal |
| --- | --- | --- | --- |
| FR-016 | P0 | Provide bounded native discovery with scope/exclusions/concurrency/timeouts and distinct discovered/unreachable/auth-failed/unknown-vendor results. | G2 |
| FR-017 | P0 | Preview discovered inventory duplicates/field changes without merge/export writes until explicitly selected. | G2 |
| FR-018 | P0 | Validate/export/refresh existing inventory with explicit/derived groups, precedence and credential-free Ansible hostvars. | G2 |
| FR-019 | P0 | Bind credential-free caches to inventory/context/schema; missing/malformed source fails despite an existing cache. | G3 |
| FR-020 | P0 | Preserve native vault crypto/unlock and environment → device → first matching group → default precedence, distinguishing locked/missing/wrong-password. | G2 |
| FR-021 | P0 | Supply task/target-scoped credentials through qualified protected handoff; forbid plaintext argv/environment/inventory/secret-file fallback. | G3 |
| FR-022 | P0 | Preserve transport/port/host-key/bastion routes across controller boundaries, blocking unqualified routes rather than connecting directly. | G3 |
| FR-023 | P0 | Collect configurations with native host/device-type/collection-time/success/config/error semantics. | G2 |
| FR-024 | P0 | Produce explicit backups with correct content, protected permissions and declared retention/Git effects. | G2 |
| FR-025 | P0 | Provide native-safe guarded plan/apply/rollback for applicable update/reload, ACL and NTP intents. | G2 |
| FR-026 | P0 | Preserve pre-state/confirmation/vendor-recovery safeguards, distinguishing committed/confirmed/rolled-back/failed/uncertain state. | G3 |
| FR-027 | P0 | Evaluate health/interface/BGP/VLAN through compatible facts/role/templates with inclusive threshold alerts and reading provenance. | G2 |
| FR-028 | P0 | Report missing/malformed readings as unavailable/error or unknown, never healthy zero; reject unsupported checks including OSPF explicitly. | G3 |
| FR-029 | P0 | Compare snapshots/results through native semantic analysis with change/no-op, parser/vendor context and invalid/unsupported-input outcomes. | G2 |
| FR-030 | P0 | Generate inspectable guarded vendor-aware remediation as unexecuted artifacts, never collection/apply permission. | G2 |
| FR-031 | P0 | Render aggregated outcomes as HTML/requested PDF preserving alerts/errors/blocked targets/coverage/incompleteness. | G2 |
| FR-032 | P0 | Provide working native/companion report entrypoints with output references/integrity only after successful rendering. | G2 |

### Protection, verification and lifecycle

| ID | Priority | The system shall… | Goal |
| --- | --- | --- | --- |
| FR-033 | P0 | Exclude decrypted credentials from caches/exports/ordinary artifacts/logs/reports, fixing injection-before-cache leakage. | G3 |
| FR-034 | P0 | Protect explicitly authorized sensitive recovery snapshots separately from redacted outputs; unavailable secure storage blocks promised apply. | G3 |
| FR-035 | P0 | Reject injection/path/symlink/archive escapes, unauthorized overwrites and executable device data, including unapproved report remote fetches. | G3 |
| FR-036 | P0 | Clean only owned resources on every exit, reporting cleanup failure/uncertain remote state without implied additional recovery consent. | G3 |
| FR-037 | P0 | Execute real daemon-free Molecule lifecycle on controlled fixtures/mock SSH with seven-area state/result/side-effect assertions. | G4 |
| FR-038 | P0 | Provide independently qualified opt-in container scenarios with consented runtime prerequisites and honest mock/vendor limits. | G4 |
| FR-039 | P0 | Package/discover required modules/roles/templates/scenarios/public entrypoints from wheel and sdist installations outside checkout. | G4 |
| FR-040 | P0 | Advertise only qualified native/controller/platform/credential paths and tiers. | G4 |
| FR-041 | P0 | Keep unit tests service-free, including loopback, separate from controlled real integration/Molecule tests. | G4 |
| FR-042 | P0 | Provide independent criteria-derived load-bearing tests, genuine evidence/CI gates and final full-suite validation. | G4 |
| FR-043 | P0 | Maintain install/API/tutorial/reference docs and runnable secret-free examples with dependency/public-surface drift checks. | G4 |
| FR-044 | P0 | Verify activation/reversible updates/uninstall while preserving native usability and user vaults/inventory/backups/unknown resources. | G3 |
| FR-045 | P0 | Capture actual built-product media only at code-complete immediately prerelease, refreshing after relevant final changes. | G4 |

## 5. Acceptance Criteria

Assert positive/negative effects, not exit codes alone.

| ID | Requirements | Given / When / Then and required evidence |
| --- | --- | --- |
| AC-001 | FR-001–007 | Clean/partial/drifted installs prove planning/provision/re-probe/consent/recovery. Missing/wrong dependencies, network/trust/permission denial, cancel and unsupported platforms yield actionable non-success, preserving native state. Unselected tier is not-requested; unregistered dependencies fail drift checks. |
| AC-002 | FR-008–012 | CLI/TUI/API mixed-target/alert/error fixtures yield equivalent statuses/provenance. Unknown major schemas fail; additive fields follow documented compatibility. Companion failures have distinct nonzero categories; native regressions pass. |
| AC-003 | FR-013–015 | All previews: zero connections/writes/reloads/pruning/audit files. Observation/output stays scoped. Changed/expired target/plan/input/context invalidates apply/rollback consent, including API automation. |
| AC-004 | FR-016–017 | Discovery proves bounds/exclusions/enrichment/duplicates/failure distinctions. Preview preserves inventory; explicit save matches proposed merge. Real claimed protocols have separate proof beyond mocks. |
| AC-005 | FR-018–019,033 | Real Ansible loads installed inventory with correct groups/hostvars/precedence. Source/context/schema changes invalidate cache; malformed/missing source fails. Exports/cache are credential-free; diagnose legacy secret caches without silent reuse/copy. |
| AC-006 | FR-020–022,033 | Synthetic vaults prove precedence/unlock errors. Real handoff proves scope/expiry, malformed/truncated/oversized-input rejection and cancel cleanup. Inspect argv/environment/callbacks/caches/staging for leaks. Qualify real Windows→WSL/bastion/key paths without plaintext/direct-route fallback. |
| AC-007 | FR-023–026,034 | Real roles/modules on stateful fixtures prove collection schema, backup content/retention/modes, update/ACL/NTP effects and snapshot/confirm/recovery order. Inject precondition/auth/transport/apply/rollback/cancel failure: truthful partial/uncertain state, no unauthorized mutation. |
| AC-008 | FR-027–028 | Real facts/role/template chain proves nested schema, below/equal/above thresholds and interface/BGP/VLAN outcomes. Missing/malformed data is not healthy zero; OSPF is explicitly unsupported. |
| AC-009 | FR-029–030 | Paired configs prove normalization/change/no-op, vendor mismatch, malformed-input and generation guards. Generated intent is deterministic/unexecuted; collection/apply need separate consent. |
| AC-010 | FR-031–032,035 | Installed report paths render HTML/PDF with mixed-outcome counts/hashes. Template/library/permission failures are non-success; malicious text is escaped, remote fetch blocked. |
| AC-011 | FR-034–036,044 | Actual Windows ACL/Linux/WSL permission and malicious-path tests prove protection. Interrupted update/activation, timeout/cancel/cleanup failure preserves original errors/user state; known-good recovery works; uninstall removes only owned resources. |
| AC-012 | FR-037–038 | Both tiers execute dependency/setup/create, prepare, converge, applicable idempotence, verify, cleanup/destroy with injected lifecycle failures/cancel. Assert effects/owned teardown; timestamp backups use content/retention invariants. Record runtime/image/driver/collection context. |
| AC-013 | FR-039–041 | Inspect/install wheel and separately build/install sdist outside checkout; execute CLI/TUI/API/assets/examples without editable imports/PYTHONPATH. Qualify actual Linux/macOS/native-Windows+WSL launch/cancel/setup recovery and non-CI script exits. Unit suite starts zero services. |
| AC-014 | FR-042–043 | Independent criteria-derived tests map all IDs to source/evidence; applicable revert/negative controls fail. Final full-suite/lint/type/build/audit/docs/integration/platform/CI passes; review has zero high-severity findings; installed examples pass, docs/help drift fails. |
| AC-015 | FR-040,044–045 | Complete scope/both tiers qualify before readiness. Revert preserves native defaults. Code-complete prerelease media has real build provenance; merge/release stays human-controlled. |

## 6. Nonfunctional Requirements

Proposed acceptance thresholds, not measured performance/support guarantees:

| ID | Dimension | Target and verification |
| --- | --- | --- |
| NFR-001 | Safety/privacy | Zero forbidden effects/targets/sentinel-secret leaks in AC-003/006/011 output/staging inspection. No perfect-redaction or Python-memory-erasure guarantee. |
| NFR-002 | Responsiveness | Ready dependencies, 100 inventory records: mapping preview p95 ≤2s over 20 warm runs on documented hardware; exclude downloads/process cold start. |
| NFR-003 | Recovery | Stop new dispatch within 2s of accepted cancel; stalled fixtures prove bounded timeouts/uncertain-state reporting, not stopping issued remote commands. |
| NFR-004 | Compatibility | 100% native regression/advertised platform-tier cells pass AC-002/013; toolkit Python ≥3.9 is separate from controller versions. |
| NFR-005 | Evidence | 100% FR/AC/NFR mapping with code/spec, commands/context, versions, exits/results and safe artifact/CI references; stale proof fails AC-014. |
| NFR-006 | Observability | Every I/O boundary has structured safe operation/step/target/error context; every selected failure has category/next action (AC-001/002/011); no raw secret dumps. |

## 7. Constraints and Dependencies

Controller: isolated managed per-user Python on Linux/macOS; qualified existing or consented guided WSL on Windows, not native Windows Ansible. No global Python mutation or silent fallback.

Probe ping, selected Git, PDF native libraries, controller tools and Galaxy/lifecycle prerequisites. Versions/images/libraries/platform tuples need qualification. Keep inventory/settings separate; no implicit vault/master-password/private-key copying.

The authorized Python/Textual/local-state exception remains unapplied/execution-inactive. Actual feature PX spec/tests and foundation reconciliation precede implementation, not waived by Requirements approval. Approved gates/review/publication transport remain dependencies.

## 8. Open Questions

No unresolved product-scope question. Platform/credential qualification precedes support claims; failure is actionable non-success, not scope reduction.
