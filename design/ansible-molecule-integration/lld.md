# LLD — Ansible and Molecule integration

| # | Field | Value |
|---|---|---|
| 1 | HLD | [Approved design](design.md), [frozen requirements](requirements.md) |
| 2 | Status | Draft |

## Design rationale & key decisions

1. Explicit companions compose native engines because native availability must not depend on Ansible or a controller.
2. One dependency DAG drives full-toolkit setup and readiness, preventing installers, help and operational checks from drifting.
3. A managed per-user controller isolates Ansible versions from toolkit Python ≥3.9. Linux/macOS run directly and Windows uses qualified WSL.
4. Daemon-free Molecule targets are the default. Containers are separately qualified optional targets, never an alternative controller.
5. Credentials cross only a private framed pipe and controller-local scoped resolver. Extra-vars, environment and secret files are rejected because they expose secrets to Ansible staging and callbacks.
6. Preview is a pure path, not native push dry-run: the latter connects and snapshots. Fresh one-use consent gates mutation and permitted recovery.
7. Peer-backend replacement and mandatory containers are rejected for native compatibility and setup burden. Existing inventory, vault, analysis and change owners remain authoritative.
8. Actual PX/foundation binding is a pre-implementation prerequisite, not a Python bridge invented by this design or a blanket compatibility waiver.

## 1. Summary

This LLD specifies all seven explicit companions, full-toolkit provisioning, public contracts, owned state, protected execution and qualification. The greatest risk is preserving scoped credentials, routes and cancellation across WSL and Ansible forks without fallback. The insertion points below are real source owners; new contracts are explicitly **PROPOSED**, not claims of existing APIs.

## 2. Interfaces & Interactions

### Public surfaces

1. **Existing:** `netops.__main__.main() -> int`, `netops.tui.__main__.main() -> int`, native module APIs and [component references](../../docs/api/README.md). Preserve native spellings, defaults, exit semantics and ordered command results.
2. **PROPOSED CLI:** `netops setup {plan,apply,status,resume,restore,uninstall}` and `netops ansible <area> <operation>`. Shared options: `--request FILE`, `--mode {preview,check,observe,output,apply,rollback}`, `--json`. Request/input loading is read-only and happens outside pure preview (§2 hydration). No password, master-password, arbitrary executable or reusable `--yes` option.
3. **PROPOSED Python:** `WorkflowService.catalog()`, `preview(request, loaded)`, `execute(request, authorization=None)`, `cancel(operation_id)` (§3). Calls are synchronous except cancellation from another thread. Textual dispatches execution through its worker facilities and consumes safe progress events on the UI thread.
4. Textual adds one companion catalog/setup screen under the existing `NetopsTUI`, with all seven areas, disabled reasons, plan effects/sources, separate consent prompts and per-target status. Existing native buttons do not silently switch engines. No new HTTP endpoints or daemon.
5. Effectful API automation uses the same consent port as the CLI/TUI, not an asserted permission bit in request JSON. Installer consent cannot authorize operation execution.

| # | Area | Operations | Typed input and result |
|---|---|---|---|
| 1 | scan | discover, inventory-preview, save | Explicit host/CIDR scope and exclusions, protocol flags and bounds → per-address discovery disposition and merge proposal |
| 2 | inventory | validate, export, refresh | Source identity/content and controller mapping → groups, allowlisted hostvars, validation/cache disposition |
| 3 | vault | preflight, resolve-for-run | Requested target/task field set → source category and readiness only, never secret values |
| 4 | config | collect, backup, plan, apply, rollback | Collection or typed update/reload/ACL/NTP intent, observations and recovery limits → native payload, remote state and protected artifact descriptors |
| 5 | health | gather, evaluate | health/interfaces/bgp/vlans/all, finite thresholds and expected state → nested facts and independent findings |
| 6 | compare | compare, remediation-preview, generate | Snapshot/result pairs, vendor/parser context and hashes → semantic diff or inspectable unexecuted intent |
| 7 | report | aggregate, render | Versioned outcomes, title, output kinds/root intent → coverage-preserving report and verified output descriptors |

### Version-1 contracts — PROPOSED in `netops/ansible/contracts.py`

| # | Type | Required fields and constraints |
|---|---|---|
| 1 | OperationRequest | `schema_version="1.0"`, UUID `operation_id`, allowlisted `operation`, `mode`, `scope`, `context`, `inputs[]`, nullable `plan_digest`, `output_intent`. Empty target scope is invalid for network operations, valid for offline reports. |
| 2 | Scope / Context | Scope: ordered unique `target_ids`, validated exclusions, positive `limit`. Context: `controller_id`, `route_digest`, source/mapping identity. Normalize host/port/vendor/transport from inventory, never trust an ID as authentication. |
| 3 | InputRef / OutputIntent | Input: `kind`, owned or explicitly selected `ref`, SHA256 `digest`. Output: `kinds[]`, `root_ref`, overwrite policy and explicit retention/Git effects. Credentials and NTP authentication values use private field references, not serialized bytes or hashes. |
| 4 | OperationPlan | Request identity, normalized targets/routes, input/registry/assets/controller digests, ordered typed effects, observations with provenance/freshness, concurrency/deadlines, output destinations and recovery scope. `plan_digest` hashes canonical nonsecret content. |
| 5 | Authorization | Private, opaque, in-memory one-use grant: random ID, session, plan/target/route/controller/input/observation bindings, approved effects/recovery, monotonic deadline. Excluded from JSON, repr, logs and persistence. |
| 6 | TargetOutcome / StepOutcome | ID, `status`, `attempted`, unapplied effects, compatible nested `native_payload`, `changed`, `remote_state`, findings/error references. Every selected target/step remains represented, including never dispatched work. |
| 7 | Finding | `check`, `category`, `severity`, `result=pass|alert|unknown|error`, nullable `reading`, threshold/expected value, vendor/parser and safe raw-source reference. Connectivity success is independent. |
| 8 | OperationOutcome | Schema/operation ID, requested/executed modes, readiness projections, targets/steps, aggregate status, changed, findings, artifacts, errors, cleanup and safe provenance. Large results use explicit chunk descriptors, never silent target truncation. |
| 9 | SafeError / CleanupOutcome | Error: category, named reason, stage, target/step ID, retryable, safe detail, next action. Cleanup: `succeeded|failed|not-requested`, owned remaining references and secondary errors. Preserve primary failures and remote uncertainty. |
| 10 | LoadedInputContext | `schema_version="1.0"`, request/context binding, ordered `contents: tuple[LoadedInput, ...]`, `observations: tuple[Observation, ...]`, `binding_digest`. Immutable runtime value, never an implicit loader or persisted credential channel. |
| 11 | LoadedInput / Observation | Input: exact InputRef identity/kind/digest, format (`json|yaml|text`), credential-free content (`bytes`), validated parser/vendor revision. Observation: ID, target/context/route/controller binding, source InputRef, content digest, UTC provenance and supplied age in milliseconds at hydration. Values contain no decrypted credentials. |

1. JSON accepts finite numbers only, bounded strings, duplicate-key rejection and schema validation before dispatch. Unknown effect-bearing request keys and unknown major versions fail. Optional additive response fields may be ignored.
2. Canonical digest: UTF-8 JSON, sorted object keys, compact separators, no NaN, deterministic normalized values. Preserve order of targets, commands and first-match groups. Exclude credentials and volatile display timestamps, include observation identity/time and policy/asset revisions.
3. Step/target statuses are `succeeded|failed|blocked|unsupported|cancelled|not-requested`. Aggregate may additionally be `partial`. Success requires every selected effect complete, health policy satisfied and cleanup clean.
4. Any completed selected work plus unsuccessful selected work is partial. Otherwise execution/rendering/policy/cleanup failure takes precedence, then cancellation, unsupported, blocked. Unselected work never affects success.
5. Companion exits: 0 complete success or successful truthful status query, 2 invalid input/schema, 3 dependency/platform/credentials/consent/precondition blocked, 4 partial, 5 execution/render/policy/cleanup failure, 6 unsupported, 130 cancellation without completion. Full outcome retains secondary causes.
6. Internal interactions are typed calls/events and fixed controller processes with framed JSON. Packaged YAML roles pass nonsecret intent and handles to a local action, not credential-bearing remote modules.

### Loaded-input hydration — PROPOSED, outside pure preview

1. CLI loads selected request/input files through checked read-only handles before logging/bootstrap. Textual hydrates its selected files or prior in-memory outcomes in a worker, then passes the immutable context. Python callers supply already-loaded values or explicitly call the same adapter. Proposed adapter in `netops/ansible/workflows.py`: `hydrate_inputs(request: OperationRequest, sources: Sequence[InputSource], clock: ClockPort) -> LoadedInputContext`; `InputSource` is an explicit checked file descriptor or immutable in-memory bytes plus provenance, not an arbitrary fetch URL. Expected read/schema failures raise `ContractError` with safe detail.
2. Hydration validates bounded content, duplicate keys/identities, source types, credential-free inventory/results and observation provenance. It computes SHA256 over the exact nonsecret bytes matching each InputRef, then `binding_digest` over canonical request/context/ref digests and observation identities/content/provenance/age. Sensitive exact recovery bytes stay in protected storage under execution consent, not this context, serialized requests or ordinary digest inputs.
3. `preview(request, loaded)` independently checks version, request/context binding, complete one-to-one input matches and recomputes content/binding digests in memory. No filesystem/clock/probe/event-effect calls. Invalid, extra, swapped or missing required content raises `ContractError` (`input-binding-invalid`), never silently falls back to a loader. No supplied observations is valid and yields unmet observation preconditions; malformed or mismatched supplied observations is invalid. Supplied age is planning information, never execution freshness authority.
4. Native preview receives the same context: loaded inventory/fragment for the extracted pure merge helper, text pairs for `diff_configs`, normalized findings for guarded generation/report mapping. It does not reopen refs. Execution independently revalidates current sources/observations and grant bindings before effects; a valid preview digest alone confers no consent. These contracts refine HLD §4.4–4.6, FR-010/013/017/029/030.

## 3. Component & code change map

| # | Component / area (folder) | Change | What & why | HLD ref | Requirement |
|---|---|---|---|---|---|
| 1 | Dispatch and Textual (`netops/`, `netops/tui/`) | modified | Add explicit setup/companion adapters, pure preview before logging and shared result/consent views | §4.1/4.4/4.5 | FR-008–015/032 |
| 2 | Dependency authority (`netops/dependencies/`, PROPOSED new folder) | new | Versioned registry, public-operation manifest, consuming-context probes, guided provisioners and qualification lock | §4.3/4.5 | FR-001–007/040/043/044 |
| 3 | Workflow/controller (`netops/ansible/`) | new + modified | Proposed contracts/workflows/controller/worker/credentials and local action plugin around existing engines | §4.2/4.4/6 | FR-010–015/021/022/033–036 |
| 4 | Discovery/inventory (`netops/inventory/`, `netops/core/`, `netops/ansible/`) | modified | Bound native discovery, pure merge preview and source-validated credential-free mapping/cache | §4.6 | FR-016–022/033 |
| 5 | Native operations/roles (`netops/collect/`, `netops/change/`, `netops/check/`, `netops/ansible/roles/`) | modified | Reuse collection/safe push, guarded typed role actions, nested facts and unavailable-reading validation | §4.6/4.7 | FR-023–028/034/036 |
| 6 | Analysis/generation (`netops/change/`, `netops/playbooks/`, `netops/parsers/`, `netops/templates/`) | modified | Native semantic diff and guarded deterministic intent, preserve canonical vendor ownership | §4.6 | FR-029/030/035 |
| 7 | Reports/artifacts (`netops/report/`, `netops/ansible/`) | modified + new | Repair native CLI dispatch, safe report mapping and PROPOSED artifacts boundary with atomic protection | §4.5/4.6/6 | FR-024/031–036 |
| 8 | Installation/packaging (`install.ps1`, `install.sh`, `pyproject.toml`) | modified | Consume dependency authority, replace destructive in-place updates, include installed assets | §4.3/9 | FR-001–007/039/044 |
| 9 | Tests/scenarios (`tests/`, `netops/ansible/roles/`, PROPOSED `netops/ansible/molecule/`) | modified + new | Service-free units, stateful integration, both real Molecule lifecycles and installed-artifact proof | §10 | FR-037–042 |
| 10 | Delivery/docs (`.github/workflows/`, `scripts/`, `docs/`, `examples/ansible/`) | modified | Preserve existing gates, add qualification/drift checks and runnable examples, defer real media to prerelease | §8/10 | FR-040–045 |

### Load-bearing NEW service contracts — all PROPOSED

1. Types are frozen dataclasses/TypedDicts and string enums on Python ≥3.9, with typed `Protocol` ports and constructor injection. No explicit `Any`, new lint suppressions, TUI dependency in base CLI or parallel native engine. Dataclasses do not imply database or policy integration.
2. `WorkflowService` in `netops/ansible/workflows.py`, application composition layer:
   - `__init__(self, policy: PolicyPort, dependencies: DependencyPort, controller: ControllerPort, native: NativeWorkflowPort, artifacts: ArtifactPort, clock: ClockPort, events: EventPort) -> None`.
   - `catalog(self) -> CapabilityCatalog`: in-memory packaged operation descriptors, required prerequisites and supplied readiness. No installs, vault unlock or production probes.
   - `preview(self, request: OperationRequest, loaded: LoadedInputContext) -> OperationPlan`: validated immutable content/observations only (§2). No I/O through injected effect ports or clock, absent observations listed as preconditions. Invalid input raises `ContractError` only, caught at public adapters.
   - `execute(self, request: OperationRequest, authorization: Authorization | None = None) -> OperationOutcome`: validates current context before effects, consumes grant atomically, never auto-installs dependencies. Operational errors return safe outcomes, including cancellation and cleanup.
   - `cancel(self, operation_id: str) -> CancelReceipt`: thread-safe event signal, idempotent, receipt has `accepted`, safe reason and monotonic receipt time. Unknown ID returns not-running, never kills an unrelated process.
3. `PolicyPort`, PROPOSED decision boundary declared alongside workflow contracts:
   - `decide(self, event: DecisionEvent, facts: DecisionFacts) -> DecisionResult`.
   - `authorize(self, plan: OperationPlan, consent: ConsentReceipt) -> Authorization`.
   - Decisions/events match HLD `DependencyObserved/InstallConsented/StepCompleted`, `OperationRequested/Observed/ApplyConsented/Cancelled`, `CandidateVerified/Activated`.
   - Pure rules decide selection, mode/effects, aggregation, consent and activation. Python adapters perform I/O only. Actual PX binding and persistence applicability must be reconciled (§Open questions) before implementing this port. No permissive Python fallback is specified.
4. `DependencyService` in PROPOSED `netops/dependencies/service.py`, application layer:
   - `__init__(self, registry: DependencyRegistry, adapters: Mapping[str, DependencyAdapter], state: OwnedStatePort, policy: PolicyPort, clock: ClockPort, events: EventPort) -> None`.
   - `catalog(self) -> DependencyCatalog`, `plan(self, scope: InstallScope, context: InstallContext) -> InstallPlan`.
   - `provision(self, plan: InstallPlan, consent: InstallConsent, cancel: CancelPort) -> InstallOutcome`.
   - `verify(self, scope: InstallScope, context: InstallContext) -> ReadinessReport`, `resume(self, install_id: str, consent: InstallConsent, cancel: CancelPort) -> InstallOutcome`, `uninstall(self, plan: UninstallPlan, consent: InstallConsent) -> InstallOutcome`.
   - `plan_restore(self, generation_id: str, context: InstallContext) -> RestorePlan`; `restore(self, plan: RestorePlan, consent: InstallConsent, cancel: CancelPort) -> InstallOutcome`. Both are **NEW proposed** methods, with selection, pre/postconditions and errors in §16. Planning probes read-only, restore changes only the owned pointer, never reprovisions or rolls back devices.
   - Planning/verification probe consuming contexts without mutation or production connections. Provision/resume require fresh plan consent and separate consequential grants. Unknown state/ownership blocks mutation, never adoption by directory existence.
5. `DependencyAdapter` in PROPOSED `netops/dependencies/adapters.py`, infrastructure `Protocol`:
   - `probe(self, entry: DependencyEntry, context: InstallContext, deadline: float) -> ProbeResult`.
   - `provision(self, step: InstallStep, consent: InstallConsent, cancel: CancelPort) -> StepResult`.
   - `cleanup(self, resources: Sequence[OwnedResource]) -> CleanupOutcome`.
   - Fixed adapter IDs, structured arguments, bounded effects and owning manifests. No registry-provided shell commands. Expected network/process/permission failures return categorized errors.
6. `ControllerLauncher` in PROPOSED `netops/ansible/controller.py`, implements `ControllerPort`:
   - `__init__(self, processes: ProcessPort, credentials: CredentialPort, state: OwnedStatePort, clock: ClockPort, events: EventPort) -> None`.
   - `verify(self, context: ControllerContext) -> ControllerReadiness`.
   - `run(self, request: ControllerRequest, credentials: ScopedCredentials, cancel: CancelPort) -> OperationOutcome`.
   - Fixed qualified interpreter/WSL executable, no shell, allowlisted environment, one operation-owned process group. Frame validation precedes any dispatch. Never return secrets/raw process dumps.
7. `ScopedCredentialResolver` in PROPOSED `netops/ansible/credentials.py`, infrastructure:
   - `__init__(self, vault: CredentialVault, routes: RoutePolicyPort, clock: ClockPort) -> None`.
   - `resolve(self, scope: CredentialScope, session: UnlockSession) -> ScopedCredentials`.
   - `revoke(self, operation_id: str) -> None`; repeat revocation is safe.
   - Resolve only allowed target/task fields, preserving native precedence. `UnlockSession` stays host-side. Locked/missing/wrong-password are distinct safe errors. Returned credentials are private, nonserializable except the protected frame.
8. `ArtifactStore` in PROPOSED `netops/ansible/artifacts.py`, implements `ArtifactPort` and shared owned-state boundary:
   - `__init__(self, filesystem: ProtectedFilesystemPort, clock: ClockPort, events: EventPort) -> None`.
   - `publish(self, intent: OutputIntent, content: bytes, binding: ArtifactBinding) -> ArtifactDescriptor`.
   - `read(self, descriptor: ArtifactDescriptor, binding: ArtifactBinding) -> bytes`.
   - `cleanup(self, resources: Sequence[OwnedResource]) -> CleanupOutcome`.
   - Revalidate root/ownership/permissions and content digest at open/publication. No overwrite without intent, no sensitive publication under diagnostics root. Expected failures return `ArtifactError` to the caller for outcome mapping.
9. `NetopsWorkflowAction` is PROPOSED `ActionModule` in `netops/ansible/action_plugins/netops_workflow.py`, action adapter layer:
   - Ansible integration `run(self, tmp: str | None = None, task_vars: dict[str, object] | None = None) -> dict[str, object]`; subclass the qualified Ansible `ActionBase`, not a remote module.
   - Nonsecret typed intent/handle only. Check mode returns unexecuted in-memory result before resolver/session access. Approved action runs native engines in the action process and returns minimized safe outcome/facts.
   - Ansible plugin loader requirements and subprocess/fork behavior are tuple-qualified. Never call `_execute_module` with secrets or qualify arbitrary third-party playbooks from `no_log`.

### Supporting port and setup contracts — PROPOSED

| # | Port / value | Contract |
|---|---|---|
| 1 | ClockPort / CancelPort | `monotonic(self) -> float`, `utc_now(self) -> datetime`; `is_cancelled(self) -> bool`, `wait(self, timeout: float) -> bool`. Deadline comparisons use monotonic time, persisted UTC is display/provenance only. |
| 2 | EventPort | `emit(self, event: SafeEvent) -> None`. SafeEvent contains §12 dimensions and duration, never secret content. Preview uses only an in-memory sink. Sink failure becomes safe diagnostic error, never permission to skip security checks. |
| 3 | NativeWorkflowPort | `preview(self, request: OperationRequest, loaded: LoadedInputContext) -> OperationPlan`; `run(self, plan: OperationPlan, credentials: ScopedCredentials, cancel: CancelPort) -> OperationOutcome`. Preview validates/reuses supplied bytes without I/O; run composes existing owners and rejects unauthorized effects. |
| 4 | OwnedStatePort | `read(self, resource_id: str) -> OwnedRecord`; `compare_replace(self, resource_id: str, expected_revision: int, record: OwnedRecord) -> OwnedRecord`; `lock(self, resource_ids: Sequence[str], timeout: float) -> OwnedLock`. Context-managed lock releases on all exits, conflict is precondition failure. |
| 5 | ProtectedFilesystemPort | `validate(self, intent: OutputIntent) -> ProtectedRoot`; `publish(self, root: ProtectedRoot, content: bytes, binding: ArtifactBinding) -> ArtifactDescriptor`; `read(self, descriptor: ArtifactDescriptor) -> bytes`. Implement platform no-follow/ACL/atomic semantics in this infrastructure port, not separate unchecked workflow writes. |
| 6 | ProcessPort | `run(self, launch: FixedLaunch, private_input: bytes, cancel: CancelPort) -> ProcessResult`. FixedLaunch contains verified executable/structured nonsecret args/context/owned process group/deadline. ProcessResult exposes safe typed frames and exit/teardown, not arbitrary stdout dumps. |
| 7 | InstallPlan / InstallScope | Scope: `full-toolkit`, selected native capabilities, companions and enhanced selection. Plan: UUID/digest/context/registry revision/ordered steps/sources/owned destinations/reuse/effects/required grants/qualification limits/free-space estimate when known. |
| 8 | InstallConsent / InstallOutcome | Consent privately binds plan/context/effects and separately granted consequential categories. Outcome: schema/installation/plan IDs, selected scope, step statuses, native/companion/enhanced readiness, candidate/active/previous IDs, original errors, pending actions and cleanup. |
| 9 | ReadinessReport / CapabilityCatalog | Schema/revision/context, per-capability `ready|blocked|unsupported|not-requested`, observed versions/probe results/qualification evidence and safe next action. Native, companion and enhanced projections remain independent. |
| 10 | ContractError / CredentialError / ArtifactError | PROPOSED exceptions carry only `SafeError`. ContractError subclasses ValueError, others RuntimeError. Public execute boundaries translate them to outcomes; safe error fields, never native raw exceptions, may be logged. |
| 11 | RestorePlan | Version 1, UUID/plan digest, root/context, exact retained generation ID/content/qualification digest, expected active ID/revision, owned manifest digest, probe results, effect `restore-active-pointer`, cancellation scope. No automatic latest/previous selection at execution. |
| 12 | ControllerBudget / ControlPort | Version 1 frame fields `ready_nonce`, integer `authorization_remaining_ms` (1–300000), `operation_remaining_ms` (1–3600000), `control_timeout_ms=2000`. **NEW proposed** `ControlPort.request_dispatch(self, binding: DispatchBinding, cancel: CancelPort) -> DispatchPermit`, `revoke(self, operation_id: str) -> None`; private permits bind one task/target/effect and budget anchor (§5). |

1. `CredentialPort`, `ControllerPort`, `DependencyPort` and `ArtifactPort` expose the corresponding methods in §3, allowing service-free fakes. `RoutePolicyPort` exposes `validate(self, context: ControllerContext, scope: CredentialScope) -> RouteBinding`, with no network activity in preview.
2. All private values disable value-bearing repr/serialization and remain bounded by frame rules. Resource IDs refer to checked manifests, not caller-selected executable paths. Unknown port implementation or unqualified platform returns blocked.

### Existing owner integration details

1. `Inventory.from_file(path)` merges device over defaults and registers groups through `add`; `to_ansible()` provides host metadata. Dynamic `build_inventory(...)` checks existence but currently returns TTL cache before parsing, injects vault secrets then writes cache. Keep existing function parameters, remove injection from its export/cache path, validate source first and emit explicit legacy-cache diagnosis (§17).
2. `scan_subnet` returns reachable hosts only and materializes subnet hosts. Companion adapter must maintain the complete bounded selected address ledger, call native per-host discovery/helpers behind a bounded dispatcher and record ping/SSH/SNMP dispositions. Do not mistake omission for success or call an unbounded full-subnet engine.
3. Preserve `merge_inventory(existing_path, fragment)` semantics: new devices, fill only missing/None/unknown/empty fields and merge placeholder tag subkeys. Its existing file-loading/logging wrapper is not pure. Companion preview passes validated `LoadedInputContext` content to a **NEW proposed** extracted pure helper in that owner, with no reads/log writes. Detect duplicate hostname/address proposals before dict construction, show conflicts rather than silently overwrite.
4. `collect_config(ConnectionParams)` retains `host/device_type/collected_at/success/config/error` and successful `lines`. Raw configuration remains private in memory or explicitly sensitive storage; ordinary wrapper payloads are redacted and marked as such.
5. `run_push(..., commit=False, ...)` still snapshots remotely; never invoke it for companion preview. Extract shared snapshot/push/rollback responsibilities within `netops/change/push.py`, adding injected confirmation/cancel/artifact hooks without changing native defaults. Companion apply cannot use its current `changelog_path` raw write. Pre-state must be protected before first mutation, post-state checked before confirmation.
6. Cisco XR and Juniper recovery stay vendor-aware. Generic snapshot-line replay is not proof of safe OS-image recovery. Update/reload capability requires qualified boot-image/pre-state checks, confirmed recovery and explicitly approved image/route. Unsupported safety blocks apply, not a best-effort promise.
7. ACL intent includes ordered names/rules/interface/direction and expected prior state. NTP intent includes added/removed servers/source/timezone/sync policy, with authentication secret through the resolver. Existing role variables remain documented inputs, but companion roles must remove password-bearing module/debug/copy/shell paths in favor of typed local actions.
8. Health role currently asks facts for cpu/memory/ospf/empty strings and reads flat zero-default fields. Replace with supported nested `ansible_facts.netops`, health CPU/memory check results and native interface/BGP/VLAN payloads. Validate parser presence/finite values at shared check boundary before zero defaults, retain threshold and raw parsed provenance. Empty parsed output is unknown unless qualified observation proves genuine emptiness. OSPF explicitly returns unsupported.
9. `diff_configs(before, after, *, style=None)` and `DiffResult` own semantics. Validate vendor/style/input before calling permissive parsers. Remediation uses `generate_playbook(..., dry_run=True, include_pause=True)`, preserving guards and aliases. Normalize volatile UUID/time metadata in the companion adapter from input digest/observation time so identical inputs produce identical unexecuted artifacts.
10. `ReportGenerator.build_report/generate_html/generate_pdf` and `ReportSection/ReportData` remain owners. Add PROPOSED `generator.main(argv: list[str] | None = None) -> int`, input sections/outcomes and explicit output options, and return its status through dispatcher. Existing native report command has no working successful behavior to preserve. Companions add coverage/count/error sections rather than treating absent targets as healthy.
11. Report hardening uses explicit autoescape for `.html.j2`, safe JSON escaping, packaged trusted templates only by default, and a deny-network PDF URL fetcher. Render in memory then publish through ArtifactStore, not existing unchecked `_resolve_path` writes. Requested render can succeed while source aggregate stays non-success.
12. Use installed package resources for templates/roles/modules/actions/scenarios. New files named above are insertion proposals under verified owning folders, not preexisting assets.

## 4. Data Model, Data Storage, Data Queries

| # | Record / proposed schema | Storage/key/access | Fields, bounds and retention |
|---|---|---|---|
| 1 | DependencyRegistry v1 | Packaged `netops/dependencies/registry.json`, immutable ID/revision DAG, read-heavy | `schema_version`, `catalog_revision`, entries: ID/kind/consumers/edges/context/platform constraints/source/digest/probe/verify/provisioner/consent/recovery/ownership. Reject cycles, unknown adapters and omitted consumers. |
| 2 | PublicOperationManifest v1 | PROPOSED packaged `netops/dependencies/operations.json`, operation key, read-heavy | Entry point/module/export/UI action, capability IDs, native/companion/tier and selected optional intents. Include all exported toolkit functions, not just dispatcher commands. Drift check fails unregistered public operations. |
| 3 | QualificationLock v1 | PROPOSED packaged `qualification.json`, exact tuple key | OS/architecture/native/controller Python/core/Molecule/collection/asset/runtime/image/PDF/credential-route tuple, evidence digest, state. An empty qualified set means unqualified, not compatible-by-range. |
| 4 | InstallState v1 | Per-user `installs/<id>/state.json`, candidate/active/previous key, writes per step | Ownership token, file/directory manifest with content digests, plan/controller/registry digest, step states, original errors, pending consequential grant/reboot. ≤1 MiB metadata; referenced owned manifests handle larger payloads. No automatic TTL of active/previous resources. |
| 5 | ActivePointer v1 | `active.json`, atomic compare-and-replace | Environment ID/content digest/prior ID and state revision. One installation writer per root. Readers pin a generation for run lifetime; in-flight work does not switch controller. |
| 6 | InventoryCache v1 | Existing configured cache location, new envelope source/context/mapping key, read-heavy | Source canonical identity/content hash, schema/mapping/route/controller digest, created/expires, nonsecret groups/hostvars. TTL 300s, ≤16 MiB; larger mappings bypass cache without target loss. |
| 7 | OperationRecord v1 | Explicit `operations/<UUID>/outcome.json`, append steps then atomic terminal summary | Safe request/plan/outcome, source/controller/asset/registry provenance, artifacts and primary/cleanup errors. ≤1 MiB metadata; chunked results are integrity-bound. Default diagnostic TTL 7 days only if persistence selected. |
| 8 | ArtifactDescriptor v1 | Explicit output root + operation/target/kind identity | Ref, SHA256, size, media type, classification, permissions proof, retention, owning resource and input binding. Sensitive snapshot stores exact bytes separately, with explicit retention. Never diagnostic-purged. |

1. **PROPOSED user roots:** Linux `$XDG_DATA_HOME/netops-toolkit` or `~/.local/share/netops-toolkit`, macOS `~/Library/Application Support/netops-toolkit`, Windows `%LOCALAPPDATA%/netops-toolkit`. Host and WSL roots are distinct. PROPOSED `NETOPS_STATE_ROOT` accepts only an explicitly selected protected root. Keep existing inventory/vault/TUI/log paths separate.
2. Cache hostvar allowlist: host, effective port, network OS/connection, nonsecret vendor/transport/site/role and validated nonsecret tags. Strip credential identity/value fields, including `ansible_user` on companion exports. Reject credential-bearing free-form tags/source hostvars rather than treating an allowlisted container as safe. Never hash secrets to create cache or consent bindings.
3. Validate inventory mapping, types and source bytes before cache lookup. Cache hit requires all identity/context/schema/TTL fields to match. Malformed/missing source fails even with a valid cache. A concurrent source change between read and publish invalidates the candidate.
4. All owned records use strict versioned JSON, private parent directory, no-follow opens and same-filesystem atomic publication. Windows uses verified owner ACLs, Linux/macOS/WSL directory 0700 and private file 0600. Unsupported permission enforcement blocks sensitive storage.
5. Cross-process locks use OS file locking, PROPOSED install-root and per-output-root lock ports: POSIX `flock`, Windows file-handle lock. A diagnostic lock record is not the lock authority. No deleting a lock held by another process. Timeout returns blocked with owning operation reference.
6. Version/migration: reject unknown major and corrupt ownership state before mutation. Upgrade only known owned nonsecret schemas into a staged revision, retain previous metadata/pointer for revert. No secret dual-write, vault crypto migration or shared database. Legacy inventory caches are rejected on read and require explicit owned cleanup, never copied/reused/deleted implicitly.
7. Queries are local ID/manifest lookups and bounded TTL enumeration, no distributed partition/index/replication. Cleanup runs on explicit non-preview lifecycle/output intent, never catalog, status, check or background cron.

## 5. Detailed flows

:::mermaid
flowchart LR
    CLI["CLI Textual and Python"] --> Hydration["Explicit input hydration"]
    Hydration --> Workflow["WorkflowService"]
    Workflow --> Policy["PolicyPort"]
    Workflow --> Dependency["DependencyService"]
    Workflow --> Controller["ControllerLauncher"]
    Workflow --> Artifact["ArtifactStore"]
    Controller --> Worker["Fixed worker"]
    Worker --> Action["NetopsWorkflowAction"]
    Action --> Resolver["Scoped resolver"]
    Action --> Native["Native engines"]
    Native --> Target["Selected routed target"]
:::

:::mermaid
sequenceDiagram
    actor User
    participant Adapter as Surface input adapter
    participant Service as WorkflowService
    participant Policy as PolicyPort
    participant Launcher as ControllerLauncher
    participant Worker as Fixed worker
    participant Action as NetopsWorkflowAction
    participant Store as ArtifactStore
    participant Native as Native change owner
    User->>Adapter: Select request and source inputs
    Adapter->>Adapter: Read validate and bind content
    Adapter->>Service: preview request and loaded context
    Service->>Service: Recompute content and binding digests
    Service->>Policy: OperationRequested with supplied facts
    Policy-->>Service: Pure plan or missing preconditions
    Service-->>User: Plan without connections or writes
    User->>Service: Explicit observation and snapshot output
    Service->>Launcher: Resolve scoped credentials and launch
    Launcher->>Worker: Private bound credential frame
    Worker->>Action: Nonsecret observation intent
    Action->>Native: Read selected routed pre-state
    Native-->>Action: Exact observation
    Action->>Store: Publish protected snapshot
    Store-->>Service: Bound descriptor and observation
    User->>Service: Fresh apply and allowed recovery consent
    Service->>Policy: ApplyConsented for current digest
    Policy-->>Service: One-use grant
    Service->>Launcher: Authorized current plan
    Launcher->>Worker: New private scoped frame
    Worker->>Action: Revalidate grant and pre-state
    Action->>Native: Apply ordered typed effects
    alt Post-state and confirmation succeed
        Native-->>Action: Committed and confirmed
    else Failure after dispatch
        Action->>Native: Only approved vendor recovery
        Native-->>Action: Rolled back or uncertain
    end
    Worker-->>Service: Primary result and independent cleanup
    Service-->>User: Aggregate with findings and remote state
:::

:::mermaid
stateDiagram-v2
    [*] --> Planned
    Planned --> Blocked: Missing readiness or observation
    Planned --> AwaitingConsent: Valid effects
    AwaitingConsent --> Running: Fresh one use grant
    AwaitingConsent --> Cancelled: Declined
    Running --> Recovering: Approved recovery needed
    Running --> Finalizing: Complete or interrupted
    Recovering --> Finalizing: Recovery result
    Finalizing --> Succeeded: Complete and clean
    Finalizing --> Partial: Completed plus incomplete
    Finalizing --> Failed: Primary or cleanup failure
    Finalizing --> Cancelled: No completed work
    Blocked --> Planned: Explicit revalidation
    Succeeded --> [*]
    Partial --> [*]
    Failed --> [*]
    Cancelled --> [*]
:::

### Dependency and protected-controller algorithms

1. Dependency plan topologically resolves full toolkit scope with native/companion/enhanced projections. Probe installed context, show sources/sizes if known, reuse and exact destinations/effects. Download candidates only after consent, verify digests before extraction, provision into owned staging, re-probe actual functions, then atomically activate. Resume re-probes completed steps and recomputes plans after drift. Cleanup success never converts failed install into success.
2. Registry coverage includes native transport/crypto/YAML, Textual, SNMP, ping, selected backup Git, Jinja, WeasyPrint/native PDF libraries, controller Python/core/Molecule/tool executables, Galaxy collections, selected scenario driver/runtime/image and OS/WSL prerequisites. Existing backup shell utilities remain registered until role refactoring removes them. Native module/API exports, vendor checks, report mail/scheduler and other optional surfaces must appear in the public manifest with their existing prerequisites, not acquire invented service requirements.
3. Registry changes and `pyproject.toml` ranges are reviewed together; move `ansible.netcommon` from pip extras into Galaxy dependencies. Do not resolve arbitrary newest versions as qualified. Qualification locks bind resolved versions, assets, trusted sources and proof; no tuple is certified by this LLD.
4. Bootstrap installers may create an owned native candidate with selected user-local Python, then invoke the packaged dependency service. No pip post-install network hook. Remove existing `venv --clear` update behavior and curl-to-shell tool installation path in favor of verified registered bootstrap assets. Show full plan before additional effects and offer the same guided assistant on first run/dependency failure.
5. Linux/macOS fixed worker: managed absolute interpreter `-m netops.ansible.worker`. Windows: validated `wsl.exe --distribution <qualified-name> --exec <managed-linux-python> -m netops.ansible.worker`. No `bash -c`, translated secret path or implicit distribution install. Controller request contains only selected nonsecret data, not the host inventory/vault file.
6. Host sends 4-byte unsigned big-endian length then strict UTF-8 JSON frame, ≤1 MiB, once over private anonymous stdin/pipe. Fields: protocol version, operation/plan/controller binding, §3 ControllerBudget, allowed target/task field scopes and minimal credentials. Reject zero/oversize length, duplicate fields, malformed/truncated/trailing frames, expired bindings and unknown targets before sessions. Close input after frame; control/cancel uses a separate owned channel.
7. Worker starts a run-owned Unix socket under 0700 directory, 0600 socket, with 256-bit ephemeral authentication, operation/plan/target/task checks and expiry. Resolver responses use the same bounded framing and strict decoder. Do not publish socket authentication in state or outputs.
8. Worker launches a fixed controller-local action runner with auth only through an inherited private pipe. A nonsecret descriptor number may identify that pipe. Runner consumes it once before Ansible forks, closes descriptor and initializes a private credential-client object in memory. Forked owned actions inherit that client, not token-bearing variables. Spawn/non-inheritance tuples are unqualified until separately proven, not repaired with environment/files.
9. Runner invokes the pinned Ansible playbook entry point with packaged search paths, nonsecret inventory/intent, approved local action tasks and fixed callbacks. `NetopsWorkflowAction` resolves credentials only inside the approved action process and invokes native engines in-process. Remote module execution, async staging and arbitrary plugins are outside this protected contract.
10. Reconstruct controller-local bastion `direct-tcpip` routing using separately scoped credentials and approved host/port/key policy. Never transfer workstation SOCKS token/descriptors or call host `active_bastion()` as a pure preview probe: it contacts a service. Revalidate selected route, controller-local known hosts and key access. Companion strict host-key policy uses known keys and rejects untrusted/changed keys; explicit trust enrollment is a separately authorized setup effect, not native AutoAdd inheritance.
11. Cancellation sets dispatch-stop event immediately, revokes unused scopes and cooperatively signals owned runner/worker. Allow only already authorized bounded recovery, then terminate remaining owned process group after deadline. On WSL prove Linux process-group teardown, not merely Windows launcher exit. Socket/pipe/process teardown is independently checked.

### Cross-clock budget and host authority — PROPOSED

1. Absolute monotonic deadlines never leave their process. Host owns grant expiry from consent time and operation expiry from accepted execution, including all startup, queue and transit time. UTC is provenance only. Host watchdog runs independently of worker readiness; expiry atomically closes admission, revokes credentials/permits, sends revoke and begins bounded owned teardown. A startup timeout or grant expired before readiness sends no credential frame.
2. Worker sends a random ready nonce on the private control channel, recording its own monotonic `ready_start`. Host checks live consent and returns remaining budgets in integer milliseconds rounded down, bound to that nonce and plan. Worker sets deadlines to `ready_start + remaining_ms / 1000`, never receipt time. Thus the entire handshake transit is conservatively consumed, not granted again. Replayed nonce, zero/negative/out-of-range budget or a locally exhausted budget rejects before resolving credentials. Reconnect/retry never resets any deadline.
3. Before each credential resolution/new task or mutation, the action requests a one-use `DispatchPermit` through the worker and private host control channel. Worker records local request-start and conservatively anchors returned remaining budgets there too, clamped to original deadlines. Host checks its own deadline, cancellation, kill switch and exact effect bindings atomically before issuing a permit. Permits are revocable, not renewable consent or permission for an unbounded task.
4. Host expiry is authoritative even if the worker's clock origin differs. Control close, malformed response or no response within 2000ms stops admission, revokes local scopes and triggers owned teardown; a valid message cannot renew consent. Host watchdog handles a suspended/stalled worker or lost revoke acknowledgement. Already issued remote commands may complete or be uncertain, not retroactively undone; only separately preauthorized bounded recovery remains allowed.
5. Local elapsed timers and suspend/teardown behavior must be qualified per host/controller tuple. Arbitrary clock origins are supported without subtraction across clocks; unsupported elapsed-timer behavior blocks the tuple. Never use wall-time comparison or plaintext fallback. Deadline/control failure uses `deadline-exceeded`/`control-lost`, paired `consent.invalidated` and `cleanup.result` records with §12 dimensions. This refines HLD §6/7 and FR-015/021/036.

## 6. Dependencies

| # | Dependency boundary | Validation and degraded behavior |
|---|---|---|
| 1 | Package/tool/interpreter/collections | Actual consuming-context executable/version and functional smoke, assets/plugin discovery. Missing/incompatible leaves affected capability blocked and native unaffected; offer guided setup. |
| 2 | Download feeds/bootstrap/Galaxy | Allowlisted HTTPS origin, resolved lock/digest and safe archive extraction. Network denial preserves prior install. Offline previously verified assets may be reused only with matching consent/lock. No trust bypass. |
| 3 | WSL/OS/native PDF/runtime | Real command/permission and bounded functional render/lifecycle probes. Guided separate consent for elevation/features/VM/runtime/service/security/reboot. Decline/pending reboot is non-ready, never a successful partial full-toolkit install. |
| 4 | Vault/protected broker/route/key | Native unlock/precedence and tuple-qualified handoff. Failure blocks selected execution before dispatch, never plaintext/direct-route fallback. |
| 5 | Target device | Validate scope/vendor/transport/timeouts and qualified route. Preserve other independent selected outcomes but stop mutation dispatch after cancel or safety failure. |
| 6 | Local storage/Git/templates | Protect root/content/ownership, explicit Git intent and trusted template. Output failure retains successful observation and failure status, publishes no false descriptor. Selected Git failure is non-success, not silent downgrade. |
| 7 | PX/foundation/policy | Actual policy owner resolves binding/applicability before code. Absent port is blocked, not default allow; local approval is not external compliance proof. |

## 7. Scalability

1. Current entity/traffic baseline is unmeasured. Acceptance workload is 100 inventory records, 20 warm mapping previews and p95 ≤2s, excluding downloads/cold process startup. Do not advertise unsupported production throughput.
2. PROPOSED companion defaults: limit 100 selected addresses/targets, maximum 4096 per bounded request; ping concurrency 50, SNMP 10, SSH/backup 5, one mutation per target. Reject overscope before enumeration, exclusions before dispatch. Explicit higher bound up to 4096 requires plan regeneration.
3. Bounded dispatcher queues at most twice selected concurrency, avoids one future per address, stops new dispatch ≤2s after accepted cancellation. One operation worker per controller run, no persistent fleet resources. Larger workloads use explicitly separate scoped requests, never implicit scope expansion.
4. Cache ≤16 MiB, metadata ≤1 MiB and framed control/credential payload ≤1 MiB. Stream large native results into explicitly authorized integrity-bound artifacts; otherwise fail size preconditions rather than lose targets. Downloads stream with declared destination/free-space preflight.
5. Record process RSS, active processes, queue depth, output bytes and free disk during qualification at 100 and 4096 targets. Resource needs grow with concurrency and artifact bytes, not an unmeasured autoscaling promise.

## 8. Reliability & Redundancy

1. PROPOSED deadlines: dependency metadata/download attempts 60s/300s, controller startup 30s, credential/control requests 5s, device connect/command 30s, default operation 300s. Update/reload uses explicit qualified plan deadline, retaining existing reload wait input rather than treating 300s as universal. Ping uses bounded native timeout.
2. Retry idempotent feed metadata/download/probes at most twice, exponential 1s then 2s jitter bounded ±20%, within overall deadline. Retry reads only when qualified safe and scoped, one retry after 1s. No automatic apply/reload/rollback replay after lost acknowledgement.
3. Per-run transient-probe circuit opens after three consecutive transport failures for that dependency, reports next action and requires explicit revalidation. Credential/host-key/input/trust errors never retry. No cross-target cascade or automatic remote recovery without consent.
4. Root lock serializes provision/activate/restore/uninstall. Per-target mutation lock binds route/identity across CLI/TUI/API processes. Acquire multiple locks in normalized ID order; release on every exit. Busy returns blocked, not queued indefinitely. Grant consumption and cancel/dispatch decision are atomic.
5. Native and companion environments remain separate; pinned active generation protects running work from update. Retain known-good previous controller until explicit owned deletion. Controller loss yields uncertain state after dispatched mutation, not success from absence of an error frame.
6. Throttle by selected queue depth/concurrency; reject overload instead of raising target counts. Emit active/queued/attempt counts. A hung target times out independently, owned teardown failure remains visible and stops promotion.
7. Crash recovery reads owned checkpoint, re-probes, marks dispatched-but-unconfirmed mutation uncertain and never resumes mutation automatically. Installer resume creates fresh consent if effects/context changed. No TTL lock stealing, unowned cleanup or compensating production write.

## 9. Configuration & Flighting

All keys below are **PROPOSED** except the existing environment settings explicitly identified. New settings use strict version-1 `settings.json` under the protected user root, read-only snapshots per request. CLI/request overrides tuning, never safety or consent. Configuration writes are explicit setup/settings effects.

| # | Key | Type / default | Binding and validation | Safety/flight behavior |
|---|---|---|---|---|
| 1 | `ansible.enabled` | bool / false | Shared workflow dispatch, exact bool | Distinct kill switch for new companion runs, native unaffected |
| 2 | `ansible.mode` | enum / audit | audit or enforce | Audit permits preview/status and explicitly selected observations, blocks mutation; enforce still needs fresh consent |
| 3 | `ansible.enhanced` | bool / false | Request selection, qualified tier | Unselected container tier is not-requested, no runtime startup |
| 4 | `controller.id`, `controller.wsl_distribution` | optional string / null | Owned verified active ID, allowlisted qualified WSL name | No arbitrary executable, no native-Windows Ansible fallback |
| 5 | `NETOPS_STATE_ROOT` | optional path / platform root (§4) | ProtectedFilesystemPort, absolute approved root | No root/symlink escape or global/shared environment adoption |
| 6 | `inventory.cache_ttl_seconds` | int / 300 | 0–86400, source-bound cache | Zero disables caching; preview never refreshes |
| 7 | `diagnostics.retention_days` | int / 7 | 1–365, explicit persistence only | Never purges sensitive snapshots or user backups |
| 8 | `execution.target_limit` | int / 100 | 1–4096, regenerated plan | Scope/exclusions required, never implicitly broadened |
| 9 | `execution.ssh_concurrency`, `execution.ping_concurrency`, `execution.snmp_concurrency` | int / 5, 50, 10 | 1–50, 1–50, 1–10 | Enforced queue and cancellation bounds |
| 10 | `execution.timeout_seconds`, `controller.start_timeout_seconds` | int / 300, 30 | 1–3600, 1–120, update deadline explicit | Snapshot/grant freshness cannot be disabled |
| 11 | `authorization.ttl_seconds`, `observation.max_age_seconds` | int / 60, 60 | 1–300, monotonic expiry and current content recheck | Single-use bound consent, no stale replay |
| 12 | `backup.retention_count`, `backup.git` | int, bool / 10, false | Positive count and explicitly approved output effects | Exact sensitive output intent required, no implicit commit/prune |
| 13 | Health threshold input | float / native 80 CPU, 85 memory | finite 0–100; role-specific explicit 90 preserved | Inclusive alert, unknown never healthy |
| 14 | Existing `NETOPS_INVENTORY`, `NETOPS_VAULT`, `NETOPS_INVENTORY_CACHE`, `NETOPS_TUI_SETTINGS` | existing paths/defaults | Existing owners, separated state | Master-password environment is not forwarded or used by exports |
| 15 | Existing `NETOPS_LOG_DIR`, `NETOPS_LOG_SETTINGS` | existing paths/default INFO, 10 MiB | Existing logging owner, cap ≥1 KiB | Companion preview bypasses initialization/file writes |

1. ConfigInvalid emits paired metric/log (§12), returns blocked/invalid next action, does not silently replace malformed safety settings with enforce defaults. Preview reports it only in memory.
2. No repository-established cloud ring/feature-flag service exists. Local audit/off settings plus owned active-pointer promotion implement the HLD validation sequence (§16); these are not invented org-wide flights.
3. Packaged registry source/adapter IDs and qualification locks are not mutable user executable configuration. WSL or protected credential qualification changes invalidate active readiness.

## 10. Identities & Access Control

1. No new cloud identities or long-lived secrets. Reuse invoking local user and selected existing device credentials; ephemeral per-run resolver authentication is not persistent identity.
2. Controller runs unprivileged in separate user-owned environment. Production target scope is distinct from fixture identities/resources. Tests generate synthetic vaults/credentials/host keys and never read user vaults.
3. Explicit target/task credential scope, controller-local key references and least permitted commands/effects. Resolve bastion separately, never a command target. Do not copy vault/master password/private key across host/WSL.
4. Installing OS features/runtime, security grants or trusting host keys requires separate meaningful consent. Same-user/root/WSL-admin compromise is outside the promised boundary.

## 11. Security

| # | Threat / boundary | Protection and fail behavior |
|---|---|---|
| 1 | Untrusted JSON/inventory/device data | Strict shapes, bounded scope/frames, duplicate-key/type rejection, vendor/intent allowlist, no executable YAML/template/shell interpolation |
| 2 | Host → controller → Ansible credentials | Private framed pipes, owner socket, ephemeral scope/deadline authentication, fixed runner/fork qualification, no secret argv/env/variables/module staging/callbacks |
| 3 | Route/key substitution or host-key drift | Bound controller/route digest, strict known-host verification, no direct or weaker-protocol fallback, inaccessible keys block |
| 4 | Artifact/archive/path TOCTOU | No-follow owned handles, parent/ACL revalidation, containment, no traversal/link archive members, atomic publish, collision refusal unless authorized |
| 5 | Supply-chain replacement | Trusted HTTPS origins and recorded content locks/digests, safe extraction, pinned resolved assets and functional qualification, no curl-to-shell or global pip mutation |
| 6 | Snapshot/config/NTP-secret exposure | Private memory, separately protected exact recovery bytes, minimized ordinary summaries, credential references for auth keys, sentinel inspection and disclosed redaction limits |
| 7 | Report XSS/remote fetch | Explicit Jinja escaping for actual `.html.j2`, safe JSON, trusted templates, deny-network PDF fetcher, no device-supplied executable templates |
| 8 | Consent replay/overbroad cleanup | One-use atomic grants with freshness/effects bindings, owned-resource manifests and locks, no implicit remote recovery or unknown-resource deletion |

1. This is a threat-model delta at existing local-user/device boundaries, not a new management service. No HTTP management endpoint needs authentication.
2. Every external call in §6 uses typed validated adapters, bounded resilience (§8), paired boundary/failure records (§12), enabled/mode/tier gates and explicit consent for consequential effects.
3. Structured error construction strips raw exception/argv/stdout/config values before logging. Broker values and secret-bearing intent never participate in ordinary hashing, caching or reports. Python memory erasure and perfect pattern redaction are not guarantees.
4. Cancel/timeout/process loss revoke handles, close pipes/socket/sessions and verify owned cleanup. Security failures abort promotion even if other work succeeds.

## 12. Observability

PROPOSED metric identifiers are derived from safe structured records, not claims of an existing collector. Common dimensions `operation_id`, `step_id`, safe `target_id`, `context_id`, `mode`, `status`, `error_category`, `reason`, `retryable` match logs. Aggregate metrics drop operation/target IDs to avoid unbounded cardinality; corresponding logs retain correlation.

| # | Outcome | Metric identifier | Paired structured event |
|---|---|---|---|
| 1 | Dependency observed / failed | `netops.dependency.probe.count` | `dependency.probe` with capability/context/status/reason/duration |
| 2 | Installer step fired / rejected / failure | `netops.install.step.count` | `install.step` with effect/consent category/status/reason |
| 3 | Controller launch failure | `netops.controller.launch.count` | `controller.launch` with qualified tuple/context/status/reason |
| 4 | Operation fired / failure / policy alert | `netops.operation.step.count` | `operation.step` with operation/step/target/status/error category |
| 5 | Consent rejected / invalidated | `netops.consent.invalidated.count` | `consent.invalidated` with binding kind/reason, no grant material |
| 6 | ConfigInvalid | `netops.config.invalid.count` | `config.invalid` with key and safe reason, never raw value |
| 7 | Artifact publication failure | `netops.artifact.publish.count` | `artifact.publish` with kind/classification/status/reason/bytes |
| 8 | Cleanup failure / remote uncertainty | `netops.cleanup.result.count`, `netops.remote.uncertain.count` | `cleanup.result`, `operation.step` with same outcome dimensions |

1. Performance/load: PROPOSED `netops.preview.duration_seconds`, `netops.cancel.dispatch_stop_seconds`, `netops.boundary.duration_seconds`, `netops.dispatch.queue_depth`, `netops.dispatch.active`. Pair boundary duration/load records with safe event above.
2. Utilization: PROPOSED `netops.worker.rss_bytes`, `netops.worker.process_count`, `netops.artifact.bytes`, `netops.storage.free_bytes` with `controller.resource`/`artifact.publish` records during effectful qualification. No resource sampler in preview.
3. Existing `logging_setup.setup_logging`/`CappedFileHandler` is the bounded local destination. New safe event adapter emits structured JSON through it and optional explicitly selected diagnostic artifacts; no remote telemetry export. In-memory preview diagnostics only, no audit-file/bootstrap side effect.
4. Worker deadlines and accepted cancel receipts provide watchdog records. TUI displays selected-scope completeness, primary failure, cleanup and uncertainty, not a green banner from process exit alone.

## 13. Health

1. **Healthy:** selected capability probes/qualification current, selected work complete, required readings available and policy satisfied, cleanup clean. **Degraded:** native usable but selected companion/prerequisite/reading unavailable, or partial work. **Critical:** leaked sentinel/forbidden effect, unknown mutation state, unsafe ownership or failed protected teardown.
2. SLIs from §12: selected successes/selected attempts, selected failures by category, clean cleanup/owned teardowns, uncertain mutations, preview p95, cancel-to-stop maximum. No fleet uptime guarantee is introduced.
3. Automatable promotion alerts: any sentinel/forbidden effect or uncertainty → Critical and halt; any failed cleanup/qualification/native regression → halt; preview p95 >2s at acceptance workload or dispatch-stop >2s → halt. Dependency failure is actionable Degraded, never ignored for full selected scope.
4. Troubleshoot by safe operation/step ID: inspect outcome/errors and pinned tuple, compare source/controller/route/registry digests, check permissions/readiness, choose explicit guided resume or manual remote inspection for uncertainty. Do not dump raw frames, configs or environment. Remote rollback still requires its own current consent if not already approved.

## 14. Special Cloud Considerations

1. No cloud service or sovereign/air-gapped platform qualification is added. Local host/controller/target behavior is the contract, not a Public/Sovereign equivalence claim.
2. Restricted network environments can reuse explicitly approved verified offline artifacts. Missing package/collection/PDF/runtime dependencies remain actionable blocked readiness. No public mirror fallback or outbound report-resource fetch.
3. Actual Linux/macOS/Windows+WSL, route and lifecycle proof remains necessary on each advertised tuple; simulation and localhost fixtures do not certify special-cloud/vendor firmware.

## 15. Error handling & edge-case matrix

Define PROPOSED `OutcomeStatus`, `ErrorCategory`, `ReasonCode`, `Stage` constants in `contracts.py`; wire spellings below are stable v1 values, never raw exceptions.

| # | Failure mode | Detection | Behavior | Wire status / category / reason / stage | User impact |
|---|---|---|---|---|---|
| 1 | Bad input/schema/CIDR/effect | Strict decode/type/scope validation | Zero dispatch/write | failed / invalid-input / invalid-request / validate | Exit 2, correct request |
| 2 | Missing dependency/unqualified tuple | Functional probe/lock mismatch | Native preserved, assistant | blocked / dependency / dependency-not-ready / readiness | Exit 3, guided setup |
| 3 | Consequential consent declined/reboot pending | Grant/checkpoint | Preserve prior install, selected scope incomplete | blocked / platform / consent-required or reboot-pending / provision | Exit 3, scoped next step |
| 4 | Download/trust/permission/install failure | Digest/process/ACL result | Own partial cleanup, original failure retained | failed / dependency / provision-failed / provision | Exit 5, explicit resume |
| 5 | Locked/missing/wrong-password vault | Native error boundary | No secret return/session | blocked / credentials / vault-locked or vault-missing or vault-password-invalid / credentials | Exit 3, secure unlock |
| 6 | Bad frame/scope/expiry or inaccessible key | Decoder/broker/route preflight | Revoke and zero dispatch | blocked / credentials / handoff-invalid or credential-scope-invalid / controller | Exit 3, qualify secure path |
| 7 | Selected route unavailable/host-key drift | Controller-origin route check | No direct fallback | blocked / transport / route-unavailable or host-key-invalid / connect | Exit 3, repair approved route |
| 8 | Source invalid or legacy secret cache | Parse before cache | No stale reuse/copy/delete | failed / invalid-input / inventory-invalid or legacy-cache-rejected / inventory | Exit 2, fix source/explicit cleanup |
| 9 | Missing observation/stale/spent grant/lock busy | Digest/time/atomic lock | Block before mutation | blocked / precondition / observation-required or consent-stale or resource-busy / authorize | Exit 3, observe/replan |
| 10 | Unknown vendor/OSPF/unsafe recovery | Capability validation | Explicit unsupported, no apply | unsupported / unsupported-capability / operation-unsupported / validate | Exit 6, no invented support |
| 11 | Missing/malformed reading or alert | Typed check/threshold | Unknown/error or alert finding, never healthy zero | failed / policy / reading-unavailable or health-alert / evaluate | Exit 5, connectivity separate |
| 12 | Apply/confirm/rollback or acknowledgement failure | Native ordered record/post-state | Approved recovery only, preserve changed/uncertain | failed or partial / execution / apply-failed or remote-state-uncertain / apply or recover | Exit 5 or 4, inspect remote state |
| 13 | Render/output/remote-fetch/collision failure | Safe renderer/store | No false descriptor, retain source failures | failed / rendering / render-failed or output-rejected / render or publish | Exit 5, repair output intent |
| 14 | Cancel/timeout/process loss | Cancel event/deadline/worker exit | Stop dispatch, revoke, owned teardown | cancelled or partial / execution / cancelled or deadline-exceeded / dispatch | Exit 130, 4 or 5 by aggregate |
| 15 | Cleanup failure/corrupt ownership | Teardown/re-probe/manifest | Preserve primary error and unknown resources | failed or partial / cleanup / cleanup-failed or ownership-invalid / finalize | Non-success, explicit recovery |
| 16 | Loaded input missing/swapped/tampered | Pure digest/schema/provenance validation | No fallback read or effect | failed / invalid-input / input-binding-invalid / validate | Exit 2, explicitly hydrate corrected inputs |
| 17 | Control loss/expired budget | Host watchdog and worker-local bounds | Revoke, stop admission, owned teardown, preserve issued uncertainty | blocked or partial / credentials / control-lost or deadline-exceeded / controller | Non-success, fresh consent after safe inspection |
| 18 | Restore candidate corrupt/drifted/busy | Manifest/probe/root lock/CAS | Preserve pointer, no repair/download/delete | blocked / precondition / restore-candidate-invalid or consent-stale or resource-busy / activate | Exit 3, select verified retained generation and replan |

## 16. Rollout & Risk Controls

Validation phases are not permission to defer an area or ship partially qualified support. Local operator settings are the only declared flight mechanism; each promotion is a human action with exact candidate/qualification evidence.

| # | Phase | Bake / scope | Metrics and gates watched | Promote-if / abort-and-revert |
|---|---|---|---|---|
| 1 | Off/audit design-to-fixture | ≥24h and ≥20 warm previews, owned fixtures only | Zero connections/writes in previews, p95 ≤2s/100 records, no secrets, all contract/unit cases green | Promote only after protected handoff feasibility and native regressions green; abort on any forbidden effect, keep off |
| 2 | Explicit fixture observation | ≥24h, repeated seven-area daemon-free runs | Selected completion 100%, teardown success 100%, zero unknown-as-healthy, cancel dispatch-stop ≤2s | Promote with installed assets and complete default lifecycle proof; abort on any cleanup/readiness/parity failure |
| 3 | Consented controlled mutation | ≥48h, stateful update/ACL/NTP and recovery fixtures | Zero unauthorized effects/uncertainty/leaks, 100% pre-state/confirm/recovery assertions and failure-injection cases | Promote after all mutation negatives pass and independent review has zero high-severity defects; abort, disable dispatch and preserve evidence |
| 4 | Full tuple/tier qualification | ≥24h per actual platform/tier/route tuple | Native/platform cells 100%, both lifecycle tiers green, installed wheel/sdist and HTML/PDF proof, all NFR targets | Promote only with all approved scope complete; any missing resource/proof remains blocked, never simulated pass |
| 5 | Human-approved prerelease/release | ≥24h prerelease candidate observation | Final full gates/CI, drift/example checks and code-complete real media provenance | Release only through later authorized human process; relevant final change invalidates affected proof/media |

1. **Fast revert:** `netops setup restore --generation <retained-id> --json` plans, displays exact source/destination generations/probe results/effects and asks fresh interactive plan consent before restoring the pointer (§16 contract below). No redeploy; target ≤5 minutes excluding unavoidable issued remote recovery. Revert cannot undo device mutations.
2. **Distinct kill switch:** set `ansible.enabled=false`, checked at new dispatch and before each new mutation, target new-dispatch stop ≤2s. Does not abandon preauthorized in-flight recovery or disable native commands.
3. Audit mode is not relaxed security. Returning to audit blocks new mutations, preserves safe observation/diagnostics. Pointer revert and kill switch are separately available if one environment is corrupt.
4. §13 alerts plus §19 canary suite gate every promotion. Bake times are proposed operational validation minima, not measured production stability guarantees.

### Executable restore contract — all NEW PROPOSED

1. **Operator:** set the distinct `ansible.enabled=false` kill switch, then run `netops setup status --json` to list retained owned generation IDs/digests and pinned runs. Invoke `netops setup restore --generation <retained-id> --json`, inspect the computed RestorePlan and approve that exact plan through the existing secure consent port. Verify with `netops setup status --json`: active ID/digest matches selection, functional readiness passed, no new bad-generation pins. Keep dispatch off until qualification permits re-enable.
2. **Python:** `plan = dependencies.plan_restore(generation_id, context)` then `dependencies.restore(plan, fresh_install_consent, cancel)`. **Textual:** setup screen selects an explicitly listed retained generation, shows the identical plan and fresh consent prompt, calls those methods in a worker and displays outcome/readiness/cleanup. Decline performs no write. No hand-editing active.json, reusable yes flag or operation-mutation grant.
3. `plan_restore` requires a retained generation from owned state, resolves exact ID (not a moving alias), validates root/manifest/content/qualification digests and performs bounded read-only functional probes of the selected candidate. The broken current environment need not execute. Corrupt active-pointer/ownership metadata cannot be bypassed; report blocked for explicit owned-state recovery. Malformed ID raises `ContractError`; expected missing/corrupt/unqualified candidate yields a blocked RestorePlan with safe errors, never a restorable plan.
4. `restore` requires a valid plan and fresh one-use InstallConsent binding pointer effect, generation, digests/context and expected active revision. Acquire the root lock (busy is blocked), stop new generation admission and safely cancel owned old-generation work, preserving any authorized recovery. Recheck ownership/digests/qualification/probes under lock; CAS `active.json` against expected revision. Changed selection/pointer invalidates consent and requires replanning, never silently chooses another previous generation.
5. Cancellation before CAS leaves pointer unchanged; CAS is the linearization point. Cancellation after CAS reports the selected active ID and independent cleanup rather than switching back implicitly. Post-CAS verification failure keeps admission off and returns non-success; restoring another candidate requires a new plan/consent. Corrupt candidate never activates, repairs, downloads or deletes anything. Pinned runs never change controller mid-run. Expected faults return InstallOutcome with §15 errors, not raw exceptions.
6. Measure operator-confirmed restore to verified pointer/status within ≤5 minutes, without remote rollback or reinstall. Emit `install.step` / `netops.install.step.count` with effect `restore-active-pointer`, context/status/reason and duration, plus paired consent/cleanup failures. Root-lock timeout and bounded probes use §8 deadlines within this target; unavoidable already-issued remote recovery is separately disclosed. HLD §8/9, FR-044, AC-011/015.

## 17. Backward Compatibility & Migration

1. Preserve native default commands/exits/vault AES-GCM/PBKDF2 format/precedence, inventory defaults/group order, collection result names and module ordered `output`/joined `stdout`. New wrappers are additive and versioned.
2. **Intentional security break:** dynamic inventory no longer injects/decrypted-cache-exports credentials, even when legacy `--vault`/password environment supplied. Retain parameters for explicit safe deprecation guidance, diagnose old cache and point to scoped run resolver. Never re-enable insecure cache on revert.
3. Shared health correctness repair replaces false zero/healthy defaults with unavailable/error while preserving existing fields and real inclusive thresholds. Role/facts/docs/tests change together. Native report CLI repair adds a working entry point without renaming report APIs.
4. Remove pip collection confusion, preserve extras names and explain managed setup. Installed search paths/resources replace checkout paths. Migration is staged only for owned nonsecret install metadata; existing inventory/vault/settings/backups are not relocated or adopted implicitly.
5. Pure companion preview is stronger than native dry-run. Keep native semantics, explicitly document distinction instead of changing native push to silently become connection-free.

## 18. Deprecation

1. Retire dynamic-inventory credential injection and insecure cache reuse immediately with explicit guidance and negative tests. Do not extend a secret dual-write compatibility window.
2. Existing unsafe companion role credential/shell paths are replaced when typed local actions and installed lifecycle proof pass. Preserve native standalone module signatures, but do not advertise them as protected arbitrary-playbook credential paths.
3. No native engine/command, user vault, OS/WSL distribution or existing user artifact is deprecated by this feature.

## 19. Test plan / test seams

1. **PROPOSED seams:** injected clock/ID source, policy/consent port, process/WSL launcher, filesystem/permission/OS locks, package/network probes, credential resolver and event sink. Use fake ports for all unit I/O including loopback/subprocess launch. No unit service startup.
2. Existing constructions stay source-compatible: `DeviceConnection(params)`, `CredentialVault(vault_path=...)`, `ReportGenerator(template_path=..., output_dir=...)`. Optional extracted native hooks preserve defaults. Update affected mocks in `tests/test_change_push.py`, `test_change_rollback.py`, `test_change_plan.py`, `test_collect_config.py`, `test_backup.py`, `test_health.py`, `test_ansible.py`, `test_report.py`, `test_playbook_generator.py`, `test_jump_host.py`, `test_active_bastion.py`, `test_bastion_lifecycle.py` and TUI/integration tests when owner hooks change. No required constructor change to existing owners.
3. Add PROPOSED tests under existing `tests/` for dependency registry/provisioning, workflow contracts/consent/controller/artifacts and installed packages. Extend `tests/mock_ssh_server.py` only for integration: mutable config/image/ACL/NTP state, ordered command journal, host-key/auth/direct-tcpip and failure/cancel controls. Current fixed-response/mock password server does not qualify these capabilities.
4. PROPOSED packaged `netops/ansible/molecule/default` and `container`: actual selected qualified strategy executes dependency/setup/create, prepare, converge, applicable idempotence, verify, cleanup/destroy. Default owns stateful fixture listeners, no daemon. Container tier owns consented disposable targets with qualified runtime/image digest/driver/collection. No privileged daemon socket or unapproved runtime start.
5. Both tiers run the same seven-area behavioral matrix below and independent lifecycle failure tests. Backup idempotence checks content/retention, not timestamped file zero-change. A failing converge still invokes owned cleanup/destroy, reports both primary and teardown results. Unit YAML structure tests remain only structural proof.

| # | Test case / traceability | Type | Given / When / Then |
|---|---|---|---|
| 1 | T01 registry totality — FR-001/005/043, AC-001/014 | unit + installed | Given every dispatcher/module export/UI operation and extras/assets / build catalog / then all map to prerequisite IDs; new unregistered function, cycle, adapter or collection-as-pip fails drift |
| 2 | T02 full plan/consent — FR-002–004/006, AC-001 | unit + real provision | Given clean/partial host / plan full scope then accept only local changes / then sources/ownership/reuse shown, consequential steps separately blocked and native preserved |
| 3 | T03 provision/recovery — FR-003/005–007, AC-001/011 | integration | Given qualified local candidate / provision and re-probe then inject trust/download/permission/cancel faults / then actual functions verified or explicit non-success, original error survives cleanup/resume |
| 4 | T04 locks/activation — FR-007/036/044, AC-011 | integration concurrency | Given retained verified generation and two setup writers / race plan_restore/restore with activation/uninstall, corrupt candidate or cancel before/after CAS / then one writer, stale consent blocks, exact pointer outcome preserved, unknown/user resources untouched |
| 5 | T05 schema/surface parity — FR-008–011, AC-002 | unit + Textual | Given same mixed target request / CLI/TUI/API dispatch / then equal statuses/provenance/native payload order; unknown major/effect key rejected, additive response tolerated |
| 6 | T06 aggregation/exits — FR-011/012, AC-002 | unit | Given every selected status combination, alert/cleanup and unselected tier / aggregate / then exact §2 exits, partial preserved, cleanup cannot erase primary/uncertainty |
| 7 | T07 pure modes — FR-013/014, AC-003, NFR-001 | unit all operations | Given per-surface hydrated LoadedInputContext and absent/invalid/swapped content/observations / call preview(request, loaded) with all effect/clock spies / then valid pure plans or explicit preconditions, invalid binding raises ContractError and zero I/O |
| 8 | T08 scope/consent — FR-014/015/026, AC-003 | unit concurrency + integration | Given observation/grant / alter target/route/input/controller/time or race apply twice / then stale/spent blocked and exactly one permitted dispatch; installer grant cannot apply |
| 9 | T09 discovery bounds — FR-016, AC-004 | unit + protocol integration | Given selected/excluded addresses and reachable/auth-failed/unknown vendors / discover / then exact bounds/timeouts/dispositions and no excluded calls; real claimed ping/SNMP/SSH proof separate from mocks |
| 10 | T10 merge collision — FR-017, AC-004 | unit + integration | Given loaded inventory/fragment with duplicate names/addresses and manual/placeholder tags / preview(request, loaded) then explicit save / then conflict visible, digest mismatch rejected, no preview write, exact approved merge preserves manual values |
| 11 | T11 inventory load/cache — FR-018/019/033, AC-005 | real Ansible integration | Given installed source/groups/defaults / load export then corrupt/change/remove source/context/schema with cache / then correct hostvars or failure/invalidation, no secret cache reuse |
| 12 | T12 credential precedence — FR-020/033, AC-006 | unit | Given synthetic env/device/ordered groups/default vault / resolve / then first native match, locked/missing/wrong password distinct, no plaintext result/log/export |
| 13 | T13 secure handoff — FR-021/033/036, AC-006 | real worker/Ansible | Given private frame and independent clock origins / delay readiness/transit past host expiry, replay nonce or corrupt budgets/frame / then no dispatch, receipt never renews consent, qualified fork works and no secret argv/env/callback/staging/cache/socket-state |
| 14 | T14 routed controller — FR-022/040, AC-006/013 | actual platform integration | Given Linux/macOS/Windows→WSL with independent clocks, keys/bastion / slow-start, expire consent before receipt, lose control/revoke acknowledgement, cancel or change key / then host watchdog and local budgets stop admission, exact route and Linux owned teardown, no copy/direct fallback |
| 15 | T15 collect/backup — FR-023/024/034, AC-007 | both Molecule tiers | Given mutable config and approved sensitive output/retention/Git / collect and backup twice / then native schema/exact bytes/protection/content-retention and selected Git failures truthfully non-success |
| 16 | T16 config plans/effects — FR-025/026, AC-007 | unit + both tiers | Given supported update/reload/ACL/NTP intent / preview then authorized apply / then pre-state before dispatch, ordered real state changes/postchecks/confirmation and no unsupported recovery promise |
| 17 | T17 failure/recovery — FR-025/026/034/036, AC-007/011 | integration faults | Given staged pre-state / inject auth/precondition/apply/confirm/rollback/cancel failure / then only approved recovery, committed/confirmed/rolled-back/failed/uncertain truthful and primary preserved |
| 18 | T18 facts thresholds — FR-027/028, AC-008 | actual role/module/template | Given below/equal/above CPU/memory and interface/BGP/VLAN fixtures / gather/evaluate / then nested facts and inclusive alerts, missing/malformed/null never healthy zero, OSPF exit 6 |
| 19 | T19 semantic compare — FR-029/030, AC-009 | unit + both tiers | Given hydrated cisco/junos/flat text pairs and normalized generation findings / preview(request, loaded) / then native no-op/change semantics and guarded deterministic intent; swapped digest/malformed/vendor mismatch fails without reads |
| 20 | T20 guarded generation — FR-030, AC-009 | unit + installed | Given validated alert inputs / generate twice / then deterministic unexecuted intent, guards/pre/post/recovery remain, no collect/apply call, explicit output only |
| 21 | T21 report outputs — FR-031/032/035, AC-010 | installed HTML/PDF | Given alerts/errors/blocked/missing targets / native and companion render / then bytes/counts/coverage/hash correct only after publication, rendering does not erase source failure |
| 22 | T22 hostile outputs — FR-035, AC-010/011 | unit + actual permissions | Given malicious text/Jinja/URL/path/symlink/archive/collision / render/extract/publish / then escaping, no remote fetch/escape/unauthorized overwrite, no false descriptor |
| 23 | T23 protection/cleanup — FR-034–036/044, AC-011 | Windows ACL + POSIX/WSL | Given protected/unprotectable roots and owned/unowned resources / publish/cancel/crash/uninstall / then actual ACL/mode proof or apply blocked, only owned cleanup, snapshots/user state retained |
| 24 | T24 real lifecycles — FR-037/038, AC-012 | Molecule both tiers | Given qualified strategy/context / full lifecycle plus setup/create/converge/verify/destroy failures / then seven-area side effects asserted, cancellation teardown and independent cleanup results |
| 25 | T25 packaging/launch — FR-039/040/044, AC-013/015 | installed platform | Given built wheel and separately built sdist in clean outside-checkout roots / run CLI/TUI/API/inventory/actions/roles/templates/scenarios/examples / then no editable/PYTHONPATH reliance, actual launcher/recovery/uninstall |
| 26 | T26 unit isolation — FR-041, AC-013 | unit enforcement | Given unit selection / patch process/socket bind/connect/service starts to fail / then suite green with zero services; integration uses separately explicit markers/commands |
| 27 | T27 evidence/drift — FR-042/043, AC-014, NFR-005 | CI + independent review | Given exact build/spec/test mappings / run required gates and applicable revert controls / then 100% IDs/provenance, controls fail, stale evidence/docs/help/examples fail |
| 28 | T28 support/revert/media — FR-040/044/045, AC-011/015 | actual prerelease | Given full qualified build, retained candidate and corrupt current executable / invoke setup restore --generation exact-id with fresh consent via CLI/Python/Textual / then verified pointer/status ≤5min, no redeploy/device rollback, native preserved; corrupt candidate/consent/CAS faults block and media retains real provenance |
| 29 | T29 preview latency — NFR-002, AC-014 | load | Given ready dependencies and hydrated 100-record context / 20 warm preview(request, loaded) calls including digest validation on recorded hardware / then nearest-rank p95 ≤2s, hydration/download/cold start separately recorded and excluded, raw timings retained |
| 30 | T30 cancellation bound — NFR-003, AC-003/011 | concurrency/load | Given saturated queue/stalled fixtures and different host/worker clock origins / cancel, expire during startup/transit or lose control / then cancel dispatch-stop ≤2s, host-authoritative revoke/local budget never renewed by receipt, bounded teardown/issued uncertainty and real WSL proof |
| 31 | T31 native/platform regression — NFR-004, AC-002/013 | full regression + actual platform | Given native minimum/boundaries/TUI/controller supported cells / run entire applicable matrix / then 100% native and advertised cells pass, absent resource is blocked evidence |
| 32 | T32 safe boundary records — NFR-006, AC-001/002/011 | unit + integration | Given every external I/O/error/cancel/config boundary / execute faults / then paired safe dimensions/category/next action, no raw secret/error dump; preview only memory |
| 33 | T33 safety inspection — NFR-001, AC-003/006/011 | integration negative controls | Given sentinel credentials/config secrets and forbidden target spies / inspect outputs/argv/env/staging/owned paths / then zero forbidden effects/leaks, injected leak control fails |

6. Coverage: preserve configured 30% global baseline and existing wrapper omission, but require every new safety/consent/mode/aggregation/cleanup branch exercised and ≥80% line/branch coverage for new service code. Real wrapper/action lifecycle assertions compensate for wrapper coverage omission. All 45 FRs, 15 ACs and 6 NFRs above require exact source/test/evidence mapping; table IDs are proposed tests, not passed proof.
7. Final gates preserve `scripts/sync_version.py --check`, Ruff, mypy, full pytest/coverage, Python 3.14 TUI tests, build, pip-audit and strict MkDocs. Add installed wheel/sdist, daemon-free/enhanced Molecule, protocol/platform/permission and dependency/help/example drift qualification jobs. Existing Ubuntu-only CI and YAML tests are not evidence these gates passed.
8. Canary before every §16 promotion: T05–T08, T11–T18, T21–T25/T30/T33 green on that candidate/tuple, all relevant native regressions and complete lifecycle teardown. Release additionally requires T01–T33, final full suite and zero high-severity independent review findings.
9. Evidence binds code SHA, frozen spec/criteria, tuple/version/assets, exact commands/cwd/environment, exits/results, safe artifacts/digests and genuine CI job references. Source/spec/tuple change invalidates affected proof. No media now: capture actual built product only at code-complete immediately prerelease.

## Open questions

| # | Unresolved prerequisite | Owner / required resolution | Boundary |
|---|---|---|---|
| 1 | Genuine feature PX specification/tests, supported decision/event Python I/O binding and foundation applicability | Coordinator and governing-policy owner must reconcile actual `has_px_spec`, `uses_foundation`, `bypasses_foundation` obligations and bounded Python/Textual/local-state authorization. No implemented bridge or passing policy is asserted. | Implementation blocked; architecture/scope unchanged |
| 2 | Exact qualified interpreter/core/Molecule/collection/PDF/runtime/image/credential-route/platform tuples | Implementer and independent tester execute §19 on approved real resources and populate evidence-backed qualification lock. Feasibility failure blocks support, never permits plaintext fallback or drops an area/tier. | Readiness/support blocked for unqualified cells |
| 3 | Later native review/publication and pre-push policy applicability | Coordinator/framework owner resolves separately if that route is ever authorized. Present route is local-only, adapter parked/unvalidated/uninstalled; independent local review cannot claim native thread clearance. | No publication, Spec/task decomposition or implementation authorized here |

No unresolved product-scope decision remains. These are the HLD's retained external prerequisites, not permission for implementers to choose another architecture.
