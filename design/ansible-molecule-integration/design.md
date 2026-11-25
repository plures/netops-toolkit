# Ansible and Molecule Integration — High-Level Design

| Field | Value |
| --- | --- |
| Author(s) | NetOps Toolkit maintainers |
| Last Updated | 2026-11-05 |
| Requirements | [Approved Requirements](requirements.md) |

## 1. Executive Summary

Explicit Ansible companions reuse native engines through shared CLI, Textual and Python plans/outcomes. One full-toolkit dependency authority provisions an isolated user-local controller. Real daemon-free Molecule validation is default; optional container targets are separately qualified. Protected credentials and cancellation across Windows/WSL are the principal engineering risk.

## 2. Goals

This design addresses [G1–G4 and their success criteria](requirements.md#2-goals-and-success-criteria).

## 3. Non-Goals

The [Requirements non-goals](requirements.md#3-non-goals) apply unchanged; no functional area or required qualification is deferred.

## 4. Architecture and Behavior

### 4.1. Native engines, explicit companions

:::mermaid
flowchart LR
    User["Operator or Python caller"]
    subgraph Host["Toolkit user boundary"]
        Surface["CLI and Textual adapters"]
        Contract["Requests, plans and outcome adapters"]
        Registry["Dependency registry and provisioners"]
        Policy["Decision and authorization seam"]
        Vault["Native vault and scoped resolver"]
        Native["Existing native engines"]
        Store["Protected owned state and artifacts"]
    end
    subgraph Controller["Managed Linux or macOS controller, including WSL"]
        Worker["Fixed worker and private credential channel"]
        Ansible["Ansible workflows and local action adapter"]
        Molecule["Two Molecule target lifecycles"]
    end
    subgraph Targets["Explicit network boundary"]
        Devices["Selected devices via qualified direct or bastion route"]
        Fixtures["Owned stateful fixtures or optional container targets"]
    end
    User --> Surface
    Surface --> Contract
    User -->|"Python API"| Contract
    Contract --> Registry
    Contract --> Policy
    Contract --> Native
    Contract -->|"Nonsecret request and protected pipe"| Worker
    Vault -->|"Minimal run credentials"| Worker
    Worker --> Ansible
    Ansible -->|"Reuse engines locally"| Native
    Ansible --> Devices
    Molecule --> Fixtures
    Worker -->|"Safe outcomes"| Contract
    Contract -->|"Explicit authorized outputs"| Store
:::

Native commands stay usable without a controller. Companions compose fixed workflows around existing engines, not another inventory, vault, parser or safe-change implementation.

Linux/macOS launch the isolated controller directly; Windows launches qualified WSL. Verify routes, keys and reachability where sessions originate. Containers are test targets, never controllers.

Dependency selection, consent, mode, aggregation and activation decisions require genuine feature PX specification/tests before implementation. Python I/O adapters consume their effects. No existing Python-to-foundation bridge is asserted; §12 blocks implementation until binding/compliance is reconciled.

### 4.2. Components and bounded change map

**New** paths are proposals, not existing assets.

| Component | Responsibility and interface | Key files / reuse | Requirements |
| --- | --- | --- | --- |
| Public adapters | Discover all seven workflows; normalize input, display plans/results and collect scoped consent without separate business logic | `netops\__main__.py`, `netops\tui\__main__.py`; **new** `netops\ansible\cli.py`, `contracts.py`, `workflows.py` | FR-008–015 |
| Dependency authority | `catalog`, `plan`, `provision`, `verify`, `resume`, `uninstall`; graph and typed adapter dispatch | `pyproject.toml`; **new** `netops\dependencies\registry.json`, `service.py`, `adapters.py`, `qualification.json` | FR-001–007/043/044 |
| Controller boundary | Fixed-process launch, framed requests, scoped credentials, cancellation and ownership | `netops\core\bastion.py`, `vault.py`; **new** `netops\ansible\controller.py`, `worker.py`, `credentials.py`, `action_plugins\netops_workflow.py` | FR-021/022/033–036 |
| Discovery and inventory | Native discovery and canonical inventory mapping, credential-free source-bound cache | `netops\inventory\scan.py`, `netops\core\inventory.py`, `netops\ansible\dynamic_inventory.py` | FR-016–019/033 |
| Safe operations | Collection/backup, guarded changes, health/facts, comparison and generation adapters | `netops\collect\*`, `change\push.py`, `change\diff.py`, `check\*`, `playbooks\generator.py`; existing Ansible modules/roles | FR-023–030 |
| Reports and local artifacts | Outcome-to-report mapping, native dispatch repair, safe HTML/PDF and integrity publication | `netops\report\generator.py`, existing templates; **new** `netops\ansible\artifacts.py` | FR-031/032/034/035 |
| Qualification and delivery | Stateful fixtures, both actual lifecycle suites, installed-package tests, generated docs | `tests\mock_ssh_server.py`, `tests\INTEGRATION.md`, `examples\ansible\*`, role scenarios, `.github\workflows\ci.yml`, `docs.yml`; **new** packaged `netops\ansible\molecule\default` and `container` | FR-037–045 |

Policy events cover `DependencyObserved/InstallConsented/StepCompleted`, `OperationRequested/Observed/ApplyConsented/Cancelled` and `CandidateVerified/Activated`; typed effects feed I/O adapters. The actual PX/foundation binding remains prerequisite, not an invented engine/database or permissive fallback.

### 4.3. Full-toolkit dependency lifecycle

The versioned registry DAG has immutable IDs and a catalog revision. Entries contain kind, consumers/edges, host/controller context, platform/compatibility, trusted source, probe/verification/provisioner IDs, consent, recovery and ownership policy. Allowlisted adapters replace shell text; unknown IDs, cycles, missing consumers and incompatible constraints are errors.

Enumerate **every public toolkit function**, not just companions: base transport/crypto/YAML packages; Textual and SNMP; OS ping; selected Git-backed backup; Jinja HTML; WeasyPrint plus native PDF libraries; controller interpreter/core/Molecule and executables; Galaxy collections; required backup shell utilities; selected lifecycle strategy/runtime/image; platform/WSL prerequisites. A public-operation manifest links all entrypoints to registry capability IDs. Drift tests compare that manifest with dispatch/API/TUI exports, dependency metadata, installer consumption and generated help/docs.

Remove `ansible.netcommon` from pip requirements; install it through managed Galaxy. Controller Python is independent of native Python ≥3.9. Registry ranges permit resolution; evidence-backed qualification records alone authorize supported tuples. No version, PDF library, driver or image is qualified here.

`plan(scope=full-toolkit, enhanced=false)` discovers current host and controller state, then returns all steps with sources, sizes when known, destination/ownership, reuse, exact intended changes, qualification limits and consent requirements. Native, companion and enhanced readiness are separate projections. Unselected enhanced capabilities remain `not-requested`. Plain pip installation must not run privileged/network post-install hooks: the documented installation entrypoint and first-run/setup assistant proactively offer the full plan before operational use; dependency failure in an operation opens the same supported assistant, never an unrelated manual-install recipe.

Under plan consent, provision user-local prerequisites with defaults: isolated environments, registered packages/executables and collections. Stage a candidate, verify actual consuming executables/imports/assets, then activate it. Do not mutate global Python. Where no compatible user-local interpreter exists, the registered platform adapter provisions a qualified user-local interpreter; OS-only prerequisites enter guided consequential setup rather than being silently omitted.

Elevation, OS package/features, WSL distribution/VM setup, virtualization, runtime installation/service starts, reboot and security grants each need separate scoped consent. Existing WSL must pass execution/path/permissions/interpreter probes; guided WSL setup records pending reboot/resume state without assuming authorization. A declined step leaves selected scope non-success with exact next action and preserves usable native functions.

Checkpoints retain owned steps and original safe failures. Resume re-probes; stale plans need new consent. Rollback removes only unactivated owned partial resources. Verify real collection/tool invocation, PDF rendering, assets and requested runtime access, not imports/presence. Status never installs, unlocks the vault or contacts production.

### 4.4. Public request, plan and outcome contracts

Expose `netops setup {plan,apply,status,resume,uninstall}` for full-toolkit provisioning and `netops ansible <area> <operation>` for companions. Areas are `scan`, `inventory`, `vault`, `config`, `health`, `compare` and `report`; compare includes analyze/remediation-preview. Native spellings/defaults/exits remain unchanged. Textual provides the same capability catalog, setup assistant, plan/consent view, task status and per-target results, including disabled/unqualified reasons. Python exports `catalog()`, `preview(request)`, `execute(request, authorization=None)` and `cancel(operation_id)` through the workflow service; no HTTP endpoints are added.

Version-1 JSON shape, mirrored by Python types:

```json
{
  "schema_version": "1.0", "operation_id": "opaque-id",
  "operation": "config.apply", "mode": "apply",
  "scope": {"target_ids": ["fixture-router"], "exclusions": [], "limit": 1},
  "context": {"controller_id": "managed-candidate-id", "route_digest": "sha256"},
  "inputs": [{"kind": "validated-intent", "ref": "owned-ref", "digest": "sha256"}],
  "plan_digest": "sha256",
  "output_intent": {"kinds": ["sensitive-snapshot"], "root_ref": "approved-root"}
}
```

`OperationPlan` contains normalized targets/routes, input/registry/asset/controller digests, commands/effects, required observations/freshness, timeout/concurrency, local writes and recovery. Canonical serialization produces its digest. `Authorization` is a private in-memory one-use grant bound to that digest, caller session, targets/controller/route, observations, effects/recovery and expiry, not reusable `--yes` or user-asserted JSON permission. API automation supplies equally scoped consent.

`OperationOutcome` carries schema/operation ID, requested/executed mode, safe provenance, readiness, `targets[]`, `steps[]`, aggregate status, `changed`, findings, artifacts, errors and cleanup. Each step/target has `succeeded|failed|blocked|unsupported|cancelled|not-requested`, attempted/unapplied work and remote state (`unchanged|committed|confirmed|rolled-back|failed|uncertain`). Findings carry check/category/severity, reading/threshold/raw-source reference and `pass|alert|unknown|error`, independently of transport/execution status. Native payloads remain nested compatible data, not renamed fields.

Aggregate success requires all selected work complete and policy satisfied. Mixed completed/unsuccessful work is `partial`; otherwise use the terminal error class. Ignore unselected work. Health-policy failure remains non-success despite successful transport; cleanup never replaces primary failure or remote uncertainty.

| Companion CLI exit | When |
| --- | --- |
| 0 | Complete selected-scope success, or a successful status query that truthfully reports non-readiness |
| 2 | Invalid input, unknown major schema, malformed artifact or incompatible request |
| 3 | Dependency/platform qualification, credentials, consent or observation precondition blocks execution |
| 4 | Partial aggregate |
| 5 | Execution/rendering/health-policy failure, or cleanup failure after otherwise complete execution |
| 6 | Unsupported operation/check/vendor scope |
| 130 | Cancellation without completed selected work; mixed completion remains partial |

Stable error categories are `invalid-input`, `dependency`, `platform`, `credentials`, `transport`, `unsupported-capability`, `precondition`, `execution`, `policy`, `rendering`, `cleanup`. Each has safe detail, affected step/target, retryability and supported next action. For homogeneous incomplete outcomes, cancellation/unsupported/blocked/failure determine their matching exit; any actual execution failure takes failure precedence. Persist the full outcome so an exit cannot hide secondary failures.

Reject unknown major schemas; ignore additive optional response fields, but reject unknown effect-bearing request fields. Changed required shape/meaning needs a new major and adapter. Toolkit, asset, registry and schema versions are distinct.

### 4.5. Modes and local-state schemas

| Mode | Allowed effect | Enforcement |
| --- | --- | --- |
| Preview/check | In-memory validation/plan/result only; no device session, subprocess device probe, vault unlock, cache refresh, file/audit write, pruning or reload | Pure path before logging/bootstrap side effects; absent observations become preconditions, never healthy/unchanged proof |
| Observe | Bounded explicitly selected network reads | Target/route allowlist and timeouts; no local persistence unless output intent authorizes it |
| Local output | Explicit export/backup/render/remediation generation, with declared retention/Git effects | Separate output intent, protected paths and collision validation; generation is not apply |
| Apply/rollback | Plan-bound device mutation and only explicitly authorized recovery | Fresh single-use consent and pre-state validation immediately before dispatch |

The CLI configures persistent logging before delegation: validate companion preview/check before that setup. API/TUI likewise suppress preview audit/cache hooks. Empty module check results mean `not executed`, not observed health. Installer/status probing never inherits operational consent.

| Record / owner | Key and content | Retention and bounds |
| --- | --- | --- |
| Registry / package | Entry ID + catalog revision; typed dependency graph | Immutable per package; no secrets |
| Qualification lock / package | Exact OS/architecture/controller/core/Molecule/collections/assets/runtime/image/PDF tuple + evidence digest and qualified state | Revalidate affected tuple after changes; unsupported/unqualified is explicit |
| Managed installation state / user | Environment ID; ownership token, content manifest, candidate/active/previous, safe steps/errors and plan digest | User-local state root, restrictive permissions; preserve known-good until verified replacement; metadata target ≤1 MiB per install |
| Inventory cache / user | Schema + canonical source identity/content hash + mapping version + controller/path/route context digest; credential-free hostvars/groups | Default 300s TTL, validated source before cache lookup; bounded 16 MiB entry, oversize bypasses cache rather than silently truncating inventory |
| Operation record / user | Operation ID; safe request/plan/outcome and artifact descriptors | Only explicit/non-preview persistence; default 7-day owned diagnostic retention, configurable before writing; metadata ≤1 MiB, large results referenced/chunked |
| Sensitive snapshot / user | Operation/target/input digest, exact protected bytes, permission and retention classification | Separate explicit root/consent and retention; no default diagnostic purge of recovery evidence or user backups |

Use platform user-data roots, separate host/WSL paths and explicit mappings; no distributed collection is introduced. Secrets enter neither caches nor hash inputs. Bounds trigger errors or explicit streaming/bypass, never target loss. Versioned owned records use atomic replace/ownership checks; unknown state blocks mutation.

### 4.6. Seven concrete workflows

| Area and operations | Composition and concrete contract |
| --- | --- |
| Scan: `discover`, `inventory-preview`, `save` | Ansible-local task invokes native bounded ping/SNMP/SSH discovery with CIDR/host allowlist, exclusions, target/concurrency/time limits. Preserve discovered/unreachable/auth-failed/unknown-vendor distinctions. Normalize into canonical device proposals; preview duplicates/field precedence in memory, then separately authorize exact merge/export. WSL probes run from WSL, not assumed host-equivalent. |
| Inventory: `validate`, `export`, `refresh` | Reuse `Inventory.from_file` and `to_ansible`; retain explicit groups, metadata-derived groups, canonical per-device/default precedence and `_meta.hostvars`. Parse/validate source before any cache return. Split mapping from credential resolution; remove full credential-cache injection, cache only allowlisted nonsecret data and bind it to §4.5 identity. Legacy unversioned/secret-bearing caches are rejected and diagnosed without reuse/copy or silent deletion. |
| Vault: `preflight`, `resolve-for-run` | Resolve only requested target/task fields using native crypto/unlock and environment → device → first matching group → default precedence. Preserve locked/missing/wrong-password distinction. Preview cannot unlock; execution obtains a secure host-side session. Return source category/status, never credentials; handoff is §6, not an inventory export. |
| Config: `collect`, `backup`, `plan`, `apply`, `rollback` | Preserve native `host/device_type/collected_at/success/config/error`. Refactor backup/update/ACL/NTP role tasks to fixed typed actions sharing native collection, snapshot, safe-push and generation services. Exact backup bytes use sensitive output consent; redacted summaries are separate. Plans show vendor-supported commands/reload, confirm timers and recovery limits; unsupported safe recovery blocks promised apply. Preserve committed/confirmed/rolled-back/error distinctions and ordered `output` plus joined `stdout`. |
| Health: `gather`, `evaluate` | Reconcile module/role/template around nested `ansible_facts.netops` and supported `health/interfaces/bgp/vlans/all`. Map CPU/memory via health/native parsers, add no fictitious `cpu/memory/ospf` gather categories. Explicitly reject OSPF. Missing/malformed readings carry null utilization and unknown/error; retain raw-source/threshold provenance and inclusive `utilization >= threshold` alerts. Role assertions and report mapping consume that same normalized schema. |
| Compare/analyze: `compare`, `remediation-preview`, `generate` | Offline snapshots/results feed native semantic diff with input hashes/vendor/parser context. Invalid/vendor-mismatch/unsupported inputs fail explicitly. Native guarded generator produces deterministic inspectable unexecuted intent with dry-run default, pre/post checks and rollback intent. Persisting the generated artifact is explicit; collecting fresh inputs or applying it requires separate scope/consent. No parallel analyze engine. |
| Report: `aggregate`, `render` | Map all outcomes, including alerts/errors/blocked targets and incomplete coverage, into existing `ReportSection`/`ReportData`. Repair missing native `generator.main()` or its dispatcher together, preserving native API. HTML uses safe Jinja/template resolution; requested PDF additionally proves native rendering. Validate bytes before atomic output publication and then return path/hash; rendering success cannot override failed input operations. |

Declare backup retention/Git effects; test timestamped backups by content/retention, not zero change. Preserve exact protected rollback bytes separately from redacted summaries. Health adapters validate parser field presence before native zero defaults; repair the shared check boundary where needed.

### 4.7. End-to-end guarded configuration

:::mermaid
sequenceDiagram
    actor Operator
    participant UI as CLI Textual or API
    participant Service as Shared workflow service
    participant Vault as Native scoped resolver
    participant Worker as Managed controller
    participant Action as Fixed Ansible local action
    participant Device as Selected routed device
    Operator->>UI: Preview typed config intent and supplied observations
    UI->>Service: Pure preview request
    Service-->>UI: In-memory plan or missing-observation precondition
    Operator->>UI: Explicit observe scope and snapshot output intent
    UI->>Service: Observe request
    Service->>Vault: Resolve selected fields after secure unlock
    Vault-->>Service: In-memory scoped credentials
    Service->>Worker: Fixed launch and bounded private input frame
    Worker->>Action: Nonsecret request and run-scoped handle
    Action->>Device: Qualified route and read pre-state
    Device-->>Action: Observation
    Action-->>Service: Safe outcome and protected snapshot descriptor
    Service-->>UI: Target and context bound plan
    Operator->>UI: Fresh apply and permitted recovery consent
    UI->>Service: One-use bound authorization
    Service->>Worker: Validate current plan and observations
    Worker->>Action: Authorized fixed apply intent
    Action->>Device: Recheck preconditions and apply
    alt Apply and confirmation succeed
        Device-->>Action: Post-state and confirmation
        Action-->>Service: Committed and confirmed outcome
    else Failure or cancel after dispatch
        Action->>Device: Only preauthorized supported recovery
        Device-->>Action: Recovery result or unknown state
        Action-->>Service: Failure or partial with remote uncertainty
    end
    Worker-->>Service: Owned cleanup outcome and credential revocation
    Service-->>UI: Aggregate plus independent findings and cleanup
:::

Recheck freshness immediately before each mutation; target/route/context/input changes invalidate consent. Cancel stops new dispatch within the NFR bound; issued commands may complete. Protected snapshots precede apply or block it. Confirmation timeout uses only preauthorized vendor recovery.

:::mermaid
stateDiagram-v2
    [*] --> Planned
    Planned --> Blocked: Missing prerequisite or observation
    Planned --> AwaitingConsent: Valid effectful plan
    AwaitingConsent --> Running: Fresh scoped authorization
    AwaitingConsent --> Cancelled: Decline or cancel
    Running --> Recovering: Authorized recovery needed
    Running --> Finalizing: Completed or interrupted
    Recovering --> Finalizing: Recovery result recorded
    Finalizing --> Succeeded: Complete and clean
    Finalizing --> Partial: Completed plus incomplete work
    Finalizing --> Failed: Failed with no completed work
    Finalizing --> Cancelled: Cancelled with no completed work
    Blocked --> Planned: Explicit retry and revalidation
    Succeeded --> [*]
    Partial --> [*]
    Failed --> [*]
    Cancelled --> [*]
:::

`changed`, uncertainty and cleanup are orthogonal; retry cannot reuse spent consent.

## 5. Alternatives Considered

| Choice | Benefit / cost | Disposition |
| --- | --- | --- |
| Explicit companions versus peer/Ansible-primary backend | Reuses engines without making native availability controller-dependent; retains some orchestration overlap | Adopt [Decision 0001](../../docs/decisions/0001-ansible-integration-uses-explicit-companion-workflows.md); reject backend replacement because native defaults must remain authoritative. |
| Managed user-local Python versus container controller | Isolated versions and broad local access; Windows needs WSL qualification | Adopt [Decision 0002](../../docs/decisions/0002-ansible-companions-use-a-managed-per-user-python-controller.md); reject container controller as an unapproved runtime dependency and architecture substitution. |
| Two target tiers versus fixture-only or mandatory containers | Default avoids daemon setup; optional isolation adds a second real lifecycle to maintain | Adopt [Decision 0003](../../docs/decisions/0003-molecule-uses-daemon-free-defaults-with-an-opt-in-container-tier.md); neither eliminating enhanced coverage nor imposing it by default satisfies the selected experience. |
| Protected private frame plus controller-local resolver versus extra-vars/env/secret files | More adapter qualification work but avoids common secret persistence channels | Select the proposed protected path; reject plaintext transport shortcuts even if they simplify Ansible integration. |

## 6. Security and Privacy

Trust the local user/controller, not devices, inventory, plans, device text or returned artifacts. This does not defend against a compromised same-user process or host/WSL administrator. Validate supplied target IDs against canonical inventory and authorized targets/routes; identity strings are not authentication.

**Protected credential path is a required new capability, not an existing broker.** The host resolves minimal values and launches a fixed worker with structured argv and an allowlisted nonsecret environment. A private anonymous pipe/stdin carries a versioned length-prefixed UTF-8 frame, maximum 1 MiB, containing request binding, deadline, allowed targets/tasks and selected credentials. Reject oversized/truncated/duplicate/malformed frames before work. Windows uses fixed `wsl.exe --exec` invocation; no shell interpolation, mounted secret file, vault master password, general secret environment inheritance or copied key/vault is allowed.

The worker holds credentials in memory and starts a run-owned Unix socket in a mode-0700 directory with mode-0600 socket, per-run authentication and target/task/expiry checks. Authentication material reaches only its owned action process through a private inherited pipe, not argv/env. A fixed controller-local Ansible action invokes the native engine in-process using this resolver; it never puts credentials into Ansible variables, module arguments, fact caches, callback payloads or remote module staging. Packaged roles invoke that action with nonsecret typed intent/handles. No remote toolkit installation or secret-bearing async module execution is permitted.

Prove actual Ansible worker/fork/plugin discovery and descriptor inheritance on each tuple; otherwise block, never substitute module password arguments. Preserve existing module signatures; `no_log` alone cannot qualify arbitrary external playbooks as protected workflows.

At origin, explicitly selected environment credentials retain native precedence but are not forwarded wholesale. Private keys need a qualified controller-local arrangement and explicit authorization; inaccessible keys block rather than being silently copied. Host active bastion sockets are not portable descriptors: reconstruct controller-local `direct-tcpip` routing with approved nonsecret host/port/key policy and separately scoped bastion credentials. Never fall back to direct access, weaken host-key checks or treat the bastion as a command target. Close all sessions/sockets on every exit.

Validate typed CIDRs, target bounds, ports, vendors, thresholds, input digests and intent before invoking fixed executables. Reject shell interpolation, path traversal, unsafe symlinks/archive members, unauthorized overwrite and output-root escape in the actual host/WSL context. Use ownership-aware atomic artifact publication and validate Windows ACLs and Linux/WSL permissions. A credential-free cache allowlist must also reject secrets already embedded in source hostvars.

Ordinary outputs are minimized/redacted with coverage limitations disclosed; exact snapshots use separately consented sensitive storage. Never claim perfect secret detection or cryptographic erasure of Python memory. Report templates escape device data, forbid executable templates from device input and deny remote-resource fetches, including PDF URL fetching. Structured logs contain safe IDs/categories, not raw argv/stdout or secrets. Revoke handles and close pipes/sockets at deadline/completion/cancel; cleanup only owned resources and preserve requested evidence.

## 7. Failure Handling and Risks

| Failure / risk | Detection | Behavior / user-visible result |
| --- | --- | --- |
| Missing/wrong dependency, download/trust/permission failure | Consuming-context probe or provision result | Preserve native state; selected install scope is blocked/failed with guided resume and original safe error. |
| WSL/OS/runtime consequence declined or reboot pending | Separate consent/probe checkpoint | No silent setup/service/reboot; pending selected capabilities stay non-ready. |
| Protected handoff/route/key/host-key failure | Frame/socket/discovery and transport qualification | Block before device dispatch; never plaintext or direct-route fallback. |
| Malformed/missing source with a cache present | Source validation before cache lookup | Error, not stale success; reject legacy secret cache and guide owned cleanup. |
| Missing health readings or failed policy | Typed fact validation and threshold evaluation | Unknown/error or alert distinct from transport; non-success policy outcome. |
| Precondition drift, apply/confirm/rollback failure | Fresh observations and native ordered change record | Invalidate grant or authorized recovery only; partial/failed/uncertain state and manual next action. |
| Timeout/cancel, process loss or cleanup failure | Deadlines, process ownership and teardown verification | Stop dispatch, revoke credentials, preserve primary error and independent cleanup/remote uncertainty. |
| Render/path/permission/native PDF failure | Safe renderer and output integrity checks | No false output reference; prior target failures survive successful partial rendering. |
| Fixture fidelity or platform overclaim | Qualification matrix and real lifecycle/evidence checks | Unsupported/unqualified status; mocks never imply vendor certification. |

## 8. Observability, Qualification and Rollout

Use the existing structured logging boundary with safe `operation_id`, step, target ID, context ID, mode, status, duration, error category and retryability. Proposed event identifiers are `dependency.probe`, `install.step`, `controller.launch`, `operation.step`, `consent.invalidated`, `artifact.publish`, `cleanup.result`; pure preview emits only in-memory diagnostics. Never emit credential values, source secret environment, raw device configs or full process dumps.

Measure selected-scope readiness/completion, failures by category, preview latency, cancel-to-stop-dispatch latency and cleanup success from those records. Targets are the exact NFR-001–006 thresholds, not new availability claims: 100-record mapping p95 ≤2s over 20 warm runs on documented hardware; stop new dispatch ≤2s after accepted cancel; zero forbidden effects/sentinel leaks; complete criteria/evidence/native/platform coverage.

Rollout progresses from owned fixture observation to explicitly consented controlled mutation and full platform/tier qualification, then human-approved release. This is validation sequencing, not partial feature delivery. Do not advertise complete readiness until all seven areas and both supported tiers satisfy the contract. Runtime enhanced-tier selection stays optional and visibly not-requested when unselected.

Companion dispatch requires explicit selection and a verified active controller. A proposed user setting `ansible.enabled=false` blocks new companion runs without disabling native commands; it is a kill switch, not permission to abandon in-flight recovery. Activate a verified candidate via an atomic active-pointer change and retain the prior owned environment. Fast revert disables new companion dispatch/restores that pointer after safe cancellation; it does not undo remote mutations.

Uninstall verifies ownership manifests and scope before deleting managed resources. Preserve inventory/vaults/backups/unknown files, user settings and WSL distributions unless separately specifically authorized. Interrupted activation, corrupt manifests and failed uninstall must be recoverable without a native toolkit downgrade.

## 9. Backward Compatibility and Migration

Preserve native commands/defaults/exits, vault encryption/precedence, canonical inventory and collection schemas, report APIs and ordered module outputs. New outcome wrappers do not rewrite native data. The tightly coupled cache credential leak, health role/fact mismatch and report dispatch defect require corresponding source/tests/docs in the eventual implementation, not documentation-only claims.

Reject legacy caches on read; never dual-write secrets or silently copy/delete user caches. Migrate only known owned nonsecret installation state after version/ownership checks, retaining recovery metadata. Reject incompatible registry/schema/assets. Revert must disable/rebuild rather than re-enable secret-bearing caches.

Discover modules, action plugins, roles, scenarios, templates and examples through installed package resources with explicit Ansible search-path setup. Remove collection-as-pip confusion while preserving documented extras and providing the setup assistant. Package-data manifests and sdist inputs must include every required runtime asset. No checkout path or editable import is a runtime contract.

## 10. Validation and Documentation

First qualify protected frame → Ansible action → scoped SSH/bastion, especially Windows→WSL cancellation/staging; then controller tuples and native PDF rendering. Failed feasibility blocks support, never removes approved scope or authorizes shortcuts.

| Criteria / coverage | Proof required |
| --- | --- |
| AC-001; FR-001–007 | Hermetic graph/installer/probe/drift tests plus separately authorized real provisioning/re-probes, resume/decline/cancel/failure and native preservation. |
| AC-002/003; FR-008–015 | CLI/Textual/Python schema/status parity and all aggregate cases; spies prove zero connections/files/cache/audit effects in every preview; stale/spent/changed-context grants fail. |
| AC-004/005; FR-016–019/033 | Bounded discovery/merge, real claimed protocol probes, installed Ansible inventory loading, group/precedence/source/context invalidation and legacy secret-cache rejection. |
| AC-006; FR-020–022/033 | Synthetic vault precedence/unlock tests; actual protected handoff, malformed frames/auth/scope/expiry, Windows/WSL/bastion/key/host-key proof and sentinel inspection of argv/env/callback/cache/staging. |
| AC-007/011; FR-023–026/034/036/044 | Stateful role/module/native collection, exact backup/retention/modes and update/ACL/NTP state effects; ordered snapshot/apply/confirm/recovery; permission/cancel/cleanup/activation/uninstall failures. |
| AC-008/009; FR-027–030 | Real nested facts/role/template chain with below/equal/above/missing/malformed/unsupported cases; semantic no-op/change/vendor/input/generation guards, deterministic unexecuted remediation. |
| AC-010; FR-031/032/035 | Installed native/companion HTML/PDF bytes/hashes and mixed-outcome counts; template/library/path failures, escaping and remote-fetch denial. |
| AC-012; FR-037/038 | Both actual Molecule lifecycles with state/effect assertions, applicable idempotence and injected provision/converge/verify/cancel/cleanup/destroy failures. |
| AC-013/015; FR-039–041/044/045 | Wheel and separately built sdist installed outside checkout; all public entrypoints/assets/examples; actual Linux/macOS/native-Windows+WSL/platform/PDF/credential tuples and reversible activation. |
| AC-014; FR-042/043; NFR-001–006 | Independent criteria-derived tests, applicable failing revert/negative controls, measured targets, complete traceability, final full suite/all required gates/CI and zero high-severity review findings. |

Unit tests stub every network/service/subprocess boundary, including loopback; no service startup belongs there. Controlled integration alone owns bounded loopback listeners and state-rich SSH fixtures extending the existing harness. Default Molecule uses real dependency/setup/create, prepare, converge, applicable idempotence, verify, cleanup/destroy; owned fixtures model config state, threshold responses, auth/transport loss and rollback failure across seven areas. Verify effects, not directory existence or exit zero.

The optional container scenario uses an explicitly selected qualified runtime, image digest and actual lifecycle collection/driver strategy; no blanket Docker/Podman/plugin assumption. It runs the same behavioral suite and separate create/destroy/failure checks. Containers host controlled targets only, without privileged daemon sockets or silently acquired grants. Timestamped backups assert content/retention invariants rather than artificial zero-change idempotence. Both suites verify owned teardown and report cleanup failure; mock personalities are not vendor firmware.

Build/inspect wheel and sdist, then install each in clean owned workspaces outside checkout without editable imports/PYTHONPATH. Prove native/companion CLI, TUI/API, dynamic inventory, modules/action plugins/roles/templates/scenarios/examples discover and run there. Execute actual Linux, macOS and native Windows launcher plus WSL, native minimum/boundaries and advertised TUI/controller tuples, PDF rendering, setup recovery and non-CI script exits. Missing approved resources is missing evidence, not simulated-platform qualification.

Independent tester/reviewer evidence binds exact code SHA, frozen spec/version/digest, worker/task, AC/test/source mapping, command/cwd/environment/versions, exit/results, safe artifact digests and actual GitHub Actions run/job links. Changed source/spec invalidates affected proof. Final gates include existing version-sync check, Ruff, mypy, full pytest suite, Python 3.14 TUI checks, build, pip-audit and strict MkDocs, plus required installed-artifact/Molecule/integration/platform gates. Existing Ubuntu CI is not evidence that these new gates/platforms already passed.

Update installation/platform/consent/recovery/uninstall guides; CLI/Textual/Python API/schema references; Ansible module/role/scenario examples and tutorials; native cache/health/report contract documentation. Generate dependency/help tables from the registry and fail drift checks. Installed secret-free examples default to owned fixtures, no production discovery/apply. Actual running-product media is captured only when code-complete immediately prerelease, with build/environment/doc provenance and refresh after relevant changes. No generated images or screenshots substitute for qualification.

## 12. Open Questions and External Prerequisites

No scope question remains; prerequisites do not waive gates:

| Unresolved prerequisite | Owner / required resolution | Boundary |
| --- | --- | --- |
| Actual feature PX/foundation binding and bounded compatibility exception | Coordinator with governing-policy owner: reconcile genuine PX spec/tests and truthful foundation use/no-bypass applicability; define the supported Python I/O adapter binding before source work. Direct-user compatibility authorization remains unapplied/execution-inactive. | Implementation blocked; no invented bridge or compliance claim. |
| Protected transport/platform/version qualification | Implementer and independent tester: execute §6/§10 on approved real resources and record exact supported tuples, PDF libraries and container lifecycle dependencies. | Support/readiness blocked for unqualified cells; full scope still required. |
| Review/publication transport and pre-push policy applicability | Coordinator/framework owner: approve an actual GitHub transport preserving required PR-thread findings and stage-review binding; resolve Python-equivalent versus cargo/clippy contract from governing source. | Independent PR-thread review/publication and later push blocked; local author self-check is not independent review. |
