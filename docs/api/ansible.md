# `netops.ansible` — Ansible Integration

## Consumer examples in the source distribution

`MANIFEST.in` explicitly selects these existing consumer examples for the
source distribution (sdist), beneath the extracted archive's
`examples/ansible/` directory:

- `collect_facts.yml`
- `inventory.yaml`
- `run_commands.yml`

Use that directory in the extracted sdist to obtain the sample files without a
repository checkout. These are source examples, not wheel-installed resources;
installing a wheel does not promise an `examples/ansible/` directory. Inclusion
does not establish controller readiness, example execution, artifact
authenticity or full Ansible/Molecule/platform qualification. Actual rebuilt
archive inclusion and outside-checkout verification remain separate tester
obligations. The matching source-example packaging contract is
`documentation/ansible/ansible-architecture.md`.

## Bound compare/report source checkpoint (O03/O04, not task acceptance)

The shared `WorkflowService.preview(request, loaded)` now invokes the native
semantic diff and guarded playbook owners against exactly bound immutable input,
and the pure report projector against versioned outcomes. Preview/check neither
renders nor emits output intents. Empty findings/outcomes produce explicit
`invalid-input` / `input-binding-invalid` preconditions, not healthy output or
misclassified stale consent. Missing observations remain unmet preconditions.

Compare checks paired parser/vendor identity and native syntax; generated YAML
is deterministic, dry-run guarded, human-reviewed **UNEXECUTED** intent.
The report projector retains selected/missing/blocked/unattempted coverage,
source status, findings/error categories, cleanup and uncertainty while omitting
raw native/configuration payloads. Successful native report publication retains
its factual descriptor/changed state without turning failed sources or source
cleanup into success.

The accepted eight-parameter constructor and S02 cancellation/backend completion
bindings are unchanged. A02's exact protected artifact publication remains the
only companion output boundary. The owned canonical `compare.generate` output selector now requests exactly
one `save`; the actual host publishes the reviewed bytes under original private
consent and protected-root locks, without device endpoint projection.
Empty offline report coverage and failed-source preservation remain factual
local-output behavior, not platform qualification. Fresh independent current-hash
acceptance is still required; this is not a completed O03/O04 claim or deferral.

For mixed generation, selected no-active-alert sources are `not-requested`,
unattempted and unchanged, never attributed another target's physical save.
An eligible saved plan plus this incomplete selected coverage remains `partial`
(exit 4), retaining the save descriptor, primary errors and secondary cleanup.
With no eligible plans, no empty output artifact is authorized. The strict
selected-success and public serializer contracts are unchanged.

See [report](https://github.com/plures/netops-toolkit/blob/main/documentation/report/report-architecture.md),
[comparison](https://github.com/plures/netops-toolkit/blob/main/documentation/change/change-architecture.md) and
[remediation](https://github.com/plures/netops-toolkit/blob/main/documentation/playbooks/playbooks-architecture.md) contracts.

Dynamic inventory script, custom modules, and Ansible roles for
netops-toolkit integration.

## Companion implementation boundaries

The following task-owned references describe the implemented increments and
their remaining integration/qualification boundaries:

- [Private admission](ansible-admission.md): operational and typed lifecycle
  consent, exact effect reservations, closed evidence and cancellation.
- [Protected artifacts and owned state](ansible-artifacts.md): publication,
  ownership checks, atomic state and platform-specific storage constraints.
- [Private credentials](ansible-credentials.md): scoped resolution and the
  host-admission bridge; not a new native connection engine.
- [Controller launch](ansible-controller.md) and
  [private controller protocol](../security/controller-protocol.md): fixed launch,
  exact dispatch/cancellation and remaining production composition boundaries.
- [Dependency registry and readiness](dependencies.md): read-only planning and
  consuming-context probes, with the limited I02 lifecycle increment below;
  not platform certification.

These are component contracts, not acceptance of the complete companion
feature. Memory-only lifecycle tests do not qualify real controllers, devices,
Molecule tiers, process-stop latency or native platform behavior. Closed host
observations and a policy allow are necessary inputs, not executable authority
or proof of a complete application composition root.

## I02 dependency lifecycle increment — incomplete product integration

The [closed bootstrap/layout source increment](dependencies.md#closed-bootstrap-contribution-and-separate-python-layouts-source-increment)
now connects `SetupMetadata.compose` to public setup and the managed lifecycle,
without mixing the qualified native-only producer into publisher archives.
Supported direct-host compilation retains distinct native and controller
Python installations and role-specific complete closures; the controller's
collections/libraries and actual action imports are consumed in its own path.
The managed production consumer selects that controller child while verifying
the full parent receipt/tree and retaining parent descriptor, pointer,
qualification, generation and context pins. A native descriptor is not
relabelled as controller authority, and a child root cannot bypass the parent
installation-root guard.
Typed existing publisher guest profiles return exact read-only `NeedsInput`
before metadata/effects where an actual qualified guest route is absent.
Native Windows is never substituted for a POSIX Ansible controller. This is
unverified source integration, not native/WSL, Ansible or Molecule qualification.

`DependencyService` now has `provision(plan, consent, cancel)`,
`resume(install_id, consent, cancel)`, `uninstall(plan, consent)`,
`plan_restore(generation_id, context)` and `restore(plan, consent, cancel)`.
The seven constructor arguments are unchanged. Read-only callers can retain
their ordinary state port. Effectful calls require the explicitly configured managed host (or the
separate accepted inert A02 compatibility host) on the actual `AuthorizationBroker`;
neither a nominal private value nor a mock broker becomes authority.

There are deliberately two distinct plan types: `DependencyService.plan` still
returns the I01 public `InstallPlan`. With a managed host it now contains an
exact closed lifecycle projection and explicit blockers. `review` and
`provision` accept that public plan and independently recompose it before
private admission; caller-supplied raw closed plans cannot bypass this boundary.
The inert compatibility path remains distinct.

The implemented service path validates the concrete lifecycle binding before
state I/O, evaluates packaged policy intents, spends actual private one-use
`InstallConsent`, consumes the lifecycle grant, and reserves/enters each ordered
occurrence through the real broker and owned handler. Root lock, checkpoints,
receipt reconciliation and pointer CAS remain A02-owned. Concurrent entry on the
same service returns `resource-busy`; root/CAS admission remains authoritative
across owners. Separate elevation/WSL/VM/reboot/runtime/security receipts remain
mandatory; generic installer assent cannot supply them.

`InstallOutcome` retains selected step dispositions, independent readiness,
candidate/actual-active/previous IDs, observed pointer revision, primary errors,
cleanup errors, pending actions, prior errors and uncertainty. Unknown pointer
state is not a fabricated old/new pointer. Staging-only completion is **partial**
with `dependency-not-ready` and `review-activation-plan`, not an installed/ready
claim. Cancellation revokes further entry; factual returned receipts survive
later cancellation or completion failure without reverse CAS. Resume requires
a different newly consented plan UUID for the same install UUID and re-probes.
Selected scope, context, consuming-context digests, exact generation binding and
baseline probe-report digest now have protected create-only/advance-CAS recovery
records. A fresh service can load those facts without `_plans` or `_contexts`.
Changed observations or consuming identities revoke the presented consent and
return `consent-stale`/`review-new-exact-plan` **before** dispatch or recovery
writes. Managed public replan/resume and digest-linked durable safe outcome
history are now connected; complete crash reconciliation is not. Grants are
never serialized/reconstructed, and partial metadata publication fails closed.

Activation/restore require fresh functional readiness whose report digest
matches a plan-bound `dependency-readiness` probe. A02's `inert-byte-probe` is
explicitly insufficient. Consequently the current inert A02 composition does
**not** provide product controller qualification. The separate managed path
provides factual terminal activation and qualified retained restore only when
the host supplies exact root-pinned qualification and owned run-pin ports. The
retained-plan reader is bounded/read-only and rejects malformed IDs, unowned or
corrupt metadata; it never executes the broken active generation, downloads a
replacement, repairs a candidate or undoes a device.

The metadata planner caps enumeration at 128 retained references and checks a
60-second elapsed-clock budget between metadata reads. Planning requires an exact
retained selected-scope record and a `dependency-readiness` verification digest;
inert probe records cannot pass. It runs **no** current-generation probe. This is not a measured
platform latency guarantee or preemption of a stalled host port.

The internal `_assets` acquisition primitive validates a separately reviewed
`LockedAsset` against the registered source family and the permit's exact source
descriptor/digest before entering a download. It permits credential-free,
TLS-verified, same-origin HTTPS only, bounded bytes and exact SHA256, at most two
idempotent transient retries (1/2-second jittered waits), and checks the lesser of
the original consent deadline and 300 seconds. The production body reader now
checks each bounded read (maximum 0.5-second blocking interval) and owns a joined watchdog that shuts down that exact
socket on cancellation/deadline; a slow byte stream cannot renew its budget.
DNS/connect/redirect setup still depends on the platform resolver/socket timeout,
so a hard whole-transport deadline is **not** claimed. Injected transport ports
must enforce their own in-flight bound.
Trust/hash/redirect failures do not
retry or relax validation. It returns factual bytes, **not** stage permission.
Its transport is faked in source-unit checks. It is connected to exact managed
multi-archive staging and factual completion, not real package installation.

The separate internal `_managed` increment defines
`i02-managed-generation-v1`, not `a02-owned-inert-v1`: a reviewed exact archive,
regular-file members (path, SHA256, size and owner-only executable mode), selected
scope/context and consuming identities. ZIP and bounded USTAR tar/tar.gz parsing
rejects traversal, Windows aliases/streams, case collisions, file/directory
collisions, extra/missing members, links/devices, special modes, encrypted ZIP
entries and PAX/GNU extension headers. No `extractall` or archive command is run.
Its `ManagedGenerationHandler` requires the actual private stage permit, the
same owned-state root on the broker, a distinct managed-root schema, exact source
and destination descriptors, root locking and revision CAS. It writes staging
intent before publication and staged facts only after exact tree reinspection;
completion is a separate one-use factual broker acknowledgement. A failed
private staging tree is retained, never recursively swept/adopted. The concrete
file port uses pinned no-follow protected handles and atomic no-replace
publication. This is source-level bounded **staging**, not interpreter/venv,
wheel relocation/dependency resolution, collection/runtime installation,
qualification or complete uninstall. The managed public flow dispatches this
handler through actual broker occurrences; the inert A02 path does not. Fake-port
controls are not actual ACL/POSIX/WSL qualification.

`install.step` carries `netops.install.step.count=1`, duration, kind, step kind,
status, stage, category, reason and next action in one helper with the matching
safe event. IDs/digests are log context, not counter labels. Sink failures do not
replace a primary outcome. Unexpected service failures use `stage=Unhandled`.
No URL, artifact bytes, credential, grant value or raw exception is logged.

### Bootstrap, recovery and uninstall status

The shell/PowerShell scripts no longer clear existing environments, execute
downloaded shell scripts, fetch an unverified release, acquire Python
automatically, overwrite existing docs or silently rewrite shell settings.
They require an installed interpreter, local exact hash lock and wheelhouse,
install wheels offline with no dependency fetching/source builds, and check the
installed dependency closure. They enumerate every packaged registry entry
rather than a fixed prerequisite subset. This is a catalog, not the missing
full proactive effect plan. Shortcut creation on Windows is separately opt-in.
The scripts exit 3 even after native bootstrap because full selected readiness
has not been established.

These script hardenings are **not yet** the managed protected-root/broker setup
composition. No actual installer exit, Windows ACL, POSIX/WSL protection,
platform timing or complete guided-consent behavior is qualified here.
Uninstall currently exercises only the accepted manifest-owned inert handler:
unknown/user resources and the prior pointer are preserved, but this is not
complete package/controller/WSL uninstall. Keep all active/previous resources;
there is no TTL purge, directory adoption, device undo or automatic repair.
The bounded managed source now connects durable finished-stage resume, root-pinned
retained metadata, admission draining and factual reducer completion. Real full
interpreter/wheel/collection/runtime installation, production qualification/run
pins, complete recovery/uninstall and later Q03 proofs remain required before
original I02 can be accepted. See [dependency API](dependencies.md#qualified-retained-planning-and-restore).

`WorkflowService.cancel` signals the exact composed launcher's private active
stop before broker revocation and receipt-clock reads. It changes no execute
authorization. See the [controller architecture](https://github.com/plures/netops-toolkit/blob/main/documentation/ansible-controller/ansible-controller-architecture.md)
for unfinished mutation, protected handback, installation-verifier and WSL/fork
qualification obligations; none is implied by the registry entries.

## A02 typed lifecycle host entry (inert owned effects; not full acceptance)

`netops.ansible.lifecycle_execution` exposes the original A02 typed host entry,
not an operation dispatched through `WorkflowService.execute`. Its four actual
exports are registered in the complete public operation catalog as `native.core`
with the **transitive PyYAML dependency** of the real A01 broker/workflow import.
Catalog presence is API discovery, not dependency installation, controller
readiness or platform qualification.

The public constructors and methods are:

- `OwnedLifecycleState(owned_state, facts_resource, owner, identity)` implements
  the actual A01 `LifecycleStatePort` over existing `OwnedStatePort` records,
  root-resource locking and CAS. `owner` is the exact ownership SHA256 and
  `identity` is the complete loaded `PolicyIdentity`.
- `LifecycleExecutor(authorization, state, clock)` requires the actual
  `AuthorizationBroker` and exact `OwnedLifecycleState` instance configured on
  that broker. `execute(plan, authorization)` accepts only a concrete typed
  `InstallPlan`, `UninstallPlan` or `RestorePlan` and its private
  `LifecycleAuthorization`. A grant for another kind or a merely nominal
  grant/permit is not authority.
- `LifecycleHandlerReceipt` records `binding`, `kind`, `result_digest`,
  `changed`, and an optional actual `(generation_id, revision)` pointer.
- `LifecycleRunResult` records ordered `receipts`, `pending`, `completed` and
  `uncertain`. A returned fact survives a later completion-checkpoint failure.
  `pending` describes reserved/entered work without acknowledged completion;
  it is not permission to retry.

Trusted bootstrap composes the existing typed constructors, without introducing
a factory, callback registry, request-JSON grant or new service constructor:

```python
state = OwnedLifecycleState(owned_state, facts_resource, owner_sha256, identity)
consent = TrustedLifecycleConsentAdapter(trusted_lifecycle_reviewer)
broker = AuthorizationBroker(
    current_operational_state,
    trusted_operational_consent,
    lifecycle_state=state,
    lifecycle_consent=consent,
)
owner = LifecycleExecutor(authorization=broker, state=state, clock=clock)
receipt = consent.review(plan, original_now, finite_duration)
grant = broker.issue_lifecycle(plan, receipt, actual_policy_intents, original_now)
result = owner.execute(plan, grant)
```

The classes come from `netops.ansible.lifecycle_execution` and
`netops.ansible.policy.authorization`. Inputs named `current_*`, `trusted_*`
and `actual_policy_intents` above are **host-owned ports/evidence**, not shipped
concrete application providers or caller assertions. The exact public call is
exercised for all seven symbols in
`tests/policy/test_lifecycle_execution.py::test_original_a02_typed_host_entry_composes_real_admission_and_owned_io`:
real packaged policy intent, trusted review, broker consume/reserve/entry,
owned pending receipt, fixed handler, owned result/CAS and factual completion.
These unprivileged owned-file fixtures do not qualify the native protected
filesystem backend.

`actual_policy_intents` must retain the real loaded evaluator's decision,
reason, rule IDs and policy identity and exactly match the reviewed ordered
occurrences. A contract-permitted executable-intent projection may discard the
factual `record_outcome` action; it must never invent `allow`, add an effect,
discard denial/revocation or replace the policy client. A policy allow alone
cannot mint consent or a grant. Each consequential category requires its own
exact private receipt. Original review deadlines are never renewed.

### Current owned facts and exact effects

The host must independently collect and own the source records before composing
this entry. Persisting a caller's projection under an owned filename does not
establish trustworthy facts. Every snapshot rereads the exact record kind,
owner, complete policy/reducer identity, closed schema and checked revision.
The `a02-owned-inert-v1` facts checkpoint references the current root manifest,
generation records, ordered step records, pin records and verification record;
it also holds explicit registry/qualification/context digests, setup/cancel
flags and the explicit pointer. Missing/corrupt state never means virgin
absence. Generation/source content and manifest digests are recomputed from
the current actual owned bytes, rather than filled from the plan.

Verification additionally requires the current successful `inert-byte-probe`
result digest to equal the measured generation bytes. This is deliberately
**not** a functional controller probe. Source records, owned reservations,
reviewer and qualification facts remain trusted application-bootstrap
obligations; no concrete managed-controller collector is claimed.

Only the seven exact frozen symbols select handlers:

| Symbol | Actual effect in this adapter |
| --- | --- |
| `dependency-probe` | Reread current owned evidence; no package/device mutation. |
| `dependency-download` | Copy exact already-owned inert bytes into an explicit owned reservation; no acquisition. |
| `dependency-stage` | Copy exact verified owned source/reuse bytes into that reservation. |
| `dependency-verify` | Measure current inert destination bytes against the bound generation digest. |
| `dependency-activate` | Perform actual A01 reviewed active-pointer revision CAS. |
| `dependency-uninstall` | Tombstone only the exact owned, currently unpinned inert artifact; never delete an OS path. |
| `restore-active-pointer` | Perform actual A01 reviewed retained-generation pointer CAS with current pins/probe evidence. |

Artifacts are bounded to 65,536 inert bytes. Neither “download” nor “stage”
executes them or invokes a package manager, network, elevated installer,
controller or device. A pending factual receipt precedes handler I/O; observed
receipts contain no consent, grant, session, permit or credential. Reopening
them cannot reconstruct admission. `enter(permit, binding)`, `complete(permit)`
and `reconcile(permit)` are private-host orchestration methods, not public
unauthorized handler fallbacks. Raw `OwnedLifecycleState` mutation methods are
trusted storage infrastructure, not an alternative admitted application API.

`cancel(plan)` revokes eligibility before any clock/revision allocation.
Late factual completion and reconciliation cannot restore dispatch. A pointer
CAS that already won remains the actual result after cancellation/lost
acknowledgement; no implicit reverse CAS is performed. Numeric exhaustion blocks
new effects without disabling cancellation or factual reconciliation.

Both frozen service constructors and their existing methods remain unchanged.
`DependencyService` still provides read-only catalog/planning/verification;
selecting `netops.ansible.lifecycle_execution:LifecycleExecutor` plans its real
PyYAML prerequisite and reports blocked readiness when that prerequisite is
missing, without writing owned state or consuming lifecycle admission.
This increment does **not** implement its designed I02 provision/resume/
uninstall/restore application flows, automatic acquisition or installer UI.
The separate operational `ExecutionHost` is not silently retrofitted with a
second broker. Full original A02 criteria, concrete bootstrap integration,
independent verification, real controller stop timing and platform/Molecule
qualification remain outstanding; no successor task is unlocked by this entry.

## Pure companion workflow planning (C01)

### A02 owned event recovery increment (partial)

When the actual A01 host broker is configured,
`WorkflowService.cancel(operation_id)` now revokes its actual private admission
before reading the acknowledgement clock. An uncomposed C01 planning-only
service still returns `accepted=False` / `dependency-not-ready`, without calling
unqualified host ports. A successful receipt
has `accepted=True`, reason `cancelled`, and the finite `received_at` time.
Invalid operation IDs never reach the broker. Repeated cancellation is
idempotent at the broker and allocates no numeric state revision. This receipt
acknowledges local revocation only: it does not claim controller teardown,
remote rollback, or that an already-issued command was recalled. A failing
receipt clock cannot undo revocation.

`netops.ansible.artifacts.OwnedPolicyJournal` is the explicit v1 owned checkpoint
adapter for factual local policy history:

```python
journal = OwnedPolicyJournal(owned_state, policy, current_binding, identity, owner)
first = journal.create(initial_state, first_event, first_facts)
receipt = journal.append(first.checkpoint_revision, next_event, next_facts)
recovered_state = journal.recover()
```

Supply the real loaded local policy engine and the existing `OwnedStatePort`.
The constructor's `PlanBinding` must come from the host's independently verified
current root, generation, plan, controller, route, input, observation, recovery
and policy identities. The journal does **not** collect those current facts,
reload sources or make caller-supplied bindings trustworthy.

Creation is explicit, starts from `Planned` revision zero and validates the first
event with the actual reducer before persisting a version-one `checkpoint`
record. It never treats a missing/corrupt record as a virgin checkpoint.
Checkpoint CAS revisions start at zero; policy revisions start at one after
the first accepted event. Their counters are distinct. Appends hold the existing
owned resource lock, replay and validate the complete prior history, compare the
expected checkpoint revision and perform one existing protected CAS. All data
remain subject to the existing one-MiB owned-record bound; exhaustion does not
silently truncate history.

Every read checks the exact owner, full policy identity/reducer, generation,
complete binding, closed event/fact/state schemas, ordered checkpoint counters
and reducer-derived state digests. It reconstructs state using the actual
reducer rather than trusting persisted summaries. An exact historical event
and identical source facts return the original `PolicyJournalReceipt` with
`duplicate=True`, without another CAS. Changed facts/content under the same
event ID, revision gaps, stale writers and malformed numeric counters reject
without changing owned bytes. The receipt contains factual state, event
identity/digest and checkpoint revision, **no executable effects or permit**.
It is not a serialized broker grant.

Recovery performs no effect or write. An unresolved invocation, or already
uncertain remote state, projects `Uncertain` with `remote_uncertain=True`.
Even apparently complete history never reconstructs consent, credentials,
sessions, pending broker invocations or dispatch eligibility. Current source
inspection and fresh specifically scoped consent remain mandatory before any
recovery effect. Cancellation reduction truthfully retains `Cancelling` until
separately verified completion/teardown, not an invented terminal success.

### A02 actual execute checkpoint (partial, not acceptance)

`WorkflowService.execute` now recognizes an explicitly constructed
`netops.ansible.execution.ExecutionHost` on its **existing `native` constructor
argument**. Uncomposed planning services still return dependency-not-ready;
no default native/controller adapter, ambient credential lookup or automatic
installation is introduced.

The concrete composition contract is:

```python
host = ExecutionHost(sources, owned_state, reviewer, effects, clock, owner_sha256)
service = WorkflowService(
    policy, host.authorization, dependencies, controller, host, artifacts, clock, events,
)
grant = host.review(service, request)
outcome = service.execute(request, grant)
```

`sources.reload(operation_id)` returns a fresh `ExecutionInputs` containing
`request`, `sources: tuple[InputSource, ...]`, `settings: SettingsSnapshot`,
`root_ref`, `generation`, `readiness: ReadinessProjection`,
`controller_qualified`, `route_qualified`, `credential_channel_qualified`, and
`cancelled=False`. **Only trusted application bootstrap supplies this port.**
It must independently reread current sources/settings/context and qualification
evidence; forwarding a caller's old projection is not a qualified implementation.
No concrete qualified application source reader is shipped by this checkpoint.

The host strictly decodes the current request, hydrates supplied current bytes,
binds current settings and runs the actual pure preview again. It repeats that
work at A01 issue/consume/permit/entry/completion snapshots, comparing the entire
binding (including observations, controller, concrete routes, policy, root and
generation). Only host-proven readiness and consent placeholders are discharged;
other preconditions remain binding. Disabled settings, stale requests/plans,
unqualified facts, exclusions and changed source bindings fail closed.
The host review uses the actual trusted consent adapter and actual A01 broker.
Each ordered occurrence must have its own matching real policy intent before
the host composes the exact broker decision; a policy allow alone is not consent.

Currently the fixed `scan`, `gather`, `collect`, `resolve-for-run`, `save`,
`export`, `render`, `refresh`, `backup`, `retention` and `git` dispatch entries
are implemented. The latter four still require combined policy/backend
integration verification; their presence alone does not establish readiness.
`EffectsBackend.scan(plan, effect, cancel)`, `EffectsBackend.gather(plan, effect, cancel)`,
`EffectsBackend.collect(plan, effect, cancel)`,
`EffectsBackend.resolve_for_run(plan, effect, cancel)` return
`EffectResult(step: StepOutcome, cleanup: CleanupOutcome = CleanupOutcome(),
artifacts: tuple[ArtifactDescriptor, ...] = ())`.
The step ID must equal `effect.occurrence_id`, and it must be selected and
attempted. The exact safe native payload, changed/remote-state fields, findings
and errors are retained. The final result includes every selected target and
step, including unattempted blocked work, and separates cleanup from primary
errors. No other effect name selects a callback or generic native fallback.
Private resolution stays on the bootstrap-injected private channel;
its public result must remain credential-free. This is a fixed dispatcher
entry, not a shipped concrete credential resolver.
Local operations retain their actual single occurrence even with an empty
target selection. Native entry without a result is attempted and uncertain
only for that occurrence; never-entered selected work stays blocked/unchanged.
A failed completion checkpoint retains an already returned factual native
result without contaminating subsequent targets with remote uncertainty.
`ExecutionHost.run(plan, credentials, cancel)` intentionally rejects bypass:
a native plan and credential object are not A01 admission.

Output execution requires the existing concrete `ArtifactStore` on the frozen
`artifacts` constructor seam. Read-only preflight validates current public input,
one explicit output kind and the protected destination before trusted review.
The store pins that root's observed device/inode for this execution composition;
replacement is rejected during later preflight and publication. Real exact
consent is obtained **before** evaluating the frozen output-safety constraint.
No root name or public boolean is promoted into consent. Re-review of an already
reviewed operation cannot renew its original deadline.

The fixed output handlers use the exact admitted `EffectBinding` directly with
the frozen `ArtifactPort.publish` signature, not a reconstructed artifact permit
or an arbitrary output callback. `scan.save` merges the selected hydrated fragment
with the supplied hydrated inventory through the native non-overwriting merge;
`inventory.export` uses the native inventory defaults, explicit groups,
metadata groups and `_meta.hostvars` conversion. Neither reopens an inventory,
vault or ambient cache. If targets are explicit, export selects those devices,
and save selects fragment changes while retaining untouched inventory entries.
They publish JSON or YAML. `report.render` requires supplied outcome target
coverage and renders HTML/PDF with the existing `ReportGenerator`, without its
unprotected `output_path` writer. Optional HTML/PDF dependencies remain explicit;
PDF support is not native-library qualification. Only protected publication
writes the result. The exact native payload and returned artifact descriptors
survive subsequent completion-checkpoint failure.

Execution holds concrete normalized endpoint/device and route resources plus
the operation resource through the existing owned lock port. Explicit output
also locks the observed destination identity in the same normalized order. A process-local
guard also rejects nested execution of a device across host instances, because
the native storage lock deliberately allows same-thread storage reentrancy.
The real C02 owned lock provides cross-process exclusion when a qualified
concrete `OwnedState` is supplied; inert tests do **not** prove native OS locks.
Busy executions do not consume their grants or start a second effect.

Every fixed entry requires the exact in-memory pending invocation and private
A01 permit, then invokes `enter` immediately before backend I/O. Factual
completion is journaled before broker completion. Failed/lost acknowledgements
never redispatch, and no authority is recovered from files. The original finite
review deadline is retained; hydration clock observations also terminally revoke
on expiry/backwards time or clock failure. `cancel` revokes the actual broker
and wakes this operation's cooperative `CancelPort`. This is not a claim that a
stalled real controller stops within two seconds or recalls remote commands.

By default factual journals are memory-only. Selecting an explicit output root
equal to the verified owned root persists **per-occurrence** journals using
`OwnedPolicyJournal(..., occurrence_id=effect.occurrence_id)`. Each resource is
`policy/<operation_id>/step-<digest-of-occurrence-id>`, bound to the complete plan
and exactly one disposition; no incomplete multi-target counter set is promoted
to terminal success. Existing checkpoints are not adopted or recreated.
Operational policy facts with `credentials.channel_qualified` use a closed,
reducer-revalidated group/leaf pair encoding, not a public credential object.
Legacy journal facts retain their existing encoding. The reducer now moves an
allowed operational effect intent into factual `Executing`; it still grants no
permit and leaves unmatched/denied intermediate completions unchanged.

`ExecutionHost.counters()` exposes safe stage/outcome counters paired with
`workflow.execution` structured logs from the same helper. Reload, resource-lock,
checkpoint-create/checkpoint-append and fixed backend boundaries are observed;
generic failures use stage `Unhandled`. No payload, source bytes, credentials,
paths or supplied exception text are logged.

### Guarded native configuration mutation (A02; inert adapter qualification)

`run_push(..., hooks=None)` retains native dry-run, connection, interactive
confirm-timer and raw changelog defaults. Its optional `PushHooks` port supplies
the selected connection, current-authority/cancellation checks, exact protected
prestate comparison and observed poststate confirmation. Hooked calls reject
raw changelogs and interactive timer options **before I/O**. They never return
raw pre/post configuration or diffs, log raw exceptions, or infer permission
to restore from an exception. Explicit restoration uses the native
`_rollback_to` owner (including its existing XR/Juniper strategies), followed
by an exact measured snapshot check, not an unconditional success.

The host currently accepts this closed **configuration-only** nonsecret intent:

```json
{
  "kind": "configuration",
  "commands": ["hostname selected-name"],
  "expected_digest": "<SHA256 of the exact approved post-configuration bytes>",
  "prestate": {"selected-target": "<protected artifact ref>"}
}
```

`prestate` keys must equal the selected targets; their ordered descriptor IDs
become `OperationPlan.recovery_scope`. The referenced bytes must come from this
host's **actually completed, admitted** `config.backup`, with a sensitive,
explicit-retention `ArtifactStore` receipt and the same target, complete
context, route, owned root and generation. Every admission/native boundary
rereads and integrity-checks that protected artifact. A native pre-write
snapshot must then equal those exact bytes. Copying an arbitrary descriptor
into an intent or returning a mock successful collection is not this provenance.

The trusted source collector must additionally supply an exact private
`_RecoveryQualification` for target, context, route, measured prestate digest,
proof digest and finite original expiry. Public request JSON has no such
qualification or credential field. These records are trusted collector
obligations, not a shipped production collector. The tests derive their
qualification from an actual native restore/read roundtrip on an inert
transport; this qualifies only the native hook adapter.

Before reviewing an apply, explicitly review one exact single-target
`config.rollback` request per selected target. Pass those actual unconsumed
private grants, in target order, to
`host.review(service, apply_request, recovery=(rollback_grant, ...))`.
The apply review binds each complete recovery plan digest/operation ID and
prestate reference. Its original deadline is bounded by the recovery deadlines.
The host never mints recovery authority because apply failed. A fresh
rollback entry still performs A01 consume, permit, entry and completion, its own
pending/result journal, fresh source/policy/controller/route/qualification
checks and exact native post-restore verification.

`EffectsBackend.mutation_connection(plan, effect)` is the sole private
connection seam. Trusted bootstrap must supply already selected credentials,
strict approved host-key/controller routing and bounded transport behavior.
There is **no** ambient credential lookup, native auto-connect fallback,
arbitrary handler registry or controller provider. The default frozen
`WorkflowService` constructor remains unchanged.

Successful apply does not consume its recovery grant; explicit rollback remains
distinct. Failed issued apply can invoke only its previously reviewed exact
recovery. Cancellation of apply never permits another ordinary write; the
separately reviewed recovery can continue only while its own original authority
and all current bindings remain valid. Expiry/control loss cannot manufacture
new recovery. Synchronous recovery borrows only the parent's already-held
resource locks; it does not weaken independent execution exclusion.

The primary `apply-failed` error survives successful recovery. Safe native
payloads retain `issued`, `committed`, `confirmed`, `poststate_verified`,
`rolled_back`, `prestate_ref`, and distinct `recovery_status`/nested recovery
outcome. An issued unverified write remains uncertain unless actual admitted
recovery verifies restoration. Never-issued targets are not made uncertain.
Lost checkpoint acknowledgement retains factual results and the pending
receipt, without redispatch or automatic rollback. Journals retain their
existing memory-default/explicit-output persistence boundary.
Connection teardown is independently reported in `cleanup`. A failed close
cannot erase an already verified confirmed/restored remote state, or cause a
second mutation solely because cleanup failed. Primary mutation failure and
secondary recovery/connection cleanup failures remain separate; successful
teardown never promotes a failed apply.

`tests/test_guarded_mutation_execution.py` runs actual native owners against
inert selected transport, real packaged policy, A01 and artifact ports, with
observable configuration writes/restoration. It does not qualify real devices,
image/reload/boot recovery, real credential/controller providers, protected
native filesystems, controller termination latency or either Molecule tier.
Those frozen obligations remain outstanding; unsupported safety blocks.

**Remaining original A02 scope:** combined verification of the concurrently
aligned refresh/backup/retention/Git policy and handlers; production private
credential/mutation-connection wiring; independent LA01–LA06 typed lifecycle
entry and pointer-CAS acceptance; full recovery/revert/cleanup and numeric/race matrices;
qualified current-source readers and exact real controller/credential wiring;
full execution telemetry/latency/load and native platform/Molecule proof.
The guarded native apply/rollback increment below is implemented and inert-tested;
it is not production vendor/controller recovery qualification. An observation
or an injected backend success is not qualified vendor recovery.
Backup output retains its actual `collect` then `backup` occurrences; observe
must remain collection-only. The fixed refresh entry rebuilds selected hydrated
inventory without a cache write. Backup publication consumes private
`EffectsBackend.backup_content(plan, effect, cancel)` bytes only after successful
collection and real broker entry, and publishes through the concrete protected
`ArtifactStore` sensitive channel. Retention and Git each have a separate exact
admitted occurrence and receive only the publication bindings from this run;
they are not side effects of publication. These runtime paths require matching
real packaged policy intents and qualified backend implementations. Source,
contracts and generated bundle must agree; an in-progress or stale policy
bundle fails closed rather than authorizing a fallback. No fabricated allow,
removed occurrence, expanded profile scope or skipped target resolves a
policy mismatch. This checkpoint does not accept
A02, narrow its original criteria, or unlock successors. The inert product tests
qualify only these dispatcher paths, not real devices, controllers or storage.

`netops.ansible.contracts` and `netops.ansible.workflows` provide the version-1
Python planning increment. They do **not** make the complete companion feature,
installer, CLI/Textual surfaces or Molecule qualification ready. The reviewed
pure policy evaluator is used unchanged; supplementary native-collector
qualification is separate.

The public synchronous constructor is:

```python
WorkflowService(
    policy, authorization, dependencies, controller, native, artifacts, clock, events
)
```

Ports are typed protocols. Policy bootstrap explicitly calls `load_policy` on
selected packaged bytes and constructs `LocalReferencePolicyEngine` **before**
using the service. Supply that same validated `PolicyIdentity` in `Context`.
Nothing in this API acquires dependencies, reads a default policy path, invents
registry qualification, unlocks a vault or constructs an authorization grant.
Import the service from `netops.ansible.workflows`; package initialization stays
free of eager companion imports.

Supporting injection contracts (none is a concrete adapter):

| Port | Signature |
| --- | --- |
| `AuthorizationBroker` | `issue(plan, consent, decision, now) -> Authorization`; `consume(authorization, binding, now) -> AdmissionSession`; `permit(session, binding, now) -> EffectPermit`; `revoke(operation_id) -> None` |
| `DependencyPort` | `verify(scope: InstallScope, context: InstallContext) -> ReadinessReport` |
| `ControllerPort` | `verify(context: ControllerContext) -> ControllerReadiness`; `run(request: ControllerRequest, credentials: ScopedCredentials, cancel: CancelPort) -> OperationOutcome` |
| `NativeWorkflowPort` | `preview(request, loaded) -> OperationPlan`; `run(plan, credentials: ScopedCredentials, cancel: CancelPort) -> OperationOutcome` |
| `ArtifactPort` | `publish(intent: OutputIntent, content: bytes, binding: ArtifactBinding) -> ArtifactDescriptor` |
| `ClockPort` / `CancelPort` | `monotonic() -> float`, `utc_now() -> datetime`; `is_cancelled() -> bool`, `wait(timeout: float) -> bool` |
| `EventPort` | `emit(event: SafeEvent) -> None` |

`InstallScope` contains ordered `native_capabilities`, `companions`, and explicit
`enhanced`/`full_toolkit` selections; `InstallContext` wraps the selected
`Context`. `ReadinessReport` binds schema, revision, context, nonsecret
per-capability evidence and independent readiness projections. No registry,
installer, probes or qualification results are generated by those values.
`ControllerContext` wraps `Context`; `ControllerReadiness` binds that context,
readiness and an evidence digest; `ControllerRequest` binds request and plan.
`ArtifactBinding` binds an exact effect and public/sensitive classification.
`ArtifactDescriptor` retains ref, digest, exact public size, media type,
classification, permissions proof, retention, owning resource and input binding.
`SafeEvent` has operation/step/target/context IDs, mode/status/category/reason,
retryable and finite duration. These frozen values are not permits, file handles,
readiness assertions or automatic emission hooks.

### Request, hydration and preview

Operations are area-qualified, for example `health.gather`, `config.apply`,
`compare.compare` and `report.render`. `catalog()` returns all 20 operations
across scan, inventory, vault, config, health, compare and report, with their
allowed modes and would-effects. Its `unqualified` marker is deliberately not a
dependency-registry or consuming-context readiness claim.
The catalog also declares required operand kinds: inventory operations need
inventory, scan inventory-preview needs inventory and fragment, configuration
planning/mutation needs intent, semantic comparison needs before/after,
generation/remediation needs findings, and reporting needs outcomes. Hydration
and preview enforce exactly one of each required kind through the same check.

`OperationRequest` carries schema `1.0`, canonical UUID, operation, `Mode`,
ordered `Scope`, selected `Context`, ordered `InputRef` values, optional previous
plan digest and `OutputIntent`. Context binds controller, route, source, mapping,
policy, registry and assets identities; it does not assert that a route or an
adapter is qualified. Network operations reject an empty selection. Offline
reporting permits one. `Scope.limit` defaults to 100 and has an absolute ceiling
of 4096 (not the general int53 counter maximum). Targets are never truncated.

An application that already has the service, request and explicitly selected
nonsecret bytes can plan without reading paths:

```python
from hashlib import sha256
from dataclasses import replace
from netops.ansible.contracts import InputRef, InputSource
from netops.ansible.workflows import hydrate_inputs

# request, service and clock are explicit application-owned dependencies.
content = b'{"devices":{"edge1":{"host":"192.0.2.1","vendor":"cisco_ios"}}}'
ref = InputRef("inventory", "operator-selected-inventory", sha256(content).hexdigest())
request = replace(request, inputs=(ref,))
loaded = hydrate_inputs(
    request, (InputSource(ref, "json", content, "parser-1", "vendor-1"),), clock
)
plan = service.preview(request, loaded)
```

`hydrate_inputs(request, sources, clock)` is the explicit read boundary.
Sources must correspond to request refs in the same order, exactly once.
They contain immutable bytes or an already-selected read-only regular-file
`FileIO`/`BufferedReader` descriptor. The caller must perform path/ownership/
no-follow checks before supplying a descriptor and owns its lifetime. Hydration
checks read-only/regular-file properties, reads at most 1 MiB plus one overflow
byte at the current offset, never seeks/reopens/closes it, and never accepts a
URL or automatic loader. In-memory streams are not checked file descriptors.
Clock values are validated here, outside preview.

JSON and safe YAML reject duplicate keys, aliases, nonfinite values, private
credential fields/identities and excessive depth/content. Text configuration
uses the same domain-aware rejection boundary as public payloads: SNMPv3
auth/priv statements, TACACS/RADIUS inline and block keys, generic credential
statements and private-key material are rejected **before content hashing**.
Structured camelCase/snake_case authentication, privacy and shared-key forms
and known case/compact aliases (including SNMP communities) are rejected
recursively; structured SNMP/AAA credential-domain objects have no public
schema and are rejected rather than traversed optimistically. SNMP security
level declarations without user credentials remain valid nonsecret inputs.
Authentication-trap notification selectors are likewise nonsecret, including
case-insensitive and negated SNMP commands. Credential checks interpret
authentication/privacy in credential parameter positions rather than banning
those words throughout an SNMP command; neighboring secret-bearing statements
still reject before hashing or public native-payload construction.
Rejection is not redaction or certification of
arbitrary vendor syntax; unknown credential encodings and sensitive recovery
configuration must not enter this public channel. Use the private/protected
execution path instead. Raw source/content fields are excluded from DTO repr.
Legitimate nonsecret SNMP/AAA configuration still uses the unchanged native diff.
Inventory/fragment inputs use the native `devices`/`defaults` mapping with
nonsecret device fields; supply private field references to later credential
adapters rather than embedding username/password data. Contents are limited to
1 MiB per source and 16 MiB per context. Rejection never silently truncates
selected records. These are bounded hydration operands, not a reduced public
device-value/report-total numeric range.

`preview(request, loaded)` revalidates the public DTOs, every content digest and
the complete request/context/ref/parser/vendor/observation binding **in memory**.
It never calls effect ports, clocks, resources, probes, logging setup or file/
network APIs. A missing, extra, swapped or tampered selected operand raises
`ContractError` with reason `input-binding-invalid` and a safe `error` DTO;
there is no fallback read. `OperationRequest.from_json` rejects unknown request
keys, including nested effect/consent fields. Public response decoding through
`OperationOutcome.from_json` tolerates optional additive response fields while
still validating all known fields and rejecting an unknown schema major.

Plans retain all target IDs, normalized nonsecret routes (or explicit unresolved
entries), input and policy digests, reducer version, ordered would-effect
occurrences, supplied observations, destinations, recovery scope and unmet
conditions. Native inventory defaults are overlaid by device values without a
connection. `compare.compare` requires one before/after text pair and invokes
the existing pure `diff_configs`/`format_json` owners on those bytes, preserving
native semantic results. Other domain projections expose the validated loaded
intent/data, not fabricated discovery, collected facts, merge results or
generated/remediated output; domain-owner integrations remain later tasks.

Preview diagnostics retain the original categorized error matrix and include
safe next actions. Unresolved routes use `transport / route-unavailable /
connect`; unavailable dependencies use `dependency / dependency-not-ready /
readiness`, identically to blocked execution. Observation prerequisites use
`precondition / authorize`, missing consequential consent uses `platform /
provision`, and rejected output intent uses `rendering / publish`. A local policy
denial retains its separate `policy / authorize` classification.

Observations bind selected target, controller, context, route, source digest
and UTC provenance. A missing observation produces a per-target
`observation-required` precondition for applicable operations; malformed,
duplicate or mismatched supplied observations are invalid. Supplied age is
planning information only and cannot establish execution freshness. Plan
digests exclude their own field and the request's prior plan digest, but bind
ordered arrays, exact nonsecret input bytes, observation identity/time and
policy/assets revisions. JSON object-key order is canonical; command/target/
group arrays retain order.

### Immutable settings (C01)

`netops.ansible.settings` owns `SettingsSnapshot`,
`load_settings(data: bytes)` and
`resolve_settings(snapshot, overrides: Mapping[str, object])`.
The loader requires the **complete** schema-`"1.0"` JSON document, rejects
missing/unknown nested keys, duplicates, coercions, bool-as-int, nonfinite
values and out-of-range values, and never opens files. Explicit bootstrap uses
`SettingsSnapshot()` only for absent configuration; a malformed supplied file
does not fall back. All groups are frozen:

| Group/key | Defaults and accepted bounds |
| --- | --- |
| `ansible.enabled`, `.mode`, `.enhanced` | `false`, `"audit"` (`audit`/`enforce`), `false` |
| `controller.id`, `.wsl_distribution`, `.start_timeout_seconds` | `null`, `null`, 30 (1–120); selected IDs still require host qualification |
| `NETOPS_STATE_ROOT` | `null` delegates platform-root selection to explicit protected bootstrap; an explicit value must be absolute, without parent traversal/URL/UNC |
| `inventory.cache_ttl_seconds` | 300 (0–86400; zero disables cache) |
| `diagnostics.retention_days` | 7 (1–365; explicit diagnostic persistence only) |
| `execution.target_limit` | 100 (1–4096) |
| `execution.ssh_concurrency`, `.ping_concurrency`, `.snmp_concurrency` | 5 (1–50), 50 (1–50), 10 (1–10) |
| `execution.timeout_seconds` | 300 (1–3600) |
| `authorization.ttl_seconds`, `observation.max_age_seconds` | 60, 60 (each 1–300) |
| `backup.retention_count`, `.git` | 10 (positive int53), `false` |
| `health.cpu_threshold`, `.memory_threshold` | 80, 85 (finite 0–100; explicit role threshold 90 remains valid) |
| `logging.level`, `.max_bytes` | `INFO`, 10485760 (level DEBUG/INFO/WARNING/ERROR/CRITICAL; exact int53 cap ≥1024) |
| `NETOPS_INVENTORY`, `NETOPS_VAULT`, `NETOPS_INVENTORY_CACHE`, `NETOPS_TUI_SETTINGS`, `NETOPS_LOG_DIR`, `NETOPS_LOG_SETTINGS` | `null` means the existing native owner retains its path/default; explicit selected absolute references do not read or adopt environment settings |

Health/logging field names above are the typed projections of the original
table's native threshold/logging rows, not replacements for native owners.
No environment is read or forwarded, including master-password variables.
An absolute path is not filesystem ownership/qualification proof.

Overrides use dotted keys and are limited to `execution.*`,
`controller.start_timeout_seconds`, `diagnostics.retention_days`,
`backup.retention_count` and `health.*`. Validated tuning overrides take
precedence over the validated stored snapshot; invalid values never fall through.
Enabled/mode/enhanced/controller identity/state-root/TTL/freshness/Git/native
owner/safety/consent/qualification/registry overrides are forbidden.

The exact eight-argument service constructor, `preview(request, loaded)` and
three-argument `hydrate_inputs(request, sources, clock)` remain unchanged.
Hydration binds a default immutable snapshot. Bootstrap explicitly reads the
protected settings document outside preview, resolves tuning, then calls the
pure `bind_settings(request, loaded, snapshot)` helper. This returns a new
`LoadedInputContext` with the **same snapshot object**, unchanged source
provenance and a recomputed binding including its settings digest.
`preview` independently validates that binding, retains that same snapshot
as `plan.settings`, uses its SSH concurrency/operation timeout, and includes
all protocol queues/settings in the plan digest. Selected count and explicit
scope limit must both fit the effective target limit; lowering it requires a
new explicit scope, never clipping. A configured controller ID must match the
selected context. Request JSON has no settings/overrides channel.

Neither snapshot preferences nor re-binding confer consent or readiness:
backup Git/retention preferences do not add effects to the explicit output
intent. Persisted safety changes require the later owned publication/consent
implementation; C01 provides no settings-write shortcut. A01/A02 must recheck
current kill switch, identity, qualification and freshness at admission without
extending original deadlines. Pure calls never reload settings.

### Outcomes and the explicit effectful dependency boundary

`TargetOutcome` and `StepOutcome` preserve ordered nested `native_payload`,
attempted/selected state, unapplied effects, findings, changed, remote state and
safe errors. `aggregate_outcome` requires the entire ordered selected target
ledger. Successful selected work plus unsuccessful selected work is `partial`;
otherwise failure (including health, cleanup and uncertainty) precedes
cancellation, unsupported and blocked. Unselected optional steps do not affect
success. Primary errors, changed state and secondary cleanup/resource details
are retained independently. A completed transport operation cannot make an
unknown/error/alert health finding healthy.
Selected `succeeded` targets/steps must be attempted and have no unapplied
effects. Contradictory results are rejected, including response decoding and
aggregation of corrupted DTOs. Mixed completed and pending apply work retains
the entire selected ledger, changed state and explicit non-success.

Valid-bound internal `PolicyInputError`, `PolicyEvaluationError` (including
budget exhaustion), and corrupt evaluator result identities raise the safe
in-memory `workflows.PolicyFailure`, not an invalid-input `ContractError`.
Its `error` uses existing `policy / reading-unavailable / evaluate` wire
values and exit 5; allowlisted `diagnostic` distinguishes internal input from
evaluation causes without exposing exception strings. Surface adapters retain
that error in an ordinary failed outcome. No new public reason is introduced.
Actual caller/schema/hydration errors retain invalid-input/exit 2.

Exits are 0 success, 2 invalid input, 3 blocked, 4 partial, 5 execution/policy/
rendering/cleanup failure, 6 unsupported and 130 cancellation without completion.
Public readings/totals retain exact integer values beyond the internal int53
policy-counter range. Revisions, generations, effect ordinals and counts reject
bool/coercion/overflow. Deadline helpers reject nonfinite clocks and computed
overflow; actual admission/CAS/telemetry-saturation enforcement belongs to
A01/A02 and is not supplied by a preview.

C01's uncomposed planning service deliberately cannot dispatch: `execute(request, authorization=None)`
returns a blocked, unattempted complete ledger with exit 3 and
`dependency-not-ready`, naming A01/A02 integration. It never consumes a grant,
calls a controller, writes artifacts or silently invokes native execution.
An uncomposed C01 `cancel` still returns `accepted=False` with an injected
finite clock receipt. The partial A02 path above now revokes an actual configured
A01 broker, but does not claim remote teardown. The owned event journal is also
explicit; the composed gather/collect execute checkpoint above now uses it.
Remaining full admitted execution and consuming-context readiness are their task owners'
dependencies, not placeholder successes. Private grant/session/permit/
credential types cannot be JSON- or pickle-serialized or created through
request JSON.

The focused service-free suites are `tests/test_workflow_contracts.py` and
`tests/test_companion_settings.py`. Their settings controls do not claim host
settings publication/consent implementation. The workflow suite's T29
case retains 20 raw warm timings, the 19th sorted value, hardware/runtime context
and separate hydration/cold timings as a JUnit property. A later tester/reviewer
must independently qualify the candidate; passing this suite is neither
native-collector acceptance nor full-feature/release readiness.

---

## `netops.ansible.dynamic_inventory`

Ansible dynamic inventory provider.

Builds an Ansible-compatible inventory from the netops YAML inventory file,
auto-generating `vendor_*`, `site_*`, and `role_*` groups. Supports
CredentialVault integration and file-based caching.

**CLI usage:**
```
ansible-playbook -i netops/ansible/dynamic_inventory.py site.yml
python netops/ansible/dynamic_inventory.py --list
python netops/ansible/dynamic_inventory.py --host core-rtr-01
python netops/ansible/dynamic_inventory.py --refresh-cache
```

::: netops.ansible.dynamic_inventory

---

## `netops.ansible.modules.netops_command`

Ansible module: run arbitrary commands on network devices via netops transport.

::: netops.ansible.modules.netops_command

---

## `netops.ansible.modules.netops_facts`

Ansible module: gather structured facts from network devices.

Returns `ansible_facts.netops` with categories:
`health`, `interfaces`, `bgp`, `vlans`.

**Module options:**
- `gather_subset` — `all` | `health` | `interfaces` | `bgp` | `vlans`
  (default: `all`)

::: netops.ansible.modules.netops_facts

---

## Companion policy source draft (not installed or qualified)

For checkout tests, use `python -m pytest` with the repository's `pyproject.toml`.
Pytest explicitly prepends the checkout root so embedded/script-context runners
and Python safe-path mode do not accidentally import an older installed
`netops` package. This is a test-only path setting, not installed-package proof.
Run installed wheel/sdist checks outside the checkout with a separate pytest
configuration that does not enable this setting.

For installed P02 acceptance, bind a fresh successful branch-coverage measurement
explicitly with `NETOPS_P02_COVERAGE_BINDING` (absolute JSON path),
`NETOPS_P02_COVERAGE_BINDING_SHA256`, and `NETOPS_P02_COVERAGE_ATTEMPT`.
The binding contains schema `1`, the matching attempt, measurement command
(including `--cov-branch`), exit code `0`, absolute report/JUnit paths and SHA256
hashes, and exact `sources`/`tests` path-to-SHA256 manifests. The consumer verifies
all five policy Python sources and all four original P02 test modules against
its own installed tree, a clean non-skipped measurement suite of at least 1000
tests, real branch metadata, and the original 80% line/branch thresholds.
Historical checkout receipts are not copied into an installation. The existing
checkout-only historical control remains available without those variables;
it is not fresh installed evidence. Unit parser fixtures are not measurements.

An `Observing`-phase lifecycle completion is denied by the actual PX-derived policy
before reduction: no effect, revision advance, completion disposition or consumed
receipt is produced. Tests assert this fail-closed behavior rather than requiring
a policy allow merely to reach a later defensive phase guard.
The existing install continuation selector does allow a `StepCompleted` in
`Planned`; the reducer independently rejects that completion with
`policy-event-conflict`, preserving state and receipts. Its real `Staging`
counterpart succeeds. These are distinct, tested safety boundaries.

The original consumer sources below are a **P01-partial draft**, not an
implemented companion API, a supported upstream Python binding, or evidence
that any Molecule lifecycle has run. Existing native inventory/module behavior
above is unchanged. The existing backup role's delegated/unmanaged scenario is
not proof of real-device or CI execution.

| Source | Intended responsibility |
| --- | --- |
| `netops/ansible/policy/ansible_molecule.px` | Business rules and error-severity invariants |
| `netops/ansible/policy/ansible_molecule.contracts.px` | Authored target-local allow/deny/boundary and violating-invariant examples |
| `tools/ansible_px_reference/Cargo.toml` | Build-only canonical dependency pin; not a resolved dependency lock |
| `tools/ansible_px_reference/Cargo.lock` | Retained genuine offline registry resolution; distinct from the task-local path-patched build lock |
| `tools/ansible_px_reference/src/main.rs` | Closed AST/schema validation, projection, canonical oracle and explicit file I/O |

### Authority and provenance

The canonical dependency is `plures/praxis-lang` revision
`6d367fe673756dabaa6085bc6b5202debaaabe6f`. The adapter uses the retained
`px_compiler::parse`, `px_eval::eval_rule`, `eval_constraint`,
`evaluate_expr` and unit `EmptyRegistry` interfaces. It does not interpret
PX text with regular expressions or reimplement workflow predicates in Rust.
Canonical rule output supplies fired **action names**, not action parameters,
effect execution, host phases, aggregate outcomes or permission receipts.
Static parameters come from validated declarations; phase/aggregate/error
expectations remain separately authored host expectations.

Rejected derivations retain exit code 2 and the `schema-or-example` reason.
The structured `failure_code` adds the adapter's closed validation error,
with zero-based source-declaration or contract/example ordinals where
available. It never includes parser error text, authored values or file
contents. These diagnostics do not relax validation or qualify an adapter
build; changed source requires a fresh reviewed build and execution binding.

The pinned grammar admits standalone comment lines and blank separators at
document boundaries, not between `examples:` and its first example or between
examples. `WHITESPACE` excludes newlines and `COMMENT` excludes its terminating
newline; `example_list = ("-" ~ example ~ NEWLINE)+` cannot cross either
interior separator. Keep fixture explanations before their `contract`
declaration.

The actual current-source diagnostic retained `CompileError::Parse` at
253:5, the first added dependency-readiness item after a blank/comment
separator. A second identical interruption preceded the 25 added restore
examples. The layout-only repair moves those three comment lines before
their respective declarations and removes the two interior blank lines.
All 215 complete examples (original 170 plus 45 additions), declaration
associations, ordinals, inputs and seven-field expectations are retained;
the separate 233 host vectors and strict nine-event metadata are unchanged.
The historical semantic-vector index is retained byte-for-byte; the
run-local `nov13-pinned-span-repair-artifact-v1.json` binds its original
contract hash to the corrected hash and unchanged ordered-example digest.

The focused authored-layout regression and pinned-adapter separator controls
now have retained, independently qualified execution evidence: the fresh
current-contract image `09C4ADF` compiled with exit 0 and passed all 23 Rust
tests, including the 215-example parse test, and the full selected plus
semantic pytest suite (983 passed, 18 subtests passed; exit 0). The real
current producer's earlier twin 215-case derivations, determinism, checkout
package equality and both drift checks are also qualified; these are retained
results, not a new execution here. See the current runtime evidence and
`nov13-terminal-proof-review-v1.json` scope below. Neither static layout
inspection nor historical 170-case assets establish these results or a P01
pass. P01 remains incomplete: installed wheel/sdist proof outside the checkout
is still blocked, with no installation authorized. The original diagnostic
wrapper's exit1 and the later wrapper failure remain failures. The producer's
parser-error mapping remains closed and emits no source excerpt.

API/grammar/license evidence is retained in this run's
`local-p01-partial-evidence/pinned-prerequisite-inspection.md`, with immutable
source coordinates and raw hashes. No upstream implementation was copied.
The inspected root/direct-crate MIT inheritance is not transitive-license,
dependency-resolution, publication or redistribution clearance.
That upstream MIT evidence does not relicense this consumer: the helper
manifest points to this repository's Business Source License 1.1 `LICENSE`.

The effective design is the unchanged feature Requirements/HLD/LLD plus the
accepted run-local v3 contract and narrow normalization overlay. Foundation
compatibility debt remains explicit: this is **not foundation compliance** and
does not establish a supported native Python Praxis binding. The proposed
Python reference engine, atomic authorization broker and owned state store are
not delivered by these source files.

### Closed build profile

The proposed helper arguments are `--source PATH --contracts PATH` and exactly
one of `--emit-dir PATH` or `--check-dir PATH`. Intended exits are 0 for
successful processing, 2 for schema/unsupported/example rejection, and 3 for
byte drift. **Do not run this draft without separate toolchain/execution
authority.** A registry Cargo lock accompanies the source; no qualified bundle
or canonical corpus is established by that lock.

The custom projection is schema `1.0`, profile `netops-reference-v1`, numeric
profile `exact-int53-finite-order-v1`; it is not the canonical AST ABI.
Identity binds source and contract hashes, canonical revision, declared rule
manifest, reducer version and bundle content digest. Content/profile changes
invalidate plans, consent grants and qualification; there is no policy-path
override, dynamic registry, implicit migration or permissive fallback.

The original helper's serializer pin is now `serde_json=1.0.154` with
`float_roundtrip`: its former 1.0.145 archive was absent from the existing
offline caches. This is a build-only dependency repair, not a toolkit version
bump or permission to acquire packages. Actual attempted locks, notices,
compiler diagnostics and resource limits are retained under the run's
`local-campaign-p01-evidence-v1/nov11-*` artifacts. Task-local optimized
profiles do not modify shared Cargo configuration or establish qualification.

The delivered lock restores the actual earlier offline Cargo resolution
(`B3727D17B0E396CCDBBEE06F53B80911E01577E336E287299AFEAB7B0D22CD3C`),
not a fabricated portable rewrite of the later build lock. Its 50 resolved
packages include 44 registry packages, five crates at the canonical Git pin,
and this consumer. The actual task-local adapter build used a different lock
(`47DD0628C86C0CFED1E647C353CF30C7958833CA1F3A170E92D672CA2B42B479`)
with 41 registry packages replaced by original read-only source paths.
Package versions and dependency edges match, but package source identities do
not. The executable must not be described as built using the delivered lock.

The run-local `nov11-1922-source-lock-qualification-v1.json` inventories the
complete lock graph, actual compiler-reported features, original archive/index
checksums, current source-file hashes, pinned Git blobs and license notices.
This is offline continuity evidence for independent review, not a fresh
registry authentication or a successful build against the delivered lock.
`valuable 0.1.1` remains in the cross-target lock closure with an MIT declaration
but no original license text; it and `libc` are absent from this actual MSVC
build's compiler-artifact stream. Its missing notice is not waived by target
exclusion. Preserve the Unicode-3.0 notice required by `unicode-ident` as well
as the other dependency notices. Full transitive/cross-target license approval,
redistribution clearance and P01 qualification remain unclaimed.

The source covers catalog/preview, dependency readiness, setup consent,
candidate/restore lifecycle, scan, inventory, vault, collection/backup,
configuration mutation/recovery, health, comparison/generation, reporting,
aggregation, cancellation and qualification. All seven public workflow areas
remain in scope. Actions are only `set_phase`, `record_step`,
`record_outcome`, `revoke_pending` and `request_effect` with closed constant
parameters. An intent can never replace the host's current one-use permit.
Private consent, exact effect occurrences, routes, source integrity, pointer
CAS and cancellation must still be rechecked atomically by the later broker.

Permitted expression shapes are boolean/int53/finite-float/string literals,
exact typed fact paths, `not`, parentheses and the eight admitted comparison/
logical operators. Equality rejects floats and mixed domains; ordering accepts
only matching int/int or float/float types. Booleans are not integers.
Validate both branches, even an unreachable branch, before canonical
evaluation. Budgets are 1 MiB per asset, 512 combined declarations, 32,768 AST
nodes, depth 32, 200,000 node visits per case/decision and 4,096 UTF-8 bytes per
string. Exceeding a limit rejects, never truncates.

Only these AST constant exceptions are accepted:

1. A rule/constraint expression `Expr::Path` with exactly one segment named
   lowercase `true` or `false` projects to an existing boolean literal before
   fact lookup.
2. Contract-example `Value::Path` with exactly one lowercase `null` segment
   converts to JSON null only at an already nullable expected-data leaf
   (`reason`, `next_phase`, `aggregate`, `error`).
3. Expression `Unary(Neg, Literal(Integer|Float))` normalizes to the existing
   typed numeric literal, after validating both operand and result. Integers
   remain exact int53 and floats finite binary64. Count both AST nodes.
   Negated paths, calls, arithmetic, nested negations and parenthesized
   operands reject even in dead branches. An outer expression parenthesis
   around the entire admitted negative constant is unchanged.

Expression null, contract boolean paths, other contract paths/identifiers,
contract parentheses, calls, variables, arithmetic, dynamic parameters and
executable declarations remain excluded. Quoted keyword strings retain their
string contents. Map/parameter duplicates reject before map construction.
Example IDs derive from the source declaration and zero-based example ordinal.

The pinned canonical negation evaluator internally converts integral floats
to integer JSON, including signed zeros. The projection preserves its
statically validated numeric type and float -0.0; conformance concerns only
the admitted comparison outcomes, not equality of those intermediate JSON
representations. Float equality and mixed-type comparisons stay forbidden.
Actual source spelling is determined by the pinned parser, not text rewriting.

### Closed next lifecycle occurrence

The single additional typed expression path `lifecycle.next_effect_kind`
accepts only `dependency-probe`, `dependency-download`, `dependency-stage`,
`dependency-verify`, `dependency-activate`, `dependency-uninstall`,
`restore-active-pointer` or explicit `none` (no remaining occurrence).
Missing, wrongly typed and unknown values reject; `none` is not an effect.
PX selects the existing static intent. Rust validates the path/domain only,
not registry business selection or a host callback.

For a non-`none` setup continuation, the existing PX consent invariant requires
present, unexpired, binding/effects-matching consent; preview/check cannot
authorize a new lifecycle intent. `none` leaves factual completion bookkeeping
exempt from that admission check, without renewing consent or permitting work.
Isolated selector examples do not exercise the whole-program admission guard.

The runtime owner must derive this value under the admission/root lock from
the next exact unconsumed occurrence in the full bound lifecycle plan.
Plan/lifecycle/event identity, current revision, contiguous consumed prefix,
ordinal, occurrence/step/resource IDs and exact private argument digest must
match; stale, missing, replayed, skipped or reordered data blocks without
dispatch. A final pointer effect still requires actual qualification and CAS.
The fact never supplies a permit, trusted consent or an authenticated event.
Synthetic canonical fixtures do not establish those runtime checks.
The exact run-local signed/occurrence delta and its independent review remain
separate evidence; this change does not implement the later broker/service.

### Lifecycle payload metadata boundary

The source adapter separately validates a supplied `InstallConsented` payload
as exactly `lifecycle_kind`, `plan_id` and `lifecycle_binding_digest`, following
the retained v3 lifecycle contract. Kind is `install`, `uninstall` or `restore`;
the plan ID is a hyphenated UUID and the binding digest is 64 hexadecimal
SHA256 characters. Missing, extra or wrongly typed payload fields reject.
These are syntax checks, not proof of a current plan or trusted consent.

Only the already-allowlisted `event.payload.lifecycle_kind` enters canonical
expression variables. The plan ID and binding digest remain in authored input
and derived case provenance, but are removed from evaluator variables; neither
becomes an expression fact. Supplying either on another event remains outside
the closed schema. A kind-only event without a payload remains an intentionally
sparse target-local fixture, not a fully hydrated lifecycle event.

This source-only seam does not implement the common runtime identity envelope,
other events' host-private receipt schemas, ledger validation, trusted fact
hydration or lifecycle admission. In particular it cannot mint a consent,
permit, probe receipt or pointer-CAS receipt. Runtime enforcement and independent
verification remain required; no compilation or qualification follows from
these source changes.
The canonical oracle in this draft is target-local; it is **not** a global
admission or host-reducer proof. In addition, fixtures supplying the complete
existing expression-path union receive a `canonical.combined` observation.
Sparse fixtures receive explicit null there, not invented facts or a passing
whole-program result. This additional build evidence is not a trusted runtime
event envelope.

The combined observation invokes canonical constraints first. A violation
returns deny with no actions and without evaluating admission rules; no
matching rule also denies. Fired action names must match the validated
declaration's ordered static descriptors. Duplicate descriptors, multiple
phase transitions, multiple step/outcome dispositions or multiple
effect-producing rules reject derivation.
Rule IDs are sorted; action order remains source declaration order. These
mechanical composition checks add no workflow predicates to Rust.

Aggregate examples now supply all seven counters and all three independent
failure flags. Before their target-local evaluation, the adapter rejects
missing/extra/wrong-type fields, counters outside `0..selected`,
`completed + unsuccessful != selected`, and unsuccessful categories without
any unsuccessful selected work. Addition is checked. No category-counter
partition sum is assumed. The same validation precedes a combined aggregate
result. This validates final count consistency, **not** a complete target/step
disposition ledger, and must not be used to finalize intermediate completions.

The PX identity invariant now rejects stale revisions and non-cancel events
in Completed/Cancelled phases. An incomplete selected dependency scope
explicitly records blocked without rewriting the separate readiness values.
Apply/rollback completion variants record verified post-state only without
remote uncertainty; uncertain issued changes record a failed step and
Uncertain phase, never a retry intent. Aggregate configuration success also
requires verified post-state. These are authored policy intents, not proof
that a host actually confirmed a vendor change or correlated an invocation.

Cancellation and deadline expiry block new admission, not factual
`StepCompleted` bookkeeping. An issued apply or rollback may record verified
success in Executing or Cancelling without changing phase; an uncertain result
records a failed step and Uncertain phase. Neither completion emits a new
effect, clears cancellation, renews a deadline or restores a revoked grant.
Even after Uncertain, cancellation/expiry still denies `ApplyConsented`,
including new rollback admission. This is not authorization for cleanup or
general mutation: scoped owned cleanup and any previously separately
authorized recovery remain the later broker/controller's responsibility.
Input/policy/plan binding, current revision and terminal-state guards remain
in force. The authored complete-fact examples exercise the source composition,
not trusted invocation envelopes; the later host must reject uncorrelated,
duplicate, wrong-effect/target/step and stale completions before reduction.

### Unverified work and known draft gaps

The earlier local source checkpoint performed authenticated project memory recall
(no results) and evaluated three current development-lifecycle constraints.
The foundation-only constraint remained violated under the approved,
feature-scoped B01 debt disposition; this is not a passing compliance check.
No memory write was authorized. That checkpoint ran no product tests, Rust
compilation, canonical parsing/evaluation, dependency installation,
derivation, bundle/corpus generation or platform qualification. Independent
tester evidence, if produced, is separate from these source claims.
The parked adapter remains **PARKED UNVALIDATED/UNINSTALLED**.

The renewed local continuation subsequently attempted real locked, offline
Cargo builds and a smaller API check in the inspected short task-owned root.
It repaired missing cached-input selection and applied task-only optimized,
no-debug/no-incremental, single-job/no-PDB profiles, including build dependencies.
Both final attempts stopped at the protective resource guard while compiling
dependencies; neither produced a runnable canonical helper or a passing API
check. No canonical policy parsing/evaluation, two-run derivation, bundle or
oracle generation is therefore claimed. The run-local report records the
earlier sampling-cap incident, subsequent measured stops and exact input bytes;
the finished build's minimum resource requirement remains unmeasured.

Before P01 can qualify, independently complete and verify:

- Canonical compilation against the exact pin, locked transitive dependencies
  and relevant license notices; actual two-run byte-identical derivation.
- Exact event/state identity and lifecycle payload schema closure beyond the
  draft's fact fixtures, plus full-event cross-rule and effect-occurrence
  binding. The new combined observations cover mechanical composition only;
  passing target-local examples alone are not application admission evidence.
- Remaining operation variants and host observations (inventory merge/cache
  handling, distinct resolver failures, setup registry-step progression,
  observations/post-state, teardown/uncertainty, output completion and promotion).
  Save/export/refresh/resolve/gather intents and unknown/unsupported health
  cases are drafted, not executed. Presence of a family
  in this draft does not mean every operation in that family is implemented.
- Full selected-disposition ledger validation beyond the new final-counter
  consistency checks, revision/generation exhaustion, signed int53 boundaries,
  float ordering extremes and rejected float-equality/coercion/dead-branch
  demonstrations. Source-only test cases are not passing evidence.
- Real consuming-context HTML/PDF readiness and output failure evidence.
  The report rule uses selected companion readiness, not unconditional PDF
  installation, and backup publication uses output rather than mutation mode.
  Report success must not erase source failure.
- Independent tester-owned derivation/mutation tests, complete-rule coverage,
  packaged identity invalidation, atomic host admission/replay/cancel tests,
  and both actual daemon-free and opt-in container Molecule lifecycles.

The renewed local continuation implements the explicitly authorized closed
next-occurrence refinement above; runtime binding, canonical derivation and
independent exact-byte review remain required. Independent review did not
establish whole-contract blockers for the other previously proposed pairs:
distinct safe resolver errors and native translation already belong to
S01/S02, and stale qualification evidence cannot truthfully retain valid
qualification/binding facts. Exact lifecycle namespaces, ordered occurrences
and completion correlation already have requirements. Narrow metadata
field/type closure and correspondence to pending invocations/disposition
records still need implementation and verification; the policy source alone
cannot prove host admission. Do not add hidden Rust decisions, further fact paths
or arbitrary payload keys to bypass these remaining requirements. The
cancellation source remediation addresses an existing requirement, not a new
contract; executable qualification remains outstanding.

Nothing in this draft changes native defaults, grants setup/device/network
permission, qualifies a platform, completes P01 or releases downstream work.

### First genuine canonical assets (local November 12 continuation)

The first successful canonical derivation was delivered, byte-for-byte,
as `netops/ansible/policy/bundle.json` and
`tests/policy/canonical-corpus.json`: 45 rules, 13 constraints and all 170 authored
examples. Their SHA256 values are respectively
`BD9A11722E0AE16C736AD1031FF7FF22A6D272F16305978BB683D8A0A62BCB90` and
`6BBB11D468A9DD535D469FC1DD783C905248176600083C638AA5587A08FBB2FD`.
The run-local `nov12-canonical-product-binding-a7.json` binds those bytes to the
exact producer `9C614183BBC544C434F8A8BE4F8750628CD337C8CA25EDE349B19DE14D41E994`
and independent a6 evidence. That executable is now the **historical
57,381-byte production-prefix image**, not a production rebuild of the
66,597-byte source containing the later test-only module. No hand-authored
oracle was substituted. Earlier failed attempts remain historical facts.

At that delivery milestone, a separately reviewed second guarded derivation
and full relevant policy suite were still required. Those historical 170-case
assets are superseded by the current 215-case derivations documented below;
delivery alone was not qualification.
`tests/policy/test_policy_derivation.py` contains real-adapter two-run/package-byte,
drift, numeric, malformed-input and budget negatives; it requires explicitly
qualified local adapter, direct-AST Rust harness and owned scratch paths.
Do not invoke it unguarded or silently skip missing prerequisites. The separate
offline host route retains the existing nine selectors and denies sockets and
all subprocesses. No listener, device, service or broader socket suite is
authorized by asset delivery.

No Python reference engine, atomic authorization broker, installed wheel/sdist
qualification, complete seven-area companion implementation, full feature
acceptance or P01 completion is implied. Relevant license-notice gaps and the
distinct built versus delivered Cargo locks remain recorded, unresolved work.

### Independent direct-AST harness repair (local November 12)

The full selected P01 suite actually terminated with six failures, 846 passes
and 18 passing subtests. Its six exact `nov11_independent::` filters executed
zero Rust bodies; the separate thirteen-body Rust result did not satisfy them.
That failure history remains valid.

The current delivered adapter source and owned compiled-target source now both
contain the six independent direct-AST bodies, in a test-only module alongside
the unchanged thirteen original tests. They cover signed int53 limits, finite
binary64 extremes/subnormals/signed zero, forbidden computed negation including
dead branches, both unary AST budget nodes, mixed domains/float equality, and
the closed seven-existing-effect-kinds-plus-`none` fact. Rejection cases assert
the actual expected error category; canonical comparisons remain distinct from
projection sign/type checks.

The subsequent independently executed a2 run genuinely listed and passed
**19 Rust tests**, including all six exact one-body successes, and passed the
selected **852 pytest cases plus 18 subtests**. Its compiled test image is
`AE97233EBB15F5FAFD0E8AA59085F4FFC4F1DE62553E3B026AA5EF96B39430BA`.
The independent actual-P01 review discharged the numerical R1 scope, not P01
overall. `nov12-suite-tester-evidence-a2.json` and
`nov12-actual-p01-acceptance-review-v1.json` in the active run retain the exact
source, compilation, containment and selector evidence. Earlier zero-body and
six-failure results are not rewritten. That image is historical: unchanged Rust
root/module bytes do not establish freshness when `include_str!` fixture inputs
change; the compiled image must also bind the current embedded contract bytes.

### Authored semantic continuation and current scoped evidence

The private parse-only diagnostic is documented in
`documentation/ansible-px-reference/ansible-px-reference-architecture.md`.
It subsequently compiled with exit 0 and retained the original pinned
`CompileError::Parse` at 253:5, on `- input:`, with parser exit 2. Two interior
blank/comment separators had terminated example lists. The demonstrated repair
moved three existing comments before their declarations and removed only two
interior blank lines; all 215 case inputs/expectations and 233 separate host
vectors remain unchanged. The producer CLI, grammar, operators and profile did
not change. The diagnostic wrapper's later failure remains historical.

The contracts now contain **215 examples**: all 170 original sparse examples
are retained, with 45 deliberately complete additional pure-policy fixtures.
They include restore admission; each of the six inappropriate dependency effect
kinds and explicit `none`; candidate, consent, mode, current-binding, ownership,
consequential and cancellation negatives; sole-restore completion without a
second pointer intent; source/channel/output safety; terminal cancellation;
and complete policy inputs spanning all nine existing event kinds.
Target-local expectations remain distinct from full-policy combined
expectations. No restore continuation selector or new expression path,
operator, readiness enum, profile, effect handler or runtime API was added.

The active run's
`local-campaign-p01-evidence-v1/nov12-p01-semantic-vector-index-v1.json`
contains the exact new declaration/example IDs, expected combined decisions,
criterion references and **233 separately authored host vectors**. These
concretely specify selected/unselected registry readiness and fresh-plan resume;
kind/plan and consequential receipt bindings; source/cache and duplicate merge
identity; native credential outcomes/precedence and channel expiry/route;
already-authorized recovery and factual teardown; integrity-verified output and
requested PDF versus HTML; qualification identities; nine typed events and
ordered occurrences; selected identity indexes; and numeric exhaustion,
replay, clock rejection and observational saturation. Credential precedence
follows `CredentialVault.get_credentials`: environment, device, first matching
group, then defaults. No credential values occur in these fixtures.

**Written host expectations are not host execution.** The current producer-source
candidate validates full schema-`1.0` metadata at the existing `input.event`
boundary, retaining the original map in the existing contract/corpus entries.
The 45 additive fixtures now carry all nine closed typed event variants. The
170 historical sparse fixtures and narrow three-field `InstallConsented`
payload remain explicitly sparse compatibility coverage, not hydrated events.
Complete events require exact common keys, one UUID operation/install namespace,
UUID event identity, bounded nonnegative int53 revision, SHA256 plan/context/policy
identities, safe target/step references and the applicable closed payload.
Unknown fields/schemas, malformed identities/types/bounds, duplicate approved
descriptor IDs and event/payload identity discrepancies reject.

The complete common map is exactly
`{schema,event_id,operation_id|install_id,kind,expected_revision,plan_digest,context_digest,policy_digest,target_id,step_id,payload}`.
The namespace alternative is exclusive. InstallConsented, CandidateVerified
and Activated use `install_id`; OperationRequested, Observed
and ApplyConsented use `operation_id`; DependencyObserved and factual
StepCompleted/Cancelled can belong to either domain. Payload keys are exact,
not an extensible dictionary:

| Kind | Closed payload fields |
| --- | --- |
| OperationRequested | `request_digest,loaded_input_digest,plan_digest,mode` |
| DependencyObserved | `dependency_id,context_digest,probe_receipt,probe_digest,readiness` |
| InstallConsented | `lifecycle_kind,plan_id,lifecycle_binding_digest,private_consent_reference` |
| Observed | `invocation_id,target_id,step_id,observation_ref,observation_digest,disposition` |
| ApplyConsented | `plan_digest,approved_effect_ids,approved_recovery_ids,private_consent_reference` |
| StepCompleted | `invocation_id,effect_id,target_id,step_id,safe_result_digest,primary,cleanup,remote_uncertain` |
| CandidateVerified | `candidate_digest,registry_digest,assets_digest,policy_digest,qualification_digest,functional_evidence_ref` |
| Activated | `expected_pointer_digest,current_pointer_digest,new_pointer_digest,cas_receipt` |
| Cancelled | `accepted_host_receipt,revocation_revision,safe_reason` |

Digest fields require 64 hexadecimal characters; UUID fields use the hyphenated
36-character representation. References are nonempty, free of control characters
and bounded by the existing 4096-byte string limit. Descriptor-ID lists consume
the existing contract-data node/byte budgets, contain safe unique strings and
retain their order; the declaration-count limit is not a new list-length limit.
Payload modes/readiness/dispositions/lifecycle kinds use the existing enums;
uncertainty is exactly boolean and revocation revisions use `0..MAX_INT`.
Request/approved plan, dependency context, candidate policy, activation expected
pointer, and observation/completion target-step correspondences are checked
against the same event. This is fixture consistency, not live receipt provenance,
pending-invocation correlation or an actual pointer CAS.

`tools/ansible_px_reference/src/event_metadata.rs` implements that data-only
validation once for both source roots. Before canonical evaluation it strips
every metadata field except the existing kind/revision and, only for
`InstallConsented`, `payload.lifecycle_kind`. Non-install complete variants do
not require that inapplicable install-only path for combined coverage; no
missing applicable fact is defaulted. The seven target-expectation fields,
expression-path domain, operators, numeric profile and existing budgets stay
closed. Private-reference strings are symbolic fixture references, never
authenticated receipts, grants or checkpointed private sessions. Full lifecycle
bindings, ordered six-field occurrences, qualification/cache/channel identity,
selected identity indexes and host numeric negatives remain in the separate
233-vector index, not a new producer CLI/container or fabricated canonical
outputs. The OperationRequested plan digest and CandidateVerified
registry/policy/qualification payloads now match their actual fixture bindings.
The prior 19-body Rust/852-case pytest result remains valid for its historical
inputs, not as proof for the current candidate. An intervening image,
`A66E9674555257FD291F2BA564E6FC0A53B53B8D675DA3117DB828911930CF50`,
actually ran 23 Rust tests with 18 passes and five failures at 253:5: it embedded
the prerepair contracts despite unchanged Rust root/module bytes. That failure
is preserved. A fresh root compilation exited 0 and produced current test image
`09C4ADF3A4A5F730846DCFC74790CC3F0FB57A57CFABD337156289E3F6DAB077`,
embedding the complete repaired 199,928-byte contract exactly once. It passed
all **23 Rust tests** and the full selected **983 pytest cases plus 18 subtests**,
both exit 0, including real restore-guard sensitivity and pinned-grammar
separator regressions. Both source roots and their shared metadata module are
separately bound; root-byte equality is not claimed.

The real current producer derived **215-case assets twice**, both exit 0,
byte-identically; checkout package equality and both drift checks passed
(exit 0). The current bundle SHA256 is
`EF6B259BFBC94FE8307A745225C18B06B424F142526EBFDE04CB29A7B3219853`;
the current corpus SHA256 is
`0CA06A6C64E1505612647E3FCF31FF01D0439BF5400F407FC5EC44DB5BD7387F`.
These replace the historical 170-case assets above. The fresh-image run reused
and rehashed those genuine twin derivations; it did not derive them anew.

The overall wrapper nevertheless exited 1: its live integer-PID identity map
was queried with a string PID. Independent review qualified the actual terminal
results and **749 matched direct-child creation/terminal pairs** (one compiler,
14 harness invocations and 734 producer invocations), with exact image,
creation, parent, held-handle and child-specific Job identities, plus the
observed root's owned stop. This bounded supplement is not universal descendant,
listener or continuous-peak proof, does not relabel the failed wrapper as
passing, and does not waive future guard requirements. The archived runner still
contains that defect. At that historical checkpoint, an exact consumer repair
was authored separately with independent execution/review pending; the installed
continuation below records the later six independent consumer controls.

The active run retains `local-campaign-checkpoint-v14.md` and
`local-campaign-p01-evidence-v1/nov13-current-proof-execution-evidence-v2.json`,
`nov13-embedded-refresh-execution-evidence-v1.json` and
`nov13-terminal-proof-review-v1.json` for those exact scopes. This is qualified
current native runtime evidence, **not all-P01 qualification**; that native
receipt alone is not installed wheel/sdist proof outside the checkout.
The 233 authored host vectors are not actual host
reducer, broker, persistence, CAS, credential, controller/platform/media or
companion execution. No installation, redistribution, license/debt closure or
weakened release provenance is implied. P01 remains unqualified and all 19
downstream tasks locked; manual B02 authority, lock/license debt and
tuple qualifications remain separate obligations. The installed-package slice
was subsequently verified as recorded below; it does not itself qualify P01.

### Historical offline installed-package preparation (Nov 13, before execution)

The following preparation state is retained as history, not the current
installed-proof outcome. The current scoped result follows this section.

Packaging now explicitly includes the current `ansible_molecule.px`,
`ansible_molecule.contracts.px` and `bundle.json` as resources beneath installed
`netops`. Namespace discovery is restricted to `netops*`; private run files and
build tools are not importable product packages. The sdist also retains the
build-only reference tool's Cargo manifest/lock and Rust source, plus the
canonical corpus; no compiler or native executable is shipped in the wheel.

The run-local `nov13-installed-proof-harness-v1.py` prepares two separate routes:
source→wheel→normal pip install and clean source→sdist→wheel→normal pip install.
Both use fresh owned pip-free venvs, existing local backend/pip read in place,
no index/build isolation/dependency installation/shared pip cache, and safe
help-only invocation with cwd outside the checkout. The checker requires real
installed module/metadata/resource paths, all three current asset hashes,
source/contract provenance, 215 examples, and the base console entry-point
import. Optional TUI metadata is checked but TUI extras are not installed or
imported. Missing installed assets and deliberately injected checkout paths must
fail; held assets are hash-checked and restored, never silently deleted.

Only read-only availability/resource probes are authorized in this preparation
task. The execute branch requires an independent current authority review and
exact source/tool/resource bindings. No product build/install or new test result
is claimed here. The harness does not reuse the historical native proof runner;
it reuses only retained low-level accounting and suspended child Job primitives.
Admission remediation centralizes unchanged accounting/capacity/work checks
before growth stages, after stopped-command cleanup (including immediate exits),
and against final measured usage before successful status; no continuous-peak
guarantee is implied. The outer command uses existing activated Python to launch
the pinned real WindowsApps interpreter through `subprocess.call`, not the
demonstrated Access-denied direct PowerShell form. Focused negative controls
are authored; independent unit execution and refreshed admission remain required.
The proposed PID consumer repair preserves historical wrapper1/suite0 and the
exact native image allowances. P01 remains unqualified, P02 plus all 19
dependents remain locked, and B01 reference/owned-event compatibility debt is
not foundation compliance.

### Current scoped installed-package proof (Nov 13)

The retained `local-campaign-p01-evidence-v1/nov13-installed-proof-execution-evidence-v4.json`
and independent `nov13-installed-proof-final-review-v5.json` establish both normal
offline pip-installed routes: retained source-built wheel→install, and separate
clean source→sdist→rebuilt wheel→install. Both ran with cwd `C:\`, outside the
checkout, resolving modules, metadata and resources in their own venv
`site-packages`, not by treating archive extraction as installation. Both checked
the current three asset hashes, source/contract provenance, all **215** bundle
examples and the base console import/help. Optional TUI metadata was checked,
not optional TUI runtime execution.

Exact retained package SHA-256 values (the two wheels are not claimed identical):

| Package | Bytes | SHA-256 |
| --- | ---: | --- |
| Retained v1 wheel | 258610 | `e7ca2c01b85341fe45e6c1b33e1d4bc2205d233b93bf8a6e56cee50d96e55bc3` |
| Separate v2 sdist | 280490 | `6ae8270eb71c20e67d8357afb8604660a34e714f7463ec126379f7f23c3275a8` |
| v2 sdist-rebuilt wheel | 258610 | `1962433fc2bf220fa76dcb7ad0c4f7b440b5ad6d9fde5c6efd26707ffdc59526` |

The first v1 wheel attempt remains a **WinError31 cleanup failure**, not a
successful install. The later admitted v2 route passed the real inert held-child
smoke before product work. Actual pytest exit was 0 with **109 passed**, plus
**six independent controls** passed. The tester wrapper's stale expected **66**
count caused a post-test validator failure; it remains failed, reconciled by
`nov13-installed-proof-unit-reconciled-v4.json`, not relabelled as a passing
wrapper. Across both installed routes, **ten actual negative controls** rejected
missing assets, injected checkout paths and actual preloaded checkout modules;
**two restored positives** passed after hash-checked restoration.

Raw evidence is retained at `.sdlc/p01-cargo-fb1f9495/installed-proof-nov13-v2/result.json`
(`commands/0` is the smoke; `commands` records all **23** scoped children), with
`wheel-installed-check.log`, `wheel-restored-installed-check.log`,
`sdist-wheel-installed-check.log` and `sdist-wheel-restored-installed-check.log`
under that same root. The v4 execution receipt binds their hashes and the
`nov13-installed-proof-unit-evidence-v4.json` and reconciled unit receipts.
Held process handles, matching creation identities, retained live image/parent
provenance and exact owned Jobs establish this bounded child scope, not universal
descendant coverage or global cleanup.

The v4 receipt's `resources` records measured finite points: cap **1260503843**,
trigger **924959523**, reserve **335544320 counted once**, and actual installed
work **10643118 bytes** including the final result. Its execution-final charged
value is **918514434** and evidence-audit value **918826574**. These are retained
measurements, not a fresh measurement by this documentation change, continuous
peak proof, or permission to enlarge limits.

The current-byte admission and independent tester/reviewer authority supported
that prospective execution; this is **not new explicit user install consent**
or permission for another install. Historical native wrapper1/suite0 and the
749-direct-child supplement remain distinct; retained **23 Rust + six numeric
controls**, **983 pytest + 18 subtests** and **215-case twin derivations** were
not rerun here. Separate native main roots are bound separately, not asserted
byte-equal.

The independent reviewer verified `installed_PX01_qualified=true`; **P01 remains
unqualified pending this documentation's independent review and coordinator
acceptance of actual full P01**. P02 and all 19 dependents remain locked. B01
reference/owned-event compatibility debt is not foundation compliance.
Delivered-lock, license, release and manual B02 obligations retain their owners.
No full campaign, platform, TUI, Molecule, CI or PR qualification is claimed.

## P02 pure local reference policy core

The local coordinator subsequently accepted the P01 prerequisite in
`nov13-p01-local-acceptance-v1.json` in the same run. The locked-state statements
above describe the earlier proof/documentation checkpoint, not that later
decision. Its installed-wheel and separate-sdist proofs bind their original
revision; adding this Python core does not retroactively qualify a new package.

`netops.ansible.policy` now exposes these **toolkit-owned**, pure interfaces:

```python
load_policy(source: bytes, contracts: bytes, bundle: bytes,
            expected: PolicyIdentity) -> PolicyProgram
LocalReferencePolicyEngine(program: PolicyProgram)
engine.decide(event: DecisionEvent, facts: DecisionFacts) -> DecisionResult
engine.reduce(state: PolicyState, event: DecisionEvent,
              facts: DecisionFacts) -> PolicyTransition
```

There is no `authorize` alias, resource bootstrap, clock read, file access,
network call, callback registry, executable evaluation, Rust/Node runtime,
dispatch or persistence in this boundary. Callers obtain immutable asset bytes
outside it. A decision and every `request_effect` are **intents**, never consent,
an authorization grant, an effect permit or evidence of execution.

`PolicyIdentity` requires the full sorted unique declaration manifest (rules
**and** constraints), source/contract/raw-bundle SHA256 values, canonical pin
`6d367fe673756dabaa6085bc6b5202debaaabe6f`, reducer `"1"`, schema `"1.0"`,
profile `"netops-reference-v1"` and numeric profile
`"exact-int53-finite-order-v1"`. The loader accepts the producer's compact
sorted UTF-8/LF encoding, preserves its original binary64 spelling for content
digest verification, and validates all 215 current examples. It does not parse
PX itself or certify a fresh canonical derivation.

All DTOs are frozen. `FrozenObject` is a recursively immutable mapping;
`contracts.object_value(mapping)` defensively constructs one. `DecisionFacts`
contains `values` (closed nonsecret fact groups), `state_phase: Phase` and
`state_revision: int`. Supplied groups are validated completely, including
unused fields. Applicable declarations require their manifest paths even when
an expression short-circuits. Full runtime events require the nine-event
metadata/payload schemas. The loader alone recognizes the accepted sparse
expression-only contract fixtures; they are not valid runtime events.

The engine requires exact recursively immutable program DTOs, not subclasses or
objects that merely compare equal to them. The loader retains the three original
immutable byte operands in a private, non-constructor, non-repr `PolicyProgram`
field. Engine construction reloads those operands against the original identity
and compares the complete executable projection (including examples and node
count). A copied/modified projection with the old hashes, or a program constructed
without loader provenance, is rejected. This internal proof does not change the
public constructors, wire identity, policy profile or authorization boundary;
normal callers obtain a program through `load_policy`, not `dataclasses.replace`.

Boolean/integer coercion, float equality, mixed comparisons, nonfinite floats,
negative/overflow counters, duplicate/unknown fields and identity/profile/action
drift reject. Limits remain 1 MiB per input asset, 512 declarations, 32,768
expression nodes, expression depth32, 200,000 evaluation visits and 4,096-byte
strings. Int53 comparisons are exact; finite binary64 permits ordering only.
Signed constants are already literals in the accepted projection; no arithmetic
or dynamic negation was added. `lifecycle.next_effect_kind` remains the seven
existing lifecycle effects plus `none`.

State restoration validates every field and selected target/step receipt.
`PolicyState.namespace` distinguishes operation/install UUID namespaces;
its `operation_id` holds the corresponding identifier. A transition returns
the old `expected_revision`; the host must independently perform CAS, validate
the full plan/occurrence and admit each effect. Replayed identical last events
return the unchanged state with no effects; conflicting or out-of-order events
reject. MAX-int53 revision advancement rejects without modifying the input.
Completed selected coverage is checked against the complete disposition index,
not inferred from a success flag. Observations do not themselves authorize
mutation or activation. Host cancellation, reservation and already-issued-effect
reconciliation remain separate responsibilities.

Intermediate `StepCompleted` counters may leave selected work pending:
`completed + unsuccessful <= selected`. Reduction binds every supplied category
to the entire selected index, records only the matching invocation/effect receipt,
and preserves pending entries. A complete partition is required only for actual
terminal aggregation, with no pending selected entry, no remaining lifecycle
occurrence and no next effect intent. A lifecycle continuation cannot return
`Completed` together with another requested effect. The existing PX selectors,
not a new host selector, still choose the next intent. Their exact additional
completion cases are install/`Verified` with activation and uninstall/`Admitted`
with uninstall or pointer restore; unrelated phases/events remain invalid.

For health observations the correlated factual disposition is retained when it
is failed, blocked, unsupported or cancelled; a healthy finding cannot turn it
into success. A successful observation may still become failed/unsupported under
the health policy. The outcome summary combines factual and health outcomes with
failure before cancellation, unsupported, blocked and success; the observation
digest and receipt correlation are preserved. Health findings never manufacture
successful connectivity or erase execution failures.

Errors are `PolicyLoadError`, `PolicyInputError`, `PolicyBudgetError` and
`PolicyEvaluationError`, with safe internal `reason` constants. Denials contain
no effects. Pure evaluation emits neither logs nor metrics; the later authorized
execution boundary owns paired structured telemetry, grant consumption,
storage, clocks and dispatch.

Lifecycle owned-state reads and compare-and-replace calls pair each
`lifecycle.owned_read` / `lifecycle.owned_cas` start with a succeeded or failed
terminal event, including interrupted I/O. Shared artifact observations attach
`netops.lifecycle.owned_io.count` (value 1), bounded `boundary`/`outcome`
dimensions and finite nonnegative monotonic `duration` seconds to each event.
Process-local `io_id` correlates the pair only in logs, never metric labels.
Every record carries log-only `operation_id` (lifecycle plan), `step_id`,
`occurrence_id`, `target_id`, `context_id`, `mode`, `status`, `error_category`,
`reason`, `retryable` and `next_action`. Bound identifier correlation uses
deterministic `sha256:` references, not raw caller strings. Lifecycle work has
no device target (`target_id="none"`). Snapshot/admission work has no entered
occurrence (`step_id`/`occurrence_id="none"`); direct unscoped adapter calls use
`"none"` correlation. ContextVar scopes isolate concurrent operations and reset
on all exits; nested locks preserve the current occurrence.
Start/success records use `none` error category/reason/next action; failures
use closed `storage` / `owned-io-failed`, `retryable=false`, and fixed guidance:
inspect the owned receipt/current state before any new reviewed attempt.
Only bounded `boundary`/`outcome` are metric dimensions. No raw resource IDs,
grants, private paths, payloads or exception text enter these records.
Telemetry clocks and sinks cannot change authority, replace primary errors,
retry effects or discard late factual receipts. These are local inert adapter
observations, not controller/platform qualification or A02 acceptance.
The same nonthrowing reporting rule covers native execution start/success/failure
and bare lifecycle handler records, including interrupting sinks. Observations
are attempted once without retry; returned native payload/status, cancellation,
secondary cleanup and persisted observed receipts remain factual.

The telemetry helper centralizes the closed metric and outcome vocabulary.
An unknown boundary is rejected before entering I/O or emitting a pair.
Regression controls pin the raw metric/dimension strings and verify actual
process-local counter increments; no exporter or delivery guarantee is added.

This is the P02 **implementation milestone**, not P02 acceptance. Independent
canonical-corpus/operator comparisons, restored-state/replay/safety controls,
line/branch coverage (at least80%), review and downstream integration remain
required. No tests were added or modified by this implementation worker.
No native command, service, controller, transport, package asset, dependency or
installation path was changed. B01 compatibility debt and all seven-area,
both-tier, platform and manual B02 obligations remain unchanged.
# Local output integration checkpoint (not acceptance)

Fixed local `report.render`, `compare.generate`, `scan.save` and
`inventory.export` output plans do not require a qualified controller tuple
when their actual effects are exclusively local. Native declared blockers,
bound source validation, protected root permission and one-use admission are
still enforced. Device/controller paths retain the original strict tuple.
Explicit empty offline report coverage is valid without invented targets;
nonempty selected coverage must still be present in the source outcome.
Minimized validated report source facts survive later preflight/render failure.

The drafted `compare.generate` handler publishes the exact reviewed YAML bytes,
never collects/applies or executes generated YAML. It remains fail-closed
pending the coordinator-owned executable policy intent: the current packaged
compare rule provides only factual `record_outcome`, not `request_effect(save)`.
No host conversion of factual success into authority is made.

