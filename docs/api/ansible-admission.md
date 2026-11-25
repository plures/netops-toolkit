# Private operational and typed lifecycle admission (A01)

## Typed lifecycle boundary

The operational API below is unchanged. Lifecycle callers import the distinct
`InstallPlan`, `UninstallPlan`, `RestorePlan`, their concrete bindings and
nominal authority types from `netops.ansible.policy.contracts`. There is no
`OperationPlan` conversion. All projection fields are required; install also
binds its exact `InstallScope`. The immutable credential-free `content` field
has the closed schema below. Empty content, readiness booleans, unknown fields,
unbound arguments and kind-inappropriate descriptors reject before consent.
The broker validates evidence, but does not collect it or implement the planner.

`bind_lifecycle(plan)` revalidates the concrete type, literal kind, exact field
set, UUID namespace, int53 ordinals/revisions, complete supported policy identity,
ordered occurrences, categories and digest. `lifecycle_plan_digest` is the pure
hash derivation for the dependency planner. Uninstall binds a nonempty ordered
`GenerationBinding.selected` tuple; restore permits exactly one
`restore-active-pointer` occurrence and never an absent pointer.
An uninstall's explicitly planned final switch also uses
`restore-active-pointer`, matching the packaged PX symbol; it stays in the
uninstall namespace and requires retained verification. `dependency-activate`
belongs to install, not uninstall.
`AbsentPointer("absent", 0)` is meaningful only with trusted verified ownership,
not missing/corrupt state.

Bootstrap supplies optional keyword-only `lifecycle_state` and
`lifecycle_consent` dependencies to the existing `AuthorizationBroker` constructor.
`lifecycle_telemetry` optionally supplies the local paired observation collector.
`TrustedLifecycleConsentAdapter` calls the trusted `LifecycleReviewPort` once for
the whole binding and separately for **every** required consequential category.
The returned `InstallConsent` and its identity-registered category receipts are
memory-only. Generic assent, operational consent, constructed nominal instances,
foreign adapters, missing/excess/mismatched receipts and expired receipts do not
grant lifecycle admission.

```python
issue_lifecycle(plan, consent, decision, now) -> LifecycleAuthorization
consume_lifecycle(authorization, binding, now) -> LifecycleAdmissionSession
permit_lifecycle(session, effect_binding, now) -> LifecycleEffectPermit
revoke_lifecycle(kind, plan_id) -> None
```

Decisions use the existing evaluator's ordered `request_effect{kind}` symbols and
bundle SHA256, not an invented evaluator wire schema. A real evaluator result may
include its exact leading `set_phase`: `Staging` for install preparation,
`Verified` for activation, `Admitted` for uninstall/restore. Only that specific
optional prefix is accepted; reordered, missing, duplicate or extra executable
effects reject. Every rule ID must belong to the bound policy manifest.
Full occurrence identities,
arguments, categories, complete policy identity and expected pointer remain bound
independently in private consent/grant/session records; policy symbols alone
are never permits. A changed identity requires new planning and consent.

`LifecycleStatePort` provides `lock_lifecycle`, `snapshot_lifecycle`,
`compare_lifecycle_revision` and `compare_replace_lifecycle`. Every owned-state
writer and external cancellation must share the root lock. The broker takes its
private lock first. Snapshots independently report checkpoint revision,
cancellation, setup safety and **required `LifecycleEvidence` observations**.
The older ownership/pin/probe booleans remain additional deny-only checks;
all-true booleans without evidence cannot admit anything. `setup_enabled` is **not**
the companion device-dispatch kill switch: explicitly consented owned restore
must remain available during that fast-revert switch.

The next occurrence reserves one checked checkpoint CAS. Its fixed A02 handler
must call `enter_lifecycle` exactly once. `complete_lifecycle` records an entered
effect's one correlated completion CAS before another occurrence can reserve;
repeated action names remain distinct. Invocation identity is never reconstructed
from a checkpoint after lost acknowledgement. The final pointer-changing handler
calls `replace_lifecycle_pointer`: it rechecks the full original binding under
the root lock and CASes the **reviewed pointer revision**, not the checkpoint
revision. Success terminates the session. A02 owns actual fixed handlers; C02
owns durable state and OS/root locking.

Cancellation before pointer CAS leaves the pointer unchanged. CAS before cancel
retains the actual new generation/revision in `reconcile_lifecycle_pointer`;
there is no automatic reverse CAS. `reconcile_lifecycle` reads issued occurrence
facts after cancellation, expiry or revision exhaustion without renewing entry.
Late entered-effect completion can record factual progress after expiry/cancel
but cannot reopen a finished invocation or restore dispatch. Cancellation and
reconciliation allocate no numeric revision.

Every admission boundary observes the supplied trusted host clock against the
registry-owned scope before validating caller projections or invoking host
callbacks. Finite forward progress is retained even when a subsequent check or
callback fails. Observed expiry or backwards progression permanently retires
that operation/lifecycle scope: an earlier subsequent time cannot revive its
receipt, session, permit or final pointer CAS. Deadlines are never clamped,
renewed or replaced. Malformed input revokes only the scope resolved from actual
private authority, never another scope named by a caller's projection.
Outstanding issued facts remain readable; monotonically timed late factual
completion remains available after expiry or revocation, without granting new
entry or dispatch. Operational completion still retires its pending receipt.

### Closed lifecycle content and observation records

All objects below are exact `FrozenObject` values; sequences are tuples.
`content` requires exactly `schema="1.0"`, `steps`, `verification`, `pins`,
`cancel_scope`. The cancellation scope is the complete ordered occurrence-ID
tuple. No field is an optional wildcard: use explicit `None` where specified.

Each step requires `occurrence_id`, `generation_id`, `source`, `destination`,
`reuse`, `consequential`. `lifecycle_arguments_digest(step)` hashes every step
field except `occurrence_id`; it must match the corresponding occurrence's
`arguments_digest`. Steps match the complete occurrence order.

| Record | Exact fields and constraints |
| --- | --- |
| Source | `source_id`, `registry_digest`, `artifact_digest`, `descriptor_digest`; all digests SHA256 and registry identity exact. `descriptor_digest` identifies the complete approved nonsecret source descriptor, not just its display name. |
| Destination | `resource_id`, `root_resource_id`, `segments`, `manifest_digest`; exact occurrence resource and owned root. Nonempty relative path components forbid traversal, separators, drive syntax, trailing dot/space and Windows reserved device names. A02 still owns actual filesystem/symlink/OS-lock enforcement. |
| Reuse | `kind="owned"\|"external"`, `resource_id`, `generation_id`, `content_digest`, `manifest_digest`. Owned reuse requires an exactly matching observed owned generation. External reuse has `generation_id=None`, is a read source only and cannot be the destination. |
| Pin | `generation_id`, `manifest_digest`, checked `revision`, ordered unique `holders`. Uninstall binds all selected generations' exact pins in order and requires no holders. Other kinds require an empty pin tuple. Removing the active generation without an explicit final switch to a retained nonremoved generation rejects. |
| Verification | `kind="candidate"\|"retained"`, `event_kind="CandidateVerified"`, event UUID, checked `revision`, `generation_id`, `content_digest`, `manifest_digest`, `context_digest`, `registry_digest`, `policy_digest`, `qualification_digest`, finite float `observed_at`/`expires_at`, nonempty `probes`. All identities match the reviewed binding. |
| Probe | `probe_id`, `generation_id`, `content_digest`, `context_digest`, `result_digest`, `status="succeeded"`. IDs are unique. Failed/missing/unbound probes never count as verification. |

Download requires a source and owned destination, with no reuse. Stage requires
an owned destination and exactly one of source/reuse. Verify and uninstall
require an owned destination with neither source nor reuse. Probe and pointer
effects accept none of these three arguments. Every uninstall removal names a
selected owned generation and its manifest. Consequential categories on each
step must exactly reproduce the separately prompted category/occurrence
requirements; adding a category while omitting its receipt is invalid.

An unverified install-preparation plan may have `verification=None`, never an
activation effect. Activation requires candidate verification; restore requires
retained verification and exactly one pointer effect. New verification/probe
records change the plan identity and require fresh planning and consent.
An uninstall final switch also requires retained verification; it cannot select
a generation its removal steps remove. Verification validity is rechecked at issue, consume, reservation, entry and
final CAS; neither probes nor consent have their original deadline renewed.

`LifecycleEvidence` (from `policy.lifecycle_evidence`) requires `root`,
`generations`, `steps`, `pins`, `verification`. `LifecycleSnapshot.evidence`
defaults to `None` **only to fail closed for unmigrated hosts**. The host state
adapter must independently read current registry/source descriptors,
owned-destination manifests, reuse content, reference pins and correlated
verification/probe records while holding the same root lock. Copying plan data
into an observation is not a production collector. Exact descriptor equality
and owned-generation identities are independently rechecked before a state
change. A policy allow derived from caller-supplied booleans cannot replace
these observations.

`LifecycleAdmissionTelemetry` pairs its local `policy_decisions_total` counter
with one structured `policy.rejected` log in the same helper. Dimensions are
`outcome=Rejected`, `stage=lifecycle-admission`, closed `kind`, and safe `cause`
(`consent-stale`, `policy-input-invalid`, `evidence-mismatch`). Invalid kinds
become `unknown`; no supplied data is rendered. `counters()` returns detached
kind/cause/count rows for the host's metrics exporter. It does not initialize
an exporter, listener or logging configuration. Admission/entry/CAS/completion
rejections emit once at the outer boundary, not again at individual checks.
Trusted snapshot bindings undergo structural and numeric validation before exact
identity comparison. Well-formed identity drift revokes pending authority and
raises `AuthorizationError` with one `consent-stale` rejection pair, even when
that drift also invalidates the old content's correlations. Malformed numeric
snapshot fields still raise `ContractError`, revoke pending authority and emit
one `policy-input-invalid` pair. Neither path reserves an effect or changes a
pointer; restoring the old snapshot does not revive revoked authority.

`tests/policy/test_lifecycle_admission_completion.py` contains in-memory closed
evidence negatives, exact-observation drift at each admission boundary, paired
telemetry and **real packaged evaluator → broker** tests for preparation,
uninstall, restore and verified activation. Those tests pass the actual decision,
including its transition descriptor, rather than a fabricated `DecisionResult`.
They do not qualify a real dependency-service orchestration, handler,
process-stop latency, durable store, platform or controller.

The original `test_a01_lifecycle_admission.py` fixtures now supply closed content
and independent typed observations while retaining their original assertions.
No empty-evidence compatibility bypass is provided.

Import the concrete broker directly from
`netops.ansible.policy.authorization`. Shared package exports and the C01
protocols remain unchanged. This is a bounded toolkit Python implementation,
not an upstream Praxis Python API or foundation-compliance claim.

## Host bootstrap and private API

The host constructs `TrustedConsentAdapter(reviewer: ConsentReviewPort)` and
`AuthorizationBroker(state: AdmissionStatePort, consent: TrustedConsentAdapter)`.
Do not expose either object as a public request/JSON adapter.

`bind_plan(plan, root_ref, generation) -> PlanBinding` validates the complete
plan digest and derives the operational projection. It is not authorization.
The host supplies the exact current owned root and generation, not user-selected
permission JSON. The projection binds context, controller, complete routes,
inputs, observations, policy, plan and ordered recovery descriptors.

`ConsentReviewPort.confirm(plan, binding, deadline) -> bool` is the application's
trusted interactive/authenticated local API prompt. Only that injected adapter's
exact `True` response lets `TrustedConsentAdapter.review(plan, binding, now,
duration)` create a private receipt. No caller assertion or nominal receipt
subclass is trusted. Duration must fit the plan deadline and produce a finite,
strictly future monotonic deadline. The receipt is spent by successful issuance.

The operational methods retain the frozen signatures:

```python
issue(plan: OperationPlan, consent: ConsentReceipt,
      decision: DecisionResult, now: float) -> Authorization
consume(authorization: Authorization, binding: PlanBinding,
        now: float) -> AdmissionSession
permit(session: AdmissionSession, binding: EffectBinding,
       now: float) -> EffectPermit
revoke(operation_id: str) -> None
```

Decisions must allow the exact ordered `request_effect{kind}` descriptors.
Preconditions must be empty. Every grant, session and permit is nominal,
memory-only, registered by identity with its issuing host and unhydratable.
Repr contains only `<private>`; copy, pickle and public serialization reject.
Bindings and effect records are detached from caller-owned frozen objects.
Consumption never extends the original deadline.

`AdmissionStatePort` provides:

* `lock(operation_id)` — a context manager shared by **all** current-state
  writers, including external cancellation.
* `snapshot(operation_id) -> AdmissionSnapshot(binding, revision, cancelled,
  dispatch_enabled)` — trusted, current host evidence. `dispatch_enabled` is
  the host's applicable safety/kill-switch projection, not default readiness.
* `compare_revision(operation_id, expected_revision, next_revision) -> bool` —
  exact CAS under that lock; false leaves state unchanged.

The broker takes its own lock before the host lock. Host implementations must
not call back into the broker while holding their state lock. No concrete
owned-file/OS-lock implementation is supplied by this increment.

## Reservation, handler entry and factual completion

`permit` reserves only the next exact occurrence/target/step/recovery tuple.
Repeated action names remain distinct; skipped, reordered, replayed and
cross-session duplicate occurrences reject. Reservation advances the checked
host revision once and records the UUID event. A lost acknowledgement must not
reconstruct or retry the reservation.

Before entering its fixed handler, the A02 host must call
`enter(permit, exact_effect_binding, now) -> bool`. It consumes that reservation's
entry eligibility once, rechecking current binding, deadline, cancellation and
kill switch. A cancel linearized before entry prevents entry. An entry
linearized first is already-issued work and may require uncertain-state
reconciliation; cancellation does not pretend to undo it.

`complete(permit, event_id, expected_revision, now)` accepts one correlated
entered-effect completion with its own checked revision CAS. It never removes
revocation. Factual late completion remains recordable after authority expires;
it cannot renew the session. `reconcile(permit) -> EffectBinding` returns a
detached pending receipt without authorizing entry or allocating a revision,
including after cancellation, expiry or exhaustion.

All time arguments are exact finite, nonnegative floats, never integer/string
coercions. Backward host time rejects. All revision/generation/ordinal values
are exact bounded nonnegative integers, excluding booleans. MAX−1 advances once
to MAX; any required next increment at MAX rejects unchanged and revokes pending
admissions. Cancel, host kill and read-only reconciliation require no increment.
`AuthorizationError` reports safe `consent-stale`; numeric/input failures retain
internal cause `policy-input-invalid`, not a new public exit.

## Verification boundary and remaining work

Owned tests use memory state, a fake trusted review port, barriers and threads.
They do not prove OS-lock persistence, controller dispatch, process/listener
containment, stop-within-two-seconds, platform or device qualification.

Implementation self-checks are not independent acceptance. The typed lifecycle
methods, private receipts, closed evidence validation and paired local rejection
telemetry are implemented; actual host evidence collection and fixed-handler
integration remain later owners' work. A single evaluator decision must cover
the exact executable occurrence sequence being admitted; one next-effect
decision cannot authorize an arbitrary longer plan. Full DependencyService
composition and independent LA01–LA06 acceptance remain unclaimed.

Integration follow-up: merge this API description into `docs/api/ansible.md`
and the component architecture documentation after coordinating their ownership.
Wire real host locks/current evidence and fixed handlers in A02; independently
test/review all resulting source hashes before accepting any A01 claim.
