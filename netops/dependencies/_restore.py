"""Qualified retained restore over the actual managed host and private broker.

Qualification descriptors are host-supplied, pinned owned facts, not generated
by this coordinator. Unit functional ports never certify a real platform.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol
from uuid import uuid4

from netops.ansible import contracts as c
from netops.ansible.artifacts import OwnedRecord
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    bind_lifecycle,
    lifecycle_plan_digest,
)
from netops.ansible.policy.lifecycle_evidence import lifecycle_arguments_digest, validate_current

from ._assets import _MonotonicClock
from ._lifecycle import InstallOutcome, InstallStepOutcome, _error, _observe
from ._recovery import RecoveryStore

if TYPE_CHECKING:
    from ._composition import ManagedLifecycleState
    from .service import DependencyService

__all__: tuple[str, ...] = ()


@dataclass(frozen=True)
class ManagedQualification:
    """Exact externally qualified tuple; absent descriptors always block restore."""

    generation_binding: lc.GenerationBinding
    scope: c.InstallScope
    context: c.InstallContext
    consuming_contexts: tuple[str, ...]
    report_digest: str
    qualification_digest: str

    @property
    def generation(self) -> lc.GenerationBinding:
        """Keep generation DTOs distinct from exact numeric checkpoint fields."""
        return self.generation_binding

    def __post_init__(self) -> None:
        """Reject incomplete or moving qualification identities."""
        c.uuid_text(self.generation.generation_id)
        c.counter(self.generation.ordinal)
        c.sha256(self.generation.content_digest)
        c.sha256(self.generation.manifest_digest)
        if self.generation.selected or type(self.scope) is not c.InstallScope or type(self.context) is not c.InstallContext:
            raise c.ContractError()
        self.scope.__post_init__()
        self.context.__post_init__()
        c.unique(self.consuming_contexts)
        for digest in self.consuming_contexts:
            c.sha256(digest)
        c.sha256(self.report_digest)
        c.sha256(self.qualification_digest)


class GenerationRunsPort(Protocol):
    """Host-owned run admission/pins; draining must retain approved recovery."""

    def pins(self) -> tuple[lc.FrozenObject, ...]:
        """Read exact durable root-owned pin observations."""
        ...

    def stop_admission(self) -> None:
        """Stop new owned runs without revoking already approved recovery."""
        ...

    def drain(self, cancel: c.CancelPort, clock: c.ClockPort, deadline: float) -> bool:
        """Cancel owned work, retain recovery, and join it within the deadline."""
        ...

    def start_admission(self, generation: lc.GenerationBinding) -> None:
        """Reopen only after the selected generation passed its postcheck."""
        ...


def qualification(
    host: ManagedLifecycleState, generation: lc.GenerationBinding,
) -> ManagedQualification:
    """Resolve one immutable root-pinned exact qualification, never infer one."""
    host._facts()
    matches = tuple(item for item in host.qualifications if item.generation == generation)
    if len(matches) != 1:
        raise AuthorizationError()
    item = matches[0]
    item.__post_init__()
    retained = RecoveryStore(host).retained(generation)
    if (
        retained.scope != item.scope or retained.context != item.context
        or retained.consuming_contexts != item.consuming_contexts
    ):
        raise AuthorizationError()
    return item


def plan_restore(
    host: ManagedLifecycleState, generation_id: str, context: c.InstallContext,
    service: DependencyService,
) -> lc.RestorePlan:
    """Plan from retained descriptors only, without running either interpreter."""
    c.uuid_text(generation_id)
    if type(context) is not c.InstallContext or host.runs is None:
        raise c.ContractError()
    started = c.finite(service.clock.monotonic())
    with host._mutex, host._state.lock((host._facts_resource,), 0.0):
        root = host._facts()
        matches = tuple(item for item in host.manifests if item.generation_id == generation_id)
        if len(matches) != 1:
            raise AuthorizationError()
        manifest = matches[0]
        generation = lc.GenerationBinding(generation_id, 0, manifest.content_digest, c.digest(manifest))
        item = qualification(host, generation)
        if (
            context != item.context or context.context.policy_identity != service._policy_identity
            or context.context.registry_digest != service.registry.digest
        ):
            raise AuthorizationError()
        pointer = host._pointer_locked()
        if type(pointer) is not lc.PresentPointer or pointer.active_generation_id == generation_id:
            raise AuthorizationError()
        pins = host.runs.pins()
        expected_ids = (generation_id, pointer.active_generation_id)
        if (
            type(pins) is not tuple or len(pins) != 2
            or tuple(pin["generation_id"] for pin in pins) != expected_ids
        ):
            raise AuthorizationError()
        for pin in pins:
            manifests = tuple(value for value in host.manifests if value.generation_id == pin["generation_id"])
            if len(manifests) != 1 or pin["manifest_digest"] != c.digest(manifests[0]):
                raise AuthorizationError()
        verification = host._retained_verification(generation)
        probes = verification["probes"]
        if type(probes) is not tuple or len(probes) != 1:
            raise AuthorizationError()
        if (
            verification["qualification_digest"] != item.qualification_digest
            or c.public_object(probes[0])["result_digest"] != item.report_digest
        ):
            raise AuthorizationError()
        step = c.public_object({
            "occurrence_id": "restore-active-pointer", "generation_id": generation_id,
            "source": None, "destination": None, "reuse": None, "consequential": (),
        })
        effect = lc.LifecycleEffectOccurrence(
            "restore-active-pointer", 0, "restore-active-pointer", root.resource_id,
            "restore-active-pointer", lifecycle_arguments_digest(step),
        )
        identifier = str(uuid4())
        plan = lc.RestorePlan(
            "1.0", identifier, identifier, "0" * 64, c.digest(context),
            lc.OwnedRootBinding(root.resource_id, c.digest(c.public_object(root.payload["root_manifest"]))),
            generation, pointer, service._policy_identity, service.registry.digest,
            item.qualification_digest, (effect,), (), c.public_object({
                "schema": "1.0", "steps": (step,), "verification": verification,
                "pins": pins, "cancel_scope": (effect.occurrence_id,),
            }), "restore",
        )
        plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
        binding = bind_lifecycle(plan)
        snapshot = host.snapshot_lifecycle(binding)
        validate_current(binding, snapshot.evidence, c.finite(service.clock.monotonic()))
        if not snapshot.owned_valid or c.finite(service.clock.monotonic()) - started >= 60.0:
            raise AuthorizationError()
        return plan


class ManagedRestore:
    """One actual retained-pointer operation; no downloads or reverse CAS."""

    def __init__(
        self, host: ManagedLifecycleState, service: DependencyService,
        plan: lc.RestorePlan, consent: lc.InstallConsent, cancel: c.CancelPort,
    ) -> None:
        self.host, self.service, self.plan = host, service, plan
        binding = bind_lifecycle(plan)
        if type(binding) is not lc.RestoreBinding:
            raise c.ContractError()
        self.binding = binding
        self.consent, self.cancel = consent, cancel
        self.clock = _MonotonicClock(service.clock)
        if type(service.authorization) is not AuthorizationBroker:
            raise AuthorizationError()
        self.broker: AuthorizationBroker = service.authorization
        self.scope = self.broker._life_scope(consent)
        self.item = qualification(host, binding.generation)
        self.report: c.ReadinessReport | None = None

    def probe(self, *, retained: bool = True) -> c.ReadinessReport:
        """Revalidate the exact retained file and consuming tuple, never current."""
        if (
            self.scope is None
            or c.digest(self.item.context) != self.binding.context_digest
            or tuple(sorted(item.digest for item in self.service._contexts().values()))
            != self.item.consuming_contexts
        ):
            raise AuthorizationError()
        manifest = self.host._manifest(self.binding)
        if manifest.bootstrap_digest is not None:
            self.host.guard_source(manifest, self.clock, self.cancel, self.scope.deadline)
        self.host.files.verify(manifest, self.clock, self.cancel, self.scope.deadline)
        if manifest.bootstrap_digest is not None:
            self.host.guard_source(manifest, self.clock, self.cancel, self.scope.deadline)
        report = self.service.verify(self.item.scope, self.item.context)
        if (
            c.digest(report) != self.item.report_digest
            or any(value not in ("ready", "not-requested") for value in (
                report.readiness.native, report.readiness.companion, report.readiness.enhanced,
            ))
        ):
            raise AuthorizationError()
        self.report = report
        return report

    def _completed(
        self, state: lc.PolicyState, initial: lc.DecisionEvent,
        facts: lc.DecisionFacts, checkpoint: OwnedRecord,
    ) -> None:
        """Record the factual CAS before cancel or postcheck can report failure."""
        if type(checkpoint) is not OwnedRecord:
            raise c.ContractError()
        binding = self.binding
        effect = binding.effects[0]
        pending = state.dispositions[0]
        event = replace(initial, event_id=str(uuid4()), kind=lc.EventKind.STEP_COMPLETED,
                        expected_revision=state.revision, payload=c.public_object({
                            "invocation_id": pending.invocation_id, "effect_id": effect.occurrence_id,
                            "target_id": effect.resource_id, "step_id": effect.step_id,
                            "safe_result_digest": c.digest((binding.generation, self.host.pointer())),
                            "primary": "success", "cleanup": "success", "remote_uncertain": False,
                        }))
        values = {**dict(facts.values), "lifecycle": {"next_effect_kind": "none"},
                  "change": {"poststate_verified": False},
                  "result": {"selected": 1, "completed": 1, "unsuccessful": 0, "failed": 0,
                             "cancelled": 0, "unsupported": 0, "blocked": 0,
                             "policy_failed": False, "cleanup_failed": False, "remote_uncertain": False}}
        final = self.service.policy.reduce(
            state, event, lc.DecisionFacts(c.public_object(values), lc.Phase.ADMITTED, state.revision),
        )
        if final.decision.decision != "allow" or final.next_state.revision != state.revision + 1:
            raise AuthorizationError()
        self.host._checkpoint(binding, final.next_state, event, checkpoint)

    def execute(self) -> InstallOutcome:
        """Stop admission, drain owned pins, revalidate/CAS once and postcheck."""
        binding, host, broker = self.binding, self.host, self.broker
        effect = binding.effects[0]
        started = c.finite(self.clock.monotonic())
        errors: list[c.SafeError] = []
        cleanup: list[c.SafeError] = []
        committed = False
        permit: lc.LifecycleEffectPermit | None = None
        uncertain = False
        admission_stopped = False
        observation_stage: str | None = None
        try:
            if self.cancel.is_cancelled():
                raise InterruptedError()
            if (
                host.runs is None or self.scope is None or self.scope.binding != binding
                or broker._lifecycle_state is not host
            ):
                raise AuthorizationError()
            now = c.finite(self.clock.monotonic())
            remaining = max(0, int((self.scope.deadline - now) * 1000))
            event = lc.DecisionEvent(
                str(uuid4()), lc.EventKind.INSTALL_CONSENTED, 0, binding.plan_digest,
                binding.context_digest, binding.policy.bundle_sha256,
                binding.root.resource_id, effect.step_id, c.public_object({
                    "lifecycle_kind": "restore", "plan_id": binding.plan_id,
                    "lifecycle_binding_digest": c.digest(binding),
                    "private_consent_reference": "host-private-lifecycle",
                }), install_id=binding.lifecycle_id,
            )
            facts = lc.DecisionFacts(c.public_object({
                "binding": {"input_valid": True, "plan_current": True, "policy_current": binding.policy == self.service._policy_identity},
                "request": {"area": "setup", "operation": "restore", "mode": "apply"},
                "control": {"cancelled": False, "remaining_ms": remaining},
                "consent": {"present": True, "binding_matches": True, "effects_match": True, "recovery_matches": True, "remaining_ms": remaining},
                "consequential": {"required": False, "granted": False},
                "ownership": {"valid": True},
                "candidate": {"verified": True, "retained_owned": True, "pointer_matches": True},
                "lifecycle": {"next_effect_kind": "restore-active-pointer"},
            }), lc.Phase.PLANNED, 0)
            state = lc.PolicyState(
                binding.policy, binding.lifecycle_id, 0, lc.Phase.PLANNED,
                binding.plan_digest, binding.context_digest, binding.policy.bundle_sha256,
                (lc.StepDisposition(binding.root.resource_id, effect.step_id,
                                    invocation_id=str(uuid4()), effect_id=effect.occurrence_id),),
                namespace="install",
            )
            transition = self.service.policy.reduce(state, event, facts)
            grant = broker.issue_lifecycle(self.plan, self.consent, transition.decision, now)
            session = broker.consume_lifecycle(grant, binding, now)
            checkpoint = host._checkpoint(binding, transition.next_state, event, None)
            current = host.snapshot_lifecycle(binding)
            occurrence = lc.LifecycleEffectBinding(binding, str(uuid4()), current.revision, effect.occurrence_id)
            permit = broker.permit_lifecycle(session, occurrence, c.finite(self.clock.monotonic()))
            broker.enter_lifecycle(permit, occurrence, c.finite(self.clock.monotonic()))
            # Broker -> root is the universal lock order. A nested call in this
            # same thread uses the already held OS lock, never reacquires it.
            with broker._lock, host.lock_lifecycle(binding):
                host._set_admission(False)
                host.runs.stop_admission()
                admission_stopped = True
                pins = host.runs.pins()
            # Joining an old run while holding root/broker locks would block
            # that run's already-authorized recovery. Drain outside both.
            if not host.runs.drain(self.cancel, self.clock, min(self.scope.deadline, started + 300.0)):
                raise AuthorizationError()
            with broker._lock, host.lock_lifecycle(binding):
                current_pins = host.runs.pins()
                host._validate_drained_pins(pins, current_pins)
                if self.cancel.is_cancelled():
                    raise InterruptedError()
                self.probe()
                broker.replace_lifecycle_pointer(permit, c.finite(self.clock.monotonic()))
                committed = True
                current = host.snapshot_lifecycle(binding)
                broker.complete_lifecycle(permit, str(uuid4()), current.revision, c.finite(self.clock.monotonic()))
                self._completed(transition.next_state, event, facts, checkpoint)
                if self.cancel.is_cancelled():
                    raise InterruptedError()
                self.probe()
                if self.cancel.is_cancelled():
                    raise InterruptedError()
                if c.finite(self.clock.monotonic()) >= self.scope.deadline:
                    raise TimeoutError()
                host.runs.start_admission(binding.generation)
                host._set_admission(True)
                admission_stopped = False
        except (Exception, KeyboardInterrupt) as exc:
            broker.revoke_lifecycle("restore", binding.plan_id)
            if not isinstance(exc, (InterruptedError, KeyboardInterrupt, AuthorizationError, TimeoutError)):
                observation_stage = "Unhandled"
            cancelled = isinstance(exc, (InterruptedError, KeyboardInterrupt))
            try:
                cancelled = cancelled or self.cancel.is_cancelled()
            except Exception:
                pass
            reason = c.ReasonCode.CANCELLED if cancelled else (
                c.ReasonCode.CONSENT_STALE if isinstance(exc, AuthorizationError) else c.ReasonCode.PROVISION_FAILED
            )
            errors.append(_error(reason, c.ErrorCategory.PRECONDITION, c.Stage.FINALIZE,
                                 "Admission remains stopped; inspect actual pointer and review new restore consent.",
                                 effect.step_id))
            # Any failed postcheck or late cancellation keeps admission off.
            if committed:
                try:
                    with host.lock_lifecycle(binding):
                        host._set_admission(False)
                    if host.runs is not None:
                        host.runs.stop_admission()
                    admission_stopped = True
                except Exception:
                    uncertain = True
                    cleanup.append(_error(c.ReasonCode.OWNERSHIP_INVALID, c.ErrorCategory.CLEANUP,
                                          c.Stage.FINALIZE, "Inspect stopped admission and protected pointer."))
        active = None
        revision = None
        try:
            pointer = host.pointer()
            revision = pointer.revision
            if type(pointer) is lc.PresentPointer:
                active = pointer.active_generation_id
            if permit is not None:
                try:
                    actual = broker.reconcile_lifecycle_pointer(permit)
                    committed = actual == (binding.generation.generation_id, revision)
                except AuthorizationError:
                    pass
        except Exception:
            uncertain = True
        status = c.OutcomeStatus.SUCCEEDED if not (errors or cleanup or uncertain) else (
            c.OutcomeStatus.PARTIAL if committed else (
                c.OutcomeStatus.CANCELLED if errors and errors[0].reason == c.ReasonCode.CANCELLED else c.OutcomeStatus.BLOCKED
            )
        )
        step_status = c.OutcomeStatus.SUCCEEDED if committed else status
        try:
            duration = max(0.0, c.finite(self.clock.monotonic()) - started)
        except Exception:
            duration = 0.0
        _observe(binding, effect, step_status, duration,
                 errors[0] if errors else None, self.service.events, stage=observation_stage)
        return InstallOutcome(
            binding.lifecycle_id, binding.plan_id, "restore", status,
            (InstallStepOutcome(effect.occurrence_id, effect.step_id, effect.kind, step_status, committed),),
            self.report.readiness if status == c.OutcomeStatus.SUCCEEDED and self.report is not None else c.ReadinessProjection(),
            binding.generation.generation_id, active,
            binding.expected_pointer.active_generation_id if committed and type(binding.expected_pointer) is lc.PresentPointer else None,
            tuple(errors), tuple(cleanup), ("review-new-exact-restore",) if admission_stopped else (),
            uncertain, revision, selected_scope=self.item.scope,
        )
