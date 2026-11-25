"""Service coordination for the admitted owned-resource lifecycle.

This module does not turn A02's inert byte handler into a package installer or
turn its byte probe into controller qualification. Host composition must supply
the exact owned state used by the broker. Persisted facts are never consent.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING
from uuid import uuid4

from netops.ansible import contracts as c
from netops.ansible.artifacts import ArtifactError
from netops.ansible.lifecycle_execution import (
    LifecycleExecutor,
    LifecycleHandlerReceipt,
    OwnedLifecycleState,
)
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    bind_lifecycle,
    lifecycle_plan_digest,
)
from netops.ansible.policy.lifecycle_evidence import EvidenceMismatch, validate_current

if TYPE_CHECKING:
    from .service import DependencyService

__all__: tuple[str, ...] = ()

from ._recovery import RecoverySelection, RecoveryStore

_LOG = logging.getLogger(__name__)
_STEP_EVENT = "install.step"
_STEP_METRIC = "netops.install.step.count"
_UNHANDLED = "Unhandled"


@dataclass(frozen=True)
class InstallStepOutcome:
    """One selected occurrence, including work never entered after a failure."""

    occurrence_id: str
    step_id: str
    kind: lc.LifecycleEffectKind
    status: c.OutcomeStatus
    changed: bool = False
    error: c.SafeError | None = None


@dataclass(frozen=True)
class InstallOutcome:
    """Factual lifecycle result; selection, cleanup and uncertainty stay separate."""

    installation_id: str
    plan_id: str
    kind: lc.LifecycleKind
    status: c.OutcomeStatus
    steps: tuple[InstallStepOutcome, ...]
    readiness: c.ReadinessProjection
    candidate_generation_id: str
    active_generation_id: str | None
    previous_generation_id: str | None
    errors: tuple[c.SafeError, ...] = ()
    cleanup_errors: tuple[c.SafeError, ...] = ()
    pending_actions: tuple[str, ...] = ()
    uncertain: bool = False
    pointer_revision: int | None = None
    schema_version: str = "1.0"
    selected_scope: c.InstallScope | None = None
    original_errors: tuple[c.SafeError, ...] = ()
    remote_state: str = "not-requested"


def _error(
    reason: c.ReasonCode, category: c.ErrorCategory, stage: c.Stage,
    action: str, step: str | None = None,
) -> c.SafeError:
    return c.SafeError(category, reason, stage, step_id=step, next_action=action)


def _observe(
    binding: lc.LifecycleBinding, effect: lc.LifecycleEffectOccurrence,
    status: c.OutcomeStatus, duration: float, error: c.SafeError | None,
    events: c.EventPort, *, stage: str | None = None,
) -> None:
    """Pair log/counter dimensions in one non-authoritative, nonthrowing helper."""
    dimensions = {
        "metric_name": _STEP_METRIC, "metric_value": 1,
        "kind": binding.kind, "step_kind": effect.kind, "status": status.value,
        "stage": stage or ("activate" if effect.kind in (
            "dependency-activate", "restore-active-pointer",
        ) else "provision"),
        "category": error.category.value if error is not None else "none",
        "reason": error.reason.value if error is not None else "none",
        "next_action": error.next_action if error is not None else "none",
        "duration": duration,
        # IDs are log context, not counter labels.
        "operation_id": binding.lifecycle_id, "step_id": effect.step_id,
        "context_digest": binding.context_digest,
        "metric_labels": ("kind", "step_kind", "status", "stage", "category", "reason"),
    }
    try:
        _LOG.info(_STEP_EVENT, extra=dimensions)
    except Exception:
        pass
    try:
        events.emit(c.SafeEvent(
            binding.lifecycle_id, effect.step_id, binding.root.resource_id,
            binding.context_digest, c.Mode.APPLY, status,
            error.category if error is not None else None,
            error.reason if error is not None else None, False, duration,
        ))
    except Exception:
        pass


class DependencyLifecycle:
    """Own service-level admission and completion, never a second broker.

    The accepted A02 handler is deliberately limited to pre-owned inert assets.
    Unsupported host composition fails closed instead of silently constructing a
    broker, inventing ownership, acquiring packages or qualifying a controller.
    """

    def __init__(self, service: DependencyService) -> None:
        self.service = service
        self._mutex = threading.Lock()
        self._contexts: dict[str, c.InstallContext] = {}
        self._plans: dict[str, lc.InstallPlan] = {}
        self._last: dict[str, InstallOutcome] = {}

    def remember_context(self, context: c.InstallContext) -> None:
        """Retain only immutable request context, never a grant or readiness claim."""
        self._contexts[c.digest(context)] = context

    def _host(self) -> tuple[OwnedLifecycleState, AuthorizationBroker, LifecycleExecutor]:
        state = self.service.state
        broker = self.service.authorization
        if (
            type(state) is not OwnedLifecycleState or type(broker) is not AuthorizationBroker
            or broker._lifecycle_state is not state
        ):
            raise AuthorizationError()
        return state, broker, LifecycleExecutor(broker, state, self.service.clock)

    def _now(self) -> float:
        return c.finite(self.service.clock.monotonic())

    def _facts(
        self, binding: lc.LifecycleBinding, consent: lc.InstallConsent,
        index: int, cancel: c.CancelPort, revision: int,
    ) -> lc.DecisionFacts:
        state, broker, _ = self._host()
        now = self._now()
        snapshot = state.snapshot_lifecycle(binding)
        if not snapshot.owned_valid:
            raise ArtifactError(_error(
                c.ReasonCode.OWNERSHIP_INVALID, c.ErrorCategory.CLEANUP,
                c.Stage.FINALIZE, "Inspect owned metadata; do not adopt or remove unknown resources.",
            ))
        scope = broker._life_scope(consent)
        matches = scope is not None and scope.binding == binding
        remaining = max(0, int((scope.deadline - now) * 1000)) if scope is not None else 0
        grants = False
        if scope is not None and broker._lifecycle_consent is not None:
            try:
                broker._lifecycle_consent.validate(scope, now)
                grants = True
            except AuthorizationError:
                pass
        verified = False
        try:
            validate_current(binding, snapshot.evidence, now)
            verified = (
                snapshot.probes_valid and binding.content["verification"] is not None
            )
        except (c.ContractError, EvidenceMismatch):
            pass
        return lc.DecisionFacts(c.public_object({
            "binding": {
                "input_valid": True, "plan_current": snapshot.binding == binding,
                "policy_current": binding.policy == self.service._policy_identity,
            },
            "request": {"area": "setup", "operation": binding.kind, "mode": "apply"},
            "control": {"cancelled": cancel.is_cancelled() or snapshot.cancelled,
                        "remaining_ms": remaining},
            "consent": {
                "present": scope is not None, "binding_matches": matches,
                "effects_match": matches, "recovery_matches": matches,
                "remaining_ms": remaining,
            },
            "consequential": {"required": len(binding.required_consequential) != 0,
                              "granted": grants},
            "ownership": {"valid": snapshot.owned_valid},
            "candidate": {
                "verified": verified, "pointer_matches": snapshot.binding.expected_pointer == binding.expected_pointer,
                "retained_owned": snapshot.owned_valid and snapshot.pins_valid,
            },
            "lifecycle": {"next_effect_kind": binding.effects[index].kind},
        }), lc.Phase.PLANNED, revision)

    def _decision(
        self, binding: lc.LifecycleBinding, consent: lc.InstallConsent, cancel: c.CancelPort,
    ) -> lc.DecisionResult:
        """Evaluate every occurrence; aggregate intents do not grant any effect."""
        state, _, _ = self._host()
        revision = state.snapshot_lifecycle(binding).revision
        effects: list[lc.EffectDescriptor] = []
        rules: set[str] = set()
        reason = "policy-rejected"
        for index, effect in enumerate(binding.effects):
            event = lc.DecisionEvent(
                str(uuid4()), lc.EventKind.INSTALL_CONSENTED, revision,
                binding.plan_digest, binding.context_digest, binding.policy.bundle_sha256,
                binding.root.resource_id, effect.step_id, c.public_object({
                    "lifecycle_kind": binding.kind, "plan_id": binding.plan_id,
                    "lifecycle_binding_digest": c.digest(binding),
                    "private_consent_reference": "host-private-lifecycle",
                }), install_id=binding.lifecycle_id,
            )
            decision = self.service.policy.decide(
                event, self._facts(binding, consent, index, cancel, revision),
            )
            requested = tuple(item for item in decision.effects if item.name == "request_effect")
            wanted = (lc.EffectDescriptor(
                "request_effect", c.public_object({"kind": effect.kind}),
            ),)
            if decision.decision != "allow" or requested != wanted:
                raise AuthorizationError()
            effects.extend(requested)
            rules.update(decision.rule_ids)
            reason = decision.reason
        return lc.DecisionResult(
            "allow", tuple(sorted(rules)), reason, tuple(effects), binding.policy.bundle_sha256,
        )

    @staticmethod
    def _readiness_digest(binding: lc.LifecycleBinding) -> str:
        verification = binding.content["verification"]
        if type(verification) is not lc.FrozenObject:
            raise AuthorizationError()
        probes = verification["probes"]
        if type(probes) is not tuple:
            raise AuthorizationError()
        matching = tuple(probe for probe in probes if (
            type(probe) is lc.FrozenObject and probe["probe_id"] == "dependency-readiness"
        ))
        if len(matching) != 1:
            raise AuthorizationError()
        return c.sha256(c.public_object(matching[0])["result_digest"])

    def _reprobe(self, binding: lc.LifecycleBinding) -> c.ReadinessProjection:
        """Do not treat A02's inert-byte evidence as product/controller readiness."""
        state, _, _ = self._host()
        prior = RecoveryStore(state).retained(binding.generation)
        context = prior.context
        if (
            c.digest(context) != binding.context_digest
            or tuple(sorted(item.digest for item in self.service._contexts().values()))
            != prior.consuming_contexts
        ):
            # Do not execute the active interpreter to discover that it is not
            # the selected retained candidate. Identity checks precede probes.
            raise AuthorizationError()
        if binding.kind == "install":
            scope = binding.scope
            if scope != prior.scope:
                raise AuthorizationError()
        else:
            scope = prior.scope
        report = self.service.verify(scope, context)
        if any(value == "blocked" for value in (
            report.readiness.native, report.readiness.companion, report.readiness.enhanced,
        )):
            raise AuthorizationError()
        if self._readiness_digest(binding) != c.digest(report):
            # A ready re-probe with different evidence is still drift. In
            # particular A02's inert-byte probe must never activate a controller.
            raise AuthorizationError()
        return report.readiness

    def _unobserved_readiness(self, binding: lc.LifecycleBinding) -> c.ReadinessProjection:
        if type(binding) is not lc.InstallBinding:
            return c.ReadinessProjection()
        selected = self.service._selection(binding.scope)
        tiers = {operation.tier for operation in selected}
        return c.ReadinessProjection(
            "blocked" if "native" in tiers else "not-requested",
            "blocked" if "companion" in tiers else "not-requested",
            "blocked" if "enhanced" in tiers else "not-requested",
        )

    def execute(
        self, plan: lc.LifecyclePlan, consent: lc.InstallConsent, cancel: c.CancelPort,
        *, recovery: RecoverySelection | None = None,
    ) -> InstallOutcome:
        """Consume once, admit each occurrence, preserve factual CAS and failures."""
        from ._composition import ManagedLifecycleState

        if type(self.service.state) is ManagedLifecycleState:
            if type(plan) not in (lc.InstallPlan, lc.RestorePlan, lc.UninstallPlan) or recovery is not None:
                raise c.ContractError()
            assert isinstance(plan, (lc.InstallPlan, lc.RestorePlan, lc.UninstallPlan))
            return self.service.state.execute(plan, consent, cancel, self.service)
        binding = bind_lifecycle(plan)  # strict validation precedes any state/clock I/O
        state, broker, executor = self._host()
        if not self._mutex.acquire(blocking=False):
            return self._blocked(binding, c.ReasonCode.RESOURCE_BUSY)
        results: list[InstallStepOutcome] = []
        errors: list[c.SafeError] = []
        cleanup: list[c.SafeError] = []
        uncertain = False
        readiness = c.ReadinessProjection()
        receipt: LifecycleHandlerReceipt | None = None
        active: str | None = None
        pointer_revision: int | None = None
        selected = binding.effects[0]
        started = 0.0
        entered = False
        phase = "authorize"
        permit: lc.LifecycleEffectPermit | None = None
        try:
            if binding.policy != self.service._policy_identity or binding.registry_digest != self.service.registry.digest:
                raise AuthorizationError()
            readiness = self._unobserved_readiness(binding)
            if cancel.is_cancelled():
                executor.cancel(plan)
                raise InterruptedError()
            decision = self._decision(binding, consent, cancel)
            grant = broker.issue_lifecycle(plan, consent, decision, self._now())
            session = broker.consume_lifecycle(grant, binding, self._now())
            if type(plan) is lc.InstallPlan:
                if type(binding) is not lc.InstallBinding:
                    raise c.ContractError()
                context = self._contexts.get(binding.context_digest)
                if context is None:
                    raise AuthorizationError()
                report = self.service.verify(plan.scope, context)
                observed = RecoverySelection(
                    plan.lifecycle_id, plan.plan_id, plan.generation, plan.scope, context,
                    tuple(sorted(item.digest for item in self.service._contexts().values())),
                    c.digest(report),
                )
                if recovery is not None and (
                    observed.context != recovery.context or observed.scope != recovery.scope
                    or observed.consuming_contexts != recovery.consuming_contexts
                    or observed.observation_digest != recovery.observation_digest
                ):
                    raise AuthorizationError()
                RecoveryStore(state).save(binding, observed, recovery)
                self._plans[binding.lifecycle_id] = plan
            for selected in binding.effects:
                started = self._now()
                receipt = None
                entered = False
                permit = None
                phase = "provision"
                if cancel.is_cancelled():
                    executor.cancel(plan)
                    raise InterruptedError()
                if selected.kind in ("dependency-activate", "restore-active-pointer"):
                    phase = "activate"
                    readiness = self._reprobe(binding)
                current = state.snapshot_lifecycle(binding)
                effect = lc.LifecycleEffectBinding(
                    binding, str(uuid4()), current.revision, selected.occurrence_id,
                )
                permit = broker.permit_lifecycle(session, effect, self._now())
                # No effect has entered before the accepted host checks the permit.
                entered = True
                try:
                    receipt = executor.enter(permit, effect)
                    executor.complete(permit)
                except BaseException:
                    receipt = executor.reconcile(permit)
                    entered = permit in executor._pending
                    raise
                results.append(InstallStepOutcome(
                    selected.occurrence_id, selected.step_id, selected.kind,
                    c.OutcomeStatus.SUCCEEDED, receipt.changed,
                ))
                _observe(binding, selected, c.OutcomeStatus.SUCCEEDED,
                         max(0.0, self._now() - started), None, self.service.events)
                if cancel.is_cancelled():
                    # Completion and pointer facts survive cancellation after CAS.
                    executor.cancel(plan)
                    raise InterruptedError()
            if binding.effects[-1].kind in ("dependency-activate", "restore-active-pointer"):
                phase = "activate"
                readiness = self._reprobe(binding)
            elif binding.kind == "install":
                errors.append(_error(
                    c.ReasonCode.DEPENDENCY_NOT_READY, c.ErrorCategory.DEPENDENCY,
                    c.Stage.READINESS,
                    "Staging is complete; review a separately verified activation plan.",
                ))
        except (Exception, KeyboardInterrupt) as exc:
            broker.revoke_lifecycle(binding.kind, binding.plan_id)
            if isinstance(exc, (InterruptedError, KeyboardInterrupt)):
                error = _error(c.ReasonCode.CANCELLED, c.ErrorCategory.EXECUTION,
                               c.Stage.DISPATCH, "Inspect completed work; replan before resuming.")
                status = c.OutcomeStatus.CANCELLED
            elif isinstance(exc, AuthorizationError):
                error = _error(c.ReasonCode.CONSENT_STALE, c.ErrorCategory.PRECONDITION,
                               c.Stage.AUTHORIZE, "Reprobe and review a new exact plan.")
                status = c.OutcomeStatus.BLOCKED
            elif isinstance(exc, ArtifactError):
                error = exc.error
                cleanup.extend(exc.cleanup_errors)
                status = c.OutcomeStatus.FAILED
            else:
                error = _error(
                    c.ReasonCode.PROVISION_FAILED, c.ErrorCategory.DEPENDENCY,
                    c.Stage.PROVISION, "Inspect owned checkpoints and explicitly resume.",
                )
                status = c.OutcomeStatus.FAILED
            errors.append(error)
            if entered and receipt is None:
                uncertain = True
            if receipt is not None and not any(
                item.occurrence_id == selected.occurrence_id for item in results
            ):
                results.append(InstallStepOutcome(
                    selected.occurrence_id, selected.step_id, selected.kind,
                    c.OutcomeStatus.SUCCEEDED, receipt.changed,
                ))
            if not any(item.occurrence_id == selected.occurrence_id for item in results):
                results.append(InstallStepOutcome(
                    selected.occurrence_id, selected.step_id, selected.kind, status, error=error,
                ))
            try:
                duration = max(0.0, self._now() - started) if started else 0.0
            except Exception:
                duration = 0.0
            known = isinstance(exc, (
                InterruptedError, KeyboardInterrupt, AuthorizationError, ArtifactError,
                c.ContractError, EvidenceMismatch, OSError,
            ))
            _observe(binding, selected, status, duration, error, self.service.events,
                     stage=phase if known else _UNHANDLED)
        finally:
            try:
                pointer = state.pointer()
                pointer_revision = pointer.revision
                if type(pointer) is lc.PresentPointer:
                    active = pointer.active_generation_id
            except Exception:
                uncertain = True
                cleanup.append(_error(
                    c.ReasonCode.OWNERSHIP_INVALID, c.ErrorCategory.CLEANUP,
                    c.Stage.FINALIZE, "Inspect the protected pointer; do not adopt a directory.",
                ))
            self._mutex.release()
        done = {item.occurrence_id for item in results}
        results.extend(
            InstallStepOutcome(effect.occurrence_id, effect.step_id, effect.kind,
                               c.OutcomeStatus.BLOCKED)
            for effect in binding.effects if effect.occurrence_id not in done
        )
        order = {effect.occurrence_id: effect.ordinal for effect in binding.effects}
        results.sort(key=lambda item: order[item.occurrence_id])
        succeeded = any(item.status == c.OutcomeStatus.SUCCEEDED for item in results)
        unsuccessful = bool(errors or cleanup or uncertain) or any(
            item.status != c.OutcomeStatus.SUCCEEDED for item in results
        )
        if succeeded and unsuccessful:
            overall = c.OutcomeStatus.PARTIAL
        elif not unsuccessful:
            overall = c.OutcomeStatus.SUCCEEDED
        elif cleanup or uncertain or any(item.status == c.OutcomeStatus.FAILED for item in results):
            overall = c.OutcomeStatus.FAILED
        elif any(item.status == c.OutcomeStatus.CANCELLED for item in results):
            overall = c.OutcomeStatus.CANCELLED
        else:
            overall = c.OutcomeStatus.BLOCKED
        previous = (
            binding.expected_pointer.active_generation_id
            if type(binding.expected_pointer) is lc.PresentPointer
            and active != binding.expected_pointer.active_generation_id else None
        )
        pending_actions = tuple(effect.occurrence_id for effect in binding.effects if any(
            item.occurrence_id == effect.occurrence_id and item.status != c.OutcomeStatus.SUCCEEDED
            for item in results
        ))
        if binding.kind == "install" and binding.effects[-1].kind != "dependency-activate":
            pending_actions += ("review-activation-plan",)
        prior = self._last.get(binding.lifecycle_id)
        history = prior.original_errors + prior.errors if prior is not None else ()
        outcome = InstallOutcome(
            binding.lifecycle_id, binding.plan_id, binding.kind, overall, tuple(results),
            readiness, binding.generation.generation_id, active, previous,
            tuple(errors), tuple(cleanup),
            pending_actions, uncertain, pointer_revision,
            selected_scope=binding.scope if type(binding) is lc.InstallBinding else None,
            original_errors=history,
        )
        self._last[binding.lifecycle_id] = outcome
        return outcome

    def _blocked(self, binding: lc.LifecycleBinding, reason: c.ReasonCode) -> InstallOutcome:
        error = _error(reason, c.ErrorCategory.PRECONDITION, c.Stage.AUTHORIZE,
                       "Wait for the other writer, then review a new exact plan."
                       if reason == c.ReasonCode.RESOURCE_BUSY else
                       "Facts changed; replan and review a new exact consent before any effect.")
        effect = binding.effects[0]
        _observe(binding, effect, c.OutcomeStatus.BLOCKED, 0.0, error, self.service.events)
        return InstallOutcome(
            binding.lifecycle_id, binding.plan_id, binding.kind, c.OutcomeStatus.BLOCKED,
            tuple(InstallStepOutcome(item.occurrence_id, item.step_id, item.kind,
                                    c.OutcomeStatus.BLOCKED, error=error)
                  for item in binding.effects),
            self._unobserved_readiness(binding), binding.generation.generation_id, None, None, (error,),
            pending_actions=(
                ("review-new-exact-plan",) if reason == c.ReasonCode.CONSENT_STALE else ()
            ) + tuple(item.occurrence_id for item in binding.effects),
        )

    def resume(
        self, install_id: str, consent: lc.InstallConsent, cancel: c.CancelPort,
    ) -> InstallOutcome:
        """Require a newly reviewed plan, never reconstruct authority from history."""
        c.uuid_text(install_id)
        state, broker, _ = self._host()
        scope = broker._life_scope(consent)
        if scope is None:
            raise AuthorizationError()
        previous = RecoveryStore(state).read(install_id)
        binding = scope.binding
        if (
            type(binding) is not lc.InstallBinding or binding.lifecycle_id != install_id
            or binding.plan_id == previous.plan_id
        ):
            raise AuthorizationError()
        # Re-probe completed dependencies before taking a fresh install admission.
        context = previous.context
        if c.digest(context) != binding.context_digest or binding.scope != previous.scope:
            raise AuthorizationError()
        report = self.service.verify(binding.scope, context)
        current_contexts = tuple(sorted(item.digest for item in self.service._contexts().values()))
        if (
            c.digest(report) != previous.observation_digest
            or current_contexts != previous.consuming_contexts
        ):
            broker.revoke_lifecycle(binding.kind, binding.plan_id)
            return self._blocked(binding, c.ReasonCode.CONSENT_STALE)
        self.remember_context(context)
        values = {name: getattr(binding, name) for name in lc.InstallBinding.__dataclass_fields__}
        plan = lc.InstallPlan(**values)
        return self.execute(plan, consent, cancel, recovery=previous)

    def plan_restore(self, generation_id: str, context: c.InstallContext) -> lc.RestorePlan:
        """Inspect retained owned metadata only; never execute the active generation."""
        c.uuid_text(generation_id)
        if type(context) is not c.InstallContext:
            raise c.ContractError()
        self.remember_context(context)
        from ._composition import ManagedLifecycleState
        from ._restore import plan_restore

        if type(self.service.state) is ManagedLifecycleState:
            return plan_restore(self.service.state, generation_id, context, self.service)
        state, _, _ = self._host()
        deadline = self._now() + 60.0

        def check_budget() -> None:
            if self._now() >= deadline:
                raise AuthorizationError()

        # This reader deliberately uses the accepted owned-record validators.
        # No missing file or directory can become an ownership record.
        facts = state._facts()
        data = facts.payload
        check_budget()
        pointer = state.pointer()
        if type(pointer) is not lc.PresentPointer:
            raise AuthorizationError()
        refs = data["generation_refs"]
        if type(refs) is not tuple or len(refs) > 128:
            raise c.ContractError()
        candidates = []
        for ref in refs:
            check_budget()
            candidates.append(state._generation(c.text(ref)))
        check_budget()
        matches = tuple(item for item in candidates if item.generation_id == generation_id)
        if len(matches) != 1:
            raise AuthorizationError()
        verification_ref = data["verification_ref"]
        if verification_ref is None:
            raise AuthorizationError()
        verification = state._read(c.text(verification_ref)).payload
        check_budget()
        step_refs = data["step_refs"]
        if type(step_refs) is not tuple or len(step_refs) != 1:
            raise AuthorizationError()
        step = state._read(c.text(step_refs[0])).payload
        check_budget()
        from netops.ansible.policy.lifecycle_evidence import lifecycle_arguments_digest

        occurrence = c.text(step["occurrence_id"])
        effect = lc.LifecycleEffectOccurrence(
            occurrence, 0, "restore-active-pointer", facts.resource_id,
            "restore-active-pointer", lifecycle_arguments_digest(step),
        )
        plan_id = str(uuid4())
        plan = lc.RestorePlan(
            "1.0", plan_id, plan_id, "0" * 64, c.digest(context),
            lc.OwnedRootBinding(facts.resource_id, c.digest(c.public_object(data["root_manifest"]))),
            matches[0], pointer, facts.policy_identity,
            c.sha256(data["registry_digest"]), c.sha256(data["qualification_digest"]),
            (effect,), (), c.public_object({
                "schema": "1.0", "steps": (step,), "verification": verification,
                "pins": (), "cancel_scope": (occurrence,),
            }), "restore",
        )
        plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
        binding = bind_lifecycle(plan)
        if (
            binding.registry_digest != self.service.registry.digest
            or binding.policy != self.service._policy_identity
        ):
            raise AuthorizationError()
        snapshot = state.snapshot_lifecycle(binding)
        check_budget()
        if snapshot.binding != binding:
            raise AuthorizationError()
        validate_current(binding, snapshot.evidence, self._now())
        self._readiness_digest(binding)
        # Planning is retained-metadata-only. Functional checks belong to the
        # exact retained context at admitted restore entry, never the active
        # interpreter (which may be broken). Missing durable selection is not
        # inferred from a directory or an unrelated current preview.
        retained = RecoveryStore(state).retained(binding.generation)
        if retained.context != context:
            raise AuthorizationError()
        check_budget()
        return plan
