"""Host-private operational admission, separate from pure policy decisions.

The host owns the consent adapter and state port; neither is a public request
surface. This module does not implement owned-file locks or controller dispatch.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from copy import deepcopy
from dataclasses import dataclass, fields, replace
from typing import NoReturn, Protocol

from .. import contracts as c
from . import contracts as lc
from .admission_telemetry import LifecycleAdmissionTelemetry
from .contracts import MAX_SAFE_INT, DecisionResult, EffectDescriptor, FrozenObject
from .lifecycle_evidence import (
    EvidenceMismatch,
    LifecycleEvidence,
    validate_content,
    validate_current,
)
from .loader import validate_identity

CONSENT_STALE = "consent-stale"
POLICY_INPUT_INVALID = "policy-input-invalid"


class AuthorizationError(ValueError):
    """A safe host rejection, without supplied values in diagnostics."""

    def __init__(self, *, numeric: bool = False) -> None:
        self.reason = CONSENT_STALE
        self.cause = POLICY_INPUT_INVALID if numeric else CONSENT_STALE
        super().__init__(self.reason)


@dataclass(frozen=True)
class AdmissionSnapshot:
    """Current trusted host facts, read only while the host state lock is held."""

    binding: c.PlanBinding
    revision: int
    cancelled: bool
    dispatch_enabled: bool

    def validate(self) -> None:
        """Independently revalidate restored or mutated host values."""
        _binding(self.binding)
        c.counter(self.revision)
        if type(self.cancelled) is not bool or type(self.dispatch_enabled) is not bool:
            raise c.ContractError()


class AdmissionStatePort(Protocol):
    """Host CAS seam; implementations must share their lock with all writers."""

    def lock(self, operation_id: str) -> AbstractContextManager[object]:
        """Serialize host binding/revision reads, CAS and external cancellation."""
        ...

    def snapshot(self, operation_id: str) -> AdmissionSnapshot:
        """Return factual current state, not a caller's permission projection."""
        ...

    def compare_revision(
        self, operation_id: str, expected_revision: int, next_revision: int,
    ) -> bool:
        """CAS exactly once under lock; false must leave state unchanged."""
        ...


class ConsentReviewPort(Protocol):
    """Application-owned interactive/API adapter, never deserialized input."""

    def confirm(
        self, plan: c.OperationPlan, binding: c.PlanBinding, deadline: float,
    ) -> bool:
        """Prompt for this exact ordered plan, recovery scope and deadline."""
        ...


class _Opaque:
    """Keep all authority in host registries, never on a transferable value."""

    __slots__ = ()

    @property
    def _host_owned(self) -> bool:
        return True

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        raise TypeError("private-value")

    def __copy__(self) -> NoReturn:
        raise TypeError("private-value")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        raise TypeError("private-value")


class _Consent(_Opaque, c.ConsentReceipt):
    __slots__ = ()


class _Authorization(_Opaque, c.Authorization):
    __slots__ = ()


class _Session(_Opaque, c.AdmissionSession):
    __slots__ = ()


class _Permit(_Opaque, c.EffectPermit):
    __slots__ = ()


class _InstallConsent(_Opaque, lc.InstallConsent):
    __slots__ = ()


class _ConsequentialGrant(_Opaque, lc.ConsequentialGrant):
    __slots__ = ()


class _LifecycleAuthorization(_Opaque, lc.LifecycleAuthorization):
    __slots__ = ()


class _LifecycleSession(_Opaque, lc.LifecycleAdmissionSession):
    __slots__ = ()


class _LifecyclePermit(_Opaque, lc.LifecycleEffectPermit):
    __slots__ = ()


def _lifecycle_structure(binding: lc.LifecycleBinding) -> None:
    expected = {
        lc.InstallBinding: "install", lc.UninstallBinding: "uninstall",
        lc.RestoreBinding: "restore",
    }
    if (
        type(binding) not in expected
        or set(vars(binding)) != set(type(binding).__dataclass_fields__)
        or type(binding.kind) is not str or binding.kind != expected[type(binding)]
    ):
        raise c.ContractError()
    if binding.schema != "1.0":
        raise c.ContractError()
    if type(binding) is lc.InstallBinding:
        if type(binding.scope) is not c.InstallScope:
            raise c.ContractError()
        binding.scope.__post_init__()
    c.uuid_text(binding.plan_id)
    c.uuid_text(binding.lifecycle_id)
    if binding.kind != "install" and binding.lifecycle_id != binding.plan_id:
        raise c.ContractError()
    for value in (binding.plan_digest, binding.context_digest, binding.registry_digest,
                  binding.qualification_digest):
        c.sha256(value)
    if type(binding.root) is not lc.OwnedRootBinding:
        raise c.ContractError()
    if set(vars(binding.root)) != {item.name for item in fields(binding.root)}:
        raise c.ContractError()
    c.text(binding.root.resource_id)
    c.sha256(binding.root.manifest_digest)
    generation = binding.generation
    if type(generation) is not lc.GenerationBinding or type(generation.selected) is not tuple:
        raise c.ContractError()
    for item in (generation, *generation.selected):
        if type(item) is not lc.GenerationBinding:
            raise c.ContractError()
        if set(vars(item)) != {field.name for field in fields(item)}:
            raise c.ContractError()
        c.text(item.generation_id)
        c.counter(item.ordinal)
        c.sha256(item.content_digest)
        c.sha256(item.manifest_digest)
        if item is not generation and item.selected != ():
            raise c.ContractError()
    if binding.kind == "uninstall":
        if not generation.selected or generation.generation_id not in tuple(
            item.generation_id for item in generation.selected
        ):
            raise c.ContractError()
        c.unique(tuple(item.generation_id for item in generation.selected))
    elif generation.selected != ():
        raise c.ContractError()
    pointer = binding.expected_pointer
    if type(pointer) is lc.AbsentPointer:
        if pointer.kind != "absent" or pointer.revision != 0 or binding.kind == "restore":
            raise c.ContractError()
    elif type(pointer) is lc.PresentPointer:
        if pointer.kind != "present":
            raise c.ContractError()
        c.text(pointer.active_generation_id)
        c.sha256(pointer.pointer_digest)
    else:
        raise c.ContractError()
    c.counter(pointer.revision)
    if set(vars(pointer)) != {item.name for item in fields(pointer)}:
        raise c.ContractError()
    if type(binding.policy) is not lc.PolicyIdentity:
        raise c.ContractError()
    try:
        validate_identity(binding.policy)
    except lc.PolicyLoadError:
        raise c.ContractError() from None
    for value in (binding.policy.source_sha256, binding.policy.contracts_sha256,
                  binding.policy.bundle_sha256):
        c.sha256(value)
    for value in (binding.policy.canonical_revision, binding.policy.reducer_version,
                  binding.policy.profile, binding.policy.numeric_profile):
        c.text(value)
    c.unique(binding.policy.rule_manifest)
    if binding.policy.schema != "1.0":
        raise c.ContractError()
    if type(binding.effects) is not tuple or not binding.effects:
        raise c.ContractError()
    allowed = {
        "install": ("dependency-probe", "dependency-download", "dependency-stage",
                    "dependency-verify", "dependency-activate"),
        "uninstall": ("dependency-uninstall", "restore-active-pointer"),
        "restore": ("restore-active-pointer",),
    }
    for index, effect in enumerate(binding.effects):
        if type(effect) is not lc.LifecycleEffectOccurrence:
            raise c.ContractError()
        if set(vars(effect)) != {item.name for item in fields(effect)}:
            raise c.ContractError()
        c.text(effect.occurrence_id)
        c.counter(effect.ordinal)
        c.text(effect.step_id)
        c.text(effect.resource_id)
        c.sha256(effect.arguments_digest)
        if effect.ordinal != index or effect.kind not in allowed[binding.kind]:
            raise c.ContractError()
        if effect.kind in ("dependency-activate", "restore-active-pointer") and (
            index != len(binding.effects) - 1
        ):
            raise c.ContractError()
    ids = tuple(effect.occurrence_id for effect in binding.effects)
    c.unique(ids)
    if binding.kind == "restore" and len(binding.effects) != 1:
        raise c.ContractError()
    if type(binding.required_consequential) is not tuple:
        raise c.ContractError()
    categories: set[str] = set()
    for requirement in binding.required_consequential:
        if type(requirement) is not lc.ConsequentialRequirement or requirement.category not in (
            "elevation", "wsl-change", "vm-change", "reboot", "runtime-install", "security-change",
        ) or requirement.category in categories:
            raise c.ContractError()
        categories.add(requirement.category)
        if set(vars(requirement)) != {item.name for item in fields(requirement)}:
            raise c.ContractError()
        c.unique(requirement.occurrence_ids)
        if not requirement.occurrence_ids or tuple(
            item for item in ids if item in requirement.occurrence_ids
        ) != requirement.occurrence_ids:
            raise c.ContractError()
    if type(binding.content) is not FrozenObject:
        raise c.ContractError()


def _lifecycle(binding: lc.LifecycleBinding) -> None:
    _lifecycle_structure(binding)
    validate_content(binding)


def bind_lifecycle(plan: lc.LifecyclePlan) -> lc.LifecycleBinding:
    """Derive a closed nominal projection without granting authority or doing I/O."""
    if type(plan) not in (lc.InstallPlan, lc.UninstallPlan, lc.RestorePlan):
        raise c.ContractError()
    if set(vars(plan)) != {item.name for item in fields(plan)}:
        raise c.ContractError()
    values = {item.name: getattr(plan, item.name) for item in fields(plan)}
    binding: lc.LifecycleBinding
    if type(plan) is lc.InstallPlan:
        binding = lc.InstallBinding(**values)
    elif type(plan) is lc.UninstallPlan:
        binding = lc.UninstallBinding(**values)
    elif type(plan) is lc.RestorePlan:
        binding = lc.RestoreBinding(**values)
    else:
        raise c.ContractError()
    _lifecycle(binding)
    if lifecycle_plan_digest(binding) != binding.plan_digest:
        raise c.ContractError()
    return deepcopy(binding)


def lifecycle_plan_digest(binding: lc.LifecycleBinding) -> str:
    """Hash every nonsecret projection field except the digest being derived."""
    return c.digest(tuple(
        (item.name, getattr(binding, item.name)) for item in fields(binding)
        if item.name != "plan_digest"
    ))


def lifecycle_effects(binding: lc.LifecycleBinding) -> tuple[EffectDescriptor, ...]:
    """Project ordered policy symbols; the private scope binds complete occurrences."""
    return tuple(EffectDescriptor(
        "request_effect", FrozenObject((("kind", effect.kind),)),
    ) for effect in binding.effects)


def _lifecycle_decision(decision: DecisionResult, binding: lc.LifecycleBinding) -> None:
    _decision(decision)
    for effect in decision.effects:
        key = {"request_effect": "kind", "set_phase": "phase"}.get(effect.name)
        if key is None or tuple(effect.params) != (key,) or type(effect.params[key]) is not str:
            raise AuthorizationError()
    expected = lifecycle_effects(binding)
    phase = (
        "Verified" if binding.effects[0].kind == "dependency-activate" else "Staging"
    ) if binding.kind == "install" else "Admitted"
    transition = EffectDescriptor("set_phase", FrozenObject((("phase", phase),)))
    if (
        decision.decision != "allow" or decision.policy_digest != binding.policy.bundle_sha256
        or not decision.rule_ids or tuple(sorted(set(decision.rule_ids))) != decision.rule_ids
        or any(rule not in binding.policy.rule_manifest for rule in decision.rule_ids)
        or decision.effects not in (expected, (transition, *expected))
    ):
        raise AuthorizationError()


@dataclass(frozen=True)
class LifecycleSnapshot:
    """Trusted owned state; missing/corrupt ownership is not virgin absence."""

    binding: lc.LifecycleBinding
    revision: int
    cancelled: bool
    setup_enabled: bool
    owned_valid: bool
    pins_valid: bool
    probes_valid: bool
    evidence: LifecycleEvidence | None = None


class LifecycleStatePort(Protocol):
    """Host-owned root lock, checkpoint CAS and final pointer CAS seam."""

    def lock_lifecycle(self, binding: lc.LifecycleBinding) -> AbstractContextManager[object]:
        """Share this root lock with all pointer writers and cancellation."""
        ...

    def snapshot_lifecycle(self, binding: lc.LifecycleBinding) -> LifecycleSnapshot:
        """Read current owned/pointer/pin/probe facts under the root lock."""
        ...

    def compare_lifecycle_revision(
        self, binding: lc.LifecycleBinding, expected: int, following: int,
    ) -> bool:
        """CAS one exact checkpoint revision; false leaves state unchanged."""
        ...

    def compare_replace_lifecycle(
        self, binding: lc.LifecycleBinding, expected: lc.PointerExpectation,
        following_revision: int,
    ) -> bool:
        """CAS the reviewed pointer to the plan's exact selected generation."""
        ...


class LifecycleReviewPort(Protocol):
    """Trusted local prompt seam, separate from operational consent."""

    def confirm_lifecycle(self, binding: lc.LifecycleBinding, deadline: float) -> bool:
        """Review the complete exact lifecycle and ordered occurrences."""
        ...

    def confirm_consequential(
        self, binding: lc.LifecycleBinding, requirement: lc.ConsequentialRequirement,
        deadline: float,
    ) -> bool:
        """Separately prompt one consequential category and its occurrences."""
        ...


@dataclass(frozen=True)
class _LifecycleScope:
    binding: lc.LifecycleBinding
    issued_at: float
    deadline: float
    grants: tuple[_ConsequentialGrant, ...]


class TrustedLifecycleConsentAdapter:
    """Identity-register exact, separately prompted memory-only receipts."""

    def __init__(self, reviewer: LifecycleReviewPort) -> None:
        self._reviewer = reviewer
        self._lock = threading.RLock()
        self._receipts: dict[_InstallConsent, _LifecycleScope] = {}
        self._categories: dict[
            _ConsequentialGrant, tuple[lc.LifecycleBinding, lc.ConsequentialRequirement, float]
        ] = {}

    def review(
        self, plan: lc.LifecyclePlan, now: float, duration: float,
    ) -> lc.InstallConsent:
        """Prompt each category separately; generic assent is insufficient."""
        binding = bind_lifecycle(plan)
        c.finite(now)
        deadline = c.checked_deadline(now, duration)
        if deadline <= now:
            raise AuthorizationError()
        if self._reviewer.confirm_lifecycle(binding, deadline) is not True:
            raise AuthorizationError()
        grants: list[_ConsequentialGrant] = []
        with self._lock:
            for requirement in binding.required_consequential:
                if self._reviewer.confirm_consequential(binding, requirement, deadline) is not True:
                    raise AuthorizationError()
                grant = _ConsequentialGrant()
                self._categories[grant] = (binding, requirement, deadline)
                grants.append(grant)
            receipt = _InstallConsent()
            self._receipts[receipt] = _LifecycleScope(binding, now, deadline, tuple(grants))
            return receipt

    def validate(self, scope: _LifecycleScope, now: float) -> None:
        """Require all and only the original separately prompted receipts."""
        c.finite(now)
        if not scope.issued_at <= now < scope.deadline:
            raise AuthorizationError()
        if len(scope.grants) != len(scope.binding.required_consequential):
            raise AuthorizationError()
        for grant, requirement in zip(scope.grants, scope.binding.required_consequential):
            if self._categories.get(grant) != (scope.binding, requirement, scope.deadline):
                raise AuthorizationError()


@dataclass(frozen=True)
class _Scope:
    binding: c.PlanBinding
    effects: tuple[c.PlannedEffect, ...]
    issued_at: float
    deadline: float


@dataclass
class _SessionRecord:
    scope: _Scope
    next_ordinal: int = 0


@dataclass(frozen=True)
class _Pending:
    scope: _Scope
    binding: c.EffectBinding


def _binding(binding: c.PlanBinding) -> None:
    if type(binding) is not c.PlanBinding:
        raise c.ContractError()
    binding.__post_init__()


def bind_plan(plan: c.OperationPlan, root_ref: str, generation: int) -> c.PlanBinding:
    """Derive the exact nonsecret projection; this function grants nothing."""
    # Operational hydration owns YAML; lifecycle bootstrap must be able to
    # review/install its complete pinned prerequisites before YAML is present.
    from ..workflows import plan_digest

    if type(plan) is not c.OperationPlan:
        raise c.ContractError()
    plan.__post_init__()
    plan.context.__post_init__()
    for effect in plan.effects:
        effect.__post_init__()
    for observation in plan.observations:
        observation.__post_init__()
    if plan_digest(plan) != plan.plan_digest:
        raise c.ContractError(c.INPUT_BINDING_INVALID)
    return c.PlanBinding(
        plan.operation_id, plan.plan_digest, plan.policy_digest, c.digest(plan.context),
        c.digest(plan.context.controller_id), c.digest((plan.context.route_digest, plan.routes)),
        plan.input_binding_digest, c.digest(plan.observations), root_ref, generation,
        plan.recovery_scope,
    )


def _time(scope: _Scope, now: float) -> None:
    c.finite(now)
    c.finite(scope.issued_at)
    c.finite(scope.deadline)
    if not scope.issued_at <= now < scope.deadline:
        raise AuthorizationError()


def _decision(decision: DecisionResult) -> None:
    if type(decision) is not DecisionResult or type(decision.effects) is not tuple:
        raise AuthorizationError()
    c.text(decision.decision)
    c.text(decision.reason)
    c.sha256(decision.policy_digest)
    c.unique(decision.rule_ids)
    for effect in decision.effects:
        if type(effect) is not EffectDescriptor or type(effect.params) is not FrozenObject:
            raise AuthorizationError()
        c.text(effect.name)


class TrustedConsentAdapter:
    """Mint private receipts only after a trusted port reviews the exact plan.

    Construct at application bootstrap and keep private. A caller's JSON, bool,
    old decision, or subclass of ConsentReceipt is never a receipt in this store.
    """

    def __init__(self, reviewer: ConsentReviewPort) -> None:
        self._reviewer = reviewer
        self._lock = threading.RLock()
        self._receipts: dict[_Consent, _Scope] = {}

    def review(
        self, plan: c.OperationPlan, binding: c.PlanBinding, now: float, duration: float,
    ) -> c.ConsentReceipt:
        """Review one plan and issue a receipt with its original finite expiry."""
        try:
            _binding(binding)
            c.finite(now)
            c.finite(duration)
            deadline = c.checked_deadline(now, duration)
            if (
                deadline <= now
                or binding != bind_plan(plan, binding.root_ref, binding.generation)
                or duration > plan.deadline_ms / 1000.0
            ):
                raise AuthorizationError()
            accepted = self._reviewer.confirm(plan, binding, deadline)
            if type(accepted) is not bool or accepted is not True:
                raise AuthorizationError()
            receipt = _Consent()
            with self._lock:
                self._receipts[receipt] = _Scope(
                    replace(binding), tuple(replace(effect) for effect in plan.effects),
                    now, deadline,
                )
            return receipt
        except c.ContractError:
            raise AuthorizationError(numeric=True) from None

    def _peek(self, receipt: c.ConsentReceipt) -> _Scope:
        if type(receipt) is not _Consent:
            raise AuthorizationError()
        scope = self._receipts.get(receipt)
        if scope is None:
            raise AuthorizationError()
        return scope

    def _spend(self, receipt: c.ConsentReceipt) -> None:
        if type(receipt) is not _Consent:
            raise AuthorizationError()
        del self._receipts[receipt]


class AuthorizationBroker:
    """Serialize exact operational grant consumption, reservation and revocation.

    The private broker lock is always acquired before the host state lock.
    Host implementations must not call back into this broker while holding their
    state lock. Only the host constructs this service and supplies its ports.
    """

    def __init__(
        self, state: AdmissionStatePort, consent: TrustedConsentAdapter,
        *, lifecycle_state: LifecycleStatePort | None = None,
        lifecycle_consent: TrustedLifecycleConsentAdapter | None = None,
        lifecycle_telemetry: LifecycleAdmissionTelemetry | None = None,
    ) -> None:
        if type(consent) is not TrustedConsentAdapter:
            raise AuthorizationError()
        self._state = state
        self._consent = consent
        self._lock = threading.RLock()
        self._grants: dict[_Authorization, _Scope] = {}
        self._sessions: dict[_Session, _SessionRecord] = {}
        self._pending: dict[_Permit, _Pending] = {}
        self._revoked: set[str] = set()
        self._events: set[tuple[str, str]] = set()
        self._reserved: set[tuple[str, str, str]] = set()
        self._entered: set[_Permit] = set()
        self._last_now: dict[str, float] = {}
        self._lifecycle_state = lifecycle_state
        self._lifecycle_consent = lifecycle_consent
        self._lifecycle_telemetry = (
            lifecycle_telemetry if lifecycle_telemetry is not None else LifecycleAdmissionTelemetry()
        )
        self._life_grants: dict[_LifecycleAuthorization, _LifecycleScope] = {}
        self._life_sessions: dict[_LifecycleSession, tuple[_LifecycleScope, int]] = {}
        self._life_pending: dict[_LifecyclePermit, tuple[_LifecycleScope, lc.LifecycleEffectBinding]] = {}
        self._life_entered: set[_LifecyclePermit] = set()
        self._life_finished: set[_LifecyclePermit] = set()
        self._life_revoked: set[tuple[str, str]] = set()
        self._life_events: set[tuple[str, str, str]] = set()
        self._life_reserved: set[tuple[str, str, str, str]] = set()
        self._life_now: dict[tuple[str, str], float] = {}
        self._life_completed: set[tuple[str, str, str, str]] = set()
        self._life_pointer_results: dict[_LifecyclePermit, tuple[str, int]] = {}
        self._life_plans: dict[tuple[str, str], str] = {}

    @contextmanager
    def _life_rejection(
        self, binding: object, authority: object = None, now: float | None = None,
        *, completion: bool = False,
    ) -> Iterator[None]:
        kind = "unknown"
        key: tuple[str, str] | None = None
        scope = self._life_scope(authority)
        if scope is not None:
            key = (scope.binding.kind, scope.binding.plan_id)
        try:
            if scope is not None:
                self._life_clock(scope, now, completion=completion)
            # Caller projections cannot prevent observation of the registry-owned clock.
            if type(binding) is lc.LifecycleEffectBinding:
                self._life_effect_binding(binding)
                binding = binding.lifecycle
            if isinstance(binding, (
                lc.InstallPlan, lc.UninstallPlan, lc.RestorePlan,
                lc.InstallBinding, lc.UninstallBinding, lc.RestoreBinding,
            )) and type(binding) in (
                lc.InstallPlan, lc.UninstallPlan, lc.RestorePlan,
                lc.InstallBinding, lc.UninstallBinding, lc.RestoreBinding,
            ):
                if set(vars(binding)) != set(type(binding).__dataclass_fields__):
                    raise c.ContractError()
                kind = binding.kind
            yield
        except EvidenceMismatch:
            self._lifecycle_telemetry.rejected(kind, "evidence-mismatch")
            raise AuthorizationError() from None
        except AuthorizationError as error:
            self._lifecycle_telemetry.rejected(kind, error.cause)
            raise
        except c.ContractError:
            if key is not None:
                with self._lock:
                    self._life_revoked.add(key)
            self._lifecycle_telemetry.rejected(kind, POLICY_INPUT_INVALID)
            raise

    def _life_scope(self, authority: object) -> _LifecycleScope | None:
        if type(authority) is _InstallConsent and self._lifecycle_consent is not None:
            with self._lifecycle_consent._lock:
                return self._lifecycle_consent._receipts.get(authority)
        if type(authority) is _LifecycleAuthorization:
            return self._life_grants.get(authority)
        if type(authority) is _LifecycleSession:
            record = self._life_sessions.get(authority)
            return record[0] if record is not None else None
        if type(authority) is _LifecyclePermit:
            pending = self._life_pending.get(authority)
            return pending[0] if pending is not None else None
        return None

    def _life_clock(
        self, scope: _LifecycleScope, now: object, *, completion: bool = False,
    ) -> None:
        key = (scope.binding.kind, scope.binding.plan_id)
        try:
            observed = c.finite(now)
            if observed < self._life_now.get(key, scope.issued_at):
                raise AuthorizationError()
            # Keep trusted clock progress even if a later projection or callback fails.
            self._life_now[key] = observed
            if completion is not True:
                if key in self._life_revoked:
                    raise AuthorizationError()
                consent = self._lifecycle_consent
                if consent is None:
                    raise AuthorizationError()
                consent.validate(scope, observed)
        except (c.ContractError, AuthorizationError):
            self._life_revoked.add(key)
            raise

    @contextmanager
    def _life_current(
        self, scope: _LifecycleScope, now: float,
    ) -> Iterator[tuple[LifecycleStatePort, LifecycleSnapshot]]:
        state = self._lifecycle_state
        consent = self._lifecycle_consent
        if state is None or consent is None:
            raise AuthorizationError()
        binding = scope.binding
        with state.lock_lifecycle(binding):
            _lifecycle(binding)
            self._life_clock(scope, now)
            key = (binding.kind, binding.plan_id)
            snapshot = state.snapshot_lifecycle(binding)
            if type(snapshot) is not LifecycleSnapshot:
                raise c.ContractError()
            # Validate malformed numerics before treating well-formed identity
            # drift as stale authority, not as a content-schema failure.
            _lifecycle_structure(snapshot.binding)
            try:
                c.counter(snapshot.revision)
            except c.ContractError:
                self._life_revoked.add(key)
                raise
            for flag in (snapshot.cancelled, snapshot.setup_enabled, snapshot.owned_valid,
                         snapshot.pins_valid, snapshot.probes_valid):
                if type(flag) is not bool:
                    raise c.ContractError()
            if (
                snapshot.binding != binding or snapshot.cancelled or not snapshot.setup_enabled
                or not snapshot.owned_valid or not snapshot.pins_valid or not snapshot.probes_valid
                or key in self._life_revoked
            ):
                self._life_revoked.add(key)
                raise AuthorizationError()
            try:
                validate_current(binding, snapshot.evidence, now)
            except (c.ContractError, EvidenceMismatch):
                self._life_revoked.add(key)
                raise
            yield state, snapshot

    def issue_lifecycle(
        self, plan: lc.LifecyclePlan, consent: lc.InstallConsent,
        decision: DecisionResult, now: float,
    ) -> lc.LifecycleAuthorization:
        """Issue only against complete concrete lifecycle and private consent."""
        with self._lock, self._life_rejection(plan, consent, now):
            return self._issue_lifecycle(plan, consent, decision, now)

    def _issue_lifecycle(
        self, plan: lc.LifecyclePlan, consent: lc.InstallConsent,
        decision: DecisionResult, now: float,
    ) -> lc.LifecycleAuthorization:
        binding = bind_lifecycle(plan)
        adapter = self._lifecycle_consent
        if adapter is None or type(consent) is not _InstallConsent:
            raise AuthorizationError()
        with self._lock, adapter._lock:
            scope = adapter._receipts.get(consent)
            if scope is None or scope.binding != binding:
                raise AuthorizationError()
            key = (binding.kind, binding.plan_id)
            if self._life_plans.get(key, binding.plan_digest) != binding.plan_digest:
                raise AuthorizationError()
            with self._life_current(scope, now):
                _lifecycle_decision(decision, binding)
                grant = _LifecycleAuthorization()
                self._life_grants[grant] = scope
                self._life_plans[key] = binding.plan_digest
                del adapter._receipts[consent]
                return grant

    def consume_lifecycle(
        self, authorization: lc.LifecycleAuthorization, binding: lc.LifecycleBinding, now: float,
    ) -> lc.LifecycleAdmissionSession:
        """Consume once without crossing kind or renewing the original deadline."""
        with self._lock, self._life_rejection(binding, authorization, now):
            return self._consume_lifecycle(authorization, binding, now)

    def _consume_lifecycle(
        self, authorization: lc.LifecycleAuthorization, binding: lc.LifecycleBinding, now: float,
    ) -> lc.LifecycleAdmissionSession:
        with self._lock:
            if type(authorization) is not _LifecycleAuthorization:
                raise AuthorizationError()
            scope = self._life_grants.get(authorization)
            if scope is None:
                raise AuthorizationError()
            _lifecycle(binding)
            if scope.binding != binding:
                raise AuthorizationError()
            with self._life_current(scope, now):
                session = _LifecycleSession()
                self._life_sessions[session] = (scope, 0)
                del self._life_grants[authorization]
                return session

    def permit_lifecycle(
        self, session: lc.LifecycleAdmissionSession, binding: lc.LifecycleEffectBinding, now: float,
    ) -> lc.LifecycleEffectPermit:
        """Reserve the next exact occurrence through the root-serialized CAS."""
        with self._lock, self._life_rejection(binding, session, now):
            return self._permit_lifecycle(session, binding, now)

    def _permit_lifecycle(
        self, session: lc.LifecycleAdmissionSession, binding: lc.LifecycleEffectBinding, now: float,
    ) -> lc.LifecycleEffectPermit:
        with self._lock:
            if type(session) is not _LifecycleSession:
                raise AuthorizationError()
            record = self._life_sessions.get(session)
            if record is None:
                raise AuthorizationError()
            scope, ordinal = record
            self._life_effect_binding(binding)
            if binding.lifecycle != scope.binding or ordinal >= len(scope.binding.effects):
                raise AuthorizationError()
            selected = scope.binding.effects[ordinal]
            key = (scope.binding.kind, scope.binding.plan_id)
            event = (*key, binding.event_id)
            occurrence = (*key, scope.binding.plan_digest, binding.occurrence_id)
            with self._life_current(scope, now) as (state, snapshot):
                previous = (
                    (*key, scope.binding.plan_digest,
                     scope.binding.effects[ordinal - 1].occurrence_id) if ordinal else None
                )
                if (
                    selected.occurrence_id != binding.occurrence_id
                    or snapshot.revision != binding.expected_revision
                    or event in self._life_events or occurrence in self._life_reserved
                    or (previous is not None and previous not in self._life_completed)
                ):
                    raise AuthorizationError()
                if snapshot.revision == MAX_SAFE_INT:
                    self._life_revoked.add(key)
                    raise AuthorizationError(numeric=True)
                if state.compare_lifecycle_revision(
                    scope.binding, snapshot.revision, snapshot.revision + 1,
                ) is not True:
                    raise AuthorizationError()
                permit = _LifecyclePermit()
                self._life_pending[permit] = (scope, deepcopy(binding))
                self._life_sessions[session] = (scope, ordinal + 1)
                self._life_events.add(event)
                self._life_reserved.add(occurrence)
                return permit

    @staticmethod
    def _life_effect_binding(binding: lc.LifecycleEffectBinding) -> None:
        if (
            type(binding) is not lc.LifecycleEffectBinding
            or set(vars(binding)) != set(lc.LifecycleEffectBinding.__dataclass_fields__)
        ):
            raise c.ContractError()
        _lifecycle(binding.lifecycle)
        c.uuid_text(binding.event_id)
        c.counter(binding.expected_revision)
        c.text(binding.occurrence_id)

    def enter_lifecycle(
        self, permit: lc.LifecycleEffectPermit, binding: lc.LifecycleEffectBinding, now: float,
    ) -> bool:
        """Consume fixed-handler entry exactly once; A02 supplies the handler."""
        with self._lock, self._life_rejection(binding, permit, now):
            return self._enter_lifecycle(permit, binding, now)

    def _enter_lifecycle(
        self, permit: lc.LifecycleEffectPermit, binding: lc.LifecycleEffectBinding, now: float,
    ) -> bool:
        with self._lock:
            if type(permit) is not _LifecyclePermit:
                raise AuthorizationError()
            pending = self._life_pending.get(permit)
            if pending is None or permit in self._life_entered or permit in self._life_finished:
                raise AuthorizationError()
            scope, expected = pending
            self._life_effect_binding(binding)
            if binding != expected:
                raise AuthorizationError()
            with self._life_current(scope, now):
                self._life_entered.add(permit)
                return True

    def replace_lifecycle_pointer(
        self, permit: lc.LifecycleEffectPermit, now: float,
    ) -> bool:
        """CAS only the final reviewed pointer effect, never implicitly reverse it."""
        with self._lock:
            pending = self._life_pending.get(permit) if type(permit) is _LifecyclePermit else None
            with self._life_rejection(
                pending[0].binding if pending is not None else None, permit, now,
            ):
                return self._replace_lifecycle_pointer(permit, now)

    def _replace_lifecycle_pointer(
        self, permit: lc.LifecycleEffectPermit, now: float,
    ) -> bool:
        with self._lock:
            if type(permit) is not _LifecyclePermit:
                raise AuthorizationError()
            pending = self._life_pending.get(permit)
            if pending is None or permit not in self._life_entered:
                raise AuthorizationError()
            scope, effect_binding = pending
            last = scope.binding.effects[-1]
            if (
                last.occurrence_id != effect_binding.occurrence_id
                or last.kind not in ("dependency-activate", "restore-active-pointer")
            ):
                raise AuthorizationError()
            with self._life_current(scope, now) as (state, _):
                revision = scope.binding.expected_pointer.revision
                if revision == MAX_SAFE_INT:
                    self._life_revoked.add((scope.binding.kind, scope.binding.plan_id))
                    raise AuthorizationError(numeric=True)
                if state.compare_replace_lifecycle(
                    scope.binding, scope.binding.expected_pointer, revision + 1,
                ) is not True:
                    raise AuthorizationError()
                self._life_revoked.add((scope.binding.kind, scope.binding.plan_id))
                self._life_pointer_results[permit] = (
                    scope.binding.generation.generation_id, revision + 1,
                )
                return True

    def complete_lifecycle(
        self, permit: lc.LifecycleEffectPermit, event_id: str, expected_revision: int, now: float,
    ) -> None:
        """Record one factual entered-effect completion, even after cancellation."""
        with self._lock:
            pending = self._life_pending.get(permit) if type(permit) is _LifecyclePermit else None
            with self._life_rejection(
                pending[0].binding if pending is not None else None, permit, now, completion=True,
            ):
                self._complete_lifecycle(permit, event_id, expected_revision, now)

    def _complete_lifecycle(
        self, permit: lc.LifecycleEffectPermit, event_id: str, expected_revision: int, now: float,
    ) -> None:
        with self._lock:
            if type(permit) is not _LifecyclePermit or permit not in self._life_entered:
                raise AuthorizationError()
            pending = self._life_pending.get(permit)
            state = self._lifecycle_state
            if pending is None or state is None:
                raise AuthorizationError()
            scope, binding = pending
            c.uuid_text(event_id)
            c.counter(expected_revision)
            c.finite(now)
            key = (scope.binding.kind, scope.binding.plan_id)
            event = (*key, event_id)
            with state.lock_lifecycle(scope.binding):
                snapshot = state.snapshot_lifecycle(scope.binding)
                if type(snapshot) is not LifecycleSnapshot:
                    raise c.ContractError()
                c.counter(snapshot.revision)
                if (
                    now < self._life_now.get(key, scope.issued_at)
                    or snapshot.revision != expected_revision or event in self._life_events
                ):
                    raise AuthorizationError()
                if expected_revision == MAX_SAFE_INT:
                    self._life_revoked.add(key)
                    raise AuthorizationError(numeric=True)
                if state.compare_lifecycle_revision(
                    scope.binding, expected_revision, expected_revision + 1,
                ) is not True:
                    raise AuthorizationError()
                self._life_events.add(event)
                self._life_completed.add((
                    *key, scope.binding.plan_digest, binding.occurrence_id,
                ))
                self._life_entered.remove(permit)
                self._life_finished.add(permit)

    def reconcile_lifecycle_pointer(self, permit: lc.LifecycleEffectPermit) -> tuple[str, int]:
        """Return the acknowledged actual pointer CAS result without reverse CAS."""
        with self._lock:
            if type(permit) is not _LifecyclePermit or permit not in self._life_pointer_results:
                raise AuthorizationError()
            return self._life_pointer_results[permit]

    def reconcile_lifecycle(self, permit: lc.LifecycleEffectPermit) -> lc.LifecycleEffectBinding:
        """Read issued facts after cancel/exhaustion without reconstructing authority."""
        with self._lock:
            if type(permit) is not _LifecyclePermit or permit not in self._life_pending:
                raise AuthorizationError()
            return deepcopy(self._life_pending[permit][1])

    def revoke_lifecycle(self, kind: lc.LifecycleKind, plan_id: str) -> None:
        """Cancel in a separate namespace without allocating a numeric revision."""
        if type(kind) is not str or kind not in ("install", "uninstall", "restore"):
            raise c.ContractError()
        c.uuid_text(plan_id)
        with self._lock:
            self._life_revoked.add((kind, plan_id))

    @contextmanager
    def _critical(
        self, scope: _Scope, now: float, *, completion: bool = False,
    ) -> Iterator[None]:
        operation_id = scope.binding.operation_id
        with self._lock:
            try:
                observed = c.finite(now)
                if observed < self._last_now.get(operation_id, scope.issued_at):
                    self._revoke(operation_id)
                    raise AuthorizationError()
                self._last_now[operation_id] = observed
                if completion is not True:
                    try:
                        _time(scope, observed)
                    except AuthorizationError:
                        self._revoke(operation_id)
                        raise
                with self._state.lock(operation_id):
                    yield
            except c.ContractError:
                self._revoke(operation_id)
                raise AuthorizationError(numeric=True) from None

    def _current(
        self, scope: _Scope, now: float, *, completion: bool = False,
    ) -> AdmissionSnapshot:
        """Check host facts after _critical has recorded this call's clock."""
        _binding(scope.binding)
        operation_id = scope.binding.operation_id
        snapshot = self._state.snapshot(operation_id)
        if type(snapshot) is not AdmissionSnapshot:
            raise c.ContractError()
        snapshot.validate()
        if snapshot.binding != scope.binding:
            self._revoke(operation_id)
            raise AuthorizationError()
        if completion is not True and (
            operation_id in self._revoked or snapshot.cancelled is True
            or snapshot.dispatch_enabled is not True
        ):
            self._revoke(operation_id)
            raise AuthorizationError()
        return snapshot

    def issue(
        self, plan: c.OperationPlan, consent: c.ConsentReceipt,
        decision: DecisionResult, now: float,
    ) -> c.Authorization:
        """Issue once from an exact reviewed plan and its selected policy intents."""
        with self._lock, self._consent._lock:
            scope = self._consent._peek(consent)
            return self._issue(plan, consent, decision, now, scope)

    def _issue(
        self, plan: c.OperationPlan, consent: c.ConsentReceipt,
        decision: DecisionResult, now: float, scope: _Scope,
    ) -> c.Authorization:
        with self._critical(scope, now):
            if type(plan) is not c.OperationPlan:
                raise AuthorizationError()
            _decision(decision)
            self._current(scope, now)
            if (
                bind_plan(plan, scope.binding.root_ref, scope.binding.generation) != scope.binding
                or plan.effects != scope.effects
                or len(plan.preconditions) != 0
                or type(decision) is not DecisionResult
                or decision.decision != "allow"
                or decision.policy_digest != plan.policy_digest
                or type(decision.rule_ids) is not tuple
                or len(decision.rule_ids) == 0
                or tuple(sorted(set(decision.rule_ids))) != decision.rule_ids
                or decision.effects != tuple(
                    EffectDescriptor("request_effect", FrozenObject((("kind", e.kind),)))
                    for e in scope.effects
                )
            ):
                raise AuthorizationError()
            grant = _Authorization()
            self._grants[grant] = scope
            self._consent._spend(consent)
            return grant

    def consume(
        self, authorization: c.Authorization, binding: c.PlanBinding, now: float,
    ) -> c.AdmissionSession:
        """Consume the exact host-owned grant once, without renewing its deadline."""
        with self._lock:
            if type(authorization) is not _Authorization:
                raise AuthorizationError()
            scope = self._grants.get(authorization)
            if scope is None:
                raise AuthorizationError()
            with self._critical(scope, now):
                _binding(binding)
                self._current(scope, now)
                if scope.binding != binding:
                    raise AuthorizationError()
                session = _Session()
                self._sessions[session] = _SessionRecord(scope)
                del self._grants[authorization]
                return session

    def _advance(self, operation_id: str, revision: int) -> None:
        c.counter(revision)
        if revision == MAX_SAFE_INT:
            self._revoke(operation_id)
            raise AuthorizationError(numeric=True)
        accepted = self._state.compare_revision(operation_id, revision, revision + 1)
        if type(accepted) is not bool or accepted is not True:
            raise AuthorizationError()

    def permit(
        self, session: c.AdmissionSession, binding: c.EffectBinding, now: float,
    ) -> c.EffectPermit:
        """Reserve only the next exact occurrence, advancing the checked host CAS."""
        with self._lock:
            if type(session) is not _Session:
                raise AuthorizationError()
            record = self._sessions.get(session)
            if record is None:
                raise AuthorizationError()
            scope = record.scope
            with self._critical(scope, now):
                if type(binding) is not c.EffectBinding:
                    raise AuthorizationError()
                binding.__post_init__()
                snapshot = self._current(scope, now)
                if snapshot.revision == MAX_SAFE_INT:
                    self._revoke(scope.binding.operation_id)
                    raise AuthorizationError(numeric=True)
                if record.next_ordinal >= len(scope.effects):
                    raise AuthorizationError()
                selected = scope.effects[record.next_ordinal]
                selected.__post_init__()
                event_key = (scope.binding.operation_id, binding.event_id)
                occurrence_key = (
                    scope.binding.operation_id, scope.binding.plan_digest, binding.occurrence_id,
                )
                if (
                    binding.plan != scope.binding
                    or binding.expected_revision != snapshot.revision
                    or binding.occurrence_id != selected.occurrence_id
                    or binding.target_id != selected.target_id
                    or binding.step_id != selected.step_id
                    or binding.recovery_scope != scope.binding.recovery_scope
                    or event_key in self._events
                    or occurrence_key in self._reserved
                ):
                    raise AuthorizationError()
                self._advance(scope.binding.operation_id, snapshot.revision)
                permit = _Permit()
                self._pending[permit] = _Pending(
                    scope, replace(binding, plan=replace(binding.plan)),
                )
                self._events.add(event_key)
                self._reserved.add(occurrence_key)
                record.next_ordinal += 1
                return permit

    def enter(
        self, permit: c.EffectPermit, binding: c.EffectBinding, now: float,
    ) -> bool:
        """Consume a reservation once at the fixed handler's entry boundary.

        A02 must call this immediately before its fixed handler. Entering once
        does not permit retry after a lost acknowledgement or remote uncertainty.
        """
        with self._lock:
            if type(permit) is not _Permit:
                raise AuthorizationError()
            pending = self._pending.get(permit)
            if pending is None:
                raise AuthorizationError()
            with self._critical(pending.scope, now):
                if permit in self._entered:
                    raise AuthorizationError()
                if type(binding) is not c.EffectBinding:
                    raise AuthorizationError()
                binding.__post_init__()
                self._current(pending.scope, now)
                if binding != pending.binding:
                    raise AuthorizationError()
                self._entered.add(permit)
                return True

    def reconcile(self, permit: c.EffectPermit) -> c.EffectBinding:
        """Read an already-issued receipt after revoke/expiry/exhaustion, never reissue."""
        with self._lock:
            if type(permit) is not _Permit:
                raise AuthorizationError()
            pending = self._pending.get(permit)
            if pending is None:
                raise AuthorizationError()
            return replace(pending.binding, plan=replace(pending.binding.plan))

    def complete(
        self, permit: c.EffectPermit, event_id: str, expected_revision: int, now: float,
    ) -> None:
        """Accept one correlated completion CAS without clearing prior revocation."""
        with self._lock:
            if type(permit) is not _Permit:
                raise AuthorizationError()
            pending = self._pending.get(permit)
            if pending is None:
                raise AuthorizationError()
            operation_id = pending.scope.binding.operation_id
            with self._critical(pending.scope, now, completion=True):
                if permit not in self._entered:
                    raise AuthorizationError()
                c.uuid_text(event_id)
                c.counter(expected_revision)
                snapshot = self._current(pending.scope, now, completion=True)
                event_key = (operation_id, event_id)
                if snapshot.revision == MAX_SAFE_INT:
                    self._revoke(operation_id)
                    raise AuthorizationError(numeric=True)
                if snapshot.revision != expected_revision or event_key in self._events:
                    raise AuthorizationError()
                self._advance(operation_id, expected_revision)
                self._events.add(event_key)
                del self._pending[permit]
                self._entered.discard(permit)

    def _revoke(self, operation_id: str) -> None:
        self._revoked.add(operation_id)
        self._grants = {
            grant: scope for grant, scope in self._grants.items()
            if scope.binding.operation_id != operation_id
        }
        self._sessions = {
            session: record for session, record in self._sessions.items()
            if record.scope.binding.operation_id != operation_id
        }

    def revoke(self, operation_id: str) -> None:
        """Revoke grants and sessions without allocating a numeric revision."""
        try:
            c.uuid_text(operation_id)
        except c.ContractError:
            raise AuthorizationError() from None
        with self._lock:
            self._revoke(operation_id)

    def is_revoked(self, operation_id: str) -> bool:
        """Expose current cancellation fact for the host, never a permission token."""
        with self._lock:
            return operation_id in self._revoked
