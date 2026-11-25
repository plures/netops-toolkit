"""Explicit host composition for admitted fixed effects, not a controller adapter.

Only application bootstrap constructs this host. Reloaders and effect backends
are private trusted ports, never request JSON or runtime callback registries.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import sys
import threading
from collections import Counter
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol, cast
from uuid import uuid4

if TYPE_CHECKING:
    from netops.core.connection import ConnectionParams, DeviceConnection

from . import contracts as c
from .artifacts import ArtifactError, ArtifactStore, OwnedPolicyJournal, OwnedRecord, OwnedStatePort
from .policy.authorization import (
    AdmissionSnapshot,
    AuthorizationBroker,
    AuthorizationError,
    ConsentReviewPort,
    TrustedConsentAdapter,
    bind_plan,
)
from .policy.contracts import (
    MAX_SAFE_INT,
    DecisionEvent,
    DecisionFacts,
    DecisionResult,
    EffectDescriptor,
    EventKind,
    Phase,
    PolicyState,
    StepDisposition,
    object_value,
)
from .settings import SettingsSnapshot
from .workflows import (
    WorkflowService,
    _planned_effects,
    bind_settings,
    hydrate_inputs,
    plan_digest,
    request_digest,
)

_RESOURCE_MUTEX = threading.RLock()
_HELD_RESOURCES: set[str] = set()


@dataclass(frozen=True)
class _RecoveryQualification:
    """Trusted collector's exact native configuration-recovery qualification.

    An inert transport proof qualifies only that adapter, never a real vendor,
    managed controller or platform. Public requests cannot supply this record.
    """

    target_id: str
    context_digest: str
    route_digest: str
    prestate_digest: str
    proof_digest: str
    expires_at: float


@dataclass(frozen=True)
class ExecutionInputs:
    """Fresh host readings; no plan, allow decision or caller permission field."""

    request: c.OperationRequest
    sources: tuple[c.InputSource, ...]
    settings: SettingsSnapshot
    root_ref: str
    generation: int
    readiness: c.ReadinessProjection
    controller_qualified: bool
    route_qualified: bool
    credential_channel_qualified: bool
    cancelled: bool = False
    recovery_qualifications: tuple[_RecoveryQualification, ...] = ()


class ExecutionSourcePort(Protocol):
    """Application-owned independent readers of current source/qualification facts."""

    def reload(self, operation_id: str) -> ExecutionInputs:
        """Reopen current selected sources/settings/context and qualification evidence."""
        ...


@dataclass(frozen=True)
class EffectResult:
    """Exact safe native step and separate cleanup; no hidden success defaults."""

    step: c.StepOutcome
    cleanup: c.CleanupOutcome = c.CleanupOutcome()
    artifacts: tuple[c.ArtifactDescriptor, ...] = ()


class EffectsBackend(Protocol):
    """Fixed trusted I/O symbols; an inert implementation qualifies dispatch only."""

    def scan(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, cancel: c.CancelPort,
    ) -> EffectResult:
        """Discover only the exact admitted selected target."""
        ...

    def gather(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, cancel: c.CancelPort,
    ) -> EffectResult:
        """Gather the exact selected target without ambient fallback."""
        ...

    def collect(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, cancel: c.CancelPort,
    ) -> EffectResult:
        """Collect the exact selected target without implicit backup or output."""
        ...

    def resolve_for_run(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, cancel: c.CancelPort,
    ) -> EffectResult:
        """Resolve through the private credential channel; return no secret material."""
        ...

    def backup_content(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, cancel: c.CancelPort,
    ) -> bytes:
        """Privately transfer this target's already collected exact configuration."""
        ...

    def retention(
        self, plan: c.OperationPlan, effect: c.PlannedEffect,
        publications: tuple[tuple[c.ArtifactDescriptor, c.ArtifactBinding], ...],
        cancel: c.CancelPort,
    ) -> EffectResult:
        """Apply only the explicit owned backup retention selection/count."""
        ...

    def git(
        self, plan: c.OperationPlan, effect: c.PlannedEffect,
        publications: tuple[tuple[c.ArtifactDescriptor, c.ArtifactBinding], ...],
        cancel: c.CancelPort,
    ) -> EffectResult:
        """Snapshot only these exact protected backup publications, without hooks."""
        ...

    def mutation_connection(
        self, plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> AbstractContextManager[DeviceConnection]:
        """Open this exact private credential/strict-route connection, without fallback."""
        ...


class _MutationHooks:
    """Native hooks carrying an already entered permit, not permission booleans."""

    def __init__(
        self, host: ExecutionHost, plan: c.OperationPlan, effect: c.PlannedEffect,
        permit: c.EffectPermit, prestate: bytes, expected_digest: str,
    ) -> None:
        self.host, self.plan, self.effect, self.permit = host, plan, effect, permit
        self.before, self.expected_digest = prestate, expected_digest
        self.issued = False
        self.verified = False
        self.connection_opened = False
        self.cleanup_failed = False

    @contextmanager
    def connect(self, params: ConnectionParams) -> Iterator[DeviceConnection]:
        self.check()
        manager = self.host._backend.mutation_connection(self.plan, self.effect)
        connection = manager.__enter__()
        self.connection_opened = True
        try:
            yield connection
        except BaseException:
            try:
                manager.__exit__(*sys.exc_info())
            except BaseException:
                self.cleanup_failed = True
                raise
            raise
        else:
            try:
                manager.__exit__(None, None, None)
            except BaseException:
                self.cleanup_failed = True
                raise

    def check(self) -> None:
        self.host._check_mutation(self.plan, self.effect, self.permit)

    def prestate(self, content: str) -> None:
        self.check()
        if content.encode("utf-8") != self.before:
            raise _Rejected(c.ReasonCode.INPUT_BINDING_INVALID)

    def mutating(self) -> None:
        self.check()
        self.issued = True

    def confirm(self, before: str, after: str) -> bool:
        import hashlib

        self.check()
        self.verified = hashlib.sha256(after.encode("utf-8")).hexdigest() == self.expected_digest
        return self.verified


class _Cancellation:
    def __init__(self, host: ExecutionHost, operation_id: str, deadline: float) -> None:
        self._host = host
        self._operation_id = operation_id
        self._deadline = deadline
        self._last_now = 0.0
        self._signal = threading.Event()

    def is_cancelled(self) -> bool:
        try:
            now = self._host._now(self._operation_id)
            if now < self._last_now or now >= self._deadline:
                self._host.authorization.revoke(self._operation_id)
            self._last_now = now
        except BaseException:
            self._host.authorization.revoke(self._operation_id)
            self._signal.set()
            raise
        return self._signal.is_set() or self._host.authorization.is_revoked(self._operation_id)

    def wait(self, timeout: float) -> bool:
        c.finite(timeout)
        if self.is_cancelled():
            return True
        self._signal.wait(min(timeout, max(0.0, self._deadline - self._last_now)))
        return self.is_cancelled()


class _HydrationClock:
    def __init__(self, host: ExecutionHost, operation_id: str) -> None:
        self._host, self._operation_id = host, operation_id

    def monotonic(self) -> float:
        return self._host._now(self._operation_id)

    def utc_now(self) -> c.datetime:
        return self._host._clock.utc_now()


class _MemoryJournalState:
    """Default factual history is process-local, never automatic output."""

    def __init__(self) -> None:
        self.records: dict[str, bytes] = {}
        self.mutex = threading.RLock()

    def lock(self, resource_ids: object, timeout: float) -> threading.RLock:
        return self.mutex

    def read(self, resource_id: str) -> OwnedRecord:
        if resource_id not in self.records:
            raise _Rejected(c.ReasonCode.OWNERSHIP_INVALID)
        return OwnedRecord.from_bytes(self.records[resource_id])

    def compare_replace(
        self, resource_id: str, expected_revision: int, record: OwnedRecord,
    ) -> OwnedRecord:
        current = self.records.get(resource_id)
        if current is None:
            if expected_revision != 0 or record.revision != 0:
                raise _Rejected(c.ReasonCode.CONSENT_STALE)
        elif (
            OwnedRecord.from_bytes(current).revision != expected_revision
            or record.revision != expected_revision + 1
        ):
            raise _Rejected(c.ReasonCode.CONSENT_STALE)
        self.records[resource_id] = record.to_bytes()
        return OwnedRecord.from_bytes(self.records[resource_id])


class _Rejected(RuntimeError):
    def __init__(self, reason: c.ReasonCode) -> None:
        self.reason = reason
        super().__init__(reason.value)


class OwnedAdmissionState:
    """A01 state port sharing owned locks and freshly reloading each admission.

    Numeric admission revisions are in-memory and independent of journal CAS.
    No broker authority survives process loss. Owned resource locks remain the
    cross-process authority; a persisted checkpoint cannot resume dispatch.
    """

    def __init__(self, host: ExecutionHost) -> None:
        self._host = host
        self._mutex = threading.RLock()
        self._revisions: dict[str, int] = {}

    def lock(self, operation_id: str) -> threading.RLock:
        """Serialize host revision writers after the broker's own mutex."""
        c.uuid_text(operation_id)
        return self._mutex

    def snapshot(self, operation_id: str) -> AdmissionSnapshot:
        """Independently reload current host facts, never the approved old plan."""
        service, request = self._host._requests[operation_id]
        plan, inputs = self._host._load(service, request)
        return AdmissionSnapshot(
            bind_plan(plan, inputs.root_ref, inputs.generation),
            self._revisions.get(operation_id, 0), inputs.cancelled, True,
        )

    def compare_revision(
        self, operation_id: str, expected_revision: int, next_revision: int,
    ) -> bool:
        """CAS only exact int53 successor revisions, without reset or coercion."""
        c.counter(expected_revision)
        c.counter(next_revision)
        if expected_revision == MAX_SAFE_INT or next_revision != expected_revision + 1:
            return False
        if self._revisions.get(operation_id, 0) != expected_revision:
            return False
        self._revisions[operation_id] = next_revision
        return True


class ExecutionHost:
    """Host-owned execution on WorkflowService's existing native constructor seam.

    Fixed native symbols are selected only after exact real policy admission.
    Unsupported policy sequences and lifecycle execution remain blocked, rather
    than routing arbitrary names to callbacks.
    """

    def __init__(
        self, sources: ExecutionSourcePort, state: OwnedStatePort,
        reviewer: ConsentReviewPort, backend: EffectsBackend, clock: c.ClockPort,
        ownership_token: str,
    ) -> None:
        c.sha256(ownership_token)
        self._sources = sources
        self._owned = state
        self._backend = backend
        self._clock = clock
        self._owner = ownership_token
        self._requests: dict[str, tuple[WorkflowService, c.OperationRequest]] = {}
        self._state = OwnedAdmissionState(self)
        self._consent = TrustedConsentAdapter(reviewer)
        self.authorization = AuthorizationBroker(self._state, self._consent)
        self._mutex = threading.RLock()
        self._running: set[str] = set()
        self._finished: set[str] = set()
        self._deadlines: dict[str, float] = {}
        self._cancellations: dict[str, _Cancellation] = {}
        self._pending: dict[c.EffectPermit, tuple[c.EffectBinding, str]] = {}
        self._entered: set[c.EffectPermit] = set()
        self._last_now: dict[str, float] = {}
        self._reviewed: dict[str, c.PlanBinding] = {}
        self._output_safe: set[str] = set()
        self._report_sources: dict[str, c.FrozenObject] = {}
        self._generation_sources: dict[str, c.FrozenObject] = {}
        self._output_roots: dict[str, tuple[int, int]] = {}
        self._publications: dict[str, list[tuple[c.ArtifactDescriptor, c.ArtifactBinding]]] = {}
        self._collections: dict[tuple[str, str], c.StepOutcome] = {}
        self._completed_plans: dict[str, c.OperationPlan] = {}
        self._recovery_selection: dict[str, tuple[c.Authorization, ...]] = {}
        self._borrowed_resources: dict[str, tuple[int, frozenset[str]]] = {}
        self._resource_sets: dict[str, frozenset[str]] = {}
        self._mutation_safe: set[str] = set()
        self._memory = _MemoryJournalState()
        self._counts: Counter[tuple[str, str]] = Counter()
        self._logger = logging.getLogger(__name__)

    def _now(self, operation_id: str) -> float:
        try:
            now = c.finite(self._clock.monotonic())
        except BaseException:
            self.authorization.revoke(operation_id)
            raise
        previous = self._last_now.get(operation_id, now)
        if now < previous or now >= self._deadlines.get(operation_id, float("inf")):
            self.authorization.revoke(operation_id)
        self._last_now[operation_id] = max(now, previous)
        return now

    def _emit(self, stage: str, outcome: str) -> None:
        try:
            with self._mutex:
                self._counts[(stage, outcome)] += 1
                self._logger.info("workflow.execution", extra={
                    "metric": "workflow_execution_io_total", "stage": stage, "outcome": outcome,
                })
        except BaseException:
            # Observations never replace backend facts, cancellation or cleanup.
            # Do not retry a pair whose counter or sink may already have advanced.
            return

    def counters(self) -> tuple[tuple[str, str, int], ...]:
        """Expose paired safe local I/O counters, never qualification facts."""
        with self._mutex:
            return tuple((stage, result, count) for (stage, result), count in sorted(
                self._counts.items(),
            ))

    def preview(
        self, request: c.OperationRequest, loaded: c.LoadedInputContext,
    ) -> c.OperationPlan:
        """Delegate pure preview only to this operation's explicitly registered service."""
        registered = self._requests.get(request.operation_id)
        if registered is None:
            raise c.ContractError()
        return registered[0].preview(request, loaded)

    def run(
        self, plan: c.OperationPlan, credentials: c.ScopedCredentials, cancel: c.CancelPort,
    ) -> c.OperationOutcome:
        """Reject the native bypass: credentials and a plan are not A01 authority."""
        raise c.ContractError()

    @contextmanager
    def _io(self, stage: str) -> Iterator[None]:
        self._emit(stage, "started")
        try:
            yield
        except BaseException:
            self._emit(stage, "failed")
            raise
        else:
            self._emit(stage, "succeeded")

    def _load(
        self, service: WorkflowService, request: c.OperationRequest,
    ) -> tuple[c.OperationPlan, ExecutionInputs]:
        self._emit("reload", "started")
        self._report_sources.pop(request.operation_id, None)
        self._generation_sources.pop(request.operation_id, None)
        try:
            inputs = self._sources.reload(request.operation_id)
            if type(inputs) is not ExecutionInputs:
                raise c.ContractError()
            if any(type(value) is not bool for value in (
                inputs.controller_qualified, inputs.route_qualified,
                inputs.credential_channel_qualified, inputs.cancelled,
            )):
                raise c.ContractError()
            c.text(inputs.root_ref)
            c.counter(inputs.generation)
            current = c.OperationRequest.from_json(c.canonical_bytes(inputs.request))
            if request_digest(current) != request_digest(request):
                raise _Rejected(c.ReasonCode.INPUT_BINDING_INVALID)
            loaded = bind_settings(
                current, hydrate_inputs(
                    current, inputs.sources, _HydrationClock(self, request.operation_id),
                ), inputs.settings,
            )
            plan = service.preview(current, loaded)
            if plan.operation == "compare.generate":
                # Keep validated source dispositions even when no output can
                # be reviewed. This cache is factual, never consent or intent.
                self._generation_sources[request.operation_id] = self._generation_source(plan)
            if plan.operation == "report.render" and isinstance(
                plan.native_payload.get("report"), c.FrozenObject,
            ):
                # Retain only the validated minimized source projection if a
                # later preflight fails. This is factual data, never admission.
                self._report_sources[request.operation_id] = cast(
                    c.FrozenObject, plan.native_payload["report"],
                )
            for route in plan.routes:
                for exclusion in current.scope.exclusions:
                    try:
                        excluded = ipaddress.ip_network(exclusion)
                        address = ipaddress.ip_address(c.text(route["host"]))
                    except (ValueError, KeyError):
                        raise _Rejected(c.ReasonCode.ROUTE_UNAVAILABLE) from None
                    if address in excluded:
                        raise _Rejected(c.ReasonCode.ROUTE_UNAVAILABLE)
            # Local output consumes the actual native encoder in its fixed
            # handler. A global controller/dependency tier projection is not
            # that encoder's capability, and cannot qualify or block it.
            if not self._local_output(plan) and (
                not inputs.controller_qualified or not inputs.route_qualified
                or not inputs.credential_channel_qualified
                or inputs.readiness.companion != "ready"
                or len(inputs.readiness.errors) != 0
                or inputs.settings.ansible.enabled is not True
            ):
                raise _Rejected(c.ReasonCode.DEPENDENCY_NOT_READY)
            # Only host-proven prerequisites are discharged; all source,
            # observation, route and output diagnostics remain load-bearing.
            remaining = tuple(error for error in plan.preconditions if error.reason not in (
                c.ReasonCode.DEPENDENCY_NOT_READY, c.ReasonCode.CONSENT_REQUIRED,
            ))
            plan = replace(plan, preconditions=remaining)
            if plan.operation in ("config.apply", "config.rollback"):
                intent = self._mutation_intent(plan)
                for target in plan.targets:
                    descriptor, prestate_binding, _ = self._mutation_prestate(service, plan, target)
                    if (
                        prestate_binding.effect.plan.root_ref != inputs.root_ref
                        or prestate_binding.effect.plan.generation != inputs.generation
                    ):
                        raise _Rejected(c.ReasonCode.OWNERSHIP_INVALID)
                    qualifications = tuple(
                        item for item in inputs.recovery_qualifications
                        if type(item) is _RecoveryQualification and item.target_id == target
                    )
                    if len(qualifications) != 1:
                        raise _Rejected(c.ReasonCode.DEPENDENCY_NOT_READY)
                    qualified = qualifications[0]
                    c.sha256(qualified.proof_digest)
                    if (
                        qualified.context_digest != c.digest(plan.context)
                        or qualified.route_digest != c.digest(tuple(
                            route for route in plan.routes if route["target_id"] == target
                        ))
                        or qualified.prestate_digest != descriptor.digest
                        or self._now(plan.operation_id) >= c.finite(qualified.expires_at)
                    ):
                        raise _Rejected(c.ReasonCode.DEPENDENCY_NOT_READY)
                if not callable(getattr(self._backend, "mutation_connection", None)):
                    raise _Rejected(c.ReasonCode.DEPENDENCY_NOT_READY)
                if plan.operation == "config.apply":
                    recoveries = self._recovery_plans(plan)
                    plan = replace(plan, native_payload=c.public_object({
                        **dict(plan.native_payload), "approved_recovery": tuple(
                            c.public_object({
                                "target_id": recovery.targets[0],
                                "plan_digest": recovery.plan_digest,
                                "operation_id": recovery.operation_id,
                                "prestate": recovery.recovery_scope[0],
                            }) for recovery in recoveries
                        ),
                    }))
                # Only exact configuration restoration is qualified here;
                # image/reload/boot recovery cannot follow from snapshot replay.
                if intent["kind"] != "configuration":
                    raise _Rejected(c.ReasonCode.INPUT_BINDING_INVALID)
            plan = replace(plan, plan_digest=plan_digest(plan))
            if plan.operation in ("config.apply", "config.rollback"):
                self._mutation_safe.add(plan.plan_digest)
            if remaining:
                raise _Rejected(remaining[0].reason)
            if request.plan_digest is not None and request.plan_digest != plan.plan_digest:
                raise _Rejected(c.ReasonCode.CONSENT_STALE)
            if plan.requested_mode == c.Mode.OUTPUT and plan.operation in (
                "scan.save", "inventory.export", "report.render", "compare.generate", "config.backup",
            ):
                if (
                    plan.output_intent.root_ref != inputs.root_ref
                    or type(service._artifacts) is not ArtifactStore
                ):
                    raise _Rejected(c.ReasonCode.OUTPUT_REJECTED)
                with self._io("output-preflight"):
                    if plan.operation == "scan.save":
                        selected_input = self._input_value(plan, "fragment")
                    elif plan.operation == "inventory.export":
                        selected_input = self._input_value(plan, "inventory")
                    elif plan.operation == "report.render":
                        self._input_value(plan, "outcomes")
                    elif plan.operation == "compare.generate":
                        self._input_value(plan, "findings")
                        if (
                            plan.output_intent.kinds != ("yaml",)
                            or plan.output_intent.retention or plan.output_intent.git
                            or not self._generation_eligible(plan)
                        ):
                            raise _Rejected(c.ReasonCode.OUTPUT_REJECTED)
                    elif plan.operation == "config.backup":
                        if (
                            plan.output_intent.kinds != ("text",)
                            or plan.output_intent.retention is not True
                            or not callable(getattr(self._backend, "backup_content", None))
                            or not callable(getattr(self._backend, "retention", None))
                            or (plan.output_intent.git and not callable(getattr(self._backend, "git", None)))
                        ):
                            raise _Rejected(c.ReasonCode.OUTPUT_REJECTED)
                    if plan.operation in ("scan.save", "inventory.export") and any(
                        target not in selected_input.get("devices", {}) for target in plan.targets
                    ):
                        raise _Rejected(c.ReasonCode.INPUT_BINDING_INVALID)
                    expected_kinds = (
                        ("html", "pdf") if plan.operation == "report.render"
                        else ("yaml",) if plan.operation == "compare.generate"
                        else ("text",) if plan.operation == "config.backup" else ("json", "yaml")
                    )
                    if plan.output_intent.kinds not in tuple((kind,) for kind in expected_kinds):
                        raise _Rejected(c.ReasonCode.OUTPUT_REJECTED)
                    root = service._artifacts._preflight_public(
                        plan.output_intent, c.canonical_bytes(plan.native_payload),
                    )
                    self._output_roots[plan.operation_id] = (root.device, root.inode)
                    if plan.operation == "report.render":
                        self._report_coverage(plan)
                self._output_safe.add(plan.plan_digest)
            self._emit("reload", "succeeded")
            return plan, inputs
        except BaseException:
            self.authorization.revoke(request.operation_id)
            self._emit("reload", "failed")
            raise

    @staticmethod
    def _mutation_intent(plan: c.OperationPlan) -> dict:
        intent = ExecutionHost._input_value(plan, "intent")
        if (
            set(intent) != {"kind", "commands", "expected_digest", "prestate"}
            or intent["kind"] != "configuration"
            or type(intent["commands"]) is not list
            or not intent["commands"] or any(
                type(command) is not str or not command.strip()
                or "\n" in command or "\r" in command for command in intent["commands"]
            )
            or type(intent["prestate"]) is not dict
            or set(intent["prestate"]) != set(plan.targets)
            or not plan.targets
            or plan.output_intent != c.OutputIntent()
        ):
            raise _Rejected(c.ReasonCode.INPUT_BINDING_INVALID)
        c.sha256(intent["expected_digest"])
        if plan.recovery_scope != tuple(c.text(intent["prestate"][target]) for target in plan.targets):
            raise _Rejected(c.ReasonCode.INPUT_BINDING_INVALID)
        return intent

    def _mutation_prestate(
        self, service: WorkflowService, plan: c.OperationPlan, target: str,
    ) -> tuple[c.ArtifactDescriptor, c.ArtifactBinding, bytes]:
        intent = self._mutation_intent(plan)
        selected = intent["prestate"][target]
        for operation_id, publications in self._publications.items():
            previous = self._completed_plans.get(operation_id)
            if previous is None or previous.operation != "config.backup":
                continue
            old_routes = tuple(route for route in previous.routes if route["target_id"] == target)
            new_routes = tuple(route for route in plan.routes if route["target_id"] == target)
            if previous.context != plan.context or old_routes != new_routes:
                continue
            for descriptor, binding in publications:
                if (
                    descriptor.ref == selected and binding.effect.target_id == target
                    and descriptor.classification == "sensitive"
                    and descriptor.retention == "explicit"
                    and binding.effect.plan.plan_digest == previous.plan_digest
                    and type(service._artifacts) is ArtifactStore
                ):
                    with self._io("prestate-read"):
                        content = service._artifacts.read(descriptor, binding)
                    if not content:
                        raise _Rejected(c.ReasonCode.INPUT_BINDING_INVALID)
                    return descriptor, binding, content
        raise _Rejected(c.ReasonCode.INPUT_BINDING_INVALID)

    def _recovery_plans(self, plan: c.OperationPlan) -> tuple[c.OperationPlan, ...]:
        grants = self._recovery_selection.get(plan.operation_id, ())
        if len(grants) != len(plan.targets):
            raise _Rejected(c.ReasonCode.CONSENT_REQUIRED)
        result: list[c.OperationPlan] = []
        for target, grant in zip(plan.targets, grants):
            scope = next((scope for token, scope in self.authorization._grants.items()
                          if token is grant), None)
            if scope is None:
                raise _Rejected(c.ReasonCode.CONSENT_STALE)
            selected = self._requests.get(scope.binding.operation_id)
            if selected is None or selected[1].operation != "config.rollback":
                raise _Rejected(c.ReasonCode.CONSENT_STALE)
            recovery, inputs = self._load(*selected)
            if (
                recovery.targets != (target,) or recovery.context != plan.context
                or recovery.recovery_scope != (
                    plan.recovery_scope[plan.targets.index(target)],
                )
                or recovery.routes != tuple(route for route in plan.routes if route["target_id"] == target)
                or bind_plan(recovery, inputs.root_ref, inputs.generation) != scope.binding
                or self.authorization.is_revoked(recovery.operation_id)
                or self._now(recovery.operation_id) >= self._deadlines[recovery.operation_id]
            ):
                raise _Rejected(c.ReasonCode.CONSENT_STALE)
            result.append(recovery)
        return tuple(result)

    @staticmethod
    def _local_output(plan: c.OperationPlan) -> bool:
        """Identify only fixed pure-local public output effects, never device work."""
        return plan.requested_mode == c.Mode.OUTPUT and plan.operation in (
            "scan.save", "inventory.export", "report.render", "compare.generate",
        ) and bool(plan.effects) and all(effect.target_id == "local" for effect in plan.effects)

    @staticmethod
    def _supported(plan: c.OperationPlan) -> None:
        supported = {
            "scan.discover": (c.Mode.OBSERVE, "scan"),
            "health.gather": (c.Mode.OBSERVE, "gather"),
            "config.collect": (c.Mode.OBSERVE, "collect"),
            "vault.resolve-for-run": (c.Mode.OBSERVE, "resolve-for-run"),
            "scan.save": (c.Mode.OUTPUT, "save"),
            "inventory.export": (c.Mode.OUTPUT, "export"),
            "report.render": (c.Mode.OUTPUT, "render"),
            "compare.generate": (c.Mode.OUTPUT, "save"),
            "inventory.refresh": (c.Mode.OBSERVE, "refresh"),
            "config.apply": (c.Mode.APPLY, "apply"),
            "config.rollback": (c.Mode.ROLLBACK, "rollback"),
        }
        if plan.operation == "config.backup":
            expected = tuple(
                (target, kind)
                for target in plan.targets
                for kind in (("collect",) if plan.requested_mode == c.Mode.OBSERVE else ("collect", "backup"))
            )
            if plan.requested_mode == c.Mode.OUTPUT:
                expected += tuple(
                    ("local", kind) for kind, selected in (
                        ("retention", plan.output_intent.retention), ("git", plan.output_intent.git),
                    ) if selected
                )
            if (
                plan.requested_mode not in (c.Mode.OBSERVE, c.Mode.OUTPUT)
                or not plan.targets or not expected
                or tuple((effect.target_id, effect.kind) for effect in plan.effects) != expected
                or (plan.requested_mode == c.Mode.OBSERVE and (
                    plan.output_intent.root_ref is not None or plan.output_intent.kinds
                    or plan.output_intent.retention or plan.output_intent.git
                ))
            ):
                raise _Rejected(c.ReasonCode.DEPENDENCY_NOT_READY)
            return
        selected = supported.get(plan.operation)
        if selected is None or (
            plan.requested_mode != selected[0] or not plan.effects
            or any(effect.kind != selected[1] for effect in plan.effects)
        ):
            raise _Rejected(c.ReasonCode.DEPENDENCY_NOT_READY)

    @staticmethod
    def _report_coverage(plan: c.OperationPlan) -> None:
        covered: list[str] = []
        inputs = plan.native_payload["inputs"]
        if not isinstance(inputs, tuple):
            raise c.ContractError()
        for item in inputs:
            if not isinstance(item, c.FrozenObject) or item["kind"] != "outcomes":
                continue
            outcome = c.OperationOutcome.from_json(c.canonical_bytes(item["value"]))
            covered.extend(target.target_id for target in outcome.targets if target.selected)
        if any(target not in covered for target in plan.targets):
            raise _Rejected(c.ReasonCode.INPUT_BINDING_INVALID)

    @staticmethod
    def _generation_source(plan: c.OperationPlan) -> c.FrozenObject:
        """Retain selected coverage only, not executable plays or raw inputs."""
        return c.public_object({
            "request_digest": plan.request_digest,
            "coverage": plan.native_payload.get("coverage", ()),
            "execution_performed": False, "collect_authorized": False,
            "apply_authorized": False,
        })

    @staticmethod
    def _generation_eligible(plan: c.OperationPlan) -> bool:
        """Require native generated plays before protected save admission."""
        generated = plan.native_payload.get("generated")
        content = plan.native_payload.get("generated_yaml")
        return (
            plan.operation == "compare.generate" and isinstance(generated, tuple)
            and bool(generated) and isinstance(content, str) and bool(content.strip())
        )

    def _facts(
        self, plan: c.OperationPlan, remaining_ms: int, cancelled: bool = False,
        effect: c.PlannedEffect | None = None,
    ) -> DecisionFacts:
        if effect is not None and (
            effect.ordinal >= len(plan.effects) or plan.effects[effect.ordinal] != effect
        ):
            raise c.ContractError()
        reviewed = self._reviewed.get(plan.operation_id)
        consent_matches = reviewed is not None and (
            bind_plan(plan, reviewed.root_ref, reviewed.generation) == reviewed
        )
        consent_ms = 0 if not consent_matches else max(0, min(
            remaining_ms, int((self._deadlines[plan.operation_id] - self._now(plan.operation_id)) * 1000),
        ))
        return DecisionFacts(object_value({
            "request": {"area": c.capability(plan.operation).area,
                        "operation": c.capability(plan.operation).operation,
                        "mode": plan.requested_mode.value},
            "binding": {"input_valid": True, "plan_current": True, "policy_current": True},
            "control": {"cancelled": cancelled, "remaining_ms": remaining_ms},
            "scope": {"exclusions_valid": True, "selected_count": len(plan.targets)},
            "config": {"enabled": plan.settings.ansible.enabled, "mode": plan.settings.ansible.mode},
            "inventory": {"source_valid": True, "cache_binding_valid": True, "hostvars_safe": True},
            "readiness": {"companion": "ready"},
            "controller": {"qualified": not self._local_output(plan)},
            "route": {"qualified": not self._local_output(plan)},
            "credentials": {"channel_qualified": not self._local_output(plan)},
            "discovery": {"scope_valid": True},
            "operational": {"next_effect_kind": (
                effect.kind if plan.operation == "config.backup" and effect is not None else "none"
            )},
            "lifecycle": {"next_effect_kind": "none"},
            "output": {
                "retention_requested": plan.output_intent.retention,
                "git_requested": plan.output_intent.git,
            },
            "storage": {"sensitive_ready": (
                plan.operation == "config.backup" and plan.requested_mode == c.Mode.OUTPUT
                and plan.plan_digest in self._output_safe
            ) or plan.plan_digest in self._mutation_safe},
            "change": {
                "prestate_bound": plan.plan_digest in self._mutation_safe,
                "vendor_recovery_qualified": plan.plan_digest in self._mutation_safe,
                "poststate_verified": False,
            },
            "consent": {
                "present": consent_matches, "binding_matches": consent_matches,
                "effects_match": consent_matches, "remaining_ms": consent_ms,
                "recovery_matches": consent_matches and bool(plan.recovery_scope),
            },
            "report": {
                "output_safe": plan.plan_digest in self._output_safe,
                "coverage_complete": plan.operation == "report.render"
                and plan.plan_digest in self._output_safe,
            },
            "compare": {
                # Current hydration/preview validates parser, vendor and
                # digest binding before this protected-output preflight.
                "inputs_bound": plan.operation == "compare.generate"
                and plan.plan_digest in self._output_safe and self._generation_eligible(plan),
                "vendor_supported": plan.operation == "compare.generate"
                and plan.plan_digest in self._output_safe and self._generation_eligible(plan),
            },
        }))

    @staticmethod
    def _requested(plan: c.OperationPlan, effect: c.PlannedEffect) -> DecisionEvent:
        mutation = plan.operation in ("config.apply", "config.rollback")
        return DecisionEvent(
            str(uuid4()), (
                EventKind.APPLY_CONSENTED if mutation
                else EventKind.OPERATION_REQUESTED
            ), 0, plan.plan_digest,
            c.digest(plan.context), plan.policy_digest, effect.target_id, effect.occurrence_id,
            c.public_object({
                "plan_digest": plan.plan_digest,
                "approved_effect_ids": tuple(item.occurrence_id for item in plan.effects),
                "approved_recovery_ids": plan.recovery_scope,
                "private_consent_reference": "host-reviewed",
            } if mutation else {
                "request_digest": plan.request_digest, "loaded_input_digest": plan.input_binding_digest,
                "plan_digest": plan.plan_digest, "mode": plan.requested_mode.value,
            }), operation_id=plan.operation_id,
        )

    def review(
        self, service: WorkflowService, request: c.OperationRequest,
        *, recovery: tuple[c.Authorization, ...] = (),
    ) -> c.Authorization:
        """Review and issue the exact fresh plan through the actual A01 broker."""
        request = c.OperationRequest.from_json(c.canonical_bytes(request))
        if service._authorization is not self.authorization or service._native is not self:
            raise _Rejected(c.ReasonCode.CONSENT_STALE)
        with self._mutex:
            if (
                request.operation_id in self._running or request.operation_id in self._finished
                or request.operation_id in self._reviewed
            ):
                raise _Rejected(c.ReasonCode.RESOURCE_BUSY)
            if recovery:
                if request.operation != "config.apply" or type(recovery) is not tuple:
                    raise _Rejected(c.ReasonCode.CONSENT_STALE)
                self._recovery_selection[request.operation_id] = recovery
            self._requests[request.operation_id] = (service, request)
        plan, inputs = self._load(service, request)
        self._supported(plan)
        now = self._now(request.operation_id)
        binding = bind_plan(plan, inputs.root_ref, inputs.generation)
        duration = min(float(plan.settings.authorization.ttl_seconds), plan.deadline_ms / 1000.0)
        if plan.operation == "config.apply":
            duration = min(duration, *(self._deadlines[item.operation_id] - now
                                       for item in self._recovery_plans(plan)))
        receipt = self._consent.review(plan, binding, now, duration)
        self._deadlines[request.operation_id] = c.checked_deadline(now, duration)
        self._reviewed[request.operation_id] = binding
        decisions = tuple(service._policy.decide(
            self._requested(plan, effect), self._facts(plan, plan.deadline_ms, effect=effect),
        ) for effect in plan.effects)
        if plan.operation in ("config.apply", "config.rollback"):
            # Preserve the actual evaluator's denial/rules/identity. The
            # factual phase projection is not an executable admission intent.
            if any(any(
                item != EffectDescriptor("set_phase", c.public_object({"phase": "Admitted"}))
                and item.name != "request_effect" for item in decision.effects
            ) for decision in decisions):
                raise _Rejected(c.ReasonCode.CONSENT_STALE)
            decisions = tuple(replace(decision, effects=tuple(
                item for item in decision.effects if item.name == "request_effect"
            )) for decision in decisions)
        expected = tuple(EffectDescriptor("request_effect", c.public_object({"kind": e.kind}))
                         for e in plan.effects)
        if any(
            type(decision) is not DecisionResult or decision.decision != "allow"
            or decision.policy_digest != plan.policy_digest
            or decision.effects != (expected[index],)
            for index, decision in enumerate(decisions)
        ):
            raise _Rejected(c.ReasonCode.CONSENT_STALE)
        decision = replace(
            decisions[0], rule_ids=tuple(sorted({rule for d in decisions for rule in d.rule_ids})),
            effects=tuple(d.effects[0] for d in decisions),
        )
        return self.authorization.issue(plan, receipt, decision, self._now(request.operation_id))

    def notify_cancelled(self, operation_id: str) -> None:
        """Wake only this operation's cooperative backend after broker revocation."""
        c.uuid_text(operation_id)
        with self._mutex:
            cancel = self._cancellations.get(operation_id)
            if cancel is not None:
                cancel._signal.set()

    @contextmanager
    def _resources(self, plan: c.OperationPlan) -> Iterator[None]:
        # Device identities exclude aliases, vendor labels and credentials.
        # Include the concrete route separately; aliases to the same endpoint
        # therefore contend even if their operation IDs differ.
        resources = ["operation/" + plan.operation_id]
        if plan.output_intent.root_ref is not None:
            resources.append("output/" + c.digest(c.public_object({
                "root": tuple(str(value) for value in self._output_roots.get(
                    plan.operation_id, (),
                )) or (plan.output_intent.root_ref,),
            })))
        # Pure local output retains operation/protected-root contention but
        # has no device endpoint. Do not interpret finding identity as a route.
        for route in (() if self._local_output(plan) else plan.routes):
            host = c.text(route["host"]).casefold().rstrip(".")
            try:
                host = ipaddress.ip_address(host).compressed
            except ValueError:
                host = host.encode("idna").decode("ascii")
            endpoint = c.public_object({
                "host": host,
                "port": route["port"], "transport": route["transport"],
            })
            resources.append("device/" + c.digest(endpoint))
            resources.append("route/" + c.digest(c.public_object({
                "endpoint": endpoint, "controller": plan.context.controller_id,
                "route": plan.context.route_digest,
            })))
        ordered = tuple(sorted(set(resources)))
        # Native owned locks deliberately support storage reentrancy on the
        # same thread. That must not admit nested *executions* of a resource.
        with _RESOURCE_MUTEX:
            inherited = self._borrowed_resources.get(plan.operation_id)
            allowed = (
                inherited[1] if inherited is not None and inherited[0] == threading.get_ident()
                else frozenset()
            )
            if _HELD_RESOURCES.intersection(ordered).difference(allowed):
                raise _Rejected(c.ReasonCode.RESOURCE_BUSY)
            acquired = set(ordered).difference(_HELD_RESOURCES)
            _HELD_RESOURCES.update(acquired)
            self._resource_sets[plan.operation_id] = frozenset(ordered)
        try:
            with self._io("resource-lock"), self._owned.lock(ordered, 0.0):
                yield
        finally:
            with _RESOURCE_MUTEX:
                _HELD_RESOURCES.difference_update(acquired)
                self._resource_sets.pop(plan.operation_id, None)

    def _check_mutation(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, permit: c.EffectPermit,
    ) -> None:
        pending = self._pending.get(permit)
        if pending is None or permit not in self._entered:
            raise _Rejected(c.ReasonCode.CONSENT_STALE)
        binding = self.authorization.reconcile(permit)
        if binding != pending[0] or binding.occurrence_id != effect.occurrence_id:
            raise _Rejected(c.ReasonCode.CONSENT_STALE)
        if self._cancellations[plan.operation_id].is_cancelled():
            raise _Rejected(c.ReasonCode.CANCELLED)
        service, request = self._requests[plan.operation_id]
        current, inputs = self._load(service, request)
        if inputs.cancelled or bind_plan(current, inputs.root_ref, inputs.generation) != binding.plan:
            raise _Rejected(c.ReasonCode.CONSENT_STALE)

    def _mutate(
        self, permit: c.EffectPermit, binding: c.EffectBinding,
        plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> EffectResult:
        from netops.change.push import _run_guarded_rollback, run_push
        from netops.core.connection import ConnectionParams, Transport

        if effect.kind not in ("apply", "rollback"):
            raise _Rejected(c.ReasonCode.CONSENT_STALE)
        self._entry(permit, binding, plan, effect, effect.kind)
        with self._io(effect.kind):
            intent = self._mutation_intent(plan)
            descriptor, _, content = self._mutation_prestate(
                self._requests[plan.operation_id][0], plan, effect.target_id,
            )
            route = next(route for route in plan.routes if route["target_id"] == effect.target_id)
            params = ConnectionParams(
                host=c.text(route["host"]), device_type=c.text(route["vendor"]),
                port=c.counter(route["port"], positive=True),
                transport=Transport(c.text(route["transport"])),
            )
            hooks = _MutationHooks(
                self, plan, effect, permit, content,
                descriptor.digest if effect.kind == "rollback" else intent["expected_digest"],
            )
            from .controller_backend import _ControllerEffectsBackend

            if type(self._backend) is _ControllerEffectsBackend:
                return self._backend._mutate_action(
                    plan, effect, permit, content, descriptor.ref, hooks.expected_digest,
                )
            if effect.kind == "apply":
                record = run_push(params, intent["commands"], commit=True, hooks=hooks)
            elif effect.kind == "rollback":
                record = _run_guarded_rollback(params, content.decode("utf-8"), hooks)
            else:
                raise _Rejected(c.ReasonCode.CONSENT_STALE)
            succeeded = hooks.verified and record.confirmed and (
                record.error is None or hooks.cleanup_failed
            )
            errors = () if succeeded else (c.SafeError(
                c.ErrorCategory.EXECUTION, c.ReasonCode.APPLY_FAILED,
                c.Stage.RECOVER if effect.kind == "rollback" else c.Stage.APPLY,
                target_id=effect.target_id, step_id=effect.occurrence_id,
                next_action="Inspect actual state; do not retry an issued command.",
            ),)
            cleanup = c.CleanupOutcome(
                "failed" if hooks.cleanup_failed else (
                    "succeeded" if hooks.connection_opened else "not-requested"
                ),
                errors=() if not hooks.cleanup_failed else (c.SafeError(
                    c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
                    target_id=effect.target_id, step_id=effect.occurrence_id,
                    next_action="Inspect the selected connection teardown; do not replay mutation.",
                ),),
            )
            return EffectResult(c.StepOutcome(
                effect.occurrence_id,
                c.OutcomeStatus.SUCCEEDED if succeeded else c.OutcomeStatus.FAILED, True,
                native_payload=c.public_object({
                    "committed": record.committed, "confirmed": record.confirmed,
                    "rolled_back": record.rolled_back, "issued": hooks.issued,
                    "poststate_verified": hooks.verified,
                    "prestate_ref": descriptor.ref, "recovery_status": (
                        "not-needed" if succeeded else "not-attempted"
                    ) if effect.kind == "apply" else "not-requested",
                }),
                changed=hooks.issued,
                remote_state=(
                    ("rolled-back" if effect.kind == "rollback" else "confirmed") if succeeded
                    else ("uncertain" if hooks.issued else "unchanged")
                ), errors=errors,
            ), cleanup)

    def _recover_apply(
        self, service: WorkflowService, plan: c.OperationPlan,
        effect: c.PlannedEffect, result: EffectResult,
    ) -> EffectResult:
        if result.step.native_payload.get("issued") is not True:
            return result
        grants = self._recovery_selection.get(plan.operation_id, ())
        if len(grants) != len(plan.targets):
            return result
        grant = grants[plan.targets.index(effect.target_id)]
        scope = next((scope for token, scope in self.authorization._grants.items()
                      if token is grant), None)
        if scope is None:
            return replace(result, step=replace(result.step, native_payload=c.public_object({
                **dict(result.step.native_payload), "recovery_status": "blocked",
            })))
        selected = self._requests[scope.binding.operation_id]
        # Borrow only this synchronous parent's already held endpoint locks.
        # The child still consumes its own exact, separately reviewed A01 grant.
        child_id = selected[1].operation_id
        self._borrowed_resources[child_id] = (
            threading.get_ident(), self._resource_sets[plan.operation_id],
        )
        try:
            recovery = self.execute(*selected, grant)
        finally:
            self._borrowed_resources.pop(child_id, None)
        restored = bool(recovery.targets) and all(
            target.remote_state == "rolled-back" for target in recovery.targets
        )
        cleanup = c.CleanupOutcome(
            "failed" if "failed" in (result.cleanup.status, recovery.cleanup.status) else (
                "succeeded" if "succeeded" in (result.cleanup.status, recovery.cleanup.status)
                else "not-requested"
            ),
            tuple(sorted(set(result.cleanup.remaining_refs + recovery.cleanup.remaining_refs))),
            result.cleanup.errors + recovery.cleanup.errors,
        )
        return replace(result, cleanup=cleanup, step=replace(
            result.step, remote_state="rolled-back" if restored else result.step.remote_state,
            native_payload=c.public_object({
                **dict(result.step.native_payload), "recovery_status": recovery.status.value,
                "recovery_operation_id": recovery.operation_id,
                "recovery": json.loads(c.canonical_bytes(recovery)),
            }),
        ))

    def _gather(
        self, permit: c.EffectPermit, binding: c.EffectBinding,
        plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> EffectResult:
        self._entry(permit, binding, plan, effect, "gather")
        self._emit("gather", "started")
        try:
            result = self._backend.gather(plan, effect, self._cancellations[plan.operation_id])
            self._validate_result(result, effect)
            self._emit("gather", "succeeded")
            return result
        except BaseException:
            self._emit("gather", "failed")
            raise

    def _scan(
        self, permit: c.EffectPermit, binding: c.EffectBinding,
        plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> EffectResult:
        self._entry(permit, binding, plan, effect, "scan")
        with self._io("scan"):
            result = self._backend.scan(plan, effect, self._cancellations[plan.operation_id])
            self._validate_result(result, effect)
            return result

    def _collect(
        self, permit: c.EffectPermit, binding: c.EffectBinding,
        plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> EffectResult:
        self._entry(permit, binding, plan, effect, "collect")
        self._emit("collect", "started")
        try:
            result = self._backend.collect(plan, effect, self._cancellations[plan.operation_id])
            self._validate_result(result, effect)
            if result.step.status == c.OutcomeStatus.SUCCEEDED:
                self._collections[(plan.operation_id, effect.target_id)] = result.step
            self._emit("collect", "succeeded")
            return result
        except BaseException:
            self._emit("collect", "failed")
            raise

    def _refresh(
        self, permit: c.EffectPermit, binding: c.EffectBinding,
        plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> EffectResult:
        self._entry(permit, binding, plan, effect, "refresh")
        with self._io("refresh"):
            from netops.core.inventory import Inventory

            from .dynamic_inventory import _from_inventory

            # _load and broker entry have rehydrated/rebound the source. Never
            # rescue it from a stale cache or write during this observe effect.
            value = self._input_value(plan, "inventory")
            if plan.targets:
                value["devices"] = {
                    name: item for name, item in value.get("devices", {}).items()
                    if name in plan.targets
                }
            return EffectResult(c.StepOutcome(
                effect.occurrence_id, c.OutcomeStatus.SUCCEEDED, True,
                native_payload=c.public_object(_from_inventory(Inventory._from_data(value))),
            ))

    def _backup(
        self, permit: c.EffectPermit, binding: c.EffectBinding,
        plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> EffectResult:
        self._entry(permit, binding, plan, effect, "backup")
        with self._io("backup"):
            from .native_effects import _publish_backup

            collected = self._collections.get((plan.operation_id, effect.target_id))
            if collected is None:
                raise _Rejected(c.ReasonCode.INPUT_BINDING_INVALID)
            content = self._backend.backup_content(
                plan, effect, self._cancellations[plan.operation_id],
            )
            if self._cancellations[plan.operation_id].is_cancelled():
                return EffectResult(c.StepOutcome(
                    effect.occurrence_id, c.OutcomeStatus.CANCELLED, True,
                    unapplied_effects=("backup",),
                ))
            descriptor, artifact_binding = _publish_backup(
                self._requests[plan.operation_id][0]._artifacts,
                plan, effect, binding, content,
            )
            self._publications.setdefault(plan.operation_id, []).append((descriptor, artifact_binding))
            return EffectResult(c.StepOutcome(
                effect.occurrence_id, c.OutcomeStatus.SUCCEEDED, True,
                native_payload=collected.native_payload, changed=True,
            ), artifacts=(descriptor,))

    def _retention(
        self, permit: c.EffectPermit, binding: c.EffectBinding,
        plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> EffectResult:
        self._entry(permit, binding, plan, effect, "retention")
        with self._io("retention"):
            result = self._backend.retention(
                plan, effect, tuple(self._publications.get(plan.operation_id, ())),
                self._cancellations[plan.operation_id],
            )
            self._validate_result(result, effect)
            return result

    def _git(
        self, permit: c.EffectPermit, binding: c.EffectBinding,
        plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> EffectResult:
        self._entry(permit, binding, plan, effect, "git")
        with self._io("git"):
            result = self._backend.git(
                plan, effect, tuple(self._publications.get(plan.operation_id, ())),
                self._cancellations[plan.operation_id],
            )
            self._validate_result(result, effect)
            return result

    def _resolve_for_run(
        self, permit: c.EffectPermit, binding: c.EffectBinding,
        plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> EffectResult:
        self._entry(permit, binding, plan, effect, "resolve-for-run")
        with self._io("resolve-for-run"):
            result = self._backend.resolve_for_run(
                plan, effect, self._cancellations[plan.operation_id],
            )
            self._validate_result(result, effect)
            return result

    def _save(
        self, permit: c.EffectPermit, binding: c.EffectBinding,
        plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> EffectResult:
        self._entry(permit, binding, plan, effect, "save")
        with self._io("save"):
            if plan.operation == "compare.generate":
                content = plan.native_payload.get("generated_yaml")
                if not isinstance(content, str) or plan.output_intent.kinds != ("yaml",):
                    raise _Rejected(c.ReasonCode.OUTPUT_REJECTED)
                # Do not dump the projection as a YAML mapping or regenerate
                # volatile identity/time: publish the exact reviewed bytes.
                return self._publish(plan, effect, binding, dict(plan.native_payload), content.encode("utf-8"))
            from netops.inventory.scan import _merge_inventory_data

            existing = self._input_value(plan, "inventory", required=False)
            fragment = self._input_value(plan, "fragment")
            if plan.targets:
                fragment["devices"] = {
                    name: value for name, value in fragment.get("devices", {}).items()
                    if name in plan.targets
                }
            native = _merge_inventory_data(existing, fragment)
            return self._publish(plan, effect, binding, native)

    def _export(
        self, permit: c.EffectPermit, binding: c.EffectBinding,
        plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> EffectResult:
        self._entry(permit, binding, plan, effect, "export")
        with self._io("export"):
            from netops.core.inventory import Inventory

            from .dynamic_inventory import _from_inventory

            inventory = self._input_value(plan, "inventory")
            if plan.targets:
                inventory["devices"] = {
                    name: value for name, value in inventory.get("devices", {}).items()
                    if name in plan.targets
                }
            native = _from_inventory(Inventory._from_data(inventory))
            return self._publish(plan, effect, binding, native)

    def _render(
        self, permit: c.EffectPermit, binding: c.EffectBinding,
        plan: c.OperationPlan, effect: c.PlannedEffect,
    ) -> EffectResult:
        self._entry(permit, binding, plan, effect, "render")
        with self._io("render"):
            from netops.report.generator import ReportGenerator, ReportSection

            outcomes = self._input_value(plan, "outcomes")
            outcomes["overall_alert"] = outcomes["status"] != c.OutcomeStatus.SUCCEEDED.value
            generator = ReportGenerator()
            section: ReportSection = {
                "name": "Selected outcomes", "type": "companion", "data": outcomes,
            }
            native = generator.build_report(sections=[section])
            kind = plan.output_intent.kinds[0]
            if kind == "html":
                content = generator.generate_html(native).encode("utf-8")
            elif kind == "pdf":
                content = generator.generate_pdf(native)
            else:
                raise _Rejected(c.ReasonCode.OUTPUT_REJECTED)
            return self._publish(plan, effect, binding, dict(native), content)

    @staticmethod
    def _input_value(
        plan: c.OperationPlan, kind: str, *, required: bool = True,
    ) -> dict:
        inputs = plan.native_payload["inputs"]
        if not isinstance(inputs, tuple):
            raise c.ContractError()
        values = tuple(item["value"] for item in inputs
                       if isinstance(item, c.FrozenObject) and item["kind"] == kind)
        if not values and not required:
            return {}
        if len(values) != 1 or not isinstance(values[0], c.FrozenObject):
            raise _Rejected(c.ReasonCode.INPUT_BINDING_INVALID)
        return cast(dict, json.loads(c.canonical_bytes(values[0])))

    def _publish(
        self, plan: c.OperationPlan, effect: c.PlannedEffect, binding: c.EffectBinding,
        native: dict, content: bytes | None = None,
    ) -> EffectResult:
        safe = c.public_object(native)
        kind = plan.output_intent.kinds[0]
        if content is None:
            if kind == "json":
                content = c.canonical_bytes(safe)
            elif kind == "yaml":
                import yaml

                content = yaml.safe_dump(json.loads(c.canonical_bytes(safe))).encode("utf-8")
            else:
                raise _Rejected(c.ReasonCode.OUTPUT_REJECTED)
        if self._cancellations[plan.operation_id].is_cancelled():
            return EffectResult(c.StepOutcome(
                effect.occurrence_id, c.OutcomeStatus.CANCELLED, True,
                unapplied_effects=(effect.kind,), native_payload=safe,
            ))
        store = self._requests[plan.operation_id][0]._artifacts
        descriptor = store.publish(plan.output_intent, content, c.ArtifactBinding(binding, "public"))
        result = EffectResult(
            c.StepOutcome(
                effect.occurrence_id, c.OutcomeStatus.SUCCEEDED, True,
                native_payload=safe, changed=True,
            ), artifacts=(descriptor,),
        )
        self._validate_result(result, effect)
        return result

    def _entry(
        self, permit: c.EffectPermit, binding: c.EffectBinding,
        plan: c.OperationPlan, effect: c.PlannedEffect, kind: str,
    ) -> None:
        pending = self._pending.get(permit)
        if (
            type(effect) is not c.PlannedEffect or effect.kind != kind
            or pending is None or pending[0] != binding
            or binding.occurrence_id != effect.occurrence_id
            or self.authorization.reconcile(permit) != binding
            or bind_plan(plan, binding.plan.root_ref, binding.plan.generation) != binding.plan
            or effect.ordinal >= len(plan.effects) or plan.effects[effect.ordinal] != effect
        ):
            raise _Rejected(c.ReasonCode.CONSENT_STALE)
        self.authorization.enter(permit, binding, self._now(plan.operation_id))
        self._entered.add(permit)

    @staticmethod
    def _validate_result(result: EffectResult, effect: c.PlannedEffect) -> None:
        if type(result) is not EffectResult or type(result.step) is not c.StepOutcome:
            raise c.ContractError()
        result.step.__post_init__()
        if type(result.cleanup) is not c.CleanupOutcome:
            raise c.ContractError()
        result.cleanup.__post_init__()
        if (
            type(result.artifacts) is not tuple
            or any(type(item) is not c.ArtifactDescriptor for item in result.artifacts)
        ):
            raise c.ContractError()
        for item in result.artifacts:
            item.__post_init__()
        if result.artifacts and effect.kind not in ("save", "export", "render", "backup"):
            raise c.ContractError()
        if (
            result.step.step_id != effect.occurrence_id or not result.step.attempted
            or not result.step.selected
        ):
            raise c.ContractError()

    def execute(
        self, service: WorkflowService, request: c.OperationRequest,
        authorization: c.Authorization | None,
    ) -> c.OperationOutcome:
        """Consume once, journal pending facts before entry, and never redispatch."""
        with self._mutex:
            if request.operation_id in self._running:
                return self._outcome(request, (), c.ReasonCode.RESOURCE_BUSY)
            if request.operation_id in self._finished:
                return self._outcome(request, (), c.ReasonCode.CONSENT_STALE)
            self._running.add(request.operation_id)
        results: list[EffectResult] = []
        entered_effect: c.PlannedEffect | None = None
        plan: c.OperationPlan | None = None
        consumed = False
        try:
            if service._authorization is not self.authorization or authorization is None:
                raise _Rejected(c.ReasonCode.CONSENT_REQUIRED)
            plan, inputs = self._load(service, request)
            self._supported(plan)
            binding = bind_plan(plan, inputs.root_ref, inputs.generation)
            with self._resources(plan):
                # The actual broker's snapshot reloads all current sources again
                # under its own admission lock before consuming the private grant.
                session = self.authorization.consume(
                    authorization, binding, self._now(request.operation_id),
                )
                consumed = True
                self._cancellations[request.operation_id] = _Cancellation(
                    self, request.operation_id, self._deadlines[request.operation_id],
                )
                if (
                    request.output_intent.root_ref is not None
                    and request.output_intent.root_ref != inputs.root_ref
                ):
                    raise _Rejected(c.ReasonCode.OWNERSHIP_INVALID)
                journal_state = (
                    self._owned if request.output_intent.root_ref is not None
                    else cast(OwnedStatePort, self._memory)
                )
                for effect in plan.effects:
                    revision = self._state._revisions.get(request.operation_id, 0)
                    effect_binding = c.EffectBinding(
                        binding, str(uuid4()), revision, effect.occurrence_id,
                        effect.target_id, effect.step_id, binding.recovery_scope,
                    )
                    permit = self.authorization.permit(
                        session, effect_binding, self._now(request.operation_id),
                    )
                    pending_step = StepDisposition(
                        effect.target_id, effect.occurrence_id,
                        invocation_id=str(uuid4()), effect_id=effect.occurrence_id,
                    )
                    assert pending_step.invocation_id is not None
                    self._pending[permit] = (effect_binding, pending_step.invocation_id)
                    initial = PolicyState(
                        plan.context.policy_identity, request.operation_id, 0, Phase.PLANNED,
                        plan.plan_digest, c.digest(plan.context), plan.policy_digest,
                        dispositions=(pending_step,),
                    )
                    journal = OwnedPolicyJournal(
                        journal_state, service._policy, binding,
                        plan.context.policy_identity, self._owner,
                        occurrence_id=effect.occurrence_id,
                    )
                    with self._io("checkpoint-create"):
                        receipt = journal.create(
                            initial, self._requested(plan, effect),
                            self._facts(plan, plan.deadline_ms, effect=effect),
                        )
                    try:
                        if effect.kind == "gather":
                            result = self._gather(permit, effect_binding, plan, effect)
                        elif effect.kind == "scan":
                            result = self._scan(permit, effect_binding, plan, effect)
                        elif effect.kind == "collect":
                            result = self._collect(permit, effect_binding, plan, effect)
                        elif effect.kind == "resolve-for-run":
                            result = self._resolve_for_run(permit, effect_binding, plan, effect)
                        elif effect.kind == "save":
                            result = self._save(permit, effect_binding, plan, effect)
                        elif effect.kind == "export":
                            result = self._export(permit, effect_binding, plan, effect)
                        elif effect.kind == "render":
                            result = self._render(permit, effect_binding, plan, effect)
                        elif effect.kind == "refresh":
                            result = self._refresh(permit, effect_binding, plan, effect)
                        elif effect.kind == "backup":
                            result = self._backup(permit, effect_binding, plan, effect)
                        elif effect.kind == "retention":
                            result = self._retention(permit, effect_binding, plan, effect)
                        elif effect.kind in ("apply", "rollback"):
                            result = self._mutate(permit, effect_binding, plan, effect)
                        elif effect.kind == "git":
                            result = self._git(permit, effect_binding, plan, effect)
                        else:
                            raise _Rejected(c.ReasonCode.DEPENDENCY_NOT_READY)
                    finally:
                        entered_effect = effect if permit in self._entered else None
                    results.append(result)
                    state = receipt.state
                    selected = next(step for step in state.dispositions
                                    if step.effect_id == effect.occurrence_id)
                    primary = ("success" if result.step.status == c.OutcomeStatus.SUCCEEDED
                               else result.step.status.value)
                    statuses = tuple(
                        primary if step is selected else (
                            "success" if step.disposition.value == "succeeded" else step.disposition.value
                        )
                        for step in state.dispositions
                    )
                    complete_event = DecisionEvent(
                        str(uuid4()), EventKind.STEP_COMPLETED, state.revision,
                        plan.plan_digest, c.digest(plan.context), plan.policy_digest,
                        effect.target_id, effect.occurrence_id,
                        c.public_object({
                            "invocation_id": selected.invocation_id,
                            "effect_id": effect.occurrence_id, "target_id": effect.target_id,
                            "step_id": effect.occurrence_id, "safe_result_digest": c.digest(result.step),
                            "primary": primary,
                            "cleanup": "failed" if result.cleanup.status == "failed" else "success",
                            "remote_uncertain": result.step.remote_state == "uncertain",
                        }), operation_id=request.operation_id,
                    )
                    base = self._facts(
                        plan, plan.deadline_ms, self.authorization.is_revoked(request.operation_id),
                    )
                    complete_facts = DecisionFacts(object_value({
                        **dict(base.values), "change": {
                            "poststate_verified": result.step.native_payload.get("poststate_verified") is True,
                        }, "result": {
                            "selected": len(statuses), "completed": statuses.count("success"),
                            "failed": statuses.count("failed"), "cancelled": statuses.count("cancelled"),
                            "unsupported": statuses.count("unsupported"),
                            "blocked": statuses.count("blocked"),
                            "unsuccessful": sum(s not in ("success", "not-requested") for s in statuses),
                            "policy_failed": False,
                            "cleanup_failed": result.cleanup.status == "failed",
                            "remote_uncertain": result.step.remote_state == "uncertain",
                        },
                    }), state.phase, state.revision)
                    with self._io("checkpoint-append"):
                        receipt = journal.append(
                            receipt.checkpoint_revision, complete_event, complete_facts,
                        )
                    self.authorization.complete(
                        permit, str(uuid4()), self._state._revisions[request.operation_id],
                        self._now(request.operation_id),
                    )
                    del self._pending[permit]
                    self._entered.discard(permit)
                    entered_effect = None
                    if plan.operation == "config.apply" and result.step.status != c.OutcomeStatus.SUCCEEDED:
                        results[-1] = self._recover_apply(service, plan, effect, result)
                    if result.step.status != c.OutcomeStatus.SUCCEEDED or result.cleanup.status == "failed":
                        break
                self._finished.add(request.operation_id)
                outcome = self._outcome(request, tuple(results), None, plan=plan)
                if outcome.status == c.OutcomeStatus.SUCCEEDED:
                    self._completed_plans[plan.operation_id] = plan
                return outcome
        except (AuthorizationError, _Rejected, ArtifactError, c.ContractError) as failure:
            reason = (
                failure.reason if isinstance(failure, _Rejected)
                else failure.error.reason if isinstance(failure, ArtifactError)
                else c.ReasonCode.CONSENT_STALE
            )
            return self._outcome(
                request, tuple(results), reason, entered_effect, plan,
                self._report_sources.get(request.operation_id),
                self._generation_sources.get(request.operation_id),
            )
        except Exception:
            self._emit("Unhandled", "failed")
            return self._outcome(
                request, tuple(results), c.ReasonCode.CONTROL_LOST, entered_effect,
                plan, self._report_sources.get(request.operation_id),
                self._generation_sources.get(request.operation_id),
            )
        finally:
            if consumed:
                self.authorization.revoke(request.operation_id)
            with self._mutex:
                self._running.discard(request.operation_id)
                # No failed acknowledgement can make this process replay entry.
                if entered_effect is not None:
                    self._finished.add(request.operation_id)
                if consumed:
                    self._finished.add(request.operation_id)
                self._cancellations.pop(request.operation_id, None)
                self._report_sources.pop(request.operation_id, None)
                self._generation_sources.pop(request.operation_id, None)

    @staticmethod
    def _missing_step(
        effect: c.PlannedEffect, entered_effect: c.PlannedEffect | None,
    ) -> c.StepOutcome:
        entered = entered_effect is not None and effect.occurrence_id == entered_effect.occurrence_id
        return c.StepOutcome(
            effect.occurrence_id,
            c.OutcomeStatus.FAILED if entered else c.OutcomeStatus.BLOCKED, entered,
            unapplied_effects=(effect.kind,),
            remote_state="uncertain" if entered else "unchanged",
        )

    @staticmethod
    def _outcome(
        request: c.OperationRequest, results: tuple[EffectResult, ...],
        reason: c.ReasonCode | None, entered_effect: c.PlannedEffect | None = None,
        plan: c.OperationPlan | None = None,
        source_report: c.FrozenObject | None = None,
        source_generation: c.FrozenObject | None = None,
    ) -> c.OperationOutcome:
        by_id = {result.step.step_id: result.step for result in results}
        uncertain = entered_effect is not None and entered_effect.occurrence_id not in by_id
        errors = () if reason is None else (c.SafeError(
            c.ErrorCategory.EXECUTION if entered_effect is not None else c.ErrorCategory.PRECONDITION,
            c.ReasonCode.REMOTE_STATE_UNCERTAIN if uncertain else reason,
            c.Stage.DISPATCH, next_action="Inspect current state and obtain a fresh exact review.",
        ),)
        effects = plan.effects if plan is not None else _planned_effects(request)
        steps = tuple(by_id.get(
            effect.occurrence_id, ExecutionHost._missing_step(effect, entered_effect),
        ) for effect in effects)
        generation = (
            ExecutionHost._generation_source(plan)
            if request.operation == "compare.generate" and plan is not None else source_generation
        )
        if isinstance(generation, c.FrozenObject) and generation.get("request_digest") != request_digest(request):
            generation = None
        coverage: dict[str, c.FrozenObject] = {}
        if request.operation == "compare.generate" and isinstance(generation, c.FrozenObject):
            coverage = {
                c.text(item["target_id"]): item for item in cast(tuple[c.FrozenObject, ...], generation["coverage"])
            }
            # A successful save is still a successful physical step. Its
            # selected-source facts must survive independently of that status.
            steps = tuple(replace(step, native_payload=c.public_object({
                **dict(step.native_payload), "generation": generation,
            })) for step in steps)
        if request.operation == "report.render":
            report = plan.native_payload.get("report") if plan is not None else source_report
            if isinstance(report, c.FrozenObject):
                sections = c.public_object({"sections": ({
                    "name": "Selected outcomes", "type": "companion", "data": report,
                },)})
                # Rendering can fail before returning native data. Keep its
                # original failure/attempted/unapplied disposition alongside
                # the already validated source facts, without copying inputs.
                steps = tuple(
                    replace(step, native_payload=sections)
                    if not step.native_payload else step for step in steps
                )
        target_results: list[c.TargetOutcome] = []
        for target in request.scope.target_ids:
            selected = tuple(step for effect, step in zip(effects, steps) if effect.target_id == target)
            if not selected:
                selected = tuple(step for effect, step in zip(effects, steps) if effect.target_id == "local")
            if not selected:
                selected = (c.StepOutcome(
                    target, c.OutcomeStatus.BLOCKED, False,
                    unapplied_effects=c.capability(request.operation).effects,
                ),)
            # A later unentered backup must not erase a returned collection
            # failure, attempted flag, native result, or remote uncertainty.
            actual = tuple(step for step in selected if step.attempted)
            native = actual[-1] if actual else selected[-1]
            status = next((value for value in (
                c.OutcomeStatus.FAILED, c.OutcomeStatus.CANCELLED,
                c.OutcomeStatus.UNSUPPORTED, c.OutcomeStatus.BLOCKED,
            ) if any(step.status == value for step in selected)), native.status)
            source = coverage.get(target)
            if source is not None:
                source_status = {
                    "failed": c.OutcomeStatus.FAILED,
                    "unsupported": c.OutcomeStatus.UNSUPPORTED,
                    "missing": c.OutcomeStatus.BLOCKED,
                }.get(c.text(source["status"]))
                if source_status is not None:
                    target_results.append(c.TargetOutcome(
                        target, source_status, False,
                        c.capability(request.operation).effects,
                        c.public_object({"generation": source, "execution_performed": False}),
                    ))
                    continue
                if source["status"] == "no-active-alert":
                    target_results.append(c.TargetOutcome(
                        target, c.OutcomeStatus.NOT_REQUESTED,
                        False, native_payload=c.public_object({
                            "generation": source, "execution_performed": False,
                        }),
                    ))
                    continue
            target_results.append(c.TargetOutcome(
                target, status, bool(actual),
                tuple(dict.fromkeys(kind for step in selected for kind in step.unapplied_effects)),
                native.native_payload, any(step.changed for step in selected),
                "uncertain" if any(step.remote_state == "uncertain" for step in selected) else native.remote_state,
                tuple(finding for step in selected for finding in step.findings),
                tuple(error for step in selected for error in step.errors),
            ))
        targets = tuple(target_results)
        cleanup_errors = tuple(error for result in results for error in result.cleanup.errors)
        cleanup_refs = tuple(sorted({ref for result in results for ref in result.cleanup.remaining_refs}))
        cleanup = c.CleanupOutcome(
            "failed" if any(r.cleanup.status == "failed" for r in results) else (
                "succeeded" if any(r.cleanup.status == "succeeded" for r in results)
                else "not-requested"
            ),
            cleanup_refs, cleanup_errors,
        )
        return c.aggregate_outcome(
            request, targets, steps, errors=errors, cleanup=cleanup,
            artifacts=tuple(c.public_object(json.loads(c.canonical_bytes(item)))
                            for result in results for item in result.artifacts),
            executed_mode=request.mode if results or entered_effect is not None else None,
            provenance=c.public_object({"execution_performed": bool(results) or entered_effect is not None,
                                        "integration_owner": "A02", "controller_qualified": False}),
        )
