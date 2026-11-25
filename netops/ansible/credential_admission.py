"""Trusted host-only composition with the operational broker's private sessions.

This adapter is inside the host trust boundary. It deliberately shares A01's
private registry/critical section; copying those facts into another authority
would lose the original deadline and the cancellation linearization point.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from typing import NoReturn
from uuid import uuid4

from netops.ansible import contracts as c
from netops.ansible.credentials import CredentialError, CredentialScope, CredentialTelemetry
from netops.ansible.policy.authorization import AdmissionSnapshot, AuthorizationBroker, bind_plan


class HostCredentialAdmission:
    """Bind one exact credential scope to an actual consumed A01 session.

    Construct only in the trusted host composition root, never from public
    requests. The scope supplies task-selected private field references; the
    actual broker registry, not a boolean or policy result, supplies authority.
    """

    def __init__(
        self, broker: AuthorizationBroker, session: c.AdmissionSession,
        plan: c.OperationPlan, scope: CredentialScope, clock: c.ClockPort,
        *, telemetry: CredentialTelemetry | None = None,
    ) -> None:
        self._telemetry = telemetry if telemetry is not None else CredentialTelemetry()
        if (
            type(broker) is not AuthorizationBroker or type(plan) is not c.OperationPlan
            or type(scope) is not CredentialScope
        ):
            self._deny()
        self._broker = broker
        self._clock = clock
        self._plan = deepcopy(plan)
        self._scope = deepcopy(scope)
        self._used = False
        self._permits: tuple[tuple[c.EffectPermit, c.EffectBinding], ...] = ()
        with broker._lock:
            selected = next((item for item in broker._sessions if item is session), None)
            if selected is None:
                self._deny()
            self._session = selected
            with self._guard(scope):
                pass

    def __repr__(self) -> str:
        """Do not reveal private session, plan or operation identities."""
        return "<private>"

    def __reduce__(self) -> NoReturn:
        """Never persist or copy a host authority adapter."""
        raise TypeError("private-value")

    def _deny(self) -> NoReturn:
        self._telemetry.rejected("credential-admission", c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        raise CredentialError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID) from None

    def _check_scope(self, scope: CredentialScope, binding: c.PlanBinding) -> None:
        if type(scope) is not CredentialScope or scope != self._scope:
            self._deny()
        scope.__post_init__()
        self._plan.__post_init__()
        if (
            self._plan.requested_mode in (c.Mode.PREVIEW, c.Mode.CHECK)
            or bind_plan(self._plan, binding.root_ref, binding.generation) != binding
            or scope.operation_id != binding.operation_id
            or scope.context != c.ControllerContext(self._plan.context)
            or scope.controller_digest != binding.controller_digest
            or scope.route_digest != self._plan.context.route_digest
        ):
            self._deny()
        for target in scope.targets:
            target.__post_init__()
            routes = tuple(
                route for route in self._plan.routes if route.get("target_id") == target.target_id
            )
            effects = tuple(
                effect for effect in self._plan.effects
                if effect.kind == "resolve-for-run"
                and (effect.target_id, effect.step_id) == (target.target_id, target.task_id)
            )
            if len(routes) != 1 or len(effects) != 1 or target.hostname != target.target_id:
                self._deny()
            route = routes[0]
            if route.get("resolved") is not True or any(
                route.get(name) != expected for name, expected in (
                    ("host", target.host), ("port", target.port), ("vendor", target.vendor),
                    ("transport", target.transport),
                    ("controller_id", self._plan.context.controller_id),
                    ("route_digest", scope.route_digest),
                )
            ):
                self._deny()

    def _monotonic(self) -> float:
        with self._broker._lock:
            record = self._broker._sessions.get(self._session)
            if record is None:
                self._deny()
            try:
                return self._clock.monotonic()
            except BaseException:
                # Retire only registry-owned authority; keep pending factual receipts.
                self._broker._revoke(record.scope.binding.operation_id)
                raise

    @contextmanager
    def _guard(self, scope: CredentialScope) -> Iterator[AdmissionSnapshot]:
        # A01 owns the lock order: broker -> host state -> resolver. Never
        # acquire this guard from inside the resolver lock.
        try:
            with self._broker._lock:
                record = self._broker._sessions.get(self._session)
                if record is None:
                    self._deny()
                now = self._monotonic()
                with self._broker._critical(record.scope, now):
                    snapshot = self._broker._current(record.scope, now)
                    self._check_scope(scope, record.scope.binding)
                    if scope.expires_at > record.scope.deadline or now >= scope.expires_at:
                        self._deny()
                    yield snapshot
                    # _current checks host facts; only _critical observes time.
                    now = self._monotonic()
                    with self._broker._critical(record.scope, now):
                        self._broker._current(record.scope, now)
                        if now >= scope.expires_at:
                            self._deny()
        except CredentialError:
            raise
        except Exception:
            self._deny()

    @contextmanager
    def admit(self, scope: CredentialScope) -> Iterator[None]:
        """Reserve and enter only the next exact fixed credential occurrences."""
        with self._guard(scope) as snapshot:
            if self._used:
                self._deny()
            self._used = True
            record = self._broker._sessions[self._session]
            selected = record.scope.effects[
                record.next_ordinal:record.next_ordinal + len(scope.targets)
            ]
            if len(selected) != len(scope.targets) or any(
                effect.kind != "resolve-for-run"
                or (effect.target_id, effect.step_id) != (target.target_id, target.task_id)
                for effect, target in zip(selected, scope.targets)
            ):
                self._deny()
            issued: list[tuple[c.EffectPermit, c.EffectBinding]] = []
            revision = snapshot.revision
            for effect in selected:
                binding = c.EffectBinding(
                    record.scope.binding, str(uuid4()), revision, effect.occurrence_id,
                    effect.target_id, effect.step_id, record.scope.binding.recovery_scope,
                )
                permit = self._broker.permit(self._session, binding, self._monotonic())
                self._broker.enter(permit, binding, self._monotonic())
                issued.append((permit, binding))
                revision += 1
            try:
                yield
                self._permits = tuple(issued)
            except BaseException:
                self._permits = ()
                raise

    @contextmanager
    def validate(self, scope: CredentialScope) -> Iterator[None]:
        """Hold live original host authority without CAS, reservation or renewal."""
        with self._guard(scope):
            if not self._permits or any(
                self._broker.reconcile(permit) != binding
                or permit not in self._broker._entered
                for permit, binding in self._permits
            ):
                self._deny()
            yield
