"""Host-only controller bridge over existing A01 pending effect authority.

Nothing in this module issues consent, reconstructs permits or accepts permission
JSON. Trusted composition must supply real, already entered host invocations.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import NoReturn, Protocol

from . import contracts as c
from .controller_content import _decode_content
from .controller_protocol import (
    ControllerBudget,
    DispatchBinding,
    ProtocolError,
    _integer,
    _time,
)
from .credentials import CredentialScope, _ResolvedCredentials
from .policy.authorization import AuthorizationBroker, bind_plan


@dataclass(frozen=True, repr=False)
class DispatchPermit:
    """One-use private bridge receipt; not an A01 effect grant."""

    binding: DispatchBinding
    budget: ControllerBudget

    def __repr__(self) -> str:
        """Never expose bridge state through diagnostics."""
        return "<private>"

    def __reduce__(self) -> NoReturn:
        """Prevent serialization of a private dispatch receipt."""
        raise TypeError("private-value")


class ControlPort(Protocol):
    """Private host bridge, bounded to two seconds by the transport."""

    def request_dispatch(self, binding: DispatchBinding, cancel: c.CancelPort) -> DispatchPermit:
        """Admit one exact pending sub-dispatch under original host authority."""
        ...

    def revoke(self, operation_id: str) -> None:
        """Idempotently revoke unused permission; never replay remote work."""
        ...


@dataclass(frozen=True, repr=False)
class _HostInvocation:
    permit: c.EffectPermit
    binding: c.EffectBinding
    invocation_id: str
    kind: str

    def __repr__(self) -> str:
        return "<private>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("private-value")


class HostDispatchControl:
    """Recheck real broker pending entry, kill switch and clocks per dispatch.

    The bridge is composed *inside* the host's pending handler. Its permitted
    phases subdivide, but cannot enlarge, the already entered exact occurrence.
    No broker lock is held across worker I/O or a remote command.
    """

    def __init__(
        self, broker: AuthorizationBroker, invocations: tuple[_HostInvocation, ...],
        plan: c.OperationPlan, clock: c.ClockPort, cancel: c.CancelPort,
        accepted_at: float,
    ) -> None:
        if type(broker) is not AuthorizationBroker or not invocations:
            raise ProtocolError()
        self._broker, self._clock, self._cancel = broker, clock, cancel
        self._plan = plan
        self._operation = plan.operation_id
        self._accepted = _time(accepted_at)
        self._deadline = c.checked_deadline(
            self._accepted, min(
                float(plan.settings.execution.timeout_seconds), plan.deadline_ms / 1000.0,
            ),
        )
        self._last = self._accepted
        self._invocations = invocations
        self._next: dict[str, int] = {}
        self._nonce: str | None = None
        self._revoked = False
        self._revocation_signal = threading.Event()
        self._closed = False
        self._contents: dict[str, bytes] = {}
        self._mutations: dict[str, dict[str, object]] = {}
        self._health: dict[str, dict[str, object]] = {}
        self._authorization_deadline = self._deadline
        selected_targets: set[str] = set()
        with broker._lock:
            for entry in invocations:
                c.uuid_text(entry.invocation_id)
                if (
                    type(entry) is not _HostInvocation
                    or entry.binding.plan.operation_id != self._operation
                    or entry.binding.plan.plan_digest != plan.plan_digest
                    or entry.binding.occurrence_id in self._next
                    or entry.kind not in ("collect", "gather", "apply", "rollback")
                    or entry.binding.target_id in selected_targets
                    or bind_plan(
                        plan, entry.binding.plan.root_ref, entry.binding.plan.generation,
                    ) != entry.binding.plan
                ):
                    raise ProtocolError()
                planned = next((
                    effect for effect in plan.effects
                    if effect.occurrence_id == entry.binding.occurrence_id
                ), None)
                if (
                    planned is None or planned.kind != entry.kind
                    or planned.target_id != entry.binding.target_id
                    or planned.step_id != entry.binding.step_id
                ):
                    raise ProtocolError()
                selected_targets.add(entry.binding.target_id)
                self._next[entry.binding.occurrence_id] = 0
                _, deadline = self._validate(entry)
                self._authorization_deadline = min(self._authorization_deadline, deadline)

    def __repr__(self) -> str:
        """Keep host authority out of diagnostics."""
        return "<private>"

    def __reduce__(self) -> NoReturn:
        """Host bridge authority cannot be serialized."""
        raise TypeError("private-value")

    def _now(self) -> float:
        now = _time(self._clock.monotonic())
        if now < self._last or now < self._accepted or now >= self._deadline:
            self.revoke(self._operation)
            raise ProtocolError(c.ReasonCode.DEADLINE_EXCEEDED)
        self._last = now
        return now

    def _validate(self, entry: _HostInvocation) -> tuple[float, float]:
        if (
            self._closed or self._revocation_signal.is_set() or self._revoked
            or self._cancel.is_cancelled()
            or self._plan.settings.ansible.enabled is not True
            or self._plan.requested_mode in (c.Mode.PREVIEW, c.Mode.CHECK)
            or (entry.kind in ("apply", "rollback") and self._plan.settings.ansible.mode != "enforce")
        ):
            raise ProtocolError(c.ReasonCode.CANCELLED)
        now = self._now()
        registered = next((p for p in self._broker._pending if p is entry.permit), None)
        pending = self._broker._pending.get(registered) if registered is not None else None
        if (
            pending is None or entry.permit not in self._broker._entered
            or pending.binding != entry.binding
            or self._broker.reconcile(entry.permit) != entry.binding
        ):
            raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        with self._broker._critical(pending.scope, now):
            self._broker._current(pending.scope, now)
            # Original consent deadline, not worker readiness or receipt time.
            return now, pending.scope.deadline

    def _budget(self, entry: _HostInvocation) -> ControllerBudget:
        now, authorization = self._validate(entry)
        if self._nonce is None:
            raise ProtocolError()
        return ControllerBudget(
            self._nonce,
            min(300000, int((authorization - now) * 1000)),
            min(3600000, int((self._deadline - now) * 1000)),
        )

    def ready(self, nonce: str) -> ControllerBudget:
        """Bind exactly one live worker handshake; retry never renews authority."""
        self._check_revocation_signal()
        with self._broker._lock:
            if self._nonce is not None:
                raise ProtocolError()
            self._nonce = nonce
            budgets = tuple(self._budget(entry) for entry in self._invocations)
            return ControllerBudget(
                nonce, min(b.authorization_remaining_ms for b in budgets),
                min(b.operation_remaining_ms for b in budgets),
            )

    def request_dispatch(self, binding: DispatchBinding, cancel: c.CancelPort) -> DispatchPermit:
        """Atomically consume one phase of one exact pending host invocation."""
        try:
            self._check_revocation_signal()
            with self._broker._lock:
                if type(binding) is not DispatchBinding or cancel.is_cancelled():
                    raise ProtocolError(c.ReasonCode.CANCELLED)
                binding.__post_init__()
                entry = next((
                    entry for entry in self._invocations
                    if entry.binding.occurrence_id == binding.occurrence_id
                ), None)
                if entry is None:
                    raise ProtocolError()
                expected = entry.binding
                phases = ("credential", "task", "mutation") if entry.kind in (
                    "apply", "rollback",
                ) else ("credential", "task")
                index = self._next[binding.occurrence_id]
                _integer(index, 0, len(phases) - 1)
                if (
                    binding.operation_id != self._operation
                    or binding.plan_digest != expected.plan.plan_digest
                    or binding.controller_digest != expected.plan.controller_digest
                    or binding.invocation_id != entry.invocation_id
                    or binding.target_id != expected.target_id
                    or binding.task_id != expected.step_id
                    or binding.sequence != index or binding.phase != phases[index]
                ):
                    raise ProtocolError()
                budget = self._budget(entry)
                self._next[binding.occurrence_id] = index + 1
                return DispatchPermit(binding, budget)
        except Exception:
            if not self._revocation_signal.is_set():
                self.revoke(self._operation)
            raise ProtocolError(c.ReasonCode.CONTROL_LOST) from None

    def check(self) -> None:
        """Independent watchdog check, including a stalled or absent worker."""
        try:
            self._check_revocation_signal()
            with self._broker._lock:
                for entry in self._invocations:
                    self._validate(entry)
        except Exception:
            if not self._revocation_signal.is_set():
                self.revoke(self._operation)
            raise ProtocolError(c.ReasonCode.CONTROL_LOST) from None

    def revoke(self, operation_id: str) -> None:
        """Revoke under the same lock as reservation, independent of revisions."""
        if operation_id != self._operation:
            raise ProtocolError()
        self._signal_revoke()
        with self._broker._lock:
            self._revoked = True
            self._contents.clear()
            self._mutations.clear()
            self._health.clear()
            self._broker.revoke(operation_id)

    def _signal_revoke(self) -> None:
        # A monotonic admission latch, not a permission/revision mutation.
        # Never wait for a snapshot, resolver or broker lock to deny new work.
        self._revocation_signal.set()

    def _check_revocation_signal(self) -> None:
        if self._revocation_signal.is_set():
            raise ProtocolError(c.ReasonCode.CANCELLED)

    def _accept_content(self, binding: DispatchBinding, value: object) -> None:
        """Receive once for the exact entered read, never authorize new work."""
        self._check_revocation_signal()
        with self._broker._lock:
            entry = next((
                item for item in self._invocations
                if item.binding.occurrence_id == binding.occurrence_id
            ), None)
            if (
                self._closed or entry is None or entry.kind != "collect"
                or binding.operation_id != self._operation
                or binding.plan_digest != entry.binding.plan.plan_digest
                or binding.controller_digest != entry.binding.plan.controller_digest
                or binding.invocation_id != entry.invocation_id
                or binding.target_id != entry.binding.target_id
                or binding.task_id != entry.binding.step_id
                or binding.phase != "task" or binding.sequence != 1
                or self._next.get(binding.occurrence_id) != 2
                or binding.occurrence_id in self._contents
            ):
                raise ProtocolError()
            self._validate(entry)
            self._contents[binding.occurrence_id] = _decode_content(value)

    def _close(self) -> None:
        """Close unused sub-dispatch without revoking subsequent host effects."""
        with self._broker._lock:
            self._closed = True
            self._mutations.clear()
            self._health.clear()

    def _take_content(self, occurrence_id: str) -> bytes:
        with self._broker._lock:
            if (
                not self._closed or self._revoked or self._revocation_signal.is_set()
                or occurrence_id not in self._contents
            ):
                raise ProtocolError(c.ReasonCode.INPUT_BINDING_INVALID)
            return self._contents.pop(occurrence_id)

    def _discard_content(self) -> None:
        """Release unpublished private bytes without changing operation authority."""
        with self._broker._lock:
            self._contents.clear()
            self._mutations.clear()
            self._health.clear()


class HostControllerCredentials(c.ScopedCredentials):
    """Private composition of scoped bytes and existing pending host authority."""

    __slots__ = ("_source", "_scope", "_control")

    def __init__(
        self, source: c.ScopedCredentials, scope: CredentialScope, control: HostDispatchControl,
    ) -> None:
        if (
            type(source) is not _ResolvedCredentials or type(scope) is not CredentialScope
            or type(control) is not HostDispatchControl
            or scope.operation_id != control._operation
        ):
            raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        self._source, self._scope, self._control = source, scope, control

    @property
    def _host_owned(self) -> bool:
        return True


class _Stop:
    """Cancellation signal whose first accepted cause is never overwritten."""

    def __init__(self, parent: c.CancelPort) -> None:
        self._parent = parent
        self._event = threading.Event()
        self.reason: c.ReasonCode | None = None
        self._lock = threading.Lock()

    def stop(self, reason: c.ReasonCode) -> None:
        with self._lock:
            if self.reason is None:
                self.reason = reason
            self._event.set()

    def is_cancelled(self) -> bool:
        if self._event.is_set():
            return True
        if self._parent.is_cancelled():
            self.stop(c.ReasonCode.CANCELLED)
        return self._event.is_set()

    def _observe_parent(self) -> bool:
        """Independent monitor path: never enter the concrete A02 broker lock."""
        if self._event.is_set():
            return True
        from .execution import _Cancellation

        parent = self._parent
        # A02's ordinary is_cancelled also checks clocks/broker state and may
        # block behind a snapshot. Its accepted-stop signal is already owned
        # by that authentic host; monitors enforce original deadlines separately.
        cancelled = (
            parent._signal.is_set() if type(parent) is _Cancellation
            else parent.is_cancelled()
        )
        if cancelled:
            self.stop(c.ReasonCode.CANCELLED)
        return self._event.is_set()

    def wait(self, timeout: float) -> bool:
        if self.is_cancelled():
            return True
        self._event.wait(min(0.05, max(0.0, timeout)))
        return self.is_cancelled()
