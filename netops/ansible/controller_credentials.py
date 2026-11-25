"""Host credential preparation inside a real pending controller invocation.

The existing S01 standalone vault effect remains unchanged. This private bridge
subdivides an already entered operational effect; it creates no new plan grant.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from . import contracts as c
from .controller_control import HostDispatchControl
from .controller_protocol import ProtocolError
from .credentials import CredentialScope

_TRANSPORT_FIELDS = frozenset(("username", "password", "key_passphrase", "enable_password"))


class _ControllerCredentialAdmission:
    """Implement S01's private admission port using existing host pending entry."""

    def __init__(self, control: HostDispatchControl, scope: CredentialScope) -> None:
        if type(control) is not HostDispatchControl or type(scope) is not CredentialScope:
            raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        self._control, self._scope = control, scope
        self._used = False

    def __repr__(self) -> str:
        return "<private>"

    def _check(self, scope: CredentialScope) -> None:
        if scope != self._scope:
            raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        scope.__post_init__()
        plan = self._control._plan
        if (
            scope.operation_id != plan.operation_id
            or scope.context.context != plan.context
            or scope.controller_digest != c.digest(plan.context.controller_id)
            or scope.route_digest != plan.context.route_digest
            or scope.expires_at > min(
                self._control._deadline, self._control._authorization_deadline,
            )
            or self._control._clock.monotonic() >= scope.expires_at
            or len(scope.targets) != len(self._control._invocations)
        ):
            raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        for target, entry in zip(scope.targets, self._control._invocations):
            route = next((
                route for route in plan.routes if route.get("target_id") == target.target_id
            ), None)
            if (
                target.hostname != target.target_id
                or (target.target_id, target.task_id) != (
                    entry.binding.target_id, entry.binding.step_id,
                )
                or set(target.fields) - _TRANSPORT_FIELDS
                or "username" not in target.fields
                or (target.key_ref is None and "password" not in target.fields)
                or (target.key_ref is None and "key_passphrase" in target.fields)
                or target.transport not in ("ssh", "ssh2")
                or target.known_hosts_ref is None or route is None
                or route.get("resolved") is not True
            ):
                raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
            if any(route.get(name) != expected for name, expected in (
                ("host", target.host), ("port", target.port), ("vendor", target.vendor),
                ("transport", target.transport), ("controller_id", plan.context.controller_id),
                ("route_digest", scope.route_digest),
            )):
                raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
            self._control._validate(entry)

    @contextmanager
    def _guard(self, scope: CredentialScope) -> Iterator[None]:
        try:
            with self._control._broker._lock:
                self._check(scope)
                yield
                self._check(scope)
        except BaseException:
            self._control.revoke(self._control._operation)
            raise

    @contextmanager
    def admit(self, scope: CredentialScope) -> Iterator[None]:
        """Consume this host preparation once, never a worker's dispatch phase."""
        with self._guard(scope):
            if self._used:
                raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
            self._used = True
            yield

    @contextmanager
    def validate(self, scope: CredentialScope) -> Iterator[None]:
        """Recheck original live authority without reserving or renewing it."""
        with self._guard(scope):
            if self._used is not True:
                raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
            yield
