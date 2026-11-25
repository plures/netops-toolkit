"""Operation-private credential resolution; never an inventory or preview adapter.

The host supplies an admission port and a controller-origin route policy. Neither
the resolver nor possession of a scope/session grants operational consent.
"""

from __future__ import annotations

import json
import logging
import math
import threading
from collections import Counter
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import NoReturn, Protocol

from netops.ansible.contracts import (
    MAX_TARGET_LIMIT,
    ClockPort,
    ControllerContext,
    ErrorCategory,
    ReasonCode,
    SafeError,
    ScopedCredentials,
    Stage,
    sha256,
    text,
    unique,
    uuid_text,
)
from netops.core.connection import ConnectionParams, Transport
from netops.core.inventory import Device
from netops.core.vault import CredentialVault

_FIELDS = frozenset({
    "username", "password", "enable_password", "key_passphrase", "ntp_authentication_key",
})
_MAX_FRAME = 1024 * 1024
_ERROR_CLASSIFICATION = {
    ReasonCode.VAULT_LOCKED: (ErrorCategory.CREDENTIALS, Stage.CREDENTIALS),
    ReasonCode.VAULT_MISSING: (ErrorCategory.CREDENTIALS, Stage.CREDENTIALS),
    ReasonCode.VAULT_PASSWORD_INVALID: (ErrorCategory.CREDENTIALS, Stage.CREDENTIALS),
    ReasonCode.CREDENTIAL_SCOPE_INVALID: (ErrorCategory.CREDENTIALS, Stage.CONTROLLER),
    ReasonCode.HANDOFF_INVALID: (ErrorCategory.CREDENTIALS, Stage.CONTROLLER),
    ReasonCode.DEADLINE_EXCEEDED: (ErrorCategory.CREDENTIALS, Stage.CONTROLLER),
    ReasonCode.ROUTE_UNAVAILABLE: (ErrorCategory.TRANSPORT, Stage.CONNECT),
    ReasonCode.HOST_KEY_INVALID: (ErrorCategory.TRANSPORT, Stage.CONNECT),
}


class CredentialTelemetry:
    """Paired safe rejection counters/logs, never inputs to authorization."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._counts: Counter[tuple[str, str]] = Counter()
        self._saturated: set[tuple[str, str]] = set()
        self._logger = logging.getLogger(__name__)

    def rejected(self, stage: str, reason: ReasonCode) -> None:
        """Record one execution-only rejection without raw values/exceptions."""
        safe_stage = stage if stage in ("credential-admission", "credential-route") else "credentials"
        safe_reason = reason.value if type(reason) is ReasonCode else "credential-scope-invalid"
        with self._lock:
            key = (safe_stage, safe_reason)
            if self._counts[key] >= 9007199254740991:
                if key not in self._saturated:
                    self._saturated.add(key)
                    self._counts[(safe_stage, "numeric-telemetry-saturated")] += 1
                    self._logger.error("credential.telemetry.saturated", extra={
                        "metric": "credential_telemetry_saturated", "outcome": "Failure",
                        "stage": safe_stage, "reason": "numeric-telemetry-saturated",
                        "cause": safe_reason,
                    })
                return
            self._counts[key] += 1
            self._logger.warning("credential.rejected", extra={
                "metric": "credential_rejections_total", "outcome": "Rejected",
                "stage": safe_stage, "reason": safe_reason,
            })

    def counters(self) -> tuple[tuple[str, str, int], ...]:
        """Return detached safe observations, not live policy facts."""
        with self._lock:
            return tuple((stage, reason, count) for (stage, reason), count in sorted(self._counts.items()))


class CredentialError(RuntimeError):
    """Expose only the frozen safe credential error vocabulary."""

    def __init__(self, reason: ReasonCode) -> None:
        category, stage = _ERROR_CLASSIFICATION[reason]
        self.error = SafeError(category, reason, stage)
        super().__init__(reason.value)


def _fail(reason: ReasonCode = ReasonCode.CREDENTIAL_SCOPE_INVALID) -> NoReturn:
    raise CredentialError(reason) from None


def _deadline(value: float) -> None:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        _fail()


@dataclass(frozen=True)
class CredentialTarget:
    """Canonical nonsecret identity and exact task/field selection."""

    target_id: str
    task_id: str
    hostname: str
    host: str
    vendor: str
    transport: str
    port: int
    groups: tuple[str, ...]
    fields: tuple[str, ...]
    key_ref: str | None = None
    known_hosts_ref: str | None = None

    def __post_init__(self) -> None:
        """Reject ambiguous identities, unsupported fields and weaker protocols."""
        for value in (self.target_id, self.task_id, self.hostname, self.host, self.vendor):
            text(value)
        unique(self.groups)
        unique(self.fields)
        if (
            self.transport not in ("ssh", "ssh2", "telnet")
            or type(self.port) is not int or not 1 <= self.port <= 65535
            or len(self.fields) == 0 or not set(self.fields) <= _FIELDS
        ):
            _fail()
        for ref in (self.key_ref, self.known_hosts_ref):
            if ref is not None:
                text(ref)

    @classmethod
    def from_device(
        cls, device: Device, task_id: str, fields: tuple[str, ...],
        *, known_hosts_ref: str | None = None,
    ) -> CredentialTarget:
        """Snapshot canonical inventory without carrying its credential values."""
        if device.port is not None and (
            type(device.port) is not int or not 1 <= device.port <= 65535
        ):
            _fail()
        try:
            transport = Transport(device.transport)
        except ValueError:
            _fail()
        params = ConnectionParams(device.host, transport=transport, port=device.port)
        return cls(
            device.hostname, task_id, device.hostname, device.host, device.vendor,
            transport.value, params.effective_port, tuple(device.groups), fields,
            device.key_file, known_hosts_ref,
        )


@dataclass(frozen=True)
class CredentialScope:
    """Exact operation/controller/route/target/task lifetime, containing no secrets."""

    operation_id: str
    context: ControllerContext
    controller_digest: str
    route_digest: str
    targets: tuple[CredentialTarget, ...]
    expires_at: float

    def __post_init__(self) -> None:
        """Require complete bindings; a target label alone is insufficient."""
        uuid_text(self.operation_id)
        sha256(self.controller_digest)
        sha256(self.route_digest)
        _deadline(self.expires_at)
        if (
            type(self.context) is not ControllerContext
            or self.context.context.route_digest != self.route_digest
            or type(self.targets) is not tuple or len(self.targets) == 0
            or any(type(target) is not CredentialTarget for target in self.targets)
            or len({(t.target_id, t.task_id) for t in self.targets}) != len(self.targets)
            or len({t.target_id for t in self.targets}) > MAX_TARGET_LIMIT
        ):
            _fail()


@dataclass(frozen=True)
class RouteBinding:
    """Trusted route adapter observation, not caller permission or qualification."""

    controller_digest: str
    route_digest: str
    targets: tuple[CredentialTarget, ...]
    qualification_digest: str
    controller_local: bool
    private_channel_qualified: bool
    host_key_policy: str
    keys_accessible: bool
    jump: CredentialTarget | None = None

    def __post_init__(self) -> None:
        """Validate the observation shape without probing hosts or reading keys."""
        for digest in (
            self.controller_digest, self.route_digest, self.qualification_digest,
        ):
            sha256(digest)
        if (
            type(self.targets) is not tuple
            or any(type(target) is not CredentialTarget for target in self.targets)
            or any(type(flag) is not bool for flag in (
                self.controller_local, self.private_channel_qualified, self.keys_accessible,
            ))
            or (self.jump is not None and type(self.jump) is not CredentialTarget)
        ):
            _fail(ReasonCode.ROUTE_UNAVAILABLE)


class RoutePolicyPort(Protocol):
    """Validate current keys and qualification where the controller originates."""

    def validate(self, context: ControllerContext, scope: CredentialScope) -> RouteBinding:
        """Return a current bound route; never enroll trust or fall back."""
        ...


class CredentialAdmissionPort(Protocol):
    """Host broker bridge; must atomically admit the exact private effect.

    The A01 adapter must retain the original host deadline, cancellation and
    revocation checks. Installer consent and policy decisions are not permits.
    """

    def admit(self, scope: CredentialScope) -> AbstractContextManager[None]:
        """Guard one exact credential effect under current host authority."""
        ...

    def validate(self, scope: CredentialScope) -> AbstractContextManager[None]:
        """Hold live host authority during delivery without reserving another effect."""
        ...


class UnlockSession:
    """Host-only one-use unlock material, never hydrated from public inputs."""

    __slots__ = ("__scope", "__password", "__admission", "__used", "__lock")

    def __init__(
        self, scope: CredentialScope, password: str | None, admission: CredentialAdmissionPort,
    ) -> None:
        if type(scope) is not CredentialScope or (
            password is not None and type(password) is not str
        ):
            _fail()
        self.__scope = scope
        self.__password = None if password is None else bytearray(password.encode("utf-8"))
        self.__admission = admission
        self.__used = False
        self.__lock = threading.RLock()

    def __repr__(self) -> str:
        """Do not reveal unlock material or the bound operation."""
        return "<private>"

    def __reduce__(self) -> NoReturn:
        """Deny copying, pickling and persistence."""
        raise TypeError("private-value")

    @contextmanager
    def _use(
        self, scope: CredentialScope,
    ) -> Iterator[tuple[str | None, CredentialAdmissionPort]]:
        with self.__lock:
            if self.__used or scope != self.__scope:
                self.close()
                _fail()
            self.__used = True
            try:
                with self.__admission.admit(scope):
                    password = (
                        None if self.__password is None else self.__password.decode("utf-8")
                    )
                    yield password, self.__admission
            except CredentialError:
                raise
            except Exception:
                _fail()
            finally:
                if self.__password is not None:
                    self.__password[:] = bytes(len(self.__password))
                    self.__password = None

    def close(self) -> None:
        """Discard an unused host session on cancellation or startup failure."""
        with self.__lock:
            self.__used = True
            if self.__password is not None:
                self.__password[:] = bytes(len(self.__password))
                self.__password = None


class _ResolvedCredentials(ScopedCredentials):
    """Private memory owned by one resolver and erased on revoke/frame use."""

    __slots__ = ("__owner", "__scope", "__route", "__payload", "__spent", "__admission")

    def __init__(
        self, owner: ScopedCredentialResolver, scope: CredentialScope,
        route: RouteBinding, payload: bytearray, admission: CredentialAdmissionPort,
    ) -> None:
        self.__owner = owner
        self.__scope = scope
        self.__route = route
        self.__payload = payload
        self.__spent = False
        self.__admission = admission

    @property
    def _host_owned(self) -> bool:
        return True

    def _clear(self) -> None:
        self.__payload[:] = bytes(len(self.__payload))
        self.__payload.clear()
        self.__spent = True

    def _protected_payload(self, scope: CredentialScope) -> bytes:
        """Consume the private credential subsection, not a public wire result.

        The controller owner must wrap it in the strict nonce/budget frame and
        write only to its already-admitted private pipe. No argv/env/file path
        or ordinary serializer is supported here.
        """
        try:
            with self.__admission.validate(scope), self.__owner._lock:
                if scope != self.__scope or self.__spent:
                    _fail()
                self.__owner._check_live(scope)
                route = self.__owner._validate_route(scope)
                if route != self.__route:
                    _fail(ReasonCode.ROUTE_UNAVAILABLE)
                self.__owner._check_live(scope)
                payload = bytes(self.__payload)
                # Spend while still holding both locks: clearing only in the
                # outer finally left a second consumer a race window.
                self._clear()
                return payload
        except CredentialError:
            raise
        except Exception:
            _fail()
        finally:
            with self.__owner._lock:
                self._clear()


class ScopedCredentialResolver:
    """Resolve only admitted selected fields using the native isolated reader."""

    def __init__(self, vault: CredentialVault, routes: RoutePolicyPort, clock: ClockPort) -> None:
        self._vault = vault
        self._routes = routes
        self._clock = clock
        self._lock = threading.RLock()
        self._revoked: set[str] = set()
        self._values: dict[str, list[_ResolvedCredentials]] = {}

    def _check_live(self, scope: CredentialScope) -> None:
        now = self._clock.monotonic()
        _deadline(now)
        if scope.operation_id in self._revoked:
            _fail()
        if now >= scope.expires_at:
            self.revoke(scope.operation_id)
            _fail(ReasonCode.DEADLINE_EXCEEDED)

    def _validate_route(self, scope: CredentialScope) -> RouteBinding:
        try:
            route = self._routes.validate(scope.context, scope)
        except CredentialError:
            raise
        except Exception:
            _fail(ReasonCode.ROUTE_UNAVAILABLE)
        if (
            type(route) is not RouteBinding
            or route.controller_digest != scope.controller_digest
            or route.route_digest != scope.route_digest
            or route.targets != scope.targets
            or route.controller_local is not True
            or route.private_channel_qualified is not True
            or route.keys_accessible is not True
        ):
            _fail(ReasonCode.ROUTE_UNAVAILABLE)
        if route.host_key_policy != "reject":
            _fail(ReasonCode.HOST_KEY_INVALID)
        # Telnet has native port semantics, but no qualified protected companion
        # route is established by this adapter; never weaken SSH to make it work.
        if any(t.transport == "telnet" for t in scope.targets):
            _fail(ReasonCode.ROUTE_UNAVAILABLE)
        if route.jump is not None:
            if (
                route.jump.transport != "ssh" or route.jump.task_id != "route"
                or route.jump.target_id in {t.target_id for t in scope.targets}
            ):
                _fail(ReasonCode.ROUTE_UNAVAILABLE)
        for target in (*scope.targets, *((route.jump,) if route.jump is not None else ())):
            if target.known_hosts_ref is None:
                _fail(ReasonCode.HOST_KEY_INVALID)
        return route

    @contextmanager
    def _resolution_attempt(self, operation_id: str) -> Iterator[list[_ResolvedCredentials]]:
        created: list[_ResolvedCredentials] = []
        try:
            yield created
        except BaseException:
            # The host guard can reject on exit (cancel/expiry while reading).
            # A value constructed before that exit must not remain retained.
            with self._lock:
                retained = self._values.get(operation_id, [])
                for value in created:
                    value._clear()
                    if value in retained:
                        retained.remove(value)
                if not retained:
                    self._values.pop(operation_id, None)
            raise

    def resolve(self, scope: CredentialScope, session: UnlockSession) -> ScopedCredentials:
        """Resolve selected target/jump fields only inside host-admitted execution."""
        if type(scope) is not CredentialScope or type(session) is not UnlockSession:
            _fail()
        # Acquire host authority before the resolver lock, matching host
        # cancellation's broker -> revoke order.
        with self._resolution_attempt(scope.operation_id) as created, session._use(scope) as unlock, self._lock:
            password, admission = unlock
            self._check_live(scope)
            route = self._validate_route(scope)
            selected: list[dict[str, object]] = []
            jump: dict[str, object] | None = None
            with self._vault.private_session() as reader:
                unlocked = False
                try:
                    for target in (
                        *scope.targets, *((route.jump,) if route.jump is not None else ()),
                    ):
                        self._check_live(scope)
                        try:
                            values = reader.get_credentials(target.hostname, list(target.groups))
                        except RuntimeError:
                            if password is None:
                                _fail(ReasonCode.VAULT_LOCKED)
                            if unlocked:
                                _fail(ReasonCode.VAULT_LOCKED)
                            try:
                                reader.unlock(password)
                            except FileNotFoundError:
                                _fail(ReasonCode.VAULT_MISSING)
                            except ValueError:
                                _fail(ReasonCode.VAULT_PASSWORD_INVALID)
                            unlocked = True
                            values = reader.get_credentials(target.hostname, list(target.groups))
                        if values is None:
                            _fail()
                        private: dict[str, str] = {}
                        for field in target.fields:
                            value = values.get(field)
                            if type(value) is not str or len(value) == 0:
                                _fail()
                            private[field] = value
                        item: dict[str, object] = {
                            "target_id": target.target_id, "task_id": target.task_id,
                            "host": target.host, "port": target.port, "vendor": target.vendor,
                            "transport": target.transport, "fields": private,
                            "key_ref": target.key_ref, "known_hosts_ref": target.known_hosts_ref,
                        }
                        if target is route.jump:
                            jump = item
                        else:
                            selected.append(item)
                    self._check_live(scope)
                    payload = bytearray(json.dumps({
                        "operation_id": scope.operation_id,
                        "controller_digest": scope.controller_digest,
                        "route_digest": scope.route_digest,
                        "targets": selected, "jump": jump,
                    }, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8"))
                    if len(payload) > _MAX_FRAME:
                        payload[:] = bytes(len(payload))
                        _fail(ReasonCode.HANDOFF_INVALID)
                except CredentialError:
                    raise
                except Exception:
                    _fail()
                finally:
                    selected.clear()
            value = _ResolvedCredentials(self, scope, route, payload, admission)
            self._values.setdefault(scope.operation_id, []).append(value)
            created.append(value)
            return value

    def revoke(self, operation_id: str) -> None:
        """Clear all owned credential payloads; repeated revocation is safe."""
        text(operation_id)
        with self._lock:
            self._revoked.add(operation_id)
            for value in self._values.pop(operation_id, []):
                value._clear()
