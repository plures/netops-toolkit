"""Host-private owned-build capabilities, distinct from publisher HTTPS locks.

Only trusted composition supplies the producer port. Request documents and
durable descriptors contain facts, never the issuing actor or a live grant.
"""

from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import AuthorizationBroker, AuthorizationError

from ._assets import DownloadReceipt, _MonotonicClock

if TYPE_CHECKING:
    from ._managed import ManagedGenerationManifest

__all__: tuple[str, ...] = ()
_ORIGIN = "owned-local-build"


@dataclass(frozen=True)
class _OwnedBuildAsset:
    """Publicly serializable byte/producer binding; deliberately no vendor URL."""

    source_id: str
    dependency: str
    sha256: str
    size: int
    producer_id: str
    receipt_digest: str

    def __post_init__(self) -> None:
        if self.source_id != _ORIGIN or self.dependency != "toolkit-wheel-bundle":
            raise c.ContractError()
        for value in (self.sha256, self.producer_id, self.receipt_digest):
            c.sha256(value)
        if c.counter(self.size, positive=True) > 128 * 1024 * 1024:
            raise c.ContractError()


@dataclass(frozen=True)
class _ProducedBuild:
    """Immutable observation returned by the trusted owning build host."""

    receipt: c.FrozenObject
    content: bytes = field(repr=False)


class _BuildHostPort(Protocol):
    """Trusted constructor-only actor, not a document decoder or user callback."""

    @property
    def identity(self) -> str:
        """Return the exact trusted build-host identity."""
        ...

    def inspect(
        self, clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _ProducedBuild:
        """Validate its own producer ledger, inputs, tools, ownership and output."""
        ...


@dataclass(frozen=True, eq=False)
class _IssuedBuild:
    """Identity-bearing process/thread-local capability, never serialized."""

    _issuer: object
    _result: _ProducedBuild
    _thread: int = field(default_factory=threading.get_ident)
    _pid: int = field(default_factory=os.getpid)


class _OwnedSource:
    """Issue only after the supplied trusted producer validates its own ledger.

    A fresh host can recover a candidate through that same independently
    configured producer port. No JSON reader recreates a capability or consent.
    """

    def __init__(
        self, host: _BuildHostPort, clock: c.ClockPort,
        cancel: c.CancelPort, deadline: float,
    ) -> None:
        self._host = host
        self._identity = c.sha256(host.identity)
        self._issuer = object()
        result = host.inspect(clock, cancel, deadline)
        self._validate(result)
        self._issued = _IssuedBuild(self._issuer, result)
        self._asset = _OwnedBuildAsset(
            _ORIGIN, "toolkit-wheel-bundle", hashlib.sha256(result.content).hexdigest(),
            len(result.content), self._identity, c.digest(result.receipt),
        )

    @property
    def asset(self) -> _OwnedBuildAsset:
        """Return serializable facts, never the private issuing capability."""
        return self._asset

    def _validate(self, result: _ProducedBuild) -> None:
        if type(result) is not _ProducedBuild or type(result.receipt) is not c.FrozenObject:
            raise AuthorizationError()
        receipt = result.receipt
        if set(receipt) != {
            "schema", "producer_id", "source_seal", "build_inputs", "toolchain",
            "interpreter", "cache_inputs", "operation", "exit_code", "outputs",
            "members", "root", "consuming_root", "context_digest", "consuming_contexts",
            "archive_digest", "archive_size",
        } or (
            receipt["schema"] != "owned-offline-build-v1"
            or receipt["producer_id"] != self._identity
            or receipt["operation"] != "offline-wheel-sdist-and-cache-assembly"
            or type(receipt["exit_code"]) is not int or receipt["exit_code"] != 0
            or type(result.content) is not bytes
            or receipt["archive_digest"] != hashlib.sha256(result.content).hexdigest()
            or receipt["archive_size"] != len(result.content)
        ):
            raise AuthorizationError()
        # A hash without independently qualified, complete inputs is not origin.
        for name in ("build_inputs", "toolchain", "cache_inputs", "outputs", "members"):
            values = receipt[name]
            if type(values) is not tuple or not values:
                raise AuthorizationError()
        c.sha256(receipt["source_seal"])
        c.sha256(receipt["context_digest"])

    def _current(
        self, clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _ProducedBuild:
        issued = self._issued
        if (
            type(issued) is not _IssuedBuild or issued._issuer is not self._issuer
            or issued._thread != threading.get_ident() or issued._pid != os.getpid()
            or self._host.identity != self._identity
        ):
            raise AuthorizationError()
        if cancel.is_cancelled():
            raise InterruptedError()
        if c.finite(clock.monotonic()) >= deadline:
            raise TimeoutError()
        result = self._host.inspect(clock, cancel, deadline)
        self._validate(result)
        if result != issued._result or self.asset != _OwnedBuildAsset(
            _ORIGIN, "toolkit-wheel-bundle", hashlib.sha256(result.content).hexdigest(),
            len(result.content), self._identity, c.digest(result.receipt),
        ):
            raise AuthorizationError()
        if cancel.is_cancelled():
            raise InterruptedError()
        if c.finite(clock.monotonic()) >= deadline:
            raise TimeoutError()
        return result

    def guard(
        self, manifest: ManagedGenerationManifest, clock: c.ClockPort,
        cancel: c.CancelPort, deadline: float,
    ) -> None:
        """Recheck actor and exact source/output/context before a real effect."""
        result = self._current(clock, cancel, deadline)
        receipt = result.receipt
        spec = manifest.installation
        if (
            manifest.asset != self.asset or manifest.archives or manifest.archive != "zip"
            or spec is None or spec.controller or spec.collections or spec.tools
            or spec.native_files or spec.libraries or spec.controller_installation is not None
            or spec.requested_extras
            or manifest.scope != c.InstallScope(
                native_capabilities=("native.stdlib",), companions=(), full_toolkit=False,
                enhanced=False,
            )
            or c.digest(manifest.context) != receipt["context_digest"]
            or manifest.consuming_contexts != receipt["consuming_contexts"]
            or tuple(c.public_object(c.wire(member)) for member in manifest.members) != receipt["members"]
        ):
            raise AuthorizationError()
        interpreter = c.public_object(receipt["interpreter"])
        if (
            spec.python != interpreter["path"] or spec.python_digest != interpreter["digest"]
            or spec.python_version != interpreter["version"] or spec.platform != interpreter["platform"]
            or tuple((wheel.member, wheel.digest) for wheel in spec.wheels)
            != tuple((c.public_object(member)["path"], c.public_object(member)["digest"])
                     for member in receipt["members"])
        ):
            raise AuthorizationError()

    def acquire(
        self, manifest: ManagedGenerationManifest, broker: AuthorizationBroker,
        permit: lc.LifecycleEffectPermit, effect: lc.LifecycleEffectBinding,
        clock: c.ClockPort, cancel: c.CancelPort,
    ) -> DownloadReceipt:
        """Consume the original one-use byte-acquisition permit, never an HTTPS bypass."""
        if broker.reconcile_lifecycle(permit) != effect:
            raise AuthorizationError()
        scope = broker._life_scope(permit)
        if scope is None:
            raise AuthorizationError()
        clock = _MonotonicClock(clock)
        now = clock.monotonic()
        deadline = min(scope.deadline, c.checked_deadline(now, 300.0))
        selected = tuple(item for item in effect.lifecycle.effects
                         if item.occurrence_id == effect.occurrence_id)
        if len(selected) != 1 or selected[0].kind != "dependency-download":
            raise AuthorizationError()
        steps = effect.lifecycle.content["steps"]
        if type(steps) is not tuple:
            raise AuthorizationError()
        source = c.public_object(c.public_object(steps[selected[0].ordinal])["source"])
        if source != c.public_object({
            "source_id": self.asset.source_id, "artifact_digest": self.asset.sha256,
            "registry_digest": effect.lifecycle.registry_digest,
            "descriptor_digest": c.digest(self.asset),
        }):
            raise AuthorizationError()
        self.guard(manifest, clock, cancel, deadline)
        broker.enter_lifecycle(permit, effect, clock.monotonic())
        try:
            content = self._current(clock, cancel, deadline).content
            with broker._lock, broker._life_current(scope, clock.monotonic()):
                self.guard(manifest, clock, cancel, deadline)
            return DownloadReceipt(content, self.asset.sha256, cancel.is_cancelled())
        except BaseException:
            broker.revoke_lifecycle(effect.lifecycle.kind, effect.lifecycle.plan_id)
            raise
