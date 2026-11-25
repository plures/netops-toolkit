"""Exact full-family lifecycle dispatch through trusted typed host I/O ports.

Ports are private constructor dependencies, not serialized external APIs. The
driver cannot run a shell, accept argv, adopt a service, mint a lifecycle grant,
or infer permission from a metadata lock or an ownership receipt.
"""

from __future__ import annotations

import logging
import threading
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import NoReturn, Protocol

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import AuthorizationBroker, AuthorizationError
from netops.ansible.policy.lifecycle_evidence import lifecycle_arguments_digest

from ._family_consent import _ScopeReceipt, _ScopeReviews
from ._family_lock import _FamilyLock, _name, _Release, _trace

__all__: tuple[str, ...] = ()
_LOG = logging.getLogger(__name__)
_CATEGORIES = {
    "os": "elevation", "elevation": "elevation",
    "wsl": "wsl-change", "distribution": None,
    "vm": "vm-change", "virtualization": "vm-change",
    "runtime": "runtime-install", "image": "runtime-install",
    "service": "runtime-install", "security": "security-change", "reboot": "reboot",
}


@dataclass(frozen=True)
class _Operation:
    lock_digest: str
    release_digest: str
    action: str
    resource_id: str
    generation_id: str
    scopes: tuple[str, ...]

    def __post_init__(self) -> None:
        c.sha256(self.lock_digest)
        c.sha256(self.release_digest)
        _name(self.resource_id)
        c.text(self.generation_id)
        if self.action not in ("install", "verify", "remove"):
            raise c.ContractError()
        c.unique(self.scopes)
        if set(self.scopes) - set(_CATEGORIES):
            raise c.ContractError()


@dataclass(frozen=True)
class _Resource:
    """Protected ledger facts, never ownership inferred from OS resource names."""

    resource_id: str
    generation_id: str
    lock_digest: str
    release_digest: str
    identity_digest: str
    owned: bool
    active: bool
    pins: tuple[str, ...]
    healthy_previous: bool = False

    def __post_init__(self) -> None:
        _name(self.resource_id)
        c.text(self.generation_id)
        for value in (self.lock_digest, self.release_digest, self.identity_digest):
            c.sha256(value)
        if any(type(value) is not bool for value in (
            self.owned, self.active, self.healthy_previous,
        )):
            raise c.ContractError()
        c.unique(self.pins)


@dataclass(frozen=True)
class _HostResult:
    """Factual postcondition; no raw host diagnostics, credentials or argv."""

    identity_digest: str
    changed: bool
    owned: bool
    verified: bool

    def __post_init__(self) -> None:
        c.sha256(self.identity_digest)
        if any(type(value) is not bool for value in (self.changed, self.owned, self.verified)):
            raise c.ContractError()


@dataclass(frozen=True)
class _FamilyReceipt:
    operation: _Operation
    result: _HostResult
    ledger_revision: int


class _FamilyLedger(Protocol):
    def lock(self, binding: lc.LifecycleBinding) -> AbstractContextManager[object]:
        """Lock and recheck this exact lifecycle against current pointer/pin writers."""
        ...

    def read(
        self, root: lc.OwnedRootBinding, resource_id: str,
    ) -> tuple[int, _Resource | None, _Operation | None]:
        """Read a known owned manifest, with explicit absence; unknown roots reject."""
        ...

    def begin(
        self, root: lc.OwnedRootBinding, operation: _Operation, expected_revision: int,
    ) -> int:
        """CAS an issued marker before I/O; unfinished issuance blocks automatic replay."""
        ...

    def record(
        self, root: lc.OwnedRootBinding, operation: _Operation,
        result: _HostResult, expected_revision: int,
    ) -> int:
        """CAS exact factual membership or removal, retaining issued uncertainty."""
        ...


class _Authority:
    """Live one-use, original-deadline handler entry, scoped to one typed operation."""

    __slots__ = (
        "_broker", "_permit", "_effect", "_operation", "_clock",
        "_cancel", "_deadline", "_used", "_mutex", "_last", "_entered",
    )

    def __init__(
        self, broker: AuthorizationBroker, permit: lc.LifecycleEffectPermit,
        effect: lc.LifecycleEffectBinding, operation: _Operation,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> None:
        self._broker, self._permit, self._effect = broker, permit, effect
        self._operation, self._clock, self._cancel = operation, clock, cancel
        self._deadline, self._used, self._mutex = deadline, False, threading.Lock()
        self._last = c.finite(clock.monotonic())
        self._entered = False

    def __repr__(self) -> str:
        return "<private family authority>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("Private authority cannot be serialized.")

    @property
    def deadline(self) -> float:
        return self._deadline

    def check(self) -> None:
        """Ports repeat this check at I/O boundaries; no timeout is ever renewed."""
        with self._mutex:
            now = c.finite(self._clock.monotonic())
            if now < self._last:
                raise AuthorizationError()
            self._last = now
            if self._cancel.is_cancelled() or now >= self._deadline:
                raise AuthorizationError()
            from ._composition import ManagedLifecycleState

            state = self._broker._lifecycle_state
            if type(state) is ManagedLifecycleState:
                manifest = state._manifest(self._effect.lifecycle)
                if manifest.bootstrap_digest is not None:
                    state.guard_source(manifest, self._clock, self._cancel, self._deadline)
                    if state._bootstrap is not None and state._bootstrap.family is not None:
                        state._bootstrap.family.require_operation(self._operation)
                    observed = c.finite(self._clock.monotonic())
                    if observed < self._last or self._cancel.is_cancelled() or observed >= self._deadline:
                        raise AuthorizationError()
                    self._last = observed

    def _admit(self) -> None:
        """Enter the broker outside the OS root lock; the host still claims once."""
        self.check()
        with self._mutex:
            if self._entered:
                raise AuthorizationError()
            self._broker.enter_lifecycle(
                self._permit, self._effect, c.finite(self._clock.monotonic()),
            )
            self._entered = True

    def enter(self, operation: _Operation) -> None:
        """Claim this fixed trusted host method's exact operation before I/O."""
        self.check()
        with self._mutex:
            if not self._entered or self._used or operation != self._operation:
                raise AuthorizationError()
            self._used = True


class _FamilyHost(Protocol):
    """Fixed typed ports implemented by trusted platform composition, not plugins.

    Each method MUST enter its exact authority before I/O, use pinned
    interpreters/regular-file identities and fixed argv (never a shell), recheck
    the original deadline/cancellation and return a verified exact postcondition.
    Remove may affect only the supplied owned identity, never a global service
    name, external runtime, user file or another generation.
    """

    def python(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Install/verify/remove the pinned owned interpreter, never global Python."""
        ...

    def wheel(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Use the locked consuming interpreter and offline no-deps wheel install."""
        ...

    def executable(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Materialize exact executable members, not caller commands or PATH fallback."""
        ...

    def collection(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Use the pinned controller's offline Galaxy and exact collection closure."""
        ...

    def library(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Materialize exact ABI-compatible native members and functional render proof."""
        ...

    def runtime(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Manage the selected isolated runtime; never stop a preexisting daemon."""
        ...

    def image(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Use the pinned runtime and exact image digest, never mutable tags."""
        ...

    def service(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Manage only this generation's exact owned service identity."""
        ...

    def os_feature(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Apply one separately reviewed OS feature, never implicit elevation/reboot."""
        ...

    def distribution(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        """Import/remove the exact owned WSL/VM distribution, never a user's distro."""
        ...


def _operation(
    lock: _FamilyLock, release: _Release, action: str, generation_id: str,
) -> _Operation:
    return _Operation(
        lock.digest, c.digest(release), action,
        "family-" + c.digest((generation_id, release.requirement.key))[:40],
        generation_id, release.scopes if action != "verify" else (),
    )


def _descriptor(
    lock: _FamilyLock, release: _Release, operation: _Operation,
    root: lc.OwnedRootBinding, occurrence_id: str,
    *, generation_manifest_digest: str | None = None,
) -> lc.FrozenObject:
    """Project into the existing closed lifecycle step, not a parallel plan schema."""
    categories = tuple(dict.fromkeys(
        category for scope in operation.scopes
        if (category := _CATEGORIES[scope]) is not None
    ))
    return c.public_object({
        "occurrence_id": occurrence_id, "generation_id": operation.generation_id,
        "source": {
            "source_id": release.requirement.source, "registry_digest": lock.registry_digest,
            "artifact_digest": release.artifact.sha256 if release.artifact else release.metadata_digest,
            "descriptor_digest": c.digest(operation),
        } if operation.action == "install" else None,
        "destination": {
            "resource_id": operation.resource_id, "root_resource_id": root.resource_id,
            "segments": ("families", operation.resource_id),
            "manifest_digest": c.sha256(generation_manifest_digest)
            if operation.action == "remove" and generation_manifest_digest is not None
            else lock.digest,
        },
        "reuse": None, "consequential": categories,
    })


class _FamilyDriver:
    """Consume one actual lifecycle permit per exact typed host operation."""

    def __init__(
        self, host: _FamilyHost, ledger: _FamilyLedger, clock: c.ClockPort,
        scope_reviews: _ScopeReviews | None = None,
        scope_review: _ScopeReceipt | None = None,
        *, generation_manifest_digest: str | None = None,
    ) -> None:
        self._host, self._ledger, self._clock = host, ledger, clock
        if scope_reviews is not None and type(scope_reviews) is not _ScopeReviews:
            raise c.ContractError()
        self._scope_reviews = scope_reviews
        if scope_review is not None and type(scope_review) is not _ScopeReceipt:
            raise c.ContractError()
        self._scope_review = scope_review
        if generation_manifest_digest is not None:
            c.sha256(generation_manifest_digest)
        self._generation_manifest_digest = generation_manifest_digest

    def execute(
        self, lock: _FamilyLock, release: _Release, operation: _Operation,
        broker: AuthorizationBroker, permit: lc.LifecycleEffectPermit,
        effect: lc.LifecycleEffectBinding, cancel: c.CancelPort,
        *, scope_review: _ScopeReceipt | None = None,
    ) -> _FamilyReceipt:
        """Dispatch only exact complete locks, current grants and safe owned identities."""
        if (
            type(lock) is not _FamilyLock or type(release) is not _Release
            or type(operation) is not _Operation or type(broker) is not AuthorizationBroker
            or type(effect) is not lc.LifecycleEffectBinding
        ):
            raise c.ContractError()
        lock.__post_init__()
        operation.__post_init__()
        binding = effect.lifecycle
        if (
            release not in lock.releases or binding.registry_digest != lock.registry_digest
            or operation != _operation(lock, release, operation.action, operation.generation_id)
            or broker.reconcile_lifecycle(permit) != effect
        ):
            raise AuthorizationError()
        allowed = {
            "install": ("install", "dependency-stage"),
            "verify": ("install", "dependency-verify"),
            "remove": ("uninstall", "dependency-uninstall"),
        }[operation.action]
        occurrences = tuple(item for item in binding.effects if item.occurrence_id == effect.occurrence_id)
        if len(occurrences) != 1:
            raise AuthorizationError()
        occurrence = occurrences[0]
        generation = binding.generation if binding.kind == "install" else next(
            (selected for selected in binding.generation.selected
             if selected.generation_id == operation.generation_id), None,
        )
        descriptor = _descriptor(
            lock, release, operation, binding.root, effect.occurrence_id,
            generation_manifest_digest=self._generation_manifest_digest,
        )
        steps = binding.content["steps"]
        categories = descriptor["consequential"]
        if type(steps) is not tuple or type(categories) is not tuple:
            raise c.ContractError()
        if (
            (binding.kind, occurrence.kind) != allowed
            or occurrence.resource_id != operation.resource_id
            or occurrence.arguments_digest != lifecycle_arguments_digest(descriptor)
            or descriptor not in steps
            or generation is None or generation.manifest_digest != (
                self._generation_manifest_digest or lock.digest
            )
            or (
                binding.kind == "install"
                and operation.generation_id != binding.generation.generation_id
            )
            or (
                binding.kind == "uninstall"
                and operation.generation_id not in tuple(
                    generation.generation_id for generation in binding.generation.selected
                )
            )
        ):
            raise AuthorizationError()
        for category in categories:
            if not any(
                requirement.category == category and effect.occurrence_id in requirement.occurrence_ids
                for requirement in binding.required_consequential
            ):
                raise AuthorizationError()
        scope = broker._life_scope(permit)
        now = c.finite(self._clock.monotonic())
        if scope is None or scope.binding != binding:
            raise AuthorizationError()
        from ._family_integration import _MaterializedFamilies

        materialized = (
            release.requirement.family in (
                "python", "wheel", "executable", "collection", "library",
            ) and not release.scopes
        )
        # The real materialized hook only revalidates the original stage's
        # already acquired/installed bytes. It cannot reacquire or install them.
        poststage = materialized and type(self._host) is _MaterializedFamilies
        source_deadlines = tuple(
            item.expires_at for item in lock.observations
        ) if operation.action == "install" and not poststage else ()
        deadline = min(scope.deadline, *source_deadlines,
                       now + (60.0 if operation.action == "verify" else 300.0))
        if cancel.is_cancelled() or now >= deadline or any(
            item.observed_at > now for item in lock.observations
        ):
            raise AuthorizationError()
        if operation.scopes:
            if self._scope_reviews is None:
                raise AuthorizationError()
            self._scope_reviews.consume(
                scope_review if scope_review is not None else self._scope_review,
                lock, binding, effect.occurrence_id, operation.scopes, now,
            )
        authority = _Authority(broker, permit, effect, operation, self._clock, cancel, deadline)
        authority._admit()
        # The host ledger lock must be the same root lock as activation, pinning
        # and uninstall. Read, exact host mutation and factual CAS are indivisible.
        with self._ledger.lock(binding):
            revision, existing, pending = self._ledger.read(binding.root, operation.resource_id)
            c.counter(revision)
            from ._family_ledger import _OwnedFamilyLedger
            from ._platform_host import _supported_release

            recover_install = (
                pending is not None and type(self._ledger) is _OwnedFamilyLedger
                and operation.action == "verify"
                and (materialized or _supported_release(release))
                and pending == _operation(lock, release, "install", operation.generation_id)
            )
            recover_remove = (
                type(self._ledger) is _OwnedFamilyLedger
                and type(self._host) is _MaterializedFamilies
                and operation.action == "remove" and pending == operation
                and existing is not None
                and (materialized or _supported_release(release))
            )
            observe_materialized = (
                poststage and type(self._ledger) is _OwnedFamilyLedger
                and operation.action == "verify" and existing is None
                and pending in (None, operation)
            )
            recover_verify = observe_materialized and pending == operation
            reconciling = recover_install or recover_remove or recover_verify
            if pending is not None and not reconciling:
                raise AuthorizationError()
            if existing is not None:
                if type(existing) is not _Resource:
                    raise c.ContractError()
                existing.__post_init__()
                if (
                    existing.resource_id != operation.resource_id
                    or existing.generation_id != operation.generation_id
                    or existing.lock_digest != lock.digest
                    or existing.release_digest != c.digest(release)
                ):
                    raise AuthorizationError()
                if operation.action != "verify" and (
                    not existing.owned or existing.active or existing.pins or existing.healthy_previous
                ):
                    raise AuthorizationError()
            elif operation.action != "install" and not reconciling and not observe_materialized:
                raise AuthorizationError()
            authority.check()
            issued_revision = revision if reconciling else self._ledger.begin(
                binding.root, operation, revision,
            )
            if not reconciling and c.counter(issued_revision) != revision + 1:
                raise AuthorizationError()
            authority.check()
            _trace("family-provider", release.requirement.family, "attempt")
            try:
                result = (
                    self._host.reconcile_removal(release, operation, authority, existing)
                    if recover_remove and type(self._host) is _MaterializedFamilies
                    and existing is not None else
                    self._dispatch(release, operation, authority, existing)
                )
            except BaseException:
                _trace("family-provider", release.requirement.family, "failed")
                raise
            _trace("family-provider", release.requirement.family, "returned")
            if type(result) is not _HostResult or not authority._used:
                raise AuthorizationError()
            result.__post_init__()
            if not result.verified or (
                operation.action != "verify" and not result.owned
            ) or (
                existing is not None and operation.action != "install"
                and result.identity_digest != existing.identity_digest
            ) or (
                operation.action == "verify" and result.changed
            ):
                raise AuthorizationError()
            # Late completion remains factual. Do not retry an issued OS
            # operation or erase its ledger fact because consent expired in I/O.
            if observe_materialized and type(self._ledger) is _OwnedFamilyLedger:
                following = self._ledger.record_materialized_verification(
                    binding.root, operation, result, issued_revision,
                )
            elif reconciling:
                if type(self._ledger) is not _OwnedFamilyLedger or pending is None:
                    raise AuthorizationError()
                following = self._ledger.reconcile(
                    binding.root, pending, result, issued_revision,
                )
            else:
                following = self._ledger.record(binding.root, operation, result, issued_revision)
            if c.counter(following) != issued_revision + 1:
                raise AuthorizationError()
        try:
            _LOG.info(
                "install.step", extra={
                    "metric_name": "netops.install.step.count", "metric_value": 1,
                    "kind": binding.kind, "step_kind": release.requirement.family,
                    "status": "succeeded", "category": "none", "reason": "none",
                    "stage": "family-provider", "next_action": "verify-selected-closure",
                },
            )
        except BaseException:
            pass
        return _FamilyReceipt(operation, result, following)

    def _dispatch(
        self, release: _Release, operation: _Operation, authority: _Authority,
        existing: _Resource | None,
    ) -> _HostResult:
        family = release.requirement.family
        if family == "python":
            return self._host.python(release, operation, authority, existing)
        if family == "wheel":
            return self._host.wheel(release, operation, authority, existing)
        if family == "executable":
            return self._host.executable(release, operation, authority, existing)
        if family == "collection":
            return self._host.collection(release, operation, authority, existing)
        if family == "library":
            return self._host.library(release, operation, authority, existing)
        if family == "runtime":
            return self._host.runtime(release, operation, authority, existing)
        if family == "image":
            return self._host.image(release, operation, authority, existing)
        if family == "service":
            return self._host.service(release, operation, authority, existing)
        if family == "os-feature":
            return self._host.os_feature(release, operation, authority, existing)
        if family == "distribution":
            return self._host.distribution(release, operation, authority, existing)
        raise c.ContractError()
