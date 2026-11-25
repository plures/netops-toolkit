"""Separate exact semantic-scope review, conjunctive with the existing broker.

The broker's closed six-category schema is retained. These private review facts
cannot mint, extend or replace a lifecycle consent, admission session or permit.
They prevent collapsing service/image/OS/distro details into one generic assent.
"""

from __future__ import annotations

import threading
from typing import NoReturn, Protocol

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import AuthorizationError

from ._family_lock import _FamilyLock

__all__: tuple[str, ...] = ()


class _ScopeReviewPort(Protocol):
    def confirm_scope(
        self, binding: lc.LifecycleBinding, scope: str,
        occurrence_ids: tuple[str, ...], deadline: float,
    ) -> bool:
        """Separately review one semantic scope and its exact owned occurrences."""
        ...


class _ScopeReceipt:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<private family scope review>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("Private review cannot be serialized.")


class _ScopeReviews:
    """Keep live trusted-prompt facts; neither saved choices nor booleans are receipts."""

    def __init__(self, review: _ScopeReviewPort) -> None:
        self._review = review
        self._mutex = threading.Lock()
        self._issued: dict[
            _ScopeReceipt,
            tuple[lc.LifecycleBinding, str, float, float, tuple[tuple[str, tuple[str, ...]], ...]],
        ] = {}
        self._used: set[tuple[_ScopeReceipt, str]] = set()

    def review(
        self, lock: _FamilyLock, binding: lc.LifecycleBinding,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _ScopeReceipt:
        """Collect distinct requests without issuing any effect authority."""
        from ._family_provider import _descriptor, _operation

        if type(lock) is not _FamilyLock:
            raise c.ContractError()
        lock.__post_init__()
        started = c.finite(clock.monotonic())
        deadline = c.finite(deadline)
        if deadline <= started or deadline - started > 300.0 or cancel.is_cancelled():
            raise AuthorizationError()
        groups: dict[str, list[str]] = {}
        steps = binding.content.get("steps")
        if type(steps) is not tuple or len(steps) != len(binding.effects):
            raise c.ContractError()
        for effect, step in zip(binding.effects, steps):
            action = {
                "dependency-stage": "install", "dependency-uninstall": "remove",
                "dependency-verify": "verify",
            }.get(effect.kind)
            if action is None:
                continue
            descriptor = c.public_object(step)
            destination = descriptor.get("destination")
            if destination is not None and c.public_object(destination).get(
                "resource_id",
            ) == binding.root.resource_id:
                # The original whole-tree stage/verify is independently
                # validated by its owner and is not a family operation.
                continue
            generation_id = c.text(descriptor["generation_id"])
            generation = next((
                item for item in binding.generation.selected
                if item.generation_id == generation_id
            ), binding.generation)
            for release in lock.releases:
                operation = _operation(lock, release, action, generation_id)
                if descriptor == _descriptor(
                    lock, release, operation, binding.root, effect.occurrence_id,
                    generation_manifest_digest=generation.manifest_digest,
                ):
                    for scope in operation.scopes:
                        groups.setdefault(scope, []).append(effect.occurrence_id)
                    break
            else:
                raise AuthorizationError()
        selected = tuple((scope, tuple(ids)) for scope, ids in groups.items())
        last = started
        for scope, occurrences in selected:
            now = c.finite(clock.monotonic())
            if now < last or now >= deadline or cancel.is_cancelled():
                raise AuthorizationError()
            last = now
            if self._review.confirm_scope(binding, scope, occurrences, deadline) is not True:
                raise AuthorizationError()
        now = c.finite(clock.monotonic())
        if now < last or now >= deadline or cancel.is_cancelled():
            raise AuthorizationError()
        receipt = _ScopeReceipt()
        with self._mutex:
            self._issued[receipt] = binding, lock.digest, now, deadline, selected
        return receipt

    def consume(
        self, receipt: _ScopeReceipt | None, lock: _FamilyLock,
        binding: lc.LifecycleBinding, occurrence_id: str,
        scopes: tuple[str, ...], now: float,
    ) -> None:
        """Require the same live detailed review alongside the actual broker permit."""
        if not scopes:
            return
        with self._mutex:
            if type(receipt) is not _ScopeReceipt or receipt not in self._issued:
                raise AuthorizationError()
            selected, lock_digest, reviewed_at, deadline, groups = self._issued[receipt]
            key = receipt, occurrence_id
            if (
                selected != binding or lock_digest != lock.digest
                or not reviewed_at <= c.finite(now) < deadline or key in self._used
                or any(occurrence_id not in dict(groups).get(scope, ()) for scope in scopes)
            ):
                raise AuthorizationError()
            self._used.add(key)
