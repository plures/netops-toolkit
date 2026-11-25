"""Protected exact-membership family ledger, using the existing owned-state port."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace

from netops.ansible import contracts as c
from netops.ansible.artifacts import OwnedRecord, OwnedStatePort
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationError,
    LifecycleSnapshot,
    LifecycleStatePort,
)
from netops.ansible.policy.lifecycle_evidence import validate_current

from ._family_lock import _FamilyLock, _trace
from ._family_provider import _HostResult, _Operation, _Resource

__all__: tuple[str, ...] = ()
_SCHEMA = "netops-family-resources-v1"


class _OwnedFamilyLedger:
    """Read only explicitly initialized known roots; never adopt discovered files.

    The setup owner must create the revision-zero ledger under initialization
    consent and bind its exact immutable lock in the root manifest. This class
    only consumes that record. Merely finding this schema never creates trust.
    """

    def __init__(
        self, state: OwnedStatePort, root: lc.OwnedRootBinding, resource_id: str,
        owner: str, policy: lc.PolicyIdentity, lock: _FamilyLock,
        lifecycle: LifecycleStatePort, clock: c.ClockPort,
    ) -> None:
        if type(root) is not lc.OwnedRootBinding or type(lock) is not _FamilyLock:
            raise c.ContractError()
        lock.__post_init__()
        self._state, self._root, self._resource_id = state, root, c.text(resource_id)
        self._owner, self._policy, self._lock = c.sha256(owner), policy, lock
        self._lifecycle, self._clock = lifecycle, clock
        self._read()

    @contextmanager
    def lock(self, binding: lc.LifecycleBinding) -> Iterator[object]:
        if binding.root != self._root:
            raise AuthorizationError()
        # Use the actual broker state owner's root lock, not a second lock
        # namespace. Recheck after handler entry to close the intervening race.
        with self._lifecycle.lock_lifecycle(binding) as held:
            snapshot = self._lifecycle.snapshot_lifecycle(binding)
            if type(snapshot) is not LifecycleSnapshot or (
                snapshot.binding != binding or snapshot.cancelled or not snapshot.setup_enabled
                or not snapshot.owned_valid or not snapshot.pins_valid or not snapshot.probes_valid
            ):
                raise AuthorizationError()
            validate_current(binding, snapshot.evidence, self._clock.monotonic())
            self._read()
            yield held

    def _record(self, resource_id: str) -> OwnedRecord:
        _trace("family-ledger-read", "ledger", "attempt")
        record = self._state.read(resource_id)
        _trace("family-ledger-read", "ledger", "returned")
        if type(record) is not OwnedRecord:
            raise c.ContractError()
        record.__post_init__()
        if (
            record.resource_id != resource_id or record.kind != "checkpoint"
            or record.ownership_token != self._owner or record.policy_identity != self._policy
        ):
            raise AuthorizationError()
        return record

    def _read(self) -> OwnedRecord:
        root = self._record(self._root.resource_id)
        manifest = c.public_object(root.payload.get("root_manifest"))
        registered = manifest.get("family_locks", ())
        if type(registered) is not tuple:
            raise AuthorizationError()
        pinned = any(
            type(item) is tuple and len(item) == 2 and c.digest(item[1]) == self._lock.digest
            for item in registered
        )
        if (
            c.digest(manifest) != self._root.manifest_digest
            or (manifest.get("family_lock_digest") != self._lock.digest and not pinned)
        ):
            raise AuthorizationError()
        record = self._record(self._resource_id)
        payload = record.payload
        if (
            set(payload) != {"schema", "root", "lock_digest", "resources", "pending"}
            or payload["schema"] != _SCHEMA
            or payload["root"] != c.public_object(c.wire(self._root))
            or payload["lock_digest"] != self._lock.digest
            or type(payload["resources"]) is not tuple
            or type(payload["pending"]) is not tuple
        ):
            raise AuthorizationError()
        resources = payload["resources"]
        pending = payload["pending"]
        if not isinstance(resources, tuple) or not isinstance(pending, tuple):
            raise c.ContractError()
        if len(resources) > 256 or len(pending) > 256:
            raise c.ContractError()
        records = tuple(_resource(item) for item in resources)
        operations = tuple(_operation(item) for item in pending)
        c.unique(tuple(item.resource_id for item in records))
        c.unique(tuple(item.resource_id for item in operations))
        if any(item.lock_digest != self._lock.digest for item in records) or any(
            item.lock_digest != self._lock.digest for item in operations
        ):
            raise AuthorizationError()
        return record

    def read(
        self, root: lc.OwnedRootBinding, resource_id: str,
    ) -> tuple[int, _Resource | None, _Operation | None]:
        """Return exact membership, never existence-based ownership."""
        if root != self._root:
            raise AuthorizationError()
        record = self._read()
        resources, pending = record.payload["resources"], record.payload["pending"]
        if type(resources) is not tuple or type(pending) is not tuple:
            raise c.ContractError()
        found = tuple(_resource(item) for item in resources
                      if c.public_object(item)["resource_id"] == resource_id)
        issued = tuple(_operation(item) for item in pending
                       if c.public_object(item)["resource_id"] == resource_id)
        actual = found[0] if found else None
        if actual is not None:
            from ._composition import ManagedLifecycleState

            if type(self._lifecycle) is ManagedLifecycleState:
                actual = self._lifecycle._family_resource_facts(actual)
        return record.revision, actual, issued[0] if issued else None

    def begin(
        self, root: lc.OwnedRootBinding, operation: _Operation, expected_revision: int,
    ) -> int:
        """Retain an issued marker before host I/O, including failures and crashes."""
        if root != self._root or type(operation) is not _Operation:
            raise AuthorizationError()
        operation.__post_init__()
        record = self._read()
        pending = record.payload["pending"]
        if (
            record.revision != expected_revision or operation.lock_digest != self._lock.digest
            or type(pending) is not tuple
            or any(c.public_object(item)["resource_id"] == operation.resource_id for item in pending)
        ):
            raise AuthorizationError()
        return self._write(record, {**dict(record.payload), "pending": (*pending, c.wire(operation))})

    def record(
        self, root: lc.OwnedRootBinding, operation: _Operation,
        result: _HostResult, expected_revision: int,
    ) -> int:
        """Complete only the identical issued operation, preserving previous members."""
        if root != self._root or type(operation) is not _Operation or type(result) is not _HostResult:
            raise AuthorizationError()
        result.__post_init__()
        record = self._read()
        resources, pending = record.payload["resources"], record.payload["pending"]
        if (
            record.revision != expected_revision or type(resources) is not tuple
            or type(pending) is not tuple or c.public_object(c.wire(operation)) not in pending
        ):
            raise AuthorizationError()
        previous = tuple(item for item in resources
                         if c.public_object(item)["resource_id"] == operation.resource_id)
        remaining = tuple(item for item in resources if item not in previous)
        if operation.action == "remove":
            if len(previous) != 1:
                raise AuthorizationError()
        elif operation.action == "verify":
            if len(previous) != 1 or result.changed:
                raise AuthorizationError()
            remaining = resources
        else:
            resource = _Resource(
                operation.resource_id, operation.generation_id, operation.lock_digest,
                operation.release_digest, result.identity_digest, result.owned, False, (),
            )
            remaining = (*remaining, c.public_object(c.wire(resource)))
        return self._write(record, {
            **dict(record.payload), "resources": remaining,
            "pending": tuple(item for item in pending if item != c.public_object(c.wire(operation))),
        })

    def record_materialized_verification(
        self, root: lc.OwnedRootBinding, operation: _Operation,
        observation: _HostResult, expected_revision: int,
    ) -> int:
        """Retain fresh owned-tree proof when earlier platform failure stopped receipts."""
        if (
            type(operation) is not _Operation or operation.action != "verify"
            or type(observation) is not _HostResult or observation.changed
            or not observation.owned or not observation.verified
        ):
            raise AuthorizationError()
        operation.__post_init__()
        observation.__post_init__()
        c.counter(expected_revision)
        from ._composition import ManagedLifecycleState
        from ._family_provider import _operation

        if type(self._lifecycle) is not ManagedLifecycleState or (
            self._lifecycle._family_locks.get(operation.generation_id) != self._lock
        ):
            raise AuthorizationError()
        releases = tuple(item for item in self._lock.releases
                         if c.digest(item) == operation.release_digest)
        if len(releases) != 1 or (
            releases[0].requirement.family not in (
                "python", "wheel", "executable", "collection", "library",
            ) or releases[0].scopes
            or operation != _operation(
                self._lock, releases[0], "verify", operation.generation_id,
            )
            or observation.identity_digest != c.digest((operation.generation_id, releases[0]))
        ):
            raise AuthorizationError()
        revision, existing, pending = self.read(root, operation.resource_id)
        if revision != expected_revision or existing is not None or pending != operation:
            raise AuthorizationError()
        record = self._read()
        resources, pending_values = record.payload["resources"], record.payload["pending"]
        if (
            record.revision != expected_revision
            or type(resources) is not tuple or type(pending_values) is not tuple
        ):
            raise AuthorizationError()
        resource = _Resource(
            operation.resource_id, operation.generation_id, operation.lock_digest,
            operation.release_digest, observation.identity_digest, True, False, (),
        )
        return self._write(record, {
            **dict(record.payload),
            "resources": (*resources, c.public_object(c.wire(resource))),
            "pending": tuple(item for item in pending_values
                             if item != c.public_object(c.wire(operation))),
        })

    def reconcile(
        self, root: lc.OwnedRootBinding, issued: _Operation,
        observation: _HostResult, expected_revision: int,
    ) -> int:
        """Close a lost acknowledgement only from fresh exact read-only proof."""
        if (
            type(issued) is not _Operation or issued.action not in ("install", "remove")
            or type(observation) is not _HostResult or observation.changed
            or not observation.owned or not observation.verified
        ):
            raise AuthorizationError()
        revision, existing, pending = self.read(root, issued.resource_id)
        if revision != expected_revision or pending != issued or (
            existing is not None and existing.identity_digest != observation.identity_digest
        ):
            raise AuthorizationError()
        if issued.action == "remove" and (
            existing is None or not existing.owned or existing.active
            or existing.pins or existing.healthy_previous
        ):
            raise AuthorizationError()
        return self.record(root, issued, observation, revision)

    def _write(self, record: OwnedRecord, payload: dict) -> int:
        following = replace(
            record, revision=c.counter(record.revision + 1), payload=c.public_object(payload),
        )
        _trace("family-ledger-cas", "ledger", "attempt")
        actual = self._state.compare_replace(record.resource_id, record.revision, following)
        _trace("family-ledger-cas", "ledger", "returned")
        if actual != following:
            raise AuthorizationError()
        return following.revision


def _resource(value: object) -> _Resource:
    item = c.public_object(value)
    if set(item) != set(_Resource.__dataclass_fields__):
        raise c.ContractError()
    values: dict = dict(item)
    result = _Resource(**values)
    result.__post_init__()
    return result


def _operation(value: object) -> _Operation:
    item = c.public_object(value)
    if set(item) != set(_Operation.__dataclass_fields__):
        raise c.ContractError()
    values: dict = dict(item)
    result = _Operation(**values)
    result.__post_init__()
    return result
