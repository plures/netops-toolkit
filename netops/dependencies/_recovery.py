"""Owned non-authoritative selected-scope recovery, never serialized consent.

These records complement the lifecycle checkpoint; they are not generation
manifests, installation receipts or qualification. Missing/corrupt records are
not reconstructed from directory names, caller claims or a remembered grant.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass, fields, replace
from typing import TYPE_CHECKING, Protocol
from uuid import uuid4

from netops.ansible import contracts as c
from netops.ansible.artifacts import OwnedRecord
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import AuthorizationError

__all__: tuple[str, ...] = ()
_SCHEMA = "i02-lifecycle-recovery-v1"

if TYPE_CHECKING:
    from ._lifecycle import InstallOutcome


def _closed(value: object, names: tuple[str, ...]) -> lc.FrozenObject:
    record = c.public_object(value)
    if set(record) != set(names):
        raise c.ContractError()
    return record


def _strings(value: object) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise c.ContractError()
    result = tuple(c.text(item) for item in value)
    c.unique(result)
    return result


def _bool(value: object) -> bool:
    if type(value) is not bool:
        raise c.ContractError()
    return value


@dataclass(frozen=True)
class RecoverySelection:
    """Durable exact selection and baseline observations, not execution authority."""

    installation_id: str
    plan_id: str
    generation_binding: lc.GenerationBinding
    scope: c.InstallScope
    context: c.InstallContext
    consuming_contexts: tuple[str, ...]
    observation_digest: str

    @property
    def generation(self) -> lc.GenerationBinding:
        """Return the exact binding without a checkpoint numeric-field collision."""
        return self.generation_binding

    def __post_init__(self) -> None:
        """Validate all persisted identity fields before reading any host state."""
        c.uuid_text(self.installation_id)
        c.uuid_text(self.plan_id)
        c.text(self.generation.generation_id)
        c.counter(self.generation.ordinal)
        c.sha256(self.generation.content_digest)
        c.sha256(self.generation.manifest_digest)
        if self.generation.selected or type(self.scope) is not c.InstallScope:
            raise c.ContractError()
        if type(self.context) is not c.InstallContext:
            raise c.ContractError()
        c.sha256(self.observation_digest)
        for item in self.consuming_contexts:
            c.sha256(item)
        c.unique(self.consuming_contexts)


def _selection(value: object) -> RecoverySelection:
    data = _closed(value, tuple(item.name for item in fields(RecoverySelection)))
    raw_scope = _closed(data["scope"], (
        "native_capabilities", "companions", "enhanced", "full_toolkit",
    ))
    scope = c.InstallScope(
        _strings(raw_scope["native_capabilities"]), _strings(raw_scope["companions"]),
        _bool(raw_scope["enhanced"]), _bool(raw_scope["full_toolkit"]),
    )
    raw_context = _closed(_closed(data["context"], ("context",))["context"], (
        "controller_id", "route_digest", "source_id", "mapping_digest", "policy_identity",
        "registry_digest", "assets_digest",
    ))
    raw_policy = _closed(raw_context["policy_identity"], tuple(
        item.name for item in fields(lc.PolicyIdentity)
    ))
    policy = lc.PolicyIdentity(
        c.text(raw_policy["canonical_revision"]), c.sha256(raw_policy["source_sha256"]),
        c.sha256(raw_policy["contracts_sha256"]), c.sha256(raw_policy["bundle_sha256"]),
        _strings(raw_policy["rule_manifest"]), c.text(raw_policy["reducer_version"]),
        c.text(raw_policy["profile"]), c.text(raw_policy["numeric_profile"]),
        c.text(raw_policy["schema"]),
    )
    context = c.InstallContext(c.Context(
        c.text(raw_context["controller_id"]), c.sha256(raw_context["route_digest"]),
        c.text(raw_context["source_id"]), c.sha256(raw_context["mapping_digest"]),
        policy, c.sha256(raw_context["registry_digest"]), c.sha256(raw_context["assets_digest"]),
    ))
    generation = _closed(data["generation_binding"], (
        "generation_id", "ordinal", "content_digest", "manifest_digest", "selected",
    ))
    if generation["selected"] != ():
        raise c.ContractError()
    return RecoverySelection(
        c.text(data["installation_id"]), c.text(data["plan_id"]),
        lc.GenerationBinding(
            c.text(generation["generation_id"]), c.counter(generation["ordinal"]),
            c.sha256(generation["content_digest"]), c.sha256(generation["manifest_digest"]),
        ), scope, context, _strings(data["consuming_contexts"]),
        c.sha256(data["observation_digest"]),
    )


class _RecoveryState(Protocol):
    """Protected metadata operations shared by inert and managed host states."""

    def _read(self, resource_id: str) -> OwnedRecord:
        ...

    def _facts(self) -> OwnedRecord:
        ...

    def _write(self, resource: str, expected: int, record: OwnedRecord) -> OwnedRecord:
        ...

    def lock_lifecycle(self, binding: lc.LifecycleBinding) -> AbstractContextManager[object]:
        """Hold the exact protected root lock for metadata reads and CAS."""
        ...


class RecoveryStore:
    """CAS selected facts under the same protected root lock as lifecycle effects."""

    def __init__(self, state: _RecoveryState) -> None:
        self._state = state

    def _read(self, resource: str) -> tuple[OwnedRecord, RecoverySelection]:
        try:
            record = self._state._read(resource)
        except OSError:
            # Alternate owned ports need not expose their missing/corrupt
            # storage paths through a recovery query.
            raise AuthorizationError() from None
        data = _closed(record.payload, ("schema", "selection"))
        if data["schema"] != _SCHEMA:
            raise c.ContractError()
        return record, _selection(data["selection"])

    def read(self, installation_id: str) -> RecoverySelection:
        """Fail closed on missing/corrupt checkpoints; never infer a virgin install."""
        c.uuid_text(installation_id)
        _, selected = self._read("dependency-recovery-" + installation_id)
        if selected.installation_id != installation_id:
            raise AuthorizationError()
        return selected

    def retained(self, generation: lc.GenerationBinding) -> RecoverySelection:
        """Load the selected scope for the exact retained content and manifest."""
        c.text(generation.generation_id)
        _, selected = self._read("dependency-generation-" + c.digest(generation))
        if selected.generation != generation:
            raise AuthorizationError()
        return selected

    def save(
        self, binding: lc.InstallBinding, selection: RecoverySelection,
        previous: RecoverySelection | None,
        *, retained: RecoverySelection | None = None,
    ) -> None:
        """Create once or advance a known exact install; records confer no authority."""
        selection.__post_init__()
        if (
            selection.installation_id != binding.lifecycle_id
            or selection.plan_id != binding.plan_id or selection.generation != binding.generation
            or selection.scope != binding.scope or c.digest(selection.context) != binding.context_digest
        ):
            raise AuthorizationError()
        payload = c.public_object({"schema": _SCHEMA, "selection": c.wire(selection)})
        with self._state.lock_lifecycle(binding):
            root = self._state._facts()
            if retained is not None:
                actual_retained = self.retained(binding.generation)
                if (
                    actual_retained != retained or retained.generation != selection.generation
                    or retained.scope != selection.scope or retained.context != selection.context
                    or retained.consuming_contexts != selection.consuming_contexts
                ):
                    raise AuthorizationError()
            resource = "dependency-recovery-" + binding.lifecycle_id
            if previous is None:
                # Create-only CAS refuses an unknown existing/corrupt record.
                record = replace(root, resource_id=resource, revision=0, payload=payload)
                self._state._write(resource, 0, record)
                generation_resource = "dependency-generation-" + c.digest(binding.generation)
                if retained is None:
                    self._state._write(generation_resource, 0, replace(
                        record, resource_id=generation_resource,
                    ))
            else:
                record, actual = self._read(resource)
                if actual != previous or previous.generation != selection.generation:
                    raise AuthorizationError()
                self._state._write(resource, record.revision, replace(
                    record, revision=record.revision + 1, payload=payload,
                ))


class OutcomeStore:
    """Durable primary/cleanup/pending history; never restore authority from it."""

    def __init__(self, state: _RecoveryState) -> None:
        self._state = state

    def _head(self, installation_id: str) -> OwnedRecord | None:
        try:
            record = self._state._read("dependency-outcome-" + c.uuid_text(installation_id))
        except (FileNotFoundError, KeyError):
            return None
        data = _closed(record.payload, ("schema", "latest", "latest_digest"))
        if data["schema"] != "i02-outcome-head-v1":
            raise c.ContractError()
        return record

    def previous_errors(self, installation_id: str) -> tuple[c.SafeError, ...]:
        """Recover original primary errors from the exact immutable last outcome."""
        head = self._head(installation_id)
        if head is None:
            return ()
        event = self._state._read(c.text(head.payload["latest"]))
        if c.digest(event.payload) != head.payload["latest_digest"]:
            raise AuthorizationError()
        outcome = c.public_object(event.payload["outcome"])
        result = []
        for name in ("original_errors", "errors"):
            values = outcome[name]
            if type(values) is not tuple:
                raise c.ContractError()
            for value in values:
                data = _closed(value, ("category", "reason", "stage", "target_id", "step_id",
                                       "retryable", "detail", "next_action"))
                result.append(c.SafeError(
                    c.ErrorCategory(c.text(data["category"])), c.ReasonCode(c.text(data["reason"])),
                    c.Stage(c.text(data["stage"])),
                    None if data["target_id"] is None else c.text(data["target_id"]),
                    None if data["step_id"] is None else c.text(data["step_id"]),
                    _bool(data["retryable"]), c.text(data["detail"], empty=True),
                    c.text(data["next_action"]),
                ))
        return tuple(result)

    def save(self, binding: lc.LifecycleBinding, outcome: InstallOutcome) -> None:
        """Append complete factual outcome and CAS its head under the owned lock."""
        with self._state.lock_lifecycle(binding):
            head = self._head(outcome.installation_id)
            root = self._state._facts()
            resource = "dependency-outcome-event-" + str(uuid4())
            payload = c.public_object({
                "schema": "i02-outcome-event-v1", "outcome": c.wire(outcome),
                "previous": None if head is None else head.payload["latest"],
                "previous_digest": None if head is None else head.payload["latest_digest"],
            })
            self._state._write(resource, 0, replace(root, resource_id=resource, revision=0, payload=payload))
            identifier = "dependency-outcome-" + outcome.installation_id
            record = root if head is None else head
            self._state._write(identifier, 0 if head is None else head.revision, replace(
                record, resource_id=identifier, revision=0 if head is None else head.revision + 1,
                payload=c.public_object({"schema": "i02-outcome-head-v1", "latest": resource,
                                         "latest_digest": c.digest(payload)}),
            ))
