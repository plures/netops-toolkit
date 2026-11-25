"""Typed lifecycle dispatch through actual private A01 admission.

The owned adapter is deliberately an inert, local artifact adapter. It neither
installs packages nor qualifies a controller, runtime, platform or device.
Bootstrap supplies independently collected owned records, not caller facts.
Persisted receipts describe observations only and never restore authority.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from uuid import uuid4

from . import contracts as c
from .artifact_observations import (
    ArtifactObservations,
    _lifecycle_observation_context,
    _record_lifecycle_handler,
)
from .artifacts import ArtifactError, OwnedRecord, OwnedStatePort
from .policy import contracts as lc
from .policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    LifecycleSnapshot,
    bind_lifecycle,
)
from .policy.lifecycle_evidence import LifecycleEvidence, validate_current

_LOG = logging.getLogger(__name__)
_SCHEMA = "a02-owned-inert-v1"
_OBSERVATIONS = ArtifactObservations()


def _object(value: object, names: tuple[str, ...]) -> lc.FrozenObject:
    result = c.public_object(value)
    if set(result) != set(names):
        raise c.ContractError()
    return result


def _tuple(value: object) -> tuple[lc.Json, ...]:
    if type(value) is not tuple:
        raise c.ContractError()
    return value


def _bytes(value: object) -> bytes:
    items = _tuple(value)
    if len(items) > 65536 or any(type(item) is not int or not 0 <= item <= 255 for item in items):
        raise c.ContractError()
    return bytes(c.counter(item) for item in items)


def _pointer(value: object) -> lc.PointerExpectation:
    record = c.public_object(value)
    if set(record) == {"kind", "revision"} and record["kind"] == "absent":
        return lc.AbsentPointer("absent", c.counter(record["revision"]))
    if set(record) == {"kind", "revision", "active_generation_id", "pointer_digest"}:
        if record["kind"] != "present":
            raise c.ContractError()
        return lc.PresentPointer(
            "present", c.text(record["active_generation_id"]),
            c.sha256(record["pointer_digest"]), c.counter(record["revision"]),
        )
    raise c.ContractError()


@dataclass(frozen=True)
class LifecycleHandlerReceipt:
    """Factual local completion, explicitly separate from executable authority."""

    binding: lc.LifecycleEffectBinding
    kind: lc.LifecycleEffectKind
    result_digest: str
    changed: bool
    pointer: tuple[str, int] | None = None


@dataclass(frozen=True)
class LifecycleRunResult:
    """Observed completed work and any unfinished factual acknowledgement."""

    receipts: tuple[LifecycleHandlerReceipt, ...]
    pending: tuple[lc.LifecycleEffectBinding, ...]
    completed: bool
    uncertain: bool


class OwnedLifecycleState:
    """Read closed owner records and serialize lifecycle CAS on the root lock.

    ``facts_resource`` is an existing owned checkpoint with schema
    ``a02-owned-inert-v1``. Its root manifest, generation/step/pin references
    and verification reference are collected by trusted bootstrap. The record
    contains no grant, consent, session or permit. No missing record is virgin
    state: virgin absence is an explicit pointer descriptor in this record.
    """

    def __init__(
        self, state: OwnedStatePort, facts_resource: str, owner: str,
        identity: lc.PolicyIdentity,
    ) -> None:
        self._state = state
        self._facts_resource = c.text(facts_resource)
        self._owner = c.sha256(owner)
        self._identity = identity
        self._mutex = threading.RLock()
        self._cancelled: set[tuple[str, str]] = set()

    @contextmanager
    def lock_lifecycle(self, binding: lc.LifecycleBinding) -> Iterator[object]:
        """Use one real owned root resource lock for facts, effects and pointer CAS."""
        with _lifecycle_observation_context(binding), self._mutex, self._state.lock(
            (self._facts_resource,), 0.0,
        ) as held:
            yield held

    def _read(self, resource_id: str) -> OwnedRecord:
        with _OBSERVATIONS._io("owned_read", _LOG):
            record = self._state.read(c.text(resource_id))
            if type(record) is not OwnedRecord:
                raise c.ContractError()
            record.__post_init__()
            if (
                record.resource_id != resource_id or record.kind != "checkpoint"
                or record.ownership_token != self._owner or record.policy_identity != self._identity
            ):
                raise c.ContractError()
            return record

    def _write(self, resource: str, expected: int, record: OwnedRecord) -> OwnedRecord:
        with _OBSERVATIONS._io("owned_cas", _LOG):
            return self._state.compare_replace(resource, expected, record)

    def _facts(self) -> OwnedRecord:
        record = self._read(self._facts_resource)
        value = _object(record.payload, (
            "schema", "root_manifest", "generation_refs", "step_refs", "pin_refs",
            "verification_ref", "registry_digest", "qualification_digest", "context_digest",
            "setup_enabled", "cancelled", "pointer",
        ))
        if value["schema"] != _SCHEMA:
            raise c.ContractError()
        for flag in ("setup_enabled", "cancelled"):
            if type(value[flag]) is not bool:
                raise c.ContractError()
        for key in ("registry_digest", "qualification_digest", "context_digest"):
            c.sha256(value[key])
        return record

    def _generation(self, resource_id: str) -> lc.GenerationBinding:
        value = _object(self._read(resource_id).payload, (
            "generation_id", "ordinal", "content", "manifest",
        ))
        return lc.GenerationBinding(
            c.text(value["generation_id"]), c.counter(value["ordinal"]),
            hashlib.sha256(_bytes(value["content"])).hexdigest(),
            c.digest(c.public_object(value["manifest"])),
        )

    def _records(self, references: object) -> tuple[lc.FrozenObject, ...]:
        return tuple(self._read(c.text(ref)).payload for ref in _tuple(references))

    def snapshot_lifecycle(self, binding: lc.LifecycleBinding) -> LifecycleSnapshot:
        """Re-read current owner, generation bytes, pins, probe and pointer facts."""
        with self.lock_lifecycle(binding):
            # A corrupt/missing root cannot be adopted. Once the exact root is
            # known, failed observations block admission but must not prevent a
            # previously entered factual completion advancing its checkpoint.
            root = self._facts()
            try:
                return self._snapshot(binding)
            except (c.ContractError, ArtifactError, OSError, KeyError):
                return LifecycleSnapshot(
                    binding, root.revision,
                    root.payload["cancelled"] is True
                    or (binding.kind, binding.plan_id) in self._cancelled,
                    root.payload["setup_enabled"] is True, False, False, False, None,
                )

    def _snapshot(self, binding: lc.LifecycleBinding) -> LifecycleSnapshot:
        record = self._facts()
        data = record.payload
        generations = tuple(self._generation(c.text(ref)) for ref in _tuple(data["generation_refs"]))
        c.unique(tuple(item.generation_id for item in generations))
        steps = tuple(_object(value, (
            "occurrence_id", "generation_id", "source", "destination", "reuse", "consequential",
        )) for value in self._records(data["step_refs"]))
        for step in steps:
            for name in ("source", "reuse"):
                source = step[name]
                if source is not None:
                    observed = _object(source, (
                        ("source_id", "registry_digest", "artifact_digest", "descriptor_digest")
                        if name == "source" else
                        ("kind", "resource_id", "generation_id", "content_digest", "manifest_digest")
                    ))
                    source_id = c.text(
                        observed["source_id"] if name == "source" else observed["resource_id"],
                    )
                    expected = c.sha256(
                        observed["artifact_digest"] if name == "source"
                        else observed["content_digest"],
                    )
                    if hashlib.sha256(self.artifact(source_id)).hexdigest() != expected:
                        raise c.ContractError()
                    source_record = self._read(source_id)
                    if c.digest(c.public_object(source_record.payload["manifest"])) != (
                        observed["descriptor_digest"] if name == "source"
                        else observed["manifest_digest"]
                    ):
                        raise c.ContractError()
            destination = step["destination"]
            if destination is not None:
                descriptor = _object(destination, (
                    "resource_id", "root_resource_id", "segments", "manifest_digest",
                ))
                owned = self._read(c.text(descriptor["resource_id"]))
                if "manifest" not in owned.payload:
                    raise c.ContractError()
                if c.digest(c.public_object(owned.payload["manifest"])) != descriptor["manifest_digest"]:
                    raise c.ContractError()
        pins = self._records(data["pin_refs"])
        verification_ref = data["verification_ref"]
        verification = None if verification_ref is None else _object(
            self._read(c.text(verification_ref)).payload, (
                "kind", "event_kind", "event_id", "revision", "generation_id", "content_digest",
                "manifest_digest", "context_digest", "registry_digest", "policy_digest",
                "qualification_digest", "observed_at", "expires_at", "probes",
            ),
        )
        root = lc.OwnedRootBinding(
            self._facts_resource, c.digest(c.public_object(data["root_manifest"])),
        )
        observed_generation = next(
            (item for item in generations if item.generation_id == binding.generation.generation_id),
            None,
        )
        if observed_generation is None:
            raise c.ContractError()
        selected = tuple(
            item for wanted in binding.generation.selected for item in generations
            if item.generation_id == wanted.generation_id
        )
        generation = replace(observed_generation, selected=selected)
        if verification is not None:
            for value in _tuple(verification["probes"]):
                probe = _object(value, (
                    "probe_id", "generation_id", "content_digest", "context_digest",
                    "result_digest", "status",
                ))
                if (
                    probe["probe_id"] != "inert-byte-probe" or probe["status"] != "succeeded"
                    or probe["result_digest"] != observed_generation.content_digest
                ):
                    raise c.ContractError()
        content = c.public_object({
            "schema": "1.0", "steps": steps, "pins": pins, "verification": verification,
            "cancel_scope": tuple(c.text(step["occurrence_id"]) for step in steps),
        })
        current = replace(
            binding, root=root, generation=generation, expected_pointer=_pointer(data["pointer"]),
            context_digest=c.sha256(data["context_digest"]),
            registry_digest=c.sha256(data["registry_digest"]),
            qualification_digest=c.sha256(data["qualification_digest"]),
            policy=record.policy_identity, content=content,
        )
        evidence = LifecycleEvidence(root, generations, steps, pins, verification)
        return LifecycleSnapshot(
            current, record.revision,
            data["cancelled"] is True or (binding.kind, binding.plan_id) in self._cancelled,
            data["setup_enabled"] is True, True, True, True, evidence,
        )

    def compare_lifecycle_revision(
        self, binding: lc.LifecycleBinding, expected: int, following: int,
    ) -> bool:
        """Advance the actual owned revision without changing observed facts."""
        c.counter(expected)
        c.counter(following)
        record = self._facts()
        if record.revision != expected or expected == lc.MAX_SAFE_INT or following != expected + 1:
            return False
        self._write(
            self._facts_resource, expected, replace(record, revision=following),
        )
        return True

    def compare_replace_lifecycle(
        self, binding: lc.LifecycleBinding, expected: lc.PointerExpectation,
        following_revision: int,
    ) -> bool:
        """CAS the exact reviewed pointer; no catch-and-adopt or reverse CAS."""
        record = self._facts()
        c.counter(following_revision)
        if (
            _pointer(record.payload["pointer"]) != expected or expected.revision == lc.MAX_SAFE_INT
            or following_revision != expected.revision + 1
            or record.revision == lc.MAX_SAFE_INT
        ):
            return False
        pointer = lc.PresentPointer(
            "present", binding.generation.generation_id,
            c.digest((binding.generation, following_revision)), following_revision,
        )
        data = dict(record.payload.items())
        data["pointer"] = c.public_object(c.wire(pointer))
        self._write(
            self._facts_resource, record.revision,
            replace(record, revision=record.revision + 1, payload=c.public_object(data)),
        )
        return True

    def cancel(self, binding: lc.LifecycleBinding) -> None:
        """Retain local cancellation even when persistent revisions are exhausted."""
        with self._mutex:
            self._cancelled.add((binding.kind, binding.plan_id))

    def pointer(self) -> lc.PointerExpectation:
        """Read the actual pointer after a lost acknowledgement, without any grant."""
        with self._mutex, self._state.lock((self._facts_resource,), 0.0):
            return _pointer(self._facts().payload["pointer"])

    @staticmethod
    def _receipt_resource(binding: lc.LifecycleEffectBinding) -> str:
        return "lifecycle-receipt-" + c.digest(binding)

    def begin_receipt(self, binding: lc.LifecycleEffectBinding) -> None:
        """Persist pending factual entry, never a serializable invocation permission."""
        resource = self._receipt_resource(binding)
        record = OwnedRecord(
            resource, "checkpoint", 0, binding.lifecycle.generation.ordinal,
            self._owner, self._identity.bundle_sha256, self._identity.reducer_version,
            c.public_object({
                "schema": _SCHEMA, "binding_digest": c.digest(binding),
                "kind": binding.lifecycle.kind, "plan_id": binding.lifecycle.plan_id,
                "event_id": binding.event_id, "occurrence_id": binding.occurrence_id,
                "phase": "pending", "result": None,
            }), self._identity,
        )
        self._write(resource, 0, record)

    def finish_receipt(self, receipt: LifecycleHandlerReceipt) -> None:
        """Persist the returned fact before acknowledging it to the private broker."""
        resource = self._receipt_resource(receipt.binding)
        record = self._read(resource)
        payload = dict(record.payload.items())
        if (
            payload["binding_digest"] != c.digest(receipt.binding)
            or payload["phase"] != "pending" or record.revision != 0
        ):
            raise c.ContractError()
        payload["phase"] = "observed"
        payload["result"] = c.public_object({
            "kind": receipt.kind, "result_digest": receipt.result_digest,
            "changed": receipt.changed, "pointer": receipt.pointer,
        })
        self._write(
            resource, record.revision,
            replace(record, revision=1, payload=c.public_object(payload)),
        )

    def inspect_receipt(self, binding: lc.LifecycleEffectBinding) -> lc.FrozenObject:
        """Read factual crash evidence; pending means uncertain, never auto-replay."""
        record = self._read(self._receipt_resource(binding))
        value = _object(record.payload, (
            "schema", "binding_digest", "kind", "plan_id", "event_id", "occurrence_id",
            "phase", "result",
        ))
        if (
            value["schema"] != _SCHEMA or value["binding_digest"] != c.digest(binding)
            or value["kind"] != binding.lifecycle.kind or value["plan_id"] != binding.lifecycle.plan_id
            or value["event_id"] != binding.event_id or value["occurrence_id"] != binding.occurrence_id
            or value["phase"] not in ("pending", "observed")
        ):
            raise c.ContractError()
        if value["phase"] == "pending":
            if record.revision != 0 or value["result"] is not None:
                raise c.ContractError()
        else:
            result = _object(value["result"], ("kind", "result_digest", "changed", "pointer"))
            effect = next(
                item for item in binding.lifecycle.effects
                if item.occurrence_id == binding.occurrence_id
            )
            c.sha256(result["result_digest"])
            if record.revision != 1 or result["kind"] != effect.kind or type(result["changed"]) is not bool:
                raise c.ContractError()
            pointer = result["pointer"]
            if effect.kind in ("dependency-activate", "restore-active-pointer"):
                values = _tuple(pointer)
                if len(values) != 2 or values[0] != binding.lifecycle.generation.generation_id:
                    raise c.ContractError()
                if c.counter(values[1]) != binding.lifecycle.expected_pointer.revision + 1:
                    raise c.ContractError()
            elif pointer is not None:
                raise c.ContractError()
        return value

    def artifact(self, resource_id: str) -> bytes:
        """Read a bounded inert artifact and verify its actual bytes."""
        value = _object(self._read(resource_id).payload, (
            "schema", "content", "content_digest", "manifest",
        ))
        if value["schema"] != _SCHEMA:
            raise c.ContractError()
        content = _bytes(value["content"])
        if hashlib.sha256(content).hexdigest() != c.sha256(value["content_digest"]):
            raise c.ContractError()
        return content

    def copy_artifact(self, source: str, destination: str, expected_digest: str) -> str:
        """Copy only pre-owned inert bytes to an explicitly reserved owned record."""
        content = self.artifact(source)
        digest = hashlib.sha256(content).hexdigest()
        if digest != c.sha256(expected_digest):
            raise c.ContractError()
        current = self._read(destination)
        reserved = _object(current.payload, ("schema", "reserved", "manifest"))
        if reserved["schema"] != _SCHEMA or reserved["reserved"] is not True:
            raise c.ContractError()
        if current.revision == lc.MAX_SAFE_INT:
            raise AuthorizationError(numeric=True)
        self._write(destination, current.revision, replace(
            current, revision=current.revision + 1, payload=c.public_object({
                "schema": _SCHEMA, "content": tuple(content), "content_digest": digest,
                "manifest": reserved["manifest"],
            }),
        ))
        return digest

    def remove_artifact(self, destination: str, expected_manifest: str) -> str:
        """Tombstone only the exact owned inert resource, never delete an OS path."""
        current = self._read(destination)
        _object(current.payload, ("schema", "content", "content_digest", "manifest"))
        self.artifact(destination)
        digest = c.digest(c.public_object(current.payload["manifest"]))
        if digest != c.sha256(expected_manifest):
            raise c.ContractError()
        if current.revision == lc.MAX_SAFE_INT:
            raise AuthorizationError(numeric=True)
        self._write(destination, current.revision, replace(
            current, revision=current.revision + 1,
            payload=c.public_object({
                "schema": _SCHEMA, "removed_digest": digest, "manifest": current.payload["manifest"],
            }),
        ))
        return digest


class LifecycleExecutor:
    """Fixed typed handler owner, never a generic callback or policy authority.

    This is A02's host-owned typed lifecycle entry: bootstrap supplies the real
    broker, owned-state reader and clock; ``execute`` takes a concrete lifecycle
    plan and its private lifecycle authorization. It is not a WorkflowService
    operation or DependencyService provisioning implementation. Neither frozen
    service constructor changes to discover or construct this owner.

    The broker must already be composed with this exact ``state`` instance and
    its trusted lifecycle consent adapter. Only ``issue_lifecycle`` can create
    the authorization accepted here. No journal or caller boolean can do so.
    """

    def __init__(
        self, authorization: AuthorizationBroker, state: OwnedLifecycleState, clock: c.ClockPort,
    ) -> None:
        if type(authorization) is not AuthorizationBroker or type(state) is not OwnedLifecycleState:
            raise c.ContractError()
        if authorization._lifecycle_state is not state:
            raise c.ContractError()
        self.authorization = authorization
        self._state = state
        self._clock = clock
        self._receipts: dict[lc.LifecycleEffectPermit, LifecycleHandlerReceipt] = {}
        self._pending: dict[lc.LifecycleEffectPermit, lc.LifecycleEffectBinding] = {}
        self._completed: set[lc.LifecycleEffectPermit] = set()
        self._lock = threading.RLock()

    def _now(self, binding: lc.LifecycleBinding) -> float:
        try:
            return self._clock.monotonic()
        except BaseException:
            self.authorization.revoke_lifecycle(binding.kind, binding.plan_id)
            raise

    def cancel(self, plan: lc.LifecyclePlan) -> None:
        """Revoke private eligibility first, independently of clocks and revision space."""
        binding = bind_lifecycle(plan)
        self.authorization.revoke_lifecycle(binding.kind, binding.plan_id)
        self._state.cancel(binding)

    def _step(self, binding: lc.LifecycleEffectBinding) -> tuple[
        lc.LifecycleEffectOccurrence, lc.FrozenObject,
    ]:
        for effect, step in zip(binding.lifecycle.effects, _tuple(binding.lifecycle.content["steps"])):
            if effect.occurrence_id == binding.occurrence_id:
                return effect, c.public_object(step)
        raise c.ContractError()

    def enter(
        self, permit: lc.LifecycleEffectPermit, binding: lc.LifecycleEffectBinding,
    ) -> LifecycleHandlerReceipt:
        """Enter exactly one fixed symbol after actual private broker validation."""
        # Broker lock precedes state lock. Never call it from an owned-state lock.
        with self._lock:
            actual = self.authorization.reconcile_lifecycle(permit)
            if type(binding) is not lc.LifecycleEffectBinding or actual != binding:
                raise AuthorizationError()
            with _lifecycle_observation_context(actual.lifecycle, actual.occurrence_id):
                return self._enter(permit, binding)

    def _enter(
        self, permit: lc.LifecycleEffectPermit, binding: lc.LifecycleEffectBinding,
    ) -> LifecycleHandlerReceipt:
        with self._lock:
            self.authorization.enter_lifecycle(permit, binding, self._now(binding.lifecycle))
            self._pending[permit] = binding
            effect, step = self._step(binding)
            _record_lifecycle_handler("started", effect.kind, _LOG)
            try:
                self._state.begin_receipt(binding)
                if effect.kind in ("dependency-activate", "restore-active-pointer"):
                    self.authorization.replace_lifecycle_pointer(permit, self._now(binding.lifecycle))
                    pointer = self.authorization.reconcile_lifecycle_pointer(permit)
                    receipt = LifecycleHandlerReceipt(
                        binding, effect.kind, c.digest(pointer), True, pointer,
                    )
                else:
                    with self._state.lock_lifecycle(binding.lifecycle):
                        snapshot = self._state.snapshot_lifecycle(binding.lifecycle)
                        if snapshot.binding != binding.lifecycle or snapshot.cancelled:
                            raise AuthorizationError()
                        validate_current(
                            binding.lifecycle, snapshot.evidence, c.finite(self._now(binding.lifecycle)),
                        )
                        digest, changed = self._dispatch(effect, step, binding.lifecycle)
                    receipt = LifecycleHandlerReceipt(binding, effect.kind, digest, changed)
                self._receipts[permit] = receipt
                self._state.finish_receipt(receipt)
                _record_lifecycle_handler("succeeded", effect.kind, _LOG)
                return receipt
            except BaseException:
                self.authorization.revoke_lifecycle(binding.lifecycle.kind, binding.lifecycle.plan_id)
                _record_lifecycle_handler("failed", effect.kind, _LOG)
                raise

    def _dispatch(
        self, effect: lc.LifecycleEffectOccurrence, step: lc.FrozenObject,
        binding: lc.LifecycleBinding,
    ) -> tuple[str, bool]:
        if effect.kind == "dependency-probe":
            observed = self._state.snapshot_lifecycle(binding)
            return c.digest(observed.evidence), False
        if effect.kind in ("dependency-download", "dependency-stage"):
            source = c.public_object(step["source"] if step["source"] is not None else step["reuse"])
            source_id = c.text(source["source_id"] if "source_id" in source else source["resource_id"])
            expected = c.sha256(
                source["artifact_digest"] if "artifact_digest" in source else source["content_digest"],
            )
            return self._state.copy_artifact(source_id, effect.resource_id, expected), True
        if effect.kind == "dependency-verify":
            content = self._state.artifact(effect.resource_id)
            digest = hashlib.sha256(content).hexdigest()
            if digest != binding.generation.content_digest:
                raise c.ContractError()
            return digest, False
        if effect.kind == "dependency-uninstall":
            destination = c.public_object(step["destination"])
            return self._state.remove_artifact(
                effect.resource_id, c.sha256(destination["manifest_digest"]),
            ), True
        raise c.ContractError()

    def complete(self, permit: lc.LifecycleEffectPermit) -> LifecycleHandlerReceipt:
        """Acknowledge a returned fact once, including after cancellation or expiry."""
        with self._lock:
            self.authorization.reconcile_lifecycle(permit)
            receipt = self._receipts.get(permit)
            if receipt is None or permit in self._completed:
                raise AuthorizationError()
            with _lifecycle_observation_context(
                receipt.binding.lifecycle, receipt.binding.occurrence_id,
            ):
                return self._complete(permit, receipt)

    def _complete(
        self, permit: lc.LifecycleEffectPermit, receipt: LifecycleHandlerReceipt,
    ) -> LifecycleHandlerReceipt:
        with self._lock:
            if self._state.inspect_receipt(receipt.binding)["phase"] == "pending":
                self._state.finish_receipt(receipt)
            revision = self._state.snapshot_lifecycle(receipt.binding.lifecycle).revision
            self.authorization.complete_lifecycle(
                permit, str(uuid4()), revision, self._now(receipt.binding.lifecycle),
            )
            self._completed.add(permit)
            return receipt

    def reconcile(self, permit: lc.LifecycleEffectPermit) -> LifecycleHandlerReceipt | None:
        """Inspect pending factual work without re-entering or restoring any eligibility."""
        with self._lock:
            self.authorization.reconcile_lifecycle(permit)
            return self._receipts.get(permit)

    def execute(
        self, plan: lc.LifecyclePlan, authorization: lc.LifecycleAuthorization,
    ) -> LifecycleRunResult:
        """Consume once and execute ordered typed occurrences with current CAS."""
        binding = bind_lifecycle(plan)
        with _lifecycle_observation_context(binding):
            return self._execute(binding, authorization)

    def _execute(
        self, binding: lc.LifecycleBinding, authorization: lc.LifecycleAuthorization,
    ) -> LifecycleRunResult:
        session = self.authorization.consume_lifecycle(authorization, binding, self._now(binding))
        receipts: list[LifecycleHandlerReceipt] = []
        pending: list[lc.LifecycleEffectBinding] = []
        for effect in binding.effects:
            permit: lc.LifecycleEffectPermit | None = None
            effect_binding: lc.LifecycleEffectBinding | None = None
            try:
                current = self._state.snapshot_lifecycle(binding)
                effect_binding = lc.LifecycleEffectBinding(
                    binding, str(uuid4()), current.revision, effect.occurrence_id,
                )
                permit = self.authorization.permit_lifecycle(
                    session, effect_binding, self._now(binding),
                )
                receipt = self.enter(permit, effect_binding)
                receipts.append(receipt)
                self.complete(permit)
            except (ValueError, RuntimeError, OSError):
                self.authorization.revoke_lifecycle(binding.kind, binding.plan_id)
                factual = self._receipts.get(permit) if permit is not None else None
                if factual is not None and factual not in receipts:
                    receipts.append(factual)
                if permit is not None and effect_binding is not None:
                    pending.append(effect_binding)
                return LifecycleRunResult(
                    tuple(receipts), tuple(pending), False,
                    permit is not None and permit in self._pending and factual is None,
                )
        return LifecycleRunResult(tuple(receipts), (), True, False)
