"""Closed nonsecret lifecycle descriptors and host-observed evidence validation.

The host state port collects observations; this module neither probes resources
nor turns persisted verification records into consent or executable authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import contracts as c
from . import contracts as lc

_CATEGORIES = (
    "elevation", "wsl-change", "vm-change", "reboot", "runtime-install", "security-change",
)


class EvidenceMismatch(ValueError):
    """Current host observations no longer match the reviewed descriptors."""


@dataclass(frozen=True)
class LifecycleEvidence:
    """Observed under the root lock, never supplied by a public request.

    Steps come from current registry/source/destination/reuse observations.
    Generations come from owned manifests; pins from current reference records.
    Verification comes from correlated CandidateVerified and functional probes.
    """

    root: lc.OwnedRootBinding
    generations: tuple[lc.GenerationBinding, ...]
    steps: tuple[lc.FrozenObject, ...]
    pins: tuple[lc.FrozenObject, ...]
    verification: lc.FrozenObject | None


def _object(value: object, names: tuple[str, ...]) -> lc.FrozenObject:
    if type(value) is not lc.FrozenObject:
        raise c.ContractError()
    _closed_json(value)
    if set(value) != set(names):
        raise c.ContractError()
    c.public_object(value)
    return value


def _closed_json(value: lc.FrozenObject) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    visits = 0
    while stack:
        item, depth = stack.pop()
        visits += 1
        if visits > lc.MAX_NODES or depth > lc.MAX_DEPTH:
            raise c.ContractError()
        if type(item) is lc.FrozenObject:
            if type(item.entries) is not tuple or set(vars(item)) != {"entries"}:
                raise c.ContractError()
            keys: set[str] = set()
            for pair in item.entries:
                if type(pair) is not tuple or len(pair) != 2:
                    raise c.ContractError()
                name, child = pair
                if type(name) is not str or name in keys:
                    raise c.ContractError()
                keys.add(name)
                stack.append((child, depth + 1))
        elif type(item) is tuple:
            stack.extend((child, depth + 1) for child in item)
        elif item is not None and type(item) not in (str, bool, int, float):
            raise c.ContractError()


def _items(value: object) -> tuple[lc.Json, ...]:
    if type(value) is not tuple:
        raise c.ContractError()
    return value


def _text(value: object) -> str:
    c.text(value)
    if type(value) is not str:
        raise c.ContractError()
    return value


def _digest(value: object) -> str:
    c.sha256(value)
    if type(value) is not str:
        raise c.ContractError()
    return value


def _source(value: object, binding: lc.LifecycleBinding) -> None:
    record = _object(value, ("source_id", "registry_digest", "artifact_digest", "descriptor_digest"))
    _text(record["source_id"])
    for name in ("registry_digest", "artifact_digest", "descriptor_digest"):
        _digest(record[name])
    if record["registry_digest"] != binding.registry_digest:
        raise c.ContractError()


def _destination(value: object, binding: lc.LifecycleBinding, resource_id: str) -> None:
    record = _object(value, (
        "resource_id", "root_resource_id", "segments", "manifest_digest",
    ))
    _digest(record["manifest_digest"])
    if record["resource_id"] != resource_id or record["root_resource_id"] != binding.root.resource_id:
        raise c.ContractError()
    segments = _items(record["segments"])
    if not segments:
        raise c.ContractError()
    for segment in segments:
        text = _text(segment)
        if (
            text in (".", "..") or any(char in text for char in ("/", "\\", ":", "\x00"))
            or text.endswith((".", " "))
            or text.split(".")[0].upper() in (
                "CON", "PRN", "AUX", "NUL",
                *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10)),
            )
        ):
            raise c.ContractError()


def _reuse(value: object, destination: lc.Json) -> None:
    record = _object(value, (
        "kind", "resource_id", "generation_id", "content_digest", "manifest_digest",
    ))
    _text(record["resource_id"])
    _digest(record["content_digest"])
    _digest(record["manifest_digest"])
    if record["kind"] == "owned":
        _text(record["generation_id"])
    elif record["kind"] == "external":
        if record["generation_id"] is not None:
            raise c.ContractError()
    else:
        raise c.ContractError()
    if type(destination) is lc.FrozenObject and record["resource_id"] == destination["resource_id"]:
        # Reuse may read an external resource, never adopt/overwrite it.
        raise c.ContractError()


def _generation(value: lc.GenerationBinding) -> None:
    if type(value) is not lc.GenerationBinding or value.selected != ():
        raise c.ContractError()
    c.text(value.generation_id)
    c.counter(value.ordinal)
    c.sha256(value.content_digest)
    c.sha256(value.manifest_digest)


def _pins(value: object, binding: lc.LifecycleBinding) -> tuple[lc.FrozenObject, ...]:
    records: list[lc.FrozenObject] = []
    for item in _items(value):
        pin = _object(item, ("generation_id", "manifest_digest", "revision", "holders"))
        _text(pin["generation_id"])
        _digest(pin["manifest_digest"])
        c.counter(pin["revision"])
        holders = tuple(_text(holder) for holder in _items(pin["holders"]))
        c.unique(holders)
        records.append(pin)
    if binding.kind == "uninstall":
        if tuple(record["generation_id"] for record in records) != tuple(
            item.generation_id for item in binding.generation.selected
        ):
            raise c.ContractError()
        for record, generation in zip(records, binding.generation.selected):
            if record["manifest_digest"] != generation.manifest_digest or record["holders"] != ():
                raise c.ContractError()
    elif binding.kind == "restore" and records:
        expected_ids: tuple[str, ...] = (binding.generation.generation_id,)
        if type(binding.expected_pointer) is lc.PresentPointer:
            expected_ids += (binding.expected_pointer.active_generation_id,)
        if tuple(record["generation_id"] for record in records) != expected_ids:
            raise c.ContractError()
    elif records:
        raise c.ContractError()
    return tuple(records)


def _restore_pins_match(
    expected: tuple[lc.FrozenObject, ...], current: tuple[lc.FrozenObject, ...],
) -> bool:
    """Allow only factual release of reviewed holders, never newly acquired pins."""
    if len(expected) != len(current):
        return False
    for before, after in zip(expected, current):
        old_holders, new_holders = _items(before["holders"]), _items(after["holders"])
        if (
            before["generation_id"] != after["generation_id"]
            or before["manifest_digest"] != after["manifest_digest"]
            or c.counter(after["revision"]) < c.counter(before["revision"])
            or not set(new_holders).issubset(old_holders)
        ):
            return False
    return True


def _verification(value: object, binding: lc.LifecycleBinding) -> lc.FrozenObject | None:
    required = binding.kind == "restore" or any(
        effect.kind in ("dependency-activate", "restore-active-pointer") for effect in binding.effects
    )
    if value is None:
        if required:
            raise c.ContractError()
        return None
    record = _object(value, (
        "kind", "event_kind", "event_id", "revision", "generation_id", "content_digest",
        "manifest_digest", "context_digest", "registry_digest", "policy_digest",
        "qualification_digest", "observed_at", "expires_at", "probes",
    ))
    if (
        record["kind"] != ("candidate" if binding.kind == "install" else "retained")
        or record["event_kind"] != "CandidateVerified"
    ):
        raise c.ContractError()
    c.uuid_text(record["event_id"])
    c.counter(record["revision"])
    c.finite(record["observed_at"])
    c.finite(record["expires_at"])
    observed, expires = record["observed_at"], record["expires_at"]
    if type(observed) is not float or type(expires) is not float or expires <= observed:
        raise c.ContractError()
    expected = {
        "generation_id": binding.generation.generation_id,
        "content_digest": binding.generation.content_digest,
        "manifest_digest": binding.generation.manifest_digest,
        "context_digest": binding.context_digest,
        "registry_digest": binding.registry_digest,
        "policy_digest": binding.policy.bundle_sha256,
        "qualification_digest": binding.qualification_digest,
    }
    for name, wanted in expected.items():
        if record[name] != wanted:
            raise c.ContractError()
    probes = _items(record["probes"])
    if not probes:
        raise c.ContractError()
    ids: list[str] = []
    for value in probes:
        probe = _object(value, (
            "probe_id", "generation_id", "content_digest", "context_digest", "result_digest", "status",
        ))
        ids.append(_text(probe["probe_id"]))
        _digest(probe["result_digest"])
        if probe["status"] != "succeeded" or any(
            probe[name] != expected[name] for name in (
                "generation_id", "content_digest", "context_digest",
            )
        ):
            raise c.ContractError()
    c.unique(tuple(ids))
    return record


def lifecycle_arguments_digest(step: lc.FrozenObject) -> str:
    """Derive the exact nonsecret arguments identity for one occurrence."""
    return c.digest(lc.FrozenObject(tuple(
        (name, value) for name, value in step.items() if name != "occurrence_id"
    )))


def validate_content(binding: lc.LifecycleBinding) -> None:
    """Reject missing/extra or kind-inappropriate descriptors before consent."""
    content = _object(binding.content, ("schema", "steps", "verification", "pins", "cancel_scope"))
    if content["schema"] != "1.0":
        raise c.ContractError()
    steps = _items(content["steps"])
    if len(steps) != len(binding.effects):
        raise c.ContractError()
    required: dict[str, list[str]] = {}
    removals: list[str] = []
    selected_ids = tuple(item.generation_id for item in binding.generation.selected)
    for value, effect in zip(steps, binding.effects):
        step = _object(value, (
            "occurrence_id", "generation_id", "source", "destination", "reuse", "consequential",
        ))
        if (
            step["occurrence_id"] != effect.occurrence_id
            or lifecycle_arguments_digest(step) != effect.arguments_digest
        ):
            raise c.ContractError()
        generation_id = _text(step["generation_id"])
        if binding.kind == "uninstall" and effect.kind == "dependency-uninstall":
            if generation_id not in selected_ids:
                raise c.ContractError()
            removals.append(generation_id)
        elif generation_id != binding.generation.generation_id:
            raise c.ContractError()
        source, destination, reuse = step["source"], step["destination"], step["reuse"]
        if source is not None:
            _source(source, binding)
        if destination is not None:
            _destination(destination, binding, effect.resource_id)
        if reuse is not None:
            _reuse(reuse, destination)
        if effect.kind == "dependency-download":
            if source is None or destination is None or reuse is not None:
                raise c.ContractError()
        elif effect.kind == "dependency-stage":
            if destination is None or (source is None) == (reuse is None):
                raise c.ContractError()
        elif effect.kind == "dependency-verify":
            if destination is None or source is not None or reuse is not None:
                raise c.ContractError()
        elif effect.kind == "dependency-uninstall":
            if destination is None or source is not None or reuse is not None:
                raise c.ContractError()
            generation = next(item for item in binding.generation.selected
                              if item.generation_id == generation_id)
            if (
                type(destination) is not lc.FrozenObject
                or destination["manifest_digest"] != generation.manifest_digest
            ):
                raise c.ContractError()
        elif any(item is not None for item in (source, destination, reuse)):
            raise c.ContractError()
        categories = tuple(_text(item) for item in _items(step["consequential"]))
        c.unique(categories)
        for category in categories:
            if category not in _CATEGORIES:
                raise c.ContractError()
            required.setdefault(category, []).append(effect.occurrence_id)
    if {item.category: item.occurrence_ids for item in binding.required_consequential} != {
        key: tuple(value) for key, value in required.items()
    }:
        raise c.ContractError()
    if binding.kind == "uninstall":
        if not removals:
            raise c.ContractError()
        if type(binding.expected_pointer) is lc.PresentPointer and (
            binding.expected_pointer.active_generation_id in removals
        ) and (
            binding.effects[-1].kind != "restore-active-pointer"
            or binding.generation.generation_id in removals
        ):
            raise c.ContractError()
    _pins(content["pins"], binding)
    _verification(content["verification"], binding)
    if content["cancel_scope"] != tuple(effect.occurrence_id for effect in binding.effects):
        raise c.ContractError()


def validate_current(
    binding: lc.LifecycleBinding, evidence: LifecycleEvidence | None, now: float,
) -> None:
    """Compare reviewed descriptors with current host facts, not readiness flags."""
    if type(evidence) is not LifecycleEvidence:
        raise EvidenceMismatch()
    if type(evidence.root) is not lc.OwnedRootBinding:
        raise c.ContractError()
    c.text(evidence.root.resource_id)
    c.sha256(evidence.root.manifest_digest)
    if type(evidence.generations) is not tuple or type(evidence.steps) is not tuple:
        raise c.ContractError()
    if type(evidence.pins) is not tuple:
        raise c.ContractError()
    for step in evidence.steps:
        _object(step, (
            "occurrence_id", "generation_id", "source", "destination", "reuse", "consequential",
        ))
    for pin in evidence.pins:
        record = _object(pin, ("generation_id", "manifest_digest", "revision", "holders"))
        c.counter(record["revision"])
    if evidence.verification is not None:
        _object(evidence.verification, (
            "kind", "event_kind", "event_id", "revision", "generation_id", "content_digest",
            "manifest_digest", "context_digest", "registry_digest", "policy_digest",
            "qualification_digest", "observed_at", "expires_at", "probes",
        ))
    for generation in evidence.generations:
        _generation(generation)
    c.unique(tuple(item.generation_id for item in evidence.generations))
    observed = {item.generation_id: item for item in evidence.generations}
    generation = binding.generation
    needed = generation.selected if binding.kind == "uninstall" else (
        (generation,) if binding.kind == "restore" or binding.content["verification"] is not None
        else ()
    )
    if any(observed.get(item.generation_id) != item for item in needed):
        raise EvidenceMismatch()
    pins_match = (
        _restore_pins_match(_pins(binding.content["pins"], binding), evidence.pins)
        if binding.kind == "restore" else evidence.pins == binding.content["pins"]
    )
    if (
        evidence.root != binding.root or evidence.steps != binding.content["steps"]
        or not pins_match
        or evidence.verification != binding.content["verification"]
    ):
        raise EvidenceMismatch()
    _pins(evidence.pins, binding)
    _verification(evidence.verification, binding)
    for value in evidence.steps:
        step = _object(value, (
            "occurrence_id", "generation_id", "source", "destination", "reuse", "consequential",
        ))
        reuse = step["reuse"]
        if type(reuse) is lc.FrozenObject and reuse["kind"] == "owned":
            resource = observed.get(_text(reuse["generation_id"]))
            if resource is None or (
                resource.content_digest != reuse["content_digest"]
                or resource.manifest_digest != reuse["manifest_digest"]
            ):
                raise EvidenceMismatch()
    verification = evidence.verification
    if verification is not None:
        observed_at, expires_at = verification["observed_at"], verification["expires_at"]
        if (
            type(observed_at) is not float or type(expires_at) is not float
            or not observed_at <= now < expires_at
        ):
            raise EvidenceMismatch()
