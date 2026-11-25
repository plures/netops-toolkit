"""Durable owned generation pins shared by setup and the consuming run host."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import replace
from uuid import uuid4

from netops.ansible import contracts as c
from netops.ansible.artifacts import OwnedRecord, OwnedStatePort
from netops.ansible.lifecycle_execution import _pointer
from netops.ansible.policy import contracts as lc

__all__ = ["OwnedGenerationRuns"]


class _Pin:
    def __init__(self, generation: lc.GenerationBinding, holder: str, host: object) -> None:
        self.generation, self.holder = generation, holder
        self.host = host
        self.release_revision: int | None = None


class OwnedGenerationRuns:
    """Pin exact active generations; crash-held pins block rather than being expired."""

    def __init__(
        self, state: OwnedStatePort, root_resource: str, control_resource: str,
        owner: str, identity: lc.PolicyIdentity, generations: tuple[lc.GenerationBinding, ...],
        selected_id: str,
    ) -> None:
        self.state, self.root_resource, self.control_resource = state, root_resource, control_resource
        self.owner, self.identity, self.generations = c.sha256(owner), identity, generations
        self.selected_id = c.uuid_text(selected_id)
        c.unique(tuple(generation.generation_id for generation in generations))
        self._mutex = threading.RLock()
        self._host = object()
        self._live: dict[_Pin, tuple[Callable[[], None], Callable[[float], bool]]] = {}

    def _record(self, resource: str) -> OwnedRecord:
        record = self.state.read(resource)
        if record.ownership_token != self.owner or record.policy_identity != self.identity:
            raise c.ContractError()
        return record

    @staticmethod
    def _resource(generation: lc.GenerationBinding) -> str:
        return "dependency-run-pin-" + c.digest(generation)

    def _active(self, control: OwnedRecord, generation: lc.GenerationBinding) -> None:
        """Validate the complete typed pointer against its exact generation binding."""
        pointer = _pointer(control.payload["pointer"])
        if (
            type(pointer) is not lc.PresentPointer or generation not in self.generations
            or pointer.active_generation_id != generation.generation_id
            or pointer.pointer_digest != c.digest((generation, pointer.revision))
        ):
            raise c.ContractError()

    def initialize(self) -> None:
        """Create only missing empty pins during explicitly reviewed bootstrap registration."""
        with self.state.lock((self.root_resource,), 0.0):
            template = self._record(self.root_resource)
            for generation in self.generations:
                resource = self._resource(generation)
                try:
                    current = self._record(resource)
                except FileNotFoundError:
                    payload = c.public_object({
                        "generation_id": generation.generation_id,
                        "manifest_digest": generation.manifest_digest, "revision": 0, "holders": (),
                    })
                    self.state.compare_replace(resource, 0, replace(
                        template, resource_id=resource, revision=0, payload=payload,
                    ))
                else:
                    self._validate(current, generation)

    @staticmethod
    def _validate(record: OwnedRecord, generation: lc.GenerationBinding) -> None:
        data = record.payload
        if set(data) != {"generation_id", "manifest_digest", "revision", "holders"} or (
            data["generation_id"] != generation.generation_id
            or data["manifest_digest"] != generation.manifest_digest
            or data["revision"] != record.revision or type(data["holders"]) is not tuple
        ):
            raise c.ContractError()
        for holder in data["holders"]:
            c.uuid_text(holder)
        c.unique(data["holders"])

    def pins(self) -> tuple[lc.FrozenObject, ...]:
        """Read durable target/current pins; unknown or corrupt records are never empty."""
        with self.state.lock((self.root_resource,), 0.0), self._mutex:
            control = self._record(self.control_resource)
            pointer = _pointer(control.payload["pointer"])
            identifiers: tuple[str, ...] = (self.selected_id,)
            if type(pointer) is lc.PresentPointer and pointer.active_generation_id != self.selected_id:
                identifiers += (c.uuid_text(pointer.active_generation_id),)
            result = []
            for identifier in identifiers:
                generation = next((item for item in self.generations if item.generation_id == identifier), None)
                if generation is None:
                    raise c.ContractError()
                record = self._record(self._resource(generation))
                self._validate(record, generation)
                result.append(record.payload)
            return tuple(result)

    def acquire(
        self, generation: lc.GenerationBinding, cancel: Callable[[], None],
        join: Callable[[float], bool],
    ) -> object:
        """Retain a private run pin before dispatch, using recovery-preserving cancel/join ports."""
        with self.state.lock((self.root_resource,), 0.0), self._mutex:
            self._record(self.root_resource)
            control = self._record(self.control_resource)
            self._active(control, generation)
            if (
                control.payload.get("admission_enabled", True) is not True
                or control.payload["setup_enabled"] is not True
            ):
                raise c.ContractError()
            resource = self._resource(generation)
            record = self._record(resource)
            self._validate(record, generation)
            holders = record.payload["holders"]
            assert type(holders) is tuple
            pin = _Pin(generation, str(uuid4()), self._host)
            following = record.revision + 1
            self.state.compare_replace(resource, record.revision, replace(
                record, revision=following, payload=c.public_object({
                    **dict(record.payload), "revision": following, "holders": (*holders, pin.holder),
                }),
            ))
            self._live[pin] = (cancel, join)
            return pin

    def release(self, pin: object) -> None:
        """Release only a private pin held by this exact host; never sweep crash-held siblings."""
        with self.state.lock((self.root_resource,), 0.0), self._mutex:
            if type(pin) is not _Pin or pin.host is not self._host or pin not in self._live:
                raise c.ContractError()
            self._release_locked(pin)

    def _release_locked(self, pin: _Pin) -> None:
        resource = self._resource(pin.generation)
        record = self._record(resource)
        self._validate(record, pin.generation)
        holders = record.payload["holders"]
        if type(holders) is not tuple or pin.holder not in holders:
            raise c.ContractError()
        following = record.revision + 1
        self.state.compare_replace(resource, record.revision, replace(
            record, revision=following, payload=c.public_object({
                **dict(record.payload), "revision": following,
                "holders": tuple(holder for holder in holders if holder != pin.holder),
            }),
        ))
        pin.release_revision = following
        del self._live[pin]

    def _joined(self, pin: _Pin) -> None:
        """Recognize only this snapshot pin's successful same-host durable release."""
        with self.state.lock((self.root_resource,), 0.0), self._mutex:
            if pin.host is not self._host:
                raise c.ContractError()
            if pin in self._live:
                self._release_locked(pin)
                return
            record = self._record(self._resource(pin.generation))
            self._validate(record, pin.generation)
            holders = record.payload["holders"]
            assert type(holders) is tuple
            if (
                pin.release_revision is None or record.revision < pin.release_revision
                or pin.holder in holders
            ):
                raise c.ContractError()

    def stop_admission(self) -> None:
        """Close the same durable admission flag used by pointer writers and new run pins."""
        self._admission(False)

    def _admission(self, enabled: bool) -> None:
        with self.state.lock((self.root_resource,), 0.0):
            record = self._record(self.control_resource)
            if record.payload.get("admission_enabled", True) == enabled:
                return
            self.state.compare_replace(self.control_resource, record.revision, replace(
                record, revision=record.revision + 1,
                payload=c.public_object({**dict(record.payload), "admission_enabled": enabled}),
            ))

    def drain(self, cancel: c.CancelPort, clock: c.ClockPort, deadline: float) -> bool:
        """Join only owned runs outside all root/broker locks, preserving approved recovery."""
        c.finite(deadline)
        with self._mutex:
            live = tuple(self._live.items())
        for _, (request_cancel, _) in live:
            request_cancel()
        for pin, (_, join) in live:
            remaining = deadline - c.finite(clock.monotonic())
            if remaining <= 0 or cancel.is_cancelled() or not join(remaining):
                return False
            self._joined(pin)
        # A different process/crashed host has no join capability here. Its
        # persisted holder is a real blocker, not permission to steal a pin.
        return all(pin["holders"] == () for pin in self.pins()) and c.finite(clock.monotonic()) < deadline

    def start_admission(self, generation: lc.GenerationBinding) -> None:
        """Reopen only for the exact committed active generation after its caller's postcheck."""
        with self.state.lock((self.root_resource,), 0.0):
            self._active(self._record(self.control_resource), generation)
            self._admission(True)
