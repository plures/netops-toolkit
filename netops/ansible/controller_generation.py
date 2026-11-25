"""Private managed-generation pins around installed proof and owned dispatch."""

from __future__ import annotations

import threading
from dataclasses import replace

from netops.dependencies.runs import OwnedGenerationRuns

from . import contracts as c
from .artifacts import OwnedStatePort
from .controller import ControllerInstallation, FixedLaunch, ProcessPort, ProcessResult
from .controller_control import _Stop
from .controller_installation import _ManagedInstallationVerifier
from .controller_protocol import ProtocolError
from .lifecycle_execution import _pointer
from .policy import contracts as lc

_PIN_REF = "owned-generation-run-pin"
_PIN_GUIDANCE = "Preserve the exact installed generation until owned join and pin release are proved."


def _pin_failure(cleanup: c.CleanupOutcome) -> c.CleanupOutcome:
    return c.CleanupOutcome(
        "failed", tuple(dict.fromkeys((*cleanup.remaining_refs, _PIN_REF))),
        cleanup.errors + (c.SafeError(
            c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
            next_action=_PIN_GUIDANCE,
        ),),
    )


class _PinLifetime:
    """Callbacks describe actual completion, never elapsed-holder expiration."""

    def __init__(self, stop: _Stop | None = None) -> None:
        self._stop = stop
        self._cancelled = threading.Event()
        self._finished = threading.Event()
        self._joined = False

    def cancel(self) -> None:
        self._cancelled.set()
        if self._stop is not None:
            self._stop.stop(c.ReasonCode.CANCELLED)

    def join(self, remaining: float) -> bool:
        remaining = c.finite(remaining)
        return remaining > 0 and self._finished.wait(remaining) and self._joined

    def check(self) -> None:
        if self._cancelled.is_set():
            raise ProtocolError(c.ReasonCode.CANCELLED)


class _PinnedControllerProcesses:
    """Consume the same immutable I02 root/control and host-owned run registry.

    Construction is read-only. Pins must already exist from reviewed I02
    registration. This adapter does not initialize pins, adopt a directory,
    expire a crashed holder, qualify a tuple or reconstruct dispatch authority.
    """

    def __init__(
        self, processes: ProcessPort, verifier: _ManagedInstallationVerifier,
        state: OwnedStatePort, runs: OwnedGenerationRuns | None = None,
    ) -> None:
        self._processes, self._verifier, self._state = processes, verifier, state
        generations = self._registered()
        if runs is None:
            runs = OwnedGenerationRuns(
                state, verifier._root_resource, verifier._active, verifier._owner,
                verifier._descriptor.context.context.policy_identity,
                generations, verifier._generation.generation_id,
            )
        if (
            type(runs) is not OwnedGenerationRuns or runs.state is not state
            or runs.root_resource != verifier._root_resource
            or runs.control_resource != verifier._active or runs.owner != verifier._owner
            or runs.identity != verifier._descriptor.context.context.policy_identity
            or runs.generations != generations
            or runs.selected_id not in tuple(item.generation_id for item in generations)
        ):
            raise c.ContractError()
        self.runs = runs

    def _registered(self) -> tuple[lc.GenerationBinding, ...]:
        verifier = self._verifier
        record = self._state.read(verifier._root_resource)
        record.__post_init__()
        if (
            record.kind != "checkpoint" or record.ownership_token != verifier._owner
            or record.policy_identity != verifier._descriptor.context.context.policy_identity
            or record.payload.get("schema") != "i02-managed-generations-v1"
        ):
            raise ProtocolError()
        root = c.public_object(record.payload["root_manifest"])
        registered = root["registered_manifests"]
        if (
            root["control_resource"] != verifier._active or type(registered) is not tuple
            or c.public_object(c.wire(verifier._descriptor)) not in registered
        ):
            raise ProtocolError()
        generations = []
        for value in registered:
            manifest = c.public_object(value)
            members = manifest["members"]
            if type(members) is not tuple or not members:
                raise ProtocolError()
            ordered = tuple(sorted(
                (c.public_object(member) for member in members),
                key=lambda member: c.text(member["path"]),
            ))
            generations.append(lc.GenerationBinding(
                c.uuid_text(manifest["generation_id"]), 0, c.digest(ordered), c.digest(manifest),
            ))
        c.unique(tuple(generation.generation_id for generation in generations))
        if verifier._generation not in generations:
            raise ProtocolError()
        return tuple(generations)

    def _acquire(self, lifetime: _PinLifetime) -> object:
        verifier = self._verifier
        with self._state.lock((verifier._root_resource,), 0.0):
            if self._registered() != self.runs.generations:
                raise ProtocolError(c.ReasonCode.CONSENT_STALE)
            control = self._state.read(verifier._active)
            control.__post_init__()
            if (
                control.kind != "checkpoint" or control.ownership_token != self.runs.owner
                or control.policy_identity != self.runs.identity
                or control.payload.get("schema") != "i02-managed-control-v1"
                or control.payload.get("setup_enabled") is not True
                or control.payload.get("admission_enabled", True) is not True
            ):
                raise ProtocolError(c.ReasonCode.CONSENT_STALE)
            pointer = _pointer(control.payload["pointer"])
            if (
                type(pointer) is not lc.PresentPointer
                or pointer.active_generation_id != verifier._generation.generation_id
                or pointer.pointer_digest != c.digest((verifier._generation, pointer.revision))
            ):
                raise ProtocolError(c.ReasonCode.CONSENT_STALE)
            return self.runs.acquire(verifier._generation, lifetime.cancel, lifetime.join)

    def verify(
        self, context: c.ControllerContext, state: OwnedStatePort,
    ) -> ControllerInstallation | None:
        """Pin before byte/qualification observation; proof cannot select another root."""
        if state is not self._state or context != c.ControllerContext(self._verifier._descriptor.context.context):
            raise ProtocolError()
        lifetime = _PinLifetime()
        pin = self._acquire(lifetime)
        try:
            _, installed_digest = self._verifier._selection(context, state)
            installation = self._processes.verify(context, state)
            lifetime.check()
            if installation is not None and installation.installation_digest != installed_digest:
                raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
            return installation
        finally:
            # Verification creates no process. An interrupted/failed read
            # still completes this exact observation; it grants no readiness.
            lifetime._joined = True
            try:
                self.runs.release(pin)
            finally:
                lifetime._finished.set()

    def run(self, launch: FixedLaunch, private_input: bytes, cancel: c.CancelPort) -> ProcessResult:
        """Retain the pin through actual verified group/pipe teardown, even after revoke."""
        if type(cancel) is not _Stop or type(launch) is not FixedLaunch:
            raise ProtocolError()
        lifetime = _PinLifetime(cancel)
        pin = self._acquire(lifetime)
        result: ProcessResult | None = None
        dispatched = False
        try:
            # The transient readiness observation is not sufficient: pointer,
            # bytes and exact qualification are rechecked under this live pin
            # immediately before the fixed adapter can create a process.
            context = c.ControllerContext(launch.request.request.context)
            _, installed_digest = self._verifier._selection(context, self._state)
            installation = self._processes.verify(context, self._state)
            lifetime.check()
            if (
                installation != launch.installation or installation is None
                or installation.installation_digest != installed_digest
            ):
                raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
            launch.control.check()
            dispatched = True
            result = self._processes.run(launch, private_input, cancel)
            if type(result) is not ProcessResult:
                raise ProtocolError()
            lifetime._joined = (
                result.cleanup.status == "succeeded"
                and not result.cleanup.remaining_refs and not result.cleanup.errors
            )
        except Exception as error:
            result = ProcessResult(
                (), 1, c.CleanupOutcome("succeeded") if not dispatched else c.CleanupOutcome(),
                c.SafeError(
                    c.ErrorCategory.EXECUTION,
                    error.reason if type(error) is ProtocolError else c.ReasonCode.CONTROL_LOST,
                    c.Stage.CONTROLLER, next_action=_PIN_GUIDANCE,
                ),
            )
        finally:
            # Unknown completion after entering the adapter is never proof of
            # teardown. It leaves the holder durable for explicit recovery.
            if not dispatched:
                lifetime._joined = True
            if lifetime._joined:
                try:
                    self.runs.release(pin)
                except BaseException:
                    if result is not None:
                        result = replace(result, cleanup=_pin_failure(result.cleanup))
                finally:
                    lifetime._finished.set()
            else:
                lifetime._finished.set()
        assert result is not None
        if not lifetime._joined:
            result = replace(result, cleanup=_pin_failure(result.cleanup))
        return result
