"""Fixed controller launch boundary with original host deadlines and revocation.

Platform qualification is supplied by the consuming-context verifier, never
inferred from a path, version range, successful import or a passing fake.
"""

from __future__ import annotations

import hashlib
import json
import logging
import ntpath
import posixpath
import threading
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from . import contracts as c
from .artifacts import OwnedStatePort
from .controller_control import HostControllerCredentials, HostDispatchControl, _Stop
from .controller_observations import _ControllerIo
from .controller_protocol import ProtocolError, _encode_frame, _time
from .credentials import CredentialScope

_LAUNCH = "controller.launch"
_STEP = "operation.step"
_INVALIDATED = "consent.invalidated"
_CLEANUP = "cleanup.result"
_UNCERTAIN = "operation.remote_uncertain"
_METRICS = {
    _LAUNCH: "netops.controller.launch.count",
    _STEP: "netops.operation.step.count",
    _INVALIDATED: "netops.consent.invalidated.count",
    _CLEANUP: "netops.cleanup.result.count",
    _UNCERTAIN: "netops.operation.remote_uncertain.count",
}
_OUTCOMES = frozenset((
    "started", "succeeded", "blocked", "failed", "cancelled", "uncertain",
    "unsupported", "not-requested",
))
_NEXT_ACTION = "Inspect the owned controller receipt and remote state before fresh reviewed execution."


class _ControllerObservations:
    def __init__(self, events: c.EventPort) -> None:
        self._events = events
        self._logger = logging.getLogger(__name__)
        self._lock = threading.Lock()
        self._counts: Counter[tuple[str, str, str]] = Counter()
        self.sink_failures = 0

    def record(
        self, boundary: str, outcome: str, request: c.OperationRequest,
        *, reason: c.ReasonCode | None = None, target: str = "none", step: str = "controller",
        duration: float = 0.0, unhandled: bool = False,
    ) -> None:
        if boundary not in _METRICS or outcome not in _OUTCOMES:
            raise c.ContractError()
        safe_reason = reason.value if reason is not None else "none"
        dimensions = {
            "outcome": outcome, "reason": safe_reason,
            "stage": "Unhandled" if unhandled else "finalize" if boundary == _CLEANUP else "controller",
        }
        correlation = {
            name: "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
            for name, value in (
                ("operation_id", request.operation_id), ("target_id", target),
                ("step_id", step), ("context_id", request.context.controller_id),
            )
        }
        with self._lock:
            self._counts[(boundary, outcome, safe_reason)] += 1
        try:
            self._logger.info(boundary, extra={
                "metric": _METRICS[boundary], "metric_value": 1,
                "metric_dimensions": dimensions, **dimensions, **correlation,
                "mode": request.mode.value, "duration": duration,
                "next_action": _NEXT_ACTION if reason is not None else "none",
            })
        except BaseException:
            # Reporting failure cannot discard an already observed result.
            with self._lock:
                self.sink_failures += 1
        try:
            status = (
                c.OutcomeStatus.SUCCEEDED if outcome in ("started", "succeeded")
                else c.OutcomeStatus.CANCELLED if outcome == "cancelled"
                else c.OutcomeStatus.BLOCKED if outcome == "blocked" else c.OutcomeStatus.FAILED
            )
            self._events.emit(c.SafeEvent(
                request.operation_id, "controller", "none", request.context.controller_id,
                request.mode, status, c.ErrorCategory.CREDENTIALS if reason else None,
                reason, False, duration,
            ))
        except BaseException:
            with self._lock:
                self.sink_failures += 1


@dataclass(frozen=True)
class ControllerInstallation:
    """Verified owned installed identity, returned only by trusted verification."""

    context: c.ControllerContext
    platform: str
    python: str
    installation_digest: str
    qualification_digest: str
    wsl_executable: str | None = None
    wsl_distribution: str | None = None

    def __post_init__(self) -> None:
        """Reject shell fragments, native Windows interpreters and relative paths."""
        if type(self.context) is not c.ControllerContext:
            raise c.ContractError()
        for value in (self.installation_digest, self.qualification_digest):
            c.sha256(value)
        if (
            self.platform not in ("linux", "macos", "windows-wsl")
            or not posixpath.isabs(self.python) or posixpath.normpath(self.python) != self.python
            or any(char in self.python for char in ("\x00", "\n", "\r"))
            or not self.python.endswith(("/python", "/python3"))
        ):
            raise c.ContractError()
        if self.platform == "windows-wsl":
            if (
                type(self.wsl_executable) is not str
                or not ntpath.isabs(self.wsl_executable)
                or not ntpath.splitdrive(self.wsl_executable)[0]
                or ntpath.normpath(self.wsl_executable) != self.wsl_executable
                or any(char in self.wsl_executable for char in ("\x00", "\n", "\r"))
                or ntpath.basename(self.wsl_executable).lower() != "wsl.exe"
                or type(self.wsl_distribution) is not str
                or not self.wsl_distribution
                or any(not (ch.isalnum() or ch in "._-") for ch in self.wsl_distribution)
            ):
                raise c.ContractError()
        elif self.wsl_executable is not None or self.wsl_distribution is not None:
            raise c.ContractError()

    def _argv(self, control_fd: int) -> tuple[str, ...]:
        if type(control_fd) is not int or control_fd < 0:
            raise c.ContractError()
        worker = ("-I", "-m", "netops.ansible.worker", "--control-fd", str(control_fd))
        if self.platform == "windows-wsl":
            assert self.wsl_executable is not None and self.wsl_distribution is not None
            return (
                self.wsl_executable, "--distribution", self.wsl_distribution,
                "--exec", self.python, *worker,
            )
        return (self.python, *worker)


@dataclass(frozen=True, repr=False)
class FixedLaunch:
    """Non-user-selectable launch and private host bridge for one owned group."""

    installation: ControllerInstallation
    request: c.ControllerRequest
    control: HostDispatchControl
    start_deadline: float
    operation_deadline: float
    teardown_seconds: float = 2.0

    def __repr__(self) -> str:
        """Do not dump host control state."""
        return "<private>"


@dataclass(frozen=True)
class ProcessResult:
    """Typed factual completion and separately verified owned teardown."""

    targets: tuple[c.TargetOutcome, ...]
    exit_code: int
    cleanup: c.CleanupOutcome
    error: c.SafeError | None = None


class ProcessPort(Protocol):
    """Qualified managed-process adapter; no public command execution endpoint."""

    def verify(
        self, context: c.ControllerContext, state: OwnedStatePort,
    ) -> ControllerInstallation | None:
        """Revalidate current owned installation and exact tuple qualification."""
        ...

    def run(self, launch: FixedLaunch, private_input: bytes, cancel: c.CancelPort) -> ProcessResult:
        """Own readiness/control, one private input, safe results and group teardown."""
        ...


class CredentialPort(Protocol):
    """Existing scoped resolver revoke boundary, not another credential authority."""

    def revoke(self, operation_id: str) -> None:
        """Discard unused private scopes idempotently."""
        ...


def _scope_wire(scope: CredentialScope, control: HostDispatchControl) -> dict[str, object]:
    targets: list[dict[str, object]] = []
    for selected in scope.targets:
        targets.append({
            "target_id": selected.target_id, "task_id": selected.task_id,
            "host": selected.host, "port": selected.port, "vendor": selected.vendor,
            "transport": selected.transport, "fields": list(selected.fields),
            "key_ref": selected.key_ref, "known_hosts_ref": selected.known_hosts_ref,
        })
    return {
        "operation_id": scope.operation_id, "controller_digest": scope.controller_digest,
        "route_digest": scope.route_digest, "targets": targets,
        "plan_digest": control._plan.plan_digest,
        "concurrency": min(
            control._plan.concurrency, control._plan.settings.execution.ssh_concurrency,
        ),
    }


class _WatchdogRevocations:
    """Supervise independent tightening-only cleanup without serial lock waits."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._threads: list[tuple[str, threading.Thread]] = []
        self._errors: list[c.SafeError] = []

    def _failure(self) -> None:
        with self._lock:
            self._errors.append(c.SafeError(
                c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED,
                c.Stage.FINALIZE, next_action="Inspect independent watchdog revocation cleanup.",
            ))

    def start(self, actions: tuple[tuple[str, Callable[[], None]], ...]) -> None:
        def execute(action: Callable[[], None]) -> None:
            try:
                action()
            except BaseException:
                self._failure()

        for name, action in actions:
            thread = threading.Thread(
                target=execute, args=(action,), name="netops-" + name, daemon=True,
            )
            try:
                thread.start()
            except BaseException:
                self._failure()
            else:
                with self._lock:
                    self._threads.append((name, thread))

    def collect(self, cleanup: c.CleanupOutcome) -> c.CleanupOutcome:
        with self._lock:
            threads = tuple(self._threads)
        for _, thread in threads:
            thread.join(timeout=0.1 / max(1, len(threads)))
        pending = tuple(name for name, thread in threads if thread.is_alive())
        with self._lock:
            errors = tuple(self._errors)
        if pending:
            errors += (c.SafeError(
                c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED,
                c.Stage.FINALIZE, next_action="Inspect still-pending watchdog revocation owners.",
            ),)
        if not errors:
            return cleanup
        return c.CleanupOutcome(
            "failed", tuple(dict.fromkeys(cleanup.remaining_refs + pending)),
            cleanup.errors + errors,
        )


class ControllerLauncher:
    """Implement the frozen controller port without automatic bootstrap."""

    def __init__(
        self, processes: ProcessPort, credentials: CredentialPort, state: OwnedStatePort,
        clock: c.ClockPort, events: c.EventPort,
    ) -> None:
        self._processes, self._credentials, self._state = processes, credentials, state
        self._clock = clock
        self._observations = _ControllerObservations(events)
        self._active: dict[str, _Stop] = {}
        self._active_lock = threading.Lock()

    def _cancel(self, operation_id: str) -> None:
        # Set the stop event before any broker/resolver lock or receipt clock.
        with self._active_lock:
            active = self._active.get(operation_id)
            if active is not None:
                active.stop(c.ReasonCode.CANCELLED)

    def verify(self, context: c.ControllerContext) -> c.ControllerReadiness:
        """Return readiness only from current exact consuming-context proof."""
        try:
            installation = self._processes.verify(context, self._state)
            if type(installation) is not ControllerInstallation or installation.context != context:
                raise ProtocolError()
            installation.__post_init__()
            return c.ControllerReadiness(
                context, c.ReadinessProjection(companion="ready"), installation.qualification_digest,
            )
        except Exception:
            error = c.SafeError(
                c.ErrorCategory.DEPENDENCY, c.ReasonCode.DEPENDENCY_NOT_READY,
                c.Stage.READINESS, next_action="Qualify the exact owned installed controller tuple.",
            )
            return c.ControllerReadiness(context, c.ReadinessProjection(errors=(error,)), "0" * 64)

    def run(
        self, request: c.ControllerRequest, credentials: c.ScopedCredentials, cancel: c.CancelPort,
    ) -> c.OperationOutcome:
        """Launch only explicit non-pure work with real pending host authority."""
        return self._run(request, credentials, cancel, None)

    def _run_host_entry(
        self, request: c.ControllerRequest, credentials: c.ScopedCredentials,
        cancel: c.CancelPort, owner: object,
    ) -> c.OperationOutcome:
        # Only the actual A02 owner can retain operation authority between
        # sub-invocations. Standalone run preserves terminal revocation.
        from .controller_backend import _ControllerEffectsBackend
        from .execution import ExecutionHost

        if type(owner) is not ExecutionHost:
            raise ProtocolError(c.ReasonCode.CONSENT_REQUIRED)
        backend = owner._backend
        if (
            type(backend) is not _ControllerEffectsBackend
            or backend._launcher is not self or backend._host is not owner
            or type(credentials) is not HostControllerCredentials
            or credentials._control._broker is not owner.authorization
            or owner._cancellations.get(request.plan.operation_id) is not cancel
        ):
            raise ProtocolError(c.ReasonCode.CONSENT_REQUIRED)
        return self._run(request, credentials, cancel, owner)

    def _run(
        self, request: c.ControllerRequest, credentials: c.ScopedCredentials,
        cancel: c.CancelPort, owner: object | None,
    ) -> c.OperationOutcome:
        request.__post_init__()
        selected = request.request
        # Pure fast path must precede clocks, credential/session, state or events.
        if selected.mode in (c.Mode.PREVIEW, c.Mode.CHECK):
            return c.aggregate_outcome(
                selected, tuple(c.TargetOutcome(
                    target, c.OutcomeStatus.BLOCKED, False,
                    unapplied_effects=(selected.operation,),
                ) for target in selected.scope.target_ids),
                provenance=c.public_object({"execution_performed": False}),
            )
        stop = _Stop(cancel)
        with self._active_lock:
            if selected.operation_id in self._active:
                return c.aggregate_outcome(
                    selected, tuple(c.TargetOutcome(
                        target, c.OutcomeStatus.BLOCKED, False,
                        unapplied_effects=(selected.operation,),
                    ) for target in selected.scope.target_ids),
                    errors=(c.SafeError(
                        c.ErrorCategory.PRECONDITION, c.ReasonCode.RESOURCE_BUSY,
                        c.Stage.AUTHORIZE, next_action="Wait for this exact owned controller run.",
                    ),),
                )
            self._active[selected.operation_id] = stop
        finished = threading.Event()
        watcher: threading.Thread | None = None
        revocations = _WatchdogRevocations()
        result: ProcessResult | None = None
        primary: c.SafeError | None = None
        cleanup = c.CleanupOutcome()
        authority: HostControllerCredentials | None = None
        launch_started = _ControllerIo._time()
        self._observations.record(_LAUNCH, "started", selected)
        try:
            if type(credentials) is not HostControllerCredentials:
                raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
            authority = credentials
            control = authority._control
            scope = authority._scope
            if (
                control._plan != request.plan or scope.operation_id != selected.operation_id
                or scope.context.context != selected.context
                or scope.controller_digest != c.digest(request.plan.context.controller_id)
                or any(t.target_id not in selected.scope.target_ids for t in scope.targets)
            ):
                raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
            def watchdog() -> None:
                last = control._accepted
                while not finished.wait(0.025):
                    try:
                        if stop._observe_parent():
                            raise ProtocolError(c.ReasonCode.CANCELLED)
                        # Independent from worker readiness, host snapshot I/O
                        # and broker locks. Only original host-local deadlines.
                        now = _time(self._clock.monotonic())
                        if now < last or now >= min(
                            control._deadline, control._authorization_deadline,
                        ):
                            raise ProtocolError(c.ReasonCode.DEADLINE_EXCEEDED)
                        last = now
                    except BaseException:
                        stop.stop(
                            c.ReasonCode.CANCELLED if stop.reason == c.ReasonCode.CANCELLED
                            else c.ReasonCode.DEADLINE_EXCEEDED,
                        )
                        # Deny subauthority without broker/state locks, then
                        # attempt both independent owners. Either may be held
                        # behind the very synchronous port we are stopping.
                        control._signal_revoke()
                        revocations.start((
                            ("controller-control-revocation",
                             lambda: control.revoke(selected.operation_id)),
                            ("controller-credentials-revocation",
                             lambda: self._credentials.revoke(selected.operation_id)),
                        ))
                        return

            watcher = threading.Thread(target=watchdog, name="netops-controller-watchdog", daemon=True)
            watcher.start()
            control.check()
            _time(self._clock.monotonic())
            installation = self._processes.verify(c.ControllerContext(selected.context), self._state)
            if type(installation) is not ControllerInstallation:
                raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
            installation.__post_init__()
            if installation.context.context != selected.context:
                raise ProtocolError()
            launch = FixedLaunch(
                installation, request, control,
                min(control._deadline, c.checked_deadline(
                    control._accepted, float(request.plan.settings.controller.start_timeout_seconds),
                )), control._deadline,
            )
            payload = authority._source._protected_payload(scope)
            private = json.loads(payload.decode("utf-8"))
            frame_scope = _scope_wire(scope, control)
            # Route has already been validated by the resolver. Preserve the
            # exact jump selection rather than silently connecting directly.
            jump = private["jump"]
            if jump is not None:
                frame_scope["jump"] = dict(jump, fields=list(jump["fields"]))
            else:
                frame_scope["jump"] = None
            intents = [{
                "binding": {
                    "operation_id": selected.operation_id,
                    "plan_digest": request.plan.plan_digest,
                    "controller_digest": c.digest(request.plan.context.controller_id),
                    "invocation_id": entry.invocation_id,
                    "occurrence_id": entry.binding.occurrence_id,
                    "target_id": entry.binding.target_id, "task_id": entry.binding.step_id,
                    "phase": "credential", "sequence": 0,
                },
                "kind": entry.kind,
                **({"mutation": control._mutations[entry.binding.occurrence_id]}
                   if entry.binding.occurrence_id in control._mutations else {}),
                **({"health": control._health[entry.binding.occurrence_id]}
                   if entry.binding.occurrence_id in control._health else {}),
            } for entry in control._invocations]
            private_input = _encode_frame({
                "protocol": 1, "request": json.loads(c.canonical_bytes(selected)),
                "scope": frame_scope, "intents": intents, "credentials": private,
            })
            control.check()
            result = self._processes.run(launch, private_input, stop)
            if type(result) is not ProcessResult:
                raise ProtocolError()
            cleanup = result.cleanup
            primary = result.error
            if result.exit_code != 0 and primary is None:
                primary = c.SafeError(
                    # Pure cancellation revokes admission, not a remote
                    # execution failure. Keep the concrete adapter's category
                    # so central aggregation retains cancellation exit 130.
                    c.ErrorCategory.CREDENTIALS if stop.reason == c.ReasonCode.CANCELLED
                    else c.ErrorCategory.EXECUTION,
                    stop.reason or c.ReasonCode.CONTROL_LOST,
                    c.Stage.CONTROLLER, next_action=_NEXT_ACTION,
                )
        except ProtocolError as error:
            primary = c.SafeError(
                c.ErrorCategory.DEPENDENCY if error.reason == c.ReasonCode.DEPENDENCY_NOT_READY
                else c.ErrorCategory.CREDENTIALS, error.reason, c.Stage.CONTROLLER,
                next_action=_NEXT_ACTION,
            )
        except Exception:
            primary = c.SafeError(
                c.ErrorCategory.CREDENTIALS, c.ReasonCode.HANDOFF_INVALID, c.Stage.CONTROLLER,
                next_action=_NEXT_ACTION,
            )
            self._observations.record(
                _LAUNCH, "failed", selected, reason=primary.reason, unhandled=True,
            )
        finally:
            finished.set()
            with self._active_lock:
                if self._active.get(selected.operation_id) is stop:
                    del self._active[selected.operation_id]
            if authority is not None:
                final_control = authority._control
                if primary is not None or stop._event.is_set() or owner is None:
                    final_control._signal_revoke()
                    revocations.start((
                        ("controller-final-control",
                         lambda: final_control.revoke(selected.operation_id)),
                        ("controller-final-credentials",
                         lambda: self._credentials.revoke(selected.operation_id)),
                    ))
                else:
                    revocations.start((("controller-final-control", final_control._close),))
            if watcher is not None:
                watcher.join(timeout=0.1)
            cleanup = revocations.collect(cleanup)
            self._observations.record(
                _INVALIDATED, "succeeded", selected,
                reason=stop.reason if stop.reason is not None else None,
            )
        by_target = {target.target_id: target for target in result.targets} if result is not None else {}
        if len(by_target) != (len(result.targets) if result is not None else 0) or any(
            target not in selected.scope.target_ids for target in by_target
        ):
            by_target = {}
            primary = c.SafeError(
                c.ErrorCategory.CREDENTIALS, c.ReasonCode.HANDOFF_INVALID,
                c.Stage.CONTROLLER, next_action=_NEXT_ACTION,
            )
        targets = tuple(by_target.get(target, c.TargetOutcome(
            target, c.OutcomeStatus.CANCELLED if stop.is_cancelled() else c.OutcomeStatus.BLOCKED,
            False, unapplied_effects=(selected.operation,),
        )) for target in selected.scope.target_ids)
        for target in targets:
            self._observations.record(
                _STEP, target.status.value, selected, target=target.target_id,
                reason=target.errors[0].reason if target.errors else None,
            )
            if target.remote_state == "uncertain":
                self._observations.record(
                    _UNCERTAIN, "uncertain", selected, target=target.target_id,
                    reason=c.ReasonCode.REMOTE_STATE_UNCERTAIN,
                )
        self._observations.record(
            _CLEANUP, "failed" if cleanup.status == "failed" else "succeeded", selected,
            reason=c.ReasonCode.CLEANUP_FAILED if cleanup.status == "failed" else None,
        )
        self._observations.record(
            _LAUNCH, "blocked" if primary else "succeeded", selected,
            reason=primary.reason if primary else None,
            duration=max(0.0, _ControllerIo._time() - launch_started),
        )
        return c.aggregate_outcome(
            selected, targets, executed_mode=selected.mode,
            readiness=c.ReadinessProjection(companion="ready") if result is not None
            else c.ReadinessProjection(),
            errors=(primary,) if primary else (),
            cleanup=cleanup, provenance=c.public_object({
                "controller_qualification_claimed": False,
                "telemetry_sink_failures": self._observations.sink_failures,
            }),
        )
