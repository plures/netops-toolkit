"""Fixed Windows/WSL private transport; Linux proof, never launcher-exit proof."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import posixpath
import secrets
import threading
import time
from pathlib import Path
from typing import BinaryIO, cast

from . import contracts as c
from ._controller_pipe import _Frames, _PipeFrames
from ._windows_job import _KernelError, _start_job_process, _WindowsProcess
from .artifacts import OwnedStatePort
from .controller import ControllerInstallation, FixedLaunch, ProcessResult
from .controller_control import _Stop
from .controller_installation import _OwnedInstallationVerifier
from .controller_observations import _ControllerIo
from .controller_process import InstallationVerifier
from .controller_protocol import (
    DispatchBinding,
    ProtocolError,
    _closed,
    _decode_frame,
    _integer,
    _string,
    _time,
)

_KERNEL_STAGES = frozenset((
    "CreateJobObjectW", "SetInformationJobObject", "AssignProcessToJobObject",
    "QueryInformationJobObject", "TerminateJobObject", "TerminateProcess", "ResumeThread",
    "CloseHandle", "WaitForSingleObject", "GetExitCodeProcess", "GetWindowsDirectoryW",
    "OpenThread", "CancelSynchronousIo",
    "CreateProcess",
))


def _kernel_detail(failure: BaseException) -> str:
    if type(failure) is not _KernelError or failure.kernel_stage not in _KERNEL_STAGES:
        return ""
    return "windows-kernel:" + failure.kernel_stage + ":" + str(failure.kernel_code)


def _proof(key: str, kind: str, nonce: str, binding: str, value: object = None) -> str:
    c.sha256(key)
    c.sha256(nonce)
    c.sha256(binding)
    return hmac.new(bytes.fromhex(key), c.canonical_bytes(
        c.public_object({"kind": kind, "nonce": nonce, "binding": binding, "value": value}),
    ), hashlib.sha256).hexdigest()


def _binding(request: c.OperationRequest, plan: str) -> str:
    c.sha256(plan)
    return c.digest(c.public_object({
        "request": json.loads(c.canonical_bytes(request)), "plan_digest": plan,
    }))


def _merge_cleanup(first: c.CleanupOutcome, second: c.CleanupOutcome) -> c.CleanupOutcome:
    return c.CleanupOutcome(
        "failed" if "failed" in (first.status, second.status) else (
            second.status if first.status == "not-requested" else first.status
        ),
        tuple(dict.fromkeys(first.remaining_refs + second.remaining_refs)),
        first.errors + second.errors,
    )


def _lost_group() -> c.CleanupOutcome:
    return c.CleanupOutcome(
        "failed", remaining_refs=("owned-linux-runner-group",),
        errors=(c.SafeError(
            c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
            next_action="Inspect the exact owned Linux group; Windows launcher exit is not proof.",
        ),),
    )


def _cleanup_frame(value: object) -> c.CleanupOutcome:
    item = c.public_object(_closed(value, {"status", "remaining_refs", "errors"}))
    errors = c._sequence(item["errors"])
    for error in errors:
        c._closed(c._mapping(error), {
            "category", "reason", "stage", "target_id", "step_id", "retryable",
            "detail", "next_action",
        })
    return c.CleanupOutcome(
        c.text(item["status"]), c.unique(item["remaining_refs"]),
        tuple(c._error_from_wire(error) for error in errors),
    )


def _accept_result(message: object, request: c.OperationRequest) -> c.OperationOutcome:
    item = _closed(message, {"kind", "outcome"})
    if item["kind"] != "result":
        raise ProtocolError()
    outcome = c.OperationOutcome.from_json(json.dumps(
        item["outcome"], allow_nan=False,
    ).encode("utf-8"))
    if (
        outcome.operation_id != request.operation_id or outcome.requested_mode != request.mode
        or tuple(t.target_id for t in outcome.targets) != request.scope.target_ids
    ):
        raise ProtocolError()
    return outcome


def _control_message(
    channel: _Frames, message: dict[str, object], launch: FixedLaunch, cancel: _Stop,
) -> c.OperationOutcome | None:
    kind = message.get("kind")
    if kind == "dispatch":
        item = _closed(message, {"kind", "binding"})
        selected = DispatchBinding._parse(item["binding"])
        permit = launch.control.request_dispatch(selected, cancel)
        channel.send({
            "kind": "permit", "binding": selected._wire(), "budget": permit.budget._wire(),
        })
    elif kind == "pulse":
        _closed(message, {"kind"})
        launch.control.check()
        channel.send({"kind": "alive"})
    elif kind == "content":
        item = _closed(message, {"kind", "binding", "content"})
        launch.control._accept_content(DispatchBinding._parse(item["binding"]), item["content"])
        channel.send({"kind": "content-received"})
    else:
        return _accept_result(message, launch.request.request)
    return None


class _WslProcessIo:
    """Only the fixed installed module; no shell, default distro or arbitrary exec."""

    def __init__(self) -> None:
        self._unfinished: list[_WindowsProcess] = []
        self._lock = threading.RLock()

    def launch(self, installation: ControllerInstallation) -> _WindowsProcess:
        """Serialize launch against retained exact cleanup owners."""
        with self._lock:
            return self._launch(installation)

    def _launch(self, installation: ControllerInstallation) -> _WindowsProcess:
        installation.__post_init__()
        if self._unfinished:
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
        assert installation.wsl_executable is not None
        assert installation.wsl_distribution is not None
        try:
            return _start_job_process(
                installation.wsl_executable,
                (
                    installation.wsl_executable, "--distribution", installation.wsl_distribution,
                    "--exec", installation.python, "-I", "-m", "netops.ansible.worker",
                    "--stdio-control",
                ),
                str(Path(installation.wsl_executable).parent),
            )
        except _KernelError as failure:
            if failure.owned_process is not None:
                self._unfinished.append(failure.owned_process)
            raise

    def close_pending(self, timeout: float = 0.5) -> c.CleanupOutcome:
        """Retain exact failed-launch handles until teardown is actually proved."""
        result = c.CleanupOutcome("succeeded")
        with self._lock:
            pending = tuple(self._unfinished)
        for process in pending:
            closed = self.close_launcher(process, timeout)
            result = _merge_cleanup(result, closed)
        return result

    def frames(self, process: _WindowsProcess) -> _PipeFrames:
        if process.stdout is None or process.stdin is None:
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
        return _PipeFrames(cast(BinaryIO, process.stdout), cast(BinaryIO, process.stdin))

    def close_launcher(self, process: _WindowsProcess, timeout: float = 0.5) -> c.CleanupOutcome:
        # Register before attempting normal close, not only on failed spawn.
        # Equality is not ownership: distinct owners may compare equal.
        with self._lock:
            if not any(owner is process for owner in self._unfinished):
                self._unfinished.append(process)
        try:
            # This unnamed job owns ONLY the Windows outer tree, not Linux.
            if not process.close(timeout):
                raise ProtocolError(c.ReasonCode.CLEANUP_FAILED)
            with self._lock:
                self._unfinished[:] = [owner for owner in self._unfinished if owner is not process]
            return c.CleanupOutcome("succeeded")
        except BaseException as failure:
            failures = getattr(process, "_close_failures", ()) or (failure,)
            return c.CleanupOutcome(
                "failed", remaining_refs=("owned-wsl-launcher",),
                errors=tuple(c.SafeError(
                    c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
                    detail=_kernel_detail(item),
                ) for item in failures),
            )

    def launcher_bytes(self, path: str) -> str:
        selected = Path(path)
        before = selected.lstat()
        if selected.is_symlink() or not selected.is_file() or before.st_size > 32 * 1024 * 1024:
            raise ProtocolError()
        with selected.open("rb") as source:
            digest = hashlib.sha256(source.read()).hexdigest()
        after = selected.lstat()
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        ):
            raise ProtocolError()
        return digest


class _OwnedWslProcesses:
    """Consume existing qualified installation evidence and actual launcher bytes.

    The injected verifier retains the ownership/active-install/consuming-context
    contract. The packaged exact Q03 entry must additionally pin the Windows
    executable bytes, distro and Linux interpreter. Directory/name presence,
    Windows Ansible imports and request readiness flags never qualify a tuple.
    """

    def __init__(
        self, verifier: InstallationVerifier, clock: c.ClockPort, private_root: str,
        io: _WslProcessIo | None = None,
    ) -> None:
        if (
            not posixpath.isabs(private_root) or posixpath.normpath(private_root) != private_root
            or any(ch in private_root for ch in ("\x00", "\r", "\n"))
        ):
            raise c.ContractError()
        self._verifier, self._clock, self._root = verifier, clock, private_root
        self._ports = io if io is not None else _WslProcessIo()
        self._io = _ControllerIo()
        self._state: OwnedStatePort | None = None
        self._state_lock = threading.Lock()

    def _verified(self, context: c.ControllerContext, state: OwnedStatePort) -> ControllerInstallation:
        selected = self._verifier.verify(context, state)
        if type(selected) is not ControllerInstallation:
            raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
        selected.__post_init__()
        if selected.context != context or selected.platform != "windows-wsl":
            raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
        if selected.qualification_digest == "0" * 64:
            raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
        lock = _OwnedInstallationVerifier._qualification_lock()
        if lock.get("state") != "qualified":
            raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
        entries = [
            entry for entry in lock.get("qualified", ()) if type(entry) is dict
            and entry.get("installation_digest") == selected.installation_digest
            and entry.get("context_digest") == c.digest(context)
            and entry.get("evidence_digest") == selected.qualification_digest
            and entry.get("state") == "qualified" and entry.get("platform") == "windows-wsl"
            and entry.get("wsl_distribution") == selected.wsl_distribution
            and entry.get("python") == selected.python
        ]
        if len(entries) != 1 or set(entries[0].get("tuple", {})) != set(lock["required_tuple"]):
            raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
        expected = entries[0].get("wsl_executable_digest")
        c.sha256(expected)
        assert selected.wsl_executable is not None
        if self._ports.launcher_bytes(selected.wsl_executable) != expected:
            raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
        return selected

    def verify(
        self, context: c.ControllerContext, state: OwnedStatePort,
    ) -> ControllerInstallation | None:
        """Recheck current byte identity, ownership and consuming exact tuple."""
        try:
            with self._io.span("process.verify", context=context.context.controller_id):
                result = self._verified(context, state)
                with self._state_lock:
                    if self._state is not None and self._state is not state:
                        raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
                    self._state = state
                return result
        except Exception:
            return None

    def run(self, launch: FixedLaunch, private_input: bytes, cancel: c.CancelPort) -> ProcessResult:
        """Run actual fixed adapter logic and independent authenticated Linux stop."""
        if (
            type(launch) is not FixedLaunch or type(cancel) is not _Stop
            or launch.installation.platform != "windows-wsl" or launch.teardown_seconds != 2.0
            or (os.name != "nt" and type(self._ports) is _WslProcessIo)
        ):
            raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
        launch.installation.__post_init__()
        launch.control.check()
        with self._state_lock:
            state = self._state
        if state is None:
            raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
        with self._io.span("process.verify", launch.request.request.operation_id):
            current = self._verified(c.ControllerContext(launch.request.request.context), state)
            if current != launch.installation:
                raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
        launch.control.check()
        frame = _decode_frame(private_input)
        if "budget" in frame:
            raise ProtocolError()
        bound = _binding(launch.request.request, launch.control._plan.plan_digest)
        key, challenge = secrets.token_hex(32), secrets.token_hex(32)
        nonce = ""
        process: _WindowsProcess | None = None
        channel: _PipeFrames | None = None
        targets: tuple[c.TargetOutcome, ...] = ()
        error: c.SafeError | None = None
        cleanup = c.CleanupOutcome()
        group = _lost_group()
        finished = threading.Event()
        stop_sent = threading.Event()
        stop_lock = threading.Lock()
        monitor: threading.Thread | None = None
        code = 1
        cleanup_deadline: float | None = None

        def stop() -> None:
            remaining = 0.2 if cleanup_deadline is None else max(
                0.0, min(0.2, cleanup_deadline - time.monotonic()),
            )
            if not stop_lock.acquire(timeout=remaining):
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
            try:
                if channel is not None and nonce and not stop_sent.is_set():
                    stop_sent.set()
                    with self._io.span("process.cancel", launch.request.request.operation_id):
                        channel.send({
                            "kind": "stop", "proof": _proof(key, "stop", nonce, bound),
                        }, max(0.001, remaining))
            finally:
                stop_lock.release()

        def watch() -> None:
            last = launch.control._accepted
            while not finished.wait(0.025):
                try:
                    now = _time(self._clock.monotonic())
                    deadline = min(
                        launch.operation_deadline, launch.control._authorization_deadline,
                        launch.operation_deadline if nonce else launch.start_deadline,
                    )
                    if now < last or now >= deadline:
                        cancel.stop(c.ReasonCode.DEADLINE_EXCEEDED)
                    last = now
                    cancel._observe_parent()
                    if cancel._event.is_set():
                        # Latch first, independent of broker/resolver/snapshot
                        # locks. The existing launcher supervises revocations.
                        launch.control._signal_revoke()
                        stop()
                        return
                except BaseException:
                    cancel.stop(c.ReasonCode.CONTROL_LOST)
                    return

        try:
            if _time(self._clock.monotonic()) >= launch.start_deadline:
                raise ProtocolError(c.ReasonCode.DEADLINE_EXCEEDED)
            with self._io.span("process.launch", launch.request.request.operation_id):
                process = self._ports.launch(launch.installation)
                channel = self._ports.frames(process)
            monitor = threading.Thread(target=watch, daemon=True)
            monitor.start()
            startup_ms = int((min(
                launch.start_deadline, launch.operation_deadline,
                launch.control._authorization_deadline,
            ) - _time(self._clock.monotonic())) * 1000)
            _integer(startup_ms, 1, 120000)
            channel.send({
                "kind": "start", "key": key, "challenge": challenge, "binding": bound,
                "root": self._root, "context_digest": c.digest(launch.installation.context),
                "installation_digest": launch.installation.installation_digest,
                "qualification_digest": launch.installation.qualification_digest,
                "startup_remaining_ms": startup_ms,
            })
            with self._io.span("process.proof", launch.request.request.operation_id):
                remaining = launch.start_deadline - _time(self._clock.monotonic())
                ready = _closed(channel.receive(remaining, cancel), {"kind", "nonce", "proof"})
                nonce = _string(ready["nonce"], 64)
                if ready["kind"] != "ready" or not hmac.compare_digest(
                    _string(ready["proof"], 64), _proof(key, "ready", nonce, bound, challenge),
                ):
                    nonce = ""
                    raise ProtocolError()
            frame["budget"] = launch.control.ready(nonce)._wire()
            with self._io.span("process.input", launch.request.request.operation_id):
                channel.send({"kind": "input", "payload": frame})
            frame.clear()
            while True:
                launch.control.check()
                with self._io.span("process.control", launch.request.request.operation_id):
                    message = channel.receive(2.0, cancel)
                    outcome = _control_message(channel, message, launch, cancel)
                if outcome is not None:
                    targets, cleanup = outcome.targets, outcome.cleanup
                    error = outcome.errors[0] if outcome.errors else None
                    code = 0
                    break
        except Exception as failure:
            reason = failure.reason if type(failure) is ProtocolError else c.ReasonCode.CONTROL_LOST
            error = c.SafeError(
                c.ErrorCategory.EXECUTION, reason, c.Stage.CONTROLLER,
                detail=_kernel_detail(failure),
                next_action="Inspect owned controller facts before fresh consent; no replay.",
            )
        finally:
            cleanup_deadline = time.monotonic() + launch.teardown_seconds
            finished.set()
            if monitor is not None:
                monitor.join(timeout=0.1)
                if monitor.is_alive():
                    cleanup = _merge_cleanup(cleanup, c.CleanupOutcome(
                        "failed", remaining_refs=("owned-wsl-watchdog",), errors=_lost_group().errors,
                    ))
            if error is not None or cancel._event.is_set():
                launch.control._signal_revoke()
            if channel is not None:
                selected_channel = channel

                def read_group_proof() -> c.CleanupOutcome:
                    nonlocal targets, cleanup, error
                    started = _time(time.monotonic())
                    assert cleanup_deadline is not None
                    deadline = cleanup_deadline
                    last = started
                    seen_result = bool(targets)
                    while True:
                        now = _time(time.monotonic())
                        if now < last or now >= deadline:
                            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
                        last = now
                        message = selected_channel.receive(deadline - now)
                        if message.get("kind") == "result":
                            # Exact late completion is a fact, not permission.
                            # Never discard it because cancellation won a race.
                            if seen_result:
                                raise ProtocolError()
                            late = _accept_result(message, launch.request.request)
                            targets = late.targets
                            cleanup = _merge_cleanup(cleanup, late.cleanup)
                            error = error or (late.errors[0] if late.errors else None)
                            seen_result = True
                            continue
                        ack = _closed(message, {"kind", "cleanup", "proof"})
                        if ack["kind"] != "stopped" or not hmac.compare_digest(
                            _string(ack["proof"], 64),
                            _proof(key, "stopped", nonce, bound, ack["cleanup"]),
                        ):
                            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
                        actual = _cleanup_frame(ack["cleanup"])
                        if actual.status != "succeeded" or actual.remaining_refs or actual.errors:
                            return _merge_cleanup(actual, _lost_group())
                        return actual

                def close_pipes() -> c.CleanupOutcome:
                    assert cleanup_deadline is not None
                    remaining = max(0.0, min(0.15, cleanup_deadline - time.monotonic()))
                    closed = (
                        selected_channel.close(remaining) if type(selected_channel) is _PipeFrames
                        else selected_channel.close()
                    )
                    if not closed:
                        return c.CleanupOutcome(
                            "failed", remaining_refs=("owned-private-pipes",),
                            errors=_lost_group().errors,
                        )
                    return c.CleanupOutcome("succeeded")

                try:
                    stop()
                    group = self._io.cleanup(
                        "process.teardown", launch.request.request.operation_id, read_group_proof,
                    )
                except BaseException:
                    group = _lost_group()
                cleanup = _merge_cleanup(cleanup, group)
            else:
                cleanup = _merge_cleanup(cleanup, group)
            if process is not None:
                try:
                    launcher = self._io.cleanup(
                        "process.teardown", launch.request.request.operation_id,
                        lambda: self._ports.close_launcher(
                            process, max(0.0, min(0.5, cleanup_deadline - time.monotonic())),
                        ) if type(self._ports) is _WslProcessIo
                        else self._ports.close_launcher(process),
                    )
                except BaseException:
                    launcher = c.CleanupOutcome(
                        "failed", remaining_refs=("owned-wsl-launcher",), errors=_lost_group().errors,
                    )
                cleanup = _merge_cleanup(cleanup, launcher)
            elif type(self._ports) is _WslProcessIo:
                cleanup = _merge_cleanup(cleanup, self._ports.close_pending(
                    max(0.0, min(0.5, cleanup_deadline - time.monotonic())),
                ))
            # Linux proof is consumed first, then the outer Windows job is
            # joined/killed. Closing its last child pipe ends unblocks readers.
            if channel is not None:
                try:
                    pipes = self._io.cleanup(
                        "process.teardown", launch.request.request.operation_id, close_pipes,
                    )
                except BaseException:
                    pipes = c.CleanupOutcome(
                        "failed", remaining_refs=("owned-private-pipes",), errors=_lost_group().errors,
                    )
                cleanup = _merge_cleanup(cleanup, pipes)
            frame.clear()
            key = ""
        completed = {t.target_id for t in targets}
        targets += tuple(c.TargetOutcome(
            entry.binding.target_id, c.OutcomeStatus.FAILED, True, remote_state="uncertain",
            errors=(c.SafeError(
                c.ErrorCategory.EXECUTION, c.ReasonCode.REMOTE_STATE_UNCERTAIN, c.Stage.APPLY,
                target_id=entry.binding.target_id, next_action="Inspect issued work; do not replay.",
            ),),
        ) for entry in launch.control._invocations
            if entry.kind in ("apply", "rollback")
            and launch.control._next.get(entry.binding.occurrence_id, 0) >= 3
            and entry.binding.target_id not in completed)
        return ProcessResult(targets, code, cleanup, error)
