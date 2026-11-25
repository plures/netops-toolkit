"""Owned POSIX process adapter; no actual tuple qualification is implied.

Concrete WSL transport lives in _controller_wsl. Neither adapter equates a
Windows launcher exit with verified Linux owned-group teardown.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import threading
import time
from collections.abc import Callable
from typing import Protocol, cast

from . import contracts as c
from .artifacts import OwnedStatePort
from .controller import ControllerInstallation, FixedLaunch, ProcessResult, _WatchdogRevocations
from .controller_control import _Stop
from .controller_observations import _ControllerIo
from .controller_protocol import (
    ProtocolError,
    _closed,
    _decode_frame,
    _encode_frame,
    _string,
    _time,
)
from .controller_transport import _SocketFrames, _unix_family


class InstallationVerifier(Protocol):
    """Host-owned evidence collector, not request-provided qualification flags."""

    def verify(
        self, context: c.ControllerContext, state: OwnedStatePort,
    ) -> ControllerInstallation | None:
        """Check owned executable bytes, installed assets and exact actual tuple proof."""
        ...


class _ProcessWatchdog:
    """Signal an unreaped owned group without worker, broker or snapshot locks."""

    def __init__(
        self, pid: int, launch: FixedLaunch, stop: _Stop, clock: c.ClockPort,
    ) -> None:
        self._pid, self._launch, self._stop, self._clock = pid, launch, stop, clock
        self._finished = threading.Event()
        self.ready = threading.Event()
        self._thread = threading.Thread(target=self._watch, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _watch(self) -> None:
        last = self._launch.control._accepted
        while not self._finished.wait(0.025):
            try:
                now = _time(self._clock.monotonic())
                deadline = min(
                    self._launch.operation_deadline,
                    self._launch.control._authorization_deadline,
                    self._launch.operation_deadline if self.ready.is_set()
                    else self._launch.start_deadline,
                )
                if now < last or now >= deadline:
                    self._stop.stop(c.ReasonCode.DEADLINE_EXCEEDED)
                last = now
                # Sample the original nonblocking CancelPort independently of
                # stalled worker/control/main-loop calls, latching first cause.
                self._stop._observe_parent()
            except BaseException:
                self._stop.stop(c.ReasonCode.DEADLINE_EXCEEDED)
            if self._stop._event.is_set():
                self._signal(signal.SIGTERM)
                if not self._finished.wait(self._launch.teardown_seconds):
                    self._signal(cast(int, getattr(signal, "SIGKILL")))
                return

    def _signal(self, selected: int) -> None:
        if self._finished.is_set():
            return
        try:
            kill_group = cast(Callable[[int, int], None], getattr(os, "killpg"))
            kill_group(self._pid, selected)
        except OSError:
            # Main teardown verifies group absence separately. No factual
            # success is manufactured from a failed signal or missing ack.
            pass

    def close(self) -> bool:
        self._finished.set()
        self._thread.join(timeout=0.1)
        return not self._thread.is_alive()


class OwnedPosixProcesses:
    """Execute only the verifier's absolute fixed installed worker in a new group."""

    def __init__(
        self, verifier: InstallationVerifier, clock: c.ClockPort, private_root: str,
    ) -> None:
        self._verifier, self._clock = verifier, clock
        # This is bootstrap-selected protected runtime state, never request JSON.
        if not os.path.isabs(private_root):
            raise c.ContractError()
        self._private_root = private_root
        self._io = _ControllerIo()

    def verify(
        self, context: c.ControllerContext, state: OwnedStatePort,
    ) -> ControllerInstallation | None:
        """Delegate actual current byte/ownership/qualification verification."""
        with self._io.span("process.verify", context=context.context.controller_id):
            result = self._verifier.verify(context, state)
        if result is None:
            return None
        result.__post_init__()
        if os.name != "posix" or result.platform not in ("linux", "macos"):
            return None
        return result

    @staticmethod
    def _teardown(process: subprocess.Popen[bytes], bound: float) -> c.CleanupOutcome:
        """Signal only this run's new session/group; preserve failed teardown."""
        failed = False
        try:
            kill_group = cast(Callable[[int, int], None], getattr(os, "killpg"))
            # The group may outlive its leader. Never equate launcher exit with
            # runner/fork termination, and never signal a global process name.
            try:
                kill_group(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + bound
            while time.monotonic() < deadline:
                try:
                    kill_group(process.pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                try:
                    kill_group(process.pid, cast(int, getattr(signal, "SIGKILL")))
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=bound)
            except subprocess.TimeoutExpired:
                failed = True
            try:
                kill_group(process.pid, 0)
                failed = True
            except ProcessLookupError:
                pass
        except OSError:
            failed = True
        if failed:
            return c.CleanupOutcome("failed", remaining_refs=("owned-posix-controller-group",), errors=(c.SafeError(
                c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
                next_action="Inspect the exact owned Linux process group and private run directory.",
            ),))
        return c.CleanupOutcome("succeeded")

    def run(self, launch: FixedLaunch, private_input: bytes, cancel: c.CancelPort) -> ProcessResult:
        """Handshake once, service host dispatch and always tear down owned work."""
        from ._controller_wsl import _control_message

        if (
            os.name != "posix" or launch.installation.platform not in ("linux", "macos")
            or type(launch) is not FixedLaunch or launch.teardown_seconds != 2.0
            or type(cancel) is not _Stop
        ):
            raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
        launch.installation.__post_init__()
        launch.control.check()
        if _time(self._clock.monotonic()) >= launch.start_deadline:
            raise ProtocolError(c.ReasonCode.DEADLINE_EXCEEDED)
        parent, child = socket.socketpair(_unix_family(), socket.SOCK_STREAM)
        channel = _SocketFrames(parent)
        process: subprocess.Popen[bytes] | None = None
        targets: tuple[c.TargetOutcome, ...] = ()
        error: c.SafeError | None = None
        cleanup = c.CleanupOutcome()
        exit_code = 1
        monitor: _ProcessWatchdog | None = None
        try:
            argv = (*launch.installation._argv(child.fileno()), "--private-root", self._private_root)
            with self._io.span("process.launch", launch.request.request.operation_id):
                process = subprocess.Popen(
                    argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env={"LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1"},
                    cwd="/", close_fds=True, pass_fds=(child.fileno(),), start_new_session=True,
                    shell=False,
                )
            monitor = _ProcessWatchdog(process.pid, launch, cancel, self._clock)
            monitor.start()
            child.close()
            remaining = launch.start_deadline - self._clock.monotonic()
            if remaining <= 0:
                raise ProtocolError(c.ReasonCode.DEADLINE_EXCEEDED)
            with self._io.span("process.readiness", launch.request.request.operation_id):
                ready = _closed(channel.receive(remaining, cancel), {"kind", "nonce"})
            if ready["kind"] != "ready":
                raise ProtocolError()
            budget = launch.control.ready(_string(ready["nonce"], 64))
            frame = _decode_frame(private_input)
            if "budget" in frame:
                raise ProtocolError()
            frame["budget"] = budget._wire()
            launch.control.check()
            assert process.stdin is not None
            with self._io.span("process.input", launch.request.request.operation_id):
                process.stdin.write(_encode_frame(frame))
                process.stdin.close()
            monitor.ready.set()
            while True:
                if cancel.is_cancelled():
                    raise ProtocolError(c.ReasonCode.CANCELLED)
                launch.control.check()
                with self._io.span("process.control", launch.request.request.operation_id):
                    message = channel.receive(2.0, cancel)
                outcome = _control_message(channel, message, launch, cancel)
                if outcome is not None:
                    targets, cleanup = outcome.targets, outcome.cleanup
                    error = outcome.errors[0] if outcome.errors else None
                    # Keep the unreaped leader owned while tearing down its
                    # group; a PID cannot be reused between wait and killpg.
                    exit_code = 0
                    break
        except Exception as failure:
            reason = failure.reason if type(failure) is ProtocolError else c.ReasonCode.CONTROL_LOST
            error = c.SafeError(
                c.ErrorCategory.CREDENTIALS, reason, c.Stage.CONTROLLER,
                next_action="Inspect the owned controller receipt before fresh consent.",
            )
            # No automatic replay. Mark only entered mutating occurrences as
            # uncertain; factual returned target outcomes survive later loss.
            completed = {t.target_id for t in targets}
            uncertain = tuple(
                entry for entry in launch.control._invocations
                if entry.kind in ("apply", "rollback")
                and launch.control._next.get(entry.binding.occurrence_id, 0) >= 3
                and entry.binding.target_id not in completed
            )
            targets += tuple(c.TargetOutcome(
                entry.binding.target_id, c.OutcomeStatus.FAILED, True, remote_state="uncertain",
                errors=(c.SafeError(
                    c.ErrorCategory.EXECUTION, c.ReasonCode.REMOTE_STATE_UNCERTAIN,
                    c.Stage.APPLY, target_id=entry.binding.target_id,
                    next_action="Inspect remote state; do not retry an issued mutation.",
                ),),
            ) for entry in uncertain)
        finally:
            from ._controller_wsl import _merge_cleanup

            def finalize(reference: str, action: Callable[[], None]) -> None:
                nonlocal cleanup
                try:
                    action()
                except BaseException:
                    cleanup = _merge_cleanup(cleanup, c.CleanupOutcome(
                        "failed", remaining_refs=(reference,), errors=(c.SafeError(
                            c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED,
                            c.Stage.FINALIZE,
                            next_action="Inspect each exact owned controller finalization resource.",
                        ),),
                    ))

            # A failed revoke, child descriptor or channel close MUST NOT skip
            # owned group teardown. Likewise teardown cannot skip stdin close.
            # Preserve any already received primary error, target and cleanup.
            revocations = _WatchdogRevocations()
            if error is not None or cancel._event.is_set():
                finalize("owned-controller-control", launch.control._signal_revoke)
                revocations.start((("owned-controller-control", lambda: launch.control.revoke(
                    launch.request.request.operation_id,
                )),))
            finalize("owned-controller-child-descriptor", child.close)
            finalize("owned-controller-channel", channel.close)
            if process is not None:
                if monitor is not None:
                    def close_monitor() -> None:
                        if not monitor.close():
                            raise ProtocolError(c.ReasonCode.CLEANUP_FAILED)

                    finalize("owned-controller-watchdog", close_monitor)

                def teardown() -> None:
                    nonlocal cleanup
                    assert process is not None
                    owned = self._io.cleanup(
                        "process.teardown", launch.request.request.operation_id,
                        lambda: self._teardown(process, launch.teardown_seconds),
                    )
                    cleanup = _merge_cleanup(cleanup, owned)

                finalize("owned-posix-controller-group", teardown)
                if process.stdin is not None:
                    finalize("owned-controller-input", process.stdin.close)
            cleanup = revocations.collect(cleanup)
        return ProcessResult(targets, exit_code, cleanup, error)
