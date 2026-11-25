"""Linux runner group ownership from an actual created child, never a wire PID."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from typing import cast

from . import contracts as c
from .controller_observations import _ControllerIo
from .controller_protocol import ProtocolError


class _LinuxGroupSystem:
    """Fixed OS effects for one child; fakeable without any real process effects."""

    def identity(self, process: subprocess.Popen[bytes]) -> bool:
        group = cast(Callable[[int], int], getattr(os, "getpgid"))
        session = cast(Callable[[int], int], getattr(os, "getsid"))
        return group(process.pid) == process.pid and session(process.pid) == process.pid

    def finished(self, process: subprocess.Popen[bytes]) -> bool:
        # Observe but DO NOT reap: retain ownership until the final destructive
        # group signal. Popen.poll/wait before signalling permits PID reuse.
        wait = cast(Callable[[int, int, int], object], getattr(os, "waitid"))
        value = wait(
            cast(int, getattr(os, "P_PID")), process.pid,
            cast(int, getattr(os, "WEXITED")) | cast(int, getattr(os, "WNOHANG"))
            | cast(int, getattr(os, "WNOWAIT")),
        )
        return value is not None

    def signal(self, process: subprocess.Popen[bytes], selected: int) -> None:
        kill = cast(Callable[[int, int], None], getattr(os, "killpg"))
        kill(process.pid, selected)

    def exists(self, process: subprocess.Popen[bytes]) -> bool:
        try:
            kill = cast(Callable[[int, int], None], getattr(os, "killpg"))
            kill(process.pid, 0)
        except ProcessLookupError:
            return False
        return True

    def pause(self, seconds: float) -> None:
        time.sleep(seconds)


class _OwnedLinuxGroup:
    """Retain the new runner's unreaped leader until all destructive signals end."""

    def __init__(self, system: _LinuxGroupSystem | None = None) -> None:
        self._system = system if system is not None else _LinuxGroupSystem()
        self._lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._stopped = False
        self._outcome: c.CleanupOutcome | None = None
        self._io = _ControllerIo()
        self._operation = "none"

    def attach(self, process: subprocess.Popen[bytes], operation: str) -> None:
        with self._lock:
            self._attach(process, operation)

    def _attach(self, process: subprocess.Popen[bytes], operation: str) -> None:
        if self._process is not None:
            raise ProtocolError()
        # Retain ownership even when identity verification fails; do not
        # signal an unverified group. Cleanup then reports uncertainty.
        self._process = process
        self._operation = operation
        try:
            valid = self._system.identity(process)
        except BaseException:
            valid = False
        if not valid:
            self._outcome = self._failure()
            self._stopped = True
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
        if self._stopped:
            # A cancel arriving during Popen must stop this exact new child.
            self._outcome = self._teardown(process)
            raise ProtocolError(c.ReasonCode.CANCELLED)

    def launch(
        self, factory: Callable[[], subprocess.Popen[bytes]], operation: str,
    ) -> subprocess.Popen[bytes]:
        with self._lock:
            if self._stopped:
                raise ProtocolError(c.ReasonCode.CANCELLED)
            process = factory()
            self._attach(process, operation)
            return process

    def finished(self) -> bool:
        with self._lock:
            if self._stopped:
                raise ProtocolError(c.ReasonCode.CANCELLED)
            if self._process is None:
                raise ProtocolError()
            return self._system.finished(self._process)

    @staticmethod
    def _failure() -> c.CleanupOutcome:
        return c.CleanupOutcome(
            "failed", remaining_refs=("owned-linux-runner-group",),
            errors=(c.SafeError(
                c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
                next_action="Inspect the exact owned Linux runner group; launcher exit is not proof.",
            ),),
        )

    def _teardown(self, process: subprocess.Popen[bytes]) -> c.CleanupOutcome:
        try:
            with self._io.span("worker.group", self._operation):
                try:
                    self._system.signal(process, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                # Bounded grace, then kill ONLY while the created leader is
                # still unreaped. No signal follows wait, even if a probe fails.
                self._system.pause(0.05)
                try:
                    self._system.signal(process, cast(int, getattr(signal, "SIGKILL")))
                except ProcessLookupError:
                    pass
                process.wait(timeout=0.5)
                if self._system.exists(process):
                    raise ProtocolError(c.ReasonCode.CLEANUP_FAILED)
        except BaseException:
            return self._failure()
        return c.CleanupOutcome("succeeded")

    def close(self) -> c.CleanupOutcome:
        # Cancellation must stop a factory that is in flight even while its
        # external spawn holds the ownership lock.
        self._stopped = True
        if not self._lock.acquire(timeout=0.1):
            return self._failure()
        try:
            if self._outcome is None:
                self._outcome = (
                    self._teardown(self._process) if self._process is not None
                    else c.CleanupOutcome("succeeded")
                )
            return self._outcome
        finally:
            self._lock.release()
