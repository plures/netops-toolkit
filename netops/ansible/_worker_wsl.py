"""Linux-side inherited-frame supervisor with private owned-group proof."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import queue
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from . import contracts as c
from ._controller_pipe import _Frames, _PipeFrames
from ._controller_wsl import _binding, _proof
from ._worker_group import _OwnedLinuxGroup
from .controller_installation import _OwnedInstallationVerifier, _require_runtime_members
from .controller_observations import _ControllerIo
from .controller_protocol import (
    ProtocolError,
    _BudgetWindow,
    _closed,
    _encode_frame,
    _integer,
    _string,
    _time,
)

if TYPE_CHECKING:
    from .worker import _Cancelled


def _runtime_evidence(start: dict[str, object]) -> None:
    """Consume exact packaged qualification AND current private Linux byte pins.

    No qualification is generated here. The legitimate Q03 record must bind
    the full consuming tuple, installation and context plus every required
    runtime file, including the interpreter and this concrete transport.
    """
    lock = _OwnedInstallationVerifier._qualification_lock()
    if lock.get("state") != "qualified":
        raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
    matches = [
        item for item in lock.get("qualified", ()) if type(item) is dict
        and item.get("state") == "qualified" and item.get("platform") == "windows-wsl"
        and item.get("context_digest") == start["context_digest"]
        and item.get("installation_digest") == start["installation_digest"]
        and item.get("evidence_digest") == start["qualification_digest"]
    ]
    if len(matches) != 1 or set(matches[0].get("tuple", {})) != set(lock["required_tuple"]):
        raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
    evidence = matches[0]
    root = Path(_string(evidence["linux_root"], 4096))
    if not root.is_absolute() or ".." in root.parts:
        raise ProtocolError()
    root_before = _OwnedInstallationVerifier._private(root, directory=True)
    pins = evidence.get("runtime_pins")
    if type(pins) is not list or not pins or len(pins) > 32768:
        raise ProtocolError()
    paths: set[str] = set()
    total = 0
    for pin in pins:
        item = _closed(pin, {"path", "digest"})
        path = Path(_string(item["path"], 4096))
        digest = c.sha256(item["digest"])
        if not path.is_absolute() or path.as_posix() in paths or ".." in path.parts:
            raise ProtocolError()
        try:
            relative = path.relative_to(root)
        except ValueError:
            raise ProtocolError() from None
        if not relative.parts:
            raise ProtocolError()
        for index in range(1, len(relative.parts)):
            _OwnedInstallationVerifier._private(
                root.joinpath(*relative.parts[:index]), directory=True,
            )
        paths.add(path.as_posix())
        # Check the installed owned tree, not system / or an adopted directory.
        # Every supplied file itself must be private, singly linked and owned.
        before = _OwnedInstallationVerifier._private(path, directory=False)
        total += before.st_size
        if before.st_size > 256 * 1024 * 1024 or total > 1024 * 1024 * 1024:
            raise ProtocolError()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            if _OwnedInstallationVerifier._stamp(os.fstat(source.fileno())) != (
                _OwnedInstallationVerifier._stamp(before)
            ):
                raise ProtocolError()
            hasher = hashlib.sha256()
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
            if (
                hasher.hexdigest() != digest
                or _OwnedInstallationVerifier._stamp(os.fstat(source.fileno()))
                != _OwnedInstallationVerifier._stamp(before)
            ):
                raise ProtocolError()
        if _OwnedInstallationVerifier._stamp(path.lstat()) != _OwnedInstallationVerifier._stamp(before):
            raise ProtocolError()
    python = _string(evidence["python"], 4096)
    if python != sys.executable:
        raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
    _require_runtime_members(list(paths), python, paths)
    for member in (
        "_controller_pipe.py", "_controller_wsl.py", "_worker_group.py", "_worker_wsl.py",
    ):
        if not any(path.endswith("/netops/ansible/" + member) for path in paths):
            raise ProtocolError()
    observed: set[str] = set()
    for parent, directories, files in os.walk(root, followlinks=False):
        for child in directories:
            _OwnedInstallationVerifier._private(Path(parent) / child, directory=True)
        for child in files:
            selected = Path(parent) / child
            _OwnedInstallationVerifier._private(selected, directory=False)
            observed.add(selected.as_posix())
        if len(observed) > 32768:
            raise ProtocolError()
    if observed != paths or _OwnedInstallationVerifier._stamp(root.lstat()) != (
        _OwnedInstallationVerifier._stamp(root_before)
    ):
        raise ProtocolError()


class _StartupWatch:
    """Separate startup origin; stalled verification cannot outlive control loss."""

    def __init__(
        self, clock: c.ClockPort, pipes: _PipeFrames, exit_process: Callable[[int], None],
    ) -> None:
        self._clock, self._pipes, self._exit = clock, pipes, exit_process
        self._origin = _time(clock.monotonic())
        self._last = self._origin
        self._deadline = _time(self._origin + 2.0)
        self._accepted = False
        self._closed = threading.Event()
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._watch, daemon=True)
        self._thread.start()

    def accept(self, remaining_ms: object) -> None:
        value = _integer(remaining_ms, 1, 120000)
        with self._lock:
            now = _time(self._clock.monotonic())
            if self._accepted or now < self._last or now >= self._deadline:
                raise ProtocolError(c.ReasonCode.DEADLINE_EXCEEDED)
            self._accepted = True
            # This is one explicit startup budget, not a nonce/execution budget.
            # Anchor at process entry, NEVER receipt/verification completion.
            self._deadline = _time(self._origin + value / 1000)
            self._last = now
            if now >= self._deadline:
                raise ProtocolError(c.ReasonCode.DEADLINE_EXCEEDED)

    def _watch(self) -> None:
        while not self._closed.wait(0.025):
            try:
                with self._lock:
                    now = _time(self._clock.monotonic())
                    expired = now < self._last or now >= self._deadline
                    self._last = now
                if not expired and not self._pipes.failed.is_set():
                    continue
            except BaseException:
                pass
            _ControllerIo()._record(
                "worker.exit", "failed", 0.0, "none", "none", c.ReasonCode.CONTROL_LOST,
            )
            self._exit(3)
            return

    def close(self) -> None:
        self._closed.set()
        self._thread.join(timeout=0.1)


class _WslWorkerFrames:
    """Independent cancellation reader, separate one-use logical input channel.

    WSL cannot inherit a Windows socket descriptor as a Linux FD. The private
    inherited stdin/stdout tunnel carries closed control frames; exactly one
    input frame is materialized in memory and its independent source is closed
    before any runner/fork. No socket TCP, credential environment or disk fallback.
    """

    def __init__(
        self, pipes: _Frames, start: dict[str, object], cancel: _Cancelled,
        group: _OwnedLinuxGroup,
        *, exit_process: Callable[[int], None] = os._exit,
    ) -> None:
        self._pipes, self._start, self._cancel, self._group = pipes, start, cancel, group
        self._key = _string(start["key"], 64)
        self._bound = c.sha256(start["binding"])
        self._challenge = c.sha256(start["challenge"])
        self._nonce = ""
        self._responses: queue.Queue[dict[str, object]] = queue.Queue(1)
        self._inputs: queue.Queue[dict[str, object]] = queue.Queue(1)
        self._closed = threading.Event()
        self._revoked = threading.Event()
        self._window: _BudgetWindow | None = None
        self._exit_process = exit_process
        self._exit_armed = threading.Event()
        self._io = _ControllerIo()
        self._operation = "none"
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._watcher = threading.Thread(target=self._watch, daemon=True)
        self._reader.start()
        self._watcher.start()

    def _revoke(self) -> None:
        self._revoked.set()
        # The concrete worker owns this latch. Set it BEFORE locks/group I/O.
        self._cancel._event.set()
        if self._window is not None:
            self._window._revoked = True

    def _stop(self, *, acknowledged: bool) -> None:
        self._revoke()
        # Bound the supervisor itself even if worker input/spawn/broker I/O
        # stalls. This only exits THIS Linux process; no wire PID or global kill.
        # Failed/unverified runner cleanup still remains an honest failure.
        if not self._exit_armed.is_set():
            self._exit_armed.set()

            def finish() -> None:
                if not self._closed.wait(2.0):
                    self._io._record(
                        "worker.exit", "failed", 2.0, self._operation,
                        _string(self._start["context_digest"]), c.ReasonCode.CONTROL_LOST,
                    )
                    self._exit_process(3)

            threading.Thread(target=finish, daemon=True).start()
        outcome = self._group.close()
        if acknowledged:
            wire = json.loads(c.canonical_bytes(outcome))
            with self._io.span(
                "worker.control", self._operation, _string(self._start["context_digest"]),
            ):
                self._pipes.send({
                    "kind": "stopped", "cleanup": wire,
                    "proof": _proof(self._key, "stopped", self._nonce, self._bound, wire),
                }, 0.2)

    def _pump(self) -> None:
        input_seen = False
        try:
            while not self._closed.is_set():
                with self._io.span(
                    "worker.control", self._operation, _string(self._start["context_digest"]),
                ):
                    value = self._pipes.receive(2.0)
                if value.get("kind") == "stop":
                    item = _closed(value, {"kind", "proof"})
                    if not self._nonce or not hmac.compare_digest(
                        _string(item["proof"], 64),
                        _proof(self._key, "stop", self._nonce, self._bound),
                    ):
                        raise ProtocolError()
                    self._stop(acknowledged=True)
                    return
                if value.get("kind") == "input":
                    if input_seen:
                        raise ProtocolError()
                    input_seen = True
                    item = _closed(value, {"kind", "payload"})
                    payload = item["payload"]
                    if type(payload) is not dict:
                        raise ProtocolError()
                    self._inputs.put_nowait(payload)
                    del payload, item, value
                else:
                    self._responses.put_nowait(value)
        except BaseException:
            self._stop(acknowledged=False)

    def _watch(self) -> None:
        while not self._closed.wait(0.025):
            try:
                if self._window is not None:
                    self._window.check()
            except BaseException:
                self._stop(acknowledged=False)
                return

    def bind(self, request: c.OperationRequest, plan: str, window: _BudgetWindow) -> None:
        if (
            _binding(request, plan) != self._bound or self._window is not None
            or c.digest(c.ControllerContext(request.context)) != self._start["context_digest"]
        ):
            window._revoked = True
            self._revoke()
            raise ProtocolError()
        self._window = window
        self._operation = request.operation_id
        if self._revoked.is_set():
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)

    def input(self) -> io.BytesIO:
        value = self._take(self._inputs, 2.0)
        return io.BytesIO(_encode_frame(value))

    def _take(
        self, source: queue.Queue[dict[str, object]], timeout: float,
        cancel: c.CancelPort | None = None,
    ) -> dict[str, object]:
        last, deadline = _PipeFrames._deadline(timeout)
        while True:
            now = _time(time.monotonic())
            if (
                now < last or now >= deadline or self._revoked.is_set()
                or (cancel is not None and cancel.is_cancelled())
            ):
                self._revoke()
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
            last = now
            try:
                return source.get(timeout=min(0.025, deadline - now))
            except queue.Empty:
                continue

    def send(self, value: dict[str, object], timeout: float = 2.0) -> None:
        if value.get("kind") == "ready":
            item = _closed(value, {"kind", "nonce"})
            if self._nonce:
                raise ProtocolError()
            self._nonce = c.sha256(item["nonce"])
            value = {
                "kind": "ready", "nonce": self._nonce,
                "proof": _proof(self._key, "ready", self._nonce, self._bound, self._challenge),
            }
        self._pipes.send(value, timeout)

    def receive(
        self, timeout: float, cancel: c.CancelPort | None = None,
    ) -> dict[str, object]:
        return self._take(self._responses, min(timeout, 2.0), cancel)

    def close(self) -> c.CleanupOutcome:
        self._closed.set()
        self._revoke()
        result = self._group.close()
        self._reader.join(timeout=0.05)
        self._watcher.join(timeout=0.05)
        self._key = ""
        return result


def _run_stdio() -> int:
    # Imported only at the fixed entry point, never at import/preview time.
    from .worker import _Cancelled, _Clock, _run_private

    if sys.platform != "linux":
        return 3
    pipes = _PipeFrames(sys.stdin.buffer, sys.stdout.buffer)
    observations = _ControllerIo()
    startup = _StartupWatch(_Clock(), pipes, os._exit)
    channel: _WslWorkerFrames | None = None
    try:
        with observations.span("worker.startup"):
            start = _closed(pipes.receive(2.0), {
                "kind", "key", "challenge", "binding", "root", "context_digest",
                "installation_digest", "qualification_digest",
                "startup_remaining_ms",
            })
        if start["kind"] != "start":
            raise ProtocolError()
        startup.accept(start["startup_remaining_ms"])
        for field in ("key", "challenge", "binding", "context_digest",
                      "installation_digest", "qualification_digest"):
            c.sha256(start[field])
        root = Path(_string(start["root"], 4096))
        if not root.is_absolute() or ".." in root.parts:
            raise ProtocolError()
        with observations.span("worker.verify", context=_string(start["context_digest"])):
            _OwnedInstallationVerifier._private(root, directory=True)
            _runtime_evidence(start)
        cancel = _Cancelled()
        group = _OwnedLinuxGroup()
        channel = _WslWorkerFrames(pipes, start, cancel, group)
        startup.close()
        # _run_private owns readiness timing before input is read. Its source
        # callable obtains one separate in-memory frame, then it closes it.
        return _run_private(
            channel.input, channel, root, _Clock(), cancel, group=group,
            bind=channel.bind,
        )
    except BaseException:
        return 3
    finally:
        startup.close()
        if channel is not None:
            channel.close()
        pipes.close()
