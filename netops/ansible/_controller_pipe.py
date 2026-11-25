"""Bounded inherited pipe frames; no socket, file or environment fallback."""

from __future__ import annotations

import queue
import threading
import time
from typing import BinaryIO, Protocol

from . import contracts as c
from ._windows_job import _interrupt_pipe_thread
from .controller_protocol import ProtocolError, _encode_frame, _read_frame, _time


class _Frames(Protocol):
    def send(self, value: dict[str, object], timeout: float = 2.0) -> None: ...

    def receive(
        self, timeout: float, cancel: c.CancelPort | None = None,
    ) -> dict[str, object]: ...


class _PipeFrames:
    """Single reader/writer with bounded queues and original per-call deadlines.

    Blocking OS pipe I/O lives in owned daemon threads. A timeout invalidates
    the entire channel, never starts a second reader/writer or retries a frame.
    close reports stalled handles instead of pretending that closing a Windows
    launcher proves anything about its Linux descendants.
    """

    def __init__(self, source: BinaryIO, sink: BinaryIO) -> None:
        self._source, self._sink = source, sink
        self._incoming: queue.Queue[dict[str, object]] = queue.Queue(1)
        self._outgoing: queue.Queue[tuple[bytes, threading.Event]] = queue.Queue(1)
        self.failed = threading.Event()
        self._closed = threading.Event()
        self._send_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._closer: threading.Thread | None = None
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._writer = threading.Thread(target=self._write, daemon=True)
        self._reader.start()
        self._writer.start()

    def _read(self) -> None:
        try:
            while not self._closed.is_set():
                value = _read_frame(self._source)
                while not self._closed.is_set():
                    try:
                        self._incoming.put(value, timeout=0.025)
                        break
                    except queue.Full:
                        continue
        except BaseException:
            self.failed.set()

    def _write(self) -> None:
        try:
            while not self._closed.is_set():
                try:
                    data, completed = self._outgoing.get(timeout=0.025)
                except queue.Empty:
                    continue
                view = memoryview(data)
                while view:
                    count = self._sink.write(view)
                    if type(count) is not int or count <= 0 or count > len(view):
                        raise ProtocolError(c.ReasonCode.CONTROL_LOST)
                    view = view[count:]
                self._sink.flush()
                del data, view
                completed.set()
        except BaseException:
            self.failed.set()

    @staticmethod
    def _deadline(timeout: float) -> tuple[float, float]:
        if type(timeout) is not float or not 0 < timeout <= 120.0:
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
        started = _time(time.monotonic())
        return started, _time(started + timeout)

    def send(self, value: dict[str, object], timeout: float = 2.0) -> None:
        started, deadline = self._deadline(timeout)
        last = started
        if not self._send_lock.acquire(timeout=timeout):
            self.failed.set()
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
        try:
            if self.failed.is_set() or self._closed.is_set():
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
            done = threading.Event()
            try:
                self._outgoing.put_nowait((_encode_frame(value), done))
            except queue.Full:
                raise ProtocolError(c.ReasonCode.CONTROL_LOST) from None
            while not done.wait(0.01):
                now = _time(time.monotonic())
                if now < last or now >= deadline or self.failed.is_set():
                    raise ProtocolError(c.ReasonCode.CONTROL_LOST)
                last = now
        except BaseException:
            self.failed.set()
            raise
        finally:
            self._send_lock.release()

    def receive(
        self, timeout: float, cancel: c.CancelPort | None = None,
    ) -> dict[str, object]:
        started, deadline = self._deadline(timeout)
        last = started
        while True:
            now = _time(time.monotonic())
            if (
                now < last or now >= deadline or self._closed.is_set()
                or (cancel is not None and cancel.is_cancelled())
            ):
                self.failed.set()
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
            last = now
            try:
                return self._incoming.get(timeout=min(0.025, deadline - now))
            except queue.Empty:
                if self.failed.is_set():
                    raise ProtocolError(c.ReasonCode.CONTROL_LOST) from None

    def close(self, timeout: float = 0.15) -> bool:
        """Bound closing even if a foreign OS read/write cannot be interrupted."""
        if type(timeout) is not float or not 0 <= timeout <= 2.0:
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
        deadline = time.monotonic() + timeout
        self._closed.set()
        for thread in (self._reader, self._writer):
            try:
                _interrupt_pipe_thread(thread)
            except BaseException:
                self.failed.set()

        def close_handles() -> None:
            for stream in (self._source, self._sink):
                try:
                    stream.close()
                except BaseException:
                    self.failed.set()

        with self._close_lock:
            if self._closer is None:
                self._closer = threading.Thread(target=close_handles, daemon=True)
                self._closer.start()
            closer = self._closer
        for thread in (closer, self._reader, self._writer):
            thread.join(timeout=max(0.0, min(0.05, deadline - time.monotonic())))
        return not any(thread.is_alive() for thread in (closer, self._reader, self._writer))
