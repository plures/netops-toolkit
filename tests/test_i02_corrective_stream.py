"""Exercise the actual production body loop with process-local socket-pair I/O."""

import socket
import threading
import time
from datetime import datetime, timezone

import pytest

from netops.dependencies._assets import HttpsAssetTransport


class Clock:
    def monotonic(self):
        return time.monotonic()

    def utc_now(self):
        return datetime.now(timezone.utc)


class Cancel:
    def __init__(self):
        self.event = threading.Event()

    def is_cancelled(self):
        return self.event.is_set()

    def wait(self, timeout):
        return self.event.wait(timeout)


class Body:
    def __init__(self, stream):
        self.stream = stream

    def read1(self, maximum):
        return self.stream.recv(maximum)


def test_slow_stream_cannot_renew_aggregate_body_deadline():
    reader, writer = socket.socketpair()
    stop = threading.Event()

    def drip():
        try:
            while not stop.wait(0.01):
                writer.sendall(b"x")
        except OSError:
            pass

    thread = threading.Thread(target=drip)
    thread.start()
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            HttpsAssetTransport._body(
                Body(reader), reader, "https://files.pythonhosted.org/exact.whl",
                100000, Clock(), Cancel(), started + 0.2,
            )
        assert time.monotonic() - started < 2.0
    finally:
        stop.set()
        reader.close()
        writer.close()
        thread.join(timeout=2.0)
    assert not thread.is_alive()
    assert not any(thread.name == "netops-asset-body" for thread in threading.enumerate())


def test_cancel_interrupts_an_actual_blocked_body_read_without_waiting_for_more_bytes():
    reader, writer = socket.socketpair()
    cancel = Cancel()
    timer = threading.Timer(0.1, cancel.event.set)
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(InterruptedError):
            HttpsAssetTransport._body(
                Body(reader), reader, "https://files.pythonhosted.org/exact.whl",
                10000, Clock(), cancel, started + 10.0,
            )
        assert time.monotonic() - started < 2.0
    finally:
        timer.cancel()
        timer.join()
        reader.close()
        writer.close()
    assert not any(thread.name == "netops-asset-body" for thread in threading.enumerate())


def test_finished_body_stops_watchdog_and_preserves_exact_bytes():
    reader, writer = socket.socketpair()
    try:
        writer.sendall(b"exact reviewed bytes")
        writer.shutdown(socket.SHUT_WR)
        response = HttpsAssetTransport._body(
            Body(reader), reader, "https://files.pythonhosted.org/exact.whl",
            100, Clock(), Cancel(), time.monotonic() + 10.0,
        )
        assert response.content == b"exact reviewed bytes"
    finally:
        reader.close()
        writer.close()
    assert not any(thread.name == "netops-asset-body" for thread in threading.enumerate())
