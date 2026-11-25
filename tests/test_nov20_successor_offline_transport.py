"""Independent T03 real owned offline helper deadlines; zero network/services."""

from __future__ import annotations

import json
import subprocess
import threading
import time
import urllib.error

import pytest

from netops.ansible import contracts as c
from netops.dependencies import _https_process as transport

URL = "https://www.python.org/independent-offline-fixture"
SENTINEL = "NOV20_UNSELECTED_ENV_PRIVATE_SENTINEL"


class Clock:
    def monotonic(self):
        return time.monotonic()


class Cancel:
    def __init__(self):
        self.event = threading.Event()

    def is_cancelled(self):
        return self.event.is_set()


def offline(monkeypatch, code):
    """Instrument only the fixed child implementation; never reach a URL."""
    monkeypatch.setattr(transport, "_HTTPS_CHILD", code)
    children = []
    actual = subprocess.Popen

    def spawn(*args, **kwargs):
        assert kwargs["shell"] is False
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert SENTINEL not in str(kwargs["env"])
        assert set(kwargs["env"]) <= {"SYSTEMROOT", "SYSTEMDRIVE", "WINDIR"}
        child = actual(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(transport.subprocess, "Popen", spawn)
    return children


def joined(children):
    assert len(children) == 1
    assert children[0].poll() is not None
    assert children[0].stdout.closed
    assert not any(thread.name == "netops-https-output" for thread in threading.enumerate())


def test_t03_actual_owned_child_returns_exact_body_without_environment_credentials(monkeypatch):
    monkeypatch.setenv("NOV20_UNSELECTED_SECRET", SENTINEL)
    children = offline(monkeypatch, (
        "import json,sys;sys.stdout.buffer.write("
        "json.dumps({'status':'ok','url':sys.argv[1]}).encode()+b'\\nowned-body')"
    ))
    assert transport._read(URL, 5.0, 10, Clock(), Cancel()) == (URL, b"owned-body")
    joined(children)


def test_t03_whole_transport_stall_has_original_bounded_deadline_and_actual_join(monkeypatch):
    children = offline(monkeypatch, "import time;time.sleep(30)")
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        transport._read(URL, 0.25, 128, Clock(), Cancel())
    assert time.monotonic() - started < 3.0
    joined(children)


def test_t03_parent_cancel_stalled_owned_transport_joins_without_new_attempt(monkeypatch):
    children = offline(monkeypatch, "import time;time.sleep(30)")
    cancel = Cancel()
    timer = threading.Timer(0.2, cancel.event.set)
    started = time.monotonic()
    timer.start()
    try:
        with pytest.raises(InterruptedError):
            transport._read(URL, 5.0, 128, Clock(), cancel)
    finally:
        timer.cancel()
        timer.join(1.0)
    assert time.monotonic() - started < 3.0
    joined(children)


@pytest.mark.parametrize("header,body", [
    ({"status": "ok"}, b""),
    ({"status": "ok", "url": 1}, b""),
    ({"status": "ok", "url": URL}, b"x" * 129),
    ({"status": "http", "code": True}, b""),
    ({"status": "http", "code": 503}, b"unexpected body"),
    ({"status": "tls"}, b""),
    ({"status": "invalid"}, b""),
    ({"status": "ok", "url": URL, "unknown": True}, b""),
])
def test_t03_malformed_or_untrusted_helper_result_is_safe_nonsuccess_and_joined(
    monkeypatch, header, body,
):
    raw = json.dumps(header).encode() + b"\n" + body
    children = offline(monkeypatch, "import sys;sys.stdout.buffer.write(" + repr(raw) + ")")
    with pytest.raises(c.ContractError) as error:
        transport._read(URL, 5.0, 128, Clock(), Cancel())
    assert error.value.reason == "invalid-request"
    joined(children)


@pytest.mark.parametrize("status", ["timeout", "connection"])
def test_t03_only_named_transient_helper_error_can_reach_bounded_retry_owner(monkeypatch, status):
    raw = json.dumps({"status": status}).encode() + b"\n"
    children = offline(monkeypatch, "import sys;sys.stdout.buffer.write(" + repr(raw) + ")")
    with pytest.raises(urllib.error.URLError) as error:
        transport._read(URL, 5.0, 128, Clock(), Cancel())
    assert isinstance(error.value.reason, TimeoutError if status == "timeout" else ConnectionError)
    joined(children)


def test_t03_cancel_before_helper_creation_has_zero_owned_processes(monkeypatch):
    children = offline(monkeypatch, "raise AssertionError('must not execute')")
    cancel = Cancel()
    cancel.event.set()
    with pytest.raises(InterruptedError):
        transport._read(URL, 5.0, 128, Clock(), cancel)
    assert not children
