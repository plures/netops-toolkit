"""Joined, credential-free HTTPS helper with an original whole-transport budget."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
from http.client import HTTPMessage

from netops.ansible import contracts as c

__all__: tuple[str, ...] = ()

# Only stdlib network code runs in this child. No source/module import, shell,
# cache, filesystem write, package hook or descendant process is requested.
# DNS/connect/redirect/body stalls can therefore be terminated by this exact
# owned PID without abandoning a resolver thread in the caller.
_HTTPS_CHILD = """
import json, socket, ssl, sys, urllib.error, urllib.parse, urllib.request
url, timeout, limit = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
def origin(value):
    p = urllib.parse.urlsplit(value)
    if (p.scheme != 'https' or p.username is not None or p.password is not None
        or p.fragment or p.query or p.port not in (None, 443) or not p.hostname
        or any(ord(char) < 33 for char in value)):
        raise ValueError()
    return p.hostname
class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if origin(req.full_url) != origin(newurl):
            raise ValueError()
        return super().redirect_request(req, fp, code, msg, headers, newurl)
def header(value):
    sys.stdout.buffer.write(json.dumps(value, separators=(',', ':')).encode() + b'\\n')
try:
    origin(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())
    request = urllib.request.Request(url, headers={'Accept': 'application/octet-stream'})
    with opener.open(request, timeout=timeout) as response:
        final = response.geturl()
        if origin(final) != origin(url):
            raise ValueError()
        raw = getattr(getattr(response, 'fp', None), 'raw', None)
        sock = getattr(raw, '_sock', None)
        if not isinstance(sock, socket.socket):
            raise ValueError()
        sock.settimeout(min(0.5, timeout))
        chunks, count = [], 0
        while count < limit:
            value = response.read1(min(65536, limit - count))
            if not value:
                break
            if type(value) is not bytes or len(value) > limit - count:
                raise ValueError()
            chunks.append(value)
            count += len(value)
        header({'status': 'ok', 'url': final})
        for value in chunks:
            sys.stdout.buffer.write(value)
except urllib.error.HTTPError as error:
    header({'status': 'http', 'code': error.code})
except (urllib.error.URLError, OSError) as error:
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    status = ('tls' if isinstance(reason, ssl.SSLError) else
              'timeout' if isinstance(reason, TimeoutError) else
              'connection' if isinstance(reason, ConnectionError) else 'io')
    header({'status': status})
except Exception:
    header({'status': 'invalid'})
"""


def _read(
    url: str, timeout: float, limit: int, clock: c.ClockPort, cancel: c.CancelPort,
) -> tuple[str, bytes]:
    """Terminate and join one owned helper on cancellation or the first deadline."""
    # The caller validates origin, size and the latched source clock. Keep the
    # entire process startup/pipe/teardown inside the original remaining span.
    started = c.finite(clock.monotonic())
    deadline = c.checked_deadline(started, timeout)
    wall_deadline = time.monotonic() + timeout
    if cancel.is_cancelled():
        raise InterruptedError()
    environment = {
        key: value for key, value in os.environ.items()
        if key.upper() in ("SYSTEMROOT", "SYSTEMDRIVE", "WINDIR")
    }
    process = subprocess.Popen(
        (sys.executable, "-I", "-B", "-c", _HTTPS_CHILD, url, str(timeout), str(limit)),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=environment, shell=False,
    )
    chunks: list[bytes] = []
    exceeded, failed, tick = threading.Event(), threading.Event(), threading.Event()

    def read() -> None:
        count = 0
        try:
            assert process.stdout is not None
            while True:
                value = process.stdout.read(65536)
                if not value:
                    return
                count += len(value)
                if count > limit + 8192:
                    exceeded.set()
                elif not exceeded.is_set():
                    chunks.append(value)
        except (OSError, ValueError):
            failed.set()

    reader = threading.Thread(target=read, name="netops-https-output", daemon=False)
    try:
        reader.start()
        while process.poll() is None:
            if cancel.is_cancelled():
                raise InterruptedError()
            remaining = min(deadline - c.finite(clock.monotonic()),
                            wall_deadline - time.monotonic())
            if remaining <= 0.0:
                raise TimeoutError()
            if exceeded.is_set() or failed.is_set():
                raise c.ContractError()
            # Event waiting, not a blocking communicate/open/DNS call, keeps
            # parent cancellation and clock sampling independent of the child.
            tick.wait(min(0.05, remaining))
        if cancel.is_cancelled():
            raise InterruptedError()
        if c.finite(clock.monotonic()) >= deadline or time.monotonic() >= wall_deadline:
            raise TimeoutError()
        reader.join()
        if process.returncode != 0 or exceeded.is_set() or failed.is_set():
            raise c.ContractError()
        output = b"".join(chunks)
        header, separator, content = output.partition(b"\n")
        if not separator or len(header) > 8192 or len(content) > limit:
            raise c.ContractError()
        try:
            result = json.loads(header)
        except (ValueError, UnicodeError):
            raise c.ContractError() from None
        if type(result) is not dict:
            raise c.ContractError()
        if set(result) == {"status", "url"} and result["status"] == "ok":
            if type(result["url"]) is not str:
                raise c.ContractError()
            if cancel.is_cancelled():
                raise InterruptedError()
            if c.finite(clock.monotonic()) >= deadline or time.monotonic() >= wall_deadline:
                raise TimeoutError()
            return result["url"], content
        if content:
            raise c.ContractError()
        if set(result) == {"status", "code"} and result["status"] == "http":
            code = result["code"]
            if type(code) is not int or not 100 <= code <= 599:
                raise c.ContractError()
            raise urllib.error.HTTPError(url, code, "asset-http-failed", HTTPMessage(), None)
        if set(result) == {"status"} and result["status"] in ("timeout", "connection"):
            reason = TimeoutError() if result["status"] == "timeout" else ConnectionError()
            raise urllib.error.URLError(reason)
        # Trust/redirect/format/unknown IO failures are never transient retries.
        raise c.ContractError()
    finally:
        try:
            if process.poll() is None:
                process.kill()
        finally:
            try:
                process.wait()
            finally:
                try:
                    if reader.ident is not None:
                        reader.join()
                finally:
                    if process.stdout is not None:
                        process.stdout.close()
