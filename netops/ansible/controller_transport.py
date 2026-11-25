"""Private bounded socket framing shared by worker and owned process adapter."""

from __future__ import annotations

import select
import socket
import struct
import time
from typing import cast

from . import contracts as c
from .controller_protocol import (
    _MAX_FRAME,
    ProtocolError,
    _decode_frame,
    _encode_frame,
)


def _unix_family() -> socket.AddressFamily:
    # Do not advertise a POSIX socket or substitute TCP when unavailable.
    return cast(socket.AddressFamily, getattr(socket, "AF_UNIX"))


class _SocketFrames:
    """Keep partial bytes across waits; a fragment never restarts the deadline."""

    def __init__(self, channel: socket.socket) -> None:
        self._channel = channel
        self._buffer = bytearray()

    def send(self, value: dict[str, object], timeout: float = 2.0) -> None:
        self._channel.settimeout(timeout)
        try:
            self._channel.sendall(_encode_frame(value))
        except (OSError, ValueError):
            raise ProtocolError(c.ReasonCode.CONTROL_LOST) from None

    def receive(self, timeout: float, cancel: c.CancelPort | None = None) -> dict[str, object]:
        deadline = time.monotonic() + min(timeout, 120.0)
        try:
            while True:
                if len(self._buffer) >= 4:
                    size = struct.unpack(">I", self._buffer[:4])[0]
                    if not 0 < size <= _MAX_FRAME:
                        raise ProtocolError()
                    if len(self._buffer) >= size + 4:
                        data = bytes(self._buffer[:size + 4])
                        del self._buffer[:size + 4]
                        return _decode_frame(data)
                remaining = deadline - time.monotonic()
                if remaining <= 0 or (cancel is not None and cancel.is_cancelled()):
                    raise ProtocolError(c.ReasonCode.CONTROL_LOST)
                ready, _, _ = select.select([self._channel], [], [], min(0.05, remaining))
                if not ready:
                    continue
                part = self._channel.recv(min(65536, _MAX_FRAME + 4 - len(self._buffer)))
                if not part:
                    raise ProtocolError(c.ReasonCode.CONTROL_LOST)
                self._buffer.extend(part)
        except (OSError, ValueError):
            raise ProtocolError(c.ReasonCode.CONTROL_LOST) from None

    def close(self) -> None:
        self._channel.close()

    def receive_one(self, timeout: float = 2.0) -> dict[str, object]:
        """Require one frame followed by EOF on an individual broker connection."""
        started = time.monotonic()
        result = self.receive(timeout)
        if self._buffer:
            raise ProtocolError()
        self._channel.settimeout(max(0.001, timeout - (time.monotonic() - started)))
        try:
            if self._channel.recv(1) != b"":
                raise ProtocolError()
        except OSError:
            raise ProtocolError(c.ReasonCode.CONTROL_LOST) from None
        return result
