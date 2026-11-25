"""Bounded protected content channel, never an Ansible result or public DTO."""

from __future__ import annotations

import base64
import binascii
from typing import NoReturn

from .controller_protocol import ProtocolError

_CONTENT_LIMIT = 512 * 1024


class _NativeRead:
    """Keep collected bytes separate from the minimized callback result."""

    __slots__ = ("result", "content")

    def __init__(self, result: dict[str, object], content: bytes) -> None:
        if type(content) is not bytes or len(content) > _CONTENT_LIMIT:
            raise ProtocolError()
        self.result, self.content = result, content

    def __repr__(self) -> str:
        return "<private>"

    def __getitem__(self, key: str) -> object:
        """Expose only minimized facts to existing private native consumers."""
        return self.result[key]

    def __reduce__(self) -> NoReturn:
        raise TypeError("private-value")


def _encode_content(content: bytes) -> str:
    if type(content) is not bytes or len(content) > _CONTENT_LIMIT:
        raise ProtocolError()
    return base64.b64encode(content).decode("ascii")


def _decode_content(value: object) -> bytes:
    if type(value) is not str or len(value) > ((_CONTENT_LIMIT + 2) // 3) * 4:
        raise ProtocolError()
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ProtocolError() from None
    if len(result) > _CONTENT_LIMIT or _encode_content(result) != value:
        raise ProtocolError()
    return result
