"""Closed private controller messages; no public consent or clock transport.

These bytes may contain credentials. They must never pass through public wire,
event, inventory, exception, cache or Ansible variable serializers.
"""

from __future__ import annotations

import json
import math
import struct
import threading
from dataclasses import dataclass
from typing import BinaryIO, NoReturn

from . import contracts as c

_MAX_FRAME = 1024 * 1024
_CONTROL_MS = 2000
_PHASES = ("credential", "task", "mutation")
_FIELDS = frozenset((
    "username", "password", "enable_password", "key_passphrase", "ntp_authentication_key",
))
_KINDS = frozenset(("collect", "gather", "apply", "rollback"))


class ProtocolError(RuntimeError):
    """Carry only a closed safe cause, never a rejected value."""

    def __init__(self, reason: c.ReasonCode = c.ReasonCode.HANDOFF_INVALID) -> None:
        self.reason = reason
        super().__init__(reason.value)


def _reject(reason: c.ReasonCode = c.ReasonCode.HANDOFF_INVALID) -> NoReturn:
    raise ProtocolError(reason) from None


def _closed(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        _reject()
    assert isinstance(value, dict)
    if any(type(key) is not str for key in value):
        _reject()
    return value


def _string(value: object, maximum: int = 4096) -> str:
    if type(value) is not str:
        _reject()
    assert isinstance(value, str)
    try:
        if not 0 < len(value.encode("utf-8", errors="strict")) <= maximum or "\x00" in value:
            _reject()
    except UnicodeError:
        _reject()
    return value


def _integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int:
        _reject()
    assert isinstance(value, int)
    if not minimum <= value <= maximum:
        _reject()
    return value


def _time(value: object) -> float:
    if type(value) is not float or not math.isfinite(value) or value < 0:
        _reject(c.ReasonCode.DEADLINE_EXCEEDED)
    assert isinstance(value, float)
    return value


def _pairs(values: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in values:
        if key in result:
            _reject()
        result[key] = value
    return result


def _constant(value: str) -> NoReturn:
    _reject()


def _tree(value: object, depth: int = 0) -> None:
    if depth > 32:
        _reject()
    if type(value) is dict:
        assert isinstance(value, dict)
        for key, item in value.items():
            _string(key)
            _tree(item, depth + 1)
    elif type(value) is list:
        assert isinstance(value, list)
        for item in value:
            _tree(item, depth + 1)
    elif type(value) is str:
        assert isinstance(value, str)
        # Secret strings need not be public-safe text, but must be strict UTF-8.
        value.encode("utf-8", errors="strict")
    elif type(value) is float:
        if not math.isfinite(value):
            _reject()
    elif type(value) is int:
        _integer(value, -c.MAX_SAFE_INT, c.MAX_SAFE_INT)
    elif value is not None and type(value) is not bool:
        # The protocol has integer durations only, never absolute/float clocks.
        _reject()


def _encode_frame(value: dict[str, object]) -> bytes:
    try:
        _tree(value)
        content = json.dumps(
            value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True,
        ).encode("utf-8", errors="strict")
        if not 0 < len(content) <= _MAX_FRAME:
            _reject()
        return struct.pack(">I", len(content)) + content
    except (UnicodeError, ValueError, RecursionError, TypeError):
        _reject()


def _decode_frame(data: bytes) -> dict[str, object]:
    try:
        if type(data) is not bytes or len(data) < 4:
            _reject()
        size = struct.unpack(">I", data[:4])[0]
        if not 0 < size <= _MAX_FRAME or len(data) != size + 4:
            _reject()
        text = data[4:].decode("utf-8", errors="strict")
        if text != text.strip():
            _reject()
        value: object = json.loads(
            text,
            object_pairs_hook=_pairs, parse_constant=_constant,
        )
        _tree(value)
        if type(value) is not dict:
            _reject()
        assert isinstance(value, dict)
        return value
    except (UnicodeError, ValueError, RecursionError, TypeError, struct.error):
        _reject()


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = stream.read(size - len(chunks))
        if not part:
            _reject()
        chunks.extend(part)
    return bytes(chunks)


def _read_frame(stream: BinaryIO, *, eof: bool = False) -> dict[str, object]:
    header = _read_exact(stream, 4)
    size = struct.unpack(">I", header)[0]
    if not 0 < size <= _MAX_FRAME:
        _reject()
    result = _decode_frame(header + _read_exact(stream, size))
    if eof and stream.read(1) != b"":
        _reject()
    return result


@dataclass(frozen=True)
class ControllerBudget:
    """Relative integer budgets; never an absolute monotonic timestamp."""

    ready_nonce: str
    authorization_remaining_ms: int
    operation_remaining_ms: int
    control_timeout_ms: int = _CONTROL_MS

    def __post_init__(self) -> None:
        """Validate all fields, including otherwise unused values."""
        if len(_string(self.ready_nonce, 64)) != 64:
            _reject()
        try:
            if len(bytes.fromhex(self.ready_nonce)) != 32:
                _reject()
        except ValueError:
            _reject()
        _integer(self.authorization_remaining_ms, 1, 300000)
        _integer(self.operation_remaining_ms, 1, 3600000)
        if type(self.control_timeout_ms) is not int or self.control_timeout_ms != _CONTROL_MS:
            _reject()

    @classmethod
    def _parse(cls, value: object) -> ControllerBudget:
        item = _closed(value, {
            "ready_nonce", "authorization_remaining_ms", "operation_remaining_ms",
            "control_timeout_ms",
        })
        return cls(
            _string(item["ready_nonce"], 64),
            _integer(item["authorization_remaining_ms"], 1, 300000),
            _integer(item["operation_remaining_ms"], 1, 3600000),
            _integer(item["control_timeout_ms"], _CONTROL_MS, _CONTROL_MS),
        )

    def _wire(self) -> dict[str, object]:
        return {
            "ready_nonce": self.ready_nonce,
            "authorization_remaining_ms": self.authorization_remaining_ms,
            "operation_remaining_ms": self.operation_remaining_ms,
            "control_timeout_ms": self.control_timeout_ms,
        }


class _BudgetWindow:
    """Single readiness handshake, monotonically shrinking worker deadlines."""

    def __init__(self, clock: c.ClockPort, nonce: str, plan_digest: str) -> None:
        self._clock, self._nonce, self._plan = clock, nonce, plan_digest
        self._started = self._now()
        self._last = self._started
        self._authorization = self._operation = self._started
        self._accepted = False
        self._revoked = False
        self._lock = threading.RLock()

    def _now(self) -> float:
        return _time(self._clock.monotonic())

    def accept(self, budget: ControllerBudget, plan_digest: str) -> None:
        with self._lock:
            if self._accepted or budget.ready_nonce != self._nonce or plan_digest != self._plan:
                _reject()
            budget.__post_init__()
            self._accepted = True
            self._authorization = self._started + budget.authorization_remaining_ms / 1000
            self._operation = self._started + budget.operation_remaining_ms / 1000
            self.check()

    def check(self) -> float:
        with self._lock:
            now = self._now()
            if (
                self._revoked or not self._accepted or now < self._last
                or now >= min(self._authorization, self._operation)
            ):
                self._revoked = True
                _reject(c.ReasonCode.DEADLINE_EXCEEDED)
            self._last = now
            return now

    def reduce(self, budget: ControllerBudget, request_start: float) -> None:
        with self._lock:
            self.check()
            budget.__post_init__()
            if (
                budget.ready_nonce != self._nonce
                or _time(request_start) < self._started or request_start > self._last
            ):
                self._revoked = True
                _reject()
            self._authorization = min(
                self._authorization, request_start + budget.authorization_remaining_ms / 1000,
            )
            self._operation = min(
                self._operation, request_start + budget.operation_remaining_ms / 1000,
            )
            if self._last - request_start >= _CONTROL_MS / 1000:
                self._revoked = True
                _reject(c.ReasonCode.CONTROL_LOST)
            self.check()

    def revoke(self) -> None:
        with self._lock:
            self._revoked = True


@dataclass(frozen=True)
class DispatchBinding:
    """Nonsecret pending-invocation identity, not caller-created permission."""

    operation_id: str
    plan_digest: str
    controller_digest: str
    invocation_id: str
    occurrence_id: str
    target_id: str
    task_id: str
    phase: str
    sequence: int

    def __post_init__(self) -> None:
        """Validate exact UUID/digest identity, phase and ordinal."""
        try:
            c.uuid_text(self.operation_id)
            c.uuid_text(self.invocation_id)
            c.sha256(self.plan_digest)
            c.sha256(self.controller_digest)
            for value in (self.occurrence_id, self.target_id, self.task_id):
                _string(value)
            if self.phase not in _PHASES:
                _reject()
            _integer(self.sequence, 0, c.MAX_SAFE_INT)
        except c.ContractError:
            _reject()

    def _wire(self) -> dict[str, object]:
        return dict(
            operation_id=self.operation_id, plan_digest=self.plan_digest,
            controller_digest=self.controller_digest, invocation_id=self.invocation_id,
            occurrence_id=self.occurrence_id, target_id=self.target_id, task_id=self.task_id,
            phase=self.phase, sequence=self.sequence,
        )

    @classmethod
    def _parse(cls, value: object) -> DispatchBinding:
        item = _closed(value, {
            "operation_id", "plan_digest", "controller_digest", "invocation_id",
            "occurrence_id", "target_id", "task_id", "phase", "sequence",
        })
        return cls(
            _string(item["operation_id"]), _string(item["plan_digest"]),
            _string(item["controller_digest"]), _string(item["invocation_id"]),
            _string(item["occurrence_id"]), _string(item["target_id"]),
            _string(item["task_id"]), _string(item["phase"]),
            _integer(item["sequence"], 0, c.MAX_SAFE_INT),
        )


def _validate_private_payload(value: object, scope: dict[str, object]) -> dict[str, object]:
    """Validate all scope/field/routes before opening broker or device I/O."""
    item = _closed(value, {
        "operation_id", "controller_digest", "route_digest", "targets", "jump",
    })
    for name in ("operation_id", "controller_digest", "route_digest"):
        if item[name] != scope[name]:
            _reject(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
    targets = item["targets"]
    allowed = scope["targets"]
    if type(targets) is not list or type(allowed) is not list or len(targets) != len(allowed):
        _reject()
    assert isinstance(targets, list) and isinstance(allowed, list)
    seen: set[tuple[str, str]] = set()
    for target, selected in zip(targets, allowed):
        entry = _closed(target, {
            "target_id", "task_id", "host", "port", "vendor", "transport", "fields",
            "key_ref", "known_hosts_ref",
        })
        expected = _closed(selected, {
            "target_id", "task_id", "host", "port", "vendor", "transport", "fields",
            "key_ref", "known_hosts_ref",
        })
        fields = entry["fields"]
        if (
            type(fields) is not dict or type(expected["fields"]) is not list
            or set(fields) != set(expected["fields"]) or not set(fields) <= _FIELDS
            or not fields
        ):
            _reject(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        assert isinstance(fields, dict)
        for field in fields.values():
            _string(field, _MAX_FRAME)
        for name in expected:
            if name != "fields" and entry[name] != expected[name]:
                _reject(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        for name in ("target_id", "task_id", "host", "vendor"):
            _string(entry[name])
        _integer(entry["port"], 1, 65535)
        if entry["transport"] not in ("ssh", "ssh2"):
            _reject(c.ReasonCode.ROUTE_UNAVAILABLE)
        _string(entry["known_hosts_ref"])
        if entry["key_ref"] is not None:
            _string(entry["key_ref"])
        identity = (_string(entry["target_id"]), _string(entry["task_id"]))
        if identity in seen:
            _reject()
        seen.add(identity)
    # Jump route is validated identically and is never a selected device.
    jump = item["jump"]
    selected_jump = scope.get("jump")
    if (jump is None) != (selected_jump is None):
        _reject(c.ReasonCode.ROUTE_UNAVAILABLE)
    if jump is not None:
        nested_scope = dict(scope, targets=[selected_jump], jump=None)
        nested = dict(item, targets=[jump], jump=None)
        _validate_private_payload(nested, nested_scope)
        assert isinstance(jump, dict)
        if jump["task_id"] != "route" or any(jump["target_id"] == t[0] for t in seen):
            _reject(c.ReasonCode.ROUTE_UNAVAILABLE)
    return item
