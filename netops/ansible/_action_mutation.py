"""Protected fixed-action inputs and native guarded push hooks, never authority."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import NoReturn

from netops.core.connection import ConnectionParams, DeviceConnection

from . import contracts as c
from .controller_content import _decode_content, _encode_content
from .controller_observations import _ControllerIo
from .controller_protocol import ProtocolError, _closed, _string


@dataclass(frozen=True, repr=False)
class _MutationSpec:
    commands: tuple[str, ...]
    prestate: bytes
    expected_digest: str
    prestate_ref: str

    def __post_init__(self) -> None:
        if (
            type(self.commands) is not tuple or len(self.commands) > 4096
            or any(
                type(command) is not str or not command.strip()
                or len(command) > 4096 or "\n" in command or "\r" in command
                for command in self.commands
            )
        ):
            raise ProtocolError(c.ReasonCode.INPUT_BINDING_INVALID)
        _encode_content(self.prestate)
        self.prestate.decode("utf-8", errors="strict")
        c.sha256(self.expected_digest)
        c.text(self.prestate_ref)

    def __repr__(self) -> str:
        return "<private>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("private-value")

    def _wire(self) -> dict[str, object]:
        return {
            "commands": list(self.commands), "prestate": _encode_content(self.prestate),
            "expected_digest": self.expected_digest, "prestate_ref": self.prestate_ref,
        }

    def _validate_kind(self, kind: str) -> None:
        if kind not in ("apply", "rollback") or (kind == "apply" and not self.commands):
            raise ProtocolError()
        if kind == "rollback" and (
            self.commands or hashlib.sha256(self.prestate).hexdigest() != self.expected_digest
        ):
            raise ProtocolError()

    @classmethod
    def _parse(cls, value: object) -> _MutationSpec:
        item = _closed(value, {"commands", "prestate", "expected_digest", "prestate_ref"})
        commands = item["commands"]
        if type(commands) is not list:
            raise ProtocolError()
        return cls(
            tuple(_string(command) for command in commands), _decode_content(item["prestate"]),
            _string(item["expected_digest"]), _string(item["prestate_ref"]),
        )


class _ActionConnection(DeviceConnection):
    """Observe actual native I/O without logging commands, output or credentials."""

    def __init__(
        self, connection: DeviceConnection, io: _ControllerIo, operation: str, context: str,
        target: str, step: str,
    ) -> None:
        super().__init__(connection.params)
        self._native, self._io, self._operation, self._context = connection, io, operation, context
        self._target, self._step = target, step

    def send(self, command: str, expect_string: str | None = None) -> str:
        with self._io.span(
            "action.read", self._operation, self._context, target=self._target, step=self._step,
        ):
            return self._native.send(command, expect_string=expect_string)

    def send_config(self, commands: list[str]) -> str:
        with self._io.span(
            "action.write", self._operation, self._context, target=self._target, step=self._step,
        ):
            return self._native.send_config(commands)


class _ActionMutationHooks:
    """Native hooks subordinate to live private host checks and one mutation permit."""

    def __init__(
        self, spec: _MutationSpec, credential: dict[str, object], jump: object,
        check: Callable[[], None], admit: Callable[[], None],
        io: _ControllerIo, operation: str, context: str,
        target: str = "none", step: str = "none",
    ) -> None:
        self._spec, self._credential, self._jump = spec, credential, jump
        self._check, self._admit = check, admit
        self._io, self._operation, self._context = io, operation, context
        self._target, self._step = target, step
        self.issued = self.verified = self.connection_opened = self.cleanup_failed = False

    @contextmanager
    def connect(self, params: ConnectionParams) -> Iterator[DeviceConnection]:
        from .action_runtime import _StrictConnection

        self.check()
        connection = _StrictConnection(self._credential, self._jump)
        try:
            with self._io.span(
                "action.connect", self._operation, self._context,
                target=self._target, step=self._step,
            ):
                connection.connect()
            self.connection_opened = True
            yield _ActionConnection(
                connection, self._io, self._operation, self._context, self._target, self._step,
            )
        finally:
            try:
                with self._io.span(
                    "action.close", self._operation, self._context,
                    target=self._target, step=self._step,
                ):
                    connection.disconnect()
            except BaseException:
                self.cleanup_failed = True
                # Cleanup is an independent fact, not a replacement for the
                # command failure or a reason to discard a verified poststate.

    def check(self) -> None:
        self._check()

    def prestate(self, content: str) -> None:
        self.check()
        if content.encode("utf-8") != self._spec.prestate:
            raise ProtocolError(c.ReasonCode.INPUT_BINDING_INVALID)

    def mutating(self) -> None:
        if self.issued:
            raise ProtocolError(c.ReasonCode.CONSENT_STALE)
        self._admit()
        # A transport exception after admission cannot prove no remote write.
        self.issued = True

    def confirm(self, before: str, after: str) -> bool:
        self.check()
        self.verified = hashlib.sha256(after.encode("utf-8")).hexdigest() == (
            self._spec.expected_digest
        )
        return self.verified


def _run_mutation(
    kind: str, spec: _MutationSpec, credential: dict[str, object], jump: object,
    check: Callable[[], None], admit: Callable[[], None],
    io: _ControllerIo, operation: str, context: str,
    *, target: str = "none", step: str = "none",
) -> dict[str, object]:
    from netops.change.push import _run_guarded_rollback, run_push
    from netops.core.connection import Transport

    spec._validate_kind(kind)
    params = ConnectionParams(
        host=_string(credential["host"]), device_type=_string(credential["vendor"]),
        transport=Transport.SSH,
    )
    hooks = _ActionMutationHooks(
        spec, credential, jump, check, admit, io, operation, context, target, step,
    )
    started = io._time()
    io._record("action.mutation", "started", 0.0, operation, context, target=target, step=step)
    record = (
        run_push(params, list(spec.commands), commit=True, operator="companion", hooks=hooks)
        if kind == "apply"
        else _run_guarded_rollback(params, spec.prestate.decode("utf-8"), hooks)
    )
    succeeded = hooks.verified and record.confirmed and record.error is None
    io._record(
        "action.mutation", "succeeded" if succeeded else "failed",
        io._time() - started, operation, context,
        None if succeeded else c.ReasonCode.APPLY_FAILED,
        target=target, step=step,
    )
    return {
        "status": "succeeded" if succeeded else "failed", "attempted": True,
        "changed": hooks.issued, "line_count": 0,
        "remote_state": (
            ("rolled-back" if kind == "rollback" else "confirmed") if succeeded
            else ("uncertain" if hooks.issued else "unchanged")
        ),
        "mutation": {
            "issued": hooks.issued, "committed": record.committed,
            "confirmed": record.confirmed, "rolled_back": record.rolled_back,
            "poststate_verified": hooks.verified, "cleanup_failed": hooks.cleanup_failed,
            "connection_opened": hooks.connection_opened,
        },
    }
