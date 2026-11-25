"""Operation-owned worker socket and fork-inherited private action client."""

from __future__ import annotations

import hmac
import os
import secrets
import socket
import stat
import tempfile
import threading
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import NoReturn, cast

from . import contracts as c
from ._controller_pipe import _Frames
from .controller_content import _decode_content
from .controller_observations import _ControllerIo
from .controller_protocol import (
    ControllerBudget,
    DispatchBinding,
    ProtocolError,
    _BudgetWindow,
    _closed,
    _string,
)
from .controller_transport import _SocketFrames, _unix_family


class _HostChannel:
    def __init__(
        self, frames: _Frames, window: _BudgetWindow, cancel: c.CancelPort,
    ) -> None:
        self._frames, self._window, self._cancel = frames, window, cancel
        self._lock = threading.Lock()
        self._io = _ControllerIo()

    def dispatch(self, binding: DispatchBinding) -> None:
        with self._io.span("broker.dispatch", binding.operation_id, binding.controller_digest):
            self._dispatch(binding)

    def _dispatch(self, binding: DispatchBinding) -> None:
        started = self._window.check()
        if not self._lock.acquire(timeout=2.0):
            self._window.revoke()
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
        try:
            elapsed = self._window.check() - started
            if self._cancel.is_cancelled() or elapsed >= 2.0:
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
            self._frames.send({"kind": "dispatch", "binding": binding._wire()}, 2.0 - elapsed)
            response = _closed(self._frames.receive(
                max(0.001, 2.0 - (self._window.check() - started)), self._cancel,
            ), {"kind", "binding", "budget"})
            if response["kind"] != "permit" or DispatchBinding._parse(response["binding"]) != binding:
                raise ProtocolError()
            self._window.reduce(ControllerBudget._parse(response["budget"]), started)
        except BaseException:
            self._window.revoke()
            raise
        finally:
            self._lock.release()

    def pulse(self) -> None:
        with self._io.span("broker.pulse"):
            self._pulse()

    def _pulse(self, *, required: bool = False) -> None:
        # Heartbeats never carry a fresh budget and cannot renew local expiry.
        started = self._window.check()
        if not self._lock.acquire(timeout=0.25):
            if required:
                self._window.revoke()
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
            return
        try:
            self._frames.send({"kind": "pulse"})
            response = _closed(self._frames.receive(1.0, self._cancel), {"kind"})
            if response["kind"] != "alive" or self._window.check() - started >= 2.0:
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
        except BaseException:
            self._window.revoke()
            raise
        finally:
            self._lock.release()

    def content(self, binding: DispatchBinding, value: object) -> None:
        """Relay protected bytes on the authenticated host channel only."""
        with self._io.span("broker.content", binding.operation_id, binding.controller_digest):
            self._content(binding, value)

    def _content(self, binding: DispatchBinding, value: object) -> None:
        started = self._window.check()
        if not self._lock.acquire(timeout=2.0):
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)
        try:
            remaining = 2.0 - (self._window.check() - started)
            if remaining <= 0 or self._cancel.is_cancelled():
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
            self._frames.send({
                "kind": "content", "binding": binding._wire(), "content": value,
            }, remaining)
            response = _closed(self._frames.receive(
                max(0.001, 2.0 - (self._window.check() - started)), self._cancel,
            ), {"kind"})
            if response["kind"] != "content-received":
                raise ProtocolError()
            self._window.check()
        except BaseException:
            self._window.revoke()
            raise
        finally:
            self._lock.release()


class _WorkerBroker:
    """Bounded operation-local resolver, subordinate to live host admission."""

    def __init__(
        self, root: Path, payload: dict[str, object],
        intents: tuple[tuple[DispatchBinding, str], ...], host: _HostChannel,
        window: _BudgetWindow, concurrency: int,
        mutations: dict[str, dict[str, object]] | None = None,
        health: dict[str, dict[str, object]] | None = None,
    ) -> None:
        self._root, self._payload, self._intents = root, payload, intents
        self._mutations = mutations or {}
        self._health = health or {}
        self._io = _ControllerIo()
        self._operation = str(payload.get("operation_id", "none"))
        self._host, self._window = host, window
        self._auth = secrets.token_hex(32)
        self._lock = threading.RLock()
        self._next = {binding.occurrence_id: 0 for binding, _ in intents}
        self._results: dict[str, c.TargetOutcome] = {}
        self._content_received: set[str] = set()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._directory: Path | None = None
        self._owned_tmp: tuple[int, int] | None = None
        self._thread: threading.Thread | None = None
        self._handlers: set[threading.Thread] = set()
        self._slots = threading.BoundedSemaphore(2 * concurrency)

    def __repr__(self) -> str:
        return "<private>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("private-value")

    def start(self) -> None:
        self._window.check()
        # No symlink/shared-root adoption. The trusted launch verifier owns the
        # root; this process creates and cleans only its unique child directory.
        if os.name != "posix" or not self._root.is_absolute():
            raise ProtocolError(c.ReasonCode.DEPENDENCY_NOT_READY)
        uid = cast(Callable[[], int], getattr(os, "getuid"))()
        for component in (*reversed(self._root.parents), self._root):
            info = component.lstat()
            if (
                not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid not in (0, uid) or info.st_mode & 0o022
            ):
                raise ProtocolError(c.ReasonCode.HANDOFF_INVALID)
        info = self._root.lstat()
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise ProtocolError(c.ReasonCode.HANDOFF_INVALID)
        self._directory = Path(tempfile.mkdtemp(prefix="controller-", dir=self._root))
        os.chmod(self._directory, 0o700)
        temporary = self._directory / "ansible-tmp"
        temporary.mkdir(mode=0o700)
        info = temporary.lstat()
        self._owned_tmp = (info.st_dev, info.st_ino)
        self._listener = socket.socket(_unix_family(), socket.SOCK_STREAM)
        self._listener.bind(str(self._directory / "broker"))
        os.chmod(self._directory / "broker", 0o600)
        self._listener.listen(2)
        self._listener.settimeout(0.05)
        self._thread = threading.Thread(target=self._serve, name="netops-private-broker", daemon=True)
        self._thread.start()

    def _bootstrap(self) -> dict[str, object]:
        if self._directory is None:
            raise ProtocolError()
        return {
            "protocol": 1, "socket": str(self._directory / "broker"), "auth": self._auth,
            "intents": [{
                "handle": binding.occurrence_id, "binding": binding._wire(), "kind": kind,
                **({"mutation": self._mutations[binding.occurrence_id]}
                   if binding.occurrence_id in self._mutations else {}),
                **({"health": self._health[binding.occurrence_id]}
                   if binding.occurrence_id in self._health else {}),
            } for binding, kind in self._intents],
        }

    def _serve(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                self._window.check()
                channel, _ = self._listener.accept()
            except socket.timeout:
                continue
            except (OSError, ProtocolError):
                return
            if not self._slots.acquire(blocking=False):
                channel.close()
                continue
            thread = threading.Thread(target=self._handle, args=(channel,), daemon=True)
            with self._lock:
                self._handlers.add(thread)
            thread.start()

    def _handle(self, channel: socket.socket) -> None:
        frames = _SocketFrames(channel)
        started = self._io._time()
        self._io._record("broker.channel", "started", 0.0, self._operation, "none")
        failed: BaseException | None = None
        try:
            message = _closed(frames.receive_one(2.0), {"auth", "kind", "binding", "result"})
            auth = _string(message["auth"], 64)
            if len(auth) != 64 or not hmac.compare_digest(auth, self._auth):
                raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
            binding = DispatchBinding._parse(message["binding"])
            with self._lock:
                selected = next((
                    (original, kind) for original, kind in self._intents
                    if original.occurrence_id == binding.occurrence_id
                ), None)
                if selected is None:
                    raise ProtocolError()
                original, effect_kind = selected
                expected_phase = ("credential", "task", "mutation")
                index = self._next[binding.occurrence_id]
                if message["kind"] == "check":
                    if (
                        effect_kind not in ("apply", "rollback") or index not in (2, 3)
                        or binding != replace(original, phase="task", sequence=1)
                        or message["result"] is not None
                        or binding.occurrence_id in self._results or self._stop.is_set()
                    ):
                        raise ProtocolError()
                    self._window.check()
                    with self._io.span(
                        "broker.pulse", binding.operation_id, binding.controller_digest,
                    ):
                        self._host._pulse(required=True)
                    self._window.check()
                    response: dict[str, object] = {"kind": "checked"}
                elif message["kind"] == "content":
                    if (
                        effect_kind != "collect" or index != 2
                        or binding != replace(original, phase="task", sequence=1)
                        or binding.occurrence_id in self._content_received
                        or binding.occurrence_id in self._results
                    ):
                        raise ProtocolError()
                    _decode_content(message["result"])
                    self._window.check()
                    self._host.content(binding, message["result"])
                    self._content_received.add(binding.occurrence_id)
                    response = {"kind": "content-received"}
                elif message["kind"] == "complete":
                    if (
                        replace(binding, phase=original.phase, sequence=original.sequence) != original
                        or binding.occurrence_id in self._results
                    ):
                        raise ProtocolError()
                    result = _safe_action_result(
                        message["result"], original.target_id, effect_kind,
                    )
                    if (
                        index < 2 and not (
                            result.status == c.OutcomeStatus.UNSUPPORTED
                            and result.attempted is False and index == 0
                        )
                    ) or (
                        effect_kind in ("apply", "rollback") and (
                            index not in (2, 3)
                            or (result.native_payload.get("issued") is True and index != 3)
                            or (result.status == c.OutcomeStatus.SUCCEEDED and index != 3)
                        )
                    ):
                        raise ProtocolError()
                    self._results[binding.occurrence_id] = result
                    response = {"kind": "completed"}
                else:
                    self._window.check()
                    if self._stop.is_set():
                        raise ProtocolError()
                    if (
                        message["kind"] != "dispatch" or message["result"] is not None
                        or index >= (3 if effect_kind in ("apply", "rollback") else 2)
                        or binding != replace(original, phase=expected_phase[index], sequence=index)
                    ):
                        raise ProtocolError()
                    # Scope is spent under this lock before any response. Host
                    # transport can stall for at most 2s, never indefinitely.
                    self._host.dispatch(binding)
                    self._window.check()
                    self._next[binding.occurrence_id] += 1
                    response = {"kind": "admitted"}
                    if binding.phase == "credential":
                        targets = self._payload["targets"]
                        assert isinstance(targets, list)
                        selected_credential = next((
                            target for target in targets if isinstance(target, dict)
                            and (target["target_id"], target["task_id"])
                            == (binding.target_id, binding.task_id)
                        ), None)
                        if selected_credential is None:
                            raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
                        response = {
                            "kind": "credential", "credential": selected_credential,
                            "jump": self._payload["jump"],
                        }
            frames.send(response)
        except BaseException as error:
            failed = error
            # Never include rejected data, authentication, native exceptions or
            # credentials in errors. A malformed/auth/replay/control fault
            # revokes the whole run rather than offering an oracle/retry path.
            self._stop.set()
            self._window.revoke()
            try:
                frames.send({"kind": "rejected"})
            except BaseException:
                pass
        finally:
            self._io._record(
                "broker.channel", "succeeded" if failed is None else "failed",
                self._io._time() - started, self._operation, "none",
                failed.reason if type(failed) is ProtocolError else (
                    c.ReasonCode.HANDOFF_INVALID if failed is not None else None
                ), unhandled=failed is not None and type(failed) is not ProtocolError,
            )
            frames.close()
            with self._lock:
                self._handlers.discard(threading.current_thread())
            self._slots.release()

    def results(self) -> tuple[c.TargetOutcome, ...]:
        with self._lock:
            return tuple(
                self._results[binding.occurrence_id] for binding, _ in self._intents
                if binding.occurrence_id in self._results
            )

    def close(self) -> c.CleanupOutcome:
        self._stop.set()
        self._window.revoke()
        failed = False
        if self._listener is not None:
            self._listener.close()
        if self._thread is not None:
            self._thread.join(timeout=0.1)
            failed = self._thread.is_alive()
        with self._lock:
            handlers = tuple(self._handlers)
        for handler in handlers:
            handler.join(timeout=2.1 / max(1, len(handlers)))
            failed = failed or handler.is_alive()
        # Retain factual safe results, but discard private references. Python
        # does not promise erasure of immutable strings or forked memory.
        self._payload.clear()
        self._auth = ""
        if self._directory is not None:
            try:
                temporary = self._directory / "ansible-tmp"
                if self._owned_tmp is not None:
                    info = temporary.lstat()
                    if (
                        (info.st_dev, info.st_ino) != self._owned_tmp
                        or not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    ):
                        raise OSError("owned-temp-replaced")
                    # Delete only the exact empty base created by this broker.
                    # Unexpected Ansible/plugin residue is a separate failure,
                    # never permission for recursive unmanifested deletion.
                    temporary.rmdir()
                (self._directory / "broker").unlink()
                self._directory.rmdir()
            except OSError:
                failed = True
        return c.CleanupOutcome(
            "failed" if failed else "succeeded", errors=(c.SafeError(
                c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
                next_action="Inspect the exact owned controller socket and run directory.",
            ),) if failed else (),
        )


def _safe_action_result(
    value: object, target_id: str, kind: str | None = None,
) -> c.TargetOutcome:
    """Only minimized facts cross callbacks; native output/exception text cannot."""
    mutation = isinstance(value, dict) and "mutation" in value
    health = isinstance(value, dict) and "health" in value
    item = _closed(value, {"status", "attempted", "changed", "remote_state", "line_count"} | (
        {"mutation"} if mutation else set()
    ) | ({"health"} if health else set()))
    if (
        item["status"] not in ("succeeded", "failed", "unsupported")
        or type(item["attempted"]) is not bool or type(item["changed"]) is not bool
        or item["remote_state"] not in ("unchanged", "uncertain", "confirmed", "rolled-back")
        or type(item["line_count"]) is not int or not 0 <= item["line_count"] <= c.MAX_SAFE_INT
    ):
        raise ProtocolError()
    facts: dict[str, object] = {"line_count": item["line_count"]}
    findings: tuple[c.Finding, ...] = ()
    health_errors: tuple[c.SafeError, ...] = ()
    if health:
        from ._action_health import _validate_health

        if kind != "gather" or mutation or item["remote_state"] != "unchanged":
            raise ProtocolError()
        detail_health, findings, health_errors = _validate_health(item["health"], target_id)
        checks = detail_health["checks"]
        assert isinstance(checks, dict)
        statuses = [check["status"] for check in checks.values()]
        expected_status = (
            "succeeded" if all(status == "succeeded" for status in statuses)
            and not detail_health["overall_alert"] and not detail_health["connection_cleanup_failed"]
            else "unsupported" if all(status == "unsupported" for status in statuses)
            else "failed"
        )
        if (
            item["status"] != expected_status
            or item["attempted"] != any(status != "unsupported" for status in statuses)
        ):
            raise ProtocolError()
        facts["health"] = detail_health
    elif kind == "gather" and item["status"] == "succeeded":
        raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
    if mutation:
        detail = _closed(item["mutation"], {
            "issued", "committed", "confirmed", "rolled_back", "poststate_verified",
            "cleanup_failed", "connection_opened",
        })
        if (
            any(type(value) is not bool for value in detail.values())
            or item["changed"] != detail["issued"]
            or (detail["committed"] and not detail["issued"])
            or detail["confirmed"] != detail["poststate_verified"]
            or (detail["confirmed"] and not detail["committed"])
            or (detail["rolled_back"] and not detail["confirmed"])
            or (item["status"] == "succeeded") != detail["confirmed"]
            or item["remote_state"] != (
                ("rolled-back" if detail["rolled_back"] else "confirmed") if detail["confirmed"]
                else ("uncertain" if detail["issued"] else "unchanged")
            )
            or (kind == "apply" and detail["rolled_back"])
            or (kind == "rollback" and detail["confirmed"] and not detail["rolled_back"])
        ):
            raise ProtocolError()
        facts.update(detail)
    if kind in ("apply", "rollback") and not mutation:
        raise ProtocolError()
    if kind in ("collect", "gather") and (mutation or item["changed"]):
        raise ProtocolError()
    status = c.OutcomeStatus(_string(item["status"]))
    errors = () if status == c.OutcomeStatus.SUCCEEDED else (c.SafeError(
        c.ErrorCategory.UNSUPPORTED if status == c.OutcomeStatus.UNSUPPORTED
        else c.ErrorCategory.EXECUTION,
        c.ReasonCode.OPERATION_UNSUPPORTED if status == c.OutcomeStatus.UNSUPPORTED
        else c.ReasonCode.APPLY_FAILED,
        c.Stage.VALIDATE if status == c.OutcomeStatus.UNSUPPORTED else c.Stage.APPLY,
        target_id=target_id, next_action="Inspect the exact supported handler and current remote state.",
    ),)
    return c.TargetOutcome(
        target_id, status, item["attempted"],
        changed=item["changed"], remote_state=_string(item["remote_state"]),
        native_payload=c.public_object(facts),
        errors=health_errors or errors, findings=findings,
    )
