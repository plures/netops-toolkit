"""Fixed managed controller worker; credentials enter through one private frame.

Importing this module performs no I/O. Only the installed private process entry
starts a broker/runner. Native Windows and spawn-only action tuples are refused.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from . import contracts as c
from ._action_mutation import _MutationSpec
from ._controller_pipe import _Frames
from ._worker_group import _OwnedLinuxGroup
from .controller_observations import _ControllerIo
from .controller_protocol import (
    ControllerBudget,
    DispatchBinding,
    ProtocolError,
    _BudgetWindow,
    _closed,
    _encode_frame,
    _integer,
    _read_frame,
    _string,
    _validate_private_payload,
)
from .controller_transport import _SocketFrames
from .worker_broker import _HostChannel, _WorkerBroker


class _Clock:
    def monotonic(self) -> float:
        return time.monotonic()

    def utc_now(self) -> datetime:
        return datetime.now(timezone.utc)


class _Cancelled:
    def __init__(self) -> None:
        self._event = threading.Event()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout)


@dataclass(frozen=True, repr=False)
class _Envelope:
    request: c.OperationRequest
    scope: dict[str, object]
    intents: tuple[tuple[DispatchBinding, str], ...]
    credentials: dict[str, object]
    budget: ControllerBudget
    concurrency: int
    mutations: dict[str, dict[str, object]]
    health: dict[str, dict[str, object]]


def _parse_envelope(value: object, nonce: str) -> _Envelope:
    item = _closed(value, {"protocol", "request", "scope", "intents", "credentials", "budget"})
    _integer(item["protocol"], 1, 1)
    budget = ControllerBudget._parse(item["budget"])
    if budget.ready_nonce != nonce:
        raise ProtocolError()
    request = c.OperationRequest.from_json(json.dumps(
        item["request"], allow_nan=False, separators=(",", ":"),
    ).encode("utf-8"))
    if request.mode in (c.Mode.PREVIEW, c.Mode.CHECK):
        raise ProtocolError()
    scope = _closed(item["scope"], {
        "operation_id", "controller_digest", "route_digest", "plan_digest",
        "targets", "jump", "concurrency",
    })
    for name in ("controller_digest", "route_digest", "plan_digest"):
        c.sha256(scope[name])
    if (
        scope["operation_id"] != request.operation_id
        or scope["route_digest"] != request.context.route_digest
    ):
        raise ProtocolError()
    concurrency = _integer(scope["concurrency"], 1, 50)
    targets = scope["targets"]
    intents = item["intents"]
    if (
        type(targets) is not list or type(intents) is not list
        or not 1 <= len(targets) <= 4096 or len(intents) != len(targets)
        or len(targets) > len(request.scope.target_ids)
    ):
        raise ProtocolError()
    assert isinstance(targets, list) and isinstance(intents, list)
    parsed: list[tuple[DispatchBinding, str]] = []
    mutations: dict[str, dict[str, object]] = {}
    health: dict[str, dict[str, object]] = {}
    selected_ids: set[str] = set()
    allowed_kinds = c.capability(request.operation).effects
    for target, intent in zip(targets, intents):
        if type(target) is not dict:
            raise ProtocolError()
        assert isinstance(target, dict)
        mutation = isinstance(intent, dict) and "mutation" in intent
        gathering = isinstance(intent, dict) and "health" in intent
        task = _closed(intent, {"binding", "kind"} | ({"mutation"} if mutation else set())
                       | ({"health"} if gathering else set()))
        kind = _string(task["kind"])
        binding = DispatchBinding._parse(task["binding"])
        if (
            kind not in ("collect", "gather", "apply", "rollback") or kind not in allowed_kinds
            or binding.operation_id != request.operation_id
            or binding.plan_digest != scope["plan_digest"]
            or binding.controller_digest != scope["controller_digest"]
            or binding.target_id != target.get("target_id")
            or binding.task_id != target.get("task_id")
            or binding.phase != "credential" or binding.sequence != 0
            or binding.target_id not in request.scope.target_ids
            or binding.target_id in selected_ids
            or (kind in ("apply", "rollback") and request.mode not in (c.Mode.APPLY, c.Mode.ROLLBACK))
        ):
            raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        if kind in ("apply", "rollback"):
            if not mutation:
                raise ProtocolError(c.ReasonCode.INPUT_BINDING_INVALID)
            spec = _MutationSpec._parse(task["mutation"])
            spec._validate_kind(kind)
            mutations[binding.occurrence_id] = spec._wire()
        elif mutation:
            raise ProtocolError()
        if gathering:
            from ._action_health import _HealthSelection

            if kind != "gather":
                raise ProtocolError()
            health[binding.occurrence_id] = _HealthSelection.parse(task["health"]).wire()
        parsed.append((binding, kind))
        selected_ids.add(binding.target_id)
    credentials = _validate_private_payload(item["credentials"], scope)
    for selected in targets:
        assert isinstance(selected, dict)
        fields = selected["fields"]
        assert isinstance(fields, list)
        if (
            set(fields) - {"username", "password", "key_passphrase", "enable_password"}
            or "username" not in fields
            or (selected["key_ref"] is None and "password" not in fields)
            or (selected["key_ref"] is None and "key_passphrase" in fields)
        ):
            raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
    return _Envelope(request, scope, tuple(parsed), credentials, budget, concurrency, mutations, health)


def _run_private(
    source: BinaryIO | Callable[[], BinaryIO], frames: _Frames, root: Path,
    clock: c.ClockPort, cancel: _Cancelled,
    *, group: _OwnedLinuxGroup | None = None,
    bind: Callable[[c.OperationRequest, str, _BudgetWindow], None] | None = None,
) -> int:
    nonce = secrets.token_hex(32)
    observations = _ControllerIo()
    # Anchor before readiness leaves this process, not when a reply arrives.
    # Plan identity is learned from the private frame; nonce remains single-use.
    ready_started = clock.monotonic()
    with observations.span("worker.ready"):
        frames.send({"kind": "ready", "nonce": nonce})
    with observations.span("worker.input"):
        if callable(source):
            source = source()
        try:
            envelope = _parse_envelope(_read_frame(source, eof=True), nonce)
        finally:
            source.close()
    window = _BudgetWindow(clock, nonce, _string(envelope.scope["plan_digest"]))
    window._started = ready_started
    window._last = ready_started
    window.accept(envelope.budget, _string(envelope.scope["plan_digest"]))
    if bind is not None:
        bind(envelope.request, _string(envelope.scope["plan_digest"]), window)
    host = _HostChannel(frames, window, cancel)
    broker = _WorkerBroker(
        root, envelope.credentials, envelope.intents, host, window, envelope.concurrency,
        envelope.mutations, envelope.health,
    )
    process: subprocess.Popen[bytes] | None = None
    read_fd: int | None = None
    write_fd: int | None = None
    primary: c.SafeError | None = None
    cleanup = c.CleanupOutcome()
    try:
        with observations.span("worker.broker", envelope.request.operation_id):
            broker.start()
        assert broker._directory is not None
        read_fd, write_fd = os.pipe()
        # Fixed installed interpreter and module; no playbook, module, callback
        # path, source inventory, config file or credential can be supplied.
        with observations.span("worker.launch", envelope.request.operation_id):
            if group is not None:
                selected_fd, selected_directory = read_fd, broker._directory
                process = group.launch(
                    lambda: _launch_runner(
                        selected_fd, envelope, selected_directory, owned_group=True,
                    ),
                    envelope.request.operation_id,
                )
            else:
                process = _launch_runner(read_fd, envelope, broker._directory)
        os.close(read_fd)
        read_fd = None
        with observations.span("worker.auth", envelope.request.operation_id):
            with os.fdopen(write_fd, "wb", closefd=True) as auth:
                write_fd = None
                auth.write(_encode_frame(broker._bootstrap()))
        # Periodic private liveness messages only check authority; they never
        # carry budgets or renew consent. The host watchdog remains independent.
        with observations.span("worker.wait", envelope.request.operation_id):
            while not group.finished() if group is not None else process.poll() is None:
                if cancel.is_cancelled():
                    raise ProtocolError(c.ReasonCode.CANCELLED)
                host.pulse()
                cancel.wait(0.1)
            if group is None and process.returncode != 0:
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
    except Exception as failure:
        primary = c.SafeError(
            c.ErrorCategory.CREDENTIALS,
            failure.reason if type(failure) is ProtocolError else c.ReasonCode.HANDOFF_INVALID,
            c.Stage.CONTROLLER, next_action="Inspect the owned controller receipt before fresh consent.",
        )
    finally:
        if read_fd is not None:
            os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
        if group is not None:
            cleanup = group.close()
            if process is not None and process.returncode != 0:
                primary = primary or c.SafeError(
                    c.ErrorCategory.EXECUTION, c.ReasonCode.CONTROL_LOST, c.Stage.CONTROLLER,
                )
        elif process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    cleanup = c.CleanupOutcome("failed", errors=(c.SafeError(
                        c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
                    ),))
        owned = observations.cleanup("worker.cleanup", envelope.request.operation_id, broker.close)
        from ._controller_wsl import _merge_cleanup

        cleanup = _merge_cleanup(cleanup, owned)
    results = {result.target_id: result for result in broker.results()}
    targets: list[c.TargetOutcome] = []
    for target in envelope.request.scope.target_ids:
        if target in results:
            targets.append(results[target])
            continue
        issued = any(
            binding.target_id == target and kind in ("apply", "rollback")
            and broker._next[binding.occurrence_id] >= 3 for binding, kind in envelope.intents
        )
        reason = c.ReasonCode.REMOTE_STATE_UNCERTAIN if issued else (
            primary.reason if primary else c.ReasonCode.CONTROL_LOST
        )
        targets.append(c.TargetOutcome(
            target, c.OutcomeStatus.FAILED if issued else c.OutcomeStatus.BLOCKED,
            issued, unapplied_effects=() if issued else (envelope.request.operation,),
            remote_state="uncertain" if issued else "unchanged",
            errors=(c.SafeError(
                c.ErrorCategory.EXECUTION if issued else c.ErrorCategory.CREDENTIALS,
                reason, c.Stage.CONTROLLER, target_id=target,
                next_action="Inspect issued remote work; never automatically retry mutation.",
            ),),
        ))
    outcome = c.aggregate_outcome(
        envelope.request, tuple(targets), executed_mode=envelope.request.mode,
        errors=(primary,) if primary else (), cleanup=cleanup,
        provenance=c.public_object({"qualification_claimed": False}),
    )
    with observations.span("worker.result", envelope.request.operation_id):
        frames.send({"kind": "result", "outcome": json.loads(c.canonical_bytes(outcome))})
    # Keep the group leader alive until host-owned teardown/channel close.
    # This is not a renewed execution budget or permission for another task.
    try:
        frames.receive(2.0)
    except ProtocolError:
        pass
    return 0


def _launch_runner(
    read_fd: int, envelope: _Envelope, directory: Path,
    *, owned_group: bool = False,
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
            (sys.executable, "-I", "-m", "netops.ansible.controller_runner",
             "--auth-fd", str(read_fd), "--concurrency", str(envelope.concurrency)),
            pass_fds=(read_fd,), close_fds=True, stdin=subprocess.DEVNULL,
            start_new_session=owned_group,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={
                "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1",
                "ANSIBLE_CONFIG": "/dev/null", "ANSIBLE_HOME": str(directory),
                "ANSIBLE_LOCAL_TEMP": str(directory / "ansible-tmp"),
                "ANSIBLE_LOAD_CALLBACK_PLUGINS": "0", "ANSIBLE_CALLBACKS_ENABLED": "",
            }, cwd="/", shell=False,
        )


def _main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--control-fd", type=int)
    parser.add_argument("--private-root")
    parser.add_argument("--stdio-control", action="store_true")
    args = parser.parse_args()
    if args.stdio_control:
        if args.control_fd is not None or args.private_root is not None:
            return 3
        from ._worker_wsl import _run_stdio

        return _run_stdio()
    if os.name != "posix" or args.control_fd is None or args.control_fd < 3 or args.private_root is None:
        return 3
    frames = _SocketFrames(socket.socket(fileno=args.control_fd))
    try:
        return _run_private(sys.stdin.buffer, frames, Path(args.private_root), _Clock(), _Cancelled())
    except BaseException:
        # No raw diagnostics on stdout/stderr, including malformed private input.
        return 3
    finally:
        frames.close()


if __name__ == "__main__":
    raise SystemExit(_main())
