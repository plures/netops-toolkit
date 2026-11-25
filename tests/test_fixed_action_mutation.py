"""Author fixed-action logic controls; no ActionBase/fork/platform qualification."""

import hashlib
import pickle
from copy import deepcopy
from types import SimpleNamespace

import pytest

from netops.ansible import contracts as c
from netops.ansible._action_mutation import _MutationSpec, _run_mutation
from netops.ansible.action_runtime import _ActionClient
from netops.ansible.controller import ProcessResult
from netops.ansible.controller_observations import _ControllerIo
from netops.ansible.controller_protocol import DispatchBinding, ProtocolError, _decode_frame
from netops.ansible.worker_broker import _safe_action_result
from netops.core.connection import ConnectionParams

BEFORE = b"hostname before\n"
AFTER = b"hostname after\n"
SECRET = "SYNTHETIC-ACTION-ONLY"
CREDENTIAL = {
    "host": "192.0.2.1", "vendor": "cisco_ios",
    "fields": {"username": "synthetic", "password": SECRET},
}


def _use_action_process(process, device, monkeypatch, opened):
    """Keep actual A02/S01/launcher/action logic; fake only process/device ports."""
    class Connection:
        def __init__(self, credential, jump):
            assert jump is None
            assert credential["fields"]["password"] == "SYNTHETIC-INTEGRATION-ONLY"
            self.params = ConnectionParams(host=credential["host"], device_type=credential["vendor"])
            opened.append(credential["task_id"])

        def connect(self):
            pass

        def disconnect(self):
            pass

        def send(self, command, expect_string=None):
            return device.send(command)

        def send_config(self, commands):
            return device.send_config(commands)

    monkeypatch.setattr("netops.ansible.action_runtime._StrictConnection", Connection)

    def run(launch, private, cancel):
        process.runs.append(launch)
        frame = _decode_frame(private)
        intent = frame["intents"][0]
        original = DispatchBinding._parse(intent["binding"])
        from netops.ansible.worker import _parse_envelope

        frame["budget"] = launch.control.ready("c" * 64)._wire()
        malformed = deepcopy(frame)
        malformed["intents"][0]["mutation"]["commands"] = (
            [] if intent["kind"] == "apply" else ["unreviewed rollback command"]
        )
        with pytest.raises(ProtocolError):
            _parse_envelope(malformed, "c" * 64)
        envelope = _parse_envelope(frame, "c" * 64)
        assert envelope.mutations[original.occurrence_id] == intent["mutation"]
        client = _ActionClient({
            "protocol": 1, "socket": "/not-opened", "auth": "c" * 64,
            "intents": [dict(intent, handle=original.occurrence_id)],
        })

        def request(kind, binding, result=None):
            if kind == "dispatch":
                launch.control.request_dispatch(binding, cancel)
                if binding.phase == "credential":
                    return {
                        "kind": "credential", "credential": frame["credentials"]["targets"][0],
                        "jump": frame["credentials"]["jump"],
                    }
                return {"kind": "admitted"}
            if kind == "check":
                launch.control.check()
                return {"kind": "checked"}
            assert kind == "complete"
            _safe_action_result(result, binding.target_id, intent["kind"])
            return {"kind": "completed"}

        client._request = request
        # Intentionally test actual pure logic only, without mocking ActionBase,
        # os.name, pid/fork identity or claiming a supported execution tuple.
        result = client._execute(original.occurrence_id)
        if getattr(process, "drop_completion", False) and intent["kind"] == "apply":
            return ProcessResult((), 1, c.CleanupOutcome("succeeded"), c.SafeError(
                c.ErrorCategory.EXECUTION, c.ReasonCode.CONTROL_LOST, c.Stage.CONTROLLER,
            ))
        return ProcessResult(
            (_safe_action_result(result, original.target_id, intent["kind"]),),
            0, c.CleanupOutcome("succeeded"),
        )

    monkeypatch.setattr(process, "run", run)


@pytest.fixture
def native(monkeypatch):
    state = SimpleNamespace(
        config=BEFORE.decode(), writes=[], events=[], cleanup=False,
        after_write=lambda: None,
    )

    class Connection:
        def __init__(self, credential, jump):
            assert credential == CREDENTIAL and jump is None
            self.params = ConnectionParams(host=credential["host"], device_type=credential["vendor"])

        def connect(self):
            state.events.append("connect")

        def disconnect(self):
            state.events.append("close")
            if state.cleanup:
                raise RuntimeError(SECRET)

        def send(self, command, expect_string=None):
            assert command == "show running-config"
            state.events.append("read")
            return state.config

        def send_config(self, commands):
            state.writes.append(tuple(commands))
            state.events.append("write")
            state.config = AFTER.decode()
            state.after_write()
            return SECRET

    monkeypatch.setattr("netops.ansible.action_runtime._StrictConnection", Connection)
    return state


def _spec():
    return _MutationSpec(("hostname after",), BEFORE, hashlib.sha256(AFTER).hexdigest(), "owned-pre")


@pytest.mark.parametrize("fault", [
    "none", "prestate", "denied", "write-ambiguous", "postcheck", "poststate", "cleanup", "combined",
])
def test_actual_native_guarded_action_preserves_facts_and_never_replays(native, fault, caplog):
    if fault == "prestate":
        native.config = "hostname drifted\n"
    if fault in ("cleanup", "combined"):
        native.cleanup = True
    checks = []

    def check():
        checks.append(True)
        if fault == "postcheck" and native.writes:
            raise ProtocolError(c.ReasonCode.CANCELLED)

    def admit():
        native.events.append("permit")
        if fault == "denied":
            raise ProtocolError(c.ReasonCode.CONSENT_STALE)

    def after_write():
        if fault in ("write-ambiguous", "combined"):
            raise RuntimeError(SECRET)
        if fault == "poststate":
            native.config = "hostname unexpected\n"

    native.after_write = after_write
    io = _ControllerIo()
    with caplog.at_level("INFO"):
        result = _run_mutation(
            "apply", _spec(), CREDENTIAL, None, check, admit, io, SECRET, SECRET,
            target=SECRET, step=SECRET,
        )
    target = _safe_action_result(result, "r1", "apply")
    assert SECRET not in repr(result)
    assert all(SECRET not in repr(record.__dict__) for record in caplog.records)
    records = [record for record in caplog.records if record.msg == "controller.io"]
    assert all(record.target_ref == "sha256:" + hashlib.sha256(SECRET.encode()).hexdigest()
               for record in records)
    assert all(record.step_ref == record.target_ref for record in records)
    assert all(set(record.metric_dimensions) == {"boundary", "outcome", "stage", "reason"}
               for record in records)
    assert all(record.category != "none" and record.next_action != "none"
               for record in records if record.outcome == "failed")
    assert len(native.writes) == (0 if fault in ("prestate", "denied") else 1)
    assert result["mutation"]["cleanup_failed"] == (fault in ("cleanup", "combined"))
    if fault in ("none", "cleanup"):
        assert target.status == c.OutcomeStatus.SUCCEEDED and target.remote_state == "confirmed"
        assert native.events.index("permit") < native.events.index("write")
    else:
        assert target.status == c.OutcomeStatus.FAILED
        assert target.remote_state == (
            "unchanged" if fault in ("prestate", "denied") else "uncertain"
        )
    assert native.events[-1] == "close"


def test_real_vendor_rollback_uses_only_exact_preapproved_snapshot(native):
    spec = _MutationSpec((), BEFORE, hashlib.sha256(BEFORE).hexdigest(), "owned-pre")
    native.after_write = lambda: setattr(native, "config", BEFORE.decode())
    permits = []
    result = _run_mutation(
        "rollback", spec, CREDENTIAL, None, lambda: None, lambda: permits.append(True),
        _ControllerIo(), "operation", "context",
    )
    assert _safe_action_result(result, "r1", "rollback").remote_state == "rolled-back"
    assert permits == [True] and native.writes == [("hostname before",)]


@pytest.mark.parametrize("change", ["commands", "digest", "content", "extra"])
def test_closed_protected_mutation_input_rejects_malformed_values(change):
    packet = _spec()._wire()
    if change == "commands":
        packet["commands"] = ["hostname after\nshell injected"]
    elif change == "digest":
        packet["expected_digest"] = "not-a-digest"
    elif change == "content":
        packet["prestate"] = "not-base64"
    else:
        packet["shell"] = "not-allowed"
    with pytest.raises((ProtocolError, c.ContractError)):
        _MutationSpec._parse(packet)


def test_protected_spec_no_repr_serialization_or_callback_bytes(native):
    spec = _spec()
    assert repr(spec) == "<private>"
    with pytest.raises(TypeError):
        pickle.dumps(spec)
    result = _run_mutation(
        "apply", spec, CREDENTIAL, None, lambda: None, lambda: None,
        _ControllerIo(), "operation", "context",
    )
    assert BEFORE.decode() not in repr(result) and AFTER.decode() not in repr(result)


def test_throwing_io_sink_does_not_replace_mutation_or_cleanup_facts(native, monkeypatch):
    io = _ControllerIo()

    def throwing(*args, **kwargs):
        raise RuntimeError(SECRET)

    monkeypatch.setattr(io._logger, "info", throwing)
    native.cleanup = True
    result = _run_mutation(
        "apply", _spec(), CREDENTIAL, None, lambda: None, lambda: None,
        io, "operation", "context",
    )
    assert result["status"] == "succeeded" and result["mutation"]["cleanup_failed"]
    assert io.sink_failures > 0


def test_process_local_prestate_ablation_proves_write_oracle_is_load_bearing(native, monkeypatch):
    from netops.ansible._action_mutation import _ActionMutationHooks

    native.config = "hostname drifted\n"
    guarded = _run_mutation(
        "apply", _spec(), CREDENTIAL, None, lambda: None, lambda: None,
        _ControllerIo(), "operation", "context",
    )
    assert guarded["status"] == "failed" and native.writes == []
    with monkeypatch.context() as patch:
        patch.setattr(_ActionMutationHooks, "prestate", lambda self, content: self.check())
        unguarded = _run_mutation(
            "apply", _spec(), CREDENTIAL, None, lambda: None, lambda: None,
            _ControllerIo(), "operation", "context",
        )
        with pytest.raises(AssertionError):
            assert native.writes == [], "ablation intentionally allowed the unreviewed drifted write"
        assert unguarded["status"] == "succeeded"
    # No production source bytes or independent tests were changed by ablation.
    native.writes.clear()
    native.config = "hostname drifted\n"
    restored = _run_mutation(
        "apply", _spec(), CREDENTIAL, None, lambda: None, lambda: None,
        _ControllerIo(), "operation", "context",
    )
    assert restored["status"] == "failed" and native.writes == []


def test_public_client_entry_keeps_real_fork_guard(binding):
    client = _ActionClient({
        "protocol": 1, "socket": "/not-opened", "auth": "c" * 64,
        "intents": [{
            "handle": binding.occurrence_id, "binding": binding._wire(), "kind": "apply",
            "mutation": _spec()._wire(),
        }],
    })
    with pytest.raises(ProtocolError):
        client.execute(binding.occurrence_id)


@pytest.mark.parametrize("negative", ["replay", "target", "sequence"])
def test_actual_worker_broker_enforces_every_one_use_phase_and_binding(
    binding, envelope, monkeypatch, negative,
):
    from dataclasses import replace
    from pathlib import Path

    from netops.ansible import worker_broker as module

    calls, responses, revoked = [], [], []
    window = SimpleNamespace(check=lambda: 1.0, revoke=lambda: revoked.append(True))
    host = SimpleNamespace(dispatch=lambda value: calls.append(value))
    broker = module._WorkerBroker(
        Path("/not-opened"), envelope["credentials"], ((binding, "apply"),),
        host, window, 1, {binding.occurrence_id: _spec()._wire()},
    )

    def deliver(selected):
        message = {
            "auth": broker._auth, "kind": "dispatch", "binding": selected._wire(), "result": None,
        }
        frames = SimpleNamespace(
            receive_one=lambda timeout: message, send=lambda value: responses.append(value),
            close=lambda: None,
        )
        monkeypatch.setattr(module, "_SocketFrames", lambda channel: frames)
        assert broker._slots.acquire(blocking=False)
        broker._handle(None)

    deliver(binding)
    deliver(replace(binding, phase="task", sequence=1))
    mutation = replace(binding, phase="mutation", sequence=2)
    if negative == "replay":
        deliver(mutation)
        assert len(calls) == 3
    elif negative == "target":
        mutation = replace(mutation, target_id="unselected")
    else:
        mutation = replace(mutation, sequence=1)
    before = len(calls)
    deliver(mutation)
    assert len(calls) == before and responses[-1] == {"kind": "rejected"}
    assert revoked and broker._stop.is_set()


@pytest.mark.parametrize("field", [
    "issued", "committed", "confirmed", "poststate_verified", "rolled_back",
])
def test_minimized_mutation_handback_rejects_contradictory_facts(native, field):
    result = _run_mutation(
        "apply", _spec(), CREDENTIAL, None, lambda: None, lambda: None,
        _ControllerIo(), "operation", "context",
    )
    result["mutation"][field] = not result["mutation"][field]
    with pytest.raises(ProtocolError):
        _safe_action_result(result, "r1", "apply")


def test_installed_evidence_cannot_omit_actual_mutation_runtime():
    from netops.ansible.controller_installation import _require_runtime_members

    required = [
        "bin/python", "site/netops/ansible/worker.py",
        "site/netops/ansible/controller_runner.py", "site/netops/ansible/action_runtime.py",
        "site/netops/ansible/_action_mutation.py",
        "site/netops/ansible/_action_health.py", "site/netops/ansible/_windows_job.py",
        "site/netops/ansible/action_plugins/netops_workflow.py",
        "site/ansible/plugins/action/__init__.py",
    ]
    _require_runtime_members(required, "bin/python", set(required))
    for missing in required:
        with pytest.raises(ProtocolError):
            _require_runtime_members(
                [name for name in required if name != missing], "bin/python", set(required),
            )
    with pytest.raises(ProtocolError):
        _require_runtime_members(required, "bin/python", set(required) - {
            "site/netops/ansible/_action_mutation.py",
        })


@pytest.mark.parametrize("kind,commands,digest", [
    ("apply", (), hashlib.sha256(AFTER).hexdigest()),
    ("rollback", ("hostname after",), hashlib.sha256(BEFORE).hexdigest()),
    ("rollback", (), hashlib.sha256(AFTER).hexdigest()),
])
def test_malformed_mutation_kind_is_denied_before_private_resolution(
    binding, monkeypatch, kind, commands, digest,
):
    def forbidden(*args, **kwargs):
        pytest.fail("malformed mutation reached private credential/task resolution")

    monkeypatch.setattr(_ActionClient, "_request", forbidden)
    with pytest.raises(ProtocolError):
        _ActionClient({
            "protocol": 1, "socket": "/not-opened", "auth": "c" * 64,
            "intents": [{
                "handle": binding.occurrence_id, "binding": binding._wire(), "kind": kind,
                "mutation": _MutationSpec(commands, BEFORE, digest, "owned-pre")._wire(),
            }],
        })


pytest_plugins = ("tests.test_controller_protocol",)
