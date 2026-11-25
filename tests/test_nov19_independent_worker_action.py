"""Independent S02 worker scope/control-loss and actual ActionBase adapter tests."""

from __future__ import annotations

import copy
import importlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from netops.ansible import action_runtime
from netops.ansible import contracts as c
from netops.ansible.controller_protocol import ControllerBudget, ProtocolError, _BudgetWindow
from netops.ansible.worker import _parse_envelope
from netops.ansible.worker_broker import _HostChannel
from tests.test_nov19_independent_controller_execution import Cancel, actual_host, dispatch
from tests.test_nov19_independent_controller_protocol import Clock

NONCE = "7c" * 32


def valid_envelope():
    env = actual_host()
    request, plan, _, _, _, _, invocation = env
    binding = replace(dispatch(env), task_id=request.operation)
    target = {
        "target_id": "router", "task_id": request.operation, "host": "192.0.2.90",
        "port": 22, "vendor": "cisco_ios", "transport": "ssh",
        "fields": ["username", "password"], "key_ref": None,
        "known_hosts_ref": "approved-known-hosts",
    }
    scope = {
        "operation_id": request.operation_id,
        "controller_digest": invocation.binding.plan.controller_digest,
        "route_digest": request.context.route_digest, "plan_digest": plan.plan_digest,
        "targets": [target], "jump": None, "concurrency": 5,
    }
    private = {
        name: scope[name] for name in ("operation_id", "controller_digest", "route_digest")
    }
    private.update({
        "targets": [dict(target, fields={"username": "operator", "password": "private"})],
        "jump": None,
    })
    return {
        "protocol": 1, "request": json.loads(c.canonical_bytes(request)),
        "scope": scope, "intents": [{"binding": binding._wire(), "kind": "collect"}],
        "credentials": private, "budget": ControllerBudget(NONCE, 60000, 300000)._wire(),
    }


def test_t13_actual_worker_parses_only_bound_exact_private_envelope():
    raw = valid_envelope()
    parsed = _parse_envelope(raw, NONCE)
    assert parsed.request.operation_id == raw["scope"]["operation_id"]
    assert parsed.intents[0][0].task_id == parsed.request.operation
    assert parsed.concurrency == 5


@pytest.mark.parametrize("change", [
    "unknown", "nonce", "protocol-bool", "extra-target", "task", "effect",
    "phase", "sequence", "plan", "controller", "credential-extra-field",
    "credential-wrong-target", "concurrency-zero", "concurrency-bool", "budget-unknown",
])
def test_t13_actual_worker_rejects_malformed_or_widened_scope_before_sessions(change):
    raw = valid_envelope()
    if change == "unknown":
        raw["permission"] = True
    elif change == "nonce":
        raw["budget"]["ready_nonce"] = "ab" * 32
    elif change == "protocol-bool":
        raw["protocol"] = True
    elif change == "extra-target":
        raw["scope"]["targets"].append(copy.deepcopy(raw["scope"]["targets"][0]))
    elif change == "task":
        raw["intents"][0]["binding"]["task_id"] = "config.apply"
    elif change == "effect":
        raw["intents"][0]["kind"] = "apply"
    elif change == "phase":
        raw["intents"][0]["binding"]["phase"] = "task"
    elif change == "sequence":
        raw["intents"][0]["binding"]["sequence"] = 1
    elif change == "plan":
        raw["intents"][0]["binding"]["plan_digest"] = "0" * 64
    elif change == "controller":
        raw["intents"][0]["binding"]["controller_digest"] = "0" * 64
    elif change == "credential-extra-field":
        raw["credentials"]["targets"][0]["fields"]["enable_password"] = "extra"
    elif change == "credential-wrong-target":
        raw["credentials"]["targets"][0]["host"] = "198.51.100.1"
    elif change == "concurrency-zero":
        raw["scope"]["concurrency"] = 0
    elif change == "concurrency-bool":
        raw["scope"]["concurrency"] = True
    else:
        raw["budget"]["renew"] = True
    with pytest.raises((ProtocolError, c.ContractError)):
        _parse_envelope(raw, NONCE)


class Frames:
    """Fake private transport port: no sockets or actual listener."""

    def __init__(self, response, clock):
        self.response, self.clock = response, clock
        self.sent = []
        self.transit = 0.0
        self.error = None

    def send(self, value, timeout=2.0):
        self.sent.append((value, timeout))

    def receive(self, timeout, cancel):
        self.clock.value += self.transit
        if self.error is not None:
            raise self.error
        return self.response


@pytest.mark.parametrize("fault", ["lost", "unknown", "wrong-binding", "late", "renew"])
def test_t14_actual_worker_control_loss_revokes_local_window_permanently(fault):
    env = actual_host()
    binding = dispatch(env)
    clock = Clock()
    window = _BudgetWindow(clock, NONCE, binding.plan_digest)
    window.accept(ControllerBudget(NONCE, 60000, 300000), binding.plan_digest)
    response = {
        "kind": "permit", "binding": binding._wire(),
        "budget": ControllerBudget(NONCE, 59000, 299000)._wire(),
    }
    frames = Frames(response, clock)
    if fault == "lost":
        frames.error = ProtocolError(c.ReasonCode.CONTROL_LOST)
    elif fault == "unknown":
        response["allow"] = True
    elif fault == "wrong-binding":
        response["binding"]["target_id"] = "other"
    elif fault == "late":
        frames.transit = 2.0
    else:
        response["budget"]["authorization_remaining_ms"] = 300001
    host = _HostChannel(frames, window, Cancel())
    with pytest.raises(ProtocolError):
        host.dispatch(binding)
    with pytest.raises(ProtocolError):
        window.check()
    assert len(frames.sent) == 1
    assert frames.sent[0][1] <= 2.0


def test_t33_worker_pulse_does_not_extend_original_budget():
    env, clock = actual_host(), Clock()
    binding = dispatch(env)
    window = _BudgetWindow(clock, NONCE, binding.plan_digest)
    window.accept(ControllerBudget(NONCE, 1000, 10000), binding.plan_digest)
    frames = Frames({"kind": "alive"}, clock)
    host = _HostChannel(frames, window, Cancel())
    clock.value += 0.9
    host.pulse()
    clock.value += 0.1
    with pytest.raises(ProtocolError):
        host.pulse()


def actual_action():
    # Missing offline ansible-core is a genuine blocked dependency, never a fake
    # ActionBase class or skipped check. Actual fork/tuple proof remains later.
    module = importlib.import_module("netops.ansible.action_plugins.netops_workflow")
    base = importlib.import_module("ansible.plugins.action").ActionBase
    assert issubclass(module.NetopsWorkflowAction, base)
    return object.__new__(module.NetopsWorkflowAction)


def test_t08_actual_actionbase_check_mode_precedes_client_or_secret_access(monkeypatch):
    action = actual_action()

    class Forbidden:
        def execute(self, handle):
            raise AssertionError("check mode touched private client")

    monkeypatch.setattr(action_runtime, "_CLIENT", Forbidden())
    action._task = SimpleNamespace(check_mode=True, args={"password": "forbidden"})
    assert action.run(task_vars={"secret": "forbidden"}) == {
        "changed": False, "skipped": True, "netops": {"executed": False},
    }


def test_t13_actual_actionbase_uses_only_private_local_client_not_module(monkeypatch):
    action = actual_action()

    class Client:
        def __init__(self):
            self.handles = []

        def execute(self, handle):
            self.handles.append(handle)
            return {
                "status": "succeeded", "attempted": True, "changed": False,
                "remote_state": "unchanged", "line_count": 2,
            }

    def forbidden(*args, **kwargs):
        raise AssertionError("local action must not stage a remote module")

    client = Client()
    monkeypatch.setattr(action_runtime, "_CLIENT", client)
    monkeypatch.setattr(action, "_execute_module", forbidden)
    action._task = SimpleNamespace(check_mode=False, args={"handle": "owned-effect-0"})
    result = action.run(task_vars={})
    assert client.handles == ["owned-effect-0"]
    assert result == {
        "changed": False, "failed": False,
        "netops": {
            "status": "succeeded", "attempted": True, "changed": False,
            "remote_state": "unchanged", "line_count": 2,
        },
    }
    assert "stdout" not in result and "stderr" not in result
