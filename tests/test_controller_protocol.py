"""S02 author controls: private frames, hostile scope and conservative clocks."""

import io
import json
import pickle
import struct
from copy import deepcopy
from dataclasses import replace
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.action_runtime import _ActionClient
from netops.ansible.controller import ControllerInstallation, ControllerLauncher
from netops.ansible.controller_protocol import (
    ControllerBudget,
    DispatchBinding,
    ProtocolError,
    _BudgetWindow,
    _decode_frame,
    _encode_frame,
    _read_frame,
    _validate_private_payload,
)
from netops.ansible.settings import AnsibleSettings, SettingsSnapshot
from netops.ansible.worker import _parse_envelope
from netops.ansible.workflows import plan_digest

pytest_plugins = ("tests.test_scoped_credentials",)
D = "a" * 64
NONCE = "c" * 64
SECRET = "SYNTHETIC-S02-must-not-leak"


class Clock:
    def __init__(self, value=1000.0):
        self.value = value

    def monotonic(self):
        return self.value


class Forbidden:
    def __getattr__(self, name):
        raise AssertionError("pure path used an effectful port")


@pytest.fixture
def operation_request(scope):
    return c.OperationRequest(
        scope.operation_id, "config.collect", c.Mode.OBSERVE,
        c.Scope((scope.targets[0].target_id,)), scope.context.context,
    )


@pytest.fixture
def plan(operation_request):
    request = operation_request
    effect = c.PlannedEffect("collect-0", 0, "collect", request.scope.target_ids[0], request.operation)
    value = c.OperationPlan(
        request.operation_id, request.operation, request.mode, request.scope.target_ids,
        (c.public_object({
            "target_id": request.scope.target_ids[0], "resolved": True,
            "host": "192.0.2.1", "port": 2222, "vendor": "cisco_ios",
            "transport": "ssh", "controller_id": request.context.controller_id,
            "route_digest": request.context.route_digest,
        }),),
        request.context, D, D, request.context.policy_identity.bundle_sha256,
        request.context.policy_identity.reducer_version, (effect,), (), (),
        c.FrozenObject(), c.OutputIntent(), 1, 10000, (), D,
        settings=SettingsSnapshot(ansible=AnsibleSettings(enabled=True)),
    )
    return replace(value, plan_digest=plan_digest(value))


@pytest.fixture
def binding(operation_request, plan):
    request = operation_request
    return DispatchBinding(
        request.operation_id, plan.plan_digest, c.digest(plan.context.controller_id), str(uuid4()),
        "collect-0", request.scope.target_ids[0], request.operation, "credential", 0,
    )


@pytest.fixture
def envelope(operation_request, plan, binding):
    request = operation_request
    target = {
        "target_id": binding.target_id, "task_id": binding.task_id,
        "host": "192.0.2.1", "port": 2222, "vendor": "cisco_ios",
        "transport": "ssh", "fields": ["username", "password"],
        "key_ref": None, "known_hosts_ref": "/owned/known-hosts",
    }
    scope = {
        "operation_id": request.operation_id, "controller_digest": binding.controller_digest,
        "route_digest": request.context.route_digest, "plan_digest": plan.plan_digest,
        "targets": [target], "jump": None, "concurrency": 5,
    }
    return {
        "protocol": 1, "request": json.loads(c.canonical_bytes(request)),
        "scope": scope, "intents": [{"binding": binding._wire(), "kind": "collect"}],
        "credentials": {
            "operation_id": request.operation_id, "controller_digest": binding.controller_digest,
            "route_digest": request.context.route_digest,
            "targets": [dict(target, fields={"username": "unit-user", "password": SECRET})],
            "jump": None,
        },
        "budget": ControllerBudget(NONCE, 10000, 20000)._wire(),
    }


@pytest.mark.parametrize("data", [
    b"", b"\x00", struct.pack(">I", 0), struct.pack(">I", 1048577),
    struct.pack(">I", 2) + b"{", struct.pack(">I", 2) + b"{}x",
    struct.pack(">I", 2) + b"\xff\xff",
    struct.pack(">I", 13) + b'{"a":1,"a":2}',
    struct.pack(">I", 3) + b"{} ",
    struct.pack(">I", 12) + b'{"a":"\\ud800"}',
])
def test_bad_frames_fail_without_secret_or_external_effects(data):
    with pytest.raises(ProtocolError) as caught:
        _decode_frame(data)
    assert str(caught.value) == "handoff-invalid"
    assert SECRET not in repr(caught.value)


def test_nested_duplicates_nonfinite_and_extra_json_rejected():
    for text in ('{"a":{"b":1,"b":2}}', '{"a":NaN}', '{"a":1e999}', '{}{}'):
        content = text.encode("utf-8")
        with pytest.raises(ProtocolError):
            _decode_frame(struct.pack(">I", len(content)) + content)


def test_one_frame_eof_and_short_read():
    class Fragmented(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(1, size))

    frame = _encode_frame({"safe": [1, True, None, "é"]})
    assert _read_frame(Fragmented(frame), eof=True) == {"safe": [1, True, None, "é"]}
    with pytest.raises(ProtocolError):
        _read_frame(io.BytesIO(frame + frame), eof=True)
    with pytest.raises(ProtocolError):
        _read_frame(io.BytesIO(frame[:-1]), eof=True)


def test_valid_private_frame_and_exact_selected_scope(envelope):
    parsed = _parse_envelope(_decode_frame(_encode_frame(envelope)), NONCE)
    assert parsed.concurrency == 5
    assert parsed.credentials["targets"][0]["fields"]["password"] == SECRET


@pytest.mark.parametrize("change", [
    "unknown-field", "unknown-target", "task", "port-bool", "extra-credential",
    "missing-credential", "route", "jump", "nonce", "version", "sequence", "kind", "duplicates",
])
def test_scope_and_protocol_tamper_rejected_before_io(envelope, change):
    value = deepcopy(envelope)
    target = value["credentials"]["targets"][0]
    if change == "unknown-field":
        value["scope"]["surprise"] = True
    elif change == "unknown-target":
        target["target_id"] = "unselected"
    elif change == "task":
        target["task_id"] = "other"
    elif change == "port-bool":
        target["port"] = True
        value["scope"]["targets"][0]["port"] = True
    elif change == "extra-credential":
        target["fields"]["ntp_authentication_key"] = SECRET
    elif change == "missing-credential":
        target["fields"].pop("password")
    elif change == "route":
        value["credentials"]["route_digest"] = "b" * 64
    elif change == "jump":
        value["credentials"]["jump"] = dict(target, task_id="route")
    elif change == "nonce":
        value["budget"]["ready_nonce"] = "d" * 64
    elif change == "version":
        value["protocol"] = True
    elif change == "sequence":
        value["intents"][0]["binding"]["sequence"] = 1
    elif change == "kind":
        value["intents"][0]["kind"] = "arbitrary-module"
    else:
        value["scope"]["targets"] *= 2
        value["credentials"]["targets"] *= 2
        value["intents"] *= 2
    with pytest.raises((ProtocolError, c.ContractError)):
        _parse_envelope(value, NONCE)


@pytest.mark.parametrize("field,bad", [
    ("authorization_remaining_ms", 0), ("authorization_remaining_ms", 300001),
    ("operation_remaining_ms", -1), ("operation_remaining_ms", 3600001),
    ("control_timeout_ms", 2001), ("control_timeout_ms", True),
    ("authorization_remaining_ms", 1.0), ("operation_remaining_ms", True),
])
def test_all_budget_fields_strict(field, bad):
    value = ControllerBudget(NONCE, 1000, 1000)._wire()
    value[field] = bad
    with pytest.raises(ProtocolError):
        ControllerBudget._parse(value)


def test_readiness_transit_and_unrelated_origins_never_renew():
    clock = Clock(9000000.0)
    window = _BudgetWindow(clock, NONCE, D)
    clock.value += 0.6
    window.accept(ControllerBudget(NONCE, 1000, 1000), D)
    started = window.check()
    clock.value += 0.3
    window.reduce(ControllerBudget(NONCE, 1000, 1000), started)
    clock.value = 9000001.0
    with pytest.raises(ProtocolError):
        window.check()


@pytest.mark.parametrize("delay", [1.0, 30.0])
def test_expired_before_receipt_and_nonce_replay(delay):
    clock = Clock()
    window = _BudgetWindow(clock, NONCE, D)
    clock.value += delay
    with pytest.raises(ProtocolError):
        window.accept(ControllerBudget(NONCE, 1000, 1000), D)
    clock.value = 1000.0
    with pytest.raises(ProtocolError):
        window.accept(ControllerBudget(NONCE, 1000, 1000), D)


def test_control_timeout_is_request_start_not_receipt():
    clock = Clock()
    window = _BudgetWindow(clock, NONCE, D)
    window.accept(ControllerBudget(NONCE, 10000, 10000), D)
    started = window.check()
    clock.value += 2.0
    with pytest.raises(ProtocolError) as caught:
        window.reduce(ControllerBudget(NONCE, 9999, 9999), started)
    assert caught.value.reason == c.ReasonCode.CONTROL_LOST


def test_clock_reversal_and_revocation_are_terminal():
    clock = Clock()
    window = _BudgetWindow(clock, NONCE, D)
    window.accept(ControllerBudget(NONCE, 10000, 10000), D)
    clock.value -= 0.01
    with pytest.raises(ProtocolError):
        window.check()
    clock.value += 0.02
    with pytest.raises(ProtocolError):
        window.check()


@pytest.mark.parametrize("mode", [c.Mode.PREVIEW, c.Mode.CHECK])
def test_controller_pure_mode_never_accesses_any_port(operation_request, plan, mode):
    selected = replace(operation_request, mode=mode)
    proposed = replace(plan, requested_mode=mode)
    launcher = ControllerLauncher(*(Forbidden() for _ in range(5)))
    result = launcher.run(c.ControllerRequest(selected, proposed), Forbidden(), Forbidden())
    assert result.provenance["execution_performed"] is False
    assert not any(t.attempted for t in result.targets)


def test_fixed_launch_argv_and_no_shell_windows_shape(scope):
    selected = ControllerInstallation(
        scope.context, "windows-wsl", "/owned/venv/bin/python", D, D,
        r"C:\Windows\System32\wsl.exe", "Qualified-Only",
    )
    argv = selected._argv(17)
    assert argv == (
        r"C:\Windows\System32\wsl.exe", "--distribution", "Qualified-Only",
        "--exec", "/owned/venv/bin/python", "-I", "-m", "netops.ansible.worker",
        "--control-fd", "17",
    )
    assert SECRET not in repr(argv) and "bash" not in repr(argv)
    for bad in ("python", "C:\\python.exe", "/owned/../bin/python"):
        with pytest.raises(c.ContractError):
            replace(selected, python=bad)
    with pytest.raises(c.ContractError):
        replace(selected, wsl_distribution="name --exec injected")


def test_private_client_has_no_serialization_or_value_repr(binding):
    client = _ActionClient({
        "protocol": 1, "socket": "/owned/broker", "auth": NONCE,
        "intents": [{"handle": binding.occurrence_id, "binding": binding._wire(), "kind": "collect"}],
    })
    assert repr(client) == "<private>"
    with pytest.raises(TypeError):
        pickle.dumps(client)
    with pytest.raises(ProtocolError):
        client.execute(binding.occurrence_id)


def _leak_or_effect_control(value, effects):
    assert SECRET not in json.dumps(value, sort_keys=True)
    assert effects == []


def test_deliberate_secret_and_effect_negative_controls_really_fail(envelope):
    _leak_or_effect_control({"line_count": 1}, [])
    with pytest.raises(AssertionError):
        _leak_or_effect_control(envelope["credentials"], [])
    with pytest.raises(AssertionError):
        _leak_or_effect_control({"line_count": 1}, ["unselected"])


def test_jump_cannot_be_a_selected_target_or_silent_fallback(envelope):
    payload = deepcopy(envelope["credentials"])
    scope = deepcopy(envelope["scope"])
    target = payload["targets"][0]
    jump = dict(target, task_id="route")
    scope["jump"] = dict(jump, fields=["username", "password"])
    payload["jump"] = jump
    with pytest.raises(ProtocolError):
        _validate_private_payload(payload, scope)
