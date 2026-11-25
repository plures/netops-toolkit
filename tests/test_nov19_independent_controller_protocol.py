"""Independent frozen T13/T14/T33 framing, scope and clock-budget expectations."""

from __future__ import annotations

import copy
import io
import json
import struct
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
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

NONCE = "7c" * 32
PLAN = "9" * 64


def frame(raw):
    return struct.pack(">I", len(raw)) + raw


class Clock:
    def __init__(self, value=912345.0):
        self.value = value

    def monotonic(self):
        return self.value


@pytest.mark.parametrize("data", [
    b"", b"\x00", b"\x00\x00\x00", b"\0\0\0\0",
    struct.pack(">I", 1048577),
    struct.pack(">I", 2) + b"{",
    struct.pack(">I", 1) + b"{}",
    frame(b"{}") + b"\n",
    frame(b'{"x":1,"x":2}'),
    frame(b'{"outer":{"x":1,"x":2}}'),
    frame(b'{"x":"\xff"}'),
    frame(b'{"x":"\\ud800"}'),
    frame(b'{"x":NaN}'),
    frame(b'{"x":Infinity}'),
    frame(b'{"x":1e999}'),
    frame(b"[]"), frame(b"null"),
])
def test_t13_strict_frame_rejects_malformed_before_any_effect(data):
    with pytest.raises(ProtocolError) as failure:
        _decode_frame(data)
    assert str(failure.value) == "handoff-invalid"


def test_t13_length_and_canonical_utf8_serialization_exact_wire_pin():
    raw = b'{"budget":{"control_timeout_ms":2000},"intent":"gather","schema":"1.0"}'
    assert _encode_frame({
        "schema": "1.0", "intent": "gather", "budget": {"control_timeout_ms": 2000},
    }) == struct.pack(">I", len(raw)) + raw
    assert _decode_frame(frame(raw)) == {
        "budget": {"control_timeout_ms": 2000}, "intent": "gather", "schema": "1.0",
    }


def test_t13_one_private_input_frame_rejects_appended_second_frame():
    with pytest.raises(ProtocolError):
        _read_frame(io.BytesIO(frame(b"{}") * 2), eof=True)


class FragmentedInput(io.BytesIO):
    def read(self, size=-1):
        return super().read(min(1, size))


def test_t13_partial_pipe_reads_are_joined_without_accepting_truncation():
    assert _read_frame(FragmentedInput(frame(b'{"x":true}')), eof=True) == {"x": True}
    with pytest.raises(ProtocolError):
        _read_frame(FragmentedInput(frame(b'{"x":true}')[:-1]), eof=True)


@pytest.fixture
def payload_case():
    selected = {
        "target_id": "router", "task_id": "collect", "host": "192.0.2.90",
        "port": 22, "vendor": "cisco_ios", "transport": "ssh",
        "fields": ["username", "password"], "key_ref": None,
        "known_hosts_ref": "approved-known-hosts",
    }
    scope = {
        "operation_id": "8b9985ae-5ad8-4ceb-bf39-57d5cb1b11c0",
        "controller_digest": "a" * 64, "route_digest": "b" * 64,
        "targets": [selected], "jump": None,
    }
    private = dict(
        scope, targets=[dict(selected, fields={"username": "operator", "password": "private"})],
    )
    return private, scope


def test_t13_exact_private_scope_succeeds_without_widening(payload_case):
    private, scope = payload_case
    assert _validate_private_payload(private, scope) == private


@pytest.mark.parametrize("field,value", [
    ("task_id", "apply"), ("target_id", "other"), ("host", "198.51.100.10"),
    ("port", 23), ("transport", "telnet"), ("known_hosts_ref", "unapproved"),
    ("key_ref", "unapproved-key"), ("vendor", "other"),
    ("fields", {"username": "operator", "password": "private", "enable_password": "escalation"}),
    ("extra", True),
])
def test_t13_target_task_route_and_field_widening_rejected(payload_case, field, value):
    private, scope = payload_case
    private["targets"][0][field] = value
    with pytest.raises(ProtocolError):
        _validate_private_payload(private, scope)


@pytest.mark.parametrize("change", ["unknown", "controller", "route", "operation", "duplicate"])
def test_t13_unknown_or_rebound_private_scope_rejected(payload_case, change):
    private, scope = payload_case
    if change == "unknown":
        private["allow"] = True
    elif change == "duplicate":
        private["targets"].append(copy.deepcopy(private["targets"][0]))
    else:
        name = {"controller": "controller_digest", "route": "route_digest",
                "operation": "operation_id"}[change]
        private[name] = "0" * 64
    with pytest.raises(ProtocolError):
        _validate_private_payload(private, scope)


@pytest.mark.parametrize("changes", [
    {"authorization_remaining_ms": 0}, {"authorization_remaining_ms": 300001},
    {"authorization_remaining_ms": True}, {"authorization_remaining_ms": 1.0},
    {"operation_remaining_ms": 0}, {"operation_remaining_ms": 3600001},
    {"operation_remaining_ms": float("inf")}, {"control_timeout_ms": 1999},
    {"control_timeout_ms": 2001}, {"control_timeout_ms": True},
    {"ready_nonce": "a" * 63}, {"ready_nonce": "g" * 64},
])
def test_t33_budget_types_ranges_and_nonce_are_closed(changes):
    with pytest.raises(ProtocolError):
        ControllerBudget(**dict({
            "ready_nonce": NONCE, "authorization_remaining_ms": 60000,
            "operation_remaining_ms": 300000,
        }, **changes))


def test_t33_worker_deadline_anchors_ready_not_receipt_with_unrelated_clock_origin():
    clock = Clock(912345.0)
    window = _BudgetWindow(clock, NONCE, PLAN)
    # Independent host might be at 10.0; only its remaining durations cross.
    clock.value += 0.750
    window.accept(ControllerBudget(NONCE, 1000, 10000), PLAN)
    clock.value = 912346.0
    with pytest.raises(ProtocolError) as failure:
        window.check()
    assert failure.value.reason == c.ReasonCode.DEADLINE_EXCEEDED


@pytest.mark.parametrize("change", ["nonce", "plan", "replay", "expired-transit"])
def test_t33_ready_nonce_plan_replay_and_exhausted_transit_reject(change):
    clock = Clock()
    window = _BudgetWindow(clock, NONCE, PLAN)
    budget = ControllerBudget(NONCE, 1000, 10000)
    if change == "nonce":
        budget = replace(budget, ready_nonce="ab" * 32)
    if change == "replay":
        window.accept(budget, PLAN)
    if change == "expired-transit":
        clock.value += 1.0
    with pytest.raises(ProtocolError):
        window.accept(budget, "f" * 64 if change == "plan" else PLAN)


def test_t33_control_reply_reduction_anchors_request_and_never_renews():
    clock = Clock()
    origin = clock.value
    window = _BudgetWindow(clock, NONCE, PLAN)
    window.accept(ControllerBudget(NONCE, 10000, 20000), PLAN)
    clock.value = origin + 2.0
    request_start = window.check()
    clock.value += 0.8
    window.reduce(ControllerBudget(NONCE, 1000, 1000), request_start)
    clock.value = origin + 3.0
    with pytest.raises(ProtocolError):
        window.check()


def test_t33_control_roundtrip_at_two_seconds_is_lost_not_renewed():
    clock = Clock()
    window = _BudgetWindow(clock, NONCE, PLAN)
    window.accept(ControllerBudget(NONCE, 10000, 20000), PLAN)
    request_start = window.check()
    clock.value += 2.0
    with pytest.raises(ProtocolError) as failure:
        window.reduce(ControllerBudget(NONCE, 9000, 19000), request_start)
    assert failure.value.reason == c.ReasonCode.CONTROL_LOST


@pytest.mark.parametrize("stop", ["backward", "nan", "inf", "revoke"])
def test_t33_invalid_worker_clock_or_revoke_blocks_dispatch(stop):
    clock = Clock()
    window = _BudgetWindow(clock, NONCE, PLAN)
    window.accept(ControllerBudget(NONCE, 10000, 20000), PLAN)
    if stop == "revoke":
        window.revoke()
    else:
        clock.value = {"backward": clock.value - 1.0, "nan": float("nan"),
                       "inf": float("inf")}[stop]
    with pytest.raises(ProtocolError):
        window.check()


def test_t08_dispatch_binding_exact_response_serialization_pin():
    binding = DispatchBinding(
        "8b9985ae-5ad8-4ceb-bf39-57d5cb1b11c0", "a" * 64, "b" * 64,
        "c5697c92-e0be-41d9-b2d0-582b65ed91eb", "effect-0", "router", "collect",
        "credential", 0,
    )
    expected = (
        '{"controller_digest":"' + "b" * 64
        + '","invocation_id":"c5697c92-e0be-41d9-b2d0-582b65ed91eb",'
        '"occurrence_id":"effect-0","operation_id":"8b9985ae-5ad8-4ceb-bf39-57d5cb1b11c0",'
        '"phase":"credential","plan_digest":"' + "a" * 64
        + '","sequence":0,"target_id":"router","task_id":"collect"}'
    ).encode()
    assert _encode_frame(binding._wire()) == frame(expected)
    assert DispatchBinding._parse(json.loads(expected)) == binding
