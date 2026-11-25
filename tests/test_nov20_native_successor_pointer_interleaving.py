"""Independent AC-003/011 pointer and completion races; source-only effects."""

from __future__ import annotations

import threading
import time
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.controller_control import _Stop
from netops.ansible.policy import contracts as lc
from netops.dependencies.runs import OwnedGenerationRuns
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_nov19_independent_controller_execution import Cancel
from tests.test_nov20_successor_controller_generation import launch_for, source_case
from tests.test_nov20_successor_generation_pins import (
    GENERATION,
    change,
    pin_case,
)


@pytest.mark.parametrize(
    "patch",
    [
        {"kind": "absent"},
        {"kind": "foreign"},
        {"revision": 2},
        {"pointer_digest": "e" * 64},
        {"extra": "not-a-pointer-field"},
    ],
)
def test_t30_full_typed_pointer_drift_blocks_without_touching_original_pin(patch):
    records, runs, selected, _ = pin_case()
    resource = "dependency-run-pin-" + c.digest(selected)
    original = records.read(resource)
    pointer = {**c.wire(records.read("control").payload["pointer"]), **patch}
    change(records, "control", pointer=pointer)
    with pytest.raises(c.ContractError):
        runs.acquire(selected, lambda: None, lambda remaining: True)
    assert records.read(resource) == original
    assert records.writes == []
    assert runs._live == {}


@pytest.mark.parametrize("revision", [True, -1, 1.0])
def test_t30_malformed_pointer_counter_rejected_at_owned_record_ingress(revision):
    records, _, selected, _ = pin_case()
    resource = "dependency-run-pin-" + c.digest(selected)
    original_pin = records.read(resource)
    original_control = records.read("control")
    pointer = {**c.wire(original_control.payload["pointer"]), "revision": revision}
    with pytest.raises(c.ContractError):
        change(records, "control", pointer=pointer)
    assert records.read("control") == original_control
    assert records.read(resource) == original_pin
    assert records.writes == []


def test_t30_pointer_writer_wins_root_lock_before_acquire_and_keeps_original_ids():
    records, runs, selected, _ = pin_case()
    resource = "dependency-run-pin-" + c.digest(selected)
    original = records.read(resource)
    attempted = threading.Event()
    outcomes = []

    def acquire():
        attempted.set()
        try:
            runs.acquire(selected, lambda: None, lambda remaining: True)
        except c.ContractError:
            outcomes.append("blocked")
        else:
            outcomes.append("incorrectly-admitted")

    with records.mutex:
        worker = threading.Thread(target=acquire)
        worker.start()
        assert attempted.wait(2.0)
        # This is a real contested root lock, not a patched acquire method.
        change(records, "control", pointer=c.wire(lc.PresentPointer(
            "present", GENERATION, c.digest((selected, 1)), 2,
        )))
    worker.join(3.0)
    assert not worker.is_alive()
    assert outcomes == ["blocked"]
    assert records.read(resource) == original
    assert records.writes == []


def test_t30_completed_original_slot_release_never_rewrites_new_active_generation():
    records, runs, selected, other = pin_case()
    pin = runs.acquire(selected, lambda: None, lambda remaining: True)
    old_resource = "dependency-run-pin-" + c.digest(selected)
    other_resource = "dependency-run-pin-" + c.digest(other)
    other_before = records.read(other_resource)
    change(records, "control", pointer=c.wire(lc.PresentPointer(
        "present", other.generation_id, c.digest((other, 2)), 2,
    )))
    control_before = records.read("control")
    runs.release(pin)
    assert records.read("control") == control_before
    assert records.read(other_resource) == other_before
    assert records.read(old_resource).payload["generation_id"] == selected.generation_id
    assert records.read(old_resource).payload["manifest_digest"] == selected.manifest_digest
    assert records.read(old_resource).payload["holders"] == ()
    with pytest.raises(c.ContractError):
        runs.release(pin)
    assert records.read("control") == control_before
    assert records.read(other_resource) == other_before


@pytest.mark.parametrize("foreign_holder", [False, True])
def test_t04_concurrent_real_completion_and_drain_preserve_foreign_crash_holder(
    tmp_path, policy, foreign_holder,
):
    verifier, context, state, runs, installed, process, adapter = source_case(tmp_path, policy)
    foreign = OwnedGenerationRuns(
        state, verifier._root_resource, verifier._active,
        state.read(verifier._root_resource).ownership_token,
        context.context.policy_identity, (verifier._generation,), verifier._generation.generation_id,
    )
    foreign_pin = None
    if foreign_holder:
        foreign_pin = foreign.acquire(
            verifier._generation, lambda: None, lambda remaining: False,
        )
    stop = _Stop(Cancel())
    entered = threading.Event()
    results, failures = [], []
    primary = c.SafeError(c.ErrorCategory.EXECUTION, c.ReasonCode.CANCELLED, c.Stage.CONTROLLER)
    process.error = primary

    def await_owned_cancellation():
        entered.set()
        assert stop._event.wait(3.0)

    process.inspect = await_owned_cancellation

    def complete():
        try:
            results.append(adapter.run(
                launch_for(context, installed), b"independent-source-only-private-frame", stop,
            ))
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=complete)
    worker.start()
    try:
        assert entered.wait(3.0)
        assert len(runs.pins()[0]["holders"]) == (2 if foreign_holder else 1)
        clock = type("RealClock", (), {"monotonic": lambda self: time.monotonic()})()
        drained = runs.drain(Cancel(), clock, time.monotonic() + 3.0)
        assert drained is (not foreign_holder)
    finally:
        stop.stop(c.ReasonCode.CANCELLED)
        worker.join(4.0)
        if foreign_pin is not None:
            # Only its exact host may release this independently retained pin.
            foreign.release(foreign_pin)
    assert not worker.is_alive()
    assert failures == []
    assert len(results) == 1
    assert results[0].error is primary
    assert results[0].cleanup == c.CleanupOutcome("succeeded")
    assert runs.pins()[0]["holders"] == ()


@pytest.mark.parametrize("fault", ["owner", "policy"])
def test_t30_durable_pin_identity_mismatch_never_becomes_empty_or_replayed(fault):
    records, runs, selected, _ = pin_case()
    resource = "dependency-run-pin-" + c.digest(selected)
    pin = runs.acquire(selected, lambda: None, lambda remaining: True)
    original = records.read(resource)
    records.records[resource] = (
        replace(original, ownership_token="9" * 64) if fault == "owner"
        else replace(
            original, policy_digest="e" * 64,
            policy_identity=replace(original.policy_identity, bundle_sha256="e" * 64),
        )
    )
    with pytest.raises(c.ContractError):
        runs.release(pin)
    assert records.read(resource).payload["holders"] == original.payload["holders"]
    records.records[resource] = original
    runs.release(pin)
    with pytest.raises(c.ContractError):
        runs.release(pin)
