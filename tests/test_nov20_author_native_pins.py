"""Author controls for exact pointers and same-host release; not qualification."""

import threading

import pytest

from netops.ansible import contracts as c
from tests.test_nov20_successor_generation_pins import Cancel, Clock, change, pin_case


@pytest.mark.parametrize("pointer", [
    {"kind": "absent", "revision": 0},
    {"kind": "unknown", "revision": 1},
    {"kind": "present", "revision": 1},
])
def test_full_typed_pointer_rejects_before_any_holder_write(pointer):
    """Malformed or absent pointers cannot admit a run or reopen admission."""
    records, runs, generation, _ = pin_case()
    change(records, "control", pointer=pointer)
    with pytest.raises(c.ContractError):
        runs.acquire(generation, lambda: None, lambda remaining: True)
    with pytest.raises(c.ContractError):
        runs.start_admission(generation)
    assert not records.writes


@pytest.mark.parametrize("revision", [True, 1.0, -1, 9007199254740992])
def test_pointer_revision_rejects_at_durable_typed_boundary(revision):
    """Non-int53 pointers cannot even enter the protected control record."""
    records, _, _, _ = pin_case()
    with pytest.raises(c.ContractError):
        change(records, "control", pointer={"kind": "present", "revision": revision})
    assert not records.writes


def test_same_host_owner_release_during_actual_join_is_single_durable_release():
    """The normal owner can finish while drain is joining its exact snapshot."""
    records, runs, generation, _ = pin_case()
    complete = threading.Event()
    joining = threading.Event()
    errors = []
    result = []

    def join(remaining):
        joining.set()
        return complete.wait(remaining)

    pin = runs.acquire(generation, lambda: None, join)
    runs.stop_admission()
    clock = Clock()

    def drain():
        try:
            result.append(runs.drain(Cancel(), clock, clock.now + 10))
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=drain)
    worker.start()
    try:
        assert joining.wait(5)
        # This is the normal successful consuming owner's release, not a fake
        # completed flag, crash expiry or permission to sweep other holders.
        runs.release(pin)
        complete.set()
    finally:
        complete.set()
        worker.join(5)
    assert not worker.is_alive() and not errors and result == [True]
    assert runs.pins()[0]["holders"] == ()
    assert runs.pins()[0]["revision"] == 2
    assert records.writes.count(runs._resource(generation)) == 2
    with pytest.raises(c.ContractError):
        runs.release(pin)


def test_reentrant_cancel_owner_completion_is_not_a_second_release():
    """Cancel callbacks may run successful teardown and release before join."""
    _, runs, generation, _ = pin_case()
    pin = None
    calls = []

    def cancel():
        calls.append("cancel")
        runs.release(pin)

    def join(remaining):
        calls.append("joined")
        return True

    pin = runs.acquire(generation, cancel, join)
    clock = Clock()
    assert runs.drain(Cancel(), clock, clock.now + 10)
    assert calls == ["cancel", "joined"]
    assert runs.pins()[0]["revision"] == 2


def test_completed_local_pin_does_not_sweep_sibling_or_crash_holder():
    """The same-store sibling remains durable after this host completes."""
    from netops.dependencies.runs import OwnedGenerationRuns

    records, runs, generation, other = pin_case()
    sibling = OwnedGenerationRuns(
        records, "root", "control", runs.owner, runs.identity,
        (generation, other), generation.generation_id,
    )
    sibling.acquire(generation, lambda: None, lambda remaining: False)
    pin = None

    def join(remaining):
        runs.release(pin)
        return True

    pin = runs.acquire(generation, lambda: None, join)
    runs.stop_admission()
    clock = Clock()
    assert not runs.drain(Cancel(), clock, clock.now + 10)
    assert len(runs.pins()[0]["holders"]) == 1
    assert records.read("control").payload["admission_enabled"] is False
    assert not runs.drain(Cancel(), clock, clock.now + 10)
    assert len(runs.pins()[0]["holders"]) == 1


def test_join_failure_keeps_original_exception_and_exact_holder():
    """Arbitrary callback errors are never swallowed as normal completion."""
    _, runs, generation, _ = pin_case()
    failure = RuntimeError("author-join-failure")

    def join(remaining):
        raise failure

    pin = runs.acquire(generation, lambda: None, join)
    before = runs.pins()
    clock = Clock()
    with pytest.raises(RuntimeError) as caught:
        runs.drain(Cancel(), clock, clock.now + 10)
    assert caught.value is failure and runs.pins() == before
    runs.release(pin)


def test_holder_removal_without_successful_owner_release_is_not_completion():
    """A disappeared durable holder must still fail the exact release check."""
    records, runs, generation, _ = pin_case()

    def join(remaining):
        resource = runs._resource(generation)
        change(records, resource, holders=())
        return True

    runs.acquire(generation, lambda: None, join)
    clock = Clock()
    with pytest.raises(c.ContractError):
        runs.drain(Cancel(), clock, clock.now + 10)
