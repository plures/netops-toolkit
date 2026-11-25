"""Independent AC-003/011 exact generation pin proofs; source units, not Q03."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.artifacts import OwnedRecord
from netops.ansible.policy import contracts as lc
from netops.dependencies.runs import OwnedGenerationRuns
from tests.test_nov19_independent_credentials import Clock, policy_identity

GENERATION = "a198636a-4213-4f60-8b1b-4fa41c3b7e55"
OTHER = "25950d6a-1800-4d41-a5cd-d0bb11b74396"
HOLDER = "dfde7aef-93f3-43a5-93b7-cde9f80a99e8"
OWNER = "7" * 64


class Records:
    """Checked in-memory effect port; no live controller or permission claim."""

    def __init__(self, identity):
        self.identity = identity
        self.records = {}
        self.writes = []
        self.mutex = threading.RLock()

    def seed(self, resource, payload):
        value = OwnedRecord(
            resource, "checkpoint", 0, 0, OWNER, self.identity.bundle_sha256,
            self.identity.reducer_version, c.public_object(payload), self.identity,
        )
        self.records[resource] = value
        return value

    @contextmanager
    def lock(self, resources, timeout):
        assert resources == ("root",)
        assert timeout == 0.0
        with self.mutex:
            yield

    def read(self, resource):
        try:
            return self.records[resource]
        except KeyError:
            raise FileNotFoundError(resource) from None

    def compare_replace(self, resource, expected, record):
        current = self.records.get(resource)
        assert current is None and expected == record.revision == 0 or (
            current is not None and current.revision == expected
            and record.revision == expected + 1
        )
        self.records[resource] = record
        self.writes.append(resource)
        return record


class Cancel:
    def __init__(self):
        self.value = False

    def is_cancelled(self):
        return self.value


def pin_case():
    identity = policy_identity()
    selected = lc.GenerationBinding(GENERATION, 0, "1" * 64, "2" * 64)
    other = lc.GenerationBinding(OTHER, 0, "3" * 64, "4" * 64)
    records = Records(identity)
    records.seed("root", {"root_manifest": {"control_resource": "control"}})
    records.seed("control", {
        "pointer": c.wire(lc.PresentPointer(
            "present", GENERATION, c.digest((selected, 1)), 1,
        )),
        "setup_enabled": True, "admission_enabled": True,
    })
    runs = OwnedGenerationRuns(records, "root", "control", OWNER, identity,
                               (selected, other), GENERATION)
    runs.initialize()
    records.writes.clear()
    return records, runs, selected, other


def change(records, resource, **fields):
    current = records.read(resource)
    records.records[resource] = replace(
        current, payload=c.public_object({**dict(current.payload), **fields}),
    )


def test_t30_run_pin_consumed_public_record_has_exact_nonempty_literal(monkeypatch):
    records, runs, selected, _ = pin_case()
    monkeypatch.setattr("netops.dependencies.runs.uuid4", lambda: HOLDER)
    joined = []
    pin = runs.acquire(selected, lambda: None, lambda remaining: joined.append(remaining) or True)
    assert c.canonical_bytes(runs.pins()).decode() == (
        '[{"generation_id":"a198636a-4213-4f60-8b1b-4fa41c3b7e55",'
        '"holders":["dfde7aef-93f3-43a5-93b7-cde9f80a99e8"],'
        '"manifest_digest":"' + "2" * 64 + '","revision":1}]'
    )
    with pytest.raises(c.ContractError):
        c.canonical_bytes(pin)
    clock = Clock()
    assert runs.drain(Cancel(), clock, clock.now + 10.0)
    assert joined == [10.0]
    assert runs.pins()[0]["holders"] == ()
    assert runs.pins()[0]["revision"] == 2
    with pytest.raises(c.ContractError):
        runs.release(pin)


@pytest.mark.parametrize("field,value", [
    ("setup_enabled", False), ("setup_enabled", 1), ("admission_enabled", False),
    ("admission_enabled", 1),
])
def test_t30_disabled_or_nonboolean_shared_control_never_admits_run(field, value):
    records, runs, selected, _ = pin_case()
    change(records, "control", **{field: value})
    with pytest.raises(c.ContractError):
        runs.acquire(selected, lambda: None, lambda remaining: True)
    assert not records.writes
    assert runs.pins()[0]["holders"] == ()


@pytest.mark.parametrize("resource", ["root", "control"])
def test_t30_wrong_root_or_control_owner_blocks_before_holder_write(resource):
    records, runs, selected, _ = pin_case()
    records.records[resource] = replace(records.read(resource), ownership_token="8" * 64)
    with pytest.raises(c.ContractError):
        if resource == "root":
            runs.initialize()
        else:
            runs.acquire(selected, lambda: None, lambda remaining: True)
    assert not records.writes


@pytest.mark.parametrize("field,value", [
    ("manifest_digest", "5" * 64), ("content_digest", "6" * 64), ("ordinal", 1),
])
def test_t30_same_generation_uuid_does_not_admit_different_exact_binding(field, value):
    records, runs, selected, _ = pin_case()
    with pytest.raises(c.ContractError):
        runs.acquire(replace(selected, **{field: value}), lambda: None, lambda remaining: True)
    assert not records.writes


def test_t30_stale_active_uuid_blocks_before_any_dispatch_pin():
    records, runs, selected, other = pin_case()
    change(records, "control", pointer=c.wire(lc.PresentPointer(
        "present", OTHER, c.digest((other, 2)), 2,
    )))
    with pytest.raises(c.ContractError):
        runs.acquire(selected, lambda: None, lambda remaining: True)
    assert not records.writes
    assert all(record["holders"] == () for record in runs.pins())


def test_t30_active_pointer_content_digest_drift_must_not_admit_exact_uuid():
    records, runs, selected, _ = pin_case()
    change(records, "control", pointer=c.wire(lc.PresentPointer(
        "present", GENERATION, "f" * 64, 1,
    )))
    with pytest.raises(c.ContractError):
        runs.acquire(selected, lambda: None, lambda remaining: True)
    assert not records.writes


def test_t04_failed_actual_join_keeps_durable_holder_until_join_succeeds():
    records, runs, selected, _ = pin_case()
    cancelled = []
    joined = []
    complete = [False]
    runs.acquire(
        selected, lambda: cancelled.append(True),
        lambda remaining: joined.append(remaining) or complete[0],
    )
    runs.stop_admission()
    clock = Clock()
    assert runs.drain(Cancel(), clock, clock.now + 10.0) is False
    retained = runs.pins()
    assert len(retained[0]["holders"]) == 1
    assert records.read("control").payload["admission_enabled"] is False
    with pytest.raises(c.ContractError):
        runs.acquire(selected, lambda: None, lambda remaining: True)
    complete[0] = True
    assert runs.drain(Cancel(), clock, clock.now + 5.0) is True
    assert cancelled == [True, True] and joined == [10.0, 5.0]
    assert runs.pins()[0]["holders"] == ()


def test_t28_fresh_host_never_expires_or_steals_a_crash_retained_holder():
    records, runs, selected, other = pin_case()
    runs.acquire(selected, lambda: None, lambda remaining: False)
    runs.stop_admission()
    persisted = runs.pins()
    fresh = OwnedGenerationRuns(records, "root", "control", OWNER, records.identity,
                                (selected, other), GENERATION)
    fresh.initialize()
    clock = Clock()
    assert fresh.drain(Cancel(), clock, clock.now + 10.0) is False
    assert fresh.pins() == persisted
    assert records.read("control").payload["admission_enabled"] is False


@pytest.mark.parametrize("fault", ["revision", "duplicate", "manifest", "unknown-field"])
def test_t30_corrupt_persisted_holder_is_not_treated_as_empty(fault):
    records, runs, selected, _ = pin_case()
    resource = "dependency-run-pin-" + c.digest(selected)
    value = dict(records.read(resource).payload)
    if fault == "revision":
        value["revision"] = 1
    elif fault == "duplicate":
        value["holders"] = (HOLDER, HOLDER)
    elif fault == "manifest":
        value["manifest_digest"] = "f" * 64
    else:
        value["unrecognized"] = True
    change(records, resource, **value)
    with pytest.raises(c.ContractError):
        runs.pins()
    with pytest.raises(c.ContractError):
        runs.acquire(selected, lambda: None, lambda remaining: True)
    assert not records.writes


def test_t04_original_deadline_and_cancel_do_not_remove_unjoined_owned_holder():
    _, runs, selected, _ = pin_case()
    cancelled = []
    joined = []
    runs.acquire(selected, lambda: cancelled.append(True),
                 lambda remaining: joined.append(remaining) or True)
    clock = Clock()
    assert runs.drain(Cancel(), clock, clock.now) is False
    assert cancelled == [True] and not joined and runs.pins()[0]["holders"]
    cancel = Cancel()
    cancel.value = True
    assert runs.drain(cancel, clock, clock.now + 20.0) is False
    assert cancelled == [True, True] and not joined and runs.pins()[0]["holders"]
