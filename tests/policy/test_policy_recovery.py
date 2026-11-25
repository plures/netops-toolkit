"""Owned event replay tests using the real reducer and inert byte-backed state.

These are not native storage, platform, controller or device qualification.
"""

from __future__ import annotations

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from netops.ansible.artifacts import ArtifactError, OwnedPolicyJournal, OwnedRecord
from netops.ansible.contracts import (
    ErrorCategory,
    PlanBinding,
    ReasonCode,
    SafeError,
    Stage,
    digest,
    public_object,
)
from netops.ansible.policy import LocalReferencePolicyEngine, load_policy
from netops.ansible.policy.contracts import (
    MAX_SAFE_INT,
    DecisionEvent,
    DecisionFacts,
    EventKind,
    Phase,
    PolicyIdentity,
    PolicyState,
    StepDisposition,
)
from tests import test_owned_state as owned_state_tests

D = "a" * 64
OWNER = "1" * 64
memory_state = owned_state_tests.memory_state


class ByteState:
    """Inert owned-record serialization/CAS double, not an OS-lock proof."""

    def __init__(self):
        self.content = None
        self.writes = 0
        self.mutex = threading.RLock()

    def lock(self, resource_ids, timeout):
        return self.mutex

    def read(self, resource_id):
        if self.content is None:
            raise ArtifactError(SafeError(
                ErrorCategory.PRECONDITION, ReasonCode.OWNERSHIP_INVALID, Stage.RECOVER,
            ))
        record = OwnedRecord.from_bytes(self.content)
        if record.resource_id != resource_id:
            raise ArtifactError(SafeError(
                ErrorCategory.PRECONDITION, ReasonCode.OWNERSHIP_INVALID, Stage.RECOVER,
            ))
        return record

    def compare_replace(self, resource_id, expected_revision, record):
        if self.content is None:
            assert expected_revision == record.revision == 0
        else:
            current = self.read(resource_id)
            assert current.revision == expected_revision
            assert record.revision == expected_revision + 1 <= MAX_SAFE_INT
        self.content = record.to_bytes()
        self.writes += 1
        return OwnedRecord.from_bytes(self.content)


@pytest.fixture(scope="module")
def policy():
    root = Path(__file__).resolve().parents[2] / "netops" / "ansible" / "policy"
    assets = tuple((root / name).read_bytes() for name in (
        "ansible_molecule.px", "ansible_molecule.contracts.px", "bundle.json",
    ))
    bundle = json.loads(assets[2])
    identity = PolicyIdentity(
        bundle["canonical_revision"], *(hashlib.sha256(value).hexdigest() for value in assets),
        tuple(rule["id"] for rule in bundle["manifest"]), bundle["reducer_version"],
    )
    return identity, LocalReferencePolicyEngine(load_policy(*assets, identity))


@pytest.fixture
def history(policy):
    identity, engine = policy
    binding = PlanBinding(str(uuid4()), D, identity.bundle_sha256, *(D,) * 5, "owned", 0, ())
    initial = PolicyState(
        identity, binding.operation_id, 0, Phase.PLANNED, binding.plan_digest,
        binding.context_digest, identity.bundle_sha256,
    )
    event = DecisionEvent(
        str(uuid4()), EventKind.OPERATION_REQUESTED, 0, binding.plan_digest,
        binding.context_digest, identity.bundle_sha256, "local", "preview",
        public_object({
            "request_digest": D, "loaded_input_digest": D, "plan_digest": D, "mode": "preview",
        }), operation_id=binding.operation_id,
    )
    facts = DecisionFacts(public_object({
        "request": {"area": "health", "operation": "gather", "mode": "preview"},
        "binding": {"input_valid": True, "plan_current": True, "policy_current": True},
        "control": {"cancelled": False, "remaining_ms": 1000},
        "scope": {"exclusions_valid": True, "selected_count": 0},
        "config": {"enabled": False, "mode": "audit"},
        "inventory": {"source_valid": True, "cache_binding_valid": True, "hostvars_safe": True},
    }))
    storage = ByteState()
    journal = OwnedPolicyJournal(storage, engine, binding, identity, OWNER)
    return journal, storage, initial, event, facts, binding


def cancelled(state, facts):
    return DecisionEvent(
        str(uuid4()), EventKind.CANCELLED, state.revision, state.plan_digest,
        state.context_digest, state.policy_digest, "local", "cancel",
        public_object({
            "accepted_host_receipt": "host-cancel-receipt", "revocation_revision": state.revision,
            "safe_reason": "cancelled",
        }), operation_id=state.operation_id,
    ), DecisionFacts(
        public_object({
            **dict(facts.values), "control": {"cancelled": True, "remaining_ms": 1000},
        }),
        state.phase, state.revision,
    )


def test_owned_history_reconstructs_actual_reducer_state_without_authority(history, policy):
    journal, storage, initial, event, facts, binding = history
    first = journal.create(initial, event, facts)
    assert first.state.revision == 1
    assert storage.writes == 1
    restarted = OwnedPolicyJournal(storage, policy[1], binding, policy[0], OWNER)
    assert restarted.recover() == first.state
    second_event, second_facts = cancelled(first.state, facts)
    second = restarted.append(0, second_event, second_facts)
    assert second.checkpoint_revision == 1
    assert restarted.recover() == second.state
    assert second.state.phase == Phase.CANCELLING
    assert not hasattr(second, "permit")
    assert not hasattr(second, "effects")


def test_historical_duplicate_returns_original_receipt_without_write(history):
    journal, storage, initial, event, facts, _ = history
    first = journal.create(initial, event, facts)
    second_event, second_facts = cancelled(first.state, facts)
    journal.append(0, second_event, second_facts)
    content, writes = storage.content, storage.writes
    receipt = journal.append(0, event, facts)
    assert receipt == replace(first, duplicate=True)
    assert storage.content == content
    assert storage.writes == writes


@pytest.mark.parametrize("changed", ["event", "facts", "revision", "gap"])
def test_conflicting_replay_and_stale_cas_leave_owned_bytes_unchanged(history, changed):
    journal, storage, initial, event, facts, _ = history
    first = journal.create(initial, event, facts)
    next_event, next_facts = cancelled(first.state, facts)
    expected = 0
    if changed == "event":
        next_event, next_facts = replace(event, step_id="other"), facts
    elif changed == "facts":
        next_event = event
        next_facts = replace(facts, values=public_object({
            **dict(facts.values), "scope": {"exclusions_valid": True, "selected_count": 1},
        }))
    elif changed == "revision":
        expected = 1
    else:
        next_event = replace(next_event, expected_revision=3)
    content = storage.content
    with pytest.raises(ArtifactError):
        journal.append(expected, next_event, next_facts)
    assert storage.content == content
    assert storage.writes == 1


@pytest.mark.parametrize("field", tuple(PlanBinding.__dataclass_fields__))
def test_recovery_rejects_every_changed_current_binding(history, policy, field):
    journal, storage, initial, event, facts, binding = history
    journal.create(initial, event, facts)
    changes = {
        "operation_id": str(uuid4()), "generation": 1, "root_ref": "another-owned-root",
        "recovery_scope": ("new-scope",),
    }
    changed = replace(binding, **{field: changes.get(field, "b" * 64)})
    before = storage.content
    with pytest.raises(ArtifactError):
        OwnedPolicyJournal(storage, policy[1], changed, policy[0], OWNER).recover()
    assert storage.content == before


@pytest.mark.parametrize("change", ["digest", "state", "unknown", "event-order", "counter"])
def test_recovery_does_not_trust_persisted_state_or_facts(history, change):
    journal, storage, initial, event, facts, _ = history
    journal.create(initial, event, facts)
    document = json.loads(storage.content)
    entry = document["payload"]["events"][0]
    if change == "digest":
        entry["state_digest"] = "b" * 64
    elif change == "state":
        document["payload"]["initial"]["phase"] = "Completed"
    elif change == "unknown":
        entry["facts"]["unknown"] = True
    elif change == "event-order":
        entry["event"]["expected_revision"] = 1
    else:
        entry["checkpoint_revision"] = True
    storage.content = json.dumps(document).encode()
    before = storage.content
    with pytest.raises(ArtifactError):
        journal.recover()
    assert storage.content == before


def test_pending_invocation_recovers_uncertain_and_never_redispatches(history):
    journal, storage, initial, event, facts, _ = history
    initial = replace(initial, dispositions=(StepDisposition(
        "r1", "apply", invocation_id="issued-invocation", effect_id="issued-effect",
    ),))
    journal.create(initial, event, facts)
    before = storage.content
    recovered = journal.recover()
    assert recovered.phase == Phase.UNCERTAIN
    assert recovered.remote_uncertain is True
    assert recovered.dispositions[0].result_digest is None
    assert storage.content == before


def test_concurrent_same_event_has_one_owned_cas_and_one_duplicate(history):
    journal, storage, initial, event, facts, _ = history
    first = journal.create(initial, event, facts)
    next_event, next_facts = cancelled(first.state, facts)
    barrier = threading.Barrier(2)

    def append():
        barrier.wait()
        return journal.append(0, next_event, next_facts)

    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(lambda _: append(), range(2)))
    assert sorted(receipt.duplicate for receipt in receipts) == [False, True]
    assert storage.writes == 2
    assert digest(receipts[0].state) == digest(receipts[1].state)


def test_actual_owned_state_byte_cas_retains_prior_event_checkpoint(history, policy, memory_state):
    """Compose the real C02 CAS with memory I/O; no OS protection claim."""
    _, _, initial, event, facts, binding = history
    state, files = memory_state
    journal = OwnedPolicyJournal(state, policy[1], binding, policy[0], OWNER)
    first = journal.create(initial, event, facts)
    second_event, second_facts = cancelled(first.state, facts)
    journal.append(0, second_event, second_facts)
    restarted = OwnedPolicyJournal(state, policy[1], binding, policy[0], OWNER)
    assert restarted.recover().phase == Phase.CANCELLING
    assert state.read("policy/" + binding.operation_id).revision == 1
    retained = state.retained("policy/" + binding.operation_id, 0)
    assert len(retained.payload["events"]) == 1
    before = dict(files)
    with pytest.raises(ArtifactError):
        journal.create(initial, event, facts)
    assert files == before


@pytest.mark.parametrize("revision", [True, -1, 0.0, MAX_SAFE_INT + 1])
def test_invalid_checkpoint_counters_cannot_replay_or_write(history, revision):
    journal, storage, initial, event, facts, _ = history
    journal.create(initial, event, facts)
    before = storage.content
    with pytest.raises(ArtifactError):
        journal.append(revision, event, facts)
    assert storage.content == before


def test_corrupt_missing_checkpoint_is_not_recreated(history):
    journal, storage, _, _, _, _ = history
    with pytest.raises(ArtifactError):
        journal.recover()
    assert storage.writes == 0
    storage.content = b'{"revision":0,"revision":0}'
    with pytest.raises(ArtifactError):
        journal.recover()
    assert storage.writes == 0
