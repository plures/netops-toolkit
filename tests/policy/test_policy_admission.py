"""Memory-only host admission controls; no controller or owned-file qualification."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import pickle
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from functools import partial
from pathlib import Path
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import (
    AdmissionSnapshot,
    AuthorizationBroker,
    AuthorizationError,
    TrustedConsentAdapter,
    bind_plan,
)
from netops.ansible.policy.contracts import (
    MAX_SAFE_INT,
    DecisionResult,
    EffectDescriptor,
    FrozenObject,
    PolicyIdentity,
)
from netops.ansible.workflows import plan_digest

D = "a" * 64


class Review:
    def __init__(self):
        self.accept = True
        self.calls = 0

    def confirm(self, plan, binding, deadline):
        self.calls += 1
        return self.accept


class MemoryState:
    def __init__(self, binding):
        self.binding = binding
        self.revision = 0
        self.cancelled = False
        self.dispatch_enabled = True
        self.mutex = threading.RLock()
        self.advances = []

    def lock(self, operation_id):
        return self.mutex

    def snapshot(self, operation_id):
        assert operation_id == self.binding.operation_id
        return AdmissionSnapshot(
            self.binding, self.revision, self.cancelled, self.dispatch_enabled,
        )

    def compare_revision(self, operation_id, expected_revision, next_revision):
        assert operation_id == self.binding.operation_id
        if self.revision != expected_revision:
            return False
        self.advances.append((expected_revision, next_revision))
        self.revision = next_revision
        return True


@pytest.fixture
def admission():
    root = Path(__file__).resolve().parents[2] / "netops" / "ansible" / "policy"
    bundle = (root / "bundle.json").read_bytes()
    parsed = json.loads(bundle)
    identity = PolicyIdentity(
        parsed["canonical_revision"],
        hashlib.sha256((root / "ansible_molecule.px").read_bytes()).hexdigest(),
        hashlib.sha256((root / "ansible_molecule.contracts.px").read_bytes()).hexdigest(),
        hashlib.sha256(bundle).hexdigest(),
        tuple(item["id"] for item in parsed["manifest"]),
        parsed["reducer_version"],
    )
    effects = tuple(c.PlannedEffect(f"effect-{i}", i, "gather", "r1", f"step-{i}") for i in range(2))
    plan = c.OperationPlan(
        str(uuid4()), "health.gather", c.Mode.OBSERVE, ("r1",),
        (FrozenObject((("target_id", "r1"),)),),
        c.Context("controller-local", D, "fixture", D, identity, D, D),
        D, D, identity.bundle_sha256, identity.reducer_version, effects, (), (),
        FrozenObject(), c.OutputIntent(), 1, 10000, ("recovery-1",), D,
    )
    plan = replace(plan, plan_digest=plan_digest(plan))
    binding = bind_plan(plan, "owned-root", 0)
    state = MemoryState(binding)
    review = Review()
    consent_adapter = TrustedConsentAdapter(review)
    broker = AuthorizationBroker(state, consent_adapter)
    decision = DecisionResult(
        "allow", ("netops.companion.test",), "allowed",
        tuple(EffectDescriptor("request_effect", FrozenObject((("kind", e.kind),))) for e in effects),
        plan.policy_digest,
    )
    consent = consent_adapter.review(plan, binding, 10.0, 10.0)
    return plan, binding, state, review, consent_adapter, broker, decision, consent


def issue(admission):
    plan, _, _, _, _, broker, decision, consent = admission
    return broker.issue(plan, consent, decision, 10.0)


def effect(binding, index=0, revision=0, event_id=None):
    return c.EffectBinding(
        binding, event_id or str(uuid4()), revision, f"effect-{index}",
        "r1", f"step-{index}", ("recovery-1",),
    )


def race(action):
    barrier = threading.Barrier(2)

    def attempt(_):
        barrier.wait()
        try:
            return action()
        except AuthorizationError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        return list(pool.map(attempt, range(2)))


def test_one_consume_and_one_occurrence_reservation(admission):
    _, binding, state, _, _, broker, _, _ = admission
    grant = issue(admission)
    sessions = race(lambda: broker.consume(grant, binding, 11.0))
    assert sum(value is not None for value in sessions) == 1
    session = next(value for value in sessions if value is not None)
    permits = race(lambda: broker.permit(session, effect(binding), 12.0))
    assert sum(value is not None for value in permits) == 1
    assert state.advances == [(0, 1)]
    with pytest.raises(AuthorizationError):
        broker.permit(session, effect(binding, 0, 1), 12.0)
    second = broker.permit(session, effect(binding, 1, 1), 12.0)
    assert isinstance(second, c.EffectPermit)
    assert state.advances == [(0, 1), (1, 2)]


def test_trusted_receipt_is_not_a_boolean_or_forged_private_object(admission):
    plan, binding, _, review, adapter, broker, decision, consent = admission
    for forged in (True, "yes", {}, object(), object.__new__(type(consent))):
        with pytest.raises(AuthorizationError):
            broker.issue(plan, forged, decision, 10.0)
    review.accept = False
    with pytest.raises(AuthorizationError):
        adapter.review(plan, binding, 10.0, 5.0)
    issue(admission)
    with pytest.raises(AuthorizationError):
        broker.issue(plan, consent, decision, 10.0)


@pytest.mark.parametrize("field", tuple(c.PlanBinding.__dataclass_fields__))
def test_every_binding_dimension_rechecked_at_consume(admission, field):
    _, binding, _, _, _, broker, _, _ = admission
    grant = issue(admission)
    changes = {
        "operation_id": str(uuid4()), "generation": 1,
        "root_ref": "other-root", "recovery_scope": (),
    }
    changed = replace(binding, **{field: changes.get(field, "b" * 64)})
    with pytest.raises(AuthorizationError):
        broker.consume(grant, changed, 11.0)
    assert isinstance(broker.consume(grant, binding, 11.0), c.AdmissionSession)


@pytest.mark.parametrize("stage", ["issue", "consume", "permit"])
def test_current_host_drift_rejects_under_lock(admission, stage):
    plan, binding, state, _, _, broker, decision, consent = admission
    grant = None if stage == "issue" else issue(admission)
    session = broker.consume(grant, binding, 11.0) if stage == "permit" else None
    state.binding = replace(binding, generation=1)
    with pytest.raises(AuthorizationError):
        if stage == "issue":
            broker.issue(plan, consent, decision, 10.0)
        elif stage == "consume":
            broker.consume(grant, binding, 11.0)
        else:
            broker.permit(session, effect(binding), 12.0)
    assert state.advances == []


def test_deadline_is_original_not_renewed_by_consume_or_permit(admission):
    _, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 19.0)
    broker.permit(session, effect(binding), 19.5)
    with pytest.raises(AuthorizationError):
        broker.permit(session, effect(binding, 1, 1), 20.0)
    assert state.revision == 1


@pytest.mark.parametrize("now", [math.nan, math.inf, -math.inf, -1.0, True, 10, "10"])
def test_invalid_clock_never_issues_or_consumes(admission, now):
    plan, _, state, _, _, broker, decision, consent = admission
    with pytest.raises(AuthorizationError):
        broker.issue(plan, consent, decision, now)
    assert state.revision == 0


@pytest.mark.parametrize("now", [math.nan, math.inf, -math.inf, -1.0, True, 10, "10"])
def test_invalid_clock_at_consume_revokes_pending_authority(admission, now):
    _, binding, state, _, _, broker, _, _ = admission
    grant = issue(admission)
    with pytest.raises(AuthorizationError):
        broker.consume(grant, binding, now)
    assert state.revision == 0


def test_deadline_overflow_and_clock_rollback_reject(admission):
    plan, binding, _, _, adapter, broker, _, _ = admission
    with pytest.raises(AuthorizationError):
        adapter.review(plan, binding, 1.7e308, 1.7e308)
    grant = issue(admission)
    with pytest.raises(AuthorizationError):
        broker.consume(grant, binding, 9.0)


def test_private_values_reject_copy_pickle_json_and_value_repr(admission):
    _, binding, _, _, _, broker, _, consent = admission
    grant = issue(admission)
    session = broker.consume(grant, binding, 11.0)
    permit = broker.permit(session, effect(binding), 12.0)
    for value in (consent, grant, session, permit):
        assert repr(value) == "<private>"
        assert vars(value) == {}
        for serializer in (pickle.dumps, copy.copy, copy.deepcopy, json.dumps, c.canonical_bytes):
            with pytest.raises((TypeError, c.ContractError)):
                serializer(value)
    forged = object.__new__(type(grant))
    with pytest.raises(AuthorizationError):
        broker.consume(forged, binding, 12.0)


@pytest.mark.parametrize("field,value", [
    ("occurrence_id", "gather"), ("target_id", "r2"), ("step_id", "step-1"),
    ("recovery_scope", ()), ("expected_revision", 1),
])
def test_exact_occurrence_not_action_name_or_changed_scope(admission, field, value):
    _, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    with pytest.raises(AuthorizationError):
        broker.permit(session, replace(effect(binding), **{field: value}), 12.0)
    assert state.advances == []
    with pytest.raises(AuthorizationError):
        broker.permit(session, effect(binding, 1), 12.0)
    broker.permit(session, effect(binding), 12.0)


def test_cancel_before_reservation_and_completion_cannot_unrevoke(admission):
    plan, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    selected = effect(binding)
    permit = broker.permit(session, selected, 12.0)
    broker.enter(permit, selected, 12.0)
    broker.revoke(plan.operation_id)
    assert broker.reconcile(permit).occurrence_id == "effect-0"
    broker.complete(permit, str(uuid4()), 1, 13.0)
    with pytest.raises(AuthorizationError):
        broker.permit(session, effect(binding, 1, 2), 14.0)
    assert state.revision == 2
    assert broker.is_revoked(plan.operation_id) is True


def test_revocation_wins_barrier_before_permit(admission):
    plan, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    done = threading.Event()

    def cancel():
        broker.revoke(plan.operation_id)
        done.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(cancel)
        assert done.wait(2.0)
        with pytest.raises(AuthorizationError):
            broker.permit(session, effect(binding), 12.0)
        future.result()
    assert state.advances == []


@pytest.mark.parametrize("bad", [True, -1, 1.0, MAX_SAFE_INT + 1])
def test_state_and_effect_numeric_revalidation_under_lock(admission, bad):
    _, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    state.revision = bad
    with pytest.raises(AuthorizationError):
        broker.permit(session, effect(binding), 12.0)
    assert state.advances == []


def test_max_minus_one_once_then_revoke_without_wrap(admission):
    plan, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    state.revision = MAX_SAFE_INT - 1
    permit = broker.permit(session, effect(binding, revision=MAX_SAFE_INT - 1), 12.0)
    with pytest.raises(AuthorizationError):
        broker.permit(session, effect(binding, 1, MAX_SAFE_INT), 13.0)
    assert state.revision == MAX_SAFE_INT
    assert broker.is_revoked(plan.operation_id)
    broker.revoke(plan.operation_id)
    assert broker.reconcile(permit).occurrence_id == "effect-0"


def test_concurrent_max_minus_one_completions_accept_one_cas(admission):
    _, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    permits = [
        broker.permit(session, effect(binding), 12.0),
        broker.permit(session, effect(binding, 1, 1), 12.0),
    ]
    for permit in permits:
        broker.enter(permit, broker.reconcile(permit), 12.0)
    state.revision = MAX_SAFE_INT - 1
    barrier = threading.Barrier(2)

    def complete(permit):
        barrier.wait()
        try:
            broker.complete(permit, str(uuid4()), MAX_SAFE_INT - 1, 13.0)
            return True
        except AuthorizationError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(complete, permits))
    assert results.count(True) == 1
    assert state.revision == MAX_SAFE_INT
    assert state.advances[-1] == (MAX_SAFE_INT - 1, MAX_SAFE_INT)


def test_one_handler_entry_and_cancel_between_reservation_and_entry(admission):
    plan, binding, _, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    selected = effect(binding)
    permit = broker.permit(session, selected, 12.0)
    attempts = race(lambda: broker.enter(permit, selected, 12.5))
    assert sum(value is True for value in attempts) == 1
    second_binding = effect(binding, 1, 1)
    second = broker.permit(session, second_binding, 13.0)
    broker.revoke(plan.operation_id)
    with pytest.raises(AuthorizationError):
        broker.enter(second, second_binding, 14.0)


def test_two_fresh_consents_cannot_reissue_same_occurrence(admission):
    plan, binding, state, _, adapter, broker, decision, _ = admission
    first = broker.consume(issue(admission), binding, 11.0)
    consent2 = adapter.review(plan, binding, 11.0, 9.0)
    second = broker.consume(broker.issue(plan, consent2, decision, 11.0), binding, 11.0)
    broker.permit(first, effect(binding), 12.0)
    with pytest.raises(AuthorizationError):
        broker.permit(second, effect(binding, revision=1), 12.0)
    assert state.advances == [(0, 1)]


@pytest.mark.parametrize("kind", ["grant", "session", "permit"])
def test_forged_and_foreign_private_types_have_no_authority(admission, kind):
    _, binding, state, _, adapter, broker, _, _ = admission
    grant = issue(admission)
    session = broker.consume(grant, binding, 11.0)
    selected = effect(binding)
    permit = broker.permit(session, selected, 12.0)
    other = AuthorizationBroker(state, adapter)
    token = {"grant": grant, "session": session, "permit": permit}[kind]
    for candidate in (token, object.__new__(type(token)), "opaque-token", {}, True):
        with pytest.raises(AuthorizationError):
            if kind == "grant":
                other.consume(candidate, binding, 12.0)
            elif kind == "session":
                other.permit(candidate, selected, 12.0)
            else:
                other.enter(candidate, selected, 12.0)


@pytest.mark.parametrize("change", ["deny", "policy", "effect", "rules", "empty-rules"])
def test_policy_result_cannot_widen_reviewed_effects(admission, change):
    plan, _, state, _, _, broker, decision, consent = admission
    updates = {
        "deny": {"decision": "deny"},
        "policy": {"policy_digest": "b" * 64},
        "effect": {"effects": (EffectDescriptor("request_effect", FrozenObject((("kind", "apply"),))),)},
        "rules": {"rule_ids": ("z", "a")},
        "empty-rules": {"rule_ids": ()},
    }
    with pytest.raises(AuthorizationError):
        broker.issue(plan, consent, replace(decision, **updates[change]), 10.0)
    assert state.advances == []
    assert isinstance(broker.issue(plan, consent, decision, 10.0), c.Authorization)


@pytest.mark.parametrize("field,bad", [
    ("expected_revision", True), ("expected_revision", -1),
    ("expected_revision", MAX_SAFE_INT + 1), ("expected_revision", 0.0),
    ("event_id", "not-a-uuid"),
])
def test_mutated_event_binding_is_revalidated_inside_lock(admission, field, bad):
    _, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    selected = effect(binding)
    object.__setattr__(selected, field, bad)
    with pytest.raises(AuthorizationError):
        broker.permit(session, selected, 12.0)
    assert state.advances == []


@pytest.mark.parametrize("bad", [True, -1, MAX_SAFE_INT + 1, 0.0])
def test_mutated_current_generation_rejected_under_host_lock(admission, bad):
    plan, binding, state, _, _, broker, _, _ = admission
    grant = issue(admission)
    object.__setattr__(state.binding, "generation", bad)
    with pytest.raises(AuthorizationError):
        broker.consume(grant, binding, 11.0)
    assert state.advances == []
    assert broker.is_revoked(plan.operation_id)


def test_valid_mutation_of_callers_frozen_binding_cannot_change_private_consent(admission):
    plan, binding, state, _, _, broker, _, _ = admission
    grant = issue(admission)
    object.__setattr__(binding, "generation", 1)
    with pytest.raises(AuthorizationError):
        broker.consume(grant, binding, 11.0)
    assert broker.is_revoked(plan.operation_id)
    assert state.advances == []


def test_host_kill_switch_blocks_new_entry_but_not_issued_reconciliation(admission):
    _, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    selected = effect(binding)
    permit = broker.permit(session, selected, 12.0)
    state.dispatch_enabled = False
    with pytest.raises(AuthorizationError):
        broker.enter(permit, selected, 13.0)
    assert broker.reconcile(permit) == selected
    assert state.revision == 1


def test_late_factual_completion_does_not_renew_expired_authority(admission):
    _, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    selected = effect(binding)
    permit = broker.permit(session, selected, 12.0)
    broker.enter(permit, selected, 12.0)
    broker.complete(permit, str(uuid4()), 1, 30.0)
    with pytest.raises(AuthorizationError):
        broker.complete(permit, str(uuid4()), 2, 31.0)
    with pytest.raises(AuthorizationError):
        broker.permit(session, effect(binding, 1, 2), 31.0)
    assert state.revision == 2


def test_current_snapshot_and_cas_run_with_host_lock_held(admission):
    _, binding, state, _, _, broker, _, _ = admission
    snapshot = state.snapshot
    compare = state.compare_revision
    held = []

    def checked_snapshot(operation_id):
        assert state.mutex._is_owned()
        held.append("snapshot")
        return snapshot(operation_id)

    def checked_compare(operation_id, expected_revision, next_revision):
        assert state.mutex._is_owned()
        held.append("cas")
        return compare(operation_id, expected_revision, next_revision)

    state.snapshot = checked_snapshot
    state.compare_revision = checked_compare
    session = broker.consume(issue(admission), binding, 11.0)
    broker.permit(session, effect(binding), 12.0)
    assert held == ["snapshot", "snapshot", "snapshot", "cas"]


def test_failed_host_cas_does_not_spend_occurrence_or_create_permit(admission):
    _, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    compare = state.compare_revision
    state.compare_revision = lambda *args: False
    with pytest.raises(AuthorizationError):
        broker.permit(session, effect(binding), 12.0)
    assert state.advances == []
    state.compare_revision = compare
    assert isinstance(broker.permit(session, effect(binding), 12.0), c.EffectPermit)


def test_invalid_completion_revokes_pending_without_erasing_issued_receipt(admission):
    plan, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    selected = effect(binding)
    permit = broker.permit(session, selected, 12.0)
    broker.enter(permit, selected, 12.0)
    with pytest.raises(AuthorizationError):
        broker.complete(permit, str(uuid4()), MAX_SAFE_INT + 1, 13.0)
    assert state.revision == 1
    assert broker.is_revoked(plan.operation_id)
    assert broker.reconcile(permit) == selected


def test_completion_requires_entered_correlated_permit(admission):
    _, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    selected = effect(binding)
    permit = broker.permit(session, selected, 12.0)
    with pytest.raises(AuthorizationError):
        broker.complete(permit, str(uuid4()), 1, 13.0)
    assert state.revision == 1
    broker.enter(permit, selected, 13.0)
    broker.complete(permit, str(uuid4()), 1, 14.0)
    with pytest.raises(AuthorizationError):
        broker.reconcile(permit)


@pytest.mark.parametrize("changes", [
    {"decision": True}, {"rule_ids": (True,)}, {"effects": []},
    {"effects": (True,)}, {"policy_digest": 1}, {"reason": False},
])
def test_malformed_typed_decision_is_rejected_before_authority(admission, changes):
    plan, _, state, _, _, broker, decision, consent = admission
    with pytest.raises(AuthorizationError):
        broker.issue(plan, consent, replace(decision, **changes), 10.0)
    assert state.advances == []


@pytest.mark.parametrize("boundary", ("issue", "consume", "permit", "enter"))
@pytest.mark.parametrize("observed", (20.0, 1000000.0, 9.0))
def test_terminal_clock_rejection_at_each_operational_boundary(admission, boundary, observed):
    plan, binding, state, _, _, broker, decision, receipt = admission
    if boundary == "issue":
        action = partial(broker.issue, plan, receipt, decision)
    else:
        grant = issue(admission)
        if boundary == "consume":
            action = partial(broker.consume, grant, binding)
        else:
            session = broker.consume(grant, binding, 11.0)
            eb = effect(binding)
            if boundary == "permit":
                action = partial(broker.permit, session, eb)
            else:
                permit = broker.permit(session, eb, 12.0)
                action = partial(broker.enter, permit, eb)
    before = list(state.advances)
    for now in (observed, 13.0, 19.999):
        with pytest.raises(AuthorizationError):
            action(now)
    assert state.advances == before
    assert broker.is_revoked(plan.operation_id)


@pytest.mark.parametrize("callback_failure", (False, True))
def test_operational_failed_callback_keeps_clock_progress_and_late_completion(
    admission, callback_failure,
):
    _, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    eb = effect(binding)
    permit = broker.permit(session, eb, 12.0)
    broker.enter(permit, eb, 13.0)
    compare = state.compare_revision
    def failed_compare(*args):
        if callback_failure:
            raise RuntimeError("host-callback")
        return False

    state.compare_revision = failed_compare
    with pytest.raises(RuntimeError if callback_failure else AuthorizationError):
        broker.permit(session, effect(binding, 1, 1), 18.0)
    state.compare_revision = compare
    with pytest.raises(AuthorizationError):
        broker.permit(session, effect(binding, 1, 1), 14.0)
    assert broker.reconcile(permit) == eb
    broker.complete(permit, str(uuid4()), 1, 30.0)
    assert state.advances == [(0, 1), (1, 2)]


def test_observed_expiry_preserves_late_completion_without_reviving_dispatch(admission):
    _, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    eb = effect(binding)
    permit = broker.permit(session, eb, 12.0)
    broker.enter(permit, eb, 13.0)
    with pytest.raises(AuthorizationError):
        broker.permit(session, effect(binding, 1, 1), 20.0)
    assert broker.reconcile(permit) == eb
    broker.complete(permit, str(uuid4()), 1, 30.0)
    assert state.revision == 2
    for now in (14.0, 31.0):
        with pytest.raises(AuthorizationError):
            broker.permit(session, effect(binding, 1, 2), now)
    with pytest.raises(AuthorizationError):
        broker.enter(permit, eb, 31.0)


def test_invalid_issue_projection_cannot_hide_trusted_clock_progress(admission):
    plan, _, _, _, _, broker, decision, receipt = admission
    with pytest.raises(AuthorizationError):
        broker.issue(True, receipt, decision, 18.0)
    for now in (13.0, 19.0):
        with pytest.raises(AuthorizationError):
            broker.issue(plan, receipt, decision, now)


def test_replayed_entry_observes_expiry_for_other_pending_effects(admission):
    _, binding, state, _, _, broker, _, _ = admission
    session = broker.consume(issue(admission), binding, 11.0)
    eb = effect(binding)
    first = broker.permit(session, eb, 12.0)
    broker.enter(first, eb, 13.0)
    next_binding = effect(binding, 1, 1)
    second = broker.permit(session, next_binding, 14.0)
    with pytest.raises(AuthorizationError):
        broker.enter(first, eb, 20.0)
    with pytest.raises(AuthorizationError):
        broker.enter(second, next_binding, 15.0)
    assert broker.reconcile(first) == eb
    broker.complete(first, str(uuid4()), 2, 30.0)
    assert state.revision == 3
