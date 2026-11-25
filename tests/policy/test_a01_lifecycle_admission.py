"""Memory-only LA01-LA06 proof; no A02 handler/backend qualification."""

from __future__ import annotations

import copy
import pickle
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    LifecycleSnapshot,
    TrustedConsentAdapter,
    TrustedLifecycleConsentAdapter,
    bind_lifecycle,
    lifecycle_effects,
    lifecycle_plan_digest,
)
from netops.ansible.policy.lifecycle_evidence import LifecycleEvidence, lifecycle_arguments_digest

D = "a" * 64
KINDS = ("install", "uninstall", "restore")
CATEGORIES = ("elevation", "wsl-change", "vm-change", "reboot", "runtime-install", "security-change")


def fixture_content(kind, effects, categories, verification_event):
    """Describe simulated registry, owned files, pins and successful probe observations."""
    source = c.public_object({
        "source_id": "registry-package", "registry_digest": D,
        "artifact_digest": D, "descriptor_digest": D,
    })
    destination = c.public_object({
        "resource_id": "owned-resource", "root_resource_id": "root",
        "segments": ("generation", "artifact"), "manifest_digest": D,
    })
    steps = tuple(c.public_object({
        "occurrence_id": item.occurrence_id, "generation_id": "generation",
        "source": source if item.kind == "dependency-stage" else None,
        "destination": destination if item.kind in (
            "dependency-stage", "dependency-uninstall",
        ) else None,
        "reuse": None, "consequential": categories if index == 0 else (),
    }) for index, item in enumerate(effects))
    verification = None
    if kind == "restore" or any(item.kind == "dependency-activate" for item in effects):
        verification = c.public_object({
            "kind": "candidate" if kind == "install" else "retained",
            "event_kind": "CandidateVerified", "event_id": verification_event, "revision": 0,
            "generation_id": "generation", "content_digest": D, "manifest_digest": D,
            "context_digest": D, "registry_digest": D, "policy_digest": D,
            "qualification_digest": D, "observed_at": 1.0, "expires_at": 100.0,
            "probes": (c.public_object({
                "probe_id": "functional", "generation_id": "generation",
                "content_digest": D, "context_digest": D, "result_digest": D,
                "status": "succeeded",
            }),),
        })
    pins = (c.public_object({
        "generation_id": "generation", "manifest_digest": D, "revision": 0, "holders": (),
    }),) if kind == "uninstall" else ()
    return c.public_object({
        "schema": "1.0", "steps": steps, "pins": pins, "verification": verification,
        "cancel_scope": tuple(item.occurrence_id for item in effects),
    })


class Review:
    def __init__(self):
        self.denied = None
        self.prompts = []

    def confirm(self, plan, binding, deadline):
        return True

    def confirm_lifecycle(self, binding, deadline):
        return True

    def confirm_consequential(self, binding, requirement, deadline):
        self.prompts.append(requirement.category)
        return requirement.category != self.denied


class State:
    def __init__(self, binding):
        self.binding = binding
        # Build host observations from the simulated resources, not reviewed plan.content.
        observed = fixture_content(
            binding.kind, binding.effects,
            tuple(item.category for item in binding.required_consequential), binding.lifecycle_id,
        )
        generation = lc.GenerationBinding("generation", 0, D, D)
        self.evidence = LifecycleEvidence(
            lc.OwnedRootBinding("root", D), (generation,), observed["steps"],
            observed["pins"], observed["verification"],
        )
        self.revision = 0
        self.cancelled = False
        self.valid = True
        self.mutex = threading.RLock()
        self.cas = []
        self.pointer_cas = []

    def lock_lifecycle(self, binding):
        return self.mutex

    def snapshot_lifecycle(self, binding):
        return LifecycleSnapshot(
            self.binding, self.revision, self.cancelled, True, self.valid, True, True,
            self.evidence,
        )

    def compare_lifecycle_revision(self, binding, expected, following):
        if self.revision != expected:
            return False
        self.cas.append((expected, following))
        self.revision = following
        return True

    def compare_replace_lifecycle(self, binding, expected, following_revision):
        if self.binding.expected_pointer != expected:
            return False
        self.pointer_cas.append((expected, following_revision))
        self.binding = replace(self.binding, expected_pointer=lc.PresentPointer(
            "present", binding.generation.generation_id, "b" * 64, following_revision,
        ))
        return True


def plan_for(kind, *, virgin=False, categories=(), repeated=False, plan_id=None):
    plan_id = plan_id or str(uuid4())
    generation = lc.GenerationBinding("generation", 0, D, D)
    if kind == "uninstall":
        generation = replace(generation, selected=(generation,))
    pointer = lc.AbsentPointer("absent", 0) if virgin else lc.PresentPointer("present", "old", D, 4)
    actions = {
        "install": ("dependency-stage", "dependency-stage", "dependency-activate") if repeated
        else ("dependency-activate",),
        "uninstall": ("dependency-uninstall",),
        "restore": ("restore-active-pointer",),
    }[kind]
    effects = tuple(lc.LifecycleEffectOccurrence(
        f"occurrence-{i}", i, f"step-{i}", "owned-resource", action, D,
    ) for i, action in enumerate(actions))
    lifecycle_id = str(uuid4()) if kind == "install" else plan_id
    content = fixture_content(kind, effects, categories, lifecycle_id)
    effects = tuple(replace(item, arguments_digest=lifecycle_arguments_digest(step))
                    for item, step in zip(effects, content["steps"]))
    cls = {"install": lc.InstallPlan, "uninstall": lc.UninstallPlan, "restore": lc.RestorePlan}[kind]
    plan = cls(
        "1.0", plan_id, lifecycle_id,
        D, D, lc.OwnedRootBinding("root", D), generation, pointer,
        lc.PolicyIdentity(lc.PIN, D, D, D, ("rule",), "1"),
        D, D, effects, tuple(lc.ConsequentialRequirement(category, (effects[0].occurrence_id,))
                             for category in categories), content, kind,
        **({"scope": c.InstallScope((), ("ansible",), False)} if kind == "install" else {}),
    )
    return replace(plan, plan_digest=lifecycle_plan_digest(plan))


def setup(kind="install", **kwargs):
    plan = plan_for(kind, **kwargs)
    binding = bind_lifecycle(plan)
    state = State(binding)
    review = Review()
    adapter = TrustedLifecycleConsentAdapter(review)
    broker = AuthorizationBroker(
        object(), TrustedConsentAdapter(review), lifecycle_state=state, lifecycle_consent=adapter,
    )
    decision = lc.DecisionResult(
        "allow", ("rule",), "allowed", lifecycle_effects(binding), binding.policy.bundle_sha256,
    )
    return plan, binding, state, review, adapter, broker, decision


def session_for(env):
    plan, binding, _, _, adapter, broker, decision = env
    receipt = adapter.review(plan, 10.0, 20.0)
    grant = broker.issue_lifecycle(plan, receipt, decision, 10.0)
    return broker.consume_lifecycle(grant, binding, 11.0)


def effect(binding, index=0, revision=0, event=None):
    return lc.LifecycleEffectBinding(binding, event or str(uuid4()), revision,
                                     binding.effects[index].occurrence_id)


@pytest.mark.parametrize("kind", KINDS)
def test_la01_each_concrete_lifecycle_and_nominal_authority(kind):
    env = setup(kind)
    _, binding, state, _, _, broker, _ = env
    session = session_for(env)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    assert broker.enter_lifecycle(permit, eb, 13.0) is True
    with pytest.raises(AuthorizationError):
        broker.enter_lifecycle(permit, eb, 13.0)
    if kind != "uninstall":
        assert broker.replace_lifecycle_pointer(permit, 14.0) is True
        assert broker.reconcile_lifecycle_pointer(permit) == ("generation", 5)
        with pytest.raises(AuthorizationError):
            broker.replace_lifecycle_pointer(permit, 14.0)
    else:
        broker.complete_lifecycle(permit, str(uuid4()), 1, 14.0)
        with pytest.raises(AuthorizationError):
            broker.enter_lifecycle(permit, eb, 14.0)
        with pytest.raises(AuthorizationError):
            broker.complete_lifecycle(permit, str(uuid4()), 2, 14.0)
    assert state.cas[0] == (0, 1)


def test_la01_virgin_install_and_fresh_resume_never_reconstruct_authority():
    env = setup("install", virgin=True)
    plan, binding, state, _, adapter, broker, decision = env
    old_session = session_for(env)
    permit = broker.permit_lifecycle(old_session, effect(binding), 12.0)
    broker.enter_lifecycle(permit, effect(binding, event=broker.reconcile_lifecycle(permit).event_id), 13.0)
    broker.replace_lifecycle_pointer(permit, 14.0)
    assert state.pointer_cas[0][1] == 1
    resumed = replace(plan, plan_id=str(uuid4()), expected_pointer=state.binding.expected_pointer)
    resumed = replace(resumed, plan_digest=lifecycle_plan_digest(resumed))
    resumed_binding = bind_lifecycle(resumed)
    assert resumed.lifecycle_id == plan.lifecycle_id
    assert resumed_binding != binding
    state.binding = resumed_binding
    fresh = adapter.review(resumed, 15.0, 10.0)
    resumed_decision = replace(decision, effects=lifecycle_effects(resumed_binding))
    grant = broker.issue_lifecycle(resumed, fresh, resumed_decision, 15.0)
    assert broker.consume_lifecycle(grant, resumed_binding, 16.0)
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(old_session, effect(binding, revision=1), 16.0)


@pytest.mark.parametrize("left", KINDS)
@pytest.mark.parametrize("right", KINDS)
def test_la02_cross_kind_binding_rejected_without_spending(left, right):
    if left == right:
        return
    env = setup(left)
    plan, binding, state, _, adapter, broker, decision = env
    receipt = adapter.review(plan, 10.0, 20.0)
    other = plan_for(right, plan_id=plan.plan_id)
    with pytest.raises(AuthorizationError):
        broker.issue_lifecycle(other, receipt, decision, 10.0)
    grant = broker.issue_lifecycle(plan, receipt, decision, 10.0)
    with pytest.raises(AuthorizationError):
        broker.consume_lifecycle(grant, bind_lifecycle(other), 11.0)
    session = broker.consume_lifecycle(grant, binding, 11.0)
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(session, effect(bind_lifecycle(other)), 12.0)
    assert not state.cas
    assert broker.permit_lifecycle(session, effect(binding), 12.0)


@pytest.mark.parametrize("field,value", [
    ("kind", "other"), ("schema", "2.0"), ("plan_id", "not-a-uuid"),
    ("root", lc.OwnedRootBinding("root", "bad")),
    ("generation", lc.GenerationBinding("generation", True, D, D)),
    ("expected_pointer", lc.AbsentPointer("absent", True)),
])
def test_la02_malformed_concrete_plan_rejects(field, value):
    with pytest.raises(c.ContractError):
        bind_lifecycle(replace(plan_for("install"), **{field: value}))


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("field", [
    "root", "generation", "expected_pointer", "registry_digest", "qualification_digest", "policy",
])
def test_la03_every_trusted_identity_drift_blocks_consume(kind, field):
    env = setup(kind)
    plan, binding, state, _, adapter, broker, decision = env
    grant = broker.issue_lifecycle(plan, adapter.review(plan, 10.0, 20.0), decision, 10.0)
    changed = {
        "root": replace(binding.root, resource_id="different"),
        "generation": replace(binding.generation, ordinal=1),
        "expected_pointer": replace(binding.expected_pointer, revision=5),
        "registry_digest": "b" * 64,
        "qualification_digest": "b" * 64,
        "policy": replace(binding.policy, bundle_sha256="b" * 64),
    }[field]
    state.binding = replace(binding, **{field: changed})
    with pytest.raises(AuthorizationError):
        broker.consume_lifecycle(grant, binding, 11.0)
    assert not state.cas and not state.pointer_cas


def test_la03_corrupt_ownership_never_matches_virgin():
    env = setup(virgin=True)
    session = session_for(env)
    _, binding, state, _, _, broker, _ = env
    state.valid = False
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(session, effect(binding), 12.0)
    assert not state.cas


@pytest.mark.parametrize("category", CATEGORIES)
def test_la04_every_category_requires_separate_prompt(category):
    env = setup(categories=(category,))
    plan, binding, state, review, adapter, broker, decision = env
    review.denied = category
    with pytest.raises(AuthorizationError):
        adapter.review(plan, 10.0, 20.0)
    assert review.prompts == [category] and not state.cas
    review.denied = None
    receipt = adapter.review(plan, 10.0, 20.0)
    grant = broker.issue_lifecycle(plan, receipt, decision, 11.0)
    session = broker.consume_lifecycle(grant, binding, 12.0)
    assert broker.permit_lifecycle(session, effect(binding), 13.0)


@pytest.mark.parametrize("damage", ["missing", "extra", "expired", "wrong-binding", "wrong-occurrence"])
def test_la04_tampered_consequential_registry_rejects_whole_admission(damage):
    env = setup(categories=("elevation",))
    plan, binding, state, _, adapter, broker, decision = env
    receipt = adapter.review(plan, 10.0, 20.0)
    scope = adapter._receipts[receipt]
    grant = scope.grants[0]
    if damage == "missing":
        adapter._categories.clear()
    elif damage == "extra":
        adapter._receipts[receipt] = replace(scope, grants=(*scope.grants, grant))
    elif damage == "expired":
        adapter._categories[grant] = (binding, binding.required_consequential[0], 10.0)
    elif damage == "wrong-binding":
        adapter._categories[grant] = (replace(binding, kind="restore"),
                                      binding.required_consequential[0], scope.deadline)
    else:
        adapter._categories[grant] = (binding, lc.ConsequentialRequirement("elevation", ("wrong",)),
                                      scope.deadline)
    with pytest.raises(AuthorizationError):
        broker.issue_lifecycle(plan, receipt, decision, 11.0)
    assert not state.cas


def test_la05_repeated_actions_order_completion_and_global_replay():
    env = setup(repeated=True)
    _, binding, state, _, _, broker, _ = env
    session = session_for(env)
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(session, effect(binding, index=1), 12.0)
    first = effect(binding)
    permit = broker.permit_lifecycle(session, first, 12.0)
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(session, effect(binding, index=1, revision=1), 13.0)
    broker.enter_lifecycle(permit, first, 13.0)
    broker.complete_lifecycle(permit, str(uuid4()), 1, 14.0)
    with pytest.raises(AuthorizationError):
        broker.enter_lifecycle(permit, first, 14.0)
    second = effect(binding, index=1, revision=2)
    assert broker.permit_lifecycle(session, second, 15.0)
    assert state.cas == [(0, 1), (1, 2), (2, 3)]
    plan, _, _, _, adapter, _, decision = env
    receipt = adapter.review(plan, 15.0, 10.0)
    grant = broker.issue_lifecycle(plan, receipt, decision, 15.0)
    another_session = broker.consume_lifecycle(grant, binding, 15.0)
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(another_session, effect(binding, revision=3), 15.0)


@pytest.mark.parametrize("transform", [copy.copy, copy.deepcopy, pickle.dumps])
def test_la05_authority_cannot_serialize_or_copy(transform):
    env = setup()
    _, binding, _, _, _, broker, _ = env
    session = session_for(env)
    permit = broker.permit_lifecycle(session, effect(binding), 12.0)
    for token in (session, permit):
        assert repr(token) == "<private>"
        with pytest.raises(TypeError):
            transform(token)
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(lc.LifecycleAdmissionSession(), effect(binding), 12.0)
    with pytest.raises(AuthorizationError):
        broker.enter(permit, object(), 12.0)


@pytest.mark.parametrize("cancel_first", [True, False])
def test_la06_barrier_linearizes_cancel_versus_pointer_cas(cancel_first):
    env = setup("restore")
    _, binding, state, _, _, broker, _ = env
    session = session_for(env)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    broker.enter_lifecycle(permit, eb, 13.0)
    first_done = threading.Event()

    def cancel():
        if not cancel_first:
            assert first_done.wait(3)
        broker.revoke_lifecycle("restore", binding.plan_id)
        if cancel_first:
            first_done.set()

    def pointer():
        if cancel_first:
            assert first_done.wait(3)
            with pytest.raises(AuthorizationError):
                broker.replace_lifecycle_pointer(permit, 14.0)
        else:
            assert broker.replace_lifecycle_pointer(permit, 14.0)
            first_done.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = (pool.submit(cancel), pool.submit(pointer))
        for job in jobs:
            job.result(timeout=5)
    assert len(state.pointer_cas) == (0 if cancel_first else 1)
    assert broker.reconcile_lifecycle(permit) == eb
    if not cancel_first:
        assert broker.reconcile_lifecycle_pointer(permit) == ("generation", 5)
    with pytest.raises(AuthorizationError):
        broker.replace_lifecycle_pointer(permit, 15.0)


def test_la06_exhaustion_cancel_and_lost_ack_never_reissue():
    env = setup("restore")
    _, binding, state, _, _, broker, _ = env
    session = session_for(env)
    state.revision = lc.MAX_SAFE_INT - 1
    eb = effect(binding, revision=state.revision)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    assert state.revision == lc.MAX_SAFE_INT
    broker.revoke_lifecycle("restore", binding.plan_id)
    assert broker.reconcile_lifecycle(permit) == eb
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(session, eb, 13.0)
    with pytest.raises(AuthorizationError):
        broker.enter_lifecycle(permit, eb, 13.0)
    assert not state.pointer_cas


def test_la06_deadline_and_host_cancel_rechecked_at_handler_entry():
    env = setup()
    _, binding, state, _, _, broker, _ = env
    session = session_for(env)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    with pytest.raises(AuthorizationError):
        broker.enter_lifecycle(permit, eb, 30.0)
    state.cancelled = True
    with pytest.raises(AuthorizationError):
        broker.enter_lifecycle(permit, eb, 14.0)
    assert broker.reconcile_lifecycle(permit) == eb


@pytest.mark.parametrize("kind", KINDS)
def test_la05_concurrent_consume_and_reservation_one_winner(kind):
    env = setup(kind)
    plan, binding, state, _, adapter, broker, decision = env
    grant = broker.issue_lifecycle(plan, adapter.review(plan, 10.0, 20.0), decision, 10.0)

    def race(action):
        barrier = threading.Barrier(2)

        def attempt():
            barrier.wait(timeout=3)
            try:
                return action()
            except AuthorizationError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(attempt) for _ in range(2)]
            return [future.result(timeout=5) for future in futures]

    sessions = race(lambda: broker.consume_lifecycle(grant, binding, 11.0))
    assert sum(item is not None for item in sessions) == 1
    session = next(item for item in sessions if item is not None)
    permits = race(lambda: broker.permit_lifecycle(session, effect(binding), 12.0))
    assert sum(item is not None for item in permits) == 1
    assert state.cas == [(0, 1)]


@pytest.mark.parametrize("receipt", [True, {}, lc.InstallConsent(), lc.ConsequentialGrant()])
def test_la04_generic_or_constructed_consent_is_not_authority(receipt):
    plan, _, state, _, _, broker, decision = setup()
    with pytest.raises(AuthorizationError):
        broker.issue_lifecycle(plan, receipt, decision, 10.0)
    assert not state.cas


def test_la03_stale_pointer_between_entry_and_final_cas_never_changes_pointer():
    env = setup("restore")
    _, binding, state, _, _, broker, _ = env
    session = session_for(env)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    broker.enter_lifecycle(permit, eb, 13.0)
    state.binding = replace(binding, expected_pointer=replace(binding.expected_pointer, revision=5))
    with pytest.raises(AuthorizationError):
        broker.replace_lifecycle_pointer(permit, 14.0)
    assert not state.pointer_cas
    assert broker.reconcile_lifecycle(permit) == eb


def test_la06_late_completion_after_cancel_and_expiry_cannot_resume():
    env = setup(repeated=True)
    _, binding, state, _, _, broker, _ = env
    session = session_for(env)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    broker.enter_lifecycle(permit, eb, 13.0)
    broker.revoke_lifecycle("install", binding.plan_id)
    broker.complete_lifecycle(permit, str(uuid4()), 1, 35.0)
    assert state.revision == 2
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(session, effect(binding, index=1, revision=2), 36.0)
    assert broker.reconcile_lifecycle(permit) == eb


@pytest.mark.parametrize("revision", [True, -1, lc.MAX_SAFE_INT + 1, 1.0])
def test_la06_malformed_current_checkpoint_rejects_without_cas(revision):
    env = setup()
    _, binding, state, _, _, broker, _ = env
    session = session_for(env)
    state.revision = revision
    with pytest.raises(c.ContractError):
        broker.permit_lifecycle(session, effect(binding), 12.0)
    assert not state.cas


def test_la06_max_pointer_revision_blocks_increment_but_preserves_reconciliation():
    env = setup("restore")
    plan, binding, state, _, adapter, broker, decision = env
    plan = replace(plan, expected_pointer=replace(plan.expected_pointer, revision=lc.MAX_SAFE_INT))
    plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    binding = bind_lifecycle(plan)
    state.binding = binding
    grant = broker.issue_lifecycle(plan, adapter.review(plan, 10.0, 20.0), decision, 10.0)
    session = broker.consume_lifecycle(grant, binding, 11.0)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    broker.enter_lifecycle(permit, eb, 13.0)
    with pytest.raises(AuthorizationError):
        broker.replace_lifecycle_pointer(permit, 14.0)
    broker.revoke_lifecycle("restore", binding.plan_id)
    assert broker.reconcile_lifecycle(permit) == eb
    assert not state.pointer_cas


def test_la02_subclass_extra_field_and_digest_lie_are_not_plans():
    plan = plan_for("install")
    class Unknown(lc.InstallPlan):
        pass
    with pytest.raises(c.ContractError):
        bind_lifecycle(Unknown(**vars(plan)))
    object.__setattr__(plan, "unexpected", "field")
    with pytest.raises(c.ContractError):
        bind_lifecycle(plan)
    with pytest.raises(c.ContractError):
        bind_lifecycle(replace(plan_for("restore"), plan_digest="b" * 64))
