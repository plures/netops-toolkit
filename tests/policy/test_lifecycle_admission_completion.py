"""A01 closed evidence validation; memory-only, never native qualification."""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from functools import partial
from pathlib import Path
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.admission_telemetry import LifecycleAdmissionTelemetry
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
from netops.ansible.policy.engine import LocalReferencePolicyEngine
from netops.ansible.policy.lifecycle_evidence import LifecycleEvidence, lifecycle_arguments_digest
from netops.ansible.policy.loader import load_policy

D = "a" * 64


def legacy_plan(kind, content):
    generation = lc.GenerationBinding("generation", 0, D, D)
    if kind == "uninstall":
        generation = replace(generation, selected=(generation,))
    plan_id = str(uuid4())
    cls = {"install": lc.InstallPlan, "uninstall": lc.UninstallPlan, "restore": lc.RestorePlan}[kind]
    action = {
        "install": "dependency-stage", "uninstall": "dependency-uninstall",
        "restore": "restore-active-pointer",
    }[kind]
    plan = cls(
        "1.0", plan_id, plan_id, D, D, lc.OwnedRootBinding("root", D), generation,
        lc.PresentPointer("present", "old", D, 4),
        lc.PolicyIdentity(lc.PIN, D, D, D, ("rule",), "1"), D, D,
        (lc.LifecycleEffectOccurrence("occurrence", 0, "step", "resource", action, D),),
        (), content, kind,
        **({"scope": c.InstallScope((), ("ansible",), False)} if kind == "install" else {}),
    )
    return replace(plan, plan_digest=lifecycle_plan_digest(plan))


@pytest.mark.parametrize("kind", ("install", "uninstall", "restore"))
@pytest.mark.parametrize("content", (
    lc.FrozenObject(),
    lc.FrozenObject((("schema", "unexpected"),)),
    lc.FrozenObject((("candidate_verified", True), ("probes_valid", True))),
))
def test_unstructured_or_asserted_evidence_never_binds(kind, content):
    with pytest.raises(c.ContractError):
        bind_lifecycle(legacy_plan(kind, content))


def obj(**values):
    return c.public_object(values)


def changed(value, **updates):
    return lc.FrozenObject(tuple(sorted({**dict(value), **updates}.items())))


def rehash(plan):
    effects = tuple(replace(effect, arguments_digest=lifecycle_arguments_digest(step))
                    for effect, step in zip(plan.effects, plan.content["steps"]))
    plan = replace(plan, effects=effects)
    return replace(plan, plan_digest=lifecycle_plan_digest(plan))


def plan_for(kind="install", *, actions=None, categories=(), policy=None, reuse=None):
    plan = legacy_plan(kind, lc.FrozenObject())
    if policy is not None:
        plan = replace(plan, policy=policy)
    actions = actions or {
        "install": ("dependency-stage",), "uninstall": ("dependency-uninstall",),
        "restore": ("restore-active-pointer",),
    }[kind]
    effects = tuple(lc.LifecycleEffectOccurrence(
        f"occurrence-{index}", index, f"step-{index}", "resource", action, D,
    ) for index, action in enumerate(actions))
    source = obj(source_id="registry-package", registry_digest=D, artifact_digest=D,
                 descriptor_digest=D)
    destination = obj(resource_id="resource", root_resource_id="root",
                      segments=("generation", "artifact"), manifest_digest=D)
    steps = tuple(obj(
        occurrence_id=effect.occurrence_id, generation_id="generation",
        source=source if effect.kind in ("dependency-download", "dependency-stage")
        and reuse is None else None,
        destination=destination if effect.kind in (
            "dependency-download", "dependency-stage", "dependency-verify", "dependency-uninstall",
        ) else None,
        reuse=reuse if effect.kind == "dependency-stage" else None,
        consequential=categories if index == 0 else (),
    ) for index, effect in enumerate(effects))
    verification = None
    if kind == "restore" or "dependency-activate" in actions:
        verification = obj(
            kind="retained" if kind == "restore" else "candidate",
            event_kind="CandidateVerified", event_id=str(uuid4()), revision=0,
            generation_id="generation", content_digest=D, manifest_digest=D,
            context_digest=D, registry_digest=D, policy_digest=plan.policy.bundle_sha256,
            qualification_digest=D, observed_at=1.0, expires_at=100.0,
            probes=(obj(probe_id="functional", generation_id="generation", content_digest=D,
                        context_digest=D, result_digest=D, status="succeeded"),),
        )
    pins = (obj(generation_id="generation", manifest_digest=D, revision=0, holders=()),) \
        if kind == "uninstall" else ()
    content = obj(schema="1.0", steps=steps, pins=pins, verification=verification,
                  cancel_scope=tuple(effect.occurrence_id for effect in effects))
    requirements = tuple(lc.ConsequentialRequirement(category, (effects[0].occurrence_id,))
                         for category in categories)
    return rehash(replace(plan, effects=effects, content=content, required_consequential=requirements))


def evidence_for(binding):
    generation = replace(binding.generation, selected=())
    return LifecycleEvidence(
        binding.root, binding.generation.selected or (generation,), binding.content["steps"],
        binding.content["pins"], binding.content["verification"],
    )


class State:
    def __init__(self, binding):
        self.binding = binding
        self.evidence = evidence_for(binding)
        self.revision = 0
        self.cancelled = False
        self.enabled = True
        self.mutex = threading.RLock()
        self.cas = []
        self.pointer_cas = []

    def lock_lifecycle(self, binding):
        return self.mutex

    def snapshot_lifecycle(self, binding):
        return LifecycleSnapshot(
            self.binding, self.revision, self.cancelled, self.enabled, True, True, True, self.evidence,
        )

    def compare_lifecycle_revision(self, binding, expected, following):
        if self.revision != expected:
            return False
        self.cas.append((expected, following))
        self.revision = following
        return True

    def compare_replace_lifecycle(self, binding, expected, following):
        if self.binding.expected_pointer != expected:
            return False
        self.pointer_cas.append((expected, following))
        self.binding = replace(self.binding, expected_pointer=lc.PresentPointer(
            "present", binding.generation.generation_id, "b" * 64, following,
        ))
        return True


class Review:
    def __init__(self):
        self.prompts = []
        self.denied = None

    def confirm(self, plan, binding, deadline):
        return True

    def confirm_lifecycle(self, binding, deadline):
        return True

    def confirm_consequential(self, binding, requirement, deadline):
        self.prompts.append(requirement.category)
        return requirement.category != self.denied


def environment(kind="install", **kwargs):
    plan = plan_for(kind, **kwargs)
    binding = bind_lifecycle(plan)
    state, review = State(binding), Review()
    adapter = TrustedLifecycleConsentAdapter(review)
    telemetry = LifecycleAdmissionTelemetry()
    broker = AuthorizationBroker(
        object(), TrustedConsentAdapter(review), lifecycle_state=state,
        lifecycle_consent=adapter, lifecycle_telemetry=telemetry,
    )
    decision = lc.DecisionResult(
        "allow", ("rule",), "allowed", lifecycle_effects(binding), binding.policy.bundle_sha256,
    )
    return plan, binding, state, review, adapter, telemetry, broker, decision


def grant_for(env, decision=None):
    plan, _, _, _, adapter, _, broker, default = env
    return broker.issue_lifecycle(plan, adapter.review(plan, 10.0, 20.0), decision or default, 10.0)


def effect(binding, index=0, revision=0):
    return lc.LifecycleEffectBinding(binding, str(uuid4()), revision,
                                     binding.effects[index].occurrence_id)


@pytest.mark.parametrize("boundary", ("issue", "consume", "permit", "enter", "pointer"))
@pytest.mark.parametrize("observed", (30.0, 1000000.0, 9.0))
def test_terminal_clock_rejection_at_every_lifecycle_boundary(boundary, observed):
    env = environment("restore")
    plan, binding, state, _, adapter, _, broker, decision = env
    if boundary == "issue":
        receipt = adapter.review(plan, 10.0, 20.0)
        action = partial(broker.issue_lifecycle, plan, receipt, decision)
    else:
        grant = grant_for(env)
        if boundary == "consume":
            action = partial(broker.consume_lifecycle, grant, binding)
        else:
            session = broker.consume_lifecycle(grant, binding, 11.0)
            eb = effect(binding)
            if boundary == "permit":
                action = partial(broker.permit_lifecycle, session, eb)
            else:
                permit = broker.permit_lifecycle(session, eb, 12.0)
                if boundary == "enter":
                    action = partial(broker.enter_lifecycle, permit, eb)
                else:
                    broker.enter_lifecycle(permit, eb, 13.0)
                    action = partial(broker.replace_lifecycle_pointer, permit)
    before = list(state.cas)
    for now in (observed, 14.0, 29.999):
        with pytest.raises(AuthorizationError):
            action(now)
    assert state.cas == before
    assert state.pointer_cas == []


@pytest.mark.parametrize("callback_failure", (False, True))
def test_lifecycle_failed_callback_keeps_clock_and_allows_late_facts(callback_failure):
    env = environment(actions=("dependency-stage", "dependency-stage"))
    _, binding, state, _, _, _, broker, _ = env
    session = broker.consume_lifecycle(grant_for(env), binding, 11.0)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    broker.enter_lifecycle(permit, eb, 13.0)
    snapshot = state.snapshot_lifecycle

    def failed_snapshot(*args):
        raise RuntimeError("host-callback")

    if callback_failure:
        state.snapshot_lifecycle = failed_snapshot
    with pytest.raises(RuntimeError if callback_failure else AuthorizationError):
        broker.permit_lifecycle(session, effect(binding, 1, 1), 25.0)
    state.snapshot_lifecycle = snapshot
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(session, effect(binding, 1, 1), 14.0)
    assert broker.reconcile_lifecycle(permit) == eb
    broker.complete_lifecycle(permit, str(uuid4()), 1, 40.0)
    assert state.cas == [(0, 1), (1, 2)]
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(session, effect(binding, 1, 2), 41.0)


def test_lifecycle_observed_expiry_preserves_late_completion_without_dispatch():
    env = environment(actions=("dependency-stage", "dependency-stage"))
    _, binding, state, _, _, _, broker, _ = env
    session = broker.consume_lifecycle(grant_for(env), binding, 11.0)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    broker.enter_lifecycle(permit, eb, 13.0)
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(session, effect(binding, 1, 1), 30.0)
    assert broker.reconcile_lifecycle(permit) == eb
    broker.complete_lifecycle(permit, str(uuid4()), 1, 40.0)
    assert state.cas == [(0, 1), (1, 2)]
    for now in (14.0, 41.0):
        with pytest.raises(AuthorizationError):
            broker.permit_lifecycle(session, effect(binding, 1, 2), now)


@pytest.mark.parametrize("malformed", (False, True))
def test_foreign_projection_never_revokes_its_named_unrelated_scope(malformed):
    env = environment()
    _, binding, state, _, adapter, _, broker, _ = env
    session = broker.consume_lifecycle(grant_for(env), binding, 11.0)
    foreign_plan = plan_for("uninstall")
    foreign = bind_lifecycle(foreign_plan)
    state.binding, state.evidence = foreign, evidence_for(foreign)
    decision = lc.DecisionResult(
        "allow", ("rule",), "allowed", lifecycle_effects(foreign), foreign.policy.bundle_sha256,
    )
    receipt = adapter.review(foreign_plan, 10.0, 20.0)
    foreign_session = broker.consume_lifecycle(
        broker.issue_lifecycle(foreign_plan, receipt, decision, 10.0), foreign, 11.0,
    )
    projected = lc.LifecycleEffectBinding(
        foreign, str(uuid4()), True if malformed else 0, foreign.effects[0].occurrence_id,
    )
    with pytest.raises(c.ContractError if malformed else AuthorizationError):
        broker.permit_lifecycle(session, projected, 12.0)
    state.binding, state.evidence = binding, evidence_for(binding)
    if malformed:
        with pytest.raises(AuthorizationError):
            broker.permit_lifecycle(session, effect(binding), 13.0)
    else:
        broker.permit_lifecycle(session, effect(binding), 13.0)
    state.binding, state.evidence = foreign, evidence_for(foreign)
    broker.permit_lifecycle(
        foreign_session, effect(foreign, revision=state.revision), 13.0,
    )


@pytest.mark.parametrize("kind", ("install", "uninstall", "restore"))
def test_closed_host_evidence_admits_each_kind_once(kind):
    env = environment(kind)
    _, binding, state, _, _, telemetry, broker, _ = env
    session = broker.consume_lifecycle(grant_for(env), binding, 11.0)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    broker.enter_lifecycle(permit, eb, 13.0)
    if kind == "restore":
        broker.replace_lifecycle_pointer(permit, 14.0)
        assert broker.reconcile_lifecycle_pointer(permit) == ("generation", 5)
        assert len(state.pointer_cas) == 1
    else:
        broker.complete_lifecycle(permit, str(uuid4()), 1, 14.0)
        assert state.cas == [(0, 1), (1, 2)]
    with pytest.raises(AuthorizationError):
        broker.enter_lifecycle(permit, eb, 15.0)
    assert sum(count for _, _, count in telemetry.counters()) == 1


@pytest.mark.parametrize("kind", ("install", "uninstall", "restore"))
def test_boolean_snapshot_without_observations_is_not_evidence(kind):
    env = environment(kind)
    plan, _, state, _, adapter, telemetry, broker, decision = env
    receipt = adapter.review(plan, 10.0, 20.0)
    state.evidence = None
    with pytest.raises(AuthorizationError):
        broker.issue_lifecycle(plan, receipt, decision, 10.0)
    assert not state.cas and not state.pointer_cas
    assert receipt in adapter._receipts and not broker._life_grants
    assert telemetry.counters() == ((kind, "evidence-mismatch", 1),)


@pytest.mark.parametrize("where", ("issue", "consume", "permit", "enter", "pointer"))
@pytest.mark.parametrize("field", ("root", "generations", "steps", "pins", "verification"))
def test_observation_drift_rejects_before_next_change(where, field):
    env = environment("restore")
    _, binding, state, _, _, _, broker, _ = env
    grant = grant_for(env) if where != "issue" else None
    session = broker.consume_lifecycle(grant, binding, 11.0) if where not in ("issue", "consume") else None
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0) if where in ("enter", "pointer") else None
    if where == "pointer":
        broker.enter_lifecycle(permit, eb, 13.0)
    changes = {
        "root": replace(binding.root, manifest_digest="b" * 64),
        "generations": (replace(binding.generation, content_digest="b" * 64),),
        "steps": (),
        "pins": (obj(generation_id="other", manifest_digest=D, revision=0, holders=()),),
        "verification": changed(state.evidence.verification, qualification_digest="b" * 64),
    }
    state.evidence = replace(state.evidence, **{field: changes[field]})
    before = len(state.cas), len(state.pointer_cas)
    with pytest.raises(AuthorizationError):
        if where == "issue":
            grant_for(env)
        elif where == "consume":
            broker.consume_lifecycle(grant, binding, 12.0)
        elif where == "permit":
            broker.permit_lifecycle(session, eb, 12.0)
        elif where == "enter":
            broker.enter_lifecycle(permit, eb, 13.0)
        else:
            broker.replace_lifecycle_pointer(permit, 14.0)
    assert (len(state.cas), len(state.pointer_cas)) == before


@pytest.mark.parametrize("field,value", (
    ("source", None),
    ("source", obj(source_id="package", registry_digest="b" * 64,
                   artifact_digest=D, descriptor_digest=D)),
    ("destination", None),
    ("destination", obj(resource_id="resource", root_resource_id="foreign",
                        segments=("artifact",), manifest_digest=D)),
    ("destination", obj(resource_id="resource", root_resource_id="root",
                        segments=("..", "escape"), manifest_digest=D)),
    ("destination", obj(resource_id="resource", root_resource_id="root",
                        segments=("C:\\escape",), manifest_digest=D)),
    ("destination", obj(resource_id="resource", root_resource_id="root",
                        segments=("NUL.txt",), manifest_digest=D)),
    ("reuse", obj(kind="owned", resource_id="resource", generation_id="generation",
                  content_digest=D, manifest_digest=D)),
    ("generation_id", "foreign"),
    ("consequential", ("runtime-install",)),
))
def test_source_destination_reuse_and_classification_are_semantic_not_hash_only(field, value):
    plan = plan_for()
    step = changed(plan.content["steps"][0], **{field: value})
    plan = rehash(replace(plan, content=changed(plan.content, steps=(step,))))
    with pytest.raises(c.ContractError):
        bind_lifecycle(plan)


def test_arguments_digest_is_checked_independently_of_whole_plan_hash():
    plan = plan_for()
    plan = replace(plan, effects=(replace(plan.effects[0], arguments_digest="b" * 64),))
    plan = replace(plan, plan_digest=lifecycle_plan_digest(plan))
    with pytest.raises(c.ContractError):
        bind_lifecycle(plan)


@pytest.mark.parametrize("reuse_kind", ("owned", "external"))
def test_reuse_requires_exact_host_resource_and_never_adopts_external(reuse_kind):
    reuse = obj(kind=reuse_kind, resource_id="reused-source",
                generation_id="retained" if reuse_kind == "owned" else None,
                content_digest=D, manifest_digest=D)
    env = environment(reuse=reuse)
    _, binding, state, _, _, _, broker, _ = env
    retained = lc.GenerationBinding("retained", 1, D, D)
    if reuse_kind == "owned":
        with pytest.raises(AuthorizationError):
            grant_for(env)
        env = environment(reuse=reuse)
        _, binding, state, _, _, _, broker, _ = env
        state.evidence = replace(state.evidence, generations=(*state.evidence.generations, retained))
    session = broker.consume_lifecycle(grant_for(env), binding, 11.0)
    assert broker.permit_lifecycle(session, effect(binding), 12.0)
    assert not state.pointer_cas


@pytest.mark.parametrize("kind", ("install", "restore"))
@pytest.mark.parametrize("field,value", (
    ("event_kind", "Activated"), ("event_id", "not-an-event"), ("revision", True),
    ("policy_digest", "b" * 64), ("context_digest", "b" * 64),
    ("qualification_digest", "b" * 64), ("probes", ()),
    ("observed_at", 1), ("expires_at", float("inf")),
))
def test_activation_and_restore_require_closed_correlated_verification(kind, field, value):
    plan = plan_for(kind, actions=("dependency-activate",) if kind == "install" else None)
    verification = changed(plan.content["verification"], **{field: value})
    plan = replace(plan, content=changed(plan.content, verification=verification))
    with pytest.raises(c.ContractError):
        bind_lifecycle(rehash(plan))


@pytest.mark.parametrize("status", ("failed", "blocked", "unknown"))
def test_retained_failed_probe_never_authorizes_restore(status):
    plan = plan_for("restore")
    verification = plan.content["verification"]
    probe = changed(verification["probes"][0], status=status)
    plan = rehash(replace(plan, content=changed(
        plan.content, verification=changed(verification, probes=(probe,)),
    )))
    with pytest.raises(c.ContractError):
        bind_lifecycle(plan)


def test_retained_probe_expiry_between_reservation_and_cas_preserves_reconciliation():
    env = environment("restore")
    plan = env[0]
    plan = rehash(replace(plan, content=changed(
        plan.content, verification=changed(plan.content["verification"], expires_at=15.0),
    )))
    binding = bind_lifecycle(plan)
    _, _, state, review, adapter, telemetry, _, decision = env
    state = State(binding)
    broker = AuthorizationBroker(
        object(), TrustedConsentAdapter(review), lifecycle_state=state,
        lifecycle_consent=adapter, lifecycle_telemetry=telemetry,
    )
    env = plan, binding, state, review, adapter, telemetry, broker, decision
    session = broker.consume_lifecycle(grant_for(env), binding, 11.0)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    broker.enter_lifecycle(permit, eb, 13.0)
    # Consent remains valid until 30.0; this is probe expiry alone.
    with pytest.raises(AuthorizationError):
        broker.replace_lifecycle_pointer(permit, 15.0)
    assert not state.pointer_cas
    assert broker.reconcile_lifecycle(permit) == eb


def test_uninstall_cannot_remove_active_generation_without_reviewed_pointer_switch():
    plan = plan_for("uninstall")
    plan = rehash(replace(plan, expected_pointer=lc.PresentPointer(
        "present", plan.generation.generation_id, D, 4,
    )))
    with pytest.raises(c.ContractError):
        bind_lifecycle(plan)


def test_new_pin_after_consent_prevents_uninstall_without_any_cas():
    env = environment("uninstall")
    _, binding, state, _, _, _, broker, _ = env
    grant = grant_for(env)
    state.evidence = replace(state.evidence, pins=(
        changed(state.evidence.pins[0], holders=("other-operation",)),
    ))
    with pytest.raises(AuthorizationError):
        broker.consume_lifecycle(grant, binding, 11.0)
    assert not state.cas and not state.pointer_cas


@pytest.mark.parametrize("bad", (True, -1, lc.MAX_SAFE_INT + 1, 1.0))
def test_invalid_observed_generation_revokes_without_erasing_issued_receipt(bad):
    env = environment(actions=("dependency-stage", "dependency-stage"))
    _, binding, state, _, _, _, broker, _ = env
    session = broker.consume_lifecycle(grant_for(env), binding, 11.0)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    state.evidence = replace(state.evidence, generations=(
        replace(state.evidence.generations[0], ordinal=bad),
    ))
    with pytest.raises(c.ContractError):
        broker.enter_lifecycle(permit, eb, 13.0)
    state.evidence = evidence_for(binding)
    with pytest.raises(AuthorizationError):
        broker.enter_lifecycle(permit, eb, 14.0)
    broker.revoke_lifecycle(binding.kind, binding.plan_id)
    assert broker.reconcile_lifecycle(permit) == eb and state.cas == [(0, 1)]


@pytest.mark.parametrize("bad", (True, -1, lc.MAX_SAFE_INT + 1, 1.0))
def test_invalid_completion_revokes_pending_but_factual_reconciliation_remains(bad):
    env = environment(actions=("dependency-stage", "dependency-stage"))
    _, binding, state, _, _, _, broker, _ = env
    session = broker.consume_lifecycle(grant_for(env), binding, 11.0)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    broker.enter_lifecycle(permit, eb, 13.0)
    with pytest.raises(c.ContractError):
        broker.complete_lifecycle(permit, str(uuid4()), bad, 14.0)
    broker.complete_lifecycle(permit, str(uuid4()), 1, 15.0)
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(session, effect(binding, 1, state.revision), 16.0)
    assert broker.reconcile_lifecycle(permit) == eb


@pytest.mark.parametrize("cancel_first", (True, False))
def test_cancel_pointer_cas_linearization_with_actual_evidence(cancel_first):
    env = environment("restore")
    _, binding, state, _, _, _, broker, _ = env
    session = broker.consume_lifecycle(grant_for(env), binding, 11.0)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    broker.enter_lifecycle(permit, eb, 13.0)
    barrier = threading.Barrier(2)
    first_done = threading.Event()

    def cancel():
        barrier.wait()
        if not cancel_first:
            assert first_done.wait(3.0)
        broker.revoke_lifecycle(binding.kind, binding.plan_id)
        if cancel_first:
            first_done.set()

    def pointer():
        barrier.wait()
        if cancel_first:
            assert first_done.wait(3.0)
            with pytest.raises(AuthorizationError):
                broker.replace_lifecycle_pointer(permit, 14.0)
        else:
            broker.replace_lifecycle_pointer(permit, 14.0)
            first_done.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = (pool.submit(cancel), pool.submit(pointer))
        for job in jobs:
            job.result(timeout=5.0)
    assert len(state.pointer_cas) == (0 if cancel_first else 1)
    assert broker.reconcile_lifecycle(permit) == eb
    if not cancel_first:
        assert broker.reconcile_lifecycle_pointer(permit) == ("generation", 5)


def test_max_revision_does_not_disable_cancellation_or_reconciliation():
    env = environment(actions=("dependency-stage", "dependency-stage"))
    _, binding, state, _, _, _, broker, _ = env
    session = broker.consume_lifecycle(grant_for(env), binding, 11.0)
    state.revision = lc.MAX_SAFE_INT - 1
    eb = effect(binding, revision=state.revision)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    assert state.revision == lc.MAX_SAFE_INT
    broker.enter_lifecycle(permit, eb, 13.0)
    with pytest.raises(AuthorizationError) as raised:
        broker.complete_lifecycle(permit, str(uuid4()), lc.MAX_SAFE_INT, 14.0)
    assert raised.value.cause == "policy-input-invalid"
    assert state.revision == lc.MAX_SAFE_INT and len(state.cas) == 1
    broker.revoke_lifecycle(binding.kind, binding.plan_id)
    assert broker.reconcile_lifecycle(permit) == eb


def test_replanned_evidence_requires_fresh_plan_uuid_and_consent_not_old_authority():
    env = environment()
    plan, binding, state, _, adapter, _, broker, decision = env
    old_grant = grant_for(env)
    step = changed(plan.content["steps"][0], source=changed(
        plan.content["steps"][0]["source"], artifact_digest="b" * 64,
    ))
    revised = rehash(replace(plan, content=changed(plan.content, steps=(step,))))
    revised_binding = bind_lifecycle(revised)
    state.binding, state.evidence = revised_binding, evidence_for(revised_binding)
    receipt = adapter.review(revised, 11.0, 20.0)
    with pytest.raises(AuthorizationError):
        broker.issue_lifecycle(revised, receipt, decision, 11.0)
    assert receipt in adapter._receipts
    fresh = rehash(replace(revised, plan_id=str(uuid4())))
    fresh_binding = bind_lifecycle(fresh)
    state.binding, state.evidence = fresh_binding, evidence_for(fresh_binding)
    fresh_grant = broker.issue_lifecycle(
        fresh, adapter.review(fresh, 12.0, 20.0), decision, 12.0,
    )
    assert broker.consume_lifecycle(fresh_grant, fresh_binding, 13.0)
    with pytest.raises(AuthorizationError):
        broker.consume_lifecycle(old_grant, binding, 14.0)
    assert not state.cas


def uninstall_with_pointer():
    retained_plan = plan_for("restore")
    retained = retained_plan.generation
    removed = lc.GenerationBinding("old", 1, D, D)
    generation = replace(retained, selected=(retained, removed))
    remove = obj(
        occurrence_id="remove", generation_id="old", source=None, reuse=None, consequential=(),
        destination=obj(resource_id="removed-resource", root_resource_id="root",
                        segments=("old", "artifact"), manifest_digest=D),
    )
    switch = changed(retained_plan.content["steps"][0], occurrence_id="switch")
    effects = (
        lc.LifecycleEffectOccurrence("remove", 0, "remove", "removed-resource",
                                     "dependency-uninstall", D),
        lc.LifecycleEffectOccurrence("switch", 1, "switch", "resource", "restore-active-pointer", D),
    )
    content = changed(
        retained_plan.content, steps=(remove, switch), cancel_scope=("remove", "switch"),
        pins=tuple(obj(generation_id=item.generation_id, manifest_digest=item.manifest_digest,
                       revision=0, holders=()) for item in (retained, removed)),
    )
    return rehash(lc.UninstallPlan(**{
        **vars(retained_plan), "kind": "uninstall", "generation": generation,
        "effects": effects, "content": content,
    }))


def test_uninstall_final_retained_pointer_uses_the_canonical_lifecycle_symbol():
    plan = uninstall_with_pointer()
    binding = bind_lifecycle(plan)
    state, review = State(binding), Review()
    adapter = TrustedLifecycleConsentAdapter(review)
    broker = AuthorizationBroker(
        object(), TrustedConsentAdapter(review), lifecycle_state=state, lifecycle_consent=adapter,
    )
    # Broker-only multi-occurrence proof, not a fabricated real-evaluator result.
    decision = lc.DecisionResult("allow", ("rule",), "allowed", lifecycle_effects(binding), D)
    grant = broker.issue_lifecycle(plan, adapter.review(plan, 10.0, 20.0), decision, 10.0)
    session = broker.consume_lifecycle(grant, binding, 11.0)
    first = effect(binding)
    remove = broker.permit_lifecycle(session, first, 12.0)
    broker.enter_lifecycle(remove, first, 13.0)
    with pytest.raises(AuthorizationError):
        broker.replace_lifecycle_pointer(remove, 13.0)
    broker.complete_lifecycle(remove, str(uuid4()), 1, 14.0)
    second = effect(binding, 1, 2)
    switch = broker.permit_lifecycle(session, second, 15.0)
    broker.enter_lifecycle(switch, second, 16.0)
    broker.replace_lifecycle_pointer(switch, 17.0)
    assert broker.reconcile_lifecycle_pointer(switch) == ("generation", 5)
    assert len(state.pointer_cas) == 1


@pytest.mark.parametrize("category", (
    "elevation", "wsl-change", "vm-change", "reboot", "runtime-install", "security-change",
))
def test_all_classified_consequences_require_separate_live_receipts(category):
    env = environment(categories=(category,))
    plan, binding, state, review, adapter, _, broker, _ = env
    review.denied = category
    with pytest.raises(AuthorizationError):
        adapter.review(plan, 10.0, 20.0)
    assert review.prompts == [category] and not state.cas
    review.denied = None
    grant = grant_for(env)
    session = broker.consume_lifecycle(grant, binding, 11.0)
    assert broker.permit_lifecycle(session, effect(binding), 12.0)


def test_paired_rejection_telemetry_has_only_fixed_safe_dimensions(caplog):
    env = environment("restore")
    plan, _, state, _, adapter, telemetry, broker, decision = env
    receipt = adapter.review(plan, 10.0, 20.0)
    state.evidence = None
    with pytest.raises(AuthorizationError):
        broker.issue_lifecycle(plan, receipt, decision, 10.0)
    records = [record for record in caplog.records if record.msg == "policy.rejected"]
    assert len(records) == 1
    record = records[0]
    assert (record.metric, record.outcome, record.stage, record.kind, record.cause) == (
        "policy_decisions_total", "Rejected", "lifecycle-admission", "restore", "evidence-mismatch",
    )
    assert telemetry.counters() == (("restore", "evidence-mismatch", 1),)
    assert not any(value in record.getMessage() for value in (plan.plan_id, D, "root", "generation"))


@pytest.mark.parametrize("kind,field", (
    ("uninstall", "root"),
    ("install", "registry_digest"), ("restore", "registry_digest"),
    ("install", "qualification_digest"), ("restore", "qualification_digest"),
    ("install", "policy"), ("restore", "policy"),
))
@pytest.mark.parametrize("where", ("issue", "consume", "permit", "enter"))
def test_snapshot_identity_drift_is_typed_observed_and_irrevocable(kind, field, where, caplog):
    env = environment(kind)
    _, binding, state, _, _, telemetry, broker, _ = env
    grant = grant_for(env) if where != "issue" else None
    session = broker.consume_lifecycle(grant, binding, 11.0) if where in (
        "permit", "enter",
    ) else None
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0) if where == "enter" else None
    value = {
        "root": replace(binding.root, resource_id="different"),
        "registry_digest": "b" * 64,
        "qualification_digest": "b" * 64,
        "policy": replace(binding.policy, bundle_sha256="b" * 64),
    }[field]
    state.binding = replace(binding, **{field: value})
    before = list(state.cas), list(state.pointer_cas)

    def attempt():
        if where == "issue":
            grant_for(env)
        elif where == "consume":
            broker.consume_lifecycle(grant, binding, 13.0)
        elif where == "permit":
            broker.permit_lifecycle(session, eb, 13.0)
        else:
            broker.enter_lifecycle(permit, eb, 13.0)

    with pytest.raises(AuthorizationError):
        attempt()
    assert (state.cas, state.pointer_cas) == before
    records = [record for record in caplog.records if record.msg == "policy.rejected"]
    assert len(records) == 1
    record = records[0]
    assert (record.metric, record.outcome, record.stage, record.kind, record.cause) == (
        "policy_decisions_total", "Rejected", "lifecycle-admission", kind, "consent-stale",
    )
    assert telemetry.counters() == ((kind, "consent-stale", 1),)
    state.binding = binding
    with pytest.raises(AuthorizationError):
        attempt()
    assert (state.cas, state.pointer_cas) == before


@pytest.mark.parametrize("bad", (True, -1, lc.MAX_SAFE_INT + 1, 1.0))
@pytest.mark.parametrize("field", ("generation", "expected_pointer", "revision"))
def test_snapshot_numeric_corruption_remains_contract_error_and_revokes(field, bad):
    env = environment()
    _, binding, state, _, _, telemetry, broker, _ = env
    grant = grant_for(env)
    if field == "revision":
        state.revision = bad
    else:
        original = getattr(binding, field)
        counter = "ordinal" if field == "generation" else "revision"
        state.binding = replace(binding, **{field: replace(original, **{counter: bad})})
    with pytest.raises(c.ContractError):
        broker.consume_lifecycle(grant, binding, 11.0)
    assert telemetry.counters() == (("install", "policy-input-invalid", 1),)
    state.binding, state.revision = binding, 0
    with pytest.raises(AuthorizationError):
        broker.consume_lifecycle(grant, binding, 12.0)
    assert not state.cas and not state.pointer_cas


def test_repeated_occurrences_keep_exact_order_and_one_concurrent_reservation():
    env = environment(actions=("dependency-stage", "dependency-stage"))
    _, binding, state, _, _, _, broker, _ = env
    session = broker.consume_lifecycle(grant_for(env), binding, 11.0)
    with pytest.raises(AuthorizationError):
        broker.permit_lifecycle(session, effect(binding, 1), 12.0)
    barrier = threading.Barrier(2)

    def reserve():
        barrier.wait()
        try:
            return broker.permit_lifecycle(session, effect(binding), 12.0)
        except AuthorizationError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        permits = list(pool.map(lambda _: reserve(), range(2)))
    permit = next(permit for permit in permits if permit is not None)
    assert sum(permit is not None for permit in permits) == 1
    issued = broker.reconcile_lifecycle(permit)
    broker.enter_lifecycle(permit, issued, 13.0)
    broker.complete_lifecycle(permit, str(uuid4()), 1, 14.0)
    assert broker.permit_lifecycle(session, effect(binding, 1, state.revision), 15.0)


@pytest.fixture(scope="module")
def real_policy():
    root = Path(__file__).resolve().parents[2]
    directory = root / "netops" / "ansible" / "policy"
    source = (directory / "ansible_molecule.px").read_bytes()
    contracts = (directory / "ansible_molecule.contracts.px").read_bytes()
    bundle = (directory / "bundle.json").read_bytes()
    data = json.loads(bundle)
    identity = lc.PolicyIdentity(
        lc.PIN, hashlib.sha256(source).hexdigest(), hashlib.sha256(contracts).hexdigest(),
        hashlib.sha256(bundle).hexdigest(), tuple(item["id"] for item in data["manifest"]),
        data["reducer_version"],
    )
    engine = LocalReferencePolicyEngine(load_policy(source, contracts, bundle, identity))
    corpus = json.loads((root / "tests" / "policy" / "canonical-corpus.json").read_bytes())
    raw = next(case["input"] for case in corpus["cases"] if case["case_id"] ==
               "netops_companion_setup_consent_install_consented_restore_example_3")
    return identity, engine, raw


def evaluate(real_policy, binding, *, activate=False, cancelled=False):
    _, engine, raw = real_policy
    values = copy.deepcopy(raw["facts"])
    values["request"]["operation"] = binding.kind
    values["lifecycle"]["next_effect_kind"] = binding.effects[0].kind
    values["control"]["cancelled"] = cancelled
    if activate:
        verification = binding.content["verification"]
        event_kind = lc.EventKind.CANDIDATE_VERIFIED
        payload = obj(
            candidate_digest=binding.generation.content_digest,
            registry_digest=binding.registry_digest, assets_digest=D,
            policy_digest=binding.policy.bundle_sha256,
            qualification_digest=binding.qualification_digest,
            functional_evidence_ref=verification["probes"][0]["probe_id"],
        )
        event_id = verification["event_id"]
    else:
        event_kind = lc.EventKind.INSTALL_CONSENTED
        payload = obj(lifecycle_kind=binding.kind, plan_id=binding.plan_id,
                      lifecycle_binding_digest=c.digest(binding),
                      private_consent_reference="host-private-symbolic-reference")
        event_id = str(uuid4())
    event = lc.DecisionEvent(
        event_id, event_kind, 0, binding.plan_digest, binding.context_digest,
        binding.policy.bundle_sha256, "resource", binding.effects[0].step_id, payload,
        install_id=binding.lifecycle_id,
    )
    phase = lc.Phase.STAGING if activate else lc.Phase.PLANNED
    return engine.decide(event, lc.DecisionFacts(values, phase, 0))


@pytest.mark.parametrize("kind,activate", (
    ("install", False), ("uninstall", False), ("restore", False), ("install", True),
))
def test_real_packaged_evaluator_result_enters_broker_without_fabricated_decision(
    real_policy, kind, activate,
):
    identity, _, _ = real_policy
    env = environment(kind, policy=identity, actions=("dependency-activate",) if activate else None)
    _, binding, state, _, _, _, broker, _ = env
    decision = evaluate(real_policy, binding, activate=activate)
    assert decision.decision == "allow"
    assert tuple(item.name for item in decision.effects) == ("set_phase", "request_effect")
    grant = grant_for(env, decision)
    session = broker.consume_lifecycle(grant, binding, 11.0)
    eb = effect(binding)
    permit = broker.permit_lifecycle(session, eb, 12.0)
    assert broker.enter_lifecycle(permit, eb, 13.0) is True
    if kind == "restore" or activate:
        broker.replace_lifecycle_pointer(permit, 14.0)
        assert state.pointer_cas
    else:
        broker.complete_lifecycle(permit, str(uuid4()), 1, 14.0)
    assert len(state.cas) in (1, 2)


def test_actual_policy_allow_cannot_override_missing_host_observation(real_policy):
    env = environment("restore", policy=real_policy[0])
    _, binding, state, _, _, _, _, _ = env
    decision = evaluate(real_policy, binding)
    assert decision.decision == "allow"  # Pure facts are not host authority.
    state.evidence = None
    with pytest.raises(AuthorizationError):
        grant_for(env, decision)
    assert not state.cas and not state.pointer_cas


def test_actual_evaluator_denial_and_extra_or_wrong_transition_never_spend_consent(real_policy):
    env = environment("restore", policy=real_policy[0])
    plan, binding, state, _, adapter, _, broker, _ = env
    receipt = adapter.review(plan, 10.0, 20.0)
    denial = evaluate(real_policy, binding, cancelled=True)
    assert denial.decision == "deny"
    with pytest.raises(AuthorizationError):
        broker.issue_lifecycle(plan, receipt, denial, 10.0)
    assert receipt in adapter._receipts
    good = evaluate(real_policy, binding)
    invalid = (
        replace(good, effects=good.effects + good.effects[-1:]),
        replace(good, effects=(lc.EffectDescriptor("set_phase", obj(phase="Active")), *good.effects[1:])),
        replace(good, effects=good.effects[:1]),
        replace(good, effects=(good.effects[0], lc.EffectDescriptor(
            "request_effect", obj(kind="restore-active-pointer", caller_verified=True),
        ))),
        replace(good, rule_ids=("foreign.rule",)),
    )
    for decision in invalid:
        with pytest.raises(AuthorizationError):
            broker.issue_lifecycle(plan, receipt, decision, 10.0)
        assert receipt in adapter._receipts
    assert broker.issue_lifecycle(plan, receipt, good, 10.0)
    assert not state.cas
