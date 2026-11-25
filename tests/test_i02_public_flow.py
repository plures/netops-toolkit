"""Author public-service controls: fake effects, never platform qualification."""

import hashlib
import io
import stat
import zipfile
from dataclasses import replace
from uuid import uuid4

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    TrustedConsentAdapter,
    TrustedLifecycleConsentAdapter,
)
from netops.dependencies._assets import AssetResponse, LockedAsset
from netops.dependencies._composition import ManagedLifecycleState
from netops.dependencies._managed import ManagedGenerationManifest, ManagedMember
from netops.dependencies._recovery import RecoveryStore
from netops.dependencies.service import ADAPTERS, DependencyRegistry, DependencyService
from tests.policy.test_lifecycle_execution import OWNER, Clock, FilePort, Review
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_dependency_probes import FixtureAdapter
from tests.test_i02_author_lifecycle import Cancel

DATA = b"unit-owned interpreter stand-in; no interpreter execution or qualification"
MEMBER = "bin/python"


class Effects:
    def __init__(self, content):
        self.content = content
        self.calls = []
        self.tree = None

    def read(self, url, timeout, limit):
        self.calls.append(("download", timeout))
        return AssetResponse(url, self.content)

    def stage(self, manifest, files, clock, cancel, deadline):
        self.calls.append(("stage", manifest.generation_id))
        assert self.tree is None
        self.tree = tuple((item.member, item.content) for item in files)

    def verify(self, manifest, clock, cancel, deadline):
        self.calls.append(("verify", manifest.generation_id))
        assert self.tree == ((manifest.members[0], DATA),)


class Events:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


class Engine:
    def __init__(self, engine):
        self.engine = engine
        self.events = []
        self.deny = None

    def decide(self, event, facts):
        return self.engine.decide(event, facts)

    def reduce(self, state, event, facts):
        self.events.append(event)
        result = self.engine.reduce(state, event, facts)
        if event.kind == self.deny:
            return replace(result, decision=replace(result.decision, decision="deny", effects=()))
        return result


class ManagedAdapter(FixtureAdapter):
    """Compatible fake observation, never execution or qualification evidence."""

    def probe(self, entry, consuming, deadline):
        result = super().probe(entry, consuming, deadline)
        return replace(result, version="3.12.10") if entry.id == "native-python" else result


def public_case(tmp_path, policy, *, registered=True, setup_enabled=True):
    identity, canonical = policy[:2]
    registry = DependencyRegistry.load()
    generation_id = str(uuid4())
    adapter = ManagedAdapter()
    adapter.contexts = {
        "native": replace(adapter.contexts["native"], python=str(
            tmp_path / ("generation-" + c.digest(generation_id)) / MEMBER,
        )),
    }
    scope = c.InstallScope(("native.stdlib",), (), False, False)
    context = c.InstallContext(c.Context(
        "controller", "1" * 64, "unit-managed-selection", "2" * 64, identity,
        registry.digest, "3" * 64,
    ))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo(MEMBER)
        info.external_attr = (stat.S_IFREG | 0o700) << 16
        archive.writestr(info, DATA)
    content = buffer.getvalue()
    lock = LockedAsset(
        "unit-registered-python-asset", "native-python", "https://www.python.org/unit.zip",
        hashlib.sha256(content).hexdigest(), len(content),
    )
    manifest = ManagedGenerationManifest(
        generation_id, lock, "zip",
        (ManagedMember(MEMBER, hashlib.sha256(DATA).hexdigest(), len(DATA), True),),
        scope, context, tuple(sorted(value.digest for value in adapter.contexts.values())),
    )
    manifests = (manifest,) if registered else ()
    port = FilePort(tmp_path, identity)
    port.seed("managed-root", {
        "schema": "i02-managed-generations-v1", "generations": (),
        "root_manifest": {
            "control_resource": "managed-control",
            "registered_manifests": tuple(c.wire(value) for value in manifests),
        },
    })
    port.seed("managed-control", {
        "schema": "i02-managed-control-v1", "pointer": c.wire(lc.AbsentPointer("absent", 0)),
        "verification": None, "setup_enabled": setup_enabled,
        "installation_id": None,
    })
    effects = Effects(content)
    state = ManagedLifecycleState(
        port, "managed-root", "managed-control", OWNER, identity,
        manifests, effects, effects,
    )
    review = Review()
    private = TrustedLifecycleConsentAdapter(review)
    broker = AuthorizationBroker(
        None, TrustedConsentAdapter(review), lifecycle_state=state, lifecycle_consent=private,
    )
    engine, clock = Engine(canonical), Clock()
    service = DependencyService(
        registry, dict.fromkeys(ADAPTERS, adapter), state, engine, broker, clock, Events(),
    )
    return service, scope, context, port, state, effects, engine, private


def test_public_plan_review_provision_reaches_real_managed_handlers(tmp_path, policy):
    service, scope, context, port, state, effects, engine, _ = public_case(tmp_path, policy)
    plan = service.plan(scope, context)
    assert tuple(step.dependency for step in plan.steps) == ("native-python",)
    assert not plan.blocked and plan.lifecycle is not None
    assert not effects.calls and not port.writes
    consent = service.review(plan, 10.0, 20.0)
    assert not effects.calls and not port.writes
    result = service.provision(plan, consent, Cancel())
    assert [step.status for step in result.steps] == [c.OutcomeStatus.SUCCEEDED] * 3, result
    assert result.status == c.OutcomeStatus.PARTIAL
    assert state.pointer() == lc.AbsentPointer("absent", 0)
    assert [value[0] for value in effects.calls].count("download") == 1
    assert [value[0] for value in effects.calls].count("stage") == 1
    assert [event.kind.value for event in engine.events] == [
        "InstallConsented", "StepCompleted", "StepCompleted", "DependencyObserved", "StepCompleted",
    ]
    assert all(record.kind == "checkpoint" for record in
               (port.read(resource) for resource, _, _ in port.writes))
    assert result.readiness.native == "blocked"
    assert result.pending_actions == ("review-activation-plan",)
    head_writes = [
        resource for resource, _, _ in port.writes if resource.startswith("dependency-policy-")
    ]
    history_writes = [
        resource for resource, _, _ in port.writes
        if resource.startswith("dependency-lifecycle-event-")
    ]
    assert len(head_writes) == len(history_writes) == len(engine.events)
    assert len(set(history_writes)) == len(history_writes)


def test_managed_public_entry_rejects_raw_closed_plan_before_effects(tmp_path, policy):
    service, scope, context, port, _, effects, _, _ = public_case(tmp_path, policy)
    plan = service.plan(scope, context)
    consent = service.review(plan, 10.0, 20.0)
    with pytest.raises(c.ContractError):
        service.provision(plan.lifecycle, consent, Cancel())
    assert not effects.calls and not port.writes


@pytest.mark.parametrize("invalid", [None, object(), {}])
def test_public_review_rejects_wrong_input_before_prompt_or_effects(tmp_path, policy, invalid):
    service, _, _, port, _, effects, _, _ = public_case(tmp_path, policy)
    with pytest.raises(c.ContractError):
        service.review(invalid, 10.0, 20.0)
    assert not effects.calls and not port.writes


def test_disabled_managed_setup_is_blocked_in_public_plan_before_prompt(tmp_path, policy):
    service, scope, context, port, _, effects, _, _ = public_case(
        tmp_path, policy, setup_enabled=False,
    )
    plan = service.plan(scope, context)
    assert plan.lifecycle is None and plan.blocked == ("native-python",)
    assert all(step.reason == "managed-setup-disabled" for step in plan.steps)
    with pytest.raises(c.ContractError):
        service.review(plan, 10.0, 20.0)
    assert not effects.calls and not port.writes


def test_public_fresh_activation_replan_uses_verified_tree_and_actual_pointer_cas(tmp_path, policy):
    service, scope, context, port, state, effects, engine, _ = public_case(tmp_path, policy)
    first = service.plan(scope, context)
    service.provision(first, service.review(first, 10.0, 20.0), Cancel())
    activation = service.plan(scope, context)
    assert [item.kind for item in activation.lifecycle.effects] == [
        "dependency-probe", "dependency-activate",
    ]
    before = len(effects.calls)
    result = service.provision(activation, service.review(activation, 10.0, 20.0), Cancel())
    assert all(item.status == c.OutcomeStatus.SUCCEEDED for item in result.steps), result
    assert state.pointer().active_generation_id == activation.lifecycle.generation.generation_id
    assert state.pointer().revision == 1
    assert not any(item[0] in ("download", "stage") for item in effects.calls[before:])
    assert [event.kind.value for event in engine.events][-5:] == [
        "InstallConsented", "DependencyObserved", "CandidateVerified", "StepCompleted", "Activated",
    ]
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert result.pending_actions == ()
    assert result.readiness.native == "ready"


def test_missing_registered_asset_blocks_before_prompt_or_any_effect(tmp_path, policy):
    service, scope, context, port, _, effects, engine, _ = public_case(tmp_path, policy, registered=False)
    plan = service.plan(scope, context)
    assert plan.blocked == ("native-python",)
    assert plan.steps[0].reason == "verified-asset-lock-missing"
    with pytest.raises(c.ContractError):
        service.review(plan, 10.0, 20.0)
    with pytest.raises(c.ContractError):
        service.provision(plan, lc.InstallConsent(), Cancel())
    assert not effects.calls and not engine.events and not port.writes


def test_full_selection_never_truncates_to_the_one_available_asset(tmp_path, policy):
    service, _, context, port, _, effects, engine, _ = public_case(tmp_path, policy)
    scope = c.InstallScope((), (), False, True)
    plan = service.plan(scope, context)
    expected = service._entries(service._selection(scope), scope)
    assert tuple(step.dependency for step in plan.steps) == tuple(item.id for item in expected)
    assert len(plan.steps) > 25 and plan.blocked
    assert plan.lifecycle is None and not effects.calls and not port.writes


@pytest.mark.parametrize("event", [lc.EventKind.INSTALL_CONSENTED, lc.EventKind.STEP_COMPLETED])
def test_ablation_canonical_reducer_denial_prevents_next_actual_effect(tmp_path, policy, event):
    service, scope, context, _, state, effects, engine, _ = public_case(tmp_path, policy)
    plan = service.plan(scope, context)
    engine.deny = event
    result = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    assert result.status in (c.OutcomeStatus.BLOCKED, c.OutcomeStatus.PARTIAL)
    assert not any(item[0] == "stage" for item in effects.calls)
    if event == lc.EventKind.INSTALL_CONSENTED:
        assert not effects.calls
    assert state.pointer() == lc.AbsentPointer("absent", 0)


def test_forged_and_replayed_receipts_never_reenter_actual_transport(tmp_path, policy):
    service, scope, context, _, _, effects, _, _ = public_case(tmp_path, policy)
    plan = service.plan(scope, context)
    forged = service.provision(plan, lc.InstallConsent(), Cancel())
    assert forged.status == c.OutcomeStatus.BLOCKED and not effects.calls
    # A rejected receipt revokes this plan; only a newly reviewed plan can proceed.
    plan = service.plan(scope, context)
    consent = service.review(plan, 10.0, 20.0)
    service.provision(plan, consent, Cancel())
    count = len(effects.calls)
    with pytest.raises(AuthorizationError):
        service.provision(plan, consent, Cancel())
    assert len(effects.calls) == count


def test_context_drift_after_public_review_blocks_before_transport(tmp_path, policy):
    service, scope, context, port, _, effects, _, _ = public_case(tmp_path, policy)
    plan = service.plan(scope, context)
    consent = service.review(plan, 10.0, 20.0)
    adapter = next(iter(service.adapters.values()))
    adapter.contexts["native"] = replace(adapter.contexts["native"], path="changed")
    with pytest.raises(AuthorizationError):
        service.provision(plan, consent, Cancel())
    assert not effects.calls and not port.writes


def restarted(service, state):
    """Fresh service, state host and broker over the same factual owned files."""
    host = ManagedLifecycleState(
        state._state, state._facts_resource, state._control_resource,
        state._owner, state._identity, state.manifests, state.files, state.transport,
    )
    review = Review()
    broker = AuthorizationBroker(
        None, TrustedConsentAdapter(review), lifecycle_state=host,
        lifecycle_consent=TrustedLifecycleConsentAdapter(review),
    )
    fresh = DependencyService(
        DependencyRegistry.load(), service.adapters, host, Engine(service.policy.engine),
        broker, service.clock, Events(),
    )
    return fresh, host


def test_fresh_service_public_replan_and_resume_uses_persisted_selection_not_old_grant(tmp_path, policy):
    service, scope, context, port, state, effects, _, _ = public_case(tmp_path, policy)
    plan = service.plan(scope, context)
    old = service.review(plan, 10.0, 20.0)
    result = service.provision(plan, old, Cancel())
    selected = RecoveryStore(state).read(result.installation_id)
    assert selected.generation_binding == plan.lifecycle.generation
    assert selected.context == context and selected.scope == scope
    # The independent recovery-schema finding must stay fixed.
    record = port.read("dependency-recovery-" + result.installation_id)
    assert "generation_binding" in record.payload["selection"]
    assert "generation" not in record.payload["selection"]
    fresh, host = restarted(service, state)
    with pytest.raises(AuthorizationError):
        fresh.resume(result.installation_id, old, Cancel())
    activation = fresh.plan(scope, context)
    assert activation.lifecycle.lifecycle_id == result.installation_id
    assert activation.lifecycle.plan_id != result.plan_id
    before = len(effects.calls)
    resumed = fresh.resume(
        result.installation_id, fresh.review(activation, 10.0, 20.0), Cancel(),
    )
    assert host.pointer().active_generation_id == selected.generation.generation_id
    assert resumed.active_generation_id == selected.generation.generation_id
    assert not any(item[0] in ("download", "stage") for item in effects.calls[before:])
    assert all(item.status == c.OutcomeStatus.SUCCEEDED for item in resumed.steps)
    assert resumed.status == c.OutcomeStatus.SUCCEEDED


@pytest.mark.parametrize("event", [lc.EventKind.CANDIDATE_VERIFIED, lc.EventKind.STEP_COMPLETED])
def test_activation_reducer_ablation_prevents_pointer_cas(tmp_path, policy, event):
    service, scope, context, _, state, effects, engine, _ = public_case(tmp_path, policy)
    stage = service.plan(scope, context)
    service.provision(stage, service.review(stage, 10.0, 20.0), Cancel())
    plan = service.plan(scope, context)
    engine.deny = event
    result = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    assert state.pointer() == lc.AbsentPointer("absent", 0)
    assert result.status == c.OutcomeStatus.PARTIAL
    assert result.steps[-1].status == c.OutcomeStatus.BLOCKED
    assert [item[0] for item in effects.calls].count("stage") == 1


@pytest.mark.parametrize("field,value", [
    ("steps", ()), ("digest", "0" * 64), ("consuming_contexts", ()), ("free_space", 1),
])
def test_public_review_rejects_descriptor_edits_before_prompt_or_effects(tmp_path, policy, field, value):
    service, scope, context, port, _, effects, _, _ = public_case(tmp_path, policy)
    plan = replace(service.plan(scope, context), **{field: value})
    with pytest.raises(AuthorizationError):
        service.review(plan, 10.0, 20.0)
    assert not port.writes and not effects.calls


def test_cancel_before_any_effect_retains_owned_candidate_and_selected_pointer(tmp_path, policy):
    service, scope, context, _, state, effects, _, _ = public_case(tmp_path, policy)
    plan = service.plan(scope, context)
    consent = service.review(plan, 10.0, 20.0)
    cancel = Cancel()
    cancel.value = True
    result = service.provision(plan, consent, cancel)
    assert result.status == c.OutcomeStatus.CANCELLED
    assert state.pointer() == lc.AbsentPointer("absent", 0) and not effects.calls
    assert result.readiness.native == "blocked"


def test_cancel_after_pointer_cas_keeps_actual_selection_never_switches_back(tmp_path, policy):
    service, scope, context, port, state, _, _, _ = public_case(tmp_path, policy)
    first = service.plan(scope, context)
    service.provision(first, service.review(first, 10.0, 20.0), Cancel())
    plan = service.plan(scope, context)
    cancel = Cancel()

    def after_cas(resource, record):
        if resource == "managed-control" and record.payload["pointer"]["kind"] == "present":
            cancel.value = True

    port.after_cas = after_cas
    result = service.provision(plan, service.review(plan, 10.0, 20.0), cancel)
    assert result.status == c.OutcomeStatus.PARTIAL
    assert result.active_generation_id == plan.lifecycle.generation.generation_id
    assert state.pointer().revision == 1
    assert result.steps[-1].status == c.OutcomeStatus.SUCCEEDED
    assert result.readiness.native == "blocked" and result.errors


def test_cas_rechecks_real_selected_probe_under_the_same_root_lock(tmp_path, policy):
    service, scope, context, port, state, effects, _, _ = public_case(tmp_path, policy)
    first = service.plan(scope, context)
    service.provision(first, service.review(first, 10.0, 20.0), Cancel())
    plan = service.plan(scope, context)
    entered_cas = []
    original = state.compare_replace_lifecycle
    original_verify = effects.verify

    def verify(manifest, clock, cancel, deadline):
        if entered_cas:
            assert state._local.depth > 0
        original_verify(manifest, clock, cancel, deadline)

    def compare(*args):
        entered_cas.append(True)
        next(iter(service.adapters.values())).missing = ("native-python",)
        return original(*args)

    state.compare_replace_lifecycle = compare
    effects.verify = verify
    result = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    assert entered_cas
    assert state.pointer() == lc.AbsentPointer("absent", 0)
    assert result.status == c.OutcomeStatus.PARTIAL and result.errors


def test_interrupted_staging_remains_explicitly_blocked_not_readopted(tmp_path, policy):
    service, scope, context, _, state, effects, _, _ = public_case(tmp_path, policy)
    plan = service.plan(scope, context)

    def fail(*args):
        raise PermissionError("unit protected staging fault")

    effects.stage = fail
    result = service.provision(plan, service.review(plan, 10.0, 20.0), Cancel())
    assert result.uncertain and state._facts().payload["generations"][0]["state"] == "staging"
    preview = service.plan(scope, context)
    assert preview.blocked == ("native-python",) and preview.lifecycle is None
    assert preview.steps[0].reason == "owned-staging-reconciliation-required"
    before = len(effects.calls)
    with pytest.raises(c.ContractError):
        service.provision(preview, lc.InstallConsent(), Cancel())
    assert len(effects.calls) == before
