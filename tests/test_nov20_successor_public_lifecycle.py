"""Independent original lifecycle assertions on valid typed source-unit inputs.

Storage is a real isolated file fixture; probes and generation files are fake
effect ports. No synthetic qualification is a physical controller/Q03 claim.
"""

from __future__ import annotations

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import AuthorizationError
from netops.dependencies._recovery import RecoveryStore
from netops.dependencies.runs import OwnedGenerationRuns
from tests.nov21_cancel_oracle import assert_exact_cancel, capture_state, observe_cas
from tests.policy.test_lifecycle_execution import OWNER
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_author_lifecycle import Cancel
from tests.test_i02_public_flow import public_case, restarted
from tests.test_i02_terminal_restore import qualified_case


def retained_source_case(tmp_path, policy):
    """Use exact retained typed facts and actual shared run pins, not inert A02."""
    service, host, port, effects, consent, context, target, _, previous = qualified_case(
        tmp_path, policy,
    )
    generations = tuple(lc.GenerationBinding(
        value.generation_id, 0, value.content_digest, c.digest(value),
    ) for value in host.manifests)
    current = next(value for value in generations if value.generation_id == previous.active_generation_id)
    previous = lc.PresentPointer(
        "present", current.generation_id, c.digest((current, previous.revision)), previous.revision,
    )
    old = port.read("managed-control")
    port.seed("managed-control", {
        **dict(old.payload), "pointer": c.wire(previous), "admission_enabled": True,
    })
    runs = OwnedGenerationRuns(
        port, "managed-root", "managed-control", OWNER, service._policy_identity,
        generations, target.generation_id,
    )
    runs.initialize()
    host.runs = runs
    return service, host, port, effects, consent, context, target, current, runs, previous


def test_t02_real_public_plan_review_service_provision_needs_no_private_reconstruction(
    tmp_path, policy,
):
    service, scope, context, port, state, effects, _, _ = public_case(tmp_path, policy)
    original_root = port.read("managed-root")
    public = service.plan(scope, context)
    assert public.lifecycle is not None and public.blocked == ()
    assert port.read("managed-root") == original_root and not effects.calls and not port.writes
    grant = service.review(public, 10.0, 30.0)
    assert not effects.calls and not port.writes
    staged = service.provision(public, grant, Cancel())
    assert all(step.status == c.OutcomeStatus.SUCCEEDED for step in staged.steps)
    assert staged.status == c.OutcomeStatus.PARTIAL
    assert state.pointer() == lc.AbsentPointer("absent", 0)
    fresh = service.plan(scope, context)
    assert fresh.lifecycle.plan_id != public.lifecycle.plan_id
    result = service.provision(fresh, service.review(fresh, 10.0, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert result.readiness.native == "ready"
    assert result.readiness.companion == result.readiness.enhanced == "not-requested"
    assert result.active_generation_id == fresh.lifecycle.generation.generation_id
    assert result.pointer_revision == 1
    assert [call[0] for call in effects.calls].count("stage") == 1


def test_t03_fresh_service_resume_uses_durable_selected_scope_and_fresh_public_review(
    tmp_path, policy,
):
    service, scope, context, port, state, effects, _, _ = public_case(tmp_path, policy)
    first = service.plan(scope, context)
    prior_grant = service.review(first, 10.0, 30.0)
    partial = service.provision(first, prior_grant, Cancel())
    selected = RecoveryStore(state).read(partial.installation_id)
    assert selected.scope == scope and selected.context == context
    fresh, host = restarted(service, state)
    with pytest.raises(AuthorizationError):
        fresh.resume(partial.installation_id, prior_grant, Cancel())
    plan = fresh.plan(scope, context)
    assert plan.lifecycle.lifecycle_id == partial.installation_id
    assert plan.lifecycle.plan_id != partial.plan_id
    before = len(effects.calls)
    result = fresh.resume(
        partial.installation_id, fresh.review(plan, 10.0, 30.0), Cancel(),
    )
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert host.pointer().active_generation_id == selected.generation.generation_id
    assert not any(call[0] in ("stage", "download") for call in effects.calls[before:])
    assert port.read("dependency-recovery-" + partial.installation_id).payload["selection"]["scope"] == c.public_object(c.wire(scope))


def test_t28_retained_plan_and_restore_use_exact_metadata_without_running_broken_current(
    tmp_path, policy,
):
    service, host, port, effects, consent, context, target, current, runs, previous = (
        retained_source_case(tmp_path, policy)
    )
    unrelated = tmp_path / "user-vault-inventory-backups"
    unrelated.write_bytes(b"preserve independent user state")
    before = len(effects.calls), len(port.writes)
    plan = service.plan_restore(target.generation_id, context)
    assert before == (len(effects.calls), len(port.writes))
    assert plan.expected_pointer == previous and plan.generation == target
    assert tuple(effect.kind for effect in plan.effects) == ("restore-active-pointer",)
    result = service.restore(plan, consent.review(plan, 10.0, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.SUCCEEDED
    assert result.active_generation_id == target.generation_id
    assert result.previous_generation_id == current.generation_id
    assert result.pointer_revision == previous.revision + 1
    assert host.pointer().pointer_digest == c.digest((target, previous.revision + 1))
    assert all(call[0] == "verify" and call[1] == target.generation_id for call in effects.calls)
    assert all(pin["holders"] == () for pin in runs.pins())
    assert unrelated.read_bytes() == b"preserve independent user state"


@pytest.mark.parametrize("when", ["before", "after"])
def test_t04_cancel_before_and_after_actual_cas_retains_factual_pointer_not_reverse(
    tmp_path, policy, when,
):
    service, host, port, effects, consent, context, target, current, runs, previous = (
        retained_source_case(tmp_path, policy)
    )
    plan = service.plan_restore(target.generation_id, context)
    grant = consent.review(plan, 10.0, 30.0)
    cancel = Cancel()
    if when == "before":
        cancel.value = True
    else:
        def after_cas(resource, record):
            pointer = record.payload.get("pointer")
            if resource == "managed-control" and pointer is not None and (
                pointer["revision"] == previous.revision + 1
            ):
                cancel.value = True

        port.after_cas = after_cas
    writes = len(port.writes)
    if when == "before":
        sentinel = tmp_path / "native-user-vault-inventory-backups"
        sentinel.write_bytes(b"preserve original native and user state")
        before = capture_state(tmp_path, host, port, runs, effects)
        with observe_cas(port) as calls:
            result = service.restore(plan, grant, cancel)
        after = capture_state(tmp_path, host, port, runs, effects)
        assert_exact_cancel(before, after, calls, plan, result)
    else:
        result = service.restore(plan, grant, cancel)
    assert host.pointer().active_generation_id == (
        current.generation_id if when == "before" else target.generation_id
    )
    assert host.pointer().revision == previous.revision + (when == "after")
    assert result.active_generation_id == host.pointer().active_generation_id
    assert result.status == (
        c.OutcomeStatus.CANCELLED if when == "before" else c.OutcomeStatus.PARTIAL
    )
    if when == "before":
        assert len(port.writes) == writes + 2
    else:
        assert result.steps[0].status == c.OutcomeStatus.SUCCEEDED
        assert host._control().payload["admission_enabled"] is False
    assert all(pin["holders"] == () for pin in runs.pins())


def test_t04_restore_cannot_cas_before_actual_owned_run_join_and_preserves_holder(
    tmp_path, policy,
):
    service, host, port, _, consent, context, target, current, runs, previous = (
        retained_source_case(tmp_path, policy)
    )
    cancelled = []
    joined = []
    runs.acquire(current, lambda: cancelled.append(True),
                 lambda remaining: joined.append(remaining) or False)
    holders = tuple(pin["holders"] for pin in runs.pins())
    plan = service.plan_restore(target.generation_id, context)
    result = service.restore(plan, consent.review(plan, 10.0, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.BLOCKED
    assert result.errors and host.pointer() == previous
    assert cancelled and joined and tuple(pin["holders"] for pin in runs.pins()) == holders
    assert port.read("managed-control").payload["admission_enabled"] is False
    with pytest.raises(c.ContractError):
        runs.acquire(current, lambda: None, lambda remaining: True)


def test_t23_active_uninstall_is_blocked_and_does_not_remove_a_live_generation_pin(
    tmp_path, policy,
):
    service, host, port, _, _, _, _, current, runs, previous = retained_source_case(
        tmp_path, policy,
    )
    manifest = next(value for value in host.manifests if value.generation_id == current.generation_id)
    runs.acquire(current, lambda: None, lambda remaining: False)
    before = len(port.writes), runs.pins()
    with pytest.raises(AuthorizationError):
        service.plan_uninstall(current.generation_id, manifest.context)
    assert host.pointer() == previous
    assert (len(port.writes), runs.pins()) == before
