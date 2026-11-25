"""Causal recovery controls with synthetic ports, never native qualification."""

from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.dependencies._recovery import RecoveryStore
from tests.test_i02_author_lifecycle import Cancel
from tests.test_i02_public_flow import policy as policy
from tests.test_i02_public_flow import public_case, restarted


def staged_case(tmp_path, policy, monkeypatch):
    service, scope, context, port, state, effects, _, _ = public_case(tmp_path, policy)
    adapter = next(iter(service.adapters.values()))
    original = adapter.probe

    def installed_only(entry, consuming, deadline):
        result = original(entry, consuming, deadline)
        if effects.tree is None:
            return replace(result, status="missing", reason="not-installed", evidence_digest=None)
        return result

    monkeypatch.setattr(adapter, "probe", installed_only)
    before = service.verify(scope, context)
    assert before.readiness.native == "blocked"
    plan = service.plan(scope, context)
    result = service.provision(plan, service.review(plan, 10.0, 30.0), Cancel())
    assert result.status == c.OutcomeStatus.PARTIAL
    assert result.pending_actions == ("review-activation-plan",)
    assert state.pointer() == lc.AbsentPointer("absent", 0)
    return service, scope, context, port, state, effects, result, c.digest(before)


def test_completed_install_checkpoints_post_effect_readiness_not_missing_baseline(
    tmp_path, policy, monkeypatch,
):
    service, scope, context, _, state, _, result, before = staged_case(
        tmp_path, policy, monkeypatch,
    )
    after = service.verify(scope, context)
    assert after.readiness.native == "ready" and c.digest(after) != before
    selected = RecoveryStore(state).read(result.installation_id)
    assert selected.observation_digest == c.digest(after)
    fresh, host = restarted(service, state)
    plan = fresh.plan(scope, context)
    resumed = fresh.resume(
        result.installation_id, fresh.review(plan, 10.0, 30.0), Cancel(),
    )
    assert resumed.status == c.OutcomeStatus.SUCCEEDED, resumed
    assert host.pointer().revision == 1


def test_post_checkpoint_readiness_drift_still_rejects_before_resume_effect(
    tmp_path, policy, monkeypatch,
):
    service, scope, context, _, state, effects, result, _ = staged_case(
        tmp_path, policy, monkeypatch,
    )
    fresh, host = restarted(service, state)
    plan = fresh.plan(scope, context)
    consent = fresh.review(plan, 10.0, 30.0)
    count = len(effects.calls)
    adapter = next(iter(fresh.adapters.values()))
    adapter.missing = ("native-python",)
    resumed = fresh.resume(result.installation_id, consent, Cancel())
    assert resumed.status == c.OutcomeStatus.BLOCKED
    assert resumed.errors[0].reason == c.ReasonCode.CONSENT_STALE
    assert host.pointer() == lc.AbsentPointer("absent", 0)
    assert len(effects.calls) == count


@pytest.mark.parametrize("event", [lc.EventKind.DEPENDENCY_OBSERVED, lc.EventKind.STEP_COMPLETED])
def test_denied_completion_never_publishes_successful_recovery_observation(
    tmp_path, policy, monkeypatch, event,
):
    service, scope, context, _, state, effects, engine, _ = public_case(tmp_path, policy)
    adapter = next(iter(service.adapters.values()))
    original = adapter.probe

    def installed_only(entry, consuming, deadline):
        result = original(entry, consuming, deadline)
        return result if effects.tree is not None else replace(
            result, status="missing", reason="not-installed", evidence_digest=None,
        )

    monkeypatch.setattr(adapter, "probe", installed_only)
    before = c.digest(service.verify(scope, context))
    engine.deny = event
    plan = service.plan(scope, context)
    result = service.provision(plan, service.review(plan, 10.0, 30.0), Cancel())
    assert result.status != c.OutcomeStatus.SUCCEEDED
    assert RecoveryStore(state).read(result.installation_id).observation_digest == before
    assert state.pointer() == lc.AbsentPointer("absent", 0)
