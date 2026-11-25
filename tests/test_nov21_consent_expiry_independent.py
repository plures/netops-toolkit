"""Original AC-001/003/011 resume guards through the actual public service.

The policy, broker, persistence and public methods are real. Existing fixture
effect ports and an explicit SOURCE virtual clock do not qualify native assets.
"""

from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import AuthorizationError
from netops.dependencies._recovery import RecoveryStore
from tests.test_i02_author_lifecycle import Cancel
from tests.test_i02_public_flow import policy as policy
from tests.test_i02_public_flow import public_case, restarted


def pending_resume(tmp_path, policy):
    service, scope, context, port, state, effects, _, _ = public_case(tmp_path, policy)
    first = service.plan(scope, context)
    partial = service.provision(first, service.review(first, 10.0, 20.0), Cancel())
    assert partial.status == c.OutcomeStatus.PARTIAL
    assert state.pointer() == lc.AbsentPointer("absent", 0)
    fresh, host = restarted(service, state)
    plan = fresh.plan(scope, context)
    assert plan.lifecycle.plan_id != first.lifecycle.plan_id
    assert plan.lifecycle.lifecycle_id == partial.installation_id
    grant = fresh.review(plan, 10.0, 20.0)
    return fresh, host, port, effects, partial, plan, grant


@pytest.mark.parametrize("now,allowed", [(29.999, True), (30.0, False), (30.001, False)])
def test_ac003_public_resume_fresh_unused_consent_keeps_original_deadline(
    tmp_path, policy, now, allowed,
):
    service, host, port, effects, partial, plan, grant = pending_resume(tmp_path, policy)
    prior = RecoveryStore(host).read(partial.installation_id)
    root = port.read("managed-root")
    before_calls = len(effects.calls)
    service.clock.value = now
    result = service.resume(partial.installation_id, grant, Cancel())
    calls = effects.calls[before_calls:]
    assert not any(call[0] in ("download", "stage", "remove") for call in calls)
    if allowed:
        assert result.status == c.OutcomeStatus.SUCCEEDED
        assert host.pointer().revision == 1
        assert host.pointer().active_generation_id == plan.lifecycle.generation.generation_id
        assert result.active_generation_id == host.pointer().active_generation_id
        assert calls and all(call[0] == "verify" for call in calls)
    else:
        assert result.status != c.OutcomeStatus.SUCCEEDED
        assert result.errors and all(
            error.reason == c.ReasonCode.CONSENT_STALE for error in result.errors
        )
        assert host.pointer() == lc.AbsentPointer("absent", 0)
        assert port.read("managed-root") == root
        assert RecoveryStore(host).read(partial.installation_id) == prior
        assert not calls
    after = len(effects.calls)
    if allowed:
        with pytest.raises(AuthorizationError):
            service.resume(partial.installation_id, grant, Cancel())
    else:
        rejected = service.resume(partial.installation_id, grant, Cancel())
        assert rejected.status != c.OutcomeStatus.SUCCEEDED
        assert rejected.errors and all(
            error.reason == c.ReasonCode.CONSENT_STALE for error in rejected.errors
        )
        assert host.pointer() == lc.AbsentPointer("absent", 0)
        assert port.read("managed-root") == root
        assert RecoveryStore(host).read(partial.installation_id) == prior
    assert len(effects.calls) == after


@pytest.mark.parametrize("drift", ["consuming-context", "root-membership", "cancelled"])
def test_ac003_public_resume_rechecks_live_context_root_and_cancel_before_effect(
    tmp_path, policy, drift,
):
    service, host, port, effects, partial, _, grant = pending_resume(tmp_path, policy)
    prior = RecoveryStore(host).read(partial.installation_id)
    cancel = Cancel()
    if drift == "consuming-context":
        adapter = next(iter(service.adapters.values()))
        adapter.contexts["native"] = replace(adapter.contexts["native"], path="drifted-source")
    elif drift == "root-membership":
        original = port.read("managed-root")
        port.seed("managed-root", {
            **dict(original.payload), "root_manifest": {
                **dict(original.payload["root_manifest"]), "unreviewed": "source-drift",
            },
        })
    else:
        cancel.value = True
    before = len(effects.calls)
    result = service.resume(partial.installation_id, grant, cancel)
    assert result.status != c.OutcomeStatus.SUCCEEDED
    assert result.errors
    assert host.pointer() == lc.AbsentPointer("absent", 0)
    assert not effects.calls[before:]
    assert RecoveryStore(host).read(partial.installation_id) == prior
