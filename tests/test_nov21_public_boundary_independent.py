"""Actual public lifecycle and cancellation contracts; no synthetic platform claim."""

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import AuthorizationError
from netops.ansible.workflows import WorkflowService
from tests.test_nov19_independent_controller_execution import Cancel
from tests.test_nov19_successor_public_installer import managed_environment, staged
from tests.test_nov21_lifecycle_literal_independent import (
    EXPECTED_CONTEXT,
    GEN,
    expected,
    values,
)
from tests.test_workflow_execution import Clock, broker


def test_ac002_public_cancel_request_and_response_literal_and_actual_revocation():
    authority = broker()
    service = WorkflowService(None, authority, None, None, None, None, Clock(), None)
    assert c.canonical_bytes(GEN) == b'"30000000-0000-4000-8000-000000000003"'
    receipt = service.cancel(GEN)
    assert c.canonical_bytes(receipt) == (
        b'{"accepted":true,"reason":"cancelled","received_at":12.0}'
    )
    assert authority.is_revoked(GEN)


def test_ac002_public_readiness_report_complete_nonempty_literal():
    context, _, _, _ = values()
    report = c.ReadinessReport(
        "registry-revision-fixture", context,
        (c.public_object({
            "capability": "native.stdlib", "tier": "native", "status": "blocked",
            "missing": ("native-python",), "qualification": "unqualified",
        }),),
        c.ReadinessProjection("blocked", "not-requested", "not-requested"),
    )
    assert c.canonical_bytes(context) == expected(EXPECTED_CONTEXT)
    assert c.canonical_bytes(report) == expected(
        '{"capabilities":[{"capability":"native.stdlib","missing":["native-python"],'
        '"qualification":"unqualified","status":"blocked","tier":"native"}],'
        '"context":@CONTEXT@,"readiness":{"companion":"not-requested",'
        '"enhanced":"not-requested","errors":[],"native":"blocked"},'
        '"revision":"registry-revision-fixture","schema_version":"1.0"}'
    )


@pytest.mark.parametrize("at_deadline", [False, True])
def test_ac003_public_resume_fresh_unconsumed_grant_original_deadline(at_deadline):
    """Source fake effect ports; original authority deadline, never a native clock patch."""
    env = managed_environment()
    _, _, partial = staged(env)
    service = env["service"]
    plan = service.plan(env["scope"], env["context"])
    fresh_grant = service.review(plan, env["clock"].now, 30.0)
    original_pointer = env["state"].pointer()
    original_user = env["records"].read("user-inventory")
    original_files = list(env["files"].calls)
    original_downloads = list(env["transport"].calls)
    env["clock"].now += 30.0 if at_deadline else 29.999
    try:
        result = service.resume(partial.installation_id, fresh_grant, Cancel())
    except AuthorizationError:
        assert at_deadline, "Fresh consent was rejected before its original deadline."
    else:
        if at_deadline:
            assert result.status == c.OutcomeStatus.BLOCKED
            assert result.errors
            assert all(error.reason == c.ReasonCode.CONSENT_STALE for error in result.errors)
            assert all(not step.changed for step in result.steps)
        else:
            assert result.status == c.OutcomeStatus.SUCCEEDED
            assert result.pointer_revision == original_pointer.revision + 1
            assert result.active_generation_id == env["manifest"].generation_id
    assert env["records"].read("user-inventory") == original_user
    assert env["transport"].calls == original_downloads
    assert env["files"].calls.count("stage") == original_files.count("stage")
    if at_deadline:
        assert env["state"].pointer() == original_pointer
        assert env["files"].calls == original_files
