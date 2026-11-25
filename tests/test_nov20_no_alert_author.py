"""Author regressions for mixed no-alert errors; not independent acceptance."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from tests.test_nov20_reviewed_generation import generation, record
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed
from tests.test_workflow_execution import policy as policy


@pytest.mark.parametrize("failure,reason", [
    (c.ContractError, c.ReasonCode.CONSENT_STALE),
    (RuntimeError, c.ReasonCode.CONTROL_LOST),
])
@pytest.mark.parametrize("cleanup_failed", [False, True])
def test_mixed_no_alert_preserves_after_save_error_and_cleanup(
    output_composed, monkeypatch, failure, reason, cleanup_failed,
):
    service, host, sources, effects, filesystem, _ = output_composed
    no_alert = record("r2")
    no_alert["checks"] = {"cpu": {"alert": False}}
    request = generation(sources, {"results": [record(), no_alert]}, ("r1", "r2"))
    grant = host.review(service, request)
    original_save = host._save
    cleanup_error = c.SafeError(
        c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
    )
    cleanup = c.CleanupOutcome("failed", ("owned-unremoved",), (cleanup_error,))

    def save(*args):
        result = original_save(*args)
        return replace(result, cleanup=cleanup) if cleanup_failed else result

    def fail_completion(*args):
        assert len(filesystem.bindings) == 1
        raise failure("PRIVATE_COMPLETION_FAILURE")

    monkeypatch.setattr(host, "_save", save)
    monkeypatch.setattr(host.authorization, "complete", fail_completion)
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.PARTIAL and outcome.exit_code == 4
    assert len(outcome.artifacts) == len(filesystem.bindings) == 1
    assert outcome.artifacts[0]["digest"] == hashlib.sha256(filesystem.content).hexdigest()
    assert outcome.steps[0].attempted is True and outcome.steps[0].changed is True
    assert outcome.targets[0].attempted is True and outcome.targets[0].changed is True
    target = outcome.targets[1]
    assert target.selected is True and target.status == c.OutcomeStatus.NOT_REQUESTED
    assert target.attempted is False and target.changed is False
    assert target.remote_state == "unchanged" and target.unapplied_effects == ()
    assert c.canonical_bytes(target.native_payload) == (
        b'{"execution_performed":false,'
        b'"generation":{"status":"no-active-alert","target_id":"r2"}}'
    )
    assert tuple(error.reason for error in outcome.errors) == (reason,)
    assert outcome.cleanup == (cleanup if cleanup_failed else c.CleanupOutcome())
    assert c.OperationOutcome.from_json(c.canonical_bytes(outcome)) == outcome
    assert "PRIVATE_COMPLETION_FAILURE" not in repr(outcome)
    assert effects.calls == [] and b"hosts: r2" not in filesystem.content
    assert service.execute(request, grant).status != c.OutcomeStatus.SUCCEEDED
    assert len(filesystem.bindings) == 1


@pytest.mark.parametrize("outcome_type", [c.StepOutcome, c.TargetOutcome])
def test_selected_unattempted_success_remains_schema_rejected(outcome_type):
    with pytest.raises(c.ContractError):
        outcome_type("r2", c.OutcomeStatus.SUCCEEDED, False)
