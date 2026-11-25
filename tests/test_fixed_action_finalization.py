"""Author public-finalization fault controls with actual A02/S01 and fake process I/O."""

from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from tests.test_controller_backend_integration import SECRET
from tests.test_controller_backend_integration import integrated as integrated

pytest_plugins = ("tests.test_workflow_execution",)


@pytest.mark.parametrize("with_primary", [False, True])
def test_public_final_discard_fault_preserves_primary_target_and_all_cleanup(
    integrated, monkeypatch, with_primary, caplog,
):
    service, host, request, _, process, credentials, _ = integrated
    grant = host.review(service, request)
    original_run, original_discard = process.run, credentials._discard
    prior = c.SafeError(
        c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
        next_action="preserve-original-private-directory",
    )
    primary = c.SafeError(
        c.ErrorCategory.EXECUTION, c.ReasonCode.CONTROL_LOST, c.Stage.CONTROLLER,
    )
    discarded = []

    def run(*args):
        result = original_run(*args)
        if with_primary:
            return replace(
                result, exit_code=1, error=primary,
                cleanup=c.CleanupOutcome("failed", ("original-owned-ref",), (prior,)),
            )
        return result

    def discard(operation):
        original_discard(operation)
        discarded.append(operation)
        raise RuntimeError(SECRET)

    monkeypatch.setattr(process, "run", run)
    monkeypatch.setattr(credentials, "_discard", discard)
    with caplog.at_level("INFO"):
        result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.FAILED
    assert result.cleanup.status == "failed"
    assert result.targets and result.targets[0].attempted
    assert result.targets[0].native_payload["line_count"] == 2
    assert result.cleanup.errors and len(discarded) >= 2
    if with_primary:
        assert primary in result.errors and prior in result.cleanup.errors
        assert result.cleanup.remaining_refs == ("original-owned-ref",)
    else:
        assert result.targets[0].status == c.OutcomeStatus.SUCCEEDED
    assert SECRET not in repr(result)
    assert credentials._resolvers == {} and host._backend._contents == {}
    records = [
        record for record in caplog.records
        if record.msg == "controller.io" and record.boundary == "backend.cleanup"
    ]
    # The scoped read finalizer emits a real start/terminal pair; the public
    # final discard emits its additional failure fact. Preserve all three.
    assert len(records) == 3
    assert [record.outcome for record in records] == ["started", "failed", "failed"]
    assert all(record.metric == "netops.controller.io.count" for record in records)
    assert all(record.category == "cleanup" and record.next_action != "none"
               for record in records[1:])
    assert all(SECRET not in repr(record.__dict__) for record in records)
