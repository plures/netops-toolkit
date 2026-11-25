"""Independent original-A02 factual completion and raw observability proofs."""

import hashlib
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest

from netops.ansible import contracts as c
from netops.ansible.execution import EffectResult
from netops.ansible.policy.authorization import AuthorizationError
from tests.policy import test_lifecycle_execution as lifecycle_cases
from tests.policy.test_lifecycle_execution import DATA, environment, issue, reserve
from tests.test_guarded_mutation_execution import mutation as mutation
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed
from tests.test_workflow_execution import policy as policy
from tests.test_workflow_policy_alignment import backup_composed as backup_composed

PRIVATE = "PRIVATE-reporting-password-root-grant"
LOG_FIELDS = {
    "operation_id", "step_id", "target_id", "context_id", "mode", "status",
    "error_category", "reason", "retryable", "next_action",
}


@pytest.fixture(scope="module")
def lifecycle_policy():
    """Reuse only inert policy bytes/bootstrap, not an implementation assertion."""
    return lifecycle_cases.policy.__wrapped__()


class ActualSink(logging.Handler):
    """Capture raw LogRecords and optionally fail from the real emit boundary."""

    def __init__(self, predicate=lambda record: False, fault=RuntimeError):
        super().__init__()
        self.predicate = predicate
        self.fault = fault
        self.records = []
        self.failures = 0

    def emit(self, record):
        self.records.append(record)
        if self.predicate(record):
            self.failures += 1
            raise self.fault(PRIVATE)


@contextmanager
def installed_sink(name, sink):
    """Restore only the logger state this test owns, even for BaseException."""
    logger = logging.getLogger(name)
    handlers, level, propagate = logger.handlers[:], logger.level, logger.propagate
    logger.handlers = [sink]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        yield sink
    finally:
        logger.handlers, logger.level, logger.propagate = handlers, level, propagate


@pytest.mark.parametrize("terminal", ["started", "succeeded", "all"])
@pytest.mark.parametrize("fault", [RuntimeError, KeyboardInterrupt])
def test_native_real_sink_cannot_replace_returned_payload(composed, terminal, fault):
    """FR010/011, PX10/T23: reporting cannot invent loss of returned facts."""
    service, host, request, _, backend = composed
    grant = host.review(service, request)
    sink = ActualSink(
        lambda r: terminal == "all" or (
            getattr(r, "stage", None) == "gather" and getattr(r, "outcome", None) == terminal
        ), fault,
    )
    with installed_sink("netops.ansible.execution", sink):
        result = service.execute(request, grant)
    assert sink.failures > 0
    assert len(backend.calls) == 1
    assert result.status is c.OutcomeStatus.SUCCEEDED
    assert result.steps[0].native_payload == c.public_object({
        "output": ("native", "r1"), "reading": 5,
    })
    assert result.targets[0].remote_state == "unchanged"
    assert PRIVATE not in repr(result)
    assert service.execute(request, grant).status is c.OutcomeStatus.BLOCKED
    assert len(backend.calls) == 1


@pytest.mark.parametrize("status", [c.OutcomeStatus.FAILED, c.OutcomeStatus.CANCELLED])
def test_native_real_sink_preserves_unsuccessful_return_and_cleanup(composed, status):
    """Unsuccessful factual payload and separate cleanup must not be discarded."""
    service, host, request, _, backend = composed
    error = c.SafeError(
        c.ErrorCategory.CLEANUP, c.ReasonCode.CLEANUP_FAILED, c.Stage.FINALIZE,
        next_action="Inspect exact owned cleanup state.",
    )
    calls = []

    def gather(plan, effect, cancel):
        calls.append(effect)
        return EffectResult(
            c.StepOutcome(
                effect.occurrence_id, status, True,
                native_payload=c.public_object({"factual": "returned"}),
            ),
            c.CleanupOutcome("failed", ("owned-session",), (error,)),
        )

    backend.gather = gather
    grant = host.review(service, request)
    with installed_sink("netops.ansible.execution", ActualSink(lambda r: True)) as sink:
        result = service.execute(request, grant)
    assert sink.failures and len(calls) == 1
    assert result.steps[0].status is status
    assert result.steps[0].native_payload == c.public_object({"factual": "returned"})
    assert result.steps[0].remote_state == "unchanged"
    assert result.cleanup.status == "failed"
    assert result.cleanup.errors == (error,)
    assert result.cleanup.remaining_refs == ("owned-session",)


def test_native_primary_failure_and_unhandled_sink_remain_safe(composed):
    """Failure reporting must not escape the public safe-outcome boundary."""
    service, host, request, _, backend = composed
    calls = []

    def fail(plan, effect, cancel):
        calls.append(effect)
        raise OSError(PRIVATE)

    backend.gather = fail
    grant = host.review(service, request)
    with installed_sink("netops.ansible.execution", ActualSink(lambda r: True)) as sink:
        result = service.execute(request, grant)
    assert sink.failures and len(calls) == 1
    assert result.status is c.OutcomeStatus.FAILED
    assert result.targets[0].remote_state == "uncertain"
    assert c.ReasonCode.REMOTE_STATE_UNCERTAIN in {e.reason for e in result.errors}
    assert PRIVATE not in repr(result)


@pytest.mark.parametrize("terminal", ["started", "succeeded", "all"])
@pytest.mark.parametrize("fault", [RuntimeError, KeyboardInterrupt])
def test_bare_lifecycle_handler_sink_cannot_uncomplete_observed_receipt(
    tmp_path, lifecycle_policy, terminal, fault,
):
    """Exercise bare handler logs as well as extra-bearing I/O records."""
    env = environment(tmp_path, lifecycle_policy)
    grant = issue(env, lifecycle_policy)
    sink = ActualSink(lambda r: terminal == "all" or
                      r.getMessage().startswith("lifecycle.handler." + terminal), fault)
    with installed_sink("netops.ansible.lifecycle_execution", sink):
        result = env[-1].execute(env[0], grant)
    assert sink.failures > 0
    assert result.completed and not result.pending and not result.uncertain
    assert len(result.receipts) == 1
    assert env[3].artifact("destination") == DATA
    assert env[3].inspect_receipt(result.receipts[0].binding)["phase"] == "observed"
    assert len([w for w in env[2].writes if w[0] == "destination"]) == 1
    with pytest.raises(AuthorizationError):
        env[-1].execute(env[0], grant)


@pytest.mark.parametrize("primary", [OSError, KeyboardInterrupt])
def test_failed_handler_sink_preserves_primary_identity_and_pending_fact(
    tmp_path, lifecycle_policy, monkeypatch, primary,
):
    """Sink failure cannot replace a failed/interrupting admitted effect."""
    env = environment(tmp_path, lifecycle_policy)
    permit, binding = reserve(env, lifecycle_policy)
    original = primary(PRIVATE + "-primary")

    def fail(*args):
        raise original

    monkeypatch.setattr(env[3], "copy_artifact", fail)
    sink = ActualSink(lambda r: r.getMessage().startswith("lifecycle.handler.failed"))
    with installed_sink("netops.ansible.lifecycle_execution", sink):
        with pytest.raises(primary) as raised:
            env[-1].enter(permit, binding)
    assert raised.value is original
    assert sink.failures == 1
    assert env[-1].reconcile(permit) is None
    assert env[3].inspect_receipt(binding)["phase"] == "pending"
    with pytest.raises(AuthorizationError):
        env[-1].enter(permit, binding)


def test_late_factual_receipt_and_cancel_survive_every_handler_sink(
    tmp_path, lifecycle_policy,
):
    """LA05/06: late completion does not restore revoked effect eligibility."""
    env = environment(tmp_path, lifecycle_policy)
    permit, binding = reserve(env, lifecycle_policy)
    with installed_sink(
        "netops.ansible.lifecycle_execution",
        ActualSink(lambda r: r.getMessage().startswith("lifecycle.handler.")),
    ):
        receipt = env[-1].enter(permit, binding)
        env[-1].cancel(env[0])
        assert env[-1].complete(permit) == receipt
    assert env[3].inspect_receipt(binding)["phase"] == "observed"
    assert env[-1].reconcile(permit) == receipt
    with pytest.raises(AuthorizationError):
        env[-1].enter(permit, binding)


@pytest.mark.parametrize("operation", ["apply", "rollback"])
def test_native_mutation_real_sink_preserves_verified_state_and_cleanup(
    mutation, operation,
):
    """Actual native owners retain poststate and cleanup under terminal faults."""
    service, host, apply, rollback, _, device, calls, _, _ = mutation
    recovery = host.review(service, rollback)
    grant = host.review(service, apply, recovery=(recovery,))
    original = host._backend.mutation_connection

    @contextmanager
    def close_failed(plan, effect):
        with original(plan, effect) as selected:
            yield selected
        raise RuntimeError(PRIVATE)

    host._backend.mutation_connection = close_failed
    if operation == "rollback":
        device.config = "hostname after\n"
    with installed_sink("netops.ansible.execution", ActualSink(lambda r: True)) as sink:
        result = service.execute(
            apply if operation == "apply" else rollback,
            grant if operation == "apply" else recovery,
        )
    assert sink.failures
    assert result.steps[0].status is c.OutcomeStatus.SUCCEEDED
    assert result.cleanup.status == "failed"
    assert result.cleanup.errors[0].reason is c.ReasonCode.CLEANUP_FAILED
    assert result.targets[0].remote_state == ("confirmed" if operation == "apply" else "rolled-back")
    assert len(device.writes) == len(calls) == 1
    assert PRIVATE not in repr(result)


def assert_safe_context(row, binding):
    """Assert actual raw schema, not formatter prose or metric-label equivalence."""
    assert LOG_FIELDS <= set(row.__dict__)
    assert row.operation_id == "sha256:" + hashlib.sha256(binding.plan_id.encode()).hexdigest()
    assert row.context_id == "sha256:" + hashlib.sha256(binding.context_digest.encode()).hexdigest()
    assert row.mode == binding.kind
    assert isinstance(row.retryable, bool)
    assert isinstance(row.next_action, str) and row.next_action
    assert row.status in {"started", "succeeded", "failed"}
    assert row.error_category in {"none", "storage"} | {v.value for v in c.ErrorCategory}
    assert row.reason in {"none", "owned-io-failed"} | {v.value for v in c.ReasonCode}
    assert PRIVATE not in repr(row.__dict__)
    assert not ({"operation_id", "step_id", "target_id", "context_id", "io_id"}
                & set(getattr(row, "metric_dimensions", {})))


def test_actual_lifecycle_raw_schema_retains_log_only_operation_and_step(
    tmp_path, lifecycle_policy,
):
    """NFR006/T32: all actual I/O records identify the admitted operation."""
    env = environment(tmp_path, lifecycle_policy)
    grant = issue(env, lifecycle_policy)
    with installed_sink("netops.ansible.lifecycle_execution", ActualSink()) as sink:
        assert env[-1].execute(env[0], grant).completed
    rows = [r for r in sink.records if hasattr(r, "io_id")]
    assert rows
    for row in rows:
        assert_safe_context(row, env[1])
        assert set(row.metric_dimensions) == {"boundary", "outcome"}
    handler = [r for r in sink.records if r.getMessage().startswith("lifecycle.handler.")]
    assert handler
    entered = [r for r in rows if r.step_id != "none"]
    assert entered
    for row in entered:
        assert row.step_id == "sha256:" + hashlib.sha256(
            env[1].effects[0].step_id.encode(),
        ).hexdigest()
        assert row.target_id == "none"  # Lifecycle owned storage is not a device target.
    assert str(tmp_path) not in repr([r.__dict__ for r in sink.records])


def test_actual_failed_io_has_closed_error_context_without_exception_payload(
    tmp_path, lifecycle_policy, monkeypatch,
):
    """Fail an owned read inside an admitted handler, not a synthetic helper call."""
    env = environment(tmp_path, lifecycle_policy)
    permit, binding = reserve(env, lifecycle_policy)
    original = env[2].read
    copy = env[3].copy_artifact
    inside_effect = False

    def fail_source(resource):
        if inside_effect and resource == "source":
            raise OSError(PRIVATE)
        return original(resource)

    def actual_copy(*args):
        nonlocal inside_effect
        inside_effect = True
        try:
            return copy(*args)
        finally:
            inside_effect = False

    monkeypatch.setattr(env[2], "read", fail_source)
    monkeypatch.setattr(env[3], "copy_artifact", actual_copy)
    with installed_sink("netops.ansible.lifecycle_execution", ActualSink()) as sink:
        with pytest.raises(OSError):
            env[-1].enter(permit, binding)
    failed = [r for r in sink.records if getattr(r, "outcome", None) == "failed"]
    assert failed
    for row in failed:
        assert_safe_context(row, env[1])
        assert row.error_category != "none" and row.reason != "none"
        assert row.step_id == "sha256:" + hashlib.sha256(
            binding.lifecycle.effects[0].step_id.encode(),
        ).hexdigest()
        assert row.target_id == "none"
    assert PRIVATE not in repr([r.__dict__ for r in sink.records])


def test_concurrent_lifecycle_context_is_operation_local_and_cleared(
    tmp_path, lifecycle_policy,
):
    """T32 concurrent attribution cannot leak one operation into another or later I/O."""
    envs = []
    for name in ("left", "right"):
        directory = tmp_path / name
        directory.mkdir()
        env = environment(directory, lifecycle_policy)
        envs.append((env, issue(env, lifecycle_policy)))
    barrier = threading.Barrier(2)

    def run(pair):
        env, grant = pair
        barrier.wait(timeout=10)
        return threading.get_ident(), env[-1].execute(env[0], grant)

    with installed_sink("netops.ansible.lifecycle_execution", ActualSink()) as sink:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, envs))
        end = len(sink.records)
        envs[0][0][3]._read("facts")
    assert all(result.completed for _, result in results)
    thread_to_binding = {thread: pair[0][1] for (thread, _), pair in zip(results, envs)}
    for row in sink.records[:end]:
        if hasattr(row, "io_id"):
            assert_safe_context(row, thread_to_binding[row.thread])
    later = sink.records[end:]
    assert later
    assert all(getattr(r, "operation_id", None) not in {
        "sha256:" + hashlib.sha256(env[1].plan_id.encode()).hexdigest() for env, _ in envs
    } for r in later)
