"""Original regression controls for factual completion and safe I/O attribution."""

import hashlib
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.artifact_observations import (
    ArtifactObservations,
    _lifecycle_observation_context,
)
from netops.ansible.execution import EffectResult
from netops.ansible.policy.authorization import AuthorizationError
from tests.policy.test_lifecycle_execution import environment, issue, reserve
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_workflow_execution import composed


class FailingSink(logging.Handler):
    def __init__(self, predicate, failure):
        super().__init__()
        self.predicate = predicate
        self.failure = failure
        self.attempts = []

    def emit(self, record):
        if self.predicate(record):
            self.attempts.append(record)
            raise self.failure("PRIVATE-sink-path-token")


@pytest.fixture
def native_composed(policy):
    return composed.__wrapped__(policy[:2])


@contextmanager
def failing_sink(logger, predicate, failure):
    handler = FailingSink(predicate, failure)
    old_level = logger.level
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)


@pytest.mark.parametrize("event", ["started", "succeeded", "failed"])
@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_bare_lifecycle_sink_never_replaces_completion_or_primary_error(
    tmp_path, policy, monkeypatch, event, failure,
):
    env = environment(tmp_path, policy)
    grant = issue(env, policy)
    if event == "failed":
        def fail_dispatch(*args):
            raise OSError("PRIVATE-backend-path")
        monkeypatch.setattr(env[-1], "_dispatch", fail_dispatch)
    with failing_sink(
        logging.getLogger("netops.ansible.lifecycle_execution"),
        lambda row: row.getMessage().startswith("lifecycle.handler." + event), failure,
    ) as sink:
        result = env[-1].execute(env[0], grant)
    assert len(sink.attempts) == 1
    if event == "failed":
        assert not result.completed and result.uncertain and result.pending
        assert not result.receipts
    else:
        assert result.completed and not result.pending and not result.uncertain
        assert len(result.receipts) == 1
        assert env[3].inspect_receipt(result.receipts[0].binding)["phase"] == "observed"
    assert "PRIVATE" not in repr(result)


@pytest.mark.parametrize("event", ["started", "succeeded", "failed", "all"])
@pytest.mark.parametrize("status", [
    c.OutcomeStatus.SUCCEEDED, c.OutcomeStatus.FAILED, c.OutcomeStatus.CANCELLED,
])
@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_native_sink_preserves_exact_payload_status_cleanup_and_single_dispatch(
    native_composed, monkeypatch, event, status, failure,
):
    service, host, request, _, effects = native_composed
    grant = host.review(service, request)
    payload = c.public_object({"reading": 5, "output": ("native", "r1")})
    cleanup = c.CleanupOutcome("failed", ("owned-cleanup",))

    def gather(plan, effect, cancel):
        effects.calls.append(effect)
        return EffectResult(
            c.StepOutcome(effect.occurrence_id, status, True, native_payload=payload),
            cleanup=cleanup,
        )

    monkeypatch.setattr(effects, "gather", gather)
    with failing_sink(
        host._logger,
        lambda row: event == "all" or (
            getattr(row, "stage", None) == "gather"
            and getattr(row, "outcome", None) == event
        ), failure,
    ):
        result = service.execute(request, grant)
    assert result.steps[0].status == status
    assert result.steps[0].native_payload == payload
    assert result.targets[0].native_payload == payload
    assert result.steps[0].remote_state == "unchanged"
    assert result.cleanup == cleanup
    assert len(effects.calls) == 1
    assert service.execute(request, grant).status == c.OutcomeStatus.BLOCKED
    assert len(effects.calls) == 1


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_native_failed_and_unhandled_sinks_preserve_safe_primary_failure(
    native_composed, failure,
):
    service, host, request, _, effects = native_composed
    grant = host.review(service, request)

    def fail():
        raise OSError("PRIVATE-original-backend")

    effects.before_return = fail
    with failing_sink(host._logger, lambda row: True, failure) as sink:
        result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.FAILED
    assert result.targets[0].remote_state == "uncertain"
    assert len(effects.calls) == 1
    assert any(row.stage == "gather" and row.outcome == "failed" for row in sink.attempts)
    assert any(row.stage == "Unhandled" for row in sink.attempts)
    assert "PRIVATE" not in repr(result)


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_late_lifecycle_cancel_and_terminal_sink_retain_observed_receipt(
    tmp_path, policy, monkeypatch, failure,
):
    env = environment(tmp_path, policy)
    grant = issue(env, policy)
    original = env[-1]._dispatch

    def dispatch(*args):
        factual = original(*args)
        env[-1].cancel(env[0])
        return factual

    monkeypatch.setattr(env[-1], "_dispatch", dispatch)
    with failing_sink(
        logging.getLogger("netops.ansible.lifecycle_execution"),
        lambda row: row.getMessage().startswith("lifecycle.handler."), failure,
    ):
        result = env[-1].execute(env[0], grant)
    assert result.completed and not result.pending and not result.uncertain
    assert env[3].inspect_receipt(result.receipts[0].binding)["phase"] == "observed"
    with pytest.raises(AuthorizationError):
        env[-1].execute(env[0], grant)


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_native_late_cancel_with_all_sinks_failing_still_blocks_later_target(
    native_composed, failure,
):
    service, host, request, sources, effects = native_composed
    request = replace(request, scope=c.Scope(("r1", "r2")))
    sources.value = replace(sources.value, request=request)
    grant = host.review(service, request)
    effects.before_return = lambda: service.cancel(request.operation_id)
    with failing_sink(host._logger, lambda row: True, failure):
        result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.PARTIAL
    assert result.targets[0].status == c.OutcomeStatus.SUCCEEDED
    assert result.targets[0].native_payload["output"] == ("native", "r1")
    assert not result.targets[1].attempted
    assert host.authorization.is_revoked(request.operation_id)
    assert len(effects.calls) == 1


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_lifecycle_failed_sink_never_masks_original_interrupt(
    tmp_path, policy, monkeypatch, failure,
):
    env = environment(tmp_path, policy)
    permit, binding = reserve(env, policy)
    primary = KeyboardInterrupt("PRIVATE-primary")

    def interrupt(*args):
        raise primary

    monkeypatch.setattr(env[-1], "_dispatch", interrupt)
    with failing_sink(
        logging.getLogger("netops.ansible.lifecycle_execution"),
        lambda row: row.getMessage().startswith("lifecycle.handler.failed"), failure,
    ) as sink:
        with pytest.raises(KeyboardInterrupt) as raised:
            env[-1].enter(permit, binding)
    assert raised.value is primary
    assert len(sink.attempts) == 1
    assert env[-1].reconcile(permit) is None


def assert_schema(row):
    assert row.status == row.outcome
    assert row.mode in {"install", "uninstall", "restore", "none"}
    assert row.error_category in {"none", "storage"}
    assert row.reason in {"none", "owned-io-failed"}
    assert row.retryable is False
    assert row.next_action
    for key in ("operation_id", "step_id", "target_id", "context_id", "occurrence_id"):
        assert isinstance(getattr(row, key), str)
        assert key not in row.metric_dimensions
    assert set(row.metric_dimensions) == {"boundary", "outcome"}


def correlation(value):
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_concurrent_actual_lifecycles_keep_operation_and_occurrence_context(
    tmp_path, policy, caplog, monkeypatch,
):
    environments = []
    barrier = threading.Barrier(2)
    for index in range(2):
        directory = tmp_path / str(index)
        directory.mkdir()
        env = environment(directory, policy)
        grant = issue(env, policy)
        original = env[-1]._dispatch

        def dispatch(*args, original=original):
            barrier.wait(timeout=20)
            return original(*args)

        monkeypatch.setattr(env[-1], "_dispatch", dispatch)
        environments.append((env, grant))
    with caplog.at_level(logging.INFO, logger="netops.ansible.lifecycle_execution"):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda item: item[0][-1].execute(item[0][0], item[1]),
                                    environments))
    assert all(result.completed for result in results)
    rows = [row for row in caplog.records if hasattr(row, "io_id")]
    expected = {correlation(env[0].plan_id): env[0] for env, _ in environments}
    assert {row.operation_id for row in rows} == set(expected)
    for row in rows:
        assert_schema(row)
        plan = expected[row.operation_id]
        assert row.context_id == correlation(plan.context_digest)
        assert row.mode == plan.kind
        assert row.target_id == "none"
        if row.occurrence_id != "none":
            effect = next(e for e in plan.effects
                          if correlation(e.occurrence_id) == row.occurrence_id)
            assert row.step_id == correlation(effect.step_id)
    assert all(any(row.occurrence_id == correlation(env[0].effects[0].occurrence_id)
                   and row.operation_id == correlation(env[0].plan_id) for row in rows)
               for env, _ in environments)
    # Context must be reset even after nested locks and worker completion.
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="netops.ansible.lifecycle_execution"):
        environments[0][0][3]._read("facts")
    assert all(row.operation_id == "none" for row in caplog.records if hasattr(row, "io_id"))


def test_actual_io_failure_schema_excludes_paths_and_exception_text(
    tmp_path, policy, monkeypatch, caplog,
):
    env = environment(tmp_path, policy)
    grant = issue(env, policy)

    def fail(*args):
        raise OSError("PRIVATE-secret-C:\\root\\token")

    monkeypatch.setattr(env[2], "compare_replace", fail)
    with caplog.at_level(logging.INFO, logger="netops.ansible.lifecycle_execution"):
        result = env[-1].execute(env[0], grant)
    assert not result.completed
    rows = [row for row in caplog.records if hasattr(row, "io_id")]
    assert rows and any(row.outcome == "failed" for row in rows)
    for row in rows:
        assert_schema(row)
        assert row.operation_id == correlation(env[0].plan_id)
        if row.outcome == "failed":
            assert row.error_category == "storage"
            assert row.reason == "owned-io-failed"
        assert "PRIVATE" not in repr(row.__dict__)
        assert str(tmp_path) not in repr(row.__dict__)


def test_context_hashes_untrusted_identifiers_and_resets_after_exception(
    tmp_path, policy, caplog,
):
    env = environment(tmp_path, policy)
    private = "PRIVATE-token-C:\\owned\\password"
    effect = replace(env[1].effects[0], step_id=private, occurrence_id=private)
    binding = replace(env[1], plan_id=private, context_digest=private, effects=(effect,))
    with caplog.at_level(logging.INFO, logger="netops.ansible.lifecycle_execution"):
        with pytest.raises(OSError):
            with _lifecycle_observation_context(binding, private):
                env[3]._read("facts")
                raise OSError(private)
        env[3]._read("facts")
    rows = [row for row in caplog.records if hasattr(row, "io_id")]
    assert len(rows) == 4
    for row in rows[:2]:
        assert_schema(row)
        assert row.operation_id == row.step_id == row.occurrence_id == correlation(private)
        assert row.context_id == correlation(private)
    assert all(row.operation_id == "none" for row in rows[2:])
    assert private not in repr([row.__dict__ for row in rows])


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_artifact_observation_sink_is_nonthrowing_and_never_retried(failure):
    observations = ArtifactObservations()
    with failing_sink(observations._logger, lambda row: True, failure) as sink:
        observations.record("artifact.publish", "succeeded")
    assert len(sink.attempts) == 1
    assert observations.counters() == (
        ("artifact.publish", "succeeded", "none", "none", "none", "none", 1),
    )


def test_malformed_observation_context_does_not_change_actual_read(
    tmp_path, policy, caplog,
):
    env = environment(tmp_path, policy)
    # An unencodable diagnostic identifier must not become an admission check.
    malformed = replace(env[1], plan_id=chr(0xD800))
    with caplog.at_level(logging.INFO, logger="netops.ansible.lifecycle_execution"):
        with _lifecycle_observation_context(malformed):
            assert env[3]._read("facts").resource_id == "facts"
    rows = [row for row in caplog.records if hasattr(row, "io_id")]
    assert len(rows) == 2
    assert all(row.operation_id == "none" for row in rows)
