"""Actual owned I/O telemetry is factual, bounded and never lifecycle authority."""

import logging
import math
from collections import defaultdict
from unittest.mock import Mock

import pytest

from netops.ansible import artifact_observations, lifecycle_execution
from tests.policy.test_lifecycle_execution import environment, issue
from tests.policy.test_lifecycle_execution import policy as policy


@pytest.mark.parametrize("boundary", ["read", "cas"])
@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt])
def test_actual_io_failure_has_correlated_safe_terminal_pair(
    tmp_path, policy, caplog, monkeypatch, boundary, failure,
):
    env = environment(tmp_path, policy)
    _, _, port, state, *_ = env
    private = "PRIVATE-path-password-token"
    original = failure(private)

    def fail(*args):
        raise original

    monkeypatch.setattr(port, "read" if boundary == "read" else "compare_replace", fail)
    with caplog.at_level(logging.INFO, logger="netops.ansible.lifecycle_execution"):
        with pytest.raises(failure) as raised:
            if boundary == "read":
                state._read(private)
            else:
                state._write(private, 0, None)
    assert raised.value is original
    records = [row for row in caplog.records if hasattr(row, "io_id")]
    assert [row.outcome for row in records] == ["started", "failed"]
    assert records[0].io_id == records[1].io_id
    assert all(row.metric_value == 1 for row in records)
    assert all(set(row.metric_dimensions) == {"boundary", "outcome"} for row in records)
    assert all(math.isfinite(row.duration) and row.duration >= 0 for row in records)
    assert private not in repr([row.__dict__ for row in records])


def test_real_lifecycle_success_pairs_every_read_and_write(tmp_path, policy, caplog):
    env = environment(tmp_path, policy)
    grant = issue(env, policy)
    with caplog.at_level(logging.INFO, logger="netops.ansible.lifecycle_execution"):
        result = env[-1].execute(env[0], grant)
    assert result.completed
    pairs = defaultdict(list)
    for row in caplog.records:
        if hasattr(row, "io_id"):
            pairs[row.io_id].append(row)
    assert pairs
    assert {rows[0].boundary for rows in pairs.values()} == {"owned_read", "owned_cas"}
    for rows in pairs.values():
        assert [row.outcome for row in rows] == ["started", "succeeded"]
        assert rows[0].duration == 0
        assert math.isfinite(rows[1].duration) and rows[1].duration >= 0
        assert rows[0].metric == rows[1].metric


@pytest.mark.parametrize("fault", [RuntimeError, KeyboardInterrupt])
def test_reporting_failures_preserve_actual_execution_and_receipts(
    tmp_path, policy, monkeypatch, fault,
):
    env = environment(tmp_path, policy)
    grant = issue(env, policy)

    def fail(*args, **kwargs):
        raise fault("private-reporting-diagnostic")

    monkeypatch.setattr(artifact_observations.time, "monotonic", fail)
    # Handler-level logs are outside this I/O repair: fail only the paired records.
    logger = logging.getLogger("netops.ansible.lifecycle_execution")
    monkeypatch.setattr(logger, "info", lambda *args, **kwargs: fail() if "extra" in kwargs else None)
    result = env[-1].execute(env[0], grant)
    assert result.completed and result.receipts and not result.uncertain
    for receipt in result.receipts:
        assert env[3].inspect_receipt(receipt.binding)["phase"] == "observed"


@pytest.mark.parametrize("ticks", [(float("nan"), 42.0), (42.0, float("inf")), (42.0, 40.0)])
def test_invalid_reporting_clock_cannot_invent_duration(
    tmp_path, policy, caplog, monkeypatch, ticks,
):
    env = environment(tmp_path, policy)
    values = iter(ticks)
    monkeypatch.setattr(artifact_observations.time, "monotonic", lambda: next(values))
    with caplog.at_level(logging.INFO, logger="netops.ansible.lifecycle_execution"):
        assert env[3]._read(env[3]._facts_resource)
    rows = [row for row in caplog.records if hasattr(row, "io_id")]
    assert [row.duration for row in rows] == [0.0, 0.0]


@pytest.mark.parametrize("sink_failure", [RuntimeError, KeyboardInterrupt])
def test_failed_reporting_preserves_primary_interrupted_io(
    tmp_path, policy, monkeypatch, sink_failure,
):
    env = environment(tmp_path, policy)
    primary = KeyboardInterrupt("private-io")

    def io_failure(*args):
        raise primary

    def report_failure(*args, **kwargs):
        raise sink_failure("private-sink")

    monkeypatch.setattr(env[2], "read", io_failure)
    monkeypatch.setattr(logging.getLogger("netops.ansible.lifecycle_execution"), "info", report_failure)
    with pytest.raises(KeyboardInterrupt) as raised:
        env[3]._read("facts")
    assert raised.value is primary


def test_unknown_io_boundary_cannot_emit_or_enter():
    observations = artifact_observations.ArtifactObservations()
    logger = Mock()
    entered = False
    with pytest.raises(ValueError, match="unknown-owned-io-boundary"):
        with observations._io("PRIVATE-path-password-token", logger):
            entered = True
    assert not entered
    assert not observations._io_counts
    logger.info.assert_not_called()


def test_actual_io_counters_match_raw_wire_log_dimensions(tmp_path, policy, caplog, monkeypatch):
    observations = artifact_observations.ArtifactObservations()
    monkeypatch.setattr(lifecycle_execution, "_OBSERVATIONS", observations)
    env = environment(tmp_path, policy)
    with caplog.at_level(logging.INFO, logger="netops.ansible.lifecycle_execution"):
        env[3]._read(env[3]._facts_resource)
    rows = [row for row in caplog.records if hasattr(row, "io_id")]
    assert len(rows) == 2
    assert [row.metric for row in rows] == ["netops.lifecycle.owned_io.count"] * 2
    assert [row.metric_dimensions for row in rows] == [
        {"boundary": "owned_read", "outcome": "started"},
        {"boundary": "owned_read", "outcome": "succeeded"},
    ]
    assert dict(observations._io_counts) == {
        ("owned_read", "started"): 1, ("owned_read", "succeeded"): 1,
    }
