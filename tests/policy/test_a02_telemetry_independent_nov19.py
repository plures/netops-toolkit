"""Independent PX11/T32 proof at real owned-port invocations, not log stubs."""

import json
import logging
import math
import os
from collections import defaultdict

import pytest

from tests.policy.test_lifecycle_execution import environment, issue
from tests.policy.test_lifecycle_execution import policy as policy


@pytest.mark.parametrize("fail_io", [False, True])
def test_actual_owned_calls_have_safe_correlated_metric_pairs(
    tmp_path, policy, caplog, monkeypatch, record_property, fail_io,
):
    """Every real attempted call has a factual pair, without private arguments."""
    env = environment(tmp_path, policy, "dependency-stage")
    grant = issue(env, policy)
    calls = []
    depth = 0
    private = "PRIVATE-NOV19-password-path-token"
    original_error = OSError(private)
    logger = logging.getLogger("netops.ansible.lifecycle_execution")
    original_info = logger.info

    def report(message, *args, **kwargs):
        extra = kwargs.get("extra")
        if extra is not None:
            extra = dict(extra)
            control = os.environ.get("A02_NOV19_NEGATIVE_CONTROL")
            if control == "missing-metric":
                extra.pop("metric", None)
            elif control == "broken-pair" and extra.get("outcome") != "started":
                extra["io_id"] += "-broken"
            kwargs["extra"] = extra
        original_info(message, *args, **kwargs)

    monkeypatch.setattr(logger, "info", report)
    for boundary, method in (("owned_read", "read"), ("owned_cas", "compare_replace")):
        original = getattr(env[2], method)

        def invoke(*args, _boundary=boundary, _original=original):
            nonlocal depth
            # FilePort.compare_replace performs an implementation-internal read.
            # Count external port entries, not nested work inside a single CAS.
            if depth == 0:
                calls.append(_boundary)
            depth += 1
            try:
                if fail_io:
                    raise original_error
                return _original(*args)
            finally:
                depth -= 1

        monkeypatch.setattr(env[2], method, invoke)
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=logger.name):
        if fail_io:
            with pytest.raises(OSError) as raised:
                env[3]._read(private)
            assert raised.value is original_error
            with pytest.raises(OSError) as raised:
                env[3]._write(private, 0, None)
            assert raised.value is original_error
        else:
            result = env[-1].execute(env[0], grant)
            assert result.completed and not result.uncertain
    records = [
        row for row in caplog.records
        if row.name == logger.name
        and row.getMessage().startswith(("lifecycle.owned_read.", "lifecycle.owned_cas."))
    ]
    assert calls and set(calls) == {"owned_read", "owned_cas"}
    assert len(records) == 2 * len(calls)
    paired = defaultdict(list)
    for row in records:
        assert row.metric == "netops.lifecycle.owned_io.count"
        assert row.metric_value == 1
        assert row.metric_dimensions == {"boundary": row.boundary, "outcome": row.outcome}
        assert math.isfinite(row.duration) and row.duration >= 0
        paired[row.io_id].append(row)
    assert len(paired) == len(calls)
    for pair in paired.values():
        assert [row.outcome for row in pair] == [
            "started", "failed" if fail_io else "succeeded",
        ]
        assert pair[0].boundary == pair[1].boundary
    assert private not in repr([row.__dict__ for row in records])
    record_property("actual_port_calls", json.dumps(calls))
    record_property("paired_metric_records", len(records))
