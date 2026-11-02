"""Regression tests for fail-closed health evidence and change safety (PLU-41).

All connections and device writes are mocked. No live devices are modified.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from netops.change.rollback import _health_degraded, run_rollback_push
from netops.check.health import (
    build_health_report,
    check_cpu,
    check_interface_errors,
    check_memory,
    run_health_check,
)
from netops.core.connection import ConnectionParams


class EmptyConn:
    def send(self, *args, **kwargs):
        return ""


def _params():
    return ConnectionParams(host="192.0.2.10", username="test", device_type="cisco_ios")


def _healthy():
    return {
        "host": "192.0.2.10",
        "success": True,
        "checks": {
            "cpu": {"utilization": 20, "alert": False},
            "memory": {"utilization": 30, "alert": False},
            "interface_errors": {"total": 1, "alert": False},
            "logs": {"critical_count": 0, "alert": False},
        },
        "overall_alert": False,
        "overall_unknown": False,
        "status": "HEALTHY",
        "error": None,
    }


def _unknown():
    health = _healthy()
    health["checks"] = {
        **health["checks"],
        "cpu": {"utilization": None, "alert": False, "error": "timeout"},
    }
    health["overall_unknown"] = True
    health["status"] = "UNKNOWN"
    return health


def test_empty_cpu_parser_cannot_be_health_zero():
    r = check_cpu(EmptyConn(), "cisco_ios", threshold=80)
    assert r["utilization"] is None
    assert r["error"]
    assert not r["alert"]


def test_empty_memory_parser_cannot_be_health_zero():
    r = check_memory(EmptyConn(), "cisco_ios", threshold=85)
    assert r["utilization"] is None
    assert r["error"]


def test_empty_interface_parser_reports_no_coverage():
    r = check_interface_errors(EmptyConn(), "cisco_ios")
    assert r["error"]
    assert r["total"] == 0


def test_partial_check_error_is_unknown_not_healthy(monkeypatch):
    class CM:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    monkeypatch.setattr("netops.check.health.DeviceConnection", lambda _: CM())
    monkeypatch.setattr(
        "netops.check.health.check_cpu",
        lambda *_: {"alert": False, "error": "timeout"},
    )
    monkeypatch.setattr(
        "netops.check.health.check_memory",
        lambda *_: {"alert": False, "utilization": 20},
    )
    monkeypatch.setattr(
        "netops.check.health.check_interface_errors",
        lambda *_: {"alert": False, "total": 1},
    )
    monkeypatch.setattr(
        "netops.check.health.check_logs",
        lambda *_: {"alert": False, "critical_count": 0},
    )
    r = run_health_check(_params())
    assert r["success"] is True  # transport succeeded
    assert r["overall_alert"] is False  # no measured threshold violation
    assert r["overall_unknown"] is True
    assert r["status"] == "UNKNOWN"


def test_unreachable_is_unknown_not_healthy(monkeypatch):
    monkeypatch.setattr(
        "netops.check.health.DeviceConnection",
        lambda _: (_ for _ in ()).throw(OSError("unreachable")),
    )
    r = run_health_check(_params())
    assert not r["success"]
    assert r["overall_unknown"]
    assert r["status"] == "UNKNOWN"


def test_aggregate_counts_unknown_separately_from_threshold_alerts():
    unknown = _unknown()
    unreachable = {**_healthy(), "success": False, "overall_unknown": True}
    report = build_health_report([_healthy(), unknown, unreachable])
    assert report["devices_reachable"] == 2
    assert report["devices_unknown"] == 2
    assert report["devices_with_alerts"] == 0
    assert report["overall_unknown"]


def test_cli_gate_exits_nonzero_on_unknown(monkeypatch):
    from netops.check.health import main

    monkeypatch.setattr("netops.check.health.run_health_check", lambda *a, **kw: _unknown())
    monkeypatch.setattr(
        sys, "argv",
        ["netops-health", "--host", "192.0.2.10", "--json", "--fail-on-alert"],
    )
    with pytest.raises(SystemExit) as exited:
        main()
    assert exited.value.code == 1


def test_post_change_unknown_is_degradation_even_without_threshold_alert():
    degraded, reason = _health_degraded(_healthy(), _unknown())
    assert degraded
    assert "unknown" in reason


def test_pre_change_unknown_blocks_config_push():
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    conn.send.return_value = "pre-config"
    with (
        patch("netops.change.rollback.DeviceConnection", return_value=conn),
        patch("netops.change.rollback.run_health_check", return_value=_unknown()),
        patch("netops.change.rollback._snapshot_config", return_value="pre-config"),
    ):
        result = run_rollback_push(
            _params(), ["interface loopback1"], commit=True,
            validate_health=True, snapshot_dir=None,
        )
    assert result.error is not None
    assert not result.committed
    conn.send_config.assert_not_called()


def test_post_change_unknown_fails_validation_and_requests_rollback():
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    with (
        patch("netops.change.rollback.DeviceConnection", return_value=conn),
        patch("netops.change.rollback.run_health_check", side_effect=[_healthy(), _unknown()]),
        patch("netops.change.rollback._snapshot_config", side_effect=["before", "after"]),
        patch("netops.change.rollback._push_commands"),
        patch("netops.change.rollback._rollback_to") as do_rollback,
    ):
        result = run_rollback_push(
            _params(), ["interface loopback1"], commit=True,
            validate_health=True, rollback_on_failure=True,
            snapshot_dir=None,
        )
    assert result.committed
    assert result.validation_passed is False
    assert result.rolled_back
    do_rollback.assert_called_once()
