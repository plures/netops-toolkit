"""
Unit tests for netops.change.rollback.

All device I/O and health checks are mocked — no real network connections are made.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from netops.change.rollback import (
    RollbackRecord,
    _health_degraded,
    _save_pre_snapshot,
    append_audit_log,
    load_audit_log,
    run_rollback_push,
)
from netops.core.connection import ConnectionParams

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

PRE_CONFIG = """\
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
"""

POST_CONFIG = """\
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 description WAN uplink
 no shutdown
!
"""

HEALTHY_RESULT = {
    "host": "192.0.2.1",
    "timestamp": "2024-01-01T00:00:00Z",
    "success": True,
    "checks": {
        "cpu": {"utilization": 20.0, "threshold": 80.0, "alert": False},
        "memory": {"utilization": 40.0, "threshold": 85.0, "alert": False},
        "interface_errors": {"total": 5, "with_errors": 0, "alert": False},
        "logs": {"critical_count": 0, "major_count": 0, "alert": False},
    },
    "overall_alert": False,
    "error": None,
}

UNHEALTHY_RESULT = {
    **HEALTHY_RESULT,
    "checks": {
        **HEALTHY_RESULT["checks"],
        "cpu": {"utilization": 95.0, "threshold": 80.0, "alert": True},
    },
    "overall_alert": True,
}

UNREACHABLE_RESULT = {
    "host": "192.0.2.1",
    "timestamp": "2024-01-01T00:00:00Z",
    "success": False,
    "checks": {},
    "overall_alert": False,
    "error": "Connection refused",
}


def _make_params(device_type: str = "cisco_ios") -> ConnectionParams:
    return ConnectionParams(
        host="192.0.2.1",
        username="admin",
        password="secret",
        device_type=device_type,
    )


def _make_mock_conn(pre: str = PRE_CONFIG, post: str = POST_CONFIG) -> MagicMock:
    """Return a mock DeviceConnection context manager."""
    mock_conn = MagicMock()
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_conn.send.side_effect = [pre, post]
    mock_conn.send_config.return_value = ""
    return mock_conn


# ---------------------------------------------------------------------------
# _health_degraded
# ---------------------------------------------------------------------------


class TestHealthDegraded:
    def test_no_degradation_when_both_healthy(self):
        degraded, reason = _health_degraded(HEALTHY_RESULT, HEALTHY_RESULT)
        assert degraded is False
        assert reason == ""

    def test_degraded_when_post_has_new_cpu_alert(self):
        degraded, reason = _health_degraded(HEALTHY_RESULT, UNHEALTHY_RESULT)
        assert degraded is True
        assert "cpu" in reason

    def test_no_degradation_when_pre_already_had_alert(self):
        # pre already fired the same alert — staying alerting is NOT degradation
        degraded, reason = _health_degraded(UNHEALTHY_RESULT, UNHEALTHY_RESULT)
        assert degraded is False

    def test_degraded_when_device_unreachable(self):
        degraded, reason = _health_degraded(HEALTHY_RESULT, UNREACHABLE_RESULT)
        assert degraded is True
        assert "unreachable" in reason

    def test_degraded_when_multiple_new_alerts(self):
        post = {
            **HEALTHY_RESULT,
            "checks": {
                "cpu": {"alert": True},
                "memory": {"alert": True},
                "interface_errors": {"alert": False},
                "logs": {"alert": False},
            },
        }
        degraded, reason = _health_degraded(HEALTHY_RESULT, post)
        assert degraded is True
        assert "cpu" in reason
        assert "memory" in reason

    def test_none_pre_health_treats_all_post_alerts_as_new(self):
        degraded, reason = _health_degraded(None, UNHEALTHY_RESULT)
        assert degraded is True
        assert "cpu" in reason

    def test_returns_false_when_post_has_no_alerts(self):
        degraded, _ = _health_degraded(None, HEALTHY_RESULT)
        assert degraded is False


# ---------------------------------------------------------------------------
# _save_pre_snapshot
# ---------------------------------------------------------------------------


class TestSavePreSnapshot:
    def test_saves_config_to_backup_dir(self, tmp_path):
        path = _save_pre_snapshot("router1", PRE_CONFIG, tmp_path, "20240101-120000")
        assert path is not None
        assert "router1" in path

    def test_returns_none_on_error(self, tmp_path):
        with patch("netops.collect.backup.save_backup", side_effect=OSError("disk full")):
            result = _save_pre_snapshot("r1", PRE_CONFIG, tmp_path, "20240101-120000")
        assert result is None


# ---------------------------------------------------------------------------
# Audit log helpers
# ---------------------------------------------------------------------------


class TestAuditLog:
    def _make_record(self, host: str = "r1") -> RollbackRecord:
        return RollbackRecord(
            change_id="test-uuid-1",
            host=host,
            operator="alice",
            reason="CR-123",
            started_at="2024-01-01T00:00:00+00:00",
            commands=["interface lo0"],
            pre_config="!",
            committed=True,
            validation_passed=True,
        )

    def test_append_creates_file(self, tmp_path):
        rec = self._make_record()
        path = tmp_path / "audit.jsonl"
        append_audit_log(rec, path)
        assert path.exists()

    def test_append_writes_valid_json(self, tmp_path):
        rec = self._make_record()
        path = tmp_path / "audit.jsonl"
        append_audit_log(rec, path)
        data = json.loads(path.read_text().strip())
        assert data["change_id"] == "test-uuid-1"
        assert data["host"] == "r1"
        assert data["operator"] == "alice"
        assert data["reason"] == "CR-123"

    def test_append_multiple_records_each_on_own_line(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        for i in range(3):
            rec = self._make_record(host=f"r{i}")
            append_audit_log(rec, path)
        lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
        assert len(lines) == 3

    def test_load_returns_list_of_dicts(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        append_audit_log(self._make_record(), path)
        records = load_audit_log(path)
        assert len(records) == 1
        assert records[0]["host"] == "r1"

    def test_load_missing_file_returns_empty_list(self, tmp_path):
        path = tmp_path / "missing.jsonl"
        assert load_audit_log(path) == []

    def test_append_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "a" / "b" / "audit.jsonl"
        append_audit_log(self._make_record(), path)
        assert path.exists()

    def test_all_fields_preserved(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        rec = self._make_record()
        append_audit_log(rec, path)
        loaded = load_audit_log(path)[0]
        assert loaded["change_id"] == rec.change_id
        assert loaded["reason"] == rec.reason
        assert loaded["commands"] == rec.commands
        assert loaded["pre_config"] == rec.pre_config


# ---------------------------------------------------------------------------
# run_rollback_push — dry-run
# ---------------------------------------------------------------------------


class TestRunRollbackPushDryRun:
    def test_dry_run_does_not_push(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            record = run_rollback_push(params, ["cmd"], commit=False, validate_health=False)
        mock_conn.send_config.assert_not_called()
        assert record.committed is False

    def test_dry_run_captures_pre_config(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            record = run_rollback_push(params, ["cmd"], commit=False, validate_health=False)
        assert record.pre_config == PRE_CONFIG

    def test_dry_run_with_health_check_runs_pre_check(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ) as mock_hc:
            run_rollback_push(params, ["cmd"], commit=False, validate_health=True)
        mock_hc.assert_called_once()

    def test_dry_run_aborts_if_device_unreachable_pre_check(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=UNREACHABLE_RESULT
        ):
            record = run_rollback_push(params, ["cmd"], commit=False, validate_health=True)
        assert record.error is not None
        assert record.committed is False

    def test_dry_run_no_diff(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            record = run_rollback_push(params, ["cmd"], commit=False)
        assert record.diff is None
        assert record.post_config is None


# ---------------------------------------------------------------------------
# run_rollback_push — commit, validation passes
# ---------------------------------------------------------------------------


class TestRunRollbackPushCommitPass:
    def test_commit_pushes_commands(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            record = run_rollback_push(
                params, ["interface lo0"], commit=True, validate_health=True
            )
        mock_conn.send_config.assert_called_once_with(["interface lo0"])
        assert record.committed is True

    def test_validation_passed_when_healthy(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            record = run_rollback_push(
                params, ["cmd"], commit=True, validate_health=True, rollback_on_failure=True
            )
        assert record.validation_passed is True
        assert record.rolled_back is False

    def test_diff_captured_on_commit(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            record = run_rollback_push(
                params, ["description WAN"], commit=True, validate_health=True
            )
        assert record.diff is not None
        assert "+ description WAN uplink" in record.diff

    def test_validation_skipped_when_validate_health_false(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ) as mock_hc:
            record = run_rollback_push(params, ["cmd"], commit=True, validate_health=False)
        mock_hc.assert_not_called()
        assert record.validation_passed is True

    def test_two_health_checks_run_on_commit(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ) as mock_hc:
            run_rollback_push(params, ["cmd"], commit=True, validate_health=True)
        # pre + post health checks
        assert mock_hc.call_count == 2

    def test_commit_without_validation_auto_passes(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn):
            record = run_rollback_push(params, ["cmd"], commit=True, validate_health=False)
        assert record.validation_passed is True
        assert record.rolled_back is False


# ---------------------------------------------------------------------------
# run_rollback_push — commit, validation fails → rollback
# ---------------------------------------------------------------------------


class TestRunRollbackPushCommitFail:
    def test_rollback_triggered_on_health_degradation(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check",
            side_effect=[HEALTHY_RESULT, UNHEALTHY_RESULT],
        ):
            record = run_rollback_push(
                params, ["cmd"], commit=True, validate_health=True, rollback_on_failure=True
            )
        assert record.validation_passed is False
        assert record.rolled_back is True
        assert record.rollback_reason is not None

    def test_rollback_not_triggered_when_flag_off(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check",
            side_effect=[HEALTHY_RESULT, UNHEALTHY_RESULT],
        ):
            record = run_rollback_push(
                params, ["cmd"], commit=True, validate_health=True, rollback_on_failure=False
            )
        assert record.validation_passed is False
        assert record.rolled_back is False

    def test_rollback_calls_rollback_to(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check",
            side_effect=[HEALTHY_RESULT, UNHEALTHY_RESULT],
        ), patch("netops.change.rollback._rollback_to") as mock_rb:
            run_rollback_push(
                params, ["cmd"], commit=True, validate_health=True, rollback_on_failure=True
            )
        mock_rb.assert_called_once()

    def test_rollback_on_unreachable_post_change(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check",
            side_effect=[HEALTHY_RESULT, UNREACHABLE_RESULT],
        ):
            record = run_rollback_push(
                params, ["cmd"], commit=True, validate_health=True, rollback_on_failure=True
            )
        assert record.validation_passed is False
        assert record.rolled_back is True

    def test_rollback_reason_recorded(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check",
            side_effect=[HEALTHY_RESULT, UNHEALTHY_RESULT],
        ):
            record = run_rollback_push(
                params, ["cmd"], commit=True, validate_health=True, rollback_on_failure=True
            )
        assert "cpu" in record.rollback_reason

    def test_rollback_uses_pre_config(self):
        """_rollback_to must receive the original pre-change config."""
        params = _make_params()
        mock_conn = _make_mock_conn()
        captured: list = []
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check",
            side_effect=[HEALTHY_RESULT, UNHEALTHY_RESULT],
        ), patch(
            "netops.change.rollback._rollback_to",
            side_effect=lambda conn, dt, cfg: captured.append(cfg),
        ):
            run_rollback_push(
                params, ["cmd"], commit=True, validate_health=True, rollback_on_failure=True
            )
        assert captured == [PRE_CONFIG]


# ---------------------------------------------------------------------------
# run_rollback_push — connection error handling
# ---------------------------------------------------------------------------


class TestRunRollbackPushErrors:
    def test_connection_error_captured_in_record(self):
        params = _make_params()
        with patch("netops.change.rollback.DeviceConnection") as MockDC:
            MockDC.return_value.__enter__.side_effect = OSError("connection refused")
            record = run_rollback_push(params, ["cmd"], commit=True)
        assert record.error is not None
        assert "connection refused" in record.error
        assert record.committed is False

    def test_completed_at_set_even_on_error(self):
        params = _make_params()
        with patch("netops.change.rollback.DeviceConnection") as MockDC:
            MockDC.return_value.__enter__.side_effect = OSError("refused")
            record = run_rollback_push(params, ["cmd"], commit=True)
        assert record.completed_at is not None


# ---------------------------------------------------------------------------
# run_rollback_push — audit log integration
# ---------------------------------------------------------------------------


class TestRunRollbackPushAuditLog:
    def test_audit_log_written_on_success(self, tmp_path):
        params = _make_params()
        mock_conn = _make_mock_conn()
        log = tmp_path / "audit.jsonl"
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            run_rollback_push(
                params, ["cmd"], commit=True, validate_health=True, audit_log_path=log
            )
        records = load_audit_log(log)
        assert len(records) == 1
        assert records[0]["committed"] is True

    def test_audit_log_written_on_error(self, tmp_path):
        params = _make_params()
        log = tmp_path / "audit.jsonl"
        with patch("netops.change.rollback.DeviceConnection") as MockDC:
            MockDC.return_value.__enter__.side_effect = OSError("refused")
            run_rollback_push(params, ["cmd"], commit=True, audit_log_path=log)
        records = load_audit_log(log)
        assert len(records) == 1
        assert records[0]["error"] is not None

    def test_audit_log_records_operator_and_reason(self, tmp_path):
        params = _make_params()
        mock_conn = _make_mock_conn()
        log = tmp_path / "audit.jsonl"
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            run_rollback_push(
                params,
                ["cmd"],
                commit=False,
                operator="alice",
                reason="CR-456",
                audit_log_path=log,
            )
        loaded = load_audit_log(log)[0]
        assert loaded["operator"] == "alice"
        assert loaded["reason"] == "CR-456"

    def test_audit_log_has_unique_change_id(self, tmp_path):
        params = _make_params()
        mock_conn = _make_mock_conn()
        log = tmp_path / "audit.jsonl"
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            record = run_rollback_push(params, ["cmd"], commit=False, audit_log_path=log)
        loaded = load_audit_log(log)[0]
        assert loaded["change_id"] == record.change_id
        assert len(loaded["change_id"]) > 0

    def test_audit_log_has_completed_at(self, tmp_path):
        params = _make_params()
        mock_conn = _make_mock_conn()
        log = tmp_path / "audit.jsonl"
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            run_rollback_push(params, ["cmd"], commit=False, audit_log_path=log)
        loaded = load_audit_log(log)[0]
        assert loaded["completed_at"] is not None

    def test_audit_log_records_rollback(self, tmp_path):
        params = _make_params()
        mock_conn = _make_mock_conn()
        log = tmp_path / "audit.jsonl"
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check",
            side_effect=[HEALTHY_RESULT, UNHEALTHY_RESULT],
        ), patch("netops.change.rollback._rollback_to"):
            run_rollback_push(
                params,
                ["cmd"],
                commit=True,
                validate_health=True,
                rollback_on_failure=True,
                audit_log_path=log,
            )
        loaded = load_audit_log(log)[0]
        assert loaded["rolled_back"] is True
        assert loaded["validation_passed"] is False


# ---------------------------------------------------------------------------
# run_rollback_push — snapshot integration
# ---------------------------------------------------------------------------


class TestSnapshotIntegration:
    def test_snapshot_saved_when_snapshot_dir_provided(self, tmp_path):
        params = _make_params()
        mock_conn = _make_mock_conn()
        snapshot_dir = tmp_path / "snapshots"
        fake_path = str(snapshot_dir / "router1.cfg")
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ), patch(
            "netops.change.rollback._save_pre_snapshot", return_value=fake_path
        ) as mock_snap:
            record = run_rollback_push(
                params, ["cmd"], commit=False, validate_health=False, snapshot_dir=snapshot_dir
            )
        mock_snap.assert_called_once()
        assert record.snapshot_path == fake_path

    def test_snapshot_not_saved_when_no_snapshot_dir(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ), patch("netops.change.rollback._save_pre_snapshot") as mock_snap:
            run_rollback_push(params, ["cmd"], commit=False, snapshot_dir=None)
        mock_snap.assert_not_called()

    def test_snapshot_dir_integration_writes_file(self, tmp_path):
        """End-to-end: actual snapshot saved to disk via backup integration."""
        params = _make_params()
        mock_conn = _make_mock_conn()
        snapshot_dir = tmp_path / "snapshots"
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            record = run_rollback_push(
                params, ["cmd"], commit=False, validate_health=False, snapshot_dir=snapshot_dir
            )
        assert record.snapshot_path is not None
        assert snapshot_dir.exists()


# ---------------------------------------------------------------------------
# RollbackRecord dataclass
# ---------------------------------------------------------------------------


class TestRollbackRecord:
    def test_required_fields_must_be_provided(self):
        rec = RollbackRecord(
            change_id="abc",
            host="r1",
            operator="admin",
            reason="test",
            started_at="2024-01-01T00:00:00Z",
            commands=["cmd"],
        )
        assert rec.committed is False
        assert rec.validation_passed is None
        assert rec.rolled_back is False
        assert rec.error is None

    def test_started_at_is_iso8601(self):
        from datetime import datetime

        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            record = run_rollback_push(
                params, ["cmd"], commit=False, operator="x", validate_health=False
            )
        dt = datetime.fromisoformat(record.started_at)
        assert dt.tzinfo is not None

    def test_change_id_is_unique(self):
        params = _make_params()
        mock_conn_a = _make_mock_conn()
        mock_conn_b = _make_mock_conn()
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn_a), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            record_a = run_rollback_push(params, ["cmd"], commit=False, validate_health=False)
        with patch("netops.change.rollback.DeviceConnection", return_value=mock_conn_b), patch(
            "netops.change.rollback.run_health_check", return_value=HEALTHY_RESULT
        ):
            record_b = run_rollback_push(params, ["cmd"], commit=False, validate_health=False)
        assert record_a.change_id != record_b.change_id
