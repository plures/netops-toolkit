"""
Unit tests for netops.change.push.

All device I/O (DeviceConnection) is mocked — no real network connections are
made.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from netops.change.push import (
    ChangeRecord,
    _rollback_to,
    _snapshot_config,
    _unified_diff,
    _wait_for_confirmation,
    append_changelog,
    load_changelog,
    run_push,
)
from netops.core.connection import ConnectionParams

# ---------------------------------------------------------------------------
# Fixtures / shared data
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
# _snapshot_config
# ---------------------------------------------------------------------------


class TestSnapshotConfig:
    def test_cisco_uses_show_running_config(self):
        conn = MagicMock()
        conn.send.return_value = PRE_CONFIG
        result = _snapshot_config(conn, "cisco_ios")
        conn.send.assert_called_once_with("show running-config")
        assert result == PRE_CONFIG

    def test_nokia_uses_admin_display_config(self):
        conn = MagicMock()
        conn.send.return_value = "nokia-config"
        result = _snapshot_config(conn, "nokia_sros")
        conn.send.assert_called_once_with("admin display-config")
        assert result == "nokia-config"

    def test_juniper_uses_show_configuration(self):
        conn = MagicMock()
        conn.send.return_value = "juniper-config"
        result = _snapshot_config(conn, "juniper_junos")
        conn.send.assert_called_once_with("show configuration")
        assert result == "juniper-config"

    def test_cisco_xe_uses_show_running_config(self):
        conn = MagicMock()
        conn.send.return_value = "xe-config"
        _snapshot_config(conn, "cisco_xe")
        conn.send.assert_called_once_with("show running-config")


# ---------------------------------------------------------------------------
# _unified_diff
# ---------------------------------------------------------------------------


class TestUnifiedDiff:
    def test_identical_configs_produce_empty_diff(self):
        assert _unified_diff(PRE_CONFIG, PRE_CONFIG, "router1") == ""

    def test_diff_contains_added_line(self):
        diff = _unified_diff(PRE_CONFIG, POST_CONFIG, "router1")
        assert "+ description WAN uplink" in diff

    def test_diff_fromfile_tofile_labels(self):
        diff = _unified_diff(PRE_CONFIG, POST_CONFIG, "rtr1")
        assert "rtr1:pre" in diff
        assert "rtr1:post" in diff

    def test_diff_shows_removed_line(self):
        diff = _unified_diff(POST_CONFIG, PRE_CONFIG, "r1")
        assert "- description WAN uplink" in diff


# ---------------------------------------------------------------------------
# _rollback_to
# ---------------------------------------------------------------------------


class TestRollbackTo:
    def test_cisco_xr_uses_rollback_command(self):
        conn = MagicMock()
        _rollback_to(conn, "cisco_xr", PRE_CONFIG)
        conn.send.assert_called_once_with("rollback configuration last 1")

    def test_juniper_uses_rollback_and_commit(self):
        conn = MagicMock()
        _rollback_to(conn, "juniper_junos", PRE_CONFIG)
        conn.send_config.assert_called_once_with(["rollback 1", "commit"])

    def test_generic_resends_non_comment_lines(self):
        conn = MagicMock()
        _rollback_to(conn, "cisco_ios", PRE_CONFIG)
        args, _ = conn.send_config.call_args
        sent_cmds = args[0]
        assert "interface GigabitEthernet0/0" in sent_cmds
        # Lines may have leading whitespace preserved from the config
        assert any("no shutdown" in cmd for cmd in sent_cmds)

    def test_generic_strips_comment_lines(self):
        conn = MagicMock()
        _rollback_to(conn, "cisco_ios", PRE_CONFIG)
        args, _ = conn.send_config.call_args
        sent_cmds = args[0]
        assert "!" not in sent_cmds

    def test_generic_strips_blank_lines(self):
        conn = MagicMock()
        _rollback_to(conn, "cisco_ios", PRE_CONFIG)
        args, _ = conn.send_config.call_args
        sent_cmds = args[0]
        assert "" not in sent_cmds


# ---------------------------------------------------------------------------
# _wait_for_confirmation
# ---------------------------------------------------------------------------


class TestWaitForConfirmation:
    def test_returns_true_when_confirm_typed(self, monkeypatch):
        import io

        monkeypatch.setattr("sys.stdin", io.StringIO("confirm\n"))
        result = _wait_for_confirmation(5)
        assert result is True

    def test_returns_false_when_timeout_expires(self, monkeypatch):
        import io

        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        result = _wait_for_confirmation(1)
        assert result is False

    def test_wrong_input_returns_false(self, monkeypatch):
        import io

        monkeypatch.setattr("sys.stdin", io.StringIO("yes\n"))
        result = _wait_for_confirmation(1)
        assert result is False


# ---------------------------------------------------------------------------
# append_changelog / load_changelog
# ---------------------------------------------------------------------------


class TestChangelog:
    def _make_record(self, host: str = "r1", operator: str = "alice") -> ChangeRecord:
        return ChangeRecord(
            host=host,
            operator=operator,
            started_at="2024-01-01T00:00:00+00:00",
            commands=["no ip route 0.0.0.0 0.0.0.0"],
            pre_config="!",
            committed=True,
            confirmed=True,
        )

    def test_append_creates_file_and_writes_json(self, tmp_path):
        rec = self._make_record()
        path = tmp_path / "log.jsonl"
        append_changelog(rec, path)
        assert path.exists()
        line = json.loads(path.read_text().strip())
        assert line["host"] == "r1"
        assert line["operator"] == "alice"
        assert line["committed"] is True

    def test_append_multiple_records_each_on_own_line(self, tmp_path):
        path = tmp_path / "log.jsonl"
        for i in range(3):
            rec = ChangeRecord(
                host=f"r{i}",
                operator="bob",
                started_at="2024-01-01T00:00:00+00:00",
                commands=[],
                pre_config="",
            )
            append_changelog(rec, path)
        lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
        assert len(lines) == 3

    def test_load_returns_list_of_dicts(self, tmp_path):
        path = tmp_path / "log.jsonl"
        append_changelog(self._make_record(), path)
        records = load_changelog(path)
        assert len(records) == 1
        assert records[0]["host"] == "r1"

    def test_load_missing_file_returns_empty_list(self, tmp_path):
        path = tmp_path / "missing.jsonl"
        assert load_changelog(path) == []

    def test_append_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "a" / "b" / "log.jsonl"
        append_changelog(self._make_record(), path)
        assert path.exists()

    def test_load_all_fields_preserved(self, tmp_path):
        path = tmp_path / "log.jsonl"
        rec = self._make_record()
        append_changelog(rec, path)
        loaded = load_changelog(path)[0]
        assert loaded["commands"] == rec.commands
        assert loaded["pre_config"] == rec.pre_config


# ---------------------------------------------------------------------------
# run_push
# ---------------------------------------------------------------------------


class TestRunPush:
    def test_dry_run_does_not_call_send_config(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.push.DeviceConnection", return_value=mock_conn):
            record = run_push(params, ["interface lo0"], commit=False)
        mock_conn.send_config.assert_not_called()
        assert record.committed is False

    def test_dry_run_captures_pre_config(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.push.DeviceConnection", return_value=mock_conn):
            record = run_push(params, ["interface lo0"], commit=False)
        assert record.pre_config == PRE_CONFIG

    def test_dry_run_has_no_diff(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.push.DeviceConnection", return_value=mock_conn):
            record = run_push(params, ["interface lo0"], commit=False)
        assert record.diff is None

    def test_commit_sends_commands(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with (
            patch("netops.change.push.DeviceConnection", return_value=mock_conn),
            patch("netops.change.push._wait_for_confirmation", return_value=True),
        ):
            record = run_push(params, ["interface lo0"], commit=True)
        mock_conn.send_config.assert_called_once_with(["interface lo0"])
        assert record.committed is True

    def test_commit_records_diff(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with (
            patch("netops.change.push.DeviceConnection", return_value=mock_conn),
            patch("netops.change.push._wait_for_confirmation", return_value=True),
        ):
            record = run_push(params, ["description WAN"], commit=True)
        assert record.diff is not None
        assert "+ description WAN uplink" in record.diff

    def test_commit_without_timer_auto_confirms(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.push.DeviceConnection", return_value=mock_conn):
            record = run_push(params, ["cmd"], commit=True, confirm_timer_minutes=0)
        assert record.confirmed is True
        assert record.rolled_back is False

    def test_confirm_timer_confirmed(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with (
            patch("netops.change.push.DeviceConnection", return_value=mock_conn),
            patch("netops.change.push._wait_for_confirmation", return_value=True),
        ):
            record = run_push(params, ["cmd"], commit=True, confirm_timer_minutes=1)
        assert record.confirmed is True
        assert record.rolled_back is False

    def test_confirm_timer_expired_triggers_rollback(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with (
            patch("netops.change.push.DeviceConnection", return_value=mock_conn),
            patch("netops.change.push._wait_for_confirmation", return_value=False),
        ):
            record = run_push(params, ["cmd"], commit=True, confirm_timer_minutes=1)
        assert record.rolled_back is True
        assert record.confirmed is False
        # rollback must have been attempted
        assert mock_conn.send_config.call_count >= 2  # push + rollback

    def test_connection_error_captured_in_record(self):
        params = _make_params()
        with patch("netops.change.push.DeviceConnection") as MockDC:
            MockDC.return_value.__enter__.side_effect = OSError("connection refused")
            record = run_push(params, ["cmd"], commit=True)
        assert record.error is not None
        assert "connection refused" in record.error

    def test_changelog_written_on_success(self, tmp_path):
        params = _make_params()
        mock_conn = _make_mock_conn()
        log = tmp_path / "change.jsonl"
        with (
            patch("netops.change.push.DeviceConnection", return_value=mock_conn),
            patch("netops.change.push._wait_for_confirmation", return_value=True),
        ):
            run_push(params, ["cmd"], commit=True, changelog_path=log)
        records = load_changelog(log)
        assert len(records) == 1
        assert records[0]["committed"] is True

    def test_changelog_written_on_error(self, tmp_path):
        params = _make_params()
        log = tmp_path / "change.jsonl"
        with patch("netops.change.push.DeviceConnection") as MockDC:
            MockDC.return_value.__enter__.side_effect = OSError("refused")
            run_push(params, ["cmd"], commit=True, changelog_path=log)
        records = load_changelog(log)
        assert len(records) == 1
        assert records[0]["error"] is not None

    def test_operator_recorded_in_changelog(self, tmp_path):
        params = _make_params()
        mock_conn = _make_mock_conn()
        log = tmp_path / "change.jsonl"
        with patch("netops.change.push.DeviceConnection", return_value=mock_conn):
            run_push(
                params,
                ["cmd"],
                commit=False,
                operator="netops-bot",
                changelog_path=log,
            )
        records = load_changelog(log)
        assert records[0]["operator"] == "netops-bot"

    def test_host_recorded_in_change_record(self):
        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.push.DeviceConnection", return_value=mock_conn):
            record = run_push(params, ["cmd"], commit=False, operator="x")
        assert record.host == "192.0.2.1"

    def test_started_at_is_iso8601(self):
        from datetime import datetime

        params = _make_params()
        mock_conn = _make_mock_conn()
        with patch("netops.change.push.DeviceConnection", return_value=mock_conn):
            record = run_push(params, ["cmd"], commit=False, operator="x")
        # Should parse without error
        dt = datetime.fromisoformat(record.started_at)
        assert dt.tzinfo is not None
