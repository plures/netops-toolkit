"""
Unit tests for netops.collect.backup.

All network I/O (device connection) and subprocess calls (git) are mocked so
the tests run without real devices or a git installation.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from netops.collect.backup import (
    _latest_backup_before,
    _safe_hostname,
    generate_diff,
    git_commit,
    git_init,
    run_backup,
    save_backup,
)
from netops.core.connection import ConnectionParams

# ---------------------------------------------------------------------------
# _latest_backup_before
# ---------------------------------------------------------------------------


class TestLatestBackupBefore:
    def test_returns_none_when_directory_empty(self, tmp_path):
        assert _latest_backup_before(tmp_path, "current.cfg") is None

    def test_returns_none_when_only_current_exists(self, tmp_path):
        (tmp_path / "20240101-120000.cfg").write_text("config")
        assert _latest_backup_before(tmp_path, "20240101-120000.cfg") is None

    def test_returns_previous_backup(self, tmp_path):
        (tmp_path / "20240101-120000.cfg").write_text("old config")
        (tmp_path / "20240102-130000.cfg").write_text("new config")
        result = _latest_backup_before(tmp_path, "20240102-130000.cfg")
        assert result is not None
        assert result.name == "20240101-120000.cfg"

    def test_returns_most_recent_of_multiple_previous(self, tmp_path):
        (tmp_path / "20240101-000000.cfg").write_text("v1")
        (tmp_path / "20240102-000000.cfg").write_text("v2")
        (tmp_path / "20240103-000000.cfg").write_text("v3 (current)")
        result = _latest_backup_before(tmp_path, "20240103-000000.cfg")
        assert result is not None
        assert result.name == "20240102-000000.cfg"

    def test_ignores_non_cfg_files(self, tmp_path):
        (tmp_path / "20240101-120000.txt").write_text("not a backup")
        assert _latest_backup_before(tmp_path, "20240102-130000.cfg") is None


# ---------------------------------------------------------------------------
# _safe_hostname
# ---------------------------------------------------------------------------


class TestSafeHostname:
    def test_plain_ip_unchanged(self):
        assert _safe_hostname("10.0.0.1") == "10.0.0.1"

    def test_hostname_unchanged(self):
        assert _safe_hostname("core-rtr-01.example.com") == "core-rtr-01.example.com"

    def test_forward_slash_replaced(self):
        assert "/" not in _safe_hostname("some/path")

    def test_backslash_replaced(self):
        assert "\\" not in _safe_hostname("win\\host")

    def test_dotdot_collapsed(self):
        result = _safe_hostname("../../../etc/passwd")
        assert ".." not in result
        assert "/" not in result

    def test_colon_replaced(self):
        assert ":" not in _safe_hostname("host:8080")

    def test_empty_string_returns_placeholder(self):
        assert _safe_hostname("") == "_"

    def test_only_unsafe_chars_returns_placeholder(self):
        # "..." stripped of dots yields empty → placeholder
        result = _safe_hostname("...")
        assert result == "_"


# ---------------------------------------------------------------------------
# generate_diff
# ---------------------------------------------------------------------------


class TestGenerateDiff:
    def test_identical_configs_produce_empty_diff(self, tmp_path):
        cfg = "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"
        old_path = tmp_path / "old.cfg"
        old_path.write_text(cfg)
        assert generate_diff(old_path, cfg) == ""

    def test_added_lines_appear_in_diff(self, tmp_path):
        old_path = tmp_path / "old.cfg"
        old_path.write_text("line1\n")
        diff = generate_diff(old_path, "line1\nline2\n")
        assert "+line2" in diff

    def test_removed_lines_appear_in_diff(self, tmp_path):
        old_path = tmp_path / "old.cfg"
        old_path.write_text("line1\nline2\n")
        diff = generate_diff(old_path, "line1\n")
        assert "-line2" in diff

    def test_diff_uses_old_filename_as_fromfile(self, tmp_path):
        old_path = tmp_path / "20240101-120000.cfg"
        old_path.write_text("a\n")
        diff = generate_diff(old_path, "b\n")
        assert "20240101-120000.cfg" in diff

    def test_diff_uses_current_as_tofile(self, tmp_path):
        old_path = tmp_path / "old.cfg"
        old_path.write_text("a\n")
        diff = generate_diff(old_path, "b\n")
        assert "current" in diff


# ---------------------------------------------------------------------------
# save_backup
# ---------------------------------------------------------------------------


class TestSaveBackup:
    def _make_result(self, host="10.0.0.1", config="config text\n", success=True):
        return {
            "host": host,
            "success": success,
            "config": config,
            "error": None if success else "connection refused",
        }

    def test_successful_backup_creates_file(self, tmp_path):
        result = self._make_result()
        summary = save_backup(result, tmp_path, "20240101-120000")
        saved = Path(summary["saved_path"])
        assert saved.exists()
        assert saved.read_text() == "config text\n"

    def test_file_placed_under_host_subdirectory(self, tmp_path):
        result = self._make_result(host="192.168.1.1")
        save_backup(result, tmp_path, "20240101-120000")
        assert (tmp_path / "192.168.1.1" / "20240101-120000.cfg").exists()

    def test_failed_result_not_saved(self, tmp_path):
        result = self._make_result(success=False)
        summary = save_backup(result, tmp_path, "20240101-120000")
        assert summary["saved_path"] is None
        assert not (tmp_path / "10.0.0.1").exists()

    def test_failed_result_preserves_error(self, tmp_path):
        result = self._make_result(success=False)
        result["error"] = "timeout"
        summary = save_backup(result, tmp_path, "20240101-120000")
        assert summary["error"] == "timeout"
        assert not summary["success"]

    def test_first_backup_has_no_diff(self, tmp_path):
        result = self._make_result()
        summary = save_backup(result, tmp_path, "20240101-120000")
        assert summary["diff"] is None
        assert not summary["changed"]

    def test_unchanged_config_not_marked_changed(self, tmp_path):
        config = "interface Loopback0\n ip address 1.1.1.1 255.255.255.255\n"
        result = self._make_result(config=config)
        save_backup(result, tmp_path, "20240101-120000")
        summary2 = save_backup(result, tmp_path, "20240102-130000")
        assert not summary2["changed"]
        assert summary2["diff"] is None

    def test_changed_config_marked_changed(self, tmp_path):
        result1 = self._make_result(config="hostname router1\n")
        result2 = self._make_result(config="hostname router2\n")
        save_backup(result1, tmp_path, "20240101-120000")
        summary2 = save_backup(result2, tmp_path, "20240102-130000")
        assert summary2["changed"]
        assert summary2["diff"] is not None
        assert "-hostname router1" in summary2["diff"]
        assert "+hostname router2" in summary2["diff"]

    def test_summary_success_fields(self, tmp_path):
        result = self._make_result()
        summary = save_backup(result, tmp_path, "20240101-120000")
        assert summary["host"] == "10.0.0.1"
        assert summary["success"] is True
        assert summary["error"] is None


# ---------------------------------------------------------------------------
# git_init
# ---------------------------------------------------------------------------


class TestGitInit:
    def test_calls_git_init_when_no_dot_git(self, tmp_path):
        with patch("netops.collect.backup.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = git_init(tmp_path)
        assert result is True
        mock_run.assert_called_once_with(
            ["git", "init"],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )

    def test_skips_init_when_dot_git_exists(self, tmp_path):
        (tmp_path / ".git").mkdir()
        with patch("netops.collect.backup.subprocess.run") as mock_run:
            result = git_init(tmp_path)
        assert result is True
        mock_run.assert_not_called()

    def test_returns_false_on_oserror(self, tmp_path):
        with patch(
            "netops.collect.backup.subprocess.run", side_effect=OSError("git not found")
        ):
            result = git_init(tmp_path)
        assert result is False

    def test_returns_false_on_called_process_error(self, tmp_path):
        with patch(
            "netops.collect.backup.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "git"),
        ):
            result = git_init(tmp_path)
        assert result is False


# ---------------------------------------------------------------------------
# git_commit
# ---------------------------------------------------------------------------


class TestGitCommit:
    def _make_run(self, stdout="", stderr="", returncode=0):
        mock = MagicMock()
        mock.returncode = returncode
        mock.stdout = stdout
        mock.stderr = stderr
        return mock

    def test_calls_git_add_and_commit(self, tmp_path):
        add_result = self._make_run()
        commit_result = self._make_run(stdout="1 file changed")

        with patch("netops.collect.backup.subprocess.run") as mock_run:
            mock_run.side_effect = [add_result, commit_result]
            result = git_commit(tmp_path, "backup 20240101")

        assert result is True
        assert mock_run.call_count == 2
        first_call = mock_run.call_args_list[0]
        assert first_call == call(
            ["git", "add", "."],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )

    def test_nothing_to_commit_returns_true(self, tmp_path):
        add_result = self._make_run()
        commit_result = self._make_run(
            stdout="nothing to commit, working tree clean", returncode=1
        )

        with patch("netops.collect.backup.subprocess.run") as mock_run:
            mock_run.side_effect = [add_result, commit_result]
            result = git_commit(tmp_path, "backup 20240101")

        assert result is True

    def test_real_commit_failure_returns_false(self, tmp_path):
        add_result = self._make_run()
        commit_result = self._make_run(stderr="fatal: bad object", returncode=128)

        with patch("netops.collect.backup.subprocess.run") as mock_run:
            mock_run.side_effect = [add_result, commit_result]
            result = git_commit(tmp_path, "backup 20240101")

        assert result is False

    def test_oserror_returns_false(self, tmp_path):
        with patch(
            "netops.collect.backup.subprocess.run", side_effect=OSError("git not found")
        ):
            result = git_commit(tmp_path, "backup 20240101")
        assert result is False


# ---------------------------------------------------------------------------
# run_backup (integration-level, fully mocked)
# ---------------------------------------------------------------------------


def _make_params(host="10.0.0.1"):
    return ConnectionParams(host=host, username="admin", password="secret")


class TestRunBackup:
    def test_successful_backup_creates_files(self, tmp_path):
        params = _make_params()
        fake_result = {
            "host": "10.0.0.1",
            "success": True,
            "config": "hostname rtr\n",
            "error": None,
            "collected_at": "2024-01-01T00:00:00+00:00",
            "device_type": "cisco_ios",
            "lines": 1,
        }

        with patch("netops.collect.backup.collect_config", return_value=fake_result):
            summaries = run_backup([params], tmp_path, alert_on_change=False)

        assert len(summaries) == 1
        assert summaries[0]["success"]
        assert summaries[0]["saved_path"] is not None
        assert Path(summaries[0]["saved_path"]).exists()

    def test_failed_device_reflected_in_summary(self, tmp_path):
        params = _make_params()
        fake_result = {
            "host": "10.0.0.1",
            "success": False,
            "config": None,
            "error": "connection refused",
        }

        with patch("netops.collect.backup.collect_config", return_value=fake_result):
            summaries = run_backup([params], tmp_path, alert_on_change=False)

        assert not summaries[0]["success"]
        assert summaries[0]["error"] == "connection refused"

    def test_multiple_devices_all_collected(self, tmp_path):
        params_list = [_make_params("10.0.0.1"), _make_params("10.0.0.2")]

        def fake_collect(p):
            return {
                "host": p.host,
                "success": True,
                "config": f"hostname {p.host}\n",
                "error": None,
                "collected_at": "2024-01-01T00:00:00+00:00",
                "device_type": "cisco_ios",
                "lines": 1,
            }

        with patch("netops.collect.backup.collect_config", side_effect=fake_collect):
            summaries = run_backup(params_list, tmp_path, alert_on_change=False)

        hosts = {s["host"] for s in summaries}
        assert hosts == {"10.0.0.1", "10.0.0.2"}
        assert all(s["success"] for s in summaries)

    def test_change_detected_across_two_runs(self, tmp_path):
        params = _make_params()

        def make_collect(config):
            def _inner(p):
                return {
                    "host": p.host,
                    "success": True,
                    "config": config,
                    "error": None,
                    "collected_at": "2024-01-01T00:00:00+00:00",
                    "device_type": "cisco_ios",
                    "lines": len(config.splitlines()),
                }

            return _inner

        with patch(
            "netops.collect.backup.collect_config", side_effect=make_collect("hostname old\n")
        ):
            run_backup([params], tmp_path, alert_on_change=False, _timestamp="20240101-120000")

        with patch(
            "netops.collect.backup.collect_config", side_effect=make_collect("hostname new\n")
        ):
            summaries = run_backup(
                [params], tmp_path, alert_on_change=False, _timestamp="20240102-130000"
            )

        assert summaries[0]["changed"]
        assert "-hostname old" in summaries[0]["diff"]
        assert "+hostname new" in summaries[0]["diff"]

    def test_no_change_across_two_identical_runs(self, tmp_path):
        params = _make_params()
        config = "hostname router\ninterface Lo0\n"

        def fake_collect(p):
            return {
                "host": p.host,
                "success": True,
                "config": config,
                "error": None,
                "collected_at": "2024-01-01T00:00:00+00:00",
                "device_type": "cisco_ios",
                "lines": 2,
            }

        with patch("netops.collect.backup.collect_config", side_effect=fake_collect):
            run_backup([params], tmp_path, alert_on_change=False, _timestamp="20240101-120000")

        with patch("netops.collect.backup.collect_config", side_effect=fake_collect):
            summaries = run_backup(
                [params], tmp_path, alert_on_change=False, _timestamp="20240102-130000"
            )

        assert not summaries[0]["changed"]

    def test_git_init_and_commit_called_when_git_true(self, tmp_path):
        params = _make_params()
        fake_result = {
            "host": "10.0.0.1",
            "success": True,
            "config": "hostname rtr\n",
            "error": None,
            "collected_at": "2024-01-01T00:00:00+00:00",
            "device_type": "cisco_ios",
            "lines": 1,
        }

        with patch("netops.collect.backup.collect_config", return_value=fake_result):
            with patch("netops.collect.backup.git_init", return_value=True) as mock_init:
                with patch("netops.collect.backup.git_commit", return_value=True) as mock_commit:
                    run_backup([params], tmp_path, git=True, alert_on_change=False)

        mock_init.assert_called_once_with(tmp_path)
        mock_commit.assert_called_once()

    def test_git_not_called_when_git_false(self, tmp_path):
        params = _make_params()
        fake_result = {
            "host": "10.0.0.1",
            "success": True,
            "config": "hostname rtr\n",
            "error": None,
            "collected_at": "2024-01-01T00:00:00+00:00",
            "device_type": "cisco_ios",
            "lines": 1,
        }

        with patch("netops.collect.backup.collect_config", return_value=fake_result):
            with patch("netops.collect.backup.git_init") as mock_init:
                with patch("netops.collect.backup.git_commit") as mock_commit:
                    run_backup([params], tmp_path, git=False, alert_on_change=False)

        mock_init.assert_not_called()
        mock_commit.assert_not_called()

    def test_collect_config_exception_recorded_as_failure(self, tmp_path):
        params = _make_params()

        with patch(
            "netops.collect.backup.collect_config",
            side_effect=RuntimeError("unexpected crash"),
        ):
            summaries = run_backup([params], tmp_path, alert_on_change=False)

        assert not summaries[0]["success"]
        assert "unexpected crash" in summaries[0]["error"]

    def test_alert_written_to_stderr_on_change(self, tmp_path, capsys):
        params = _make_params()

        def make_collect(cfg):
            def _inner(p):
                return {
                    "host": p.host,
                    "success": True,
                    "config": cfg,
                    "error": None,
                    "collected_at": "2024-01-01T00:00:00+00:00",
                    "device_type": "cisco_ios",
                    "lines": 1,
                }

            return _inner

        with patch(
            "netops.collect.backup.collect_config", side_effect=make_collect("hostname old\n")
        ):
            run_backup([params], tmp_path, alert_on_change=True, _timestamp="20240101-120000")

        with patch(
            "netops.collect.backup.collect_config", side_effect=make_collect("hostname new\n")
        ):
            run_backup([params], tmp_path, alert_on_change=True, _timestamp="20240102-130000")

        captured = capsys.readouterr()
        assert "CHANGED" in captured.err
        assert "10.0.0.1" in captured.err

    def test_output_directory_created_if_missing(self, tmp_path):
        out = tmp_path / "deep" / "nested" / "backups"
        params = _make_params()
        fake_result = {
            "host": "10.0.0.1",
            "success": True,
            "config": "hostname rtr\n",
            "error": None,
            "collected_at": "2024-01-01T00:00:00+00:00",
            "device_type": "cisco_ios",
            "lines": 1,
        }

        with patch("netops.collect.backup.collect_config", return_value=fake_result):
            run_backup([params], out, alert_on_change=False)

        assert out.is_dir()

    def test_workers_zero_raises_value_error(self, tmp_path):
        with pytest.raises(ValueError, match="workers must be >= 1"):
            run_backup([], tmp_path, workers=0, alert_on_change=False)

    def test_workers_negative_raises_value_error(self, tmp_path):
        with pytest.raises(ValueError, match="workers must be >= 1"):
            run_backup([], tmp_path, workers=-1, alert_on_change=False)

    def test_git_init_failure_disables_git_and_warns_stderr(self, tmp_path, capsys):
        params = _make_params()
        fake_result = {
            "host": "10.0.0.1",
            "success": True,
            "config": "hostname rtr\n",
            "error": None,
            "collected_at": "2024-01-01T00:00:00+00:00",
            "device_type": "cisco_ios",
            "lines": 1,
        }

        with patch("netops.collect.backup.collect_config", return_value=fake_result):
            with patch("netops.collect.backup.git_init", return_value=False):
                with patch("netops.collect.backup.git_commit") as mock_commit:
                    run_backup([params], tmp_path, git=True, alert_on_change=False)

        # git_commit must not be called when git_init reports failure
        mock_commit.assert_not_called()
        captured = capsys.readouterr()
        assert "Warning" in captured.err or "warning" in captured.err.lower()

    def test_git_commit_failure_raises_runtime_error(self, tmp_path):
        params = _make_params()
        fake_result = {
            "host": "10.0.0.1",
            "success": True,
            "config": "hostname rtr\n",
            "error": None,
            "collected_at": "2024-01-01T00:00:00+00:00",
            "device_type": "cisco_ios",
            "lines": 1,
        }

        with patch("netops.collect.backup.collect_config", return_value=fake_result):
            with patch("netops.collect.backup.git_init", return_value=True):
                with patch("netops.collect.backup.git_commit", return_value=False):
                    with pytest.raises(RuntimeError, match="Git commit failed"):
                        run_backup([params], tmp_path, git=True, alert_on_change=False)

    def test_safe_hostname_used_as_directory_name(self, tmp_path):
        """Hosts with path-unsafe chars must not create subdirectories outside output."""
        params = ConnectionParams(host="192.168.1.1:9999", username="admin", password="secret")
        fake_result = {
            "host": "192.168.1.1:9999",
            "success": True,
            "config": "hostname rtr\n",
            "error": None,
            "collected_at": "2024-01-01T00:00:00+00:00",
            "device_type": "cisco_ios",
            "lines": 1,
        }

        with patch("netops.collect.backup.collect_config", return_value=fake_result):
            summaries = run_backup([params], tmp_path, alert_on_change=False)

        saved = Path(summaries[0]["saved_path"])
        # The colon must not appear in the directory name
        assert ":" not in saved.parent.name
        # The saved file must still be inside tmp_path
        assert str(saved).startswith(str(tmp_path))
