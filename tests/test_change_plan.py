"""
Unit tests for netops.change.plan.

All device I/O (DeviceConnection) is mocked — no real network connections are
made.  The dry-run guarantee is validated explicitly.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from netops.change.plan import (
    ChangePlan,
    ChangeStep,
    DeviceRole,
    RiskLevel,
    _append_plan_log,
    _compute_risk,
    _dict_to_plan,
    _plan_to_dict,
    apply_plan,
    export_plan,
    generate_plan,
    load_plan,
)
from netops.change.diff import DiffResult

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

CURRENT_CONFIG = """\
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
"""

DESIRED_CONFIG = """\
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 description WAN uplink
 no shutdown
!
"""

STEP_INPUT_BASIC = {
    "host": "192.0.2.1",
    "device_type": "cisco_ios",
    "device_role": "access",
    "current_config": CURRENT_CONFIG,
    "desired_config": DESIRED_CONFIG,
}

STEP_INPUT_NO_DIFF = {
    "host": "192.0.2.1",
    "device_type": "cisco_ios",
    "device_role": "core",
    "commands": ["interface Gi0/0", "description TEST"],
}


# ---------------------------------------------------------------------------
# DeviceRole
# ---------------------------------------------------------------------------


class TestDeviceRole:
    def test_weights_ordered(self):
        assert DeviceRole.ACCESS.weight < DeviceRole.DISTRIBUTION.weight
        assert DeviceRole.DISTRIBUTION.weight < DeviceRole.EDGE.weight
        assert DeviceRole.EDGE.weight < DeviceRole.CORE.weight

    def test_unknown_weight_is_nonzero(self):
        assert DeviceRole.UNKNOWN.weight > 0

    def test_value_strings(self):
        assert DeviceRole("core") == DeviceRole.CORE
        assert DeviceRole("access") == DeviceRole.ACCESS


# ---------------------------------------------------------------------------
# _compute_risk
# ---------------------------------------------------------------------------


class TestComputeRisk:
    def test_empty_steps_returns_low(self):
        score, level = _compute_risk([], [])
        assert score == 0.0
        assert level == RiskLevel.LOW

    def test_single_access_device_small_change_is_low(self):
        step = ChangeStep(
            host="h1",
            device_type="cisco_ios",
            device_role=DeviceRole.ACCESS,
            commands=["interface Gi0/0"],
        )
        from netops.change.diff import diff_configs

        diff = diff_configs(CURRENT_CONFIG, DESIRED_CONFIG)
        score, level = _compute_risk([step], [diff])
        # With 1 change entry and weight=1: score = 1 × 1 = 1 → LOW
        assert level == RiskLevel.LOW
        assert score < 6.0

    def test_core_device_many_changes_is_high(self):
        step = ChangeStep(
            host="h1",
            device_type="cisco_ios",
            device_role=DeviceRole.CORE,
            commands=[],
        )
        # Simulate a diff with 4 change entries → score = 4 × 4 = 16 ≥ 15 → HIGH
        mock_diff = MagicMock(spec=DiffResult)
        mock_diff.added = ["a1", "a2", "a3", "a4"]
        mock_diff.removed = []
        mock_diff.changed = []
        mock_diff.security_changes = []
        score, level = _compute_risk([step], [mock_diff])
        assert level == RiskLevel.HIGH

    def test_security_changes_add_bonus(self):
        step = ChangeStep(
            host="h1",
            device_type="cisco_ios",
            device_role=DeviceRole.ACCESS,
            commands=[],
        )
        mock_diff = MagicMock(spec=DiffResult)
        mock_diff.added = ["a"]
        mock_diff.removed = []
        mock_diff.changed = []
        mock_diff.security_changes = ["sec_entry"]  # non-empty → +3
        score, level = _compute_risk([step], [mock_diff])
        # weight=1, 1 change, 3 security bonus → score=4 → LOW (< 6)
        assert score == pytest.approx(1 * 1 + 3.0)

    def test_multi_device_adds_bonus(self):
        steps = [
            ChangeStep(host="h1", device_type="cisco_ios", device_role=DeviceRole.ACCESS, commands=[]),
            ChangeStep(host="h2", device_type="cisco_ios", device_role=DeviceRole.ACCESS, commands=[]),
        ]
        def _empty_diff() -> MagicMock:
            m = MagicMock(spec=DiffResult)
            m.added = []
            m.removed = []
            m.changed = []
            m.security_changes = []
            return m

        score, _ = _compute_risk(steps, [_empty_diff(), _empty_diff()])
        # multi_device_bonus = 2.0
        assert score == pytest.approx(2.0)


# ---------------------------------------------------------------------------
# generate_plan
# ---------------------------------------------------------------------------


class TestGeneratePlan:
    def test_returns_change_plan(self):
        plan = generate_plan([STEP_INPUT_BASIC])
        assert isinstance(plan, ChangePlan)

    def test_plan_id_is_uuid_string(self):
        import re

        plan = generate_plan([STEP_INPUT_BASIC])
        assert re.match(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            plan.plan_id,
        )

    def test_dry_run_is_true_by_default(self):
        plan = generate_plan([STEP_INPUT_BASIC])
        assert plan.dry_run is True

    def test_approved_is_false_by_default(self):
        plan = generate_plan([STEP_INPUT_BASIC])
        assert plan.approved is False

    def test_operator_set(self):
        plan = generate_plan([STEP_INPUT_BASIC], operator="alice")
        assert plan.operator == "alice"

    def test_description_set(self):
        plan = generate_plan([STEP_INPUT_BASIC], description="CHG-1234")
        assert plan.description == "CHG-1234"

    def test_step_count(self):
        plan = generate_plan([STEP_INPUT_BASIC, STEP_INPUT_NO_DIFF])
        assert len(plan.steps) == 2

    def test_diff_preview_populated_when_configs_given(self):
        plan = generate_plan([STEP_INPUT_BASIC])
        assert plan.steps[0].diff_preview  # non-empty

    def test_unified_diff_populated_when_configs_given(self):
        plan = generate_plan([STEP_INPUT_BASIC])
        assert plan.steps[0].unified_diff  # non-empty

    def test_commands_derived_from_diff(self):
        """When no commands provided, derive them from diff added/changed lines."""
        plan = generate_plan([STEP_INPUT_BASIC])
        # DESIRED_CONFIG adds 'description WAN uplink' — it should appear in commands
        assert any("description WAN uplink" in cmd for cmd in plan.steps[0].commands)

    def test_explicit_commands_not_overridden(self):
        step = {**STEP_INPUT_BASIC, "commands": ["explicit cmd"]}
        plan = generate_plan([step])
        assert plan.steps[0].commands == ["explicit cmd"]

    def test_risk_level_is_risk_level_enum(self):
        plan = generate_plan([STEP_INPUT_BASIC])
        assert isinstance(plan.risk_level, RiskLevel)

    def test_device_role_unknown_for_invalid_string(self):
        step = {**STEP_INPUT_BASIC, "device_role": "nonsense"}
        plan = generate_plan([step])
        assert plan.steps[0].device_role == DeviceRole.UNKNOWN

    def test_same_input_same_risk(self):
        """Plans with the same input should have the same risk score."""
        p1 = generate_plan([STEP_INPUT_BASIC], operator="x")
        p2 = generate_plan([STEP_INPUT_BASIC], operator="y")
        assert p1.risk_score == pytest.approx(p2.risk_score)
        assert p1.risk_level == p2.risk_level

    def test_no_current_config_gives_empty_preview(self):
        step = {"host": "h1", "desired_config": DESIRED_CONFIG}
        plan = generate_plan([step])
        # current_config is '' so diff runs with empty baseline
        # diff_preview should exist but reflect all lines as added
        assert isinstance(plan.steps[0].diff_preview, str)

    def test_security_change_flagged(self):
        current = "interface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"
        desired = "interface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n ip access-group IN in\n"
        step = {
            "host": "fw1",
            "device_type": "cisco_ios",
            "device_role": "edge",
            "current_config": current,
            "desired_config": desired,
        }
        plan = generate_plan([step])
        assert plan.steps[0].has_security_changes is True


# ---------------------------------------------------------------------------
# apply_plan — dry-run guarantee
# ---------------------------------------------------------------------------


class TestApplyPlanDryRun:
    def test_no_approval_returns_plan_unchanged(self):
        plan = generate_plan([STEP_INPUT_BASIC], operator="tester")
        returned = apply_plan(plan, approved=False)
        # Nothing applied
        assert all(not s.applied for s in returned.steps)
        assert returned.approved is False
        assert returned.applied_at is None

    def test_no_approval_does_not_connect(self):
        plan = generate_plan([STEP_INPUT_BASIC], operator="tester")
        with patch("netops.change.plan.DeviceConnection") as mock_dc:
            apply_plan(plan, approved=False)
            mock_dc.assert_not_called()

    def test_dry_run_never_calls_push_commands(self):
        plan = generate_plan([STEP_INPUT_BASIC], operator="tester")
        with patch("netops.change.plan._push_commands") as mock_push:
            apply_plan(plan, approved=False)
            mock_push.assert_not_called()


# ---------------------------------------------------------------------------
# apply_plan — approved execution
# ---------------------------------------------------------------------------


def _make_mock_conn() -> MagicMock:
    mock_conn = MagicMock()
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_conn.send_config.return_value = ""
    return mock_conn


class TestApplyPlanApproved:
    def test_approved_sets_approved_flag(self):
        plan = generate_plan([STEP_INPUT_BASIC], operator="tester")
        from netops.core.connection import ConnectionParams

        params = [ConnectionParams(host="192.0.2.1", username="admin", password="x")]
        with patch("netops.change.plan.DeviceConnection", return_value=_make_mock_conn()):
            result = apply_plan(plan, connection_params=params, approved=True)
        assert result.approved is True

    def test_approved_sets_applied_at(self):
        plan = generate_plan([STEP_INPUT_BASIC], operator="tester")
        from netops.core.connection import ConnectionParams

        params = [ConnectionParams(host="192.0.2.1", username="admin", password="x")]
        with patch("netops.change.plan.DeviceConnection", return_value=_make_mock_conn()):
            result = apply_plan(plan, connection_params=params, approved=True)
        assert result.applied_at is not None

    def test_step_marked_applied_on_success(self):
        plan = generate_plan([STEP_INPUT_BASIC], operator="tester")
        from netops.core.connection import ConnectionParams

        params = [ConnectionParams(host="192.0.2.1", username="admin", password="x")]
        with patch("netops.change.plan.DeviceConnection", return_value=_make_mock_conn()):
            result = apply_plan(plan, connection_params=params, approved=True)
        assert result.steps[0].applied is True
        assert result.steps[0].error is None

    def test_missing_params_sets_error(self):
        plan = generate_plan([STEP_INPUT_BASIC], operator="tester")
        # Pass empty params list — step should get an error, not crash
        result = apply_plan(plan, connection_params=[], approved=True)
        assert result.steps[0].error is not None

    def test_device_exception_captured_in_step(self):
        plan = generate_plan([STEP_INPUT_BASIC], operator="tester")
        from netops.core.connection import ConnectionParams

        params = [ConnectionParams(host="192.0.2.1", username="admin", password="x")]
        bad_conn = _make_mock_conn()
        bad_conn.__enter__.side_effect = RuntimeError("connection refused")
        with patch("netops.change.plan.DeviceConnection", return_value=bad_conn):
            result = apply_plan(plan, connection_params=params, approved=True)
        assert result.steps[0].error == "connection refused"
        assert not result.steps[0].applied

    def test_step_without_commands_is_skipped(self):
        step_input = {"host": "192.0.2.1", "device_type": "cisco_ios", "device_role": "access"}
        plan = generate_plan([step_input])
        # No current/desired config → commands list stays empty
        plan.steps[0].commands = []
        with patch("netops.change.plan.DeviceConnection") as mock_dc:
            result = apply_plan(plan, connection_params=[], approved=True)
            mock_dc.assert_not_called()
        assert result.steps[0].applied is True

    def test_changelog_appended(self):
        plan = generate_plan([STEP_INPUT_BASIC], operator="tester")
        from netops.core.connection import ConnectionParams

        params = [ConnectionParams(host="192.0.2.1", username="admin", password="x")]
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "plan.jsonl"
            with patch("netops.change.plan.DeviceConnection", return_value=_make_mock_conn()):
                apply_plan(plan, connection_params=params, approved=True, changelog_path=log_path)
            assert log_path.exists()
            lines = [ln for ln in log_path.read_text().splitlines() if ln.strip()]
            assert len(lines) == 1
            data = json.loads(lines[0])
            assert data["plan_id"] == plan.plan_id


# ---------------------------------------------------------------------------
# export_plan / load_plan (round-trip)
# ---------------------------------------------------------------------------


class TestExportLoadRoundTrip:
    def _generate(self) -> ChangePlan:
        return generate_plan([STEP_INPUT_BASIC], operator="tester", description="CHG-001")

    def test_json_round_trip(self):
        plan = self._generate()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "plan.json"
            export_plan(plan, p, fmt="json")
            loaded = load_plan(p)

        assert loaded.plan_id == plan.plan_id
        assert loaded.operator == plan.operator
        assert loaded.description == plan.description
        assert loaded.risk_level == plan.risk_level
        assert len(loaded.steps) == len(plan.steps)
        assert loaded.steps[0].host == plan.steps[0].host
        assert loaded.steps[0].device_role == plan.steps[0].device_role

    def test_yaml_round_trip(self):
        plan = self._generate()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "plan.yaml"
            export_plan(plan, p, fmt="yaml")
            loaded = load_plan(p)

        assert loaded.plan_id == plan.plan_id
        assert loaded.risk_level == plan.risk_level

    def test_yaml_detected_by_extension(self):
        plan = self._generate()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "out.yml"
            export_plan(plan, p, fmt="json")  # fmt kwarg ignored; ext wins in load
            # But export itself uses fmt='json' here; re-save with yaml
            export_plan(plan, p, fmt="yaml")
            text = p.read_text()
        # YAML should NOT start with '{' (JSON-style)
        assert not text.strip().startswith("{")

    def test_invalid_format_raises(self):
        plan = self._generate()
        with tempfile.TemporaryDirectory() as tmp:
            with pytest.raises(ValueError, match="Unsupported export format"):
                export_plan(plan, Path(tmp) / "x.txt", fmt="xml")

    def test_load_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_plan(Path("/nonexistent/plan.json"))

    def test_json_file_is_valid_json(self):
        plan = self._generate()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "plan.json"
            export_plan(plan, p, fmt="json")
            data = json.loads(p.read_text())
        assert data["plan_id"] == plan.plan_id
        assert data["risk_level"] == plan.risk_level.value

    def test_step_device_role_survives_round_trip(self):
        step = {**STEP_INPUT_BASIC, "device_role": "core"}
        plan = generate_plan([step])
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "plan.json"
            export_plan(plan, p)
            loaded = load_plan(p)
        assert loaded.steps[0].device_role == DeviceRole.CORE


# ---------------------------------------------------------------------------
# _plan_to_dict / _dict_to_plan
# ---------------------------------------------------------------------------


class TestPlanSerialization:
    def test_risk_level_serialised_as_string(self):
        plan = generate_plan([STEP_INPUT_BASIC])
        d = _plan_to_dict(plan)
        assert isinstance(d["risk_level"], str)
        assert d["risk_level"] in {"low", "medium", "high"}

    def test_device_role_serialised_as_string(self):
        plan = generate_plan([STEP_INPUT_BASIC])
        d = _plan_to_dict(plan)
        assert isinstance(d["steps"][0]["device_role"], str)

    def test_round_trip_preserves_commands(self):
        step = {**STEP_INPUT_BASIC, "commands": ["cmd1", "cmd2"]}
        plan = generate_plan([step])
        d = _plan_to_dict(plan)
        restored = _dict_to_plan(d)
        assert restored.steps[0].commands == ["cmd1", "cmd2"]


# ---------------------------------------------------------------------------
# _append_plan_log
# ---------------------------------------------------------------------------


class TestAppendPlanLog:
    def test_creates_file_and_appends(self):
        plan = generate_plan([STEP_INPUT_BASIC], operator="tester")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sub" / "log.jsonl"
            _append_plan_log(plan, path)
            assert path.exists()
            lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
            assert len(lines) == 1
            data = json.loads(lines[0])
            assert data["plan_id"] == plan.plan_id

    def test_multiple_appends(self):
        plan = generate_plan([STEP_INPUT_BASIC], operator="tester")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log.jsonl"
            _append_plan_log(plan, path)
            _append_plan_log(plan, path)
            lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
            assert len(lines) == 2
