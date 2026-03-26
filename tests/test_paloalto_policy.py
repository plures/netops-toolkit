"""Tests for Palo Alto Networks PAN-OS security policy audit functions."""

from __future__ import annotations

import pytest

from netops.check.paloalto import (
    DEFAULT_SESSION_THRESHOLD,
    check_ha,
    check_sessions,
    check_shadowed_rules,
    check_threat_status,
    check_unused_rules,
    run_health_check,
    run_policy_audit,
)
from netops.core.connection import ConnectionParams
from netops.parsers.paloalto import (
    parse_security_policy,
    parse_security_policy_stats,
)

# ---------------------------------------------------------------------------
# Sample policy and stats fixtures
# ---------------------------------------------------------------------------

POLICY_OUTPUT = """\
Rule: web-access
  from trust
  to untrust
  source [ any ]
  destination [ any ]
  application [ web-browsing ssl ]
  service [ application-default ]
  action allow
Rule: block-malware
  from trust
  to untrust
  source [ 10.0.0.0/8 ]
  destination [ any ]
  application [ any ]
  service [ any ]
  action deny
Rule: allow-dns
  from trust
  to untrust
  source [ any ]
  destination [ any ]
  application [ dns ]
  service [ application-default ]
  action allow
Rule: unused-rule
  from dmz
  to untrust
  source [ any ]
  destination [ any ]
  application [ ftp ]
  service [ any ]
  action allow
Rule: block-all
  from any
  to any
  source [ any ]
  destination [ any ]
  application [ any ]
  service [ any ]
  action deny
"""

STATS_OUTPUT = """\
Rule Name        Hit Count   Last Hit Date
web-access       1523        2024-03-24 06:00:00
block-malware    45          2024-03-23 12:00:00
allow-dns        200         2024-03-24 05:00:00
unused-rule      0           never
block-all        892         2024-03-24 05:58:00
"""

# A policy where an earlier "any/any/any deny" shadows a later specific deny
SHADOWED_POLICY_OUTPUT = """\
Rule: permit-web
  from trust
  to untrust
  source [ any ]
  destination [ any ]
  application [ web-browsing ]
  service [ application-default ]
  action allow
Rule: catch-all-deny
  from any
  to any
  source [ any ]
  destination [ any ]
  application [ any ]
  service [ any ]
  action deny
Rule: specific-deny
  from trust
  to untrust
  source [ 192.168.1.0/24 ]
  destination [ any ]
  application [ ftp ]
  service [ any ]
  action deny
"""

EMPTY_STATS_OUTPUT = """\
"""


# ===========================================================================
# check_unused_rules
# ===========================================================================


class TestCheckUnusedRules:
    def test_returns_list(self):
        policy = parse_security_policy(POLICY_OUTPUT)
        stats = parse_security_policy_stats(STATS_OUTPUT)
        result = check_unused_rules(policy, stats)
        assert isinstance(result, list)

    def test_identifies_unused_rules(self):
        policy = parse_security_policy(POLICY_OUTPUT)
        stats = parse_security_policy_stats(STATS_OUTPUT)
        unused = check_unused_rules(policy, stats)
        unused_names = [r["name"] for r in unused]
        assert "unused-rule" in unused_names
        # block-all has hits in the fixture (realistic for a catch-all deny)
        assert "block-all" not in unused_names

    def test_does_not_flag_active_rules(self):
        policy = parse_security_policy(POLICY_OUTPUT)
        stats = parse_security_policy_stats(STATS_OUTPUT)
        unused = check_unused_rules(policy, stats)
        unused_names = [r["name"] for r in unused]
        assert "web-access" not in unused_names
        assert "block-malware" not in unused_names
        assert "allow-dns" not in unused_names

    def test_hit_count_key_present(self):
        policy = parse_security_policy(POLICY_OUTPUT)
        stats = parse_security_policy_stats(STATS_OUTPUT)
        unused = check_unused_rules(policy, stats)
        for rule in unused:
            assert "hit_count" in rule
            assert rule["hit_count"] == 0

    def test_all_unused_when_empty_stats(self):
        policy = parse_security_policy(POLICY_OUTPUT)
        stats = parse_security_policy_stats(EMPTY_STATS_OUTPUT)
        unused = check_unused_rules(policy, stats)
        assert len(unused) == len(policy)

    def test_empty_policy_returns_empty_list(self):
        result = check_unused_rules([], [])
        assert result == []

    def test_original_rule_fields_preserved(self):
        policy = parse_security_policy(POLICY_OUTPUT)
        stats = parse_security_policy_stats(STATS_OUTPUT)
        unused = check_unused_rules(policy, stats)
        unused_rule = next(r for r in unused if r["name"] == "unused-rule")
        assert unused_rule["action"] == "allow"
        assert unused_rule["from_zones"] == ["dmz"]


# ===========================================================================
# check_shadowed_rules
# ===========================================================================


class TestCheckShadowedRules:
    def test_returns_list(self):
        policy = parse_security_policy(SHADOWED_POLICY_OUTPUT)
        result = check_shadowed_rules(policy)
        assert isinstance(result, list)

    def test_detects_shadowed_rule(self):
        policy = parse_security_policy(SHADOWED_POLICY_OUTPUT)
        shadowed = check_shadowed_rules(policy)
        shadowed_names = [r["name"] for r in shadowed]
        assert "specific-deny" in shadowed_names

    def test_shadowed_by_key_present(self):
        policy = parse_security_policy(SHADOWED_POLICY_OUTPUT)
        shadowed = check_shadowed_rules(policy)
        rule = next(r for r in shadowed if r["name"] == "specific-deny")
        assert rule["shadowed_by"] == "catch-all-deny"

    def test_first_rule_never_shadowed(self):
        policy = parse_security_policy(SHADOWED_POLICY_OUTPUT)
        shadowed = check_shadowed_rules(policy)
        shadowed_names = [r["name"] for r in shadowed]
        assert "permit-web" not in shadowed_names
        assert "catch-all-deny" not in shadowed_names

    def test_no_shadows_in_clean_policy(self):
        policy = parse_security_policy(POLICY_OUTPUT)
        shadowed = check_shadowed_rules(policy)
        # block-all is the last rule; preceding rules don't cover all its traffic
        # because they have specific from/to zones
        shadowed_names = [r["name"] for r in shadowed]
        assert "web-access" not in shadowed_names
        assert "block-malware" not in shadowed_names
        assert "allow-dns" not in shadowed_names

    def test_empty_policy_returns_empty_list(self):
        assert check_shadowed_rules([]) == []

    def test_single_rule_not_shadowed(self):
        policy = parse_security_policy(POLICY_OUTPUT)[:1]
        assert check_shadowed_rules(policy) == []

    def test_original_rule_fields_preserved(self):
        policy = parse_security_policy(SHADOWED_POLICY_OUTPUT)
        shadowed = check_shadowed_rules(policy)
        rule = next(r for r in shadowed if r["name"] == "specific-deny")
        assert rule["action"] == "deny"
        assert rule["from_zones"] == ["trust"]


# ===========================================================================
# PAN-OS health parser integration (parsers/health.py)
# ===========================================================================

SHOW_SYSTEM_RESOURCES = """\
top - 10:00:00 up 30 days,  2:30,  1 user,  load average: 0.25, 0.30, 0.28
Tasks: 150 total,   1 running, 149 sleeping,   0 stopped,   0 zombie
%Cpu(s):  5.0 us,  1.5 sy,  0.0 ni, 92.5 id,  0.5 wa,  0.0 hi,  0.5 si,  0.0 st
MiB Mem : 16384.0 total,  8192.0 free,  6144.0 used,  2048.0 buff/cache
MiB Swap:  2048.0 total,  2048.0 free,     0.0 used. 10240.0 avail Mem
"""

SHOW_SYSTEM_RESOURCES_OLD = """\
top - 09:00:00 up 10 days,  1:00,  1 user
%Cpu(s): 10.0 us,  2.0 sy,  0.0 ni, 87.0 id,  1.0 wa,  0.0 hi,  0.0 si
Mem:   8388608 total,   5242880 used,   3145728 free,    524288 buffers
"""


class TestPaloAltoHealthParsers:
    def test_parse_cpu_paloalto_utilization(self):
        from netops.parsers.health import parse_cpu_paloalto

        result = parse_cpu_paloalto(SHOW_SYSTEM_RESOURCES)
        assert isinstance(result, dict)
        assert result["user"] == 5.0
        assert result["system"] == 1.5
        assert result["idle"] == 92.5
        assert result["utilization"] == pytest.approx(7.5, abs=0.01)

    def test_parse_cpu_paloalto_empty(self):
        from netops.parsers.health import parse_cpu_paloalto

        assert parse_cpu_paloalto("") == {}

    def test_parse_memory_paloalto_mib(self):
        from netops.parsers.health import parse_memory_paloalto

        result = parse_memory_paloalto(SHOW_SYSTEM_RESOURCES)
        assert result["total"] > 0
        assert result["used"] > 0
        assert result["free"] > 0
        assert 0.0 <= result["utilization"] <= 100.0

    def test_parse_memory_paloalto_old_format(self):
        from netops.parsers.health import parse_memory_paloalto

        result = parse_memory_paloalto(SHOW_SYSTEM_RESOURCES_OLD)
        assert result["total"] > 0
        assert result["used"] > 0

    def test_parse_memory_paloalto_empty(self):
        from netops.parsers.health import parse_memory_paloalto

        assert parse_memory_paloalto("") == {}

    def test_parse_memory_utilization_calculation(self):
        from netops.parsers.health import parse_memory_paloalto

        # 16384 MiB total, 8192 MiB free, 6144 MiB used
        result = parse_memory_paloalto(SHOW_SYSTEM_RESOURCES)
        expected_util = round(6144.0 / 16384.0 * 100, 2)
        assert result["utilization"] == pytest.approx(expected_util, abs=0.01)


# ---------------------------------------------------------------------------
# Additional fixtures for health-check tests
# ---------------------------------------------------------------------------

HA_OUTPUT = """\
Group 1:
  Mode: Active-Passive
  Local state: active
  Peer state: passive
  Peer IP: 10.0.0.2
  Preemptive: no
"""

HA_OUTPUT_SUSPENDED = """\
Group 1:
  Mode: Active-Passive
  Local state: suspended
  Peer state: active
  Peer IP: 10.0.0.3
  Preemptive: no
"""

HA_NOT_CONFIGURED = """\
HA is not configured.
"""

SESSION_INFO_OUTPUT = """\
Number of sessions supported:      262143
Number of active sessions:         1234
Number of active TCP sessions:     1000
Number of active UDP sessions:     200
Number of active ICMP sessions:    34
Session utilization:               1%
"""

SESSION_INFO_HIGH = """\
Number of sessions supported:      262143
Number of active sessions:         210000
Number of active TCP sessions:     200000
Number of active UDP sessions:     9000
Number of active ICMP sessions:    1000
Session utilization:               85%
"""

SYSTEM_INFO_OUTPUT = """\
Hostname: pa-firewall
IP address: 192.0.2.10
Model: PA-3220
Serial: 0123456789AB
PAN-OS Version: 10.2.3
App version: 8700-7709
Threat version: 8716-7873
URL filtering version: 20240324.20009
HA mode: Active-Passive
HA state: active
"""


class _MockConn:
    """Minimal stand-in for a live device connection."""

    def __init__(self, responses: dict[str, str]):
        self._responses = responses

    def send(self, command: str, **_kwargs) -> str:
        for key, value in self._responses.items():
            if key in command:
                return value
        return ""


# ===========================================================================
# check_ha
# ===========================================================================


class TestCheckHa:
    def test_returns_dict(self):
        conn = _MockConn({"show high-availability state": HA_OUTPUT})
        result = check_ha(conn)
        assert isinstance(result, dict)

    def test_enabled_when_ha_configured(self):
        conn = _MockConn({"show high-availability state": HA_OUTPUT})
        result = check_ha(conn)
        assert result["enabled"] is True

    def test_mode_parsed(self):
        conn = _MockConn({"show high-availability state": HA_OUTPUT})
        result = check_ha(conn)
        assert result["mode"] is not None

    def test_local_state_active(self):
        conn = _MockConn({"show high-availability state": HA_OUTPUT})
        result = check_ha(conn)
        assert result["local_state"] is not None
        assert result["local_state"].lower() == "active"

    def test_peer_state_passive(self):
        conn = _MockConn({"show high-availability state": HA_OUTPUT})
        result = check_ha(conn)
        assert result["peer_state"] is not None
        assert result["peer_state"].lower() == "passive"

    def test_peer_ip_present(self):
        conn = _MockConn({"show high-availability state": HA_OUTPUT})
        result = check_ha(conn)
        assert result["peer_ip"] == "10.0.0.2"

    def test_no_alert_when_stable(self):
        conn = _MockConn({"show high-availability state": HA_OUTPUT})
        result = check_ha(conn)
        assert result["alert"] is False

    def test_alert_when_suspended(self):
        conn = _MockConn({"show high-availability state": HA_OUTPUT_SUSPENDED})
        result = check_ha(conn)
        assert result["alert"] is True

    def test_not_configured_no_alert(self):
        conn = _MockConn({"show high-availability state": HA_NOT_CONFIGURED})
        result = check_ha(conn)
        assert result["enabled"] is False
        assert result["alert"] is False

    def test_error_key_present_on_success(self):
        conn = _MockConn({"show high-availability state": HA_OUTPUT})
        result = check_ha(conn)
        assert result["error"] is None

    def test_exception_returns_error_dict(self):
        class _BrokenConn:
            def send(self, *_a, **_kw):
                raise RuntimeError("device unreachable")

        result = check_ha(_BrokenConn())
        assert result["error"] is not None
        assert "unreachable" in result["error"]

    def test_exception_alert_false(self):
        class _BrokenConn:
            def send(self, *_a, **_kw):
                raise RuntimeError("fail")

        result = check_ha(_BrokenConn())
        assert result["alert"] is False


# ===========================================================================
# check_sessions
# ===========================================================================


class TestCheckSessions:
    def test_returns_dict(self):
        conn = _MockConn({"show session info": SESSION_INFO_OUTPUT})
        result = check_sessions(conn, threshold=80.0)
        assert isinstance(result, dict)

    def test_max_sessions_parsed(self):
        conn = _MockConn({"show session info": SESSION_INFO_OUTPUT})
        result = check_sessions(conn, threshold=80.0)
        assert result["max_sessions"] == 262143

    def test_active_sessions_parsed(self):
        conn = _MockConn({"show session info": SESSION_INFO_OUTPUT})
        result = check_sessions(conn, threshold=80.0)
        assert result["active_sessions"] == 1234

    def test_utilization_parsed(self):
        conn = _MockConn({"show session info": SESSION_INFO_OUTPUT})
        result = check_sessions(conn, threshold=80.0)
        assert result["session_utilization"] == pytest.approx(1.0, abs=0.5)

    def test_threshold_stored(self):
        conn = _MockConn({"show session info": SESSION_INFO_OUTPUT})
        result = check_sessions(conn, threshold=75.0)
        assert result["threshold"] == 75.0

    def test_no_alert_below_threshold(self):
        conn = _MockConn({"show session info": SESSION_INFO_OUTPUT})
        result = check_sessions(conn, threshold=80.0)
        assert result["alert"] is False

    def test_alert_above_threshold(self):
        conn = _MockConn({"show session info": SESSION_INFO_HIGH})
        result = check_sessions(conn, threshold=80.0)
        assert result["alert"] is True

    def test_error_key_none_on_success(self):
        conn = _MockConn({"show session info": SESSION_INFO_OUTPUT})
        result = check_sessions(conn, threshold=80.0)
        assert result["error"] is None

    def test_default_threshold_constant(self):
        assert DEFAULT_SESSION_THRESHOLD == 80.0

    def test_exception_returns_error(self):
        class _BrokenConn:
            def send(self, *_a, **_kw):
                raise OSError("timeout")

        result = check_sessions(_BrokenConn(), threshold=80.0)
        assert result["error"] is not None
        assert "timeout" in result["error"]

    def test_exception_alert_false(self):
        class _BrokenConn:
            def send(self, *_a, **_kw):
                raise OSError("timeout")

        result = check_sessions(_BrokenConn(), threshold=80.0)
        assert result["alert"] is False


# ===========================================================================
# check_threat_status
# ===========================================================================


class TestCheckThreatStatus:
    def test_returns_dict(self):
        conn = _MockConn({"show system info": SYSTEM_INFO_OUTPUT})
        result = check_threat_status(conn)
        assert isinstance(result, dict)

    def test_threat_version_parsed(self):
        conn = _MockConn({"show system info": SYSTEM_INFO_OUTPUT})
        result = check_threat_status(conn)
        assert result["threat_version"] is not None

    def test_url_version_parsed(self):
        conn = _MockConn({"show system info": SYSTEM_INFO_OUTPUT})
        result = check_threat_status(conn)
        assert result["url_version"] is not None

    def test_ha_mode_parsed(self):
        conn = _MockConn({"show system info": SYSTEM_INFO_OUTPUT})
        result = check_threat_status(conn)
        assert result["ha_mode"] is not None

    def test_alert_always_false(self):
        conn = _MockConn({"show system info": SYSTEM_INFO_OUTPUT})
        result = check_threat_status(conn)
        assert result["alert"] is False

    def test_error_key_none_on_success(self):
        conn = _MockConn({"show system info": SYSTEM_INFO_OUTPUT})
        result = check_threat_status(conn)
        assert result["error"] is None

    def test_exception_returns_error(self):
        class _BrokenConn:
            def send(self, *_a, **_kw):
                raise RuntimeError("no route")

        result = check_threat_status(_BrokenConn())
        assert result["error"] is not None
        assert "no route" in result["error"]

    def test_exception_alert_false(self):
        class _BrokenConn:
            def send(self, *_a, **_kw):
                raise RuntimeError("fail")

        result = check_threat_status(_BrokenConn())
        assert result["alert"] is False


# ===========================================================================
# run_health_check
# ===========================================================================


class _FakeConn:
    """Context-manager wrapper around _MockConn for monkeypatching DeviceConnection."""

    def __init__(self, responses: dict[str, str]):
        self._responses = responses

    def __enter__(self):
        return _MockConn(self._responses)

    def __exit__(self, *_):
        pass


ALL_RESPONSES = {
    "show high-availability state": HA_OUTPUT,
    "show session info": SESSION_INFO_OUTPUT,
    "show system info": SYSTEM_INFO_OUTPUT,
}


class TestRunHealthCheck:
    def _make_params(self) -> ConnectionParams:
        return ConnectionParams(host="192.0.2.1", username="admin", device_type="paloalto_panos")

    def test_success_flag_set(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.paloalto.DeviceConnection",
            lambda _p: _FakeConn(ALL_RESPONSES),
        )
        result = run_health_check(self._make_params())
        assert result["success"] is True

    def test_host_in_result(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.paloalto.DeviceConnection",
            lambda _p: _FakeConn(ALL_RESPONSES),
        )
        result = run_health_check(self._make_params())
        assert result["host"] == "192.0.2.1"

    def test_timestamp_present(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.paloalto.DeviceConnection",
            lambda _p: _FakeConn(ALL_RESPONSES),
        )
        result = run_health_check(self._make_params())
        assert "timestamp" in result
        assert result["timestamp"]

    def test_checks_keys_present(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.paloalto.DeviceConnection",
            lambda _p: _FakeConn(ALL_RESPONSES),
        )
        result = run_health_check(self._make_params())
        for key in ("ha", "sessions", "threat_status"):
            assert key in result["checks"]

    def test_no_overall_alert_normal_conditions(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.paloalto.DeviceConnection",
            lambda _p: _FakeConn(ALL_RESPONSES),
        )
        result = run_health_check(self._make_params())
        assert result["overall_alert"] is False

    def test_overall_alert_when_sessions_critical(self, monkeypatch):
        responses = {**ALL_RESPONSES, "show session info": SESSION_INFO_HIGH}
        monkeypatch.setattr(
            "netops.check.paloalto.DeviceConnection",
            lambda _p: _FakeConn(responses),
        )
        result = run_health_check(self._make_params(), session_threshold=80.0)
        assert result["overall_alert"] is True

    def test_custom_session_threshold_passed(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.paloalto.DeviceConnection",
            lambda _p: _FakeConn(ALL_RESPONSES),
        )
        result = run_health_check(self._make_params(), session_threshold=0.5)
        # 1% utilization >= 0.5% → alert should fire
        assert result["checks"]["sessions"]["alert"] is True

    def test_connection_error_sets_success_false(self, monkeypatch):
        def _raise(_p):
            raise ConnectionError("refused")

        monkeypatch.setattr("netops.check.paloalto.DeviceConnection", _raise)
        result = run_health_check(self._make_params())
        assert result["success"] is False
        assert "refused" in result["error"]

    def test_connection_error_no_checks(self, monkeypatch):
        def _raise(_p):
            raise ConnectionError("refused")

        monkeypatch.setattr("netops.check.paloalto.DeviceConnection", _raise)
        result = run_health_check(self._make_params())
        assert result["checks"] == {}


# ===========================================================================
# run_policy_audit (conn-based)
# ===========================================================================


POLICY_CONN_RESPONSES = {
    "show running security-policy": POLICY_OUTPUT,
    "show security policy statistics": STATS_OUTPUT,
}


class TestRunPolicyAudit:
    def test_returns_dict(self):
        conn = _MockConn(POLICY_CONN_RESPONSES)
        result = run_policy_audit(conn)
        assert isinstance(result, dict)

    def test_policy_populated(self):
        conn = _MockConn(POLICY_CONN_RESPONSES)
        result = run_policy_audit(conn)
        assert len(result["policy"]) > 0

    def test_rule_count_matches_policy(self):
        conn = _MockConn(POLICY_CONN_RESPONSES)
        result = run_policy_audit(conn)
        assert result["rule_count"] == len(result["policy"])

    def test_unused_rules_identified(self):
        conn = _MockConn(POLICY_CONN_RESPONSES)
        result = run_policy_audit(conn)
        unused_names = [r["name"] for r in result["unused_rules"]]
        assert "unused-rule" in unused_names

    def test_alert_set_when_unused_rules(self):
        conn = _MockConn(POLICY_CONN_RESPONSES)
        result = run_policy_audit(conn)
        assert result["alert"] is True

    def test_error_none_on_success(self):
        conn = _MockConn(POLICY_CONN_RESPONSES)
        result = run_policy_audit(conn)
        assert result["error"] is None

    def test_exception_sets_error(self):
        class _BrokenConn:
            def send(self, *_a, **_kw):
                raise RuntimeError("audit failed")

        result = run_policy_audit(_BrokenConn())
        assert result["error"] is not None
        assert "audit failed" in result["error"]
