"""Tests for Palo Alto Networks PAN-OS security policy audit functions."""

from __future__ import annotations

import pytest

from netops.check.paloalto import check_shadowed_rules, check_unused_rules
from netops.parsers.paloalto import parse_security_policy, parse_security_policy_stats

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
