"""Tests for Palo Alto Networks PAN-OS CLI parsers."""

from __future__ import annotations

from netops.parsers.paloalto import (
    parse_ha_state,
    parse_interfaces,
    parse_routes,
    parse_security_policy,
    parse_security_policy_stats,
    parse_session_info,
    parse_system_info,
)

# ---------------------------------------------------------------------------
# Sample CLI output fixtures
# ---------------------------------------------------------------------------

SHOW_SYSTEM_INFO = """\
Hostname: pa-fw-01
IP address: 10.0.0.1
Model: PA-3220
Serial: 0123456789AB
PAN-OS Version: 10.2.3
App version: 8700-7709
Threat version: 8700-7709
URL filtering version: 20231201.20079
HA mode: Active-Passive
HA state: active
"""

SHOW_SYSTEM_INFO_NO_HA = """\
Hostname: pa-fw-standalone
IP address: 192.168.1.1
Model: PA-500
Serial: ABCDEF123456
PAN-OS Version: 9.1.10
App version: 8600-7468
Threat version: 8600-7468
URL filtering version: 20220101.12345
"""

SHOW_INTERFACE_ALL = """\
Name            State   IP (prefix)          VSys   Zone
ethernet1/1     up      10.0.1.1/24          vsys1  trust
ethernet1/2     up      203.0.113.1/30       vsys1  untrust
ethernet1/3     down    unassigned           vsys1
loopback.1      up      1.1.1.1/32           vsys1
"""

SHOW_INTERFACE_ALL_EMPTY = """\
Name            State   IP (prefix)          VSys   Zone
"""

SHOW_ROUTING_ROUTE = """\
flags: A:active, ?:loose, C:connect, H:host, S:static, R:rip, O:ospf, B:bgp

VIRTUAL ROUTER: default (id 1)
destination         nexthop         metric  flags  age   interface
0.0.0.0/0           10.0.0.1        10      A S    1d    ethernet1/2
10.0.1.0/24         0.0.0.0         0       A C    -     ethernet1/1
10.0.0.0/8          192.168.1.1     10      A B    2d    ethernet1/2
"""

SHOW_ROUTING_ROUTE_EMPTY = """\
flags: A:active, ?:loose, C:connect, H:host, S:static, R:rip, O:ospf, B:bgp

VIRTUAL ROUTER: default (id 1)
"""

SHOW_SESSION_INFO = """\
Number of sessions supported:      131072
Number of active sessions:         1234
Number of active TCP sessions:     1000
Number of active UDP sessions:     200
Number of active ICMP sessions:    34
Session utilization:               1%
"""

SHOW_SESSION_INFO_EMPTY = """\
Session table is empty.
"""

SHOW_SECURITY_POLICY = """\
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
Rule: block-all
  from any
  to any
  source [ any ]
  destination [ any ]
  application [ any ]
  service [ any ]
  action deny
"""

SHOW_SECURITY_POLICY_EMPTY = """\
"""

SHOW_SECURITY_POLICY_STATS = """\
Rule Name        Hit Count   Last Hit Date
web-access       1523        2024-03-24 06:00:00
block-malware    45          2024-03-23 12:00:00
allow-dns        0           never
unused-rule      0           never
"""

SHOW_HA_STATE = """\
Group 1:
  Mode: Active-Passive
  Local state: active
  Peer state: passive
  Peer IP: 10.0.0.2
  Preemptive: no
"""

SHOW_HA_STATE_NO_HA = """\
HA is not configured.
"""

SHOW_HA_STATE_PREEMPTIVE = """\
Group 1:
  Mode: Active-Passive
  Local state: active
  Peer state: passive
  Peer IP: 10.0.0.2
  Preemptive: yes
"""


# ===========================================================================
# parse_system_info
# ===========================================================================


class TestParseSystemInfo:
    def test_returns_dict(self):
        result = parse_system_info(SHOW_SYSTEM_INFO)
        assert isinstance(result, dict)

    def test_hostname_parsed(self):
        result = parse_system_info(SHOW_SYSTEM_INFO)
        assert result["hostname"] == "pa-fw-01"

    def test_ip_address_parsed(self):
        result = parse_system_info(SHOW_SYSTEM_INFO)
        assert result["ip_address"] == "10.0.0.1"

    def test_model_parsed(self):
        result = parse_system_info(SHOW_SYSTEM_INFO)
        assert result["model"] == "PA-3220"

    def test_serial_parsed(self):
        result = parse_system_info(SHOW_SYSTEM_INFO)
        assert result["serial"] == "0123456789AB"

    def test_panos_version_parsed(self):
        result = parse_system_info(SHOW_SYSTEM_INFO)
        assert result["panos_version"] == "10.2.3"

    def test_app_version_parsed(self):
        result = parse_system_info(SHOW_SYSTEM_INFO)
        assert result["app_version"] == "8700-7709"

    def test_threat_version_parsed(self):
        result = parse_system_info(SHOW_SYSTEM_INFO)
        assert result["threat_version"] == "8700-7709"

    def test_url_version_parsed(self):
        result = parse_system_info(SHOW_SYSTEM_INFO)
        assert result["url_version"] == "20231201.20079"

    def test_ha_mode_parsed(self):
        result = parse_system_info(SHOW_SYSTEM_INFO)
        assert result["ha_mode"] == "Active-Passive"

    def test_ha_state_parsed(self):
        result = parse_system_info(SHOW_SYSTEM_INFO)
        assert result["ha_state"] == "active"

    def test_ha_fields_none_when_absent(self):
        result = parse_system_info(SHOW_SYSTEM_INFO_NO_HA)
        assert result["ha_mode"] is None
        assert result["ha_state"] is None

    def test_required_keys_present(self):
        result = parse_system_info(SHOW_SYSTEM_INFO)
        for key in (
            "hostname", "ip_address", "model", "serial",
            "panos_version", "app_version", "threat_version",
            "url_version", "ha_mode", "ha_state",
        ):
            assert key in result

    def test_blank_string_returns_none_values(self):
        result = parse_system_info("")
        assert result["hostname"] is None
        assert result["model"] is None


# ===========================================================================
# parse_interfaces
# ===========================================================================


class TestParseInterfaces:
    def test_returns_list(self):
        result = parse_interfaces(SHOW_INTERFACE_ALL)
        assert isinstance(result, list)

    def test_correct_count(self):
        result = parse_interfaces(SHOW_INTERFACE_ALL)
        assert len(result) == 4

    def test_up_interface(self):
        iface = parse_interfaces(SHOW_INTERFACE_ALL)[0]
        assert iface["name"] == "ethernet1/1"
        assert iface["state"] == "up"
        assert iface["ip"] == "10.0.1.1/24"
        assert iface["vsys"] == "vsys1"
        assert iface["zone"] == "trust"
        assert iface["up"] is True

    def test_down_interface(self):
        iface = parse_interfaces(SHOW_INTERFACE_ALL)[2]
        assert iface["name"] == "ethernet1/3"
        assert iface["state"] == "down"
        assert iface["ip"] is None
        assert iface["up"] is False

    def test_loopback_interface(self):
        iface = parse_interfaces(SHOW_INTERFACE_ALL)[3]
        assert iface["name"] == "loopback.1"
        assert iface["ip"] == "1.1.1.1/32"
        assert iface["up"] is True

    def test_required_keys_present(self):
        for iface in parse_interfaces(SHOW_INTERFACE_ALL):
            for key in ("name", "state", "ip", "vsys", "zone", "up"):
                assert key in iface

    def test_empty_output_returns_empty_list(self):
        assert parse_interfaces(SHOW_INTERFACE_ALL_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_interfaces("") == []


# ===========================================================================
# parse_routes
# ===========================================================================


class TestParseRoutes:
    def test_returns_list(self):
        result = parse_routes(SHOW_ROUTING_ROUTE)
        assert isinstance(result, list)

    def test_correct_count(self):
        result = parse_routes(SHOW_ROUTING_ROUTE)
        assert len(result) == 3

    def test_static_default_route(self):
        route = parse_routes(SHOW_ROUTING_ROUTE)[0]
        assert route["destination"] == "0.0.0.0/0"
        assert route["nexthop"] == "10.0.0.1"
        assert route["metric"] == 10
        assert route["active"] is True
        assert route["type"] == "S"
        assert route["age"] == "1d"
        assert route["interface"] == "ethernet1/2"

    def test_connected_route_no_age(self):
        route = parse_routes(SHOW_ROUTING_ROUTE)[1]
        assert route["destination"] == "10.0.1.0/24"
        assert route["nexthop"] == "0.0.0.0"
        assert route["type"] == "C"
        assert route["age"] is None

    def test_bgp_route(self):
        route = parse_routes(SHOW_ROUTING_ROUTE)[2]
        assert route["type"] == "B"
        assert route["age"] == "2d"

    def test_required_keys_present(self):
        for route in parse_routes(SHOW_ROUTING_ROUTE):
            for key in ("destination", "nexthop", "metric", "flags", "active", "type",
                        "age", "interface"):
                assert key in route

    def test_empty_output_returns_empty_list(self):
        assert parse_routes(SHOW_ROUTING_ROUTE_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_routes("") == []


# ===========================================================================
# parse_session_info
# ===========================================================================


class TestParseSessionInfo:
    def test_returns_dict(self):
        result = parse_session_info(SHOW_SESSION_INFO)
        assert isinstance(result, dict)

    def test_max_sessions_parsed(self):
        result = parse_session_info(SHOW_SESSION_INFO)
        assert result["max_sessions"] == 131072

    def test_active_sessions_parsed(self):
        result = parse_session_info(SHOW_SESSION_INFO)
        assert result["active_sessions"] == 1234

    def test_active_tcp_parsed(self):
        result = parse_session_info(SHOW_SESSION_INFO)
        assert result["active_tcp"] == 1000

    def test_active_udp_parsed(self):
        result = parse_session_info(SHOW_SESSION_INFO)
        assert result["active_udp"] == 200

    def test_active_icmp_parsed(self):
        result = parse_session_info(SHOW_SESSION_INFO)
        assert result["active_icmp"] == 34

    def test_session_utilization_parsed(self):
        result = parse_session_info(SHOW_SESSION_INFO)
        assert result["session_utilization"] == 1.0

    def test_required_keys_present(self):
        result = parse_session_info(SHOW_SESSION_INFO)
        for key in (
            "max_sessions", "active_sessions", "active_tcp",
            "active_udp", "active_icmp", "session_utilization",
        ):
            assert key in result

    def test_empty_output_returns_none_values(self):
        result = parse_session_info(SHOW_SESSION_INFO_EMPTY)
        assert result["active_sessions"] is None
        assert result["max_sessions"] is None

    def test_blank_string_returns_none_values(self):
        result = parse_session_info("")
        assert result["active_sessions"] is None


# ===========================================================================
# parse_security_policy
# ===========================================================================


class TestParseSecurityPolicy:
    def test_returns_list(self):
        result = parse_security_policy(SHOW_SECURITY_POLICY)
        assert isinstance(result, list)

    def test_correct_rule_count(self):
        result = parse_security_policy(SHOW_SECURITY_POLICY)
        assert len(result) == 3

    def test_first_rule_name(self):
        rule = parse_security_policy(SHOW_SECURITY_POLICY)[0]
        assert rule["name"] == "web-access"

    def test_first_rule_from_zones(self):
        rule = parse_security_policy(SHOW_SECURITY_POLICY)[0]
        assert rule["from_zones"] == ["trust"]

    def test_first_rule_to_zones(self):
        rule = parse_security_policy(SHOW_SECURITY_POLICY)[0]
        assert rule["to_zones"] == ["untrust"]

    def test_first_rule_applications(self):
        rule = parse_security_policy(SHOW_SECURITY_POLICY)[0]
        assert "web-browsing" in rule["applications"]
        assert "ssl" in rule["applications"]

    def test_first_rule_action_allow(self):
        rule = parse_security_policy(SHOW_SECURITY_POLICY)[0]
        assert rule["action"] == "allow"

    def test_second_rule_action_deny(self):
        rule = parse_security_policy(SHOW_SECURITY_POLICY)[1]
        assert rule["action"] == "deny"

    def test_block_all_rule(self):
        rule = parse_security_policy(SHOW_SECURITY_POLICY)[2]
        assert rule["name"] == "block-all"
        assert rule["from_zones"] == ["any"]
        assert rule["sources"] == ["any"]
        assert rule["destinations"] == ["any"]
        assert rule["applications"] == ["any"]

    def test_required_keys_present(self):
        for rule in parse_security_policy(SHOW_SECURITY_POLICY):
            for key in (
                "name", "from_zones", "to_zones",
                "sources", "destinations", "applications",
                "services", "action",
            ):
                assert key in rule

    def test_empty_output_returns_empty_list(self):
        assert parse_security_policy(SHOW_SECURITY_POLICY_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_security_policy("") == []


# ===========================================================================
# parse_security_policy_stats
# ===========================================================================


class TestParseSecurityPolicyStats:
    def test_returns_list(self):
        result = parse_security_policy_stats(SHOW_SECURITY_POLICY_STATS)
        assert isinstance(result, list)

    def test_correct_count(self):
        result = parse_security_policy_stats(SHOW_SECURITY_POLICY_STATS)
        assert len(result) == 4

    def test_high_hit_count(self):
        stats = parse_security_policy_stats(SHOW_SECURITY_POLICY_STATS)
        web = next(s for s in stats if s["name"] == "web-access")
        assert web["hit_count"] == 1523
        assert web["last_hit"] == "2024-03-24 06:00:00"

    def test_zero_hit_count(self):
        stats = parse_security_policy_stats(SHOW_SECURITY_POLICY_STATS)
        unused = next(s for s in stats if s["name"] == "unused-rule")
        assert unused["hit_count"] == 0
        assert unused["last_hit"] is None

    def test_never_becomes_none(self):
        stats = parse_security_policy_stats(SHOW_SECURITY_POLICY_STATS)
        dns = next(s for s in stats if s["name"] == "allow-dns")
        assert dns["last_hit"] is None

    def test_required_keys_present(self):
        for stat in parse_security_policy_stats(SHOW_SECURITY_POLICY_STATS):
            for key in ("name", "hit_count", "last_hit"):
                assert key in stat

    def test_empty_output_returns_empty_list(self):
        assert parse_security_policy_stats("") == []


# ===========================================================================
# parse_ha_state
# ===========================================================================


class TestParseHaState:
    def test_returns_dict(self):
        result = parse_ha_state(SHOW_HA_STATE)
        assert isinstance(result, dict)

    def test_ha_enabled_when_group_present(self):
        result = parse_ha_state(SHOW_HA_STATE)
        assert result["enabled"] is True

    def test_mode_parsed(self):
        result = parse_ha_state(SHOW_HA_STATE)
        assert result["mode"] == "Active-Passive"

    def test_local_state_parsed(self):
        result = parse_ha_state(SHOW_HA_STATE)
        assert result["local_state"] == "active"

    def test_peer_state_parsed(self):
        result = parse_ha_state(SHOW_HA_STATE)
        assert result["peer_state"] == "passive"

    def test_peer_ip_parsed(self):
        result = parse_ha_state(SHOW_HA_STATE)
        assert result["peer_ip"] == "10.0.0.2"

    def test_preemptive_false(self):
        result = parse_ha_state(SHOW_HA_STATE)
        assert result["preemptive"] is False

    def test_preemptive_yes(self):
        result = parse_ha_state(SHOW_HA_STATE_PREEMPTIVE)
        assert result["preemptive"] is True

    def test_ha_disabled_when_no_group(self):
        result = parse_ha_state(SHOW_HA_STATE_NO_HA)
        assert result["enabled"] is False
        assert result["mode"] is None
        assert result["local_state"] is None

    def test_required_keys_present(self):
        result = parse_ha_state(SHOW_HA_STATE)
        for key in ("enabled", "mode", "local_state", "peer_state", "peer_ip", "preemptive"):
            assert key in result

    def test_blank_string_returns_defaults(self):
        result = parse_ha_state("")
        assert result["enabled"] is False
        assert result["mode"] is None
        assert result["preemptive"] is False
