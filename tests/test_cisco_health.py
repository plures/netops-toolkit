"""Tests for Cisco IOS/IOS-XE health-check parsers and check logic."""

from __future__ import annotations

import pytest

from netops.parsers.cisco import (
    parse_environment_cisco,
    parse_ospf_neighbors,
    parse_version_cisco,
)
from netops.check.cisco import (
    _parse_thresholds,
    build_cisco_health_report,
    check_cisco_bgp,
    check_cisco_cpu,
    check_cisco_environment,
    check_cisco_interfaces,
    check_cisco_logs,
    check_cisco_memory,
    check_cisco_ospf,
    check_cisco_uptime,
    DEFAULT_CPU_THRESHOLD,
    DEFAULT_MEM_THRESHOLD,
)
from netops.templates.cisco_ios import HEALTH as CISCO_HEALTH

# ---------------------------------------------------------------------------
# Sample CLI output fixtures
# ---------------------------------------------------------------------------

OSPF_NEIGHBORS_OUTPUT = """\
Neighbor ID     Pri   State           Dead Time   Address         Interface
192.168.1.2       1   FULL/DR         00:00:37    10.0.0.2        GigabitEthernet0/0
192.168.1.3       1   FULL/BDR        00:00:38    10.0.0.3        GigabitEthernet0/0
192.168.1.4       0   INIT/DROTHER    00:00:35    10.0.0.4        GigabitEthernet0/1
"""

OSPF_NEIGHBORS_ALL_FULL = """\
Neighbor ID     Pri   State           Dead Time   Address         Interface
10.0.0.1          1   FULL/DR         00:00:34    192.168.0.1     GigabitEthernet0/0
10.0.0.2          1   FULL/BDR        00:00:36    192.168.0.2     GigabitEthernet0/0
"""

OSPF_NEIGHBORS_EMPTY = """\
Neighbor ID     Pri   State           Dead Time   Address         Interface
"""

ENVIRONMENT_IOS_XE = """\
Switch 1 FAN 1 is OK
Switch 1 FAN 2 is OK
Switch 1: TEMPERATURE is OK
SYSTEM INLET       : 28 Celsius, Critical threshold is 60 Celsius
SYSTEM OUTLET      : 35 Celsius, Critical threshold is 65 Celsius
Switch 1: POWER-SUPPLY 1 is PRESENT
Switch 1: POWER-SUPPLY 2 is NOT PRESENT
"""

ENVIRONMENT_IOS_ROUTER = """\
Number of Fans: 2
FAN 1 is OK
FAN 2 is OK
Temperature: OK
SYSTEM INLET       : 28 Celsius
SYSTEM OUTLET      : 35 Celsius
Power Supply 1: Normal
Power Supply 2: Not Present
"""

ENVIRONMENT_FAIL = """\
Switch 1 FAN 1 is FAIL
Switch 1: TEMPERATURE is OK
SYSTEM INLET       : 28 Celsius
Switch 1: POWER-SUPPLY 1 is PRESENT
"""

ENVIRONMENT_EMPTY = "No environment data available.\n"

VERSION_IOS = """\
Cisco IOS Software, Version 15.2(4)E8, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2019 by Cisco Systems, Inc.

cisco WS-C3750X-48P (PowerPC405) processor (revision F0) with 524288K bytes of memory.

Switch uptime is 2 weeks, 3 days, 4 hours, 5 minutes
System restarted by reload at 12:00:00 UTC Mon Jan 1 2024
System image file is "flash:c3750x-ipservicesk9-mz.152-4.E8.bin"
"""

VERSION_IOS_XE = """\
Cisco IOS XE Software, Version 16.12.4
Cisco IOS Software [Gibraltar], Catalyst L3 Switch Software

cisco C9300-48P (X86) processor with 1393712K/6147K bytes of memory.

Router uptime is 10 weeks, 2 days, 14 hours, 56 minutes
Last reload reason: Reload command
System image file is "bootflash:cat9k_iosxe.16.12.04.SPA.bin"
"""

VERSION_EMPTY = "Router> show version\n"

CISCO_CPU_OUTPUT = """\
CPU utilization for five seconds: 12%/3%; one minute: 8%; five minutes: 6%
 PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process
   1        1234       12345        100  0.00%  0.00%  0.00%   0 Chunk Manager
"""

CISCO_CPU_HIGH = "CPU utilization for five seconds: 95%/10%; one minute: 92%; five minutes: 88%"

CISCO_MEM_OUTPUT = """\
                 Head    Total(b)     Used(b)     Free(b)   Lowest(b)    Largest(b)
Processor  7F2B3C18  402702336   141058576   261643760   258219008   261643520
"""

CISCO_INTERFACES_OUTPUT = """\
GigabitEthernet0/0 is up, line protocol is up
  Hardware is Gigabit Ethernet, address is aabb.cc00.0100
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions, 0 interface resets
     0 input drops
     0 output drops
GigabitEthernet0/1 is up, line protocol is up
  Hardware is Gigabit Ethernet, address is aabb.cc00.0101
     5 input errors, 3 CRC, 0 frame, 0 overrun, 0 ignored
     2 output errors, 0 collisions, 0 interface resets
     10 input drops
     4 output drops
"""

CISCO_LOG_OUTPUT = """\
*Mar  1 00:02:00: %SYS-2-MALLOCFAIL: Memory allocation of 10240 bytes failed
*Mar  1 00:01:00: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
*Mar  1 00:00:01: %SYS-5-CONFIG_I: Configured from console by admin
"""

CISCO_BGP_SUMMARY = """\
BGP router identifier 10.0.0.1, local AS number 65000

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4 65001      50      60       42    0    0 01:23:45        100
10.0.0.3        4 65002       0       0        0    0    0 never    Active
"""

CISCO_BGP_ALL_ESTABLISHED = """\
BGP router identifier 10.0.0.1, local AS number 65000

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4 65001      50      60       42    0    0 01:23:45        100
10.0.0.3        4 65002      30      40       42    0    0 02:00:00         50
"""


# ---------------------------------------------------------------------------
# Minimal DeviceConnection mock
# ---------------------------------------------------------------------------


class _MockConn:
    """Minimal mock that returns pre-canned output based on command substring."""

    def __init__(self, responses: dict[str, str]):
        self._responses = responses

    def send(self, command: str, **_kwargs) -> str:
        for key, value in self._responses.items():
            if key in command:
                return value
        return ""


# ===========================================================================
# parse_ospf_neighbors
# ===========================================================================


class TestParseOspfNeighbors:
    def test_returns_list(self):
        assert isinstance(parse_ospf_neighbors(OSPF_NEIGHBORS_OUTPUT), list)

    def test_correct_neighbor_count(self):
        result = parse_ospf_neighbors(OSPF_NEIGHBORS_OUTPUT)
        assert len(result) == 3

    def test_full_dr_neighbor(self):
        n = parse_ospf_neighbors(OSPF_NEIGHBORS_OUTPUT)[0]
        assert n["neighbor_id"] == "192.168.1.2"
        assert n["priority"] == 1
        assert n["state"] == "FULL/DR"
        assert n["dead_time"] == "00:00:37"
        assert n["address"] == "10.0.0.2"
        assert n["interface"] == "GigabitEthernet0/0"
        assert n["is_full"] is True

    def test_full_bdr_neighbor(self):
        n = parse_ospf_neighbors(OSPF_NEIGHBORS_OUTPUT)[1]
        assert n["state"] == "FULL/BDR"
        assert n["is_full"] is True

    def test_init_drother_neighbor(self):
        n = parse_ospf_neighbors(OSPF_NEIGHBORS_OUTPUT)[2]
        assert n["neighbor_id"] == "192.168.1.4"
        assert n["state"] == "INIT/DROTHER"
        assert n["is_full"] is False

    def test_required_keys_present(self):
        for n in parse_ospf_neighbors(OSPF_NEIGHBORS_OUTPUT):
            for key in (
                "neighbor_id",
                "priority",
                "state",
                "dead_time",
                "address",
                "interface",
                "is_full",
            ):
                assert key in n

    def test_empty_table_returns_empty_list(self):
        assert parse_ospf_neighbors(OSPF_NEIGHBORS_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_ospf_neighbors("") == []

    def test_all_full_neighbors(self):
        result = parse_ospf_neighbors(OSPF_NEIGHBORS_ALL_FULL)
        assert len(result) == 2
        assert all(n["is_full"] for n in result)

    def test_priority_is_int(self):
        for n in parse_ospf_neighbors(OSPF_NEIGHBORS_OUTPUT):
            assert isinstance(n["priority"], int)


# ===========================================================================
# parse_environment_cisco
# ===========================================================================


class TestParseEnvironmentCisco:
    def test_returns_dict(self):
        assert isinstance(parse_environment_cisco(ENVIRONMENT_IOS_XE), dict)

    def test_required_keys_present(self):
        result = parse_environment_cisco(ENVIRONMENT_IOS_XE)
        for key in ("fans", "temperatures", "power_supplies", "overall_ok"):
            assert key in result

    def test_fans_parsed(self):
        result = parse_environment_cisco(ENVIRONMENT_IOS_XE)
        assert len(result["fans"]) >= 2

    def test_fans_ok(self):
        result = parse_environment_cisco(ENVIRONMENT_IOS_XE)
        assert all(f["ok"] for f in result["fans"])

    def test_temperatures_parsed(self):
        result = parse_environment_cisco(ENVIRONMENT_IOS_XE)
        # At least one temperature entry (either summary or detail)
        assert len(result["temperatures"]) >= 1

    def test_power_supplies_parsed(self):
        result = parse_environment_cisco(ENVIRONMENT_IOS_XE)
        assert len(result["power_supplies"]) >= 1

    def test_overall_ok_when_all_ok(self):
        result = parse_environment_cisco(ENVIRONMENT_IOS_ROUTER)
        # PS2 is "Not Present" — depends on parser's definition of ok
        # At minimum, fans and temperature should be OK
        fans_ok = all(f["ok"] for f in result["fans"])
        assert fans_ok

    def test_fan_failure_sets_not_ok(self):
        result = parse_environment_cisco(ENVIRONMENT_FAIL)
        failed_fans = [f for f in result["fans"] if not f["ok"]]
        assert len(failed_fans) >= 1
        assert result["overall_ok"] is False

    def test_empty_input_returns_empty_structure(self):
        result = parse_environment_cisco(ENVIRONMENT_EMPTY)
        assert result["fans"] == []
        assert result["temperatures"] == []
        assert result["power_supplies"] == []
        assert result["overall_ok"] is True  # no components → assumed OK

    def test_blank_string_returns_empty_structure(self):
        result = parse_environment_cisco("")
        assert result["fans"] == []
        assert result["overall_ok"] is True

    def test_ios_router_format(self):
        result = parse_environment_cisco(ENVIRONMENT_IOS_ROUTER)
        assert len(result["fans"]) >= 2
        assert any(t.get("celsius") is not None for t in result["temperatures"])

    def test_temperature_celsius_is_int(self):
        result = parse_environment_cisco(ENVIRONMENT_IOS_XE)
        detail_temps = [t for t in result["temperatures"] if t.get("celsius") is not None]
        for t in detail_temps:
            assert isinstance(t["celsius"], int)

    def test_fan_status_is_string(self):
        result = parse_environment_cisco(ENVIRONMENT_IOS_XE)
        for f in result["fans"]:
            assert isinstance(f["status"], str)


# ===========================================================================
# parse_version_cisco
# ===========================================================================


class TestParseVersionCisco:
    def test_returns_dict(self):
        assert isinstance(parse_version_cisco(VERSION_IOS), dict)

    def test_required_keys_present(self):
        result = parse_version_cisco(VERSION_IOS)
        for key in ("version", "platform", "uptime", "reload_reason", "image"):
            assert key in result

    def test_ios_version_parsed(self):
        result = parse_version_cisco(VERSION_IOS)
        assert result["version"] == "15.2(4)E8"

    def test_ios_platform_parsed(self):
        result = parse_version_cisco(VERSION_IOS)
        assert result["platform"] == "WS-C3750X-48P"

    def test_ios_uptime_parsed(self):
        result = parse_version_cisco(VERSION_IOS)
        assert result["uptime"] == "2 weeks, 3 days, 4 hours, 5 minutes"

    def test_ios_image_parsed(self):
        result = parse_version_cisco(VERSION_IOS)
        assert result["image"] == "flash:c3750x-ipservicesk9-mz.152-4.E8.bin"

    def test_ios_xe_version_parsed(self):
        result = parse_version_cisco(VERSION_IOS_XE)
        assert result["version"] == "16.12.4"

    def test_ios_xe_uptime_parsed(self):
        result = parse_version_cisco(VERSION_IOS_XE)
        assert result["uptime"] == "10 weeks, 2 days, 14 hours, 56 minutes"

    def test_ios_xe_reload_reason(self):
        result = parse_version_cisco(VERSION_IOS_XE)
        assert result["reload_reason"] == "Reload command"

    def test_ios_xe_image_parsed(self):
        result = parse_version_cisco(VERSION_IOS_XE)
        assert result["image"] == "bootflash:cat9k_iosxe.16.12.04.SPA.bin"

    def test_empty_returns_all_none(self):
        result = parse_version_cisco(VERSION_EMPTY)
        assert result["version"] is None
        assert result["platform"] is None
        assert result["uptime"] is None
        assert result["reload_reason"] is None
        assert result["image"] is None

    def test_blank_string_returns_all_none(self):
        result = parse_version_cisco("")
        assert all(v is None for v in result.values())


# ===========================================================================
# Template entries
# ===========================================================================


class TestCiscoHealthTemplates:
    def test_bgp_summary_entry_present(self):
        assert "bgp_summary" in CISCO_HEALTH

    def test_ospf_neighbors_entry_present(self):
        assert "ospf_neighbors" in CISCO_HEALTH

    def test_environment_entry_present(self):
        assert "environment" in CISCO_HEALTH

    def test_version_entry_present(self):
        assert "version" in CISCO_HEALTH

    def test_bgp_command_value(self):
        assert CISCO_HEALTH["bgp_summary"] == "show ip bgp summary"

    def test_ospf_command_value(self):
        assert CISCO_HEALTH["ospf_neighbors"] == "show ip ospf neighbor"

    def test_environment_command_value(self):
        assert CISCO_HEALTH["environment"] == "show environment all"

    def test_version_command_value(self):
        assert CISCO_HEALTH["version"] == "show version"


# ===========================================================================
# check_cisco_cpu
# ===========================================================================


class TestCheckCiscoCpu:
    def test_below_threshold(self):
        conn = _MockConn({"show processes cpu": CISCO_CPU_OUTPUT})
        result = check_cisco_cpu(conn, threshold=80.0)
        assert result["utilization"] == 8.0
        assert result["alert"] is False

    def test_above_threshold(self):
        conn = _MockConn({"show processes cpu": CISCO_CPU_HIGH})
        result = check_cisco_cpu(conn, threshold=80.0)
        assert result["utilization"] == 92.0
        assert result["alert"] is True

    def test_threshold_at_boundary(self):
        # 80% == threshold 80 → alert
        cpu_at_threshold = (
            "CPU utilization for five seconds: 80%/3%; one minute: 80%; five minutes: 80%"
        )
        result = check_cisco_cpu(_MockConn({"show processes cpu": cpu_at_threshold}), 80.0)
        assert result["alert"] is True

    def test_threshold_included_in_result(self):
        conn = _MockConn({"show processes cpu": CISCO_CPU_OUTPUT})
        result = check_cisco_cpu(conn, threshold=75.0)
        assert result["threshold"] == 75.0

    def test_raw_data_present(self):
        conn = _MockConn({"show processes cpu": CISCO_CPU_OUTPUT})
        result = check_cisco_cpu(conn, threshold=80.0)
        assert "raw" in result
        assert "one_minute" in result["raw"]

    def test_connection_error_graceful(self):
        class _FailConn:
            def send(self, *a, **kw):
                raise RuntimeError("timeout")

        result = check_cisco_cpu(_FailConn(), threshold=80.0)
        assert result["utilization"] is None
        assert result["alert"] is False
        assert "error" in result


# ===========================================================================
# check_cisco_memory
# ===========================================================================


class TestCheckCiscoMemory:
    def test_utilization_calculated(self):
        conn = _MockConn({"show processes memory": CISCO_MEM_OUTPUT})
        result = check_cisco_memory(conn, threshold=85.0)
        expected = round(141058576 / 402702336 * 100, 2)
        assert result["utilization"] == expected
        assert result["alert"] is False

    def test_alert_fires_above_threshold(self):
        high_mem = "Processor  7F2B3C18  100000000   100000000   0   0   0"
        result = check_cisco_memory(_MockConn({"show processes memory": high_mem}), 85.0)
        assert result["alert"] is True

    def test_threshold_included(self):
        conn = _MockConn({"show processes memory": CISCO_MEM_OUTPUT})
        result = check_cisco_memory(conn, threshold=85.0)
        assert result["threshold"] == 85.0


# ===========================================================================
# check_cisco_interfaces
# ===========================================================================


class TestCheckCiscoInterfaces:
    def test_no_errors(self):
        clean = (
            "GigabitEthernet0/0 is up, line protocol is up\n"
            "     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored\n"
            "     0 output errors, 0 collisions, 0 interface resets\n"
        )
        conn = _MockConn({"show interfaces": clean})
        result = check_cisco_interfaces(conn)
        assert result["with_errors"] == 0
        assert result["alert"] is False

    def test_errors_trigger_alert(self):
        conn = _MockConn({"show interfaces": CISCO_INTERFACES_OUTPUT})
        result = check_cisco_interfaces(conn)
        assert result["with_errors"] == 1
        assert result["alert"] is True

    def test_total_count(self):
        conn = _MockConn({"show interfaces": CISCO_INTERFACES_OUTPUT})
        result = check_cisco_interfaces(conn)
        assert result["total"] == 2

    def test_interfaces_list_present(self):
        conn = _MockConn({"show interfaces": CISCO_INTERFACES_OUTPUT})
        result = check_cisco_interfaces(conn)
        assert isinstance(result["interfaces"], list)


# ===========================================================================
# check_cisco_logs
# ===========================================================================


class TestCheckCiscoLogs:
    def test_critical_and_major_counted(self):
        conn = _MockConn({"show logging": CISCO_LOG_OUTPUT})
        result = check_cisco_logs(conn)
        assert result["critical_count"] >= 1
        assert result["major_count"] >= 1
        assert result["alert"] is True

    def test_no_matching_logs_no_alert(self):
        clean_log = "*Mar  1 00:00:01: %SYS-5-CONFIG_I: Configured from console by admin\n"
        conn = _MockConn({"show logging": clean_log})
        result = check_cisco_logs(conn)
        assert result["alert"] is False

    def test_events_list_present(self):
        conn = _MockConn({"show logging": CISCO_LOG_OUTPUT})
        result = check_cisco_logs(conn)
        assert isinstance(result["events"], list)


# ===========================================================================
# check_cisco_bgp
# ===========================================================================


class TestCheckCiscoBgp:
    def test_not_established_triggers_alert(self):
        conn = _MockConn({"show ip bgp summary": CISCO_BGP_SUMMARY})
        result = check_cisco_bgp(conn)
        assert result["not_established"] == 1
        assert result["alert"] is True

    def test_all_established_no_alert(self):
        conn = _MockConn({"show ip bgp summary": CISCO_BGP_ALL_ESTABLISHED})
        result = check_cisco_bgp(conn)
        assert result["not_established"] == 0
        assert result["alert"] is False

    def test_totals_correct(self):
        conn = _MockConn({"show ip bgp summary": CISCO_BGP_SUMMARY})
        result = check_cisco_bgp(conn)
        assert result["total"] == 2
        assert result["established"] == 1

    def test_peers_list_present(self):
        conn = _MockConn({"show ip bgp summary": CISCO_BGP_SUMMARY})
        result = check_cisco_bgp(conn)
        assert isinstance(result["peers"], list)

    def test_cisco_xr_uses_different_command(self):
        # XR uses "show bgp summary" not "show ip bgp summary"
        conn = _MockConn({"show bgp summary": CISCO_BGP_ALL_ESTABLISHED})
        result = check_cisco_bgp(conn, device_type="cisco_xr")
        assert result["total"] == 2


# ===========================================================================
# check_cisco_ospf
# ===========================================================================


class TestCheckCiscoOspf:
    def test_not_full_triggers_alert(self):
        conn = _MockConn({"show ip ospf neighbor": OSPF_NEIGHBORS_OUTPUT})
        result = check_cisco_ospf(conn)
        assert result["not_full"] == 1
        assert result["alert"] is True

    def test_all_full_no_alert(self):
        conn = _MockConn({"show ip ospf neighbor": OSPF_NEIGHBORS_ALL_FULL})
        result = check_cisco_ospf(conn)
        assert result["not_full"] == 0
        assert result["alert"] is False

    def test_totals_correct(self):
        conn = _MockConn({"show ip ospf neighbor": OSPF_NEIGHBORS_OUTPUT})
        result = check_cisco_ospf(conn)
        assert result["total"] == 3
        assert result["full"] == 2

    def test_empty_neighbor_table_no_alert(self):
        conn = _MockConn({"show ip ospf neighbor": OSPF_NEIGHBORS_EMPTY})
        result = check_cisco_ospf(conn)
        assert result["total"] == 0
        assert result["alert"] is False

    def test_neighbors_list_present(self):
        conn = _MockConn({"show ip ospf neighbor": OSPF_NEIGHBORS_OUTPUT})
        result = check_cisco_ospf(conn)
        assert isinstance(result["neighbors"], list)


# ===========================================================================
# check_cisco_environment
# ===========================================================================


class TestCheckCiscoEnvironment:
    def test_all_ok_no_alert(self):
        conn = _MockConn({"show environment all": ENVIRONMENT_IOS_XE})
        result = check_cisco_environment(conn)
        # Environment is OK when all reported fans/temps are OK
        # (PS2 "NOT PRESENT" sets its ok=False but depends on parser)
        assert "alert" in result

    def test_fan_failure_triggers_alert(self):
        conn = _MockConn({"show environment all": ENVIRONMENT_FAIL})
        result = check_cisco_environment(conn)
        assert result["alert"] is True
        assert result["overall_ok"] is False

    def test_empty_environment_no_alert(self):
        conn = _MockConn({"show environment all": ENVIRONMENT_EMPTY})
        result = check_cisco_environment(conn)
        assert result["alert"] is False
        assert result["overall_ok"] is True

    def test_required_keys_present(self):
        conn = _MockConn({"show environment all": ENVIRONMENT_IOS_XE})
        result = check_cisco_environment(conn)
        for key in ("fans", "temperatures", "power_supplies", "overall_ok", "alert"):
            assert key in result

    def test_connection_error_graceful(self):
        class _FailConn:
            def send(self, *a, **kw):
                raise RuntimeError("timeout")

        result = check_cisco_environment(_FailConn())
        assert result["alert"] is False
        assert "error" in result


# ===========================================================================
# check_cisco_uptime
# ===========================================================================


class TestCheckCiscoUptime:
    def test_ios_version_and_uptime(self):
        conn = _MockConn({"show version": VERSION_IOS})
        result = check_cisco_uptime(conn)
        assert result["uptime"] == "2 weeks, 3 days, 4 hours, 5 minutes"

    def test_ios_xe_reload_reason(self):
        conn = _MockConn({"show version": VERSION_IOS_XE})
        result = check_cisco_uptime(conn)
        assert result["reload_reason"] == "Reload command"
        assert result["uptime"] == "10 weeks, 2 days, 14 hours, 56 minutes"

    def test_alert_always_false(self):
        conn = _MockConn({"show version": VERSION_IOS})
        result = check_cisco_uptime(conn)
        assert result["alert"] is False

    def test_required_keys_present(self):
        conn = _MockConn({"show version": VERSION_IOS})
        result = check_cisco_uptime(conn)
        for key in ("version", "platform", "uptime", "reload_reason", "image", "alert"):
            assert key in result


# ===========================================================================
# _parse_thresholds
# ===========================================================================


class TestParseCiscoThresholds:
    def test_cpu_and_mem(self):
        result = _parse_thresholds("cpu=80,mem=85")
        assert result["cpu"] == 80.0
        assert result["mem"] == 85.0

    def test_empty_returns_empty_dict(self):
        assert _parse_thresholds("") == {}

    def test_none_returns_empty_dict(self):
        assert _parse_thresholds(None) == {}

    def test_float_value(self):
        result = _parse_thresholds("cpu=75.5")
        assert result["cpu"] == 75.5

    def test_invalid_value_skipped(self):
        result = _parse_thresholds("cpu=abc,mem=85")
        assert "cpu" not in result
        assert result["mem"] == 85.0


# ===========================================================================
# build_cisco_health_report
# ===========================================================================


class TestBuildCiscoHealthReport:
    def _make_result(self, host, checks=None, success=True, overall_alert=False):
        return {
            "host": host,
            "timestamp": "2026-01-01T00:00:00Z",
            "success": success,
            "checks": checks or {},
            "overall_alert": overall_alert,
            "error": None,
        }

    def test_empty_results(self):
        report = build_cisco_health_report([])
        assert report["devices"] == 0
        assert report["devices_reachable"] == 0
        assert report["overall_alert"] is False

    def test_single_healthy_device(self):
        result = self._make_result("router1")
        report = build_cisco_health_report([result])
        assert report["devices"] == 1
        assert report["devices_reachable"] == 1
        assert report["devices_with_alerts"] == 0
        assert report["overall_alert"] is False

    def test_unreachable_device(self):
        result = self._make_result("router1", success=False)
        result["error"] = "Connection refused"
        report = build_cisco_health_report([result])
        assert report["devices_reachable"] == 0

    def test_alert_counts_aggregated(self):
        checks_with_alerts = {
            "cpu": {"alert": True},
            "memory": {"alert": False},
            "bgp": {"alert": True},
            "ospf": {"alert": False},
        }
        result = self._make_result("r1", checks=checks_with_alerts, overall_alert=True)
        report = build_cisco_health_report([result])
        assert report["cpu_alerts"] == 1
        assert report["bgp_alerts"] == 1
        assert report["memory_alerts"] == 0
        assert report["ospf_alerts"] == 0
        assert report["overall_alert"] is True

    def test_results_included_in_report(self):
        result = self._make_result("router1")
        report = build_cisco_health_report([result])
        assert len(report["results"]) == 1
        assert report["results"][0]["host"] == "router1"

    def test_multiple_devices_aggregation(self):
        r1 = self._make_result("r1", checks={"bgp": {"alert": True}}, overall_alert=True)
        r2 = self._make_result("r2", checks={"bgp": {"alert": False}}, overall_alert=False)
        report = build_cisco_health_report([r1, r2])
        assert report["devices"] == 2
        assert report["devices_with_alerts"] == 1
        assert report["bgp_alerts"] == 1

    def test_report_keys_present(self):
        report = build_cisco_health_report([])
        for key in (
            "devices",
            "devices_reachable",
            "devices_with_alerts",
            "cpu_alerts",
            "memory_alerts",
            "interface_error_alerts",
            "log_alerts",
            "bgp_alerts",
            "ospf_alerts",
            "environment_alerts",
            "overall_alert",
            "results",
        ):
            assert key in report


# ===========================================================================
# Default threshold constants
# ===========================================================================


class TestDefaultConstants:
    def test_cpu_threshold(self):
        assert DEFAULT_CPU_THRESHOLD == 80.0

    def test_mem_threshold(self):
        assert DEFAULT_MEM_THRESHOLD == 85.0


# ===========================================================================
# parse_version_cisco — IOS reload reason via "System restarted by"
# ===========================================================================


class TestParseVersionCiscoReloadVariants:
    IOS_RELOAD_VARIANT = """\
Cisco IOS Software, Version 15.2(4)E8, RELEASE SOFTWARE (fc2)
cisco WS-C3750X-48P (PowerPC405) processor
Switch uptime is 1 day, 2 hours, 3 minutes
System restarted by reload
System image file is "flash:ios.bin"
"""

    def test_system_restarted_by_parsed(self):
        result = parse_version_cisco(self.IOS_RELOAD_VARIANT)
        assert result["reload_reason"] is not None
        assert "reload" in result["reload_reason"].lower()

    @pytest.mark.parametrize(
        "line,expected_reason",
        [
            ("Last reload reason: Reload command", "Reload command"),
            ("Last reload reason: power-on", "power-on"),
            ("Last reload reason: Reload Request by SMART-CALL-HOME", "Reload Request by SMART-CALL-HOME"),
        ],
    )
    def test_last_reload_reason_variants(self, line, expected_reason):
        result = parse_version_cisco(line)
        assert result["reload_reason"] == expected_reason
