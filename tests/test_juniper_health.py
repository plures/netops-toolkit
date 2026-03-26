"""Tests for Juniper JunOS health-check parsers and check logic."""

from __future__ import annotations

from netops.parsers.juniper import (
    parse_bgp_summary_junos,
    parse_chassis_alarms,
    parse_chassis_environment,
    parse_fpc_status,
    parse_interface_errors_junos,
    parse_ospf_neighbors_junos,
    parse_re_status,
    parse_route_summary,
)
from netops.check.juniper import (
    _parse_thresholds,
    _print_result as _junos_print_result,
    build_junos_health_report,
    check_junos_alarms,
    check_junos_bgp,
    check_junos_environment,
    check_junos_fpc,
    check_junos_interfaces,
    check_junos_ospf,
    check_junos_re,
    check_junos_routes,
    run_health_check as run_junos_health_check,
    DEFAULT_CPU_THRESHOLD,
    DEFAULT_MEM_THRESHOLD,
)
from netops.core.connection import ConnectionParams as _JunosConnParams
from netops.templates.junos import HEALTH as JUNOS_HEALTH

# ---------------------------------------------------------------------------
# Sample CLI output fixtures
# ---------------------------------------------------------------------------

RE_STATUS_OUTPUT = """\
Routing Engine status:
  Slot 0:
    Current state                  Master
    Election priority              Master (default)
    Temperature                 40 degrees C / 104 degrees F
    Total memory                 2048 MB
    Memory utilization            65 percent
    CPU utilization:
      User                          2 percent
      Background                    0 percent
      Kernel                        3 percent
      Interrupt                     0 percent
      Idle                         95 percent
    Model                          RE-S-1800x4
    Start time:                    2024-01-01 00:00:00 UTC
    Uptime:                        10 days, 3 hours, 22 minutes, 15 seconds
  Slot 1:
    Current state                  Backup
    Election priority              Backup
    Temperature                 38 degrees C / 100 degrees F
    Total memory                 2048 MB
    Memory utilization            60 percent
    CPU utilization:
      User                          1 percent
      Background                    0 percent
      Kernel                        2 percent
      Interrupt                     0 percent
      Idle                         97 percent
    Model                          RE-S-1800x4
    Start time:                    2024-01-01 00:01:00 UTC
    Uptime:                        10 days, 3 hours, 21 minutes, 10 seconds
"""

RE_STATUS_HIGH_CPU = """\
Routing Engine status:
  Slot 0:
    Current state                  Master
    Temperature                 45 degrees C / 113 degrees F
    Total memory                 2048 MB
    Memory utilization            90 percent
    CPU utilization:
      User                         45 percent
      Background                    5 percent
      Kernel                       15 percent
      Interrupt                     3 percent
      Idle                         32 percent
    Uptime:                        5 days, 1 hour, 0 minutes, 0 seconds
"""

RE_STATUS_EMPTY = "No routing engine information available.\n"

FPC_STATUS_OUTPUT = """\
                     Temp  CPU Utilization (%)   Memory  Utilization (%)
Slot State            (C)  Total  Interrupt      DRAM (MB) Heap     Buffer
0  Online              43     3          0        2048    34         47
1  Online              42     5          1        2048    36         49
2  Empty               -      -          -           -     -          -
3  Empty               -      -          -           -     -          -
"""

FPC_STATUS_OFFLINE = """\
                     Temp  CPU Utilization (%)   Memory  Utilization (%)
Slot State            (C)  Total  Interrupt      DRAM (MB) Heap     Buffer
0  Online              43     3          0        2048    34         47
1  Offline             -      -          -           -     -          -
2  Empty               -      -          -           -     -          -
"""

FPC_STATUS_EMPTY = "No FPC information available.\n"

INTERFACE_ERRORS_OUTPUT = """\
Physical interface: ge-0/0/0, Enabled, Physical link is Up
  Input errors:
    Errors: 0, Drops: 0, Framing errors: 0, Runts: 0, Giants: 0, Policed discards: 0,
    L3 incompletes: 0, L2 channel errors: 0, L2 mismatch timeouts: 0, FIFO errors: 0,
    Resource errors: 0
  Output errors:
    Carrier transitions: 1, Errors: 0, Drops: 0, Collisions: 0, Aged packets: 0,
    FIFO errors: 0, HS link CRC errors: 0, MTU errors: 0, Resource errors: 0

Physical interface: ge-0/0/1, Enabled, Physical link is Up
  Input errors:
    Errors: 5, Drops: 2, Framing errors: 0, Runts: 0, Giants: 0, Policed discards: 0,
    L3 incompletes: 0, L2 channel errors: 0, L2 mismatch timeouts: 0, FIFO errors: 0,
    Resource errors: 0
  Output errors:
    Carrier transitions: 2, Errors: 1, Drops: 0, Collisions: 0, Aged packets: 0,
    FIFO errors: 0, HS link CRC errors: 0, MTU errors: 0, Resource errors: 0

Physical interface: ge-0/0/2, Enabled, Physical link is Up
  Input errors:
    Errors: 0, Drops: 0, Framing errors: 0, Runts: 0, Giants: 0, Policed discards: 0,
    L3 incompletes: 0, L2 channel errors: 0, L2 mismatch timeouts: 0, FIFO errors: 0,
    Resource errors: 0
  Output errors:
    Carrier transitions: 0, Errors: 0, Drops: 0, Collisions: 0, Aged packets: 0,
    FIFO errors: 0, HS link CRC errors: 0, MTU errors: 0, Resource errors: 0
"""

INTERFACE_ERRORS_CLEAN = """\
Physical interface: ge-0/0/0, Enabled, Physical link is Up
  Input errors:
    Errors: 0, Drops: 0, Framing errors: 0, Runts: 0, Giants: 0, Policed discards: 0,
    Resource errors: 0
  Output errors:
    Carrier transitions: 0, Errors: 0, Drops: 0, Collisions: 0, Aged packets: 0,
    FIFO errors: 0, HS link CRC errors: 0, MTU errors: 0, Resource errors: 0
"""

INTERFACE_ERRORS_EMPTY = "No interface information.\n"

BGP_SUMMARY_OUTPUT = """\
Groups: 2 Peers: 3 Down peers: 0
Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending
  inet.0              40         38          0          0          0          0
Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...
10.0.0.1              65001      14621      14609       0       0    5d 3:14 Establ
  inet.0: 38/40/40/0
10.0.0.2              65002       1823       1821       0       1   1:23:45 Active
10.0.0.3              65003          0          0       0       0     never Connect
"""

BGP_SUMMARY_ALL_ESTABLISHED = """\
Groups: 1 Peers: 2 Down peers: 0
Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending
  inet.0              20         20          0          0          0          0
Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...
10.0.0.1              65001       5000       4999       0       0   10d 0:00 Establ
  inet.0: 20/20/20/0
10.0.0.2              65002       4500       4490       0       0    9d 1:23 Establ
  inet.0: 20/20/20/0
"""

BGP_SUMMARY_EMPTY = "No BGP peers configured.\n"

OSPF_NEIGHBORS_OUTPUT = """\
Address          Interface              State     ID               Pri  Dead
10.0.0.2         ge-0/0/0.0             Full      192.168.1.2        1    33
10.0.0.3         ge-0/0/1.0             Full      192.168.1.3        1    35
10.0.0.4         ge-0/0/2.0             ExStart   192.168.1.4        0    38
"""

OSPF_NEIGHBORS_ALL_FULL = """\
Address          Interface              State     ID               Pri  Dead
10.0.0.2         ge-0/0/0.0             Full      192.168.1.2        1    33
10.0.0.3         ge-0/0/1.0             Full      192.168.1.3        1    35
"""

OSPF_NEIGHBORS_EMPTY = """\
Address          Interface              State     ID               Pri  Dead
"""

CHASSIS_ALARMS_OUTPUT = """\
2 alarms currently active
Alarm time               Class  Description
2024-01-15 10:23:01 UTC  Major  FPC 1 Major Errors
2024-01-15 10:30:12 UTC  Minor  PEM Input Failure
"""

CHASSIS_ALARMS_MINOR_ONLY = """\
1 alarm currently active
Alarm time               Class  Description
2024-01-15 10:30:12 UTC  Minor  PEM Input Failure
"""

CHASSIS_ALARMS_NONE = """\
No alarms currently active
"""

CHASSIS_ENVIRONMENT_OUTPUT = """\
Class Item                           Status     Measurement
Power Power Supply 0                 OK
Power Power Supply 1                 OK
Cooling FPC 0 Fan 0                  OK        2250 RPM
Cooling FPC 0 Fan 1                  OK        2250 RPM
Cooling FPC 0 Fan 2                  OK        2250 RPM
Temp  CPU                            OK         38 degrees C / 100 degrees F
Temp  FPC 0                          OK         43 degrees C / 109 degrees F
Temp  FPC 1                          OK         42 degrees C / 107 degrees F
"""

CHASSIS_ENVIRONMENT_FAULT = """\
Class Item                           Status     Measurement
Power Power Supply 0                 OK
Power Power Supply 1                 Failed
Cooling FPC 0 Fan 0                  OK        2250 RPM
Cooling FPC 0 Fan 1                  OK        2250 RPM
Temp  CPU                            OK         38 degrees C / 100 degrees F
Temp  FPC 0                          OK         43 degrees C / 109 degrees F
"""

CHASSIS_ENVIRONMENT_EMPTY = "No environment data available.\n"

ROUTE_SUMMARY_OUTPUT = """\
Routing table: inet.0
Destinations: 1204  Routes: 1219  Holddown: 0  Hidden: 0
  Limit/Threshold: 1048576/1048576 destinations
  Direct:      3 routes,      3 active
  Local:       3 routes,      3 active
  BGP:      1213 routes,   1198 active

Routing table: inet6.0
Destinations: 24  Routes: 26  Holddown: 0  Hidden: 0
  Direct:      2 routes,      2 active
  Local:       2 routes,      2 active
  BGP:        22 routes,     20 active
"""

ROUTE_SUMMARY_EMPTY = "No routing table information.\n"


# ===========================================================================
# Parser tests
# ===========================================================================


class TestParseReStatus:
    def test_parses_dual_re(self):
        res = parse_re_status(RE_STATUS_OUTPUT)
        assert len(res) == 2

    def test_slot_indices(self):
        res = parse_re_status(RE_STATUS_OUTPUT)
        assert res[0]["slot"] == 0
        assert res[1]["slot"] == 1

    def test_mastership(self):
        res = parse_re_status(RE_STATUS_OUTPUT)
        assert res[0]["mastership"] == "Master"
        assert res[1]["mastership"] == "Backup"

    def test_cpu_util(self):
        res = parse_re_status(RE_STATUS_OUTPUT)
        # Idle=95 → cpu_util = 100-95 = 5
        assert res[0]["cpu_util"] == 5
        # Idle=97 → cpu_util = 3
        assert res[1]["cpu_util"] == 3

    def test_memory_util(self):
        res = parse_re_status(RE_STATUS_OUTPUT)
        assert res[0]["memory_util"] == 65
        assert res[1]["memory_util"] == 60

    def test_memory_total(self):
        res = parse_re_status(RE_STATUS_OUTPUT)
        assert res[0]["memory_total"] == 2048

    def test_temperature(self):
        res = parse_re_status(RE_STATUS_OUTPUT)
        assert res[0]["temperature"] == 40
        assert res[1]["temperature"] == 38

    def test_uptime(self):
        res = parse_re_status(RE_STATUS_OUTPUT)
        assert "10 days" in res[0]["uptime"]

    def test_high_cpu(self):
        res = parse_re_status(RE_STATUS_HIGH_CPU)
        assert len(res) == 1
        # Idle=32 → cpu_util = 68
        assert res[0]["cpu_util"] == 68
        assert res[0]["memory_util"] == 90

    def test_empty_output(self):
        res = parse_re_status(RE_STATUS_EMPTY)
        assert res == []


class TestParseFpcStatus:
    def test_parses_slots(self):
        res = parse_fpc_status(FPC_STATUS_OUTPUT)
        assert len(res) == 4

    def test_online_slots(self):
        res = parse_fpc_status(FPC_STATUS_OUTPUT)
        assert res[0]["state"] == "Online"
        assert res[1]["state"] == "Online"

    def test_empty_slots(self):
        res = parse_fpc_status(FPC_STATUS_OUTPUT)
        assert res[2]["state"] == "Empty"
        assert res[3]["state"] == "Empty"

    def test_ok_flag_online(self):
        res = parse_fpc_status(FPC_STATUS_OUTPUT)
        assert res[0]["ok"] is True
        assert res[1]["ok"] is True

    def test_ok_flag_empty(self):
        res = parse_fpc_status(FPC_STATUS_OUTPUT)
        assert res[2]["ok"] is True  # Empty is treated as ok

    def test_cpu_util(self):
        res = parse_fpc_status(FPC_STATUS_OUTPUT)
        assert res[0]["cpu_util"] == 3
        assert res[1]["cpu_util"] == 5

    def test_none_for_empty_slot(self):
        res = parse_fpc_status(FPC_STATUS_OUTPUT)
        assert res[2]["cpu_util"] is None

    def test_offline_slot(self):
        res = parse_fpc_status(FPC_STATUS_OFFLINE)
        offline = [f for f in res if f["state"] == "Offline"]
        assert len(offline) == 1
        assert offline[0]["ok"] is False

    def test_empty_output(self):
        res = parse_fpc_status(FPC_STATUS_EMPTY)
        assert res == []


class TestParseInterfaceErrors:
    def test_parses_three_interfaces(self):
        res = parse_interface_errors_junos(INTERFACE_ERRORS_OUTPUT)
        assert len(res) == 3

    def test_first_interface_no_errors(self):
        res = parse_interface_errors_junos(INTERFACE_ERRORS_OUTPUT)
        assert res[0]["name"] == "ge-0/0/0"
        assert res[0]["has_errors"] is False
        assert res[0]["input_errors"] == 0
        assert res[0]["output_errors"] == 0

    def test_second_interface_has_errors(self):
        res = parse_interface_errors_junos(INTERFACE_ERRORS_OUTPUT)
        assert res[1]["name"] == "ge-0/0/1"
        assert res[1]["has_errors"] is True
        assert res[1]["input_errors"] == 5
        assert res[1]["input_drops"] == 2
        assert res[1]["output_errors"] == 1

    def test_third_interface_no_errors(self):
        res = parse_interface_errors_junos(INTERFACE_ERRORS_OUTPUT)
        assert res[2]["name"] == "ge-0/0/2"
        assert res[2]["has_errors"] is False

    def test_clean_interfaces(self):
        res = parse_interface_errors_junos(INTERFACE_ERRORS_CLEAN)
        assert len(res) == 1
        assert res[0]["has_errors"] is False

    def test_empty_output(self):
        res = parse_interface_errors_junos(INTERFACE_ERRORS_EMPTY)
        assert res == []


class TestParseBgpSummaryJunos:
    def test_parses_three_peers(self):
        res = parse_bgp_summary_junos(BGP_SUMMARY_OUTPUT)
        assert len(res) == 3

    def test_established_peer(self):
        res = parse_bgp_summary_junos(BGP_SUMMARY_OUTPUT)
        peer = res[0]
        assert peer["neighbor"] == "10.0.0.1"
        assert peer["peer_as"] == 65001
        assert peer["state"] == "Established"

    def test_active_peer(self):
        res = parse_bgp_summary_junos(BGP_SUMMARY_OUTPUT)
        peer = res[1]
        assert peer["neighbor"] == "10.0.0.2"
        assert peer["state"] == "Active"

    def test_connect_peer(self):
        res = parse_bgp_summary_junos(BGP_SUMMARY_OUTPUT)
        peer = res[2]
        assert peer["neighbor"] == "10.0.0.3"
        assert peer["state"] == "Connect"

    def test_all_established(self):
        res = parse_bgp_summary_junos(BGP_SUMMARY_ALL_ESTABLISHED)
        assert len(res) == 2
        assert all(p["state"] == "Established" for p in res)

    def test_prefix_counts(self):
        res = parse_bgp_summary_junos(BGP_SUMMARY_OUTPUT)
        # The first peer should have prefix data from the continuation line
        assert res[0]["active_prefixes"] == 38

    def test_empty_output(self):
        res = parse_bgp_summary_junos(BGP_SUMMARY_EMPTY)
        assert res == []


class TestParseOspfNeighbors:
    def test_parses_three_neighbors(self):
        res = parse_ospf_neighbors_junos(OSPF_NEIGHBORS_OUTPUT)
        assert len(res) == 3

    def test_full_state(self):
        res = parse_ospf_neighbors_junos(OSPF_NEIGHBORS_OUTPUT)
        assert res[0]["state"] == "Full"
        assert res[0]["is_full"] is True
        assert res[0]["neighbor_id"] == "192.168.1.2"
        assert res[0]["address"] == "10.0.0.2"
        assert res[0]["interface"] == "ge-0/0/0.0"

    def test_exstart_state(self):
        res = parse_ospf_neighbors_junos(OSPF_NEIGHBORS_OUTPUT)
        assert res[2]["state"] == "ExStart"
        assert res[2]["is_full"] is False

    def test_all_full(self):
        res = parse_ospf_neighbors_junos(OSPF_NEIGHBORS_ALL_FULL)
        assert len(res) == 2
        assert all(n["is_full"] for n in res)

    def test_priority(self):
        res = parse_ospf_neighbors_junos(OSPF_NEIGHBORS_OUTPUT)
        assert res[0]["priority"] == 1
        assert res[2]["priority"] == 0

    def test_empty_output(self):
        res = parse_ospf_neighbors_junos(OSPF_NEIGHBORS_EMPTY)
        assert res == []


class TestParseChassisAlarms:
    def test_parses_two_alarms(self):
        res = parse_chassis_alarms(CHASSIS_ALARMS_OUTPUT)
        assert len(res) == 2

    def test_major_alarm(self):
        res = parse_chassis_alarms(CHASSIS_ALARMS_OUTPUT)
        major = [a for a in res if a["is_major"]]
        assert len(major) == 1
        assert "FPC 1" in major[0]["description"]
        assert major[0]["class_"] == "Major"

    def test_minor_alarm(self):
        res = parse_chassis_alarms(CHASSIS_ALARMS_OUTPUT)
        minor = [a for a in res if not a["is_major"]]
        assert len(minor) == 1
        assert "PEM" in minor[0]["description"]
        assert minor[0]["class_"] == "Minor"

    def test_minor_only(self):
        res = parse_chassis_alarms(CHASSIS_ALARMS_MINOR_ONLY)
        assert len(res) == 1
        assert res[0]["is_major"] is False

    def test_no_alarms(self):
        res = parse_chassis_alarms(CHASSIS_ALARMS_NONE)
        assert res == []


class TestParseChassisEnvironment:
    def test_all_ok(self):
        res = parse_chassis_environment(CHASSIS_ENVIRONMENT_OUTPUT)
        assert res["overall_ok"] is True

    def test_power_supplies_parsed(self):
        res = parse_chassis_environment(CHASSIS_ENVIRONMENT_OUTPUT)
        assert len(res["power_supplies"]) == 2
        assert all(p["ok"] for p in res["power_supplies"])

    def test_fans_parsed(self):
        res = parse_chassis_environment(CHASSIS_ENVIRONMENT_OUTPUT)
        assert len(res["fans"]) == 3
        assert all(f["ok"] for f in res["fans"])

    def test_temperatures_parsed(self):
        res = parse_chassis_environment(CHASSIS_ENVIRONMENT_OUTPUT)
        assert len(res["temperatures"]) == 3
        assert res["temperatures"][0]["celsius"] == 38

    def test_fault_detected(self):
        res = parse_chassis_environment(CHASSIS_ENVIRONMENT_FAULT)
        assert res["overall_ok"] is False
        failed_psu = [p for p in res["power_supplies"] if not p["ok"]]
        assert len(failed_psu) == 1
        assert failed_psu[0]["status"] == "Failed"

    def test_empty_output(self):
        res = parse_chassis_environment(CHASSIS_ENVIRONMENT_EMPTY)
        assert res["power_supplies"] == []
        assert res["fans"] == []
        assert res["temperatures"] == []
        assert res["overall_ok"] is True  # no components means no failures


class TestParseRouteSummary:
    def test_parses_two_tables(self):
        res = parse_route_summary(ROUTE_SUMMARY_OUTPUT)
        assert len(res) == 2

    def test_inet0_table(self):
        res = parse_route_summary(ROUTE_SUMMARY_OUTPUT)
        inet0 = next(t for t in res if t["table"] == "inet.0")
        assert inet0["total_routes"] == 1219
        assert inet0["active_routes"] == 1204
        assert inet0["holddown_routes"] == 0
        assert inet0["hidden_routes"] == 0

    def test_inet6_table(self):
        res = parse_route_summary(ROUTE_SUMMARY_OUTPUT)
        inet6 = next(t for t in res if t["table"] == "inet6.0")
        assert inet6["total_routes"] == 26
        assert inet6["active_routes"] == 24

    def test_empty_output(self):
        res = parse_route_summary(ROUTE_SUMMARY_EMPTY)
        assert res == []


# ===========================================================================
# Check function tests (using mocked DeviceConnection)
# ===========================================================================


class _MockConn:
    """Minimal DeviceConnection mock that returns canned output per command."""

    def __init__(self, responses: dict[str, str]):
        self._responses = responses

    def send(self, command: str) -> str:
        for key, val in self._responses.items():
            if key in command:
                return val
        return ""


class TestCheckJunosRe:
    def test_normal_operation(self):
        conn = _MockConn({"routing-engine": RE_STATUS_OUTPUT})
        res = check_junos_re(conn, 80.0, 85.0)
        assert res["error"] is None
        assert res["cpu_utilization"] is not None
        assert res["mem_utilization"] is not None
        assert res["alert"] is False

    def test_high_cpu_triggers_alert(self):
        conn = _MockConn({"routing-engine": RE_STATUS_HIGH_CPU})
        res = check_junos_re(conn, 60.0, 95.0)
        assert res["cpu_alert"] is True
        assert res["alert"] is True

    def test_high_mem_triggers_alert(self):
        conn = _MockConn({"routing-engine": RE_STATUS_HIGH_CPU})
        # RE_STATUS_HIGH_CPU has mem_util=90
        res = check_junos_re(conn, 95.0, 85.0)
        assert res["mem_alert"] is True
        assert res["alert"] is True

    def test_empty_output(self):
        conn = _MockConn({"routing-engine": RE_STATUS_EMPTY})
        res = check_junos_re(conn, 80.0, 85.0)
        assert res["cpu_utilization"] is None
        assert res["alert"] is False

    def test_exception_returns_safe_dict(self):
        class _BrokenConn:
            def send(self, _cmd: str) -> str:
                raise RuntimeError("connection lost")

        res = check_junos_re(_BrokenConn(), 80.0, 85.0)
        assert res["alert"] is False
        assert res["error"] is not None


class TestCheckJunosFpc:
    def test_all_online(self):
        conn = _MockConn({"fpc": FPC_STATUS_OUTPUT})
        res = check_junos_fpc(conn)
        assert res["online"] == 2
        assert res["offline"] == 0
        assert res["alert"] is False

    def test_offline_fpc_triggers_alert(self):
        conn = _MockConn({"fpc": FPC_STATUS_OFFLINE})
        res = check_junos_fpc(conn)
        assert res["offline"] == 1
        assert res["alert"] is True

    def test_empty_output(self):
        conn = _MockConn({"fpc": FPC_STATUS_EMPTY})
        res = check_junos_fpc(conn)
        assert res["total"] == 0
        assert res["alert"] is False


class TestCheckJunosInterfaces:
    def test_with_errors(self):
        conn = _MockConn({"interfaces extensive": INTERFACE_ERRORS_OUTPUT})
        res = check_junos_interfaces(conn)
        assert res["with_errors"] == 1
        assert res["alert"] is True

    def test_no_errors(self):
        conn = _MockConn({"interfaces extensive": INTERFACE_ERRORS_CLEAN})
        res = check_junos_interfaces(conn)
        assert res["with_errors"] == 0
        assert res["alert"] is False

    def test_empty_output(self):
        conn = _MockConn({"interfaces extensive": INTERFACE_ERRORS_EMPTY})
        res = check_junos_interfaces(conn)
        assert res["total"] == 0
        assert res["alert"] is False


class TestCheckJunosBgp:
    def test_partial_established_triggers_alert(self):
        conn = _MockConn({"bgp summary": BGP_SUMMARY_OUTPUT})
        res = check_junos_bgp(conn)
        assert res["established"] == 1
        assert res["not_established"] == 2
        assert res["alert"] is True

    def test_all_established_no_alert(self):
        conn = _MockConn({"bgp summary": BGP_SUMMARY_ALL_ESTABLISHED})
        res = check_junos_bgp(conn)
        assert res["not_established"] == 0
        assert res["alert"] is False

    def test_no_peers_no_alert(self):
        conn = _MockConn({"bgp summary": BGP_SUMMARY_EMPTY})
        res = check_junos_bgp(conn)
        assert res["total"] == 0
        assert res["alert"] is False


class TestCheckJunosOspf:
    def test_partial_full_triggers_alert(self):
        conn = _MockConn({"ospf neighbor": OSPF_NEIGHBORS_OUTPUT})
        res = check_junos_ospf(conn)
        assert res["full"] == 2
        assert res["not_full"] == 1
        assert res["alert"] is True

    def test_all_full_no_alert(self):
        conn = _MockConn({"ospf neighbor": OSPF_NEIGHBORS_ALL_FULL})
        res = check_junos_ospf(conn)
        assert res["not_full"] == 0
        assert res["alert"] is False

    def test_no_neighbors_no_alert(self):
        conn = _MockConn({"ospf neighbor": OSPF_NEIGHBORS_EMPTY})
        res = check_junos_ospf(conn)
        assert res["total"] == 0
        assert res["alert"] is False


class TestCheckJunosAlarms:
    def test_major_alarm_triggers_alert(self):
        conn = _MockConn({"alarms": CHASSIS_ALARMS_OUTPUT})
        res = check_junos_alarms(conn)
        assert res["major_count"] == 1
        assert res["minor_count"] == 1
        assert res["alert"] is True

    def test_minor_only_no_alert(self):
        conn = _MockConn({"alarms": CHASSIS_ALARMS_MINOR_ONLY})
        res = check_junos_alarms(conn)
        assert res["major_count"] == 0
        assert res["minor_count"] == 1
        assert res["alert"] is False

    def test_no_alarms_no_alert(self):
        conn = _MockConn({"alarms": CHASSIS_ALARMS_NONE})
        res = check_junos_alarms(conn)
        assert res["major_count"] == 0
        assert res["alert"] is False


class TestCheckJunosEnvironment:
    def test_all_ok(self):
        conn = _MockConn({"environment": CHASSIS_ENVIRONMENT_OUTPUT})
        res = check_junos_environment(conn)
        assert res["overall_ok"] is True
        assert res["alert"] is False

    def test_fault_triggers_alert(self):
        conn = _MockConn({"environment": CHASSIS_ENVIRONMENT_FAULT})
        res = check_junos_environment(conn)
        assert res["overall_ok"] is False
        assert res["alert"] is True

    def test_empty_output_no_alert(self):
        conn = _MockConn({"environment": CHASSIS_ENVIRONMENT_EMPTY})
        res = check_junos_environment(conn)
        assert res["alert"] is False


class TestCheckJunosRoutes:
    def test_returns_tables(self):
        conn = _MockConn({"route summary": ROUTE_SUMMARY_OUTPUT})
        res = check_junos_routes(conn)
        assert len(res["tables"]) == 2
        assert res["alert"] is False  # always informational

    def test_empty_output(self):
        conn = _MockConn({"route summary": ROUTE_SUMMARY_EMPTY})
        res = check_junos_routes(conn)
        assert res["tables"] == []
        assert res["alert"] is False


# ===========================================================================
# build_junos_health_report tests
# ===========================================================================


class TestBuildJunosHealthReport:
    def _make_result(self, host: str, success: bool, overall_alert: bool, checks: dict) -> dict:
        return {
            "host": host,
            "success": success,
            "overall_alert": overall_alert,
            "checks": checks,
        }

    def test_empty_results(self):
        report = build_junos_health_report([])
        assert report["devices"] == 0
        assert report["devices_reachable"] == 0
        assert report["overall_alert"] is False

    def test_all_healthy(self):
        results = [
            self._make_result(
                "10.0.0.1",
                True,
                False,
                {
                    "re": {"alert": False},
                    "fpc": {"alert": False},
                    "interfaces": {"alert": False},
                    "bgp": {"alert": False},
                    "ospf": {"alert": False},
                    "alarms": {"alert": False},
                    "environment": {"alert": False},
                },
            )
        ]
        report = build_junos_health_report(results)
        assert report["devices"] == 1
        assert report["devices_reachable"] == 1
        assert report["devices_with_alerts"] == 0
        assert report["overall_alert"] is False

    def test_re_alert_counted(self):
        results = [
            self._make_result(
                "10.0.0.1",
                True,
                True,
                {
                    "re": {"alert": True},
                    "fpc": {"alert": False},
                    "interfaces": {"alert": False},
                    "alarms": {"alert": False},
                    "environment": {"alert": False},
                },
            )
        ]
        report = build_junos_health_report(results)
        assert report["re_alerts"] == 1
        assert report["devices_with_alerts"] == 1
        assert report["overall_alert"] is True

    def test_unreachable_device_excluded(self):
        results = [
            self._make_result("10.0.0.1", False, False, {}),
            self._make_result("10.0.0.2", True, False, {"re": {"alert": False}}),
        ]
        report = build_junos_health_report(results)
        assert report["devices"] == 2
        assert report["devices_reachable"] == 1
        assert report["overall_alert"] is False

    def test_results_included(self):
        results = [self._make_result("10.0.0.1", True, False, {})]
        report = build_junos_health_report(results)
        assert report["results"] is results


# ===========================================================================
# CLI helper tests
# ===========================================================================


class TestParseThresholds:
    def test_cpu_and_mem(self):
        res = _parse_thresholds("cpu=75,mem=80")
        assert res["cpu"] == 75.0
        assert res["mem"] == 80.0

    def test_empty_string(self):
        assert _parse_thresholds("") == {}

    def test_none_input(self):
        assert _parse_thresholds(None) == {}

    def test_ignores_invalid(self):
        res = _parse_thresholds("cpu=80,invalid,mem=notanumber")
        assert res.get("cpu") == 80.0
        assert "mem" not in res

    def test_single_value(self):
        res = _parse_thresholds("cpu=90")
        assert res == {"cpu": 90.0}


# ===========================================================================
# Template tests
# ===========================================================================


class TestJunosHealthTemplate:
    def test_required_keys_present(self):
        for key in ("re_cpu_memory", "fpc_status", "bgp_summary", "ospf_neighbors",
                    "chassis_alarms", "chassis_environment", "route_summary"):
            assert key in JUNOS_HEALTH, f"Missing key: {key}"

    def test_commands_are_strings(self):
        for key, cmd in JUNOS_HEALTH.items():
            assert isinstance(cmd, str), f"{key} value is not a string"
            assert cmd.strip(), f"{key} command is empty"


# ===========================================================================
# Default threshold constants
# ===========================================================================


class TestDefaults:
    def test_cpu_threshold(self):
        assert DEFAULT_CPU_THRESHOLD == 80.0

    def test_mem_threshold(self):
        assert DEFAULT_MEM_THRESHOLD == 85.0


# ===========================================================================
# Additional imports for new test classes
# ===========================================================================


# ===========================================================================
# Helpers
# ===========================================================================


class _JunosRaisingConn:
    """Mock connection that always raises RuntimeError on send()."""

    def send(self, command: str) -> str:
        raise RuntimeError("simulated send failure")


# ===========================================================================
# check_junos_* error paths
# ===========================================================================


class TestCheckJunosReError:
    def test_exception_returns_error_dict(self):
        res = check_junos_re(_JunosRaisingConn(), 80.0, 85.0)
        assert res["error"] is not None
        assert "simulated" in res["error"]
        assert res["alert"] is False
        assert res["cpu_utilization"] is None
        assert res["mem_utilization"] is None
        assert res["cpu_alert"] is False
        assert res["mem_alert"] is False
        assert res["routing_engines"] == []


class TestCheckJunosFpcError:
    def test_exception_returns_error_dict(self):
        res = check_junos_fpc(_JunosRaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["fpcs"] == []
        assert res["total"] == 0
        assert res["online"] == 0
        assert res["offline"] == 0


class TestCheckJunosInterfacesError:
    def test_exception_returns_error_dict(self):
        res = check_junos_interfaces(_JunosRaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["interfaces"] == []
        assert res["total"] == 0
        assert res["with_errors"] == 0


class TestCheckJunosBgpError:
    def test_exception_returns_error_dict(self):
        res = check_junos_bgp(_JunosRaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["peers"] == []
        assert res["total"] == 0
        assert res["established"] == 0
        assert res["not_established"] == 0


class TestCheckJunosOspfError:
    def test_exception_returns_error_dict(self):
        res = check_junos_ospf(_JunosRaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["neighbors"] == []
        assert res["total"] == 0
        assert res["full"] == 0
        assert res["not_full"] == 0


class TestCheckJunosAlarmsError:
    def test_exception_returns_error_dict(self):
        res = check_junos_alarms(_JunosRaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["alarms"] == []
        assert res["major_count"] == 0
        assert res["minor_count"] == 0


class TestCheckJunosEnvironmentError:
    def test_exception_returns_error_dict(self):
        res = check_junos_environment(_JunosRaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["power_supplies"] == []
        assert res["fans"] == []
        assert res["temperatures"] == []
        assert res["overall_ok"] is True


class TestCheckJunosRoutesError:
    def test_exception_returns_error_dict(self):
        res = check_junos_routes(_JunosRaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["tables"] == []


# ===========================================================================
# run_junos_health_check (run_health_check)
# ===========================================================================


class _JunosMockConn:
    """Minimal mock returning pre-canned output based on command substring."""

    def __init__(self, responses: dict[str, str]):
        self._responses = responses

    def send(self, command: str) -> str:
        for key, val in self._responses.items():
            if key in command:
                return val
        return ""


class TestRunJunosHealthCheck:
    def _make_params(self):
        return _JunosConnParams(
            host="10.1.1.1",
            username="netops",
            password="secret",
            device_type="juniper",
        )

    def _healthy_conn(self):
        return _JunosMockConn(
            {
                "routing-engine": RE_STATUS_OUTPUT,
                "chassis fpc": FPC_STATUS_OUTPUT,
                "interfaces extensive": INTERFACE_ERRORS_CLEAN,
                "bgp summary": BGP_SUMMARY_ALL_ESTABLISHED,
                "ospf neighbor": OSPF_NEIGHBORS_ALL_FULL,
                "chassis alarms": CHASSIS_ALARMS_NONE,
                "chassis environment": CHASSIS_ENVIRONMENT_OUTPUT,
                "route summary": ROUTE_SUMMARY_OUTPUT,
            }
        )

    def test_success_path(self, monkeypatch):
        healthy = self._healthy_conn()

        class _FakeConn:
            def __enter__(self_inner):
                return healthy

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr(
            "netops.check.juniper.DeviceConnection", lambda _p: _FakeConn()
        )
        result = run_junos_health_check(self._make_params())
        assert result["success"] is True
        assert result["error"] is None
        assert "re" in result["checks"]
        assert "fpc" in result["checks"]
        assert "interfaces" in result["checks"]
        assert "bgp" in result["checks"]
        assert "ospf" in result["checks"]
        assert "alarms" in result["checks"]
        assert "environment" in result["checks"]
        assert "routes" in result["checks"]

    def test_connection_failure(self, monkeypatch):
        class _FailConn:
            def __enter__(self_inner):
                raise OSError("cannot connect")

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr(
            "netops.check.juniper.DeviceConnection", lambda _p: _FailConn()
        )
        result = run_junos_health_check(self._make_params())
        assert result["success"] is False
        assert result["error"] is not None

    def test_bgp_and_ospf_skipped_when_disabled(self, monkeypatch):
        conn = self._healthy_conn()

        class _FakeConn:
            def __enter__(self_inner):
                return conn

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr(
            "netops.check.juniper.DeviceConnection", lambda _p: _FakeConn()
        )
        result = run_junos_health_check(
            self._make_params(), check_bgp=False, check_ospf=False
        )
        assert result["success"] is True
        assert "bgp" not in result["checks"]
        assert "ospf" not in result["checks"]

    def test_overall_alert_set_when_check_alerts(self, monkeypatch):
        conn = _JunosMockConn(
            {
                "routing-engine": RE_STATUS_HIGH_CPU,
                "chassis fpc": FPC_STATUS_OUTPUT,
                "interfaces extensive": INTERFACE_ERRORS_CLEAN,
                "bgp summary": BGP_SUMMARY_ALL_ESTABLISHED,
                "ospf neighbor": OSPF_NEIGHBORS_ALL_FULL,
                "chassis alarms": CHASSIS_ALARMS_NONE,
                "chassis environment": CHASSIS_ENVIRONMENT_OUTPUT,
                "route summary": ROUTE_SUMMARY_OUTPUT,
            }
        )

        class _FakeConn:
            def __enter__(self_inner):
                return conn

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr(
            "netops.check.juniper.DeviceConnection", lambda _p: _FakeConn()
        )
        result = run_junos_health_check(self._make_params(), cpu_threshold=50.0)
        assert result["success"] is True
        assert result["overall_alert"] is True


# ===========================================================================
# _print_result (lines 494-569)
# ===========================================================================


class TestJunosPrintResult:
    def _base_result(self, success=True, overall_alert=False, checks=None):
        return {
            "host": "10.1.1.1",
            "timestamp": "2026-01-01T00:00:00Z",
            "success": success,
            "overall_alert": overall_alert,
            "checks": checks or {},
            "error": None,
        }

    def test_failed_device_prints_error(self, capsys):
        result = self._base_result(success=False)
        result["error"] = "SSH timeout"
        _junos_print_result(result)
        out = capsys.readouterr().out
        assert "10.1.1.1" in out
        assert "ERROR" in out

    def test_healthy_device_shows_re_cpu_mem(self, capsys):
        checks = {
            "re": {
                "cpu_utilization": 5.0,
                "mem_utilization": 65.0,
                "cpu_threshold": 80.0,
                "mem_threshold": 85.0,
                "alert": False,
            },
            "fpc": {"online": 2, "offline": 0, "alert": False},
            "interfaces": {"with_errors": 0, "total": 8, "alert": False},
            "alarms": {"major_count": 0, "minor_count": 0, "alert": False},
            "environment": {"overall_ok": True, "alert": False},
            "routes": {"tables": [], "alert": False},
        }
        _junos_print_result(self._base_result(checks=checks))
        out = capsys.readouterr().out
        assert "10.1.1.1" in out
        assert "5.0%" in out
        assert "65.0%" in out
        assert "FPC" in out
        assert "ALARMS" in out
        assert "ENVIRONMENT" in out

    def test_bgp_ospf_shown_when_present(self, capsys):
        checks = {
            "re": {"cpu_utilization": None, "mem_utilization": None, "alert": False},
            "fpc": {"online": 1, "offline": 0, "alert": False},
            "interfaces": {"with_errors": 0, "total": 0, "alert": False},
            "bgp": {"established": 2, "total": 2, "alert": False},
            "ospf": {"full": 1, "total": 1, "alert": False},
            "alarms": {"major_count": 0, "minor_count": 0, "alert": False},
            "environment": {"overall_ok": True, "alert": False},
            "routes": {"tables": [], "alert": False},
        }
        _junos_print_result(self._base_result(checks=checks))
        out = capsys.readouterr().out
        assert "BGP" in out
        assert "OSPF" in out

    def test_routes_tables_shown(self, capsys):
        checks = {
            "re": {"cpu_utilization": None, "mem_utilization": None, "alert": False},
            "fpc": {"online": 0, "offline": 0, "alert": False},
            "interfaces": {"with_errors": 0, "total": 0, "alert": False},
            "alarms": {"major_count": 0, "minor_count": 0, "alert": False},
            "environment": {"overall_ok": True, "alert": False},
            "routes": {
                "tables": [
                    {"table": "inet.0", "active_routes": 100, "total_routes": 120},
                ],
                "alert": False,
            },
        }
        _junos_print_result(self._base_result(checks=checks))
        out = capsys.readouterr().out
        assert "ROUTES" in out
        assert "inet.0" in out
