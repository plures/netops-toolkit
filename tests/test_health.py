"""Tests for health-check parsers and check logic."""

from __future__ import annotations

from netops.check.health import (
    DEFAULT_CPU_THRESHOLD,
    DEFAULT_MEM_THRESHOLD,
    _parse_thresholds,
    check_cpu,
    check_interface_errors,
    check_logs,
    check_memory,
    run_health_check,
)
from netops.core.connection import ConnectionParams
from netops.parsers.health import (
    parse_cpu_brocade,
    parse_cpu_cisco,
    parse_cpu_nokia,
    parse_interface_errors_brocade,
    parse_interface_errors_cisco,
    parse_interface_errors_nokia,
    parse_logs_brocade,
    parse_logs_cisco,
    parse_logs_nokia,
    parse_memory_brocade,
    parse_memory_cisco,
    parse_memory_nokia,
)

# ---------------------------------------------------------------------------
# Sample CLI output fixtures
# ---------------------------------------------------------------------------

CISCO_CPU_OUTPUT = """\
CPU utilization for five seconds: 12%/3%; one minute: 8%; five minutes: 6%
 PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process
   1        1234       12345        100  0.00%  0.00%  0.00%   0 Chunk Manager
"""

CISCO_CPU_HIGH = "CPU utilization for five seconds: 95%/10%; one minute: 92%; five minutes: 88%"

CISCO_CPU_EMPTY = "Router> show processes cpu\n"

NOKIA_CPU_OUTPUT = """\
===============================================================================
System CPU Usage
===============================================================================
Sample Period         : 30 seconds
                        avg  peak
CPU Usage             :  5%  12%
"""

NOKIA_CPU_EMPTY = "A:router> show system cpu\n"

CISCO_MEM_OUTPUT = """\
                 Head    Total(b)     Used(b)     Free(b)   Lowest(b)    Largest(b)
Processor  7F2B3C18  402702336   141058576   261643760   258219008   261643520
io         7F2B3C18   67108864    12345678    54763186    54763186    54763186
"""

CISCO_MEM_EMPTY = "Router> show processes memory\n"

NOKIA_MEM_OUTPUT = """\
===============================================================================
System Memory Pools
===============================================================================
Total In Use          :      141058576
Total Available       :      261643760
"""

NOKIA_MEM_EMPTY = "A:router> show system memory-pools\n"

CISCO_INTERFACES_OUTPUT = """\
GigabitEthernet0/0 is up, line protocol is up
  Hardware is Gigabit Ethernet, address is aabb.cc00.0100
  Internet address is 192.168.1.1/24
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
GigabitEthernet0/2 is administratively down, line protocol is down
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions, 0 interface resets
"""

CISCO_INTERFACES_EMPTY = ""

NOKIA_INTERFACES_OUTPUT = """\
Port 1/1/1
  CRC/Align Errors              :                    0
  Input Errors                  :                    0
  Output Errors                 :                    0
  Ingress Drop                  :                    0
Port 1/1/2
  CRC/Align Errors              :                   12
  Input Errors                  :                    5
  Output Errors                 :                    3
  Ingress Drop                  :                   20
  Egress Drop                   :                    8
"""

NOKIA_INTERFACES_EMPTY = ""

CISCO_LOG_OUTPUT = """\
*Mar  1 00:00:01: %SYS-5-CONFIG_I: Configured from console by admin
*Mar  1 00:01:00: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
*Mar  1 00:02:00: %SYS-2-MALLOCFAIL: Memory allocation of 10240 bytes failed
*Mar  1 00:03:00: %OSPF-5-ADJCHG: Process 1, Nbr changed
"""

CISCO_LOG_ONLY_INFO = """\
*Mar  1 00:00:01: %SYS-5-CONFIG_I: Configured from console by admin
*Mar  1 00:00:02: %SYS-6-BOOTTIME: Time taken to reboot
"""

NOKIA_LOG_OUTPUT = """\
2026-03-24T04:00:00Z CRITICAL router.ospf OSPF adjacency lost on interface 1/1/1
2026-03-24T04:01:00Z MAJOR router.bgp BGP session to 10.0.0.2 went down
2026-03-24T04:02:00Z INFO router.sys System heartbeat OK
"""

NOKIA_LOG_EMPTY = "No log events found.\n"

BROCADE_CPU_OUTPUT = """\
CPU Utilization:
  1-second average:  15 percent
  5-second average:  12 percent
 60-second average:   8 percent
"""

BROCADE_CPU_EMPTY = "ICX7550> show cpu\n"

BROCADE_MEM_OUTPUT = """\
System memory information:
  Total DRAM: 1048576 KBytes
  Used DRAM:   512000 KBytes
  Free DRAM:   536576 KBytes
"""

BROCADE_MEM_EMPTY = "ICX7550> show memory\n"

BROCADE_INTERFACES_OUTPUT = """\
GigabitEthernet1/1/1 is up, line protocol is up
  Hardware is GigabitEthernet, address is aabb.cc00.0001
  0 input errors, 0 CRC, 0 alignment errors, 0 runts, 0 giants
  0 output errors, 0 output discards
GigabitEthernet1/1/2 is up, line protocol is up
  Hardware is GigabitEthernet, address is aabb.cc00.0002
  7 input errors, 4 CRC, 0 alignment errors, 0 runts, 0 giants
  2 output errors, 5 output discards
"""

BROCADE_INTERFACES_EMPTY = ""

BROCADE_LOG_OUTPUT = """\
Mar 15 12:34:56 CRIT system Fan failure detected on module 1
Mar 15 12:35:00 ERR ospf OSPF adjacency lost with 10.0.0.1
Mar 15 12:36:00 WARN bgp BGP route dampening applied
"""

BROCADE_LOG_EMPTY = "No log messages.\n"


# ===========================================================================
# parse_cpu_cisco
# ===========================================================================


class TestParseCpuCisco:
    def test_returns_dict(self):
        assert isinstance(parse_cpu_cisco(CISCO_CPU_OUTPUT), dict)

    def test_all_fields_present(self):
        result = parse_cpu_cisco(CISCO_CPU_OUTPUT)
        assert "five_seconds" in result
        assert "one_minute" in result
        assert "five_minutes" in result

    def test_correct_values(self):
        result = parse_cpu_cisco(CISCO_CPU_OUTPUT)
        assert result["five_seconds"] == 12.0
        assert result["one_minute"] == 8.0
        assert result["five_minutes"] == 6.0

    def test_high_cpu(self):
        result = parse_cpu_cisco(CISCO_CPU_HIGH)
        assert result["one_minute"] == 92.0

    def test_empty_returns_empty_dict(self):
        assert parse_cpu_cisco(CISCO_CPU_EMPTY) == {}

    def test_blank_string_returns_empty_dict(self):
        assert parse_cpu_cisco("") == {}


# ===========================================================================
# parse_cpu_nokia
# ===========================================================================


class TestParseCpuNokia:
    def test_returns_dict(self):
        assert isinstance(parse_cpu_nokia(NOKIA_CPU_OUTPUT), dict)

    def test_all_fields_present(self):
        result = parse_cpu_nokia(NOKIA_CPU_OUTPUT)
        assert "avg" in result
        assert "peak" in result

    def test_correct_values(self):
        result = parse_cpu_nokia(NOKIA_CPU_OUTPUT)
        assert result["avg"] == 5.0
        assert result["peak"] == 12.0

    def test_empty_returns_empty_dict(self):
        assert parse_cpu_nokia(NOKIA_CPU_EMPTY) == {}

    def test_blank_string_returns_empty_dict(self):
        assert parse_cpu_nokia("") == {}


# ===========================================================================
# parse_memory_cisco
# ===========================================================================


class TestParseMemoryCisco:
    def test_returns_dict(self):
        assert isinstance(parse_memory_cisco(CISCO_MEM_OUTPUT), dict)

    def test_all_fields_present(self):
        result = parse_memory_cisco(CISCO_MEM_OUTPUT)
        for key in ("total", "used", "free", "utilization"):
            assert key in result

    def test_correct_values(self):
        result = parse_memory_cisco(CISCO_MEM_OUTPUT)
        assert result["total"] == 402702336
        assert result["used"] == 141058576
        assert result["free"] == 261643760

    def test_utilization_is_percentage(self):
        result = parse_memory_cisco(CISCO_MEM_OUTPUT)
        assert 0.0 <= result["utilization"] <= 100.0

    def test_utilization_calculation(self):
        result = parse_memory_cisco(CISCO_MEM_OUTPUT)
        expected = round(141058576 / 402702336 * 100, 2)
        assert result["utilization"] == expected

    def test_empty_returns_empty_dict(self):
        assert parse_memory_cisco(CISCO_MEM_EMPTY) == {}

    def test_blank_string_returns_empty_dict(self):
        assert parse_memory_cisco("") == {}


# ===========================================================================
# parse_memory_nokia
# ===========================================================================


class TestParseMemoryNokia:
    def test_returns_dict(self):
        assert isinstance(parse_memory_nokia(NOKIA_MEM_OUTPUT), dict)

    def test_all_fields_present(self):
        result = parse_memory_nokia(NOKIA_MEM_OUTPUT)
        for key in ("total", "used", "free", "utilization"):
            assert key in result

    def test_correct_values(self):
        result = parse_memory_nokia(NOKIA_MEM_OUTPUT)
        assert result["used"] == 141058576
        assert result["free"] == 261643760
        assert result["total"] == 141058576 + 261643760

    def test_utilization_is_percentage(self):
        result = parse_memory_nokia(NOKIA_MEM_OUTPUT)
        assert 0.0 <= result["utilization"] <= 100.0

    def test_empty_returns_empty_dict(self):
        assert parse_memory_nokia(NOKIA_MEM_EMPTY) == {}

    def test_blank_string_returns_empty_dict(self):
        assert parse_memory_nokia("") == {}


# ===========================================================================
# parse_interface_errors_cisco
# ===========================================================================


class TestParseInterfaceErrorsCisco:
    def test_returns_list(self):
        assert isinstance(parse_interface_errors_cisco(CISCO_INTERFACES_OUTPUT), list)

    def test_correct_interface_count(self):
        result = parse_interface_errors_cisco(CISCO_INTERFACES_OUTPUT)
        assert len(result) == 3

    def test_clean_interface_no_errors(self):
        iface = parse_interface_errors_cisco(CISCO_INTERFACES_OUTPUT)[0]
        assert iface["name"] == "GigabitEthernet0/0"
        assert iface["input_errors"] == 0
        assert iface["crc"] == 0
        assert iface["output_errors"] == 0
        assert iface["drops"] == 0
        assert iface["has_errors"] is False

    def test_interface_with_errors(self):
        iface = parse_interface_errors_cisco(CISCO_INTERFACES_OUTPUT)[1]
        assert iface["name"] == "GigabitEthernet0/1"
        assert iface["input_errors"] == 5
        assert iface["crc"] == 3
        assert iface["output_errors"] == 2
        assert iface["drops"] == 14  # 10 input + 4 output
        assert iface["has_errors"] is True

    def test_required_keys_present(self):
        for iface in parse_interface_errors_cisco(CISCO_INTERFACES_OUTPUT):
            for key in ("name", "input_errors", "output_errors", "crc", "drops", "has_errors"):
                assert key in iface

    def test_empty_input_returns_empty_list(self):
        assert parse_interface_errors_cisco(CISCO_INTERFACES_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_interface_errors_cisco("") == []


# ===========================================================================
# parse_interface_errors_nokia
# ===========================================================================


class TestParseInterfaceErrorsNokia:
    def test_returns_list(self):
        assert isinstance(parse_interface_errors_nokia(NOKIA_INTERFACES_OUTPUT), list)

    def test_correct_port_count(self):
        result = parse_interface_errors_nokia(NOKIA_INTERFACES_OUTPUT)
        assert len(result) == 2

    def test_clean_port_no_errors(self):
        port = parse_interface_errors_nokia(NOKIA_INTERFACES_OUTPUT)[0]
        assert port["name"] == "1/1/1"
        assert port["crc"] == 0
        assert port["input_errors"] == 0
        assert port["output_errors"] == 0
        assert port["drops"] == 0
        assert port["has_errors"] is False

    def test_port_with_errors(self):
        port = parse_interface_errors_nokia(NOKIA_INTERFACES_OUTPUT)[1]
        assert port["name"] == "1/1/2"
        assert port["crc"] == 12
        assert port["input_errors"] == 5
        assert port["output_errors"] == 3
        assert port["drops"] == 28  # 20 ingress + 8 egress
        assert port["has_errors"] is True

    def test_required_keys_present(self):
        for port in parse_interface_errors_nokia(NOKIA_INTERFACES_OUTPUT):
            for key in ("name", "input_errors", "output_errors", "crc", "drops", "has_errors"):
                assert key in port

    def test_empty_input_returns_empty_list(self):
        assert parse_interface_errors_nokia(NOKIA_INTERFACES_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_interface_errors_nokia("") == []


# ===========================================================================
# parse_logs_cisco
# ===========================================================================


class TestParseLogsCisco:
    def test_returns_list(self):
        assert isinstance(parse_logs_cisco(CISCO_LOG_OUTPUT), list)

    def test_finds_severity_2_and_3(self):
        events = parse_logs_cisco(CISCO_LOG_OUTPUT)
        severities = [e["severity"] for e in events]
        assert 2 in severities
        assert 3 in severities

    def test_skips_severity_5(self):
        events = parse_logs_cisco(CISCO_LOG_OUTPUT)
        assert all(e["severity"] <= 3 for e in events)

    def test_correct_event_count(self):
        # Only severity 0–3: %LINK-3- and %SYS-2-
        events = parse_logs_cisco(CISCO_LOG_OUTPUT)
        assert len(events) == 2

    def test_event_fields(self):
        events = parse_logs_cisco(CISCO_LOG_OUTPUT)
        for event in events:
            for key in ("facility", "severity", "mnemonic", "message"):
                assert key in event

    def test_mallocfail_event(self):
        events = parse_logs_cisco(CISCO_LOG_OUTPUT)
        mallocfail = next(e for e in events if e["mnemonic"] == "MALLOCFAIL")
        assert mallocfail["facility"] == "SYS"
        assert mallocfail["severity"] == 2

    def test_only_info_logs_returns_empty(self):
        assert parse_logs_cisco(CISCO_LOG_ONLY_INFO) == []

    def test_empty_returns_empty_list(self):
        assert parse_logs_cisco("") == []


# ===========================================================================
# parse_logs_nokia
# ===========================================================================


class TestParseLogsNokia:
    def test_returns_list(self):
        assert isinstance(parse_logs_nokia(NOKIA_LOG_OUTPUT), list)

    def test_correct_event_count(self):
        events = parse_logs_nokia(NOKIA_LOG_OUTPUT)
        assert len(events) == 2  # CRITICAL + MAJOR, not INFO

    def test_critical_event(self):
        events = parse_logs_nokia(NOKIA_LOG_OUTPUT)
        critical = next(e for e in events if e["severity"] == "CRITICAL")
        assert critical["subject"] == "router.ospf"

    def test_major_event(self):
        events = parse_logs_nokia(NOKIA_LOG_OUTPUT)
        major = next(e for e in events if e["severity"] == "MAJOR")
        assert major["subject"] == "router.bgp"

    def test_event_fields(self):
        events = parse_logs_nokia(NOKIA_LOG_OUTPUT)
        for event in events:
            for key in ("timestamp", "severity", "subject", "message"):
                assert key in event

    def test_empty_returns_empty_list(self):
        assert parse_logs_nokia(NOKIA_LOG_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_logs_nokia("") == []


# ===========================================================================
# _parse_thresholds
# ===========================================================================


class TestParseThresholds:
    def test_cpu_and_mem(self):
        result = _parse_thresholds("cpu=80,mem=85")
        assert result["cpu"] == 80.0
        assert result["mem"] == 85.0

    def test_single_threshold(self):
        result = _parse_thresholds("cpu=75")
        assert result["cpu"] == 75.0
        assert "mem" not in result

    def test_float_threshold(self):
        result = _parse_thresholds("cpu=75.5")
        assert result["cpu"] == 75.5

    def test_empty_string_returns_empty_dict(self):
        assert _parse_thresholds("") == {}

    def test_none_returns_empty_dict(self):
        assert _parse_thresholds(None) == {}

    def test_invalid_value_is_skipped(self):
        result = _parse_thresholds("cpu=abc,mem=85")
        assert "cpu" not in result
        assert result["mem"] == 85.0

    def test_whitespace_tolerant(self):
        result = _parse_thresholds(" cpu = 80 , mem = 85 ")
        assert result["cpu"] == 80.0
        assert result["mem"] == 85.0


# ===========================================================================
# check_* with mock connection
# ===========================================================================


class _MockConn:
    """Minimal DeviceConnection mock that returns pre-canned output."""

    def __init__(self, responses: dict[str, str]):
        self._responses = responses

    def send(self, command: str, **_kwargs) -> str:
        for key, value in self._responses.items():
            if key in command:
                return value
        return ""


class TestCheckCpu:
    def test_cisco_below_threshold(self):
        conn = _MockConn({"show processes cpu": CISCO_CPU_OUTPUT})
        result = check_cpu(conn, "cisco_ios", threshold=80.0)
        assert result["utilization"] == 8.0
        assert result["alert"] is False

    def test_cisco_above_threshold(self):
        conn = _MockConn({"show processes cpu": CISCO_CPU_HIGH})
        result = check_cpu(conn, "cisco_ios", threshold=80.0)
        assert result["utilization"] == 92.0
        assert result["alert"] is True

    def test_nokia_below_threshold(self):
        conn = _MockConn({"show system cpu": NOKIA_CPU_OUTPUT})
        result = check_cpu(conn, "nokia_sros", threshold=80.0)
        assert result["utilization"] == 5.0
        assert result["alert"] is False

    def test_threshold_included(self):
        result = check_cpu(_MockConn({"show processes cpu": CISCO_CPU_OUTPUT}), "cisco_ios", 80.0)
        assert result["threshold"] == 80.0

    def test_connection_error_graceful(self):
        class _FailConn:
            def send(self, *a, **kw):
                raise RuntimeError("timeout")

        result = check_cpu(_FailConn(), "cisco_ios", 80.0)
        assert result["utilization"] is None
        assert result["alert"] is False
        assert "error" in result


class TestCheckMemory:
    def test_cisco_utilization(self):
        conn = _MockConn({"show processes memory": CISCO_MEM_OUTPUT})
        result = check_memory(conn, "cisco_ios", threshold=85.0)
        expected = round(141058576 / 402702336 * 100, 2)
        assert result["utilization"] == expected
        assert result["alert"] is False

    def test_nokia_utilization(self):
        conn = _MockConn({"show system memory-pools": NOKIA_MEM_OUTPUT})
        result = check_memory(conn, "nokia_sros", threshold=85.0)
        total = 141058576 + 261643760
        expected = round(141058576 / total * 100, 2)
        assert result["utilization"] == expected

    def test_alert_fires_above_threshold(self):
        # Force 100% memory by making used == total
        high_mem = "Processor  7F2B3C18  100000000   100000000   0   0   0"
        conn = _MockConn({"show processes memory": high_mem})
        result = check_memory(conn, "cisco_ios", threshold=85.0)
        assert result["alert"] is True

    def test_threshold_included(self):
        conn = _MockConn({"show processes memory": CISCO_MEM_OUTPUT})
        result = check_memory(conn, "cisco_ios", threshold=85.0)
        assert result["threshold"] == 85.0


class TestCheckInterfaceErrors:
    def test_cisco_no_errors(self):
        clean = (
            "GigabitEthernet0/0 is up, line protocol is up\n"
            "     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored\n"
            "     0 output errors, 0 collisions, 0 interface resets\n"
        )
        conn = _MockConn({"show interfaces": clean})
        result = check_interface_errors(conn, "cisco_ios")
        assert result["with_errors"] == 0
        assert result["alert"] is False

    def test_cisco_errors_trigger_alert(self):
        conn = _MockConn({"show interfaces": CISCO_INTERFACES_OUTPUT})
        result = check_interface_errors(conn, "cisco_ios")
        assert result["with_errors"] == 1
        assert result["alert"] is True

    def test_nokia_errors_trigger_alert(self):
        conn = _MockConn({"show port detail": NOKIA_INTERFACES_OUTPUT})
        result = check_interface_errors(conn, "nokia_sros")
        assert result["with_errors"] == 1
        assert result["alert"] is True

    def test_result_keys_present(self):
        conn = _MockConn({"show interfaces": CISCO_INTERFACES_OUTPUT})
        result = check_interface_errors(conn, "cisco_ios")
        for key in ("interfaces", "total", "with_errors", "alert"):
            assert key in result


class TestCheckLogs:
    def test_cisco_critical_events(self):
        conn = _MockConn({"show logging": CISCO_LOG_OUTPUT})
        result = check_logs(conn, "cisco_ios")
        assert result["critical_count"] == 1  # severity 2
        assert result["major_count"] == 1  # severity 3
        assert result["alert"] is True

    def test_cisco_no_alert_for_info_only(self):
        conn = _MockConn({"show logging": CISCO_LOG_ONLY_INFO})
        result = check_logs(conn, "cisco_ios")
        assert result["alert"] is False

    def test_nokia_events(self):
        conn = _MockConn({"show log 99": NOKIA_LOG_OUTPUT})
        result = check_logs(conn, "nokia_sros")
        assert result["critical_count"] == 1
        assert result["major_count"] == 1
        assert result["alert"] is True

    def test_result_keys_present(self):
        conn = _MockConn({"show logging": CISCO_LOG_OUTPUT})
        result = check_logs(conn, "cisco_ios")
        for key in ("critical_count", "major_count", "events", "alert"):
            assert key in result


# ===========================================================================
# run_health_check — integration using a patched DeviceConnection
# ===========================================================================


class TestRunHealthCheck:
    def test_success_structure(self, monkeypatch):
        """run_health_check returns all expected keys on success."""

        class _FakeConn:
            def __enter__(self):
                return _MockConn(
                    {
                        "show processes cpu": CISCO_CPU_OUTPUT,
                        "show processes memory": CISCO_MEM_OUTPUT,
                        "show interfaces": CISCO_INTERFACES_OUTPUT,
                        "show logging": CISCO_LOG_ONLY_INFO,
                    }
                )

            def __exit__(self, *_):
                pass

        monkeypatch.setattr("netops.check.health.DeviceConnection", lambda _p: _FakeConn())

        params = ConnectionParams(host="10.0.0.1", username="admin", device_type="cisco_ios")
        result = run_health_check(params)

        assert result["success"] is True
        assert result["host"] == "10.0.0.1"
        assert "timestamp" in result
        assert "checks" in result
        for key in ("cpu", "memory", "interface_errors", "logs"):
            assert key in result["checks"]

    def test_connection_failure(self, monkeypatch):
        """Connection failure produces error key and success=False."""

        def _fail(_p):
            raise ConnectionError("Connection refused")

        monkeypatch.setattr("netops.check.health.DeviceConnection", _fail)

        params = ConnectionParams(host="10.0.0.2", username="admin", device_type="cisco_ios")
        result = run_health_check(params)

        assert result["success"] is False
        assert result["error"] is not None

    def test_overall_alert_true_when_cpu_fires(self, monkeypatch):
        class _FakeConn:
            def __enter__(self):
                return _MockConn(
                    {
                        "show processes cpu": CISCO_CPU_HIGH,
                        "show processes memory": CISCO_MEM_OUTPUT,
                        "show interfaces": "",
                        "show logging": CISCO_LOG_ONLY_INFO,
                    }
                )

            def __exit__(self, *_):
                pass

        monkeypatch.setattr("netops.check.health.DeviceConnection", lambda _p: _FakeConn())

        params = ConnectionParams(host="10.0.0.3", username="admin", device_type="cisco_ios")
        result = run_health_check(params, cpu_threshold=80.0)

        assert result["overall_alert"] is True

    def test_overall_alert_false_when_all_clear(self, monkeypatch):
        class _FakeConn:
            def __enter__(self):
                return _MockConn(
                    {
                        "show processes cpu": CISCO_CPU_OUTPUT,
                        "show processes memory": CISCO_MEM_OUTPUT,
                        "show interfaces": "",
                        "show logging": CISCO_LOG_ONLY_INFO,
                    }
                )

            def __exit__(self, *_):
                pass

        monkeypatch.setattr("netops.check.health.DeviceConnection", lambda _p: _FakeConn())

        params = ConnectionParams(host="10.0.0.4", username="admin", device_type="cisco_ios")
        result = run_health_check(
            params, cpu_threshold=DEFAULT_CPU_THRESHOLD, mem_threshold=DEFAULT_MEM_THRESHOLD
        )

        assert result["overall_alert"] is False

    def test_default_thresholds(self, monkeypatch):
        class _FakeConn:
            def __enter__(self):
                return _MockConn({})

            def __exit__(self, *_):
                pass

        monkeypatch.setattr("netops.check.health.DeviceConnection", lambda _p: _FakeConn())

        params = ConnectionParams(host="10.0.0.5", username="admin", device_type="cisco_ios")
        result = run_health_check(params)

        assert result["checks"]["cpu"]["threshold"] == DEFAULT_CPU_THRESHOLD
        assert result["checks"]["memory"]["threshold"] == DEFAULT_MEM_THRESHOLD


# ===========================================================================
# parse_cpu_brocade
# ===========================================================================


class TestParseCpuBrocade:
    def test_returns_dict(self):
        assert isinstance(parse_cpu_brocade(BROCADE_CPU_OUTPUT), dict)

    def test_all_fields_present(self):
        result = parse_cpu_brocade(BROCADE_CPU_OUTPUT)
        assert "one_second" in result
        assert "five_seconds" in result
        assert "one_minute" in result

    def test_correct_values(self):
        result = parse_cpu_brocade(BROCADE_CPU_OUTPUT)
        assert result["one_second"] == 15.0
        assert result["five_seconds"] == 12.0
        assert result["one_minute"] == 8.0

    def test_empty_returns_empty_dict(self):
        assert parse_cpu_brocade(BROCADE_CPU_EMPTY) == {}

    def test_blank_string_returns_empty_dict(self):
        assert parse_cpu_brocade("") == {}


# ===========================================================================
# parse_memory_brocade
# ===========================================================================


class TestParseMemoryBrocade:
    def test_returns_dict(self):
        assert isinstance(parse_memory_brocade(BROCADE_MEM_OUTPUT), dict)

    def test_all_fields_present(self):
        result = parse_memory_brocade(BROCADE_MEM_OUTPUT)
        for key in ("total", "used", "free", "utilization"):
            assert key in result

    def test_correct_values(self):
        result = parse_memory_brocade(BROCADE_MEM_OUTPUT)
        assert result["total"] == 1048576 * 1024
        assert result["used"] == 512000 * 1024
        assert result["free"] == 536576 * 1024

    def test_utilization_is_percentage(self):
        result = parse_memory_brocade(BROCADE_MEM_OUTPUT)
        assert 0.0 <= result["utilization"] <= 100.0

    def test_utilization_calculation(self):
        result = parse_memory_brocade(BROCADE_MEM_OUTPUT)
        expected = round(512000 / 1048576 * 100, 2)
        assert result["utilization"] == expected

    def test_empty_returns_empty_dict(self):
        assert parse_memory_brocade(BROCADE_MEM_EMPTY) == {}

    def test_blank_string_returns_empty_dict(self):
        assert parse_memory_brocade("") == {}


# ===========================================================================
# parse_interface_errors_brocade
# ===========================================================================


class TestParseInterfaceErrorsBrocade:
    def test_returns_list(self):
        assert isinstance(parse_interface_errors_brocade(BROCADE_INTERFACES_OUTPUT), list)

    def test_correct_interface_count(self):
        result = parse_interface_errors_brocade(BROCADE_INTERFACES_OUTPUT)
        assert len(result) == 2

    def test_clean_interface_no_errors(self):
        iface = parse_interface_errors_brocade(BROCADE_INTERFACES_OUTPUT)[0]
        assert iface["name"] == "GigabitEthernet1/1/1"
        assert iface["input_errors"] == 0
        assert iface["crc"] == 0
        assert iface["output_errors"] == 0
        assert iface["drops"] == 0
        assert iface["has_errors"] is False

    def test_interface_with_errors(self):
        iface = parse_interface_errors_brocade(BROCADE_INTERFACES_OUTPUT)[1]
        assert iface["name"] == "GigabitEthernet1/1/2"
        assert iface["input_errors"] == 7
        assert iface["crc"] == 4
        assert iface["output_errors"] == 2
        assert iface["drops"] == 5
        assert iface["has_errors"] is True

    def test_required_keys_present(self):
        for iface in parse_interface_errors_brocade(BROCADE_INTERFACES_OUTPUT):
            for key in ("name", "input_errors", "output_errors", "crc", "drops", "has_errors"):
                assert key in iface

    def test_empty_input_returns_empty_list(self):
        assert parse_interface_errors_brocade(BROCADE_INTERFACES_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_interface_errors_brocade("") == []


# ===========================================================================
# parse_logs_brocade
# ===========================================================================


class TestParseLogsBrocade:
    def test_returns_list(self):
        assert isinstance(parse_logs_brocade(BROCADE_LOG_OUTPUT), list)

    def test_correct_event_count(self):
        # CRIT, ERR, WARN all match
        events = parse_logs_brocade(BROCADE_LOG_OUTPUT)
        assert len(events) == 3

    def test_critical_normalised(self):
        events = parse_logs_brocade(BROCADE_LOG_OUTPUT)
        assert events[0]["severity"] == "CRITICAL"

    def test_error_normalised(self):
        events = parse_logs_brocade(BROCADE_LOG_OUTPUT)
        assert events[1]["severity"] == "ERROR"

    def test_warning_normalised(self):
        events = parse_logs_brocade(BROCADE_LOG_OUTPUT)
        assert events[2]["severity"] == "WARNING"

    def test_event_fields(self):
        events = parse_logs_brocade(BROCADE_LOG_OUTPUT)
        for event in events:
            for key in ("timestamp", "severity", "message"):
                assert key in event

    def test_empty_returns_empty_list(self):
        assert parse_logs_brocade(BROCADE_LOG_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_logs_brocade("") == []


# ===========================================================================
# check_* Brocade branches
# ===========================================================================


class TestCheckCpuBrocade:
    def test_brocade_below_threshold(self):
        conn = _MockConn({"show cpu": BROCADE_CPU_OUTPUT})
        result = check_cpu(conn, "brocade_fastiron", threshold=80.0)
        assert result["utilization"] == 8.0
        assert result["alert"] is False

    def test_brocade_nos_below_threshold(self):
        conn = _MockConn({"show cpu": BROCADE_CPU_OUTPUT})
        result = check_cpu(conn, "brocade_nos", threshold=80.0)
        assert result["utilization"] == 8.0
        assert result["alert"] is False

    def test_brocade_threshold_included(self):
        conn = _MockConn({"show cpu": BROCADE_CPU_OUTPUT})
        result = check_cpu(conn, "brocade_fastiron", threshold=80.0)
        assert result["threshold"] == 80.0


class TestCheckMemoryBrocade:
    def test_brocade_utilization(self):
        conn = _MockConn({"show memory": BROCADE_MEM_OUTPUT})
        result = check_memory(conn, "brocade_fastiron", threshold=85.0)
        expected = round(512000 / 1048576 * 100, 2)
        assert result["utilization"] == expected
        assert result["alert"] is False

    def test_brocade_threshold_included(self):
        conn = _MockConn({"show memory": BROCADE_MEM_OUTPUT})
        result = check_memory(conn, "brocade_fastiron", threshold=85.0)
        assert result["threshold"] == 85.0


class TestCheckInterfaceErrorsBrocade:
    def test_brocade_no_errors(self):
        clean = (
            "GigabitEthernet1/1/1 is up, line protocol is up\n"
            "  0 input errors, 0 CRC, 0 alignment errors, 0 runts, 0 giants\n"
            "  0 output errors, 0 output discards\n"
        )
        conn = _MockConn({"show interfaces": clean})
        result = check_interface_errors(conn, "brocade_fastiron")
        assert result["with_errors"] == 0
        assert result["alert"] is False

    def test_brocade_errors_trigger_alert(self):
        conn = _MockConn({"show interfaces": BROCADE_INTERFACES_OUTPUT})
        result = check_interface_errors(conn, "brocade_fastiron")
        assert result["with_errors"] == 1
        assert result["alert"] is True


class TestCheckLogsBrocade:
    def test_brocade_critical_and_error_events(self):
        conn = _MockConn({"show logging": BROCADE_LOG_OUTPUT})
        result = check_logs(conn, "brocade_fastiron")
        assert result["critical_count"] == 1  # CRITICAL
        assert result["major_count"] == 1  # ERROR maps to major
        assert result["alert"] is True

    def test_brocade_no_alert_for_empty_log(self):
        conn = _MockConn({"show logging": BROCADE_LOG_EMPTY})
        result = check_logs(conn, "brocade_fastiron")
        assert result["alert"] is False

    def test_brocade_result_keys_present(self):
        conn = _MockConn({"show logging": BROCADE_LOG_OUTPUT})
        result = check_logs(conn, "brocade_fastiron")
        for key in ("critical_count", "major_count", "events", "alert"):
            assert key in result
