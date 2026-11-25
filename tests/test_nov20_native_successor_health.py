"""AC-008 source-only actual Cisco/Junos health owners; mock external Netmiko."""

from __future__ import annotations

import pytest

from netops.ansible import _action_health as health
from netops.ansible import action_runtime as action
from netops.ansible import contracts as c
from netops.ansible.controller_protocol import ProtocolError
from netops.ansible.worker_broker import _safe_action_result

CPU = "CPU utilization for five seconds: 12%/1%; one minute: 12%; five minutes: 10%"
MEMORY = "Processor  ABCDEF  1000  250  750"
INTERFACES = """GigabitEthernet0/0 is up, line protocol is up
  0 input errors, 0 CRC, 0 frame
  0 output errors, 0 collisions
"""
JUNOS = """Routing Engine status:
  Slot 0:
  Current state Master
  Memory utilization 25 percent
  CPU utilization:
    User 20 percent
    Background 0 percent
    Kernel 15 percent
    Interrupt 0 percent
    Idle 65 percent
"""
SECRET = "source-only-private-credential-never-log"


class SourceFakeNetmiko:
    """External device port only; real connection, command and parser owners run."""

    def __init__(self):
        self.responses = {
            "show processes cpu": CPU,
            "show processes memory": MEMORY,
            "show interfaces": INTERFACES,
            "show chassis routing-engine": JUNOS,
        }
        self.commands = []
        self.closed = False
        self.fail_cleanup = False

    def send_command(self, command, **kwargs):
        self.commands.append(command)
        value = self.responses[command]
        if isinstance(value, BaseException):
            raise value
        return value

    def disconnect(self):
        self.closed = True
        if self.fail_cleanup:
            raise RuntimeError(SECRET)


@pytest.fixture
def external_ports(monkeypatch):
    device = SourceFakeNetmiko()
    connections = []

    def connect(**parameters):
        # Check actual strict Netmiko options without storing raw credentials.
        assert parameters["allow_agent"] is parameters["system_host_keys"] is False
        assert parameters["ssh_strict"] is parameters["alt_host_keys"] is True
        assert parameters["session_log"] is None
        assert parameters["password"] == SECRET
        connections.append(parameters["device_type"])
        return device

    monkeypatch.setattr("netmiko.ConnectHandler", connect)
    # Explicitly mocked credential-file port: not real host-key/ACL qualification.
    monkeypatch.setattr(
        action._StrictConnection, "_files",
        staticmethod(lambda credential: (None, "SOURCE_ONLY-known-hosts-port")),
    )
    credential = {
        "host": "192.0.2.50", "port": 22, "vendor": "cisco_ios",
        "fields": {"username": "source-only-user", "password": SECRET},
        "known_hosts_ref": "SOURCE_ONLY-known-hosts-port", "key_ref": None,
    }
    return device, connections, credential


def gather(external_ports, checks=("cpu", "memory", "interfaces"), **thresholds):
    device, _, credential = external_ports
    result = action._NativeActions().run_selected(
        "gather", credential, None, health._HealthSelection(checks, **thresholds),
    )
    assert device.closed
    assert "show version" not in device.commands
    return result


def test_t24_actual_selected_native_health_request_and_response_wire_literals(external_ports):
    selection = health._HealthSelection(("cpu", "memory", "interfaces"), 70.0, 80.0)
    assert c.canonical_bytes(c.public_object(selection.wire())).decode() == (
        '{"checks":["cpu","memory","interfaces"],"cpu_threshold":70.0,"memory_threshold":80.0}'
    )
    result = gather(external_ports, cpu_threshold=70.0, memory_threshold=80.0)
    device, connections, _ = external_ports
    assert connections == ["cisco_ios"]
    assert device.commands == ["show processes cpu", "show processes memory", "show interfaces"]
    assert c.canonical_bytes(c.public_object(result["health"])).decode() == (
        '{"checks":{"cpu":{"alert":false,"parser":"netops.check.cisco",'
        '"raw":{"five_minutes":10.0,"five_seconds":12.0,"one_minute":12.0},"status":"succeeded",'
        '"threshold":70.0,"utilization":12.0,"vendor":"cisco_ios"},'
        '"interfaces":{"alert":false,"parser":"netops.check.cisco","status":"succeeded",'
        '"total":1,"vendor":"cisco_ios","with_errors":0},'
        '"memory":{"alert":false,"parser":"netops.check.cisco",'
        '"raw":{"free":750,"total":1000,"used":250,"utilization":25.0},"status":"succeeded",'
        '"threshold":80.0,"utilization":25.0,"vendor":"cisco_ios"}},'
        '"connection_cleanup_failed":false,"overall_alert":false}'
    )
    target = _safe_action_result(result, "router", "gather")
    assert target.status == c.OutcomeStatus.SUCCEEDED
    assert [finding.result for finding in target.findings] == ["pass", "pass", "pass"]
    assert not target.changed and target.remote_state == "unchanged"
    assert SECRET not in c.canonical_bytes(target).decode()
    assert c.canonical_bytes(target).decode() == (
        '{"attempted":true,"changed":false,"errors":[],"findings":['
        '{"category":"health","check":"cpu","expected":null,"parser":"netops.check.cisco",'
        '"raw_source_ref":null,"reading":12.0,"result":"pass","severity":"info",'
        '"threshold":70.0,"vendor":"cisco_ios"},'
        '{"category":"health","check":"memory","expected":null,"parser":"netops.check.cisco",'
        '"raw_source_ref":null,"reading":25.0,"result":"pass","severity":"info",'
        '"threshold":80.0,"vendor":"cisco_ios"},'
        '{"category":"health","check":"interfaces","expected":null,"parser":"netops.check.cisco",'
        '"raw_source_ref":null,"reading":0,"result":"pass","severity":"info",'
        '"threshold":null,"vendor":"cisco_ios"}],'
        '"native_payload":{"health":{"checks":{"cpu":{"alert":false,"parser":"netops.check.cisco",'
        '"raw":{"five_minutes":10.0,"five_seconds":12.0,"one_minute":12.0},"status":"succeeded",'
        '"threshold":70.0,"utilization":12.0,"vendor":"cisco_ios"},'
        '"interfaces":{"alert":false,"parser":"netops.check.cisco","status":"succeeded",'
        '"total":1,"vendor":"cisco_ios","with_errors":0},'
        '"memory":{"alert":false,"parser":"netops.check.cisco",'
        '"raw":{"free":750,"total":1000,"used":250,"utilization":25.0},"status":"succeeded",'
        '"threshold":80.0,"utilization":25.0,"vendor":"cisco_ios"}},'
        '"connection_cleanup_failed":false,"overall_alert":false},"line_count":5},'
        '"remote_state":"unchanged","selected":true,"status":"succeeded","target_id":"router",'
        '"unapplied_effects":[]}'
    )


@pytest.mark.parametrize("reading", [69, 70, 71])
def test_t24_selected_inclusive_threshold_preserves_other_successful_facts(
    external_ports, reading,
):
    device, _, _ = external_ports
    device.responses["show processes cpu"] = CPU.replace("one minute: 12%", f"one minute: {reading}%")
    result = gather(external_ports, cpu_threshold=70.0, memory_threshold=80.0)
    target = _safe_action_result(result, "router", "gather")
    assert target.findings[0].reading == float(reading)
    assert target.findings[0].threshold == 70.0
    assert target.findings[0].result == ("pass" if reading < 70 else "alert")
    assert target.findings[1].reading == 25.0
    assert target.findings[1].result == target.findings[2].result == "pass"
    assert target.status == (c.OutcomeStatus.SUCCEEDED if reading < 70 else c.OutcomeStatus.FAILED)


@pytest.mark.parametrize(
    "reading", ["", "malformed", CPU.replace("12%", "140%"), 17,
                RuntimeError(SECRET), "x" * (512 * 1024 + 1)],
    ids=["empty", "malformed", "out-of-range", "wrong-type", "external-error", "oversize"],
)
def test_t24_missing_cpu_is_unknown_not_zero_and_other_selected_readings_survive(
    external_ports, reading, caplog,
):
    device, _, _ = external_ports
    device.responses["show processes cpu"] = reading
    result = gather(external_ports)
    target = _safe_action_result(result, "router", "gather")
    assert target.status == c.OutcomeStatus.FAILED
    assert target.findings[0].result == "unknown"
    assert target.findings[0].reading is None
    assert target.findings[1].reading == 25.0 and target.findings[1].result == "pass"
    assert target.findings[2].reading == 0 and target.findings[2].result == "pass"
    assert any(error.reason == c.ReasonCode.READING_UNAVAILABLE for error in target.errors)
    assert SECRET not in caplog.text + c.canonical_bytes(target).decode()


@pytest.mark.parametrize("command", ["show processes memory", "show interfaces"])
def test_t24_malformed_memory_or_interfaces_never_turns_into_healthy_zero(
    external_ports, command,
):
    device, _, _ = external_ports
    device.responses[command] = "no parseable measurements"
    target = _safe_action_result(gather(external_ports), "router", "gather")
    assert target.status == c.OutcomeStatus.FAILED
    finding = target.findings[1 if command == "show processes memory" else 2]
    assert finding.result == "unknown" and finding.reading is None
    assert target.findings[0].reading == 12.0


def test_t24_actual_junos_selected_cpu_memory_are_numeric_not_version_only(external_ports):
    device, _, credential = external_ports
    credential["vendor"] = "juniper_junos"
    result = gather(external_ports, checks=("cpu", "memory"))
    target = _safe_action_result(result, "router", "gather")
    assert device.commands == ["show chassis routing-engine", "show chassis routing-engine"]
    assert target.status == c.OutcomeStatus.SUCCEEDED
    assert [finding.reading for finding in target.findings] == [35.0, 25.0]
    assert all(finding.vendor == "juniper_junos" for finding in target.findings)
    assert all(finding.parser == "netops.check.juniper" for finding in target.findings)


@pytest.mark.parametrize("vendor,checks", [
    ("cisco_ios", ("ospf",)), ("juniper_junos", ("vlans",)), ("unknown", ("cpu",)),
])
def test_t24_unsupported_selected_checks_make_no_external_connection(external_ports, vendor, checks):
    device, connections, credential = external_ports
    credential["vendor"] = vendor
    result = action._NativeActions().run_selected(
        "gather", credential, None, health._HealthSelection(checks),
    )
    target = _safe_action_result(result, "router", "gather")
    assert target.status == c.OutcomeStatus.UNSUPPORTED
    assert not target.attempted and not target.changed
    assert device.commands == connections == []


def test_t24_selected_check_cancellation_preserves_cpu_and_stops_later_commands(external_ports):
    device, _, credential = external_ports
    calls = []

    def check():
        calls.append(True)
        if len(calls) >= 3:
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)

    result = action._NativeActions().run_selected(
        "gather", credential, None, health._HealthSelection(("cpu", "memory", "interfaces")), check,
    )
    target = _safe_action_result(result, "router", "gather")
    assert device.commands == ["show processes cpu"]
    assert device.closed
    assert target.status == c.OutcomeStatus.FAILED
    assert target.findings[0].reading == 12.0
    assert [finding.result for finding in target.findings[1:]] == ["unknown", "unknown"]


def test_t04_health_cleanup_failure_retains_measurements_and_never_logs_secret(external_ports, caplog):
    device, _, _ = external_ports
    device.fail_cleanup = True
    result = gather(external_ports)
    target = _safe_action_result(result, "router", "gather")
    assert result["health"]["connection_cleanup_failed"] is True
    assert target.status == c.OutcomeStatus.FAILED
    assert [finding.reading for finding in target.findings] == [12.0, 25.0, 0]
    assert SECRET not in caplog.text + c.canonical_bytes(target).decode()


@pytest.mark.parametrize("selection", [
    {"checks": ["show running-config"], "cpu_threshold": 80, "memory_threshold": 85},
    {"checks": [], "cpu_threshold": 80, "memory_threshold": 85},
    {"checks": ["cpu", "cpu"], "cpu_threshold": 80, "memory_threshold": 85},
    {"checks": ["cpu"], "cpu_threshold": True, "memory_threshold": 85},
    {"checks": ["cpu"], "cpu_threshold": float("nan"), "memory_threshold": 85},
    {"checks": ["cpu"], "cpu_threshold": 80, "memory_threshold": 85, "raw_command": "secret"},
])
def test_t24_private_selection_rejects_arbitrary_commands_and_invalid_bounds(selection):
    with pytest.raises(ProtocolError):
        health._HealthSelection.parse(selection)
