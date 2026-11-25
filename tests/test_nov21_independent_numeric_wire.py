"""FR-027/033 retry: complete native TargetOutcome, retaining safe parsed raw facts.

The original blanket-raw assertion is retained unchanged in its original file.
The original LLD and nov20-offline-authority disposition permit bounded numeric
provenance, not device text, secrets, unknown fields or inconsistent measurements.
External Netmiko is mocked; this does not qualify real Ansible or a device.
"""

from __future__ import annotations

import copy

import pytest

from netops.ansible import _action_health as health
from netops.ansible import action_runtime as action
from netops.ansible import contracts as c
from netops.ansible.controller_protocol import ProtocolError
from netops.ansible.worker_broker import _safe_action_result

SECRET = "nov21-independent-private-sentinel"
CPU = "CPU utilization for five seconds: 12%/1%; one minute: 12%; five minutes: 10%"
MEMORY = "Processor  ABCDEF  1000  250  750"
INTERFACES = (
    "GigabitEthernet0/0 is up, line protocol is up\n"
    "  0 input errors, 0 CRC, 0 frame\n"
    "  0 output errors, 0 collisions\n"
)


@pytest.fixture
def native_result(monkeypatch):
    observed = []
    responses = {
        "show processes cpu": CPU,
        "show processes memory": MEMORY,
        "show interfaces": INTERFACES,
    }

    class Device:
        closed = False

        def send_command(self, command, **kwargs):
            observed.append(command)
            return responses[command]

        def disconnect(self):
            self.closed = True

    device = Device()

    def connect(**parameters):
        assert parameters["password"] == SECRET
        assert parameters["ssh_strict"] is True
        assert parameters["session_log"] is None
        return device

    monkeypatch.setattr("netmiko.ConnectHandler", connect)
    monkeypatch.setattr(
        action._StrictConnection, "_files",
        staticmethod(lambda _: (None, "EXTERNAL-PORT-NOT-QUALIFIED")),
    )
    credential = {
        "host": "192.0.2.50", "port": 22, "vendor": "cisco_ios",
        "fields": {"username": "offline-fixture", "password": SECRET},
        "known_hosts_ref": "EXTERNAL-PORT-NOT-QUALIFIED", "key_ref": None,
    }
    selection = health._HealthSelection(("cpu", "memory", "interfaces"), 70.0, 80.0)
    assert c.canonical_bytes(c.public_object(selection.wire())).decode() == (
        '{"checks":["cpu","memory","interfaces"],"cpu_threshold":70.0,"memory_threshold":80.0}'
    )
    result = action._NativeActions().run_selected("gather", credential, None, selection)
    assert device.closed
    assert observed == ["show processes cpu", "show processes memory", "show interfaces"]
    return result


def test_ac002_ac008_complete_native_numeric_target_literal_retry(native_result):
    target = _safe_action_result(native_result, "router", "gather")
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
        '"native_payload":{"health":{"checks":{'
        '"cpu":{"alert":false,"parser":"netops.check.cisco",'
        '"raw":{"five_minutes":10.0,"five_seconds":12.0,"one_minute":12.0},'
        '"status":"succeeded","threshold":70.0,"utilization":12.0,"vendor":"cisco_ios"},'
        '"interfaces":{"alert":false,"parser":"netops.check.cisco","status":"succeeded",'
        '"total":1,"vendor":"cisco_ios","with_errors":0},'
        '"memory":{"alert":false,"parser":"netops.check.cisco",'
        '"raw":{"free":750,"total":1000,"used":250,"utilization":25.0},'
        '"status":"succeeded","threshold":80.0,"utilization":25.0,"vendor":"cisco_ios"}},'
        '"connection_cleanup_failed":false,"overall_alert":false},"line_count":5},'
        '"remote_state":"unchanged","selected":true,"status":"succeeded",'
        '"target_id":"router","unapplied_effects":[]}'
    )
    assert SECRET not in c.canonical_bytes(target).decode()


@pytest.mark.parametrize("location", ["envelope", "health", "check", "raw"])
@pytest.mark.parametrize("key", ["password", "stdout", "command", "unknown"])
def test_ac006_ac008_native_secret_text_or_extra_is_rejected_not_dropped(
    native_result, location, key, caplog,
):
    value = copy.deepcopy(native_result)
    containers = {
        "envelope": value,
        "health": value["health"],
        "check": value["health"]["checks"]["cpu"],
        "raw": value["health"]["checks"]["cpu"]["raw"],
    }
    containers[location][key] = SECRET
    with pytest.raises(ProtocolError) as caught:
        _safe_action_result(value, "router", "gather")
    assert SECRET not in str(caught.value) + caplog.text


@pytest.mark.parametrize("bad", [
    True, None, SECRET, -1.0, 101.0, float("nan"), float("inf"),
])
def test_ac008_native_impossible_or_malformed_numeric_raw_is_not_healthy(native_result, bad):
    value = copy.deepcopy(native_result)
    value["health"]["checks"]["cpu"]["raw"]["one_minute"] = bad
    with pytest.raises(ProtocolError):
        _safe_action_result(value, "router", "gather")
