"""Actual native parsing through fake external Netmiko only; never SSH proof."""

from __future__ import annotations

import json

import pytest

from netops.ansible import _action_health as health
from netops.ansible import action_runtime as action
from netops.ansible import contracts as c
from netops.ansible.worker_broker import _safe_action_result
from tests.test_nov20_native_successor_health import SECRET
from tests.test_nov20_native_successor_health import external_ports as external_ports
from tests.test_nov20_producer_numeric_provenance import FAMILIES, callback

READINGS = {
    "cisco_ios": (
        "show processes cpu", "show processes memory",
        "CPU utilization for five seconds: 12%/1%; one minute: 12%; five minutes: 10%",
        "Processor  ABCDEF  1000  250  750",
    ),
    "cisco_xe": (
        "show processes cpu", "show processes memory",
        "CPU utilization for five seconds: 12%/1%; one minute: 12%; five minutes: 10%",
        "Processor  ABCDEF  1000  250  750",
    ),
    "juniper": (
        "show chassis routing-engine", "show chassis routing-engine",
        "Routing Engine status:\n  Slot 0:\n  Current state Master\n"
        "  Memory utilization 25 percent\n  CPU utilization:\n    User 10 percent\n"
        "    Kernel 2 percent\n    Idle 88 percent\n",
        None,
    ),
    "juniper_junos": (
        "show chassis routing-engine", "show chassis routing-engine",
        "Routing Engine status:\n  Slot 0:\n  Current state Master\n"
        "  Memory utilization 25 percent\n  CPU utilization:\n    User 10 percent\n"
        "    Kernel 2 percent\n    Idle 88 percent\n",
        None,
    ),
    "arista_eos": (
        "show version | json", "show version | json",
        '{"memTotal":1000,"memFree":750,"systemStats":{"cpuInfo":{"0":{"%idle":88}}},'
        '"serialNumber":"' + SECRET + '","modelName":"' + SECRET + '"}',
        None,
    ),
    "nokia_sros": (
        "show system cpu", "show system memory-pools",
        "CPU Usage : 12% 15%",
        "Total In Use : 250\nTotal Available : 750",
    ),
    "brocade_fastiron": (
        "show cpu", "show memory",
        "CPU Utilization:\n  1-second average: 14 percent\n"
        "  5-second average: 10 percent\n  60-second average: 12 percent",
        "Total DRAM: 1000 KBytes\nUsed DRAM: 250 KBytes\nFree DRAM: 750 KBytes",
    ),
    "paloalto_panos": (
        "show system resources follow duration 1", "show system resources follow duration 1",
        "%Cpu(s): 10.0 us, 2.0 sy, 0.0 ni, 88.0 id\n"
        "MiB Mem : 1000.0 total, 500.0 free, 250.0 used, 250.0 buff/cache",
        None,
    ),
}


@pytest.mark.parametrize("vendor", list(READINGS))
def test_ac008_native_vendor_owner_actual_parser_has_exact_minimized_numeric_raw(
    external_ports, vendor, caplog,
):
    device, connections, credential = external_ports
    credential["vendor"] = vendor
    cpu_command, memory_command, cpu_text, memory_text = READINGS[vendor]
    device.responses[cpu_command] = cpu_text
    device.responses[memory_command] = memory_text if memory_text is not None else cpu_text
    result = action._NativeActions().run_selected(
        "gather", credential, None, health._HealthSelection(("cpu", "memory"), 70.0, 80.0),
    )
    target = _safe_action_result(result, "router", "gather")
    assert target.status == c.OutcomeStatus.SUCCEEDED
    assert connections == [vendor]
    assert device.commands == [cpu_command, memory_command] and device.closed
    assert [finding.reading for finding in target.findings] == [12.0, 25.0]
    family = next(row for row in FAMILIES if row[0] == vendor)
    expected = callback(*family)
    # Native byte units are explicit, not normalized away by the callback.
    if vendor == "brocade_fastiron":
        expected["health"]["checks"]["memory"]["raw"] = {
            "total": 1024000, "used": 256000, "free": 768000, "utilization": 25.0,
        }
    if vendor == "paloalto_panos":
        expected["health"]["checks"]["memory"]["raw"] = {
            "total": 1048576000, "used": 262144000, "free": 524288000, "utilization": 25.0,
        }
    assert c.canonical_bytes(target.native_payload["health"]) == c.canonical_bytes(
        c.public_object(expected["health"]),
    )
    assert SECRET not in c.canonical_bytes(target).decode() + caplog.text
    assert not target.changed and target.remote_state == "unchanged"


@pytest.mark.parametrize("vendor", list(READINGS))
@pytest.mark.parametrize("bad", ["", "not a measurement", SECRET, "{}"])
def test_ac008_each_supported_native_owner_partial_reading_is_unknown_not_healthy_zero(
    external_ports, vendor, bad, caplog,
):
    device, _, credential = external_ports
    credential["vendor"] = vendor
    cpu_command, memory_command, cpu_text, memory_text = READINGS[vendor]
    device.responses[cpu_command] = bad
    if memory_command != cpu_command:
        device.responses[memory_command] = memory_text
    result = action._NativeActions().run_selected(
        "gather", credential, None, health._HealthSelection(("cpu", "memory")),
    )
    target = _safe_action_result(result, "router", "gather")
    assert target.status == c.OutcomeStatus.FAILED
    assert target.findings[0].result == "unknown" and target.findings[0].reading is None
    assert any(error.reason == c.ReasonCode.READING_UNAVAILABLE for error in target.errors)
    assert SECRET not in c.canonical_bytes(target).decode() + caplog.text
    assert device.closed
    if memory_command != cpu_command:
        assert target.findings[1].reading == 25.0
    else:
        assert all(finding.result == "unknown" for finding in target.findings)


def test_ac008_arista_private_metadata_does_not_cross_numeric_callback(external_ports):
    device, _, credential = external_ports
    credential["vendor"] = "arista_eos"
    cpu_command, _, text, _ = READINGS["arista_eos"]
    payload = json.loads(text)
    payload.update(password=SECRET, raw_command=SECRET, error_text=SECRET)
    device.responses[cpu_command] = json.dumps(payload)
    result = action._NativeActions().run_selected(
        "gather", credential, None, health._HealthSelection(("cpu", "memory")),
    )
    target = _safe_action_result(result, "router", "gather")
    assert target.status == c.OutcomeStatus.SUCCEEDED
    assert SECRET not in c.canonical_bytes(target).decode()
    checks = target.native_payload["health"]["checks"]
    assert set(checks["cpu"]["raw"]) == {"cpu_utilization"}
    assert set(checks["memory"]["raw"]) == {"total", "used", "utilization"}
