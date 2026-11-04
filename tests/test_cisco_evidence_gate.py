"""Fail-closed evidence checks for the legacy Cisco monitor (PLU-42).

These tests use synthetic CLI responses, not device or field qualification.
"""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from netops.check import cisco
from netops.core.connection import ConnectionParams


class StubConnection:
    def __init__(self, outputs: dict[str, str] | None = None):
        self.outputs = outputs or {}

    def send(self, command: str) -> str:
        return self.outputs.get(command, "")


@pytest.mark.parametrize(
    ("check", "command"),
    [
        (cisco.check_cisco_cpu, "show processes cpu"),
        (cisco.check_cisco_memory, "show processes memory"),
    ],
)
def test_missing_cpu_or_memory_metric_is_unknown(check, command):
    result = check(StubConnection({command: "router# unrelated output"}), 80.0)
    assert result["utilization"] is None
    assert result["alert"] is False
    assert result["error"]


@pytest.mark.parametrize(
    ("output", "expected_alert", "expected_unknown"),
    [
        ("GigabitEthernet0/0 is up, line protocol is up\n", False, True),
        (
            "GigabitEthernet0/0 is up, line protocol is up\n"
            " 0 input errors, 0 CRC, 0 frame\n"
            " 0 output errors, 0 collisions\n",
            False,
            False,
        ),
        (
            "GigabitEthernet0/0 is up, line protocol is up\n"
            " 5 input errors, 0 CRC\n",
            True,
            True,
        ),
    ],
)
def test_interface_counters_require_both_observed_directions(
    output, expected_alert, expected_unknown
):
    result = cisco.check_cisco_interfaces(StubConnection({"show interfaces": output}))
    assert result["alert"] is expected_alert
    assert bool(result.get("error")) is expected_unknown


@pytest.mark.parametrize(
    ("check", "command", "args"),
    [
        (cisco.check_cisco_logs, "show logging", ()),
        (cisco.check_cisco_bgp, "show ip bgp summary", ()),
        (cisco.check_cisco_ospf, "show ip ospf neighbor", ()),
        (cisco.check_cisco_environment, "show environment all", ()),
        (cisco.check_cisco_uptime, "show version", ()),
    ],
)
def test_blank_required_cisco_outputs_are_unknown(check, command, args):
    result = check(StubConnection({command: ""}), *args)
    assert result["alert"] is False
    assert result["error"]


class FakeContext:
    def __enter__(self):
        return StubConnection()

    def __exit__(self, *_args):
        return None


def run_with_check_evidence(monkeypatch, check_overrides: dict[str, dict]):
    monkeypatch.setattr(cisco, "DeviceConnection", lambda _params: FakeContext())
    for name, default in (
        ("check_cisco_cpu", {"alert": False, "utilization": 10.0}),
        ("check_cisco_memory", {"alert": False, "utilization": 10.0}),
        ("check_cisco_interfaces", {"alert": False, "with_errors": 0, "total": 1}),
        ("check_cisco_logs", {"alert": False, "critical_count": 0, "major_count": 0}),
        ("check_cisco_uptime", {"alert": False, "uptime": "1 day"}),
    ):
        evidence = check_overrides.get(name, default)
        monkeypatch.setattr(cisco, name, lambda *_args, v=evidence: v)
    params = ConnectionParams(
        host="example.test", username="u", device_type="cisco_ios"
    )
    return cisco.run_cisco_health_check(
        params, include_bgp=False, include_ospf=False, include_environment=False
    )


def test_successful_ssh_does_not_certify_missing_check(monkeypatch):
    r = run_with_check_evidence(
        monkeypatch,
        {"check_cisco_cpu": {"alert": False, "error": "CPU output garbled"}},
    )
    assert r["success"] is True
    assert r["overall_alert"] is False
    assert r["overall_unknown"] is True
    assert r["status"] == "UNKNOWN"


def test_known_alarm_and_unknown_are_both_preserved(monkeypatch):
    r = run_with_check_evidence(
        monkeypatch,
        {
            "check_cisco_cpu": {"alert": True, "utilization": 93.0},
            "check_cisco_memory": {"alert": False, "error": "missing metric"},
        },
    )
    assert r["overall_alert"] is True
    assert r["overall_unknown"] is True
    assert r["status"] == "ALERT"


def test_complete_synthetic_checks_are_healthy(monkeypatch):
    r = run_with_check_evidence(monkeypatch, {})
    assert r["status"] == "HEALTHY"
    assert r["overall_unknown"] is False
    assert r["overall_alert"] is False


def test_report_fail_closed_for_empty_targets_and_unknown():
    empty = cisco.build_cisco_health_report([])
    assert empty["overall_unknown"] is True
    assert empty["devices_unknown"] == 0
    partial = cisco.build_cisco_health_report(
        [
            {
                "success": True, "overall_alert": False, "overall_unknown": True,
                "checks": {"memory": {"alert": False, "error": "missing"}},
            },
            {"success": False, "overall_alert": False, "checks": {}, "error": "timeout"},
        ]
    )
    assert partial["devices"] == 2
    assert partial["devices_reachable"] == 1
    assert partial["devices_unknown"] == 2
    assert partial["overall_unknown"] is True


def test_cisco_cli_failure_gate_rejects_empty_inventory(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        cisco.Inventory, "from_file", lambda _path: SimpleNamespace(devices={})
    )
    monkeypatch.setattr(
        sys, "argv",
        ["netops.check.cisco", "--inventory", str(tmp_path / "empty.yaml"),
         "--json", "--fail-on-alert"],
    )
    with pytest.raises(SystemExit) as exc:
        cisco.main()
    assert exc.value.code == 1
    report = json.loads(capsys.readouterr().out)["report"]
    assert report["devices"] == 0
    assert report["overall_unknown"] is True


def test_cli_result_shows_unknown_without_claiming_healthy(capsys):
    cisco._print_result(
        {
            "host": "example.test", "timestamp": "2026-11-04T00:00:00Z",
            "success": True, "overall_alert": False, "overall_unknown": True,
            "checks": {"cpu": {"alert": False, "error": "no CPU sample"}},
        }
    )
    out = capsys.readouterr().out
    assert "UNKNOWN cpu: no CPU sample" in out
    assert "✅" not in out
