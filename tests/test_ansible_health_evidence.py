"""Synthetic contract tests for fail-closed Ansible CPU/memory facts (PLU-43).

No live-device I/O. They validate parsed evidence, not network health.
"""

from __future__ import annotations

import pytest

from netops.ansible.modules.netops_facts import _gather_health


CISCO_CPU = "CPU utilization for five seconds: 12%/3%; one minute: 8%; five minutes: 6%"
CISCO_MEMORY = "Processor 7F2B3C18 1000 400 600"
NOKIA_CPU = "CPU Usage : 5% 12%"
NOKIA_MEMORY = "Total In Use : 400\nTotal Available : 600"


class MockConn:
    def __init__(
        self, device_type: str, replies: dict[str, str], fail: str | None = None
    ) -> None:
        self.device_type = device_type
        self.replies = replies
        self.fail = fail
        self.commands: list[str] = []

    def send_command(self, command: str) -> str:
        self.commands.append(command)
        if self.fail and self.fail in command:
            raise RuntimeError("synthetic transport failure")
        return self.replies.get(command, "")


def _cisco(cpu: str = CISCO_CPU, memory: str = CISCO_MEMORY) -> MockConn:
    return MockConn(
        "cisco_ios",
        {
            "show processes cpu | include utilization": cpu,
            "show processes memory | include Processor": memory,
        },
    )


def _nokia(cpu: str = NOKIA_CPU, memory: str = NOKIA_MEMORY) -> MockConn:
    return MockConn(
        "nokia_sros",
        {"show system cpu": cpu, "show system memory-pools": memory},
    )


@pytest.mark.parametrize("vendor", ["cisco_ios", "cisco_xe"])
def test_cisco_observed_values_follow_actual_parser_keys(vendor: str) -> None:
    conn = _cisco()
    conn.device_type = vendor
    facts = _gather_health(conn)
    assert facts["cpu_percent"] == 12.0
    assert facts["memory_percent"] == 40.0
    assert facts["memory_total_bytes"] == 1000
    assert facts["memory_used_bytes"] == 400
    assert facts["evidence"] == {"cpu": "OBSERVED", "memory": "OBSERVED"}
    assert facts["evidence_complete"] is True


def test_nokia_uses_avg_and_total_used_keys() -> None:
    facts = _gather_health(_nokia())
    assert facts["cpu_percent"] == 5.0
    assert facts["memory_percent"] == 40.0
    assert facts["evidence_complete"] is True


def test_observed_zero_is_not_missing() -> None:
    conn = _cisco(
        "CPU utilization for five seconds: 0%/0%; one minute: 0%; five minutes: 0%",
        "Processor 7F2B3C18 1000 0 1000",
    )
    facts = _gather_health(conn)
    assert facts["cpu_percent"] == 0.0
    assert facts["memory_percent"] == 0.0
    assert facts["evidence_complete"] is True


@pytest.mark.parametrize("cpu", ["", "garbled", "CPU utilization for five seconds: 120%/0%; one minute: 8%; five minutes: 6%"])
def test_unobserved_or_invalid_cpu_is_unknown(cpu: str) -> None:
    facts = _gather_health(_cisco(cpu=cpu))
    assert "cpu_percent" not in facts
    assert facts["evidence"]["cpu"] == "UNKNOWN"
    assert facts["evidence"]["memory"] == "OBSERVED"
    assert facts["evidence_complete"] is False


@pytest.mark.parametrize(
    "memory",
    ["", "garbled", "Processor 7F2B3C18 0 0 0", "Processor 7F2B3C18 1000 1200 0"],
)
def test_unobserved_or_invalid_memory_is_unknown(memory: str) -> None:
    facts = _gather_health(_cisco(memory=memory))
    assert "memory_percent" not in facts
    assert "memory_total_bytes" not in facts
    assert facts["evidence"]["memory"] == "UNKNOWN"
    assert facts["evidence"]["cpu"] == "OBSERVED"
    assert facts["evidence_complete"] is False


def test_collection_exception_is_unknown_without_error_leak() -> None:
    conn = _cisco()
    conn.fail = "cpu"
    facts = _gather_health(conn)
    assert facts["evidence"]["cpu"] == "UNKNOWN"
    assert facts["evidence"]["cpu_reason"] == "collection_failed"
    assert "cpu_percent" not in facts
    assert facts["memory_percent"] == 40.0
    assert facts["evidence_complete"] is False


def test_unsupported_vendor_does_not_send_cisco_commands() -> None:
    conn = MockConn("brocade_fastiron", {})
    facts = _gather_health(conn)
    assert conn.commands == []
    assert facts["evidence"] == {"cpu": "UNSUPPORTED", "memory": "UNSUPPORTED"}
    assert facts["evidence_complete"] is False
    assert "cpu_percent" not in facts


def test_non_cisco_nokia_vendor_has_no_guessing_fallback() -> None:
    conn = MockConn("generic_linux", {})
    assert _gather_health(conn)["evidence_complete"] is False
    assert conn.commands == []
