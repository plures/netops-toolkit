"""Regression tests for the Ansible interface fact command/parser contract.

Synthetic output only. Successful parsing is inventory evidence, not proof
that all requested interface error counters were actually observed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from netops.ansible.modules.netops_facts import _gather_interfaces


@dataclass
class FakeConnection:
    device_type: str
    output: str = ""
    fail: bool = False
    commands: list[str] = field(default_factory=list)

    def send_command(self, command: str) -> str:
        self.commands.append(command)
        if self.fail:
            raise OSError("synthetic device transport failure")
        return self.output


CISCO_DETAILED = """\
GigabitEthernet0/0 is up, line protocol is up
  5 input errors, 2 CRC, 0 frame, 0 overrun, 0 ignored
  3 output errors, 0 collisions, 0 interface resets
"""
CISCO_STATUS_TABLE = """\
Port       Name               Status       Vlan
Gi0/0                         connected    10
"""
NOKIA_PORTS = """\
Port  Admin State Link Port State
1/1/1 Up Yes Up 1514 1514
1/1/2 Down No Down 1514 1514
"""


@pytest.mark.parametrize("vendor", ["cisco_ios", "cisco_xe", "cisco_xr", "Cisco_IOS"])
def test_cisco_uses_detailed_cli_for_error_parser(vendor: str) -> None:
    conn = FakeConnection(vendor, CISCO_DETAILED)
    facts = _gather_interfaces(conn)
    assert conn.commands == ["show interfaces"]
    assert facts == [
        {
            "name": "GigabitEthernet0/0",
            "input_errors": 5,
            "output_errors": 3,
            "crc": 2,
            "drops": 0,
            "has_errors": True,
        }
    ]


@pytest.mark.parametrize("vendor", ["nokia_sros", "NOKIA_SROS"])
def test_nokia_uses_vendor_port_inventory(vendor: str) -> None:
    conn = FakeConnection(vendor, NOKIA_PORTS)
    facts = _gather_interfaces(conn)
    assert conn.commands == ["show port"]
    assert [item["name"] for item in facts] == ["1/1/1", "1/1/2"]
    assert [item["up"] for item in facts] == [True, False]


@pytest.mark.parametrize("vendor", ["juniper_junos", "paloalto_panos", "brocade_fastiron", ""])
def test_unsupported_vendor_never_receives_cisco_commands(vendor: str) -> None:
    conn = FakeConnection(vendor, CISCO_DETAILED)
    assert _gather_interfaces(conn) == []
    assert conn.commands == []


@pytest.mark.parametrize("vendor", ["cisco_ios", "nokia_sros"])
def test_transport_failure_yields_no_inventory_not_false_zero(vendor: str) -> None:
    conn = FakeConnection(vendor, fail=True)
    assert _gather_interfaces(conn) == []
    assert len(conn.commands) == 1


def test_cisco_status_table_is_not_accepted_as_error_counter_inventory() -> None:
    conn = FakeConnection("cisco_ios", CISCO_STATUS_TABLE)
    assert _gather_interfaces(conn) == []
    assert conn.commands == ["show interfaces"]


def test_cisco_empty_output_is_not_a_zero_error_observation() -> None:
    conn = FakeConnection("cisco_ios", "")
    assert _gather_interfaces(conn) == []
    assert conn.commands == ["show interfaces"]
