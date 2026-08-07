"""Tests for Arista EOS parsers (LLDP and VLAN)."""

from __future__ import annotations

from netops.parsers.arista import (
    parse_lldp_neighbors_eos,
    parse_lldp_neighbors_eos_text,
    parse_vlan_eos,
    parse_vlan_eos_text,
)

# ---------------------------------------------------------------------------
# LLDP JSON fixture
# ---------------------------------------------------------------------------

LLDP_JSON_DATA = {
    "lldpNeighbors": [
        {
            "port": "Ethernet1",
            "chassisId": "00:11:22:33:44:55",
            "neighborPort": "Ethernet1",
            "neighborDevice": "switch-1",
            "ttl": 120,
        },
        {
            "port": "Ethernet2",
            "chassisId": "00:11:22:33:44:66",
            "neighborPort": "ge-0/0/0",
            "neighborDevice": "router-2",
            "ttl": 120,
        },
    ]
}

LLDP_TEXT_OUTPUT = """\
Last table change time   : 0:05:23 ago
Number of table inserts  : 3
Number of table deletes  : 0
Number of table drops    : 0
Number of table age-outs : 0

Port          Neighbor Device ID       Neighbor Port ID    TTL
------------- ------------------------ ------------------- ----
Ethernet1     switch-1                 Ethernet1           120
Ethernet2     router-2                 ge-0/0/0            120
Ethernet49    nokia-3                  1/1/1               120
"""

LLDP_TEXT_EMPTY = """\
Last table change time   : 0:00:00 ago
Number of table inserts  : 0

Port          Neighbor Device ID       Neighbor Port ID    TTL
------------- ------------------------ ------------------- ----
"""

# ---------------------------------------------------------------------------
# VLAN JSON fixture
# ---------------------------------------------------------------------------

VLAN_JSON_DATA = {
    "vlans": {
        "1": {
            "name": "default",
            "status": "active",
            "interfaces": {"Ethernet1": {}, "Ethernet2": {}},
            "dynamic": False,
        },
        "10": {
            "name": "management",
            "status": "active",
            "interfaces": {"Ethernet49": {}},
            "dynamic": False,
        },
        "100": {
            "name": "servers",
            "status": "suspended",
            "interfaces": {},
            "dynamic": True,
        },
    }
}

VLAN_TEXT_OUTPUT = """\
VLAN  Name                             Status    Ports
----- -------------------------------- --------- -------------------------------
1     default                          active    Et1, Et2, Et3
10    management                       active    Et49, Et50
100   servers                          suspended
200   guests                           active    Et10, Et11
"""

VLAN_TEXT_EMPTY = """\
VLAN  Name                             Status    Ports
----- -------------------------------- --------- -------------------------------
"""


# ===========================================================================
# parse_lldp_neighbors_eos (JSON)
# ===========================================================================


class TestParseLldpNeighborsEos:
    def test_returns_list(self):
        result = parse_lldp_neighbors_eos(LLDP_JSON_DATA)
        assert isinstance(result, list)

    def test_correct_count(self):
        result = parse_lldp_neighbors_eos(LLDP_JSON_DATA)
        assert len(result) == 2

    def test_first_neighbor(self):
        nbr = parse_lldp_neighbors_eos(LLDP_JSON_DATA)[0]
        assert nbr["local_interface"] == "Ethernet1"
        assert nbr["chassis_id"] == "00:11:22:33:44:55"
        assert nbr["port_id"] == "Ethernet1"
        assert nbr["system_name"] == "switch-1"
        assert nbr["ttl"] == 120

    def test_empty_data(self):
        assert parse_lldp_neighbors_eos({}) == []
        assert parse_lldp_neighbors_eos({"lldpNeighbors": []}) == []

    def test_invalid_input(self):
        assert parse_lldp_neighbors_eos({"lldpNeighbors": "invalid"}) == []


# ===========================================================================
# parse_lldp_neighbors_eos_text
# ===========================================================================


class TestParseLldpNeighborsEosText:
    def test_returns_list(self):
        result = parse_lldp_neighbors_eos_text(LLDP_TEXT_OUTPUT)
        assert isinstance(result, list)

    def test_correct_count(self):
        result = parse_lldp_neighbors_eos_text(LLDP_TEXT_OUTPUT)
        assert len(result) == 3

    def test_first_neighbor(self):
        nbr = parse_lldp_neighbors_eos_text(LLDP_TEXT_OUTPUT)[0]
        assert nbr["local_interface"] == "Ethernet1"
        assert nbr["port_id"] == "Ethernet1"
        assert nbr["system_name"] == "switch-1"
        assert nbr["ttl"] == 120

    def test_empty_output(self):
        result = parse_lldp_neighbors_eos_text(LLDP_TEXT_EMPTY)
        assert result == []

    def test_blank_string(self):
        assert parse_lldp_neighbors_eos_text("") == []


# ===========================================================================
# parse_vlan_eos (JSON)
# ===========================================================================


class TestParseVlanEos:
    def test_returns_list(self):
        result = parse_vlan_eos(VLAN_JSON_DATA)
        assert isinstance(result, list)

    def test_correct_count(self):
        result = parse_vlan_eos(VLAN_JSON_DATA)
        assert len(result) == 3

    def test_vlan_fields(self):
        vlans = parse_vlan_eos(VLAN_JSON_DATA)
        vlan1 = next(v for v in vlans if v["vlan_id"] == 1)
        assert vlan1["name"] == "default"
        assert vlan1["status"] == "active"
        assert "Ethernet1" in vlan1["interfaces"]
        assert "Ethernet2" in vlan1["interfaces"]
        assert vlan1["dynamic"] is False

    def test_dynamic_vlan(self):
        vlans = parse_vlan_eos(VLAN_JSON_DATA)
        vlan100 = next(v for v in vlans if v["vlan_id"] == 100)
        assert vlan100["dynamic"] is True
        assert vlan100["status"] == "suspended"

    def test_empty_data(self):
        assert parse_vlan_eos({}) == []
        assert parse_vlan_eos({"vlans": {}}) == []

    def test_invalid_input(self):
        assert parse_vlan_eos({"vlans": "invalid"}) == []


# ===========================================================================
# parse_vlan_eos_text
# ===========================================================================


class TestParseVlanEosText:
    def test_returns_list(self):
        result = parse_vlan_eos_text(VLAN_TEXT_OUTPUT)
        assert isinstance(result, list)

    def test_correct_count(self):
        result = parse_vlan_eos_text(VLAN_TEXT_OUTPUT)
        assert len(result) == 4

    def test_vlan_with_ports(self):
        vlans = parse_vlan_eos_text(VLAN_TEXT_OUTPUT)
        vlan1 = vlans[0]
        assert vlan1["vlan_id"] == 1
        assert vlan1["name"] == "default"
        assert vlan1["status"] == "active"
        assert "Et1" in vlan1["interfaces"]
        assert "Et2" in vlan1["interfaces"]
        assert "Et3" in vlan1["interfaces"]

    def test_vlan_without_ports(self):
        vlans = parse_vlan_eos_text(VLAN_TEXT_OUTPUT)
        vlan100 = next(v for v in vlans if v["vlan_id"] == 100)
        assert vlan100["interfaces"] == []
        assert vlan100["status"] == "suspended"

    def test_empty_output(self):
        result = parse_vlan_eos_text(VLAN_TEXT_EMPTY)
        assert result == []

    def test_blank_string(self):
        assert parse_vlan_eos_text("") == []
