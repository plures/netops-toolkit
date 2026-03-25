"""Tests for Nokia SR OS CLI parsers."""

from __future__ import annotations


from netops.parsers.nokia_sros import (
    parse_bgp_summary,
    parse_interfaces,
    parse_ospf_neighbors,
)

# ---------------------------------------------------------------------------
# Sample CLI output fixtures
# ---------------------------------------------------------------------------

SHOW_PORT_OUTPUT = """\
===============================================================================
Ports on Slot 1
===============================================================================
Port          Admin Link Port    Cfg  Oper LAG/ Port Port Port
              State      State   MTU  MTU  Bndl Mode Encp Type
-------------------------------------------------------------------------------
1/1/1         Up    Yes  Up      1514 1514    - netw null Xcm
1/1/2         Up    No   Down    1514 1514    - netw null Xcm
1/1/3         Down  No   Down    1514 1514    - netw null Xcm
-------------------------------------------------------------------------------
No. of Ports: 3
===============================================================================
"""

SHOW_PORT_EMPTY = """\
===============================================================================
Ports on Slot 1
===============================================================================
Port          Admin Link Port    Cfg  Oper LAG/ Port Port Port
              State      State   MTU  MTU  Bndl Mode Encp Type
-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
No. of Ports: 0
===============================================================================
"""

BGP_SUMMARY_OUTPUT = """\
===============================================================================
 BGP Router ID:10.0.0.1         AS:65000       Local AS:65000
===============================================================================
 Legend
 D - Dynamic Capability in use
===============================================================================
 Neighbor
 Description
                             Remote AS Adj RIB  Sent      Active    Up/Down  State
                                       In
-------------------------------------------------------------------------------
 10.0.0.2
                             65001     0         0         0         00h15m   Active
 192.168.1.1
 ibgp-peer
                             65000     100       100       90        1d02h    Established
-------------------------------------------------------------------------------
No. of Peers: 2
===============================================================================
"""

BGP_SUMMARY_EMPTY = """\
===============================================================================
 BGP Router ID:10.0.0.1         AS:65000       Local AS:65000
===============================================================================
 Legend
 D - Dynamic Capability in use
===============================================================================
 Neighbor
 Description
                             Remote AS Adj RIB  Sent      Active    Up/Down  State
                                       In
-------------------------------------------------------------------------------
No. of Peers: 0
===============================================================================
"""

OSPF_NEIGHBOR_OUTPUT = """\
===============================================================================
Rtr Base OSPF Neighbors
===============================================================================
Interface-Name                   Rtr Id          State      Pri  RetxQ    TTL
-------------------------------------------------------------------------------
to-core-1                        10.0.0.1        Full         1    0       30
to-core-2                        10.0.0.2        Full         1    0       28
to-dist-1                        10.0.1.1        Init         1    0       34
-------------------------------------------------------------------------------
No. of Neighbors: 3
===============================================================================
"""

OSPF_NEIGHBOR_EMPTY = """\
===============================================================================
Rtr Base OSPF Neighbors
===============================================================================
Interface-Name                   Rtr Id          State      Pri  RetxQ    TTL
-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
No. of Neighbors: 0
===============================================================================
"""


# ===========================================================================
# parse_interfaces
# ===========================================================================


class TestParseInterfaces:
    def test_returns_list(self):
        result = parse_interfaces(SHOW_PORT_OUTPUT)
        assert isinstance(result, list)

    def test_correct_count(self):
        result = parse_interfaces(SHOW_PORT_OUTPUT)
        assert len(result) == 3

    def test_up_interface(self):
        iface = parse_interfaces(SHOW_PORT_OUTPUT)[0]
        assert iface["name"] == "1/1/1"
        assert iface["status"] == "Up"
        assert iface["protocol"] == "Up"
        assert iface["up"] is True
        assert iface["link"] is True

    def test_link_down_interface(self):
        iface = parse_interfaces(SHOW_PORT_OUTPUT)[1]
        assert iface["name"] == "1/1/2"
        assert iface["link"] is False
        assert iface["status"] == "Up"
        assert iface["protocol"] == "Down"
        assert iface["up"] is False

    def test_admin_down_interface(self):
        iface = parse_interfaces(SHOW_PORT_OUTPUT)[2]
        assert iface["name"] == "1/1/3"
        assert iface["link"] is False
        assert iface["status"] == "Down"
        assert iface["up"] is False

    def test_required_keys_present(self):
        for iface in parse_interfaces(SHOW_PORT_OUTPUT):
            assert "name" in iface
            assert "status" in iface
            assert "protocol" in iface
            assert "up" in iface
            assert "link" in iface

    def test_empty_port_table_returns_empty_list(self):
        assert parse_interfaces(SHOW_PORT_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_interfaces("") == []


# ===========================================================================
# parse_bgp_summary
# ===========================================================================


class TestParseBgpSummary:
    def test_returns_list(self):
        result = parse_bgp_summary(BGP_SUMMARY_OUTPUT)
        assert isinstance(result, list)

    def test_correct_peer_count(self):
        result = parse_bgp_summary(BGP_SUMMARY_OUTPUT)
        assert len(result) == 2

    def test_active_peer_fields(self):
        peer = parse_bgp_summary(BGP_SUMMARY_OUTPUT)[0]
        assert peer["neighbor"] == "10.0.0.2"
        assert peer["peer_as"] == 65001
        assert peer["state"] == "Active"
        assert peer["received"] == 0
        assert peer["sent"] == 0
        assert peer["active"] == 0
        assert peer["up_down"] == "00h15m"
        assert peer["description"] is None

    def test_established_peer_with_description(self):
        peer = parse_bgp_summary(BGP_SUMMARY_OUTPUT)[1]
        assert peer["neighbor"] == "192.168.1.1"
        assert peer["peer_as"] == 65000
        assert peer["state"] == "Established"
        assert peer["received"] == 100
        assert peer["sent"] == 100
        assert peer["active"] == 90
        assert peer["up_down"] == "1d02h"
        assert peer["description"] == "ibgp-peer"

    def test_required_keys_present(self):
        for peer in parse_bgp_summary(BGP_SUMMARY_OUTPUT):
            for key in ("neighbor", "peer_as", "state", "received", "sent",
                        "active", "up_down", "description"):
                assert key in peer

    def test_empty_peer_table_returns_empty_list(self):
        assert parse_bgp_summary(BGP_SUMMARY_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_bgp_summary("") == []


# ===========================================================================
# parse_ospf_neighbors
# ===========================================================================


class TestParseOspfNeighbors:
    def test_returns_list(self):
        result = parse_ospf_neighbors(OSPF_NEIGHBOR_OUTPUT)
        assert isinstance(result, list)

    def test_correct_neighbor_count(self):
        result = parse_ospf_neighbors(OSPF_NEIGHBOR_OUTPUT)
        assert len(result) == 3

    def test_full_adjacency_fields(self):
        nbr = parse_ospf_neighbors(OSPF_NEIGHBOR_OUTPUT)[0]
        assert nbr["interface"] == "to-core-1"
        assert nbr["router_id"] == "10.0.0.1"
        assert nbr["state"] == "Full"
        assert nbr["priority"] == 1
        assert nbr["retx_queue"] == 0

    def test_second_full_adjacency(self):
        nbr = parse_ospf_neighbors(OSPF_NEIGHBOR_OUTPUT)[1]
        assert nbr["interface"] == "to-core-2"
        assert nbr["router_id"] == "10.0.0.2"
        assert nbr["state"] == "Full"

    def test_init_state_neighbor(self):
        nbr = parse_ospf_neighbors(OSPF_NEIGHBOR_OUTPUT)[2]
        assert nbr["interface"] == "to-dist-1"
        assert nbr["router_id"] == "10.0.1.1"
        assert nbr["state"] == "Init"

    def test_required_keys_present(self):
        for nbr in parse_ospf_neighbors(OSPF_NEIGHBOR_OUTPUT):
            for key in ("interface", "router_id", "state", "priority", "retx_queue"):
                assert key in nbr

    def test_empty_neighbor_table_returns_empty_list(self):
        assert parse_ospf_neighbors(OSPF_NEIGHBOR_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_ospf_neighbors("") == []
