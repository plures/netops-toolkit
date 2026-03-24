"""Tests for Brocade CLI parsers."""

from __future__ import annotations

from netops.parsers.brocade import (
    parse_fabric,
    parse_interfaces,
    parse_ip_routes,
    parse_version,
)

# ---------------------------------------------------------------------------
# Sample CLI output fixtures
# ---------------------------------------------------------------------------

SHOW_INTERFACES_DETAIL = """\
GigabitEthernet1/1/1 is up, line protocol is up
  Hardware is GigabitEthernet, address is aabb.cc00.0001
  Internet address is 192.168.1.1/24
  MTU 1500 bytes, BW 1000000 Kbit
  60 second input rate: 1000 bits/sec, 1 packets/sec
  60 second output rate: 2000 bits/sec, 2 packets/sec
  0 input errors, 0 CRC, 0 alignment errors, 0 runts, 0 giants
  0 output errors, 0 output discards
GigabitEthernet1/1/2 is down, line protocol is down
  Hardware is GigabitEthernet, address is aabb.cc00.0002
  0 input errors, 0 CRC, 0 alignment errors, 0 runts, 0 giants
  0 output errors, 0 output discards
GigabitEthernet1/1/3 is administratively down, line protocol is down
  Hardware is GigabitEthernet, address is aabb.cc00.0003
  0 input errors, 0 CRC, 0 alignment errors, 0 runts, 0 giants
  0 output errors, 0 output discards
"""

SHOW_INTERFACES_BRIEF = """\
Port      Link    State   Duration    Speed          Tag  Mac            Name
Gi1/1/1   Up      Forward 3d04h00m00s 1G             No   aabb.cc00.0001
Gi1/1/2   Down    None    0d00h00m00s 1G             No   aabb.cc00.0002
GigabitEthernet1/1/4   up      up       3d04h00m00s 1G
GigabitEthernet1/1/5   down    down     0d00h00m00s 1G
"""

SHOW_INTERFACES_EMPTY = """\
Interface brief
No interfaces found.
"""

SHOW_IP_ROUTE = """\
Type   Codes - B:BGP, C:Connected, S:Static, R:RIP
Total number of IP routes: 3
Type IP-Address         Next-Hop-Router  Port  Cost
B    10.0.0.0/8         192.168.1.254    e1/1  1
C    192.168.1.0/24     DIRECT           e1/2  1
S    0.0.0.0/0          10.0.0.1         e1/1  1
"""

SHOW_IP_ROUTE_EMPTY = """\
Type   Codes - B:BGP, C:Connected, S:Static, R:RIP
Total number of IP routes: 0
"""

SHOW_VERSION = """\
HW: ICX7550-48
SW: Version 09.0.10T215 Copyright (c) 1996-2023 Ruckus Networks, Inc.
  Compiled on Tue Jan 10 08:22:32 2023
  Boot Code : Version 10.1.02T215
"""

SHOW_VERSION_NO_HW = """\
SW: Version 08.0.92T225 Copyright (c) 1996-2022 Ruckus Networks, Inc.
"""

SHOW_FABRIC = """\
Fabric Name: FabricA
Fabric OS:  v9.1.0
Switch: fc-sw-01 (domain 1)
  Port 0/1: Online
  Port 0/2: Offline
Switch: fc-sw-02 (domain 2)
  Port 0/1: Online
"""

SHOW_FABRIC_EMPTY = """\
No fabric information available.
"""


# ===========================================================================
# parse_interfaces
# ===========================================================================


class TestParseInterfaces:
    def test_returns_list(self):
        result = parse_interfaces(SHOW_INTERFACES_DETAIL)
        assert isinstance(result, list)

    def test_correct_count_detail(self):
        result = parse_interfaces(SHOW_INTERFACES_DETAIL)
        assert len(result) == 3

    def test_up_interface(self):
        iface = parse_interfaces(SHOW_INTERFACES_DETAIL)[0]
        assert iface["name"] == "GigabitEthernet1/1/1"
        assert iface["status"] == "up"
        assert iface["protocol"] == "up"
        assert iface["up"] is True

    def test_down_interface(self):
        iface = parse_interfaces(SHOW_INTERFACES_DETAIL)[1]
        assert iface["name"] == "GigabitEthernet1/1/2"
        assert iface["status"] == "down"
        assert iface["protocol"] == "down"
        assert iface["up"] is False

    def test_admin_down_interface(self):
        iface = parse_interfaces(SHOW_INTERFACES_DETAIL)[2]
        assert iface["name"] == "GigabitEthernet1/1/3"
        assert iface["status"] == "down"
        assert iface["up"] is False

    def test_required_keys_present(self):
        for iface in parse_interfaces(SHOW_INTERFACES_DETAIL):
            assert "name" in iface
            assert "status" in iface
            assert "protocol" in iface
            assert "up" in iface

    def test_brief_form_parsed(self):
        result = parse_interfaces(SHOW_INTERFACES_BRIEF)
        names = [i["name"] for i in result]
        assert "GigabitEthernet1/1/4" in names
        assert "GigabitEthernet1/1/5" in names

    def test_brief_up_interface(self):
        result = parse_interfaces(SHOW_INTERFACES_BRIEF)
        up_ifaces = [i for i in result if i["name"] == "GigabitEthernet1/1/4"]
        assert len(up_ifaces) == 1
        assert up_ifaces[0]["up"] is True

    def test_brief_down_interface(self):
        result = parse_interfaces(SHOW_INTERFACES_BRIEF)
        down_ifaces = [i for i in result if i["name"] == "GigabitEthernet1/1/5"]
        assert len(down_ifaces) == 1
        assert down_ifaces[0]["up"] is False

    def test_empty_output_returns_empty_list(self):
        assert parse_interfaces(SHOW_INTERFACES_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_interfaces("") == []


# ===========================================================================
# parse_ip_routes
# ===========================================================================


class TestParseIpRoutes:
    def test_returns_list(self):
        result = parse_ip_routes(SHOW_IP_ROUTE)
        assert isinstance(result, list)

    def test_correct_count(self):
        result = parse_ip_routes(SHOW_IP_ROUTE)
        assert len(result) == 3

    def test_bgp_route(self):
        route = parse_ip_routes(SHOW_IP_ROUTE)[0]
        assert route["type"] == "B"
        assert route["network"] == "10.0.0.0/8"
        assert route["next_hop"] == "192.168.1.254"
        assert route["interface"] == "e1/1"
        assert route["metric"] == 1

    def test_connected_route(self):
        route = parse_ip_routes(SHOW_IP_ROUTE)[1]
        assert route["type"] == "C"
        assert route["network"] == "192.168.1.0/24"
        assert route["next_hop"] == "DIRECT"

    def test_static_route(self):
        route = parse_ip_routes(SHOW_IP_ROUTE)[2]
        assert route["type"] == "S"
        assert route["network"] == "0.0.0.0/0"
        assert route["next_hop"] == "10.0.0.1"

    def test_required_keys_present(self):
        for route in parse_ip_routes(SHOW_IP_ROUTE):
            for key in ("type", "network", "next_hop", "interface", "metric"):
                assert key in route

    def test_empty_route_table_returns_empty_list(self):
        assert parse_ip_routes(SHOW_IP_ROUTE_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_ip_routes("") == []


# ===========================================================================
# parse_version
# ===========================================================================


class TestParseVersion:
    def test_returns_dict(self):
        result = parse_version(SHOW_VERSION)
        assert isinstance(result, dict)

    def test_model_parsed(self):
        result = parse_version(SHOW_VERSION)
        assert result["model"] == "ICX7550-48"

    def test_version_parsed(self):
        result = parse_version(SHOW_VERSION)
        assert result["version"] == "09.0.10T215"

    def test_vendor_always_brocade(self):
        result = parse_version(SHOW_VERSION)
        assert result["vendor"] == "Brocade"

    def test_no_hw_line_model_is_none(self):
        result = parse_version(SHOW_VERSION_NO_HW)
        assert result["model"] is None
        assert result["version"] == "08.0.92T225"

    def test_blank_string_returns_none_values(self):
        result = parse_version("")
        assert result["model"] is None
        assert result["version"] is None
        assert result["vendor"] == "Brocade"

    def test_required_keys_present(self):
        result = parse_version(SHOW_VERSION)
        for key in ("model", "version", "vendor"):
            assert key in result


# ===========================================================================
# parse_fabric
# ===========================================================================


class TestParseFabric:
    def test_returns_dict(self):
        result = parse_fabric(SHOW_FABRIC)
        assert isinstance(result, dict)

    def test_fabric_name_parsed(self):
        result = parse_fabric(SHOW_FABRIC)
        assert result["fabric_name"] == "FabricA"

    def test_fabric_os_parsed(self):
        result = parse_fabric(SHOW_FABRIC)
        assert result["fabric_os"] == "v9.1.0"

    def test_switch_count(self):
        result = parse_fabric(SHOW_FABRIC)
        assert len(result["switches"]) == 2

    def test_switch_fields(self):
        sw = parse_fabric(SHOW_FABRIC)["switches"][0]
        assert sw["name"] == "fc-sw-01"
        assert sw["domain"] == 1

    def test_port_count(self):
        result = parse_fabric(SHOW_FABRIC)
        assert len(result["ports"]) == 3

    def test_port_states(self):
        ports = parse_fabric(SHOW_FABRIC)["ports"]
        assert ports[0] == {"port": "0/1", "state": "Online"}
        assert ports[1] == {"port": "0/2", "state": "Offline"}

    def test_required_keys_present(self):
        result = parse_fabric(SHOW_FABRIC)
        for key in ("fabric_name", "fabric_os", "switches", "ports"):
            assert key in result

    def test_empty_output_returns_defaults(self):
        result = parse_fabric(SHOW_FABRIC_EMPTY)
        assert result["fabric_name"] is None
        assert result["fabric_os"] is None
        assert result["switches"] == []
        assert result["ports"] == []

    def test_blank_string_returns_defaults(self):
        result = parse_fabric("")
        assert result["fabric_name"] is None
        assert result["switches"] == []
