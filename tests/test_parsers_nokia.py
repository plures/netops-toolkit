"""Tests for Nokia SR OS CLI parsers."""

from __future__ import annotations


from netops.parsers.nokia_sros import (
    parse_bgp_summary,
    parse_bof,
    parse_cards,
    parse_chassis,
    parse_interfaces,
    parse_lag,
    parse_mda,
    parse_ospf_neighbors,
    parse_router_interface,
    parse_service_summary,
    parse_system_info,
    parse_version,
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


# ===========================================================================
# Fixtures for new parsers
# ===========================================================================

SHOW_SYSTEM_INFO_7750 = """\
===============================================================================
System Information
===============================================================================
System Name            : lab-7750-sr12
System Contact         : noc@example.com
System Location        : DC1-Row3-Rack7
System Coordinates     : N/A
Object Id              : 1.3.6.1.4.1.6527.1.3.4
System Up Time         : 142 days, 03:15:22.10 (hr:min:sec)
Last Booted            : 2025/11/02 14:22:33 UTC
Current Time           : 2026/03/23 17:37:55 UTC
Chassis Type           : 7750 SR-12
BOF Source             : cf3:
System Version         : B-23.10.R1
===============================================================================
"""

SHOW_CHASSIS_7750 = """\
===============================================================================
Chassis Information
===============================================================================
  Name                         :
  Type                         : 7750 SR-12
  Chassis Topology             : Standalone
  Location                     : DC1-Row3-Rack7
  Coordinates                  : N/A
  CLLI Code                    : LABDC1NKA
  Number of Slots              : 12
  Number of Ports              : 120
  Number of Power Supply Modules : 4
  Number of Fan Trays          : 5
  Admin State                  : up
  Oper State                   : up
  Part Number                  : 3HE04820AAAB01
  Serial Number                : NS1234567890
  CLEI Code                    : IPUIAB1RAA
  Base MAC address             : 00:25:ba:01:23:45
  Hardware Data                : Level=he7
  Firmware Version             : v1.4
  Temperature                  : 32C
===============================================================================
"""

SHOW_CHASSIS_7210 = """\
===============================================================================
Chassis Information
===============================================================================
  Name                         :
  Type                         : 7210 SAS-Sx 10/100GE
  Part Number                  : 3HE10497AARA01
  Serial Number                : NS7210SAS001
  Base MAC Address             : 00:25:ba:aa:bb:cc
  Admin State                  : up
  Oper State                   : up
===============================================================================
"""

SHOW_CARD_OUTPUT = """\
===============================================================================
Card Summary
===============================================================================
Slot  Provisioned Type                         Admin Oper
-------------------------------------------------------------------------------
1     iom3-xp                                   up    up
2     iom3-xp                                   up    up
3     iom3-xp                                   up    down
A     sfm5-12                                    up    up
B     sfm5-12                                    up    up
===============================================================================
"""

SHOW_CARD_EMPTY = """\
===============================================================================
Card Summary
===============================================================================
Slot  Provisioned Type                         Admin Oper
-------------------------------------------------------------------------------
===============================================================================
"""

SHOW_MDA_OUTPUT = """\
===============================================================================
MDA Summary
===============================================================================
Slot  Provisioned Type                         Admin Oper
-------------------------------------------------------------------------------
1/1   me12-100gb-qsfp28                         up    up
1/2   me6-100gb-qsfp28                          up    up
2/1   me12-100gb-qsfp28                         up    down
===============================================================================
"""

SHOW_BOF_OUTPUT = """\
===============================================================================
BOF (Memory)
===============================================================================

    primary-image    cf3:\\timos\\cpm.tim
    secondary-image  cf3:\\timos\\cpm_backup.tim
    tertiary-image   cf3:\\timos\\cpm_old.tim
    primary-config   cf3:\\config.cfg
    secondary-config cf3:\\config_backup.cfg
    address          10.0.0.1
    prefix-length    24
    static-route     0.0.0.0/0 next-hop 10.0.0.254
    static-route     10.10.0.0/16 next-hop 10.0.0.253
    dns-domain       example.com
    autonegotiate    true
    duplex           full
    speed            1000
    wait-time        3
    persist          on
    console-speed    115200
===============================================================================
"""

SHOW_VERSION_7750 = """\
TiMOS-B-23.10.R1 both/x86_64 Nokia 7750 SR Copyright (c) 2000-2025 Nokia.
All rights reserved. All use subject to applicable license agreements.
Built on Fri Oct 13 12:00:00 UTC 2023 by builder in /builds/2310/R1/panos/main

"""

SHOW_VERSION_7705 = """\
TiMOS-B-22.7.R2 cpm/linux Nokia 7705 SAR-18 Copyright (c) 2000-2024 Nokia.
All rights reserved. All use subject to applicable license agreements.
Built on Wed Jul 20 09:00:00 UTC 2022 by builder in /builds/2207/R2/panos/main

"""

SHOW_VERSION_ALCATEL = """\
TiMOS-B-16.0.R8 cpm/x86_64 Alcatel-Lucent 7750 SR-7 Copyright (c) 2000-2019 Nokia.
All rights reserved. All use subject to applicable license agreements.
Built on Thu Apr 04 10:00:00 UTC 2019 by builder in /builds/1600/R8/panos/main

"""

SHOW_SERVICE_USING = """\
===============================================================================
Services
===============================================================================
SvcId    SvcType  Adm  Opr  CustId  Name
-------------------------------------------------------------------------------
100      VPLS     Up   Up   1       VPLS-DC1-MGMT
200      VPRN     Up   Up   1       VPRN-INTERNET
300      Epipe    Up   Down 2       Epipe-Customer2
===============================================================================
"""

SHOW_LAG_OUTPUT = """\
===============================================================================
LAG Summary
===============================================================================
Lag-id  Adm  Opr  Port-Count  Active-Ports  Description
-------------------------------------------------------------------------------
1       up   up   2           2             to-spine-1
2       up   down 2           0             to-spine-2
===============================================================================
"""

SHOW_ROUTER_INTERFACE = """\
===============================================================================
Router Interface Table
===============================================================================
Interface   IP Address       Adm  Opr
-------------------------------------------------------------------------------
system      10.0.0.1/32      Up   Up
to-core-1   10.1.1.1/30      Up   Up
to-core-2   10.1.1.5/30      Up   Down
===============================================================================
"""


# ===========================================================================
# parse_system_info
# ===========================================================================


class TestParseSystemInfo:
    def test_parses_7750_system_info(self):
        result = parse_system_info(SHOW_SYSTEM_INFO_7750)
        assert result["system_name"] == "lab-7750-sr12"
        assert result["hostname"] == "lab-7750-sr12"
        assert result["contact"] == "noc@example.com"
        assert result["location"] == "DC1-Row3-Rack7"
        assert "142 days" in result["uptime"]
        assert result["chassis_type"] == "7750 SR-12"
        assert result["oper_version"] == "B-23.10.R1"

    def test_last_booted_and_current_time(self):
        result = parse_system_info(SHOW_SYSTEM_INFO_7750)
        assert "2025/11/02" in result["last_booted"]
        assert "2026/03/23" in result["current_time"]

    def test_empty_returns_empty_dict(self):
        assert parse_system_info("") == {}


# ===========================================================================
# parse_chassis
# ===========================================================================


class TestParseChassis:
    def test_parses_7750_chassis(self):
        result = parse_chassis(SHOW_CHASSIS_7750)
        assert result["chassis_type"] == "7750 SR-12"
        assert result["serial_number"] == "NS1234567890"
        assert result["part_number"] == "3HE04820AAAB01"
        assert result["mac_address"] == "00:25:ba:01:23:45"
        assert result["clei_code"] == "IPUIAB1RAA"
        assert result["firmware"] == "v1.4"
        assert result["temperature"] == "32C"
        assert result["num_slots"] == "12"
        assert result["num_ports"] == "120"

    def test_parses_7210_chassis(self):
        result = parse_chassis(SHOW_CHASSIS_7210)
        assert result["chassis_type"] == "7210 SAS-Sx 10/100GE"
        assert result["serial_number"] == "NS7210SAS001"
        assert result["part_number"] == "3HE10497AARA01"
        assert result["mac_address"] == "00:25:ba:aa:bb:cc"

    def test_empty_returns_empty_dict(self):
        assert parse_chassis("") == {}


# ===========================================================================
# parse_cards
# ===========================================================================


class TestParseCards:
    def test_parses_card_table(self):
        result = parse_cards(SHOW_CARD_OUTPUT)
        assert len(result) == 5

    def test_card_fields(self):
        cards = parse_cards(SHOW_CARD_OUTPUT)
        c1 = cards[0]
        assert c1["slot"] == "1"
        assert c1["card_type"] == "iom3-xp"
        assert c1["admin_state"] == "up"
        assert c1["oper_state"] == "up"

    def test_sfm_card(self):
        cards = parse_cards(SHOW_CARD_OUTPUT)
        sfm = [c for c in cards if c["slot"] == "A"]
        assert len(sfm) == 1
        assert sfm[0]["card_type"] == "sfm5-12"

    def test_down_card(self):
        cards = parse_cards(SHOW_CARD_OUTPUT)
        c3 = [c for c in cards if c["slot"] == "3"][0]
        assert c3["oper_state"] == "down"

    def test_empty_returns_empty_list(self):
        assert parse_cards(SHOW_CARD_EMPTY) == []


# ===========================================================================
# parse_mda
# ===========================================================================


class TestParseMda:
    def test_parses_mda_table(self):
        result = parse_mda(SHOW_MDA_OUTPUT)
        assert len(result) == 3

    def test_mda_fields(self):
        mdas = parse_mda(SHOW_MDA_OUTPUT)
        m1 = mdas[0]
        assert m1["slot"] == "1/1"
        assert m1["mda_type"] == "me12-100gb-qsfp28"
        assert m1["admin_state"] == "up"
        assert m1["oper_state"] == "up"

    def test_down_mda(self):
        mdas = parse_mda(SHOW_MDA_OUTPUT)
        m3 = mdas[2]
        assert m3["oper_state"] == "down"

    def test_empty_returns_empty_list(self):
        assert parse_mda("") == []


# ===========================================================================
# parse_bof
# ===========================================================================


class TestParseBof:
    def test_parses_images(self):
        result = parse_bof(SHOW_BOF_OUTPUT)
        assert "cpm.tim" in result["primary_image"]
        assert "cpm_backup.tim" in result["secondary_image"]
        assert "cpm_old.tim" in result["tertiary_image"]

    def test_parses_config(self):
        result = parse_bof(SHOW_BOF_OUTPUT)
        assert "config.cfg" in result["primary_config"]
        assert "config_backup.cfg" in result["secondary_config"]

    def test_parses_network_settings(self):
        result = parse_bof(SHOW_BOF_OUTPUT)
        assert result["address"] == "10.0.0.1"
        assert result["dns_domain"] == "example.com"

    def test_parses_static_routes(self):
        result = parse_bof(SHOW_BOF_OUTPUT)
        assert len(result["static_route"]) == 2
        assert "0.0.0.0/0" in result["static_route"][0]

    def test_parses_console_speed(self):
        result = parse_bof(SHOW_BOF_OUTPUT)
        assert result["console_speed"] == "115200"

    def test_empty_returns_empty_dict(self):
        assert parse_bof("") == {}


# ===========================================================================
# parse_version
# ===========================================================================


class TestParseVersion:
    def test_7750_version(self):
        result = parse_version(SHOW_VERSION_7750)
        assert result["timos_version"] == "TiMOS-B-23.10.R1"
        assert result["version"] == "23.10.R1"
        assert result["chassis_type"] == "7750 SR"
        assert "Oct" in result["build_date"]

    def test_7705_version(self):
        result = parse_version(SHOW_VERSION_7705)
        assert result["version"] == "22.7.R2"
        assert result["chassis_type"] == "7705 SAR-18"

    def test_alcatel_version(self):
        result = parse_version(SHOW_VERSION_ALCATEL)
        assert result["version"] == "16.0.R8"
        # Old Alcatel-Lucent branding should still extract model
        assert "7750" in result.get("chassis_type", "")

    def test_empty_returns_empty_dict(self):
        assert parse_version("") == {}


# ===========================================================================
# parse_service_summary
# ===========================================================================


class TestParseServiceSummary:
    def test_parses_services(self):
        result = parse_service_summary(SHOW_SERVICE_USING)
        assert len(result) == 3

    def test_vpls_service(self):
        svc = parse_service_summary(SHOW_SERVICE_USING)[0]
        assert svc["service_id"] == 100
        assert svc["service_type"] == "VPLS"
        assert svc["admin_state"] == "Up"
        assert svc["oper_state"] == "Up"
        assert svc["customer_id"] == 1
        assert svc["name"] == "VPLS-DC1-MGMT"

    def test_down_service(self):
        svc = parse_service_summary(SHOW_SERVICE_USING)[2]
        assert svc["oper_state"] == "Down"

    def test_empty_returns_empty_list(self):
        assert parse_service_summary("") == []


# ===========================================================================
# parse_lag
# ===========================================================================


class TestParseLag:
    def test_parses_lags(self):
        result = parse_lag(SHOW_LAG_OUTPUT)
        assert len(result) == 2

    def test_lag_fields(self):
        lag = parse_lag(SHOW_LAG_OUTPUT)[0]
        assert lag["lag_id"] == 1
        assert lag["admin_state"] == "up"
        assert lag["oper_state"] == "up"
        assert lag["port_count"] == 2
        assert lag["active_ports"] == 2
        assert lag["description"] == "to-spine-1"

    def test_down_lag(self):
        lag = parse_lag(SHOW_LAG_OUTPUT)[1]
        assert lag["oper_state"] == "down"
        assert lag["active_ports"] == 0

    def test_empty_returns_empty_list(self):
        assert parse_lag("") == []


# ===========================================================================
# parse_router_interface
# ===========================================================================


class TestParseRouterInterface:
    def test_parses_interfaces(self):
        result = parse_router_interface(SHOW_ROUTER_INTERFACE)
        assert len(result) == 3

    def test_system_interface(self):
        iface = parse_router_interface(SHOW_ROUTER_INTERFACE)[0]
        assert iface["name"] == "system"
        assert iface["ip_address"] == "10.0.0.1/32"
        assert iface["admin_state"] == "Up"
        assert iface["oper_state"] == "Up"

    def test_down_interface(self):
        iface = parse_router_interface(SHOW_ROUTER_INTERFACE)[2]
        assert iface["name"] == "to-core-2"
        assert iface["oper_state"] == "Down"

    def test_empty_returns_empty_list(self):
        assert parse_router_interface("") == []


# ===========================================================================
# Vendor identification (scan.py)
# ===========================================================================


class TestVendorIdentification:
    def test_alcatel_detected_as_nokia(self):
        from netops.inventory.scan import identify_vendor
        assert identify_vendor("Alcatel-Lucent 7750 SR-12") == "nokia_sros"
        assert identify_vendor("TiMOS-B-16.0.R8 Alcatel-Lucent") == "nokia_sros"

    def test_nokia_detected(self):
        from netops.inventory.scan import identify_vendor
        assert identify_vendor("TiMOS-B-23.10.R1 Nokia 7750 SR") == "nokia_sros"
        assert identify_vendor("Nokia SR Linux") == "nokia_srl"
