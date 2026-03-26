"""Tests for Arista EOS health-check parsers and check logic."""

from __future__ import annotations

from netops.check.arista import (
    DEFAULT_CPU_THRESHOLD,
    DEFAULT_MEM_THRESHOLD,
    _parse_thresholds,
    _send_json,
    build_eos_health_report,
    check_eos_bgp,
    check_eos_bgp_evpn,
    check_eos_cpu_memory,
    check_eos_environment,
    check_eos_interfaces,
    check_eos_mlag,
    check_eos_ospf,
    check_eos_transceivers,
    run_health_check,
)
from netops.check.arista import (
    _print_result as _eos_print_result,
)
from netops.core.connection import ConnectionParams as _AristaConnParams
from netops.parsers.arista import (
    parse_bgp_evpn_eos,
    parse_bgp_summary_eos,
    parse_bgp_summary_eos_text,
    parse_cpu_memory_eos,
    parse_environment_eos,
    parse_interface_counters_eos,
    parse_interfaces_eos,
    parse_mlag_config_sanity_eos,
    parse_mlag_eos,
    parse_mlag_eos_text,
    parse_ospf_neighbors_eos,
    parse_ospf_neighbors_eos_text,
    parse_transceivers_eos,
)
from netops.templates.arista_eos import HEALTH as EOS_HEALTH

# ===========================================================================
# JSON fixtures — simulated eAPI responses
# ===========================================================================

# ---------------------------------------------------------------------------
# show version  (CPU / memory)
# ---------------------------------------------------------------------------

VERSION_DATA = {
    "version": "4.28.3M",
    "modelName": "DCS-7050CX3-32S",
    "serialNumber": "JPE12345678",
    "uptime": 864000.0,
    "memTotal": 8192000,
    "memFree": 3000000,
    "systemStats": {
        "cpuInfo": {
            "0": {"%idle": 75.0, "%user": 15.0, "%kernel": 10.0},
            "1": {"%idle": 80.0, "%user": 12.0, "%kernel": 8.0},
        }
    },
}

VERSION_DATA_HIGH_CPU = {
    "version": "4.28.3M",
    "modelName": "DCS-7050CX3-32S",
    "serialNumber": "JPE99999999",
    "uptime": 3600.0,
    "memTotal": 8192000,
    "memFree": 500000,
    "systemStats": {
        "cpuInfo": {
            "0": {"%idle": 10.0},
            "1": {"%idle": 5.0},
        }
    },
}

VERSION_DATA_NO_CPU = {
    "version": "4.25.0F",
    "modelName": "DCS-7280SR2-48YC6",
    "serialNumber": "SN00000001",
    "memTotal": 4096000,
    "memFree": 2000000,
}

VERSION_DATA_EMPTY = {}

# ---------------------------------------------------------------------------
# show interfaces
# ---------------------------------------------------------------------------

INTERFACES_DATA = {
    "interfaces": {
        "Ethernet1": {
            "description": "uplink-to-spine1",
            "interfaceStatus": "connected",
            "lineProtocolStatus": "up",
            "interfaceCounters": {
                "inputErrors": 0,
                "outputErrors": 0,
                "inDiscards": 0,
                "outDiscards": 0,
                "alignmentErrors": 0,
            },
        },
        "Ethernet2": {
            "description": "server-leaf",
            "interfaceStatus": "connected",
            "lineProtocolStatus": "up",
            "interfaceCounters": {
                "inputErrors": 5,
                "outputErrors": 2,
                "inDiscards": 0,
                "outDiscards": 0,
                "alignmentErrors": 1,
            },
        },
        "Ethernet3": {
            "description": "unused",
            "interfaceStatus": "notconnect",
            "lineProtocolStatus": "down",
            "interfaceCounters": {
                "inputErrors": 0,
                "outputErrors": 0,
                "inDiscards": 0,
                "outDiscards": 0,
                "alignmentErrors": 0,
            },
        },
    }
}

INTERFACES_DATA_CLEAN = {
    "interfaces": {
        "Ethernet1": {
            "description": "",
            "interfaceStatus": "connected",
            "lineProtocolStatus": "up",
            "interfaceCounters": {
                "inputErrors": 0,
                "outputErrors": 0,
                "inDiscards": 0,
                "outDiscards": 0,
                "alignmentErrors": 0,
            },
        }
    }
}

INTERFACES_DATA_EMPTY = {}

# ---------------------------------------------------------------------------
# show interfaces counters errors
# ---------------------------------------------------------------------------

COUNTERS_DATA = {
    "interfaceErrorCounters": {
        "Ethernet1": {
            "fcsErrors": 0,
            "alignmentErrors": 0,
            "symbolErrors": 0,
            "rxPause": 0,
            "inErrors": 0,
            "outErrors": 0,
        },
        "Ethernet2": {
            "fcsErrors": 3,
            "alignmentErrors": 1,
            "symbolErrors": 0,
            "rxPause": 0,
            "inErrors": 4,
            "outErrors": 0,
        },
    }
}

COUNTERS_DATA_EMPTY = {}

# ---------------------------------------------------------------------------
# show interfaces transceiver
# ---------------------------------------------------------------------------

TRANSCEIVERS_DATA = {
    "interfaces": {
        "Ethernet1": {
            "mediaType": "100GBASE-SR4",
            "details": {
                "temperature": 35.5,
                "voltage": 3.30,
                "laneValues": {
                    "0": {"txPower": -2.1, "rxPower": -3.0, "txBias": 7.5},
                    "1": {"txPower": -2.3, "rxPower": -3.1, "txBias": 7.4},
                },
            },
            "domAlerts": {},
        },
        "Ethernet2": {
            "mediaType": "10GBASE-SR",
            "details": {
                "temperature": 42.0,
                "voltage": 3.28,
                "txPower": -1.5,
                "rxPower": -15.0,  # low receive power
                "txBias": 6.0,
            },
            "domAlerts": {"rxPowerAlarm": True},
        },
    }
}

TRANSCEIVERS_DATA_EMPTY = {}

# ---------------------------------------------------------------------------
# show bgp summary
# ---------------------------------------------------------------------------

BGP_SUMMARY_DATA = {
    "vrfs": {
        "default": {
            "peers": {
                "10.0.0.2": {
                    "asn": 65002,
                    "peerState": "Established",
                    "upDownTime": "5d03h",
                    "prefixReceived": 50,
                },
                "10.0.0.3": {
                    "asn": 65003,
                    "peerState": "Active",
                    "upDownTime": "00:05:23",
                    "prefixReceived": 0,
                },
            }
        }
    }
}

BGP_SUMMARY_ALL_ESTABLISHED = {
    "vrfs": {
        "default": {
            "peers": {
                "10.0.0.2": {
                    "asn": 65002,
                    "peerState": "Established",
                    "upDownTime": "10d",
                    "prefixReceived": 100,
                },
                "10.0.0.3": {
                    "asn": 65003,
                    "peerState": "Established",
                    "upDownTime": "9d",
                    "prefixReceived": 80,
                },
            }
        }
    }
}

BGP_SUMMARY_EMPTY = {}

# ---------------------------------------------------------------------------
# show bgp summary  (plain text)
# ---------------------------------------------------------------------------

BGP_SUMMARY_TEXT = """\
BGP summary information for VRF default
Router identifier 10.0.0.1, local AS number 65001
Neighbor Status Codes: m - Under maintenance
  Description              Neighbor V AS           MsgRcvd   MsgSent  InQ OutQ  Up/Down State   PfxRcd PfxAcc
  10.0.0.2                 4 65002         1000      1001    0    0 5d03h Estab   50     50
  10.0.0.3                 4 65003           50        51    0    0 00:05:23 Active
"""

BGP_SUMMARY_TEXT_ALL_ESTAB = """\
BGP summary information for VRF default
Router identifier 10.0.0.1, local AS number 65001
  Description              Neighbor V AS           MsgRcvd   MsgSent  InQ OutQ  Up/Down State   PfxRcd PfxAcc
  10.0.0.2                 4 65002         2000      2001    0    0 10d Estab   100    100
  10.0.0.3                 4 65003         1000      1001    0    0 9d  Estab    80     80
"""

# ---------------------------------------------------------------------------
# show ip ospf neighbor  (JSON)
# ---------------------------------------------------------------------------

OSPF_NEIGHBORS_DATA = {
    "instList": {
        "1": {
            "neighbors": {
                "192.168.1.2": {
                    "adjacencies": [
                        {
                            "adjState": "Full",
                            "interfaceName": "Ethernet1",
                            "routerAddress": "10.1.0.2",
                            "priority": 1,
                            "deadTime": "00:00:38",
                        }
                    ]
                },
                "192.168.1.3": {
                    "adjacencies": [
                        {
                            "adjState": "Full",
                            "interfaceName": "Ethernet2",
                            "routerAddress": "10.1.0.3",
                            "priority": 1,
                            "deadTime": "00:00:36",
                        }
                    ]
                },
                "192.168.1.4": {
                    "adjacencies": [
                        {
                            "adjState": "ExStart",
                            "interfaceName": "Ethernet3",
                            "routerAddress": "10.1.0.4",
                            "priority": 0,
                            "deadTime": "00:00:39",
                        }
                    ]
                },
            }
        }
    }
}

OSPF_NEIGHBORS_ALL_FULL = {
    "instList": {
        "1": {
            "neighbors": {
                "192.168.1.2": {
                    "adjacencies": [
                        {
                            "adjState": "Full",
                            "interfaceName": "Ethernet1",
                            "routerAddress": "10.1.0.2",
                            "priority": 1,
                            "deadTime": "00:00:38",
                        }
                    ]
                },
                "192.168.1.3": {
                    "adjacencies": [
                        {
                            "adjState": "Full",
                            "interfaceName": "Ethernet2",
                            "routerAddress": "10.1.0.3",
                            "priority": 1,
                            "deadTime": "00:00:36",
                        }
                    ]
                },
            }
        }
    }
}

OSPF_NEIGHBORS_EMPTY = {}

# ---------------------------------------------------------------------------
# show ip ospf neighbor  (plain text)
# ---------------------------------------------------------------------------

OSPF_TEXT = """\
Neighbor ID     Pri   State           Dead Time   Address         Interface
192.168.1.2       1   Full/DR         00:00:38    10.1.0.2        Ethernet1
192.168.1.3       1   Full/BDR        00:00:36    10.1.0.3        Ethernet2
192.168.1.4       0   ExStart/-       00:00:39    10.1.0.4        Ethernet3
"""

OSPF_TEXT_ALL_FULL = """\
Neighbor ID     Pri   State           Dead Time   Address         Interface
192.168.1.2       1   Full/DR         00:00:38    10.1.0.2        Ethernet1
192.168.1.3       1   Full/BDR        00:00:36    10.1.0.3        Ethernet2
"""

# ---------------------------------------------------------------------------
# show mlag  (JSON)
# ---------------------------------------------------------------------------

MLAG_DATA_ACTIVE = {
    "state": "active",
    "peerState": "active",
    "peerLink": "Port-Channel1",
    "peerLinkStatus": "up",
    "localInterface": "Vlan4094",
    "peerAddress": "10.255.0.2",
    "configSanity": "consistent",
    "localIntfStatus": {"localIpAddr": "10.255.0.1"},
}

MLAG_DATA_INACTIVE = {
    "state": "inactive",
    "peerState": "inactive",
    "peerLink": "Port-Channel1",
    "peerLinkStatus": "down",
    "localInterface": "Vlan4094",
    "peerAddress": "10.255.0.2",
    "configSanity": "",
    "localIntfStatus": {},
}

MLAG_DATA_PEER_LINK_DOWN = {
    "state": "active",
    "peerState": "active",
    "peerLink": "Port-Channel1",
    "peerLinkStatus": "down",
    "localInterface": "Vlan4094",
    "peerAddress": "10.255.0.2",
    "configSanity": "consistent",
    "localIntfStatus": {"localIpAddr": "10.255.0.1"},
}

MLAG_DATA_EMPTY = {}

# ---------------------------------------------------------------------------
# show mlag  (plain text)
# ---------------------------------------------------------------------------

MLAG_TEXT_ACTIVE = """\
MLAG Configuration:
domain-id                          :        mlag-domain
local-interface                    :            Vlan4094
peer-address                       :          10.255.0.2
peer-link                          :     Port-Channel1
peer-config                        :        consistent

MLAG Status:
state                              :              Active
negotiation status                 :           Connected
peer-link status                   :                  Up
local-int status                   :                  Up
"""

MLAG_TEXT_PEER_LINK_DOWN = """\
MLAG Configuration:
domain-id                          :        mlag-domain
local-interface                    :            Vlan4094
peer-address                       :          10.255.0.2
peer-link                          :     Port-Channel1
peer-config                        :        inconsistent

MLAG Status:
state                              :              Active
negotiation status                 :        Disconnected
peer-link status                   :                Down
"""

# ---------------------------------------------------------------------------
# show mlag config-sanity  (JSON)
# ---------------------------------------------------------------------------

MLAG_SANITY_CONSISTENT = {
    "globalConfiguration": {
        "mlagPeerLinkVlan": {
            "consistent": True,
            "localValue": "4094",
            "peerValue": "4094",
        }
    },
    "interfaceConfiguration": {},
}

MLAG_SANITY_INCONSISTENT = {
    "globalConfiguration": {
        "spanningTreeMode": {
            "consistent": False,
            "localValue": "mstp",
            "peerValue": "rstp",
        }
    },
    "interfaceConfiguration": {
        "Port-Channel10": {
            "mlagId": {
                "consistent": False,
                "localValue": "10",
                "peerValue": "11",
            }
        }
    },
}

MLAG_SANITY_EMPTY = {}

# ---------------------------------------------------------------------------
# show environment all  (JSON)
# ---------------------------------------------------------------------------

ENVIRONMENT_DATA_OK = {
    "powerSupplySlots": [
        {"label": "PowerSupply1", "state": "powerOk"},
        {"label": "PowerSupply2", "state": "powerOk"},
    ],
    "fanTraySlots": [
        {
            "label": "FanTray1",
            "fans": [
                {"label": "Fan1", "speed": 40, "status": "ok"},
                {"label": "Fan2", "speed": 42, "status": "ok"},
            ],
        },
        {
            "label": "FanTray2",
            "fans": [
                {"label": "Fan1", "speed": 38, "status": "ok"},
            ],
        },
    ],
    "tempSensors": [
        {"name": "CPU", "currentTemperature": 40.0, "alertRaised": False},
        {"name": "Board", "currentTemperature": 35.0, "alertRaised": False},
    ],
}

ENVIRONMENT_DATA_FAULT = {
    "powerSupplySlots": [
        {"label": "PowerSupply1", "state": "powerOk"},
        {"label": "PowerSupply2", "state": "powerLoss"},
    ],
    "fanTraySlots": [
        {
            "label": "FanTray1",
            "fans": [
                {"label": "Fan1", "speed": 0, "status": "failed"},
            ],
        }
    ],
    "tempSensors": [
        {"name": "CPU", "currentTemperature": 85.0, "alertRaised": True},
    ],
}

ENVIRONMENT_DATA_EMPTY = {}

# ===========================================================================
# Parser tests
# ===========================================================================


class TestParseCpuMemoryEos:
    def test_parses_version(self):
        res = parse_cpu_memory_eos(VERSION_DATA)
        assert res["eos_version"] == "4.28.3M"
        assert res["model"] == "DCS-7050CX3-32S"
        assert res["serial_number"] == "JPE12345678"

    def test_cpu_utilization(self):
        res = parse_cpu_memory_eos(VERSION_DATA)
        # slot 0: 100 - 75 = 25; slot 1: 100 - 80 = 20 → avg = 22.5
        assert res["cpu_utilization"] == 22.5

    def test_memory_util(self):
        res = parse_cpu_memory_eos(VERSION_DATA)
        assert res["memory_total_kb"] == 8192000
        assert res["memory_used_kb"] == 8192000 - 3000000
        # util = 5192000 / 8192000 * 100 ≈ 63.4
        assert res["memory_util"] is not None
        assert 60.0 < res["memory_util"] < 70.0

    def test_high_cpu(self):
        res = parse_cpu_memory_eos(VERSION_DATA_HIGH_CPU)
        # slot 0: 90; slot 1: 95 → avg = 92.5
        assert res["cpu_utilization"] == 92.5

    def test_no_cpu_info(self):
        res = parse_cpu_memory_eos(VERSION_DATA_NO_CPU)
        assert res["cpu_utilization"] is None
        assert res["memory_total_kb"] == 4096000

    def test_empty_data(self):
        res = parse_cpu_memory_eos(VERSION_DATA_EMPTY)
        assert res["cpu_utilization"] is None
        assert res["memory_util"] is None

    def test_non_dict_input(self):
        res = parse_cpu_memory_eos("not a dict")
        assert res["cpu_utilization"] is None


class TestParseInterfacesEos:
    def test_parses_three_interfaces(self):
        res = parse_interfaces_eos(INTERFACES_DATA)
        assert len(res) == 3

    def test_interface_with_errors(self):
        res = parse_interfaces_eos(INTERFACES_DATA)
        eth2 = next(i for i in res if i["name"] == "Ethernet2")
        assert eth2["has_errors"] is True
        assert eth2["in_errors"] == 5
        assert eth2["out_errors"] == 2
        assert eth2["crc_errors"] == 1

    def test_interface_no_errors(self):
        res = parse_interfaces_eos(INTERFACES_DATA)
        eth1 = next(i for i in res if i["name"] == "Ethernet1")
        assert eth1["has_errors"] is False

    def test_is_up_flag(self):
        res = parse_interfaces_eos(INTERFACES_DATA)
        eth1 = next(i for i in res if i["name"] == "Ethernet1")
        eth3 = next(i for i in res if i["name"] == "Ethernet3")
        assert eth1["is_up"] is True
        assert eth3["is_up"] is False

    def test_clean_interfaces(self):
        res = parse_interfaces_eos(INTERFACES_DATA_CLEAN)
        assert len(res) == 1
        assert res[0]["has_errors"] is False

    def test_empty_data(self):
        res = parse_interfaces_eos(INTERFACES_DATA_EMPTY)
        assert res == []


class TestParseInterfaceCountersEos:
    def test_parses_two_interfaces(self):
        res = parse_interface_counters_eos(COUNTERS_DATA)
        assert len(res) == 2

    def test_no_errors_interface(self):
        res = parse_interface_counters_eos(COUNTERS_DATA)
        eth1 = next(i for i in res if i["name"] == "Ethernet1")
        assert eth1["has_errors"] is False
        assert eth1["fcs_errors"] == 0

    def test_errors_interface(self):
        res = parse_interface_counters_eos(COUNTERS_DATA)
        eth2 = next(i for i in res if i["name"] == "Ethernet2")
        assert eth2["has_errors"] is True
        assert eth2["fcs_errors"] == 3
        assert eth2["align_errors"] == 1
        assert eth2["in_errors"] == 4

    def test_empty_data(self):
        res = parse_interface_counters_eos(COUNTERS_DATA_EMPTY)
        assert res == []


class TestParseTransceiversEos:
    def test_parses_two_transceivers(self):
        res = parse_transceivers_eos(TRANSCEIVERS_DATA)
        assert len(res) == 2

    def test_multi_lane_averages(self):
        res = parse_transceivers_eos(TRANSCEIVERS_DATA)
        eth1 = next(t for t in res if t["interface"] == "Ethernet1")
        assert eth1["tx_power_dbm"] == round((-2.1 + -2.3) / 2, 2)
        assert eth1["rx_power_dbm"] == round((-3.0 + -3.1) / 2, 2)
        assert eth1["media_type"] == "100GBASE-SR4"
        assert eth1["temperature_c"] == 35.5

    def test_dom_alert_raised(self):
        res = parse_transceivers_eos(TRANSCEIVERS_DATA)
        eth2 = next(t for t in res if t["interface"] == "Ethernet2")
        assert eth2["alert"] is True

    def test_no_dom_alert(self):
        res = parse_transceivers_eos(TRANSCEIVERS_DATA)
        eth1 = next(t for t in res if t["interface"] == "Ethernet1")
        assert eth1["alert"] is False

    def test_empty_data(self):
        res = parse_transceivers_eos(TRANSCEIVERS_DATA_EMPTY)
        assert res == []


class TestParseBgpSummaryEos:
    def test_parses_two_peers(self):
        res = parse_bgp_summary_eos(BGP_SUMMARY_DATA)
        assert len(res) == 2

    def test_established_peer(self):
        res = parse_bgp_summary_eos(BGP_SUMMARY_DATA)
        peer = next(p for p in res if p["neighbor"] == "10.0.0.2")
        assert peer["state"] == "Established"
        assert peer["is_established"] is True
        assert peer["peer_as"] == 65002
        assert peer["prefixes_rcvd"] == 50

    def test_active_peer(self):
        res = parse_bgp_summary_eos(BGP_SUMMARY_DATA)
        peer = next(p for p in res if p["neighbor"] == "10.0.0.3")
        assert peer["state"] == "Active"
        assert peer["is_established"] is False

    def test_all_established(self):
        res = parse_bgp_summary_eos(BGP_SUMMARY_ALL_ESTABLISHED)
        assert len(res) == 2
        assert all(p["is_established"] for p in res)

    def test_empty_data(self):
        res = parse_bgp_summary_eos(BGP_SUMMARY_EMPTY)
        assert res == []


class TestParseBgpEvpnEos:
    def test_same_as_bgp_summary(self):
        res = parse_bgp_evpn_eos(BGP_SUMMARY_DATA)
        # Same structure as bgp summary
        assert isinstance(res, list)


class TestParseBgpSummaryEosText:
    def test_parses_two_peers(self):
        res = parse_bgp_summary_eos_text(BGP_SUMMARY_TEXT)
        assert len(res) == 2

    def test_established_normalised(self):
        res = parse_bgp_summary_eos_text(BGP_SUMMARY_TEXT)
        estab = [p for p in res if p["is_established"]]
        assert len(estab) == 1
        assert estab[0]["neighbor"] == "10.0.0.2"
        assert estab[0]["state"] == "Established"

    def test_active_peer(self):
        res = parse_bgp_summary_eos_text(BGP_SUMMARY_TEXT)
        peer = next(p for p in res if p["neighbor"] == "10.0.0.3")
        assert peer["state"] == "Active"
        assert peer["is_established"] is False

    def test_all_established(self):
        res = parse_bgp_summary_eos_text(BGP_SUMMARY_TEXT_ALL_ESTAB)
        assert len(res) == 2
        assert all(p["is_established"] for p in res)

    def test_empty_output(self):
        res = parse_bgp_summary_eos_text("")
        assert res == []


class TestParseOspfNeighborsEos:
    def test_parses_three_neighbors(self):
        res = parse_ospf_neighbors_eos(OSPF_NEIGHBORS_DATA)
        assert len(res) == 3

    def test_full_state(self):
        res = parse_ospf_neighbors_eos(OSPF_NEIGHBORS_DATA)
        full = [n for n in res if n["is_full"]]
        assert len(full) == 2

    def test_exstart_state(self):
        res = parse_ospf_neighbors_eos(OSPF_NEIGHBORS_DATA)
        exstart = [n for n in res if n["state"] == "ExStart"]
        assert len(exstart) == 1
        assert exstart[0]["is_full"] is False

    def test_all_full(self):
        res = parse_ospf_neighbors_eos(OSPF_NEIGHBORS_ALL_FULL)
        assert len(res) == 2
        assert all(n["is_full"] for n in res)

    def test_empty_data(self):
        res = parse_ospf_neighbors_eos(OSPF_NEIGHBORS_EMPTY)
        assert res == []


class TestParseOspfNeighborsEosText:
    def test_parses_three_neighbors(self):
        res = parse_ospf_neighbors_eos_text(OSPF_TEXT)
        assert len(res) == 3

    def test_full_neighbors(self):
        res = parse_ospf_neighbors_eos_text(OSPF_TEXT)
        full = [n for n in res if n["is_full"]]
        assert len(full) == 2

    def test_exstart_neighbor(self):
        res = parse_ospf_neighbors_eos_text(OSPF_TEXT)
        exstart = [n for n in res if n["state"] == "ExStart"]
        assert len(exstart) == 1
        assert exstart[0]["neighbor_id"] == "192.168.1.4"
        assert exstart[0]["interface"] == "Ethernet3"

    def test_all_full(self):
        res = parse_ospf_neighbors_eos_text(OSPF_TEXT_ALL_FULL)
        assert len(res) == 2
        assert all(n["is_full"] for n in res)

    def test_empty_output(self):
        res = parse_ospf_neighbors_eos_text("")
        assert res == []


class TestParseMlagEos:
    def test_active_state(self):
        res = parse_mlag_eos(MLAG_DATA_ACTIVE)
        assert res["is_active"] is True
        assert res["is_peer_active"] is True
        assert res["peer_link_ok"] is True
        assert res["state"] == "active"
        assert res["peer_link"] == "Port-Channel1"
        assert res["peer_ip"] == "10.255.0.2"

    def test_inactive_state(self):
        res = parse_mlag_eos(MLAG_DATA_INACTIVE)
        assert res["is_active"] is False
        assert res["peer_link_ok"] is False

    def test_peer_link_down(self):
        res = parse_mlag_eos(MLAG_DATA_PEER_LINK_DOWN)
        assert res["is_active"] is True
        assert res["peer_link_ok"] is False

    def test_empty_data(self):
        res = parse_mlag_eos(MLAG_DATA_EMPTY)
        assert res["is_active"] is False
        assert res["peer_link_ok"] is False


class TestParseMlagEosText:
    def test_active_state(self):
        res = parse_mlag_eos_text(MLAG_TEXT_ACTIVE)
        assert res["is_active"] is True
        assert res["peer_link_ok"] is True
        assert res["peer_link"] == "Port-Channel1"
        assert res["peer_ip"] == "10.255.0.2"
        assert res["local_interface"] == "Vlan4094"
        assert res["config_sanity"] == "consistent"

    def test_peer_link_down(self):
        res = parse_mlag_eos_text(MLAG_TEXT_PEER_LINK_DOWN)
        assert res["is_active"] is True
        assert res["peer_link_ok"] is False
        assert res["config_sanity"] == "inconsistent"

    def test_empty_output(self):
        res = parse_mlag_eos_text("")
        assert res["is_active"] is False


class TestParseMlagConfigSanityEos:
    def test_consistent(self):
        res = parse_mlag_config_sanity_eos(MLAG_SANITY_CONSISTENT)
        assert res["consistent"] is True
        assert res["global_inconsistencies"] == []
        assert res["interface_inconsistencies"] == []

    def test_inconsistent(self):
        res = parse_mlag_config_sanity_eos(MLAG_SANITY_INCONSISTENT)
        assert res["consistent"] is False
        assert len(res["global_inconsistencies"]) == 1
        assert len(res["interface_inconsistencies"]) == 1
        assert "spanningTreeMode" in res["global_inconsistencies"][0]
        assert res["interface_inconsistencies"][0]["interface"] == "Port-Channel10"

    def test_empty_data(self):
        res = parse_mlag_config_sanity_eos(MLAG_SANITY_EMPTY)
        assert res["consistent"] is True


class TestParseEnvironmentEos:
    def test_all_ok(self):
        res = parse_environment_eos(ENVIRONMENT_DATA_OK)
        assert res["overall_ok"] is True

    def test_power_supplies_parsed(self):
        res = parse_environment_eos(ENVIRONMENT_DATA_OK)
        assert len(res["power_supplies"]) == 2
        assert all(p["ok"] for p in res["power_supplies"])

    def test_fans_parsed(self):
        res = parse_environment_eos(ENVIRONMENT_DATA_OK)
        assert len(res["fans"]) == 3  # 2 in FanTray1 + 1 in FanTray2
        assert all(f["ok"] for f in res["fans"])

    def test_temperatures_parsed(self):
        res = parse_environment_eos(ENVIRONMENT_DATA_OK)
        assert len(res["temperatures"]) == 2
        assert all(t["ok"] for t in res["temperatures"])

    def test_fault_detected(self):
        res = parse_environment_eos(ENVIRONMENT_DATA_FAULT)
        assert res["overall_ok"] is False
        failed_psu = [p for p in res["power_supplies"] if not p["ok"]]
        assert len(failed_psu) == 1
        assert failed_psu[0]["status"] == "powerLoss"

    def test_fan_fault(self):
        res = parse_environment_eos(ENVIRONMENT_DATA_FAULT)
        failed_fans = [f for f in res["fans"] if not f["ok"]]
        assert len(failed_fans) == 1

    def test_temp_alert(self):
        res = parse_environment_eos(ENVIRONMENT_DATA_FAULT)
        alerted = [t for t in res["temperatures"] if t["alert_raised"]]
        assert len(alerted) == 1
        assert alerted[0]["celsius"] == 85.0

    def test_empty_data(self):
        res = parse_environment_eos(ENVIRONMENT_DATA_EMPTY)
        assert res["power_supplies"] == []
        assert res["fans"] == []
        assert res["temperatures"] == []
        assert res["overall_ok"] is True


# ===========================================================================
# Check function tests (using mocked DeviceConnection)
# ===========================================================================


class _MockConn:
    """Minimal DeviceConnection mock returning canned JSON or text per command."""

    def __init__(self, json_responses: dict, text_responses: dict | None = None):
        self._json = json_responses
        self._text = text_responses or {}

    def send(self, command: str) -> dict | str:
        # Return JSON dict when command ends with "| json" or exact match found
        cmd_clean = command.replace(" | json", "").strip()
        for key, val in self._json.items():
            if key in cmd_clean:
                return val
        for key, val in self._text.items():
            if key in cmd_clean:
                return val
        return {}


class TestCheckEosCpuMemory:
    def test_normal_operation(self):
        conn = _MockConn({"show version": VERSION_DATA})
        res = check_eos_cpu_memory(conn, 80.0, 85.0)
        assert res["error"] is None
        assert res["cpu_utilization"] is not None
        assert res["memory_util"] is not None
        assert res["alert"] is False

    def test_high_cpu_triggers_alert(self):
        conn = _MockConn({"show version": VERSION_DATA_HIGH_CPU})
        res = check_eos_cpu_memory(conn, 80.0, 95.0)
        assert res["cpu_alert"] is True
        assert res["alert"] is True

    def test_high_mem_triggers_alert(self):
        conn = _MockConn({"show version": VERSION_DATA_HIGH_CPU})
        # VERSION_DATA_HIGH_CPU: mem used = 8192000-500000 = 7692000 → ~93.9%
        res = check_eos_cpu_memory(conn, 99.0, 85.0)
        assert res["mem_alert"] is True
        assert res["alert"] is True

    def test_empty_data_no_alert(self):
        conn = _MockConn({"show version": VERSION_DATA_EMPTY})
        res = check_eos_cpu_memory(conn, 80.0, 85.0)
        assert res["cpu_utilization"] is None
        assert res["alert"] is False

    def test_exception_returns_safe_dict(self):
        class _BrokenConn:
            def send(self, _cmd):
                raise RuntimeError("connection lost")

        res = check_eos_cpu_memory(_BrokenConn(), 80.0, 85.0)
        assert res["alert"] is False
        assert res["error"] is not None


class TestCheckEosInterfaces:
    def test_with_errors_triggers_alert(self):
        conn = _MockConn({"show interfaces": INTERFACES_DATA})
        res = check_eos_interfaces(conn)
        assert res["with_errors"] == 1
        assert res["alert"] is True

    def test_clean_no_alert(self):
        conn = _MockConn({"show interfaces": INTERFACES_DATA_CLEAN})
        res = check_eos_interfaces(conn)
        assert res["with_errors"] == 0
        assert res["alert"] is False

    def test_empty_data(self):
        conn = _MockConn({"show interfaces": INTERFACES_DATA_EMPTY})
        res = check_eos_interfaces(conn)
        assert res["total"] == 0
        assert res["alert"] is False


class TestCheckEosTransceivers:
    def test_dom_alert_triggers(self):
        conn = _MockConn({"show interfaces transceiver": TRANSCEIVERS_DATA})
        res = check_eos_transceivers(conn)
        assert res["with_alerts"] == 1
        assert res["alert"] is True

    def test_no_transceivers_no_alert(self):
        conn = _MockConn({"show interfaces transceiver": TRANSCEIVERS_DATA_EMPTY})
        res = check_eos_transceivers(conn)
        assert res["total"] == 0
        assert res["alert"] is False


class TestCheckEosBgp:
    def test_partial_established_triggers_alert(self):
        conn = _MockConn({"show bgp summary": BGP_SUMMARY_DATA})
        res = check_eos_bgp(conn)
        assert res["established"] == 1
        assert res["not_established"] == 1
        assert res["alert"] is True

    def test_all_established_no_alert(self):
        conn = _MockConn({"show bgp summary": BGP_SUMMARY_ALL_ESTABLISHED})
        res = check_eos_bgp(conn)
        assert res["not_established"] == 0
        assert res["alert"] is False

    def test_no_peers_no_alert(self):
        conn = _MockConn({"show bgp summary": BGP_SUMMARY_EMPTY})
        res = check_eos_bgp(conn)
        assert res["total"] == 0
        assert res["alert"] is False


class TestCheckEosBgpEvpn:
    def test_partial_established_triggers_alert(self):
        conn = _MockConn({"show bgp evpn summary": BGP_SUMMARY_DATA})
        res = check_eos_bgp_evpn(conn)
        assert res["established"] == 1
        assert res["alert"] is True

    def test_all_established_no_alert(self):
        conn = _MockConn({"show bgp evpn summary": BGP_SUMMARY_ALL_ESTABLISHED})
        res = check_eos_bgp_evpn(conn)
        assert res["alert"] is False


class TestCheckEosOspf:
    def test_partial_full_triggers_alert(self):
        conn = _MockConn({"show ip ospf neighbor": OSPF_NEIGHBORS_DATA})
        res = check_eos_ospf(conn)
        assert res["full"] == 2
        assert res["not_full"] == 1
        assert res["alert"] is True

    def test_all_full_no_alert(self):
        conn = _MockConn({"show ip ospf neighbor": OSPF_NEIGHBORS_ALL_FULL})
        res = check_eos_ospf(conn)
        assert res["not_full"] == 0
        assert res["alert"] is False

    def test_no_neighbors_no_alert(self):
        conn = _MockConn({"show ip ospf neighbor": OSPF_NEIGHBORS_EMPTY})
        res = check_eos_ospf(conn)
        assert res["total"] == 0
        assert res["alert"] is False


class TestCheckEosMlag:
    def test_active_healthy_no_alert(self):
        conn = _MockConn(
            {
                "show mlag config-sanity": MLAG_SANITY_CONSISTENT,
                "show mlag": MLAG_DATA_ACTIVE,
            }
        )
        res = check_eos_mlag(conn)
        assert res["is_active"] is True
        assert res["peer_link_ok"] is True
        assert res["config_consistent"] is True
        assert res["alert"] is False

    def test_peer_link_down_triggers_alert(self):
        conn = _MockConn(
            {
                "show mlag config-sanity": MLAG_SANITY_CONSISTENT,
                "show mlag": MLAG_DATA_PEER_LINK_DOWN,
            }
        )
        res = check_eos_mlag(conn)
        assert res["peer_link_ok"] is False
        assert res["alert"] is True

    def test_config_inconsistency_triggers_alert(self):
        conn = _MockConn(
            {
                "show mlag config-sanity": MLAG_SANITY_INCONSISTENT,
                "show mlag": MLAG_DATA_ACTIVE,
            }
        )
        res = check_eos_mlag(conn)
        assert res["config_consistent"] is False
        assert res["alert"] is True

    def test_inactive_mlag_no_alert(self):
        conn = _MockConn(
            {
                "show mlag config-sanity": MLAG_SANITY_EMPTY,
                "show mlag": MLAG_DATA_INACTIVE,
            }
        )
        res = check_eos_mlag(conn)
        # MLAG inactive → not alerting (device simply doesn't use MLAG)
        assert res["is_active"] is False
        assert res["alert"] is False


class TestCheckEosEnvironment:
    def test_all_ok_no_alert(self):
        conn = _MockConn({"show environment all": ENVIRONMENT_DATA_OK})
        res = check_eos_environment(conn)
        assert res["overall_ok"] is True
        assert res["alert"] is False

    def test_fault_triggers_alert(self):
        conn = _MockConn({"show environment all": ENVIRONMENT_DATA_FAULT})
        res = check_eos_environment(conn)
        assert res["overall_ok"] is False
        assert res["alert"] is True

    def test_empty_data_no_alert(self):
        conn = _MockConn({"show environment all": ENVIRONMENT_DATA_EMPTY})
        res = check_eos_environment(conn)
        assert res["alert"] is False


# ===========================================================================
# build_eos_health_report tests
# ===========================================================================


class TestBuildEosHealthReport:
    def _make_result(self, host: str, success: bool = True, alert: bool = False) -> dict:
        return {
            "host": host,
            "timestamp": "2024-01-01T00:00:00Z",
            "success": success,
            "overall_alert": alert,
            "checks": {
                "cpu_memory": {"alert": alert},
                "interfaces": {"alert": False},
                "bgp": {"alert": False},
                "ospf": {"alert": False},
                "mlag": {"alert": False},
                "environment": {"alert": False},
            },
            "error": None,
        }

    def test_all_ok(self):
        results = [self._make_result("10.0.0.1"), self._make_result("10.0.0.2")]
        report = build_eos_health_report(results)
        assert report["devices"] == 2
        assert report["devices_reachable"] == 2
        assert report["devices_with_alerts"] == 0
        assert report["overall_alert"] is False

    def test_one_alert(self):
        results = [
            self._make_result("10.0.0.1"),
            self._make_result("10.0.0.2", alert=True),
        ]
        report = build_eos_health_report(results)
        assert report["devices_with_alerts"] == 1
        assert report["cpu_memory_alerts"] == 1
        assert report["overall_alert"] is True

    def test_unreachable_device(self):
        results = [
            self._make_result("10.0.0.1"),
            self._make_result("10.0.0.2", success=False),
        ]
        report = build_eos_health_report(results)
        assert report["devices"] == 2
        assert report["devices_reachable"] == 1

    def test_empty_results(self):
        report = build_eos_health_report([])
        assert report["devices"] == 0
        assert report["overall_alert"] is False


# ===========================================================================
# Threshold parser tests
# ===========================================================================


class TestParseThresholds:
    def test_basic_parse(self):
        t = _parse_thresholds("cpu=80,mem=85")
        assert t["cpu"] == 80.0
        assert t["mem"] == 85.0

    def test_empty_string(self):
        assert _parse_thresholds("") == {}

    def test_none(self):
        assert _parse_thresholds(None) == {}

    def test_single_threshold(self):
        t = _parse_thresholds("cpu=90")
        assert t["cpu"] == 90.0
        assert "mem" not in t

    def test_invalid_entry_ignored(self):
        t = _parse_thresholds("cpu=80,invalid,mem=85")
        assert t["cpu"] == 80.0
        assert t["mem"] == 85.0


# ===========================================================================
# Template tests
# ===========================================================================


class TestEosHealthTemplate:
    def test_template_has_expected_keys(self):
        expected = {
            "cpu_memory",
            "interfaces",
            "interface_counters",
            "bgp_summary",
            "bgp_evpn",
            "ospf_neighbors",
            "mlag",
            "mlag_config_sanity",
            "environment",
        }
        assert expected.issubset(set(EOS_HEALTH.keys()))

    def test_defaults_match(self):
        assert DEFAULT_CPU_THRESHOLD == 80.0
        assert DEFAULT_MEM_THRESHOLD == 85.0


# ===========================================================================
# Additional imports for new test classes
# ===========================================================================


# ===========================================================================
# Helpers
# ===========================================================================


class _RaisingConn:
    """Mock connection that always raises RuntimeError on send()."""

    def send(self, command: str):
        raise RuntimeError("simulated send failure")


# ===========================================================================
# _send_json
# ===========================================================================


class TestSendJson:
    def test_dict_response_returned_directly(self):
        conn = _MockConn({"show version": {"key": "value"}})
        assert _send_json(conn, "show version") == {"key": "value"}

    def test_json_string_parsed(self):
        conn = _MockConn({}, {"show version": '{"status": "ok"}'})
        assert _send_json(conn, "show version") == {"status": "ok"}

    def test_malformed_json_string_returns_empty_dict(self):
        # Starts with '{' but is not valid JSON — covers the `pass` on decode failure.
        conn = _MockConn({}, {"show version": "{malformed json"})
        assert _send_json(conn, "show version") == {}

    def test_plain_text_response_returns_empty_dict(self):
        conn = _MockConn({}, {"show version": "plain text output"})
        assert _send_json(conn, "show version") == {}

    def test_no_matching_response_returns_empty_dict(self):
        conn = _MockConn({})
        assert _send_json(conn, "show version") == {}


# ===========================================================================
# check_eos_* error paths
# ===========================================================================


class TestCheckEosCpuMemoryError:
    def test_exception_returns_error_dict(self):
        res = check_eos_cpu_memory(_RaisingConn(), 80.0, 85.0)
        assert res["error"] is not None
        assert "simulated" in res["error"]
        assert res["alert"] is False
        assert res["cpu_utilization"] is None
        assert res["cpu_alert"] is False
        assert res["mem_alert"] is False


class TestCheckEosInterfacesError:
    def test_exception_returns_error_dict(self):
        res = check_eos_interfaces(_RaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["interfaces"] == []
        assert res["total"] == 0
        assert res["with_errors"] == 0


class TestCheckEosTransceiversError:
    def test_exception_returns_error_dict(self):
        res = check_eos_transceivers(_RaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["transceivers"] == []
        assert res["total"] == 0
        assert res["with_alerts"] == 0


class TestCheckEosBgpError:
    def test_exception_returns_error_dict(self):
        res = check_eos_bgp(_RaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["peers"] == []
        assert res["total"] == 0
        assert res["established"] == 0
        assert res["not_established"] == 0


class TestCheckEosBgpEvpnError:
    def test_exception_returns_error_dict(self):
        res = check_eos_bgp_evpn(_RaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["peers"] == []
        assert res["total"] == 0


class TestCheckEosOspfError:
    def test_exception_returns_error_dict(self):
        res = check_eos_ospf(_RaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["neighbors"] == []
        assert res["total"] == 0
        assert res["full"] == 0
        assert res["not_full"] == 0


class TestCheckEosMlagError:
    def test_exception_returns_error_dict(self):
        res = check_eos_mlag(_RaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["is_active"] is False
        assert res["peer_link_ok"] is False
        assert res["config_consistent"] is True


class TestCheckEosEnvironmentError:
    def test_exception_returns_error_dict(self):
        res = check_eos_environment(_RaisingConn())
        assert res["error"] is not None
        assert res["alert"] is False
        assert res["power_supplies"] == []
        assert res["fans"] == []
        assert res["temperatures"] == []


# ===========================================================================
# run_health_check
# ===========================================================================


class TestRunEosHealthCheck:
    def _make_params(self):
        return _AristaConnParams(
            host="10.0.0.1",
            username="admin",
            password="secret",
            device_type="arista_eos",
        )

    def _healthy_mock(self):
        return _MockConn(
            {
                "show version": VERSION_DATA,
                "show interfaces": INTERFACES_DATA_CLEAN,
                "show bgp summary": BGP_SUMMARY_ALL_ESTABLISHED,
                "show ip ospf neighbor": OSPF_NEIGHBORS_EMPTY,
                "show mlag config-sanity": MLAG_SANITY_CONSISTENT,
                "show mlag": MLAG_DATA_INACTIVE,
                "show environment all": ENVIRONMENT_DATA_OK,
            }
        )

    def test_success_path(self, monkeypatch):
        healthy = self._healthy_mock()

        class _FakeConn:
            def __enter__(self_inner):
                return healthy

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.arista.DeviceConnection", lambda _p: _FakeConn())
        result = run_health_check(self._make_params())
        assert result["success"] is True
        assert result["error"] is None
        assert "cpu_memory" in result["checks"]
        assert "interfaces" in result["checks"]
        assert "environment" in result["checks"]

    def test_connection_failure(self, monkeypatch):
        class _FailConn:
            def __enter__(self_inner):
                raise OSError("cannot connect")

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.arista.DeviceConnection", lambda _p: _FailConn())
        result = run_health_check(self._make_params())
        assert result["success"] is False
        assert result["error"] is not None

    def test_optional_transceivers_and_evpn_included(self, monkeypatch):
        conn_data = _MockConn(
            {
                "show version": VERSION_DATA,
                "show interfaces": INTERFACES_DATA_CLEAN,
                "show interfaces transceiver": TRANSCEIVERS_DATA_EMPTY,
                "show bgp summary": BGP_SUMMARY_ALL_ESTABLISHED,
                "show bgp evpn summary": BGP_SUMMARY_EMPTY,
                "show ip ospf neighbor": OSPF_NEIGHBORS_EMPTY,
                "show mlag config-sanity": MLAG_SANITY_CONSISTENT,
                "show mlag": MLAG_DATA_INACTIVE,
                "show environment all": ENVIRONMENT_DATA_OK,
            }
        )

        class _FakeConn:
            def __enter__(self_inner):
                return conn_data

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.arista.DeviceConnection", lambda _p: _FakeConn())
        result = run_health_check(
            self._make_params(), check_transceivers=True, check_evpn=True
        )
        assert result["success"] is True
        assert "transceivers" in result["checks"]
        assert "bgp_evpn" in result["checks"]

    def test_bgp_and_ospf_skipped_when_disabled(self, monkeypatch):
        conn_data = _MockConn(
            {
                "show version": VERSION_DATA,
                "show interfaces": INTERFACES_DATA_CLEAN,
                "show mlag config-sanity": MLAG_SANITY_CONSISTENT,
                "show mlag": MLAG_DATA_INACTIVE,
                "show environment all": ENVIRONMENT_DATA_OK,
            }
        )

        class _FakeConn:
            def __enter__(self_inner):
                return conn_data

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.arista.DeviceConnection", lambda _p: _FakeConn())
        result = run_health_check(
            self._make_params(), check_bgp=False, check_ospf=False
        )
        assert result["success"] is True
        assert "bgp" not in result["checks"]
        assert "ospf" not in result["checks"]

    def test_overall_alert_set_when_check_alerts(self, monkeypatch):
        conn_data = _MockConn(
            {
                "show version": VERSION_DATA_HIGH_CPU,
                "show interfaces": INTERFACES_DATA_CLEAN,
                "show bgp summary": BGP_SUMMARY_ALL_ESTABLISHED,
                "show ip ospf neighbor": OSPF_NEIGHBORS_EMPTY,
                "show mlag config-sanity": MLAG_SANITY_CONSISTENT,
                "show mlag": MLAG_DATA_INACTIVE,
                "show environment all": ENVIRONMENT_DATA_OK,
            }
        )

        class _FakeConn:
            def __enter__(self_inner):
                return conn_data

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.arista.DeviceConnection", lambda _p: _FakeConn())
        result = run_health_check(self._make_params(), cpu_threshold=50.0)
        assert result["success"] is True
        assert result["overall_alert"] is True


# ===========================================================================
# build_eos_health_report — additional coverage
# ===========================================================================


class TestBuildEosHealthReportExtra:
    def _make_result(self, host, success=True, overall_alert=False, checks=None):
        return {
            "host": host,
            "timestamp": "2024-01-01T00:00:00Z",
            "success": success,
            "overall_alert": overall_alert,
            "checks": checks or {},
            "error": None,
        }

    def test_bgp_alert_counted(self):
        checks = {
            "cpu_memory": {"alert": False},
            "interfaces": {"alert": False},
            "bgp": {"alert": True},
            "ospf": {"alert": False},
            "mlag": {"alert": False},
            "environment": {"alert": False},
        }
        result = self._make_result("10.0.0.1", overall_alert=True, checks=checks)
        report = build_eos_health_report([result])
        assert report["bgp_alerts"] == 1
        assert report["overall_alert"] is True

    def test_interface_and_ospf_alerts_counted(self):
        checks_r1 = {
            "interfaces": {"alert": True},
            "ospf": {"alert": False},
        }
        checks_r2 = {
            "interfaces": {"alert": False},
            "ospf": {"alert": True},
        }
        r1 = self._make_result("r1", overall_alert=True, checks=checks_r1)
        r2 = self._make_result("r2", overall_alert=True, checks=checks_r2)
        report = build_eos_health_report([r1, r2])
        assert report["interface_alerts"] == 1
        assert report["ospf_alerts"] == 1

    def test_results_key_contains_originals(self):
        r = self._make_result("10.0.0.1")
        report = build_eos_health_report([r])
        assert report["results"] is not None
        assert len(report["results"]) == 1
        assert report["results"][0]["host"] == "10.0.0.1"


# ===========================================================================
# _parse_thresholds — ValueError path (lines 555-556)
# ===========================================================================


class TestParseThresholdsValueError:
    def test_non_float_value_skipped(self):
        # "cpu=abc" triggers ValueError → pass → key not added
        t = _parse_thresholds("cpu=abc,mem=85")
        assert "cpu" not in t
        assert t["mem"] == 85.0

    def test_all_invalid_returns_empty(self):
        t = _parse_thresholds("cpu=notanumber,mem=alsonotanumber")
        assert t == {}


# ===========================================================================
# check_eos_bgp / check_eos_ospf text fallback paths (lines 232, 305, 349-351)
# ===========================================================================


class TestCheckEosBgpTextFallback:
    def test_text_fallback_used_when_json_empty(self):
        # json responses return nothing for bgp summary → text response kicks in
        conn = _MockConn(
            {},
            {"show bgp summary": BGP_SUMMARY_TEXT_ALL_ESTAB},
        )
        res = check_eos_bgp(conn)
        assert res["error"] is None
        assert res["total"] > 0
        assert res["not_established"] == 0
        assert res["alert"] is False


class TestCheckEosOspfTextFallback:
    def test_text_fallback_used_when_json_empty(self):
        conn = _MockConn(
            {},
            {"show ip ospf neighbor": OSPF_TEXT_ALL_FULL},
        )
        res = check_eos_ospf(conn)
        assert res["error"] is None


class TestCheckEosMlagTextFallback:
    def test_text_fallback_used_when_json_state_empty(self):
        # json returns empty MLAG dict → text fallback
        conn = _MockConn(
            {
                "show mlag config-sanity": MLAG_SANITY_CONSISTENT,
            },
            {
                "show mlag": MLAG_TEXT_ACTIVE,
            },
        )
        res = check_eos_mlag(conn)
        assert res["error"] is None


# ===========================================================================
# _print_result (lines 562-637)
# ===========================================================================


class TestEosPrintResult:
    def _base_result(self, success=True, overall_alert=False, checks=None):
        return {
            "host": "10.0.0.1",
            "timestamp": "2026-01-01T00:00:00Z",
            "success": success,
            "overall_alert": overall_alert,
            "checks": checks or {},
            "error": None,
        }

    def test_failed_device_prints_error(self, capsys):
        result = self._base_result(success=False)
        result["error"] = "Connection refused"
        _eos_print_result(result)
        out = capsys.readouterr().out
        assert "10.0.0.1" in out
        assert "ERROR" in out

    def test_healthy_device_shows_cpu_mem(self, capsys):
        checks = {
            "cpu_memory": {
                "cpu_utilization": 25.0,
                "memory_util": 60.0,
                "cpu_threshold": 80.0,
                "mem_threshold": 85.0,
                "eos_version": "4.28.3M",
                "model": "DCS-7050CX3",
                "alert": False,
            },
            "interfaces": {"with_errors": 0, "total": 10, "alert": False},
            "environment": {
                "power_supplies": [{"ok": True}],
                "fans": [{"ok": True}],
                "temperatures": [{"ok": True}],
                "alert": False,
            },
        }
        _eos_print_result(self._base_result(checks=checks))
        out = capsys.readouterr().out
        assert "10.0.0.1" in out
        assert "25.0%" in out
        assert "60.0%" in out

    def test_bgp_evpn_and_ospf_printed_when_present(self, capsys):
        checks = {
            "cpu_memory": {"cpu_utilization": None, "memory_util": None, "alert": False},
            "interfaces": {"with_errors": 0, "total": 0, "alert": False},
            "bgp": {"established": 2, "total": 2, "alert": False},
            "bgp_evpn": {"established": 1, "total": 1, "alert": False},
            "ospf": {"full": 3, "total": 3, "alert": False},
            "mlag": {
                "alert": False,
                "config_consistent": True,
                "mlag": {"state": "active"},
            },
            "environment": {
                "power_supplies": [],
                "fans": [],
                "temperatures": [],
                "alert": False,
            },
        }
        _eos_print_result(self._base_result(checks=checks))
        out = capsys.readouterr().out
        assert "BGP" in out
        assert "EVPN" in out
        assert "OSPF" in out
        assert "MLAG" in out

    def test_mlag_config_inconsistency_shown(self, capsys):
        checks = {
            "cpu_memory": {"cpu_utilization": None, "memory_util": None, "alert": False},
            "interfaces": {"with_errors": 0, "total": 0, "alert": False},
            "mlag": {
                "alert": True,
                "config_consistent": False,
                "mlag": {"state": "active"},
            },
            "environment": {
                "power_supplies": [],
                "fans": [],
                "temperatures": [],
                "alert": False,
            },
        }
        _eos_print_result(self._base_result(checks=checks))
        out = capsys.readouterr().out
        assert "SANITY" in out or "inconsistencies" in out
