"""Parsers for Arista EOS eAPI JSON responses and CLI text output.

Arista EOS supports two output modes:

* **eAPI JSON** – structured JSON returned by the ``/command-api`` endpoint
  or via Netmiko ``send_command(..., use_genie=False)`` with
  ``output_format="json"``.  These are the *primary* parsers and accept
  already-decoded ``dict`` objects.
* **CLI text** – plain-text ``show`` output, used as a fallback when eAPI
  is unavailable.  These parsers operate on raw strings.

All parser functions return lists or dicts that match the health-check schema
used by the rest of the toolkit (same key names as Juniper/Cisco equivalents
where possible).

Supported checks:

* **CPU / memory** – ``show version`` JSON (``systemStats`` block)
* **Interface counters** – ``show interfaces`` JSON / ``show interfaces
  counters errors`` JSON
* **Transceiver DOM** – ``show interfaces transceiver`` JSON
* **BGP summary** – ``show bgp summary`` JSON (IPv4 + EVPN)
* **OSPF neighbours** – ``show ip ospf neighbor`` JSON
* **MLAG health** – ``show mlag`` JSON + ``show mlag config-sanity`` JSON
* **Environment** – ``show environment all`` JSON (temperature, fans, PSUs)
"""

from __future__ import annotations

import re

__all__ = [
    # eAPI JSON parsers
    "parse_cpu_memory_eos",
    "parse_interfaces_eos",
    "parse_interface_counters_eos",
    "parse_transceivers_eos",
    "parse_bgp_summary_eos",
    "parse_bgp_evpn_eos",
    "parse_ospf_neighbors_eos",
    "parse_mlag_eos",
    "parse_mlag_config_sanity_eos",
    "parse_environment_eos",
    # CLI text parsers (fallback)
    "parse_bgp_summary_eos_text",
    "parse_ospf_neighbors_eos_text",
    "parse_mlag_eos_text",
]


# ---------------------------------------------------------------------------
# CPU / memory  (show version JSON)
# ---------------------------------------------------------------------------


def parse_cpu_memory_eos(data: dict) -> dict:
    """Parse ``show version`` eAPI JSON response for CPU and memory.

    Arista's ``show version`` JSON includes a ``systemStats`` sub-dict with:
    ``cpuInfo`` (per-core usage) and ``memUsed`` / ``memTotal`` fields.

    Returns a dict with:

    * ``cpu_utilization``   – overall CPU % (float) or ``None``
    * ``memory_total_kb``   – total physical RAM in KB (int) or ``None``
    * ``memory_used_kb``    – used RAM in KB (int) or ``None``
    * ``memory_util``       – memory utilisation % (float) or ``None``
    * ``uptime_seconds``    – system uptime in seconds (float) or ``None``
    * ``eos_version``       – EOS software version string or ``None``
    * ``serial_number``     – chassis serial number or ``None``
    * ``model``             – hardware model string or ``None``

    Returns a dict with all values ``None`` when parsing fails.
    """
    result: dict = {
        "cpu_utilization": None,
        "memory_total_kb": None,
        "memory_used_kb": None,
        "memory_util": None,
        "uptime_seconds": None,
        "eos_version": None,
        "serial_number": None,
        "model": None,
    }
    if not isinstance(data, dict):
        return result

    result["eos_version"] = data.get("version") or data.get("softwareImageVersion")
    result["serial_number"] = data.get("serialNumber")
    result["model"] = data.get("modelName")
    result["uptime_seconds"] = data.get("uptime")

    # Memory from top-level keys (present in most EOS versions)
    mem_total = data.get("memTotal")
    mem_free = data.get("memFree")
    if mem_total and mem_free is not None:
        result["memory_total_kb"] = int(mem_total)
        result["memory_used_kb"] = int(mem_total) - int(mem_free)
        result["memory_util"] = round(result["memory_used_kb"] / result["memory_total_kb"] * 100, 1)

    # CPU from systemStats (EOS 4.22+)
    sys_stats = data.get("systemStats", {})
    cpu_info = sys_stats.get("cpuInfo", {})
    if cpu_info:
        # cpuInfo is a dict keyed by CPU id; each value has "%Cpu(s)" or similar
        # Use "%" keys: user + system + nice + irq + softirq
        totals: list[float] = []
        for _cpu_id, cpu_data in cpu_info.items():
            idle = cpu_data.get("%idle", None)
            if idle is not None:
                totals.append(max(0.0, 100.0 - float(idle)))
        if totals:
            result["cpu_utilization"] = round(sum(totals) / len(totals), 1)

    # Fallback: top-level cpuInfo (older EOS)
    if result["cpu_utilization"] is None:
        top_cpu = data.get("cpuInfo", {})
        if top_cpu:
            totals = []
            for _cpu_id, cpu_data in top_cpu.items():
                idle = cpu_data.get("%idle", None)
                if idle is not None:
                    totals.append(max(0.0, 100.0 - float(idle)))
            if totals:
                result["cpu_utilization"] = round(sum(totals) / len(totals), 1)

    return result


# ---------------------------------------------------------------------------
# Interfaces  (show interfaces JSON)
# ---------------------------------------------------------------------------


def parse_interfaces_eos(data: dict) -> list[dict]:
    """Parse ``show interfaces`` eAPI JSON response.

    Returns a list of per-interface dicts:

    * ``name``           – interface name (str)
    * ``description``    – interface description (str)
    * ``line_protocol``  – line-protocol status (``'up'`` / ``'down'``)
    * ``oper_status``    – operational status string
    * ``link_status``    – link status (``'connected'`` / ``'notconnect'`` / …)
    * ``in_errors``      – input error count (int)
    * ``out_errors``     – output error count (int)
    * ``in_discards``    – input discard count (int)
    * ``out_discards``   – output discard count (int)
    * ``crc_errors``     – CRC align errors (int)
    * ``has_errors``     – ``True`` when any error counter > 0
    * ``is_up``          – ``True`` when both oper and line-protocol are up
    """
    interfaces: list[dict] = []
    ifaces = data.get("interfaces", {})
    if not isinstance(ifaces, dict):
        return interfaces

    for name, idata in ifaces.items():
        intf_status = idata.get("interfaceStatus", "")
        line_proto = idata.get("lineProtocolStatus", "")
        counters = idata.get("interfaceCounters", {})

        in_errors = int(counters.get("inputErrors", 0) or 0)
        out_errors = int(counters.get("outputErrors", 0) or 0)
        in_discards = int(counters.get("inDiscards", 0) or 0)
        out_discards = int(counters.get("outDiscards", 0) or 0)
        crc_errors = int(counters.get("alignmentErrors", 0) or 0)

        interfaces.append(
            {
                "name": name,
                "description": idata.get("description", ""),
                "line_protocol": line_proto,
                "oper_status": intf_status,
                "link_status": intf_status,
                "in_errors": in_errors,
                "out_errors": out_errors,
                "in_discards": in_discards,
                "out_discards": out_discards,
                "crc_errors": crc_errors,
                "has_errors": any([in_errors, out_errors, in_discards, out_discards, crc_errors]),
                "is_up": line_proto == "up" and intf_status == "connected",
            }
        )

    return interfaces


# ---------------------------------------------------------------------------
# Interface error counters  (show interfaces counters errors JSON)
# ---------------------------------------------------------------------------


def parse_interface_counters_eos(data: dict) -> list[dict]:
    """Parse ``show interfaces counters errors`` eAPI JSON response.

    Returns a list of per-interface error-counter dicts:

    * ``name``          – interface name (str)
    * ``fcs_errors``    – FCS / CRC errors (int)
    * ``align_errors``  – alignment errors (int)
    * ``symbol_errors`` – symbol errors (int)
    * ``rx_pause``      – received pause frames (int)
    * ``in_errors``     – total input errors (int)
    * ``out_errors``    – total output errors (int)
    * ``has_errors``    – ``True`` when any counter > 0
    """
    result: list[dict] = []
    ifaces = data.get("interfaceErrorCounters", {})
    if not isinstance(ifaces, dict):
        return result

    for name, counters in ifaces.items():
        fcs = int(counters.get("fcsErrors", 0) or 0)
        align = int(counters.get("alignmentErrors", 0) or 0)
        symbol = int(counters.get("symbolErrors", 0) or 0)
        rx_pause = int(counters.get("rxPause", 0) or 0)
        in_err = int(counters.get("inErrors", 0) or 0)
        out_err = int(counters.get("outErrors", 0) or 0)

        result.append(
            {
                "name": name,
                "fcs_errors": fcs,
                "align_errors": align,
                "symbol_errors": symbol,
                "rx_pause": rx_pause,
                "in_errors": in_err,
                "out_errors": out_err,
                "has_errors": any([fcs, align, symbol, in_err, out_err]),
            }
        )

    return result


# ---------------------------------------------------------------------------
# Transceiver DOM  (show interfaces transceiver JSON)
# ---------------------------------------------------------------------------


def parse_transceivers_eos(data: dict) -> list[dict]:
    """Parse ``show interfaces transceiver`` eAPI JSON response.

    Returns a list of per-interface transceiver dicts:

    * ``interface``       – interface name (str)
    * ``media_type``      – SFP/QSFP media type string
    * ``tx_power_dbm``    – transmit optical power in dBm (float) or ``None``
    * ``rx_power_dbm``    – receive optical power in dBm (float) or ``None``
    * ``tx_bias_ma``      – laser bias current in mA (float) or ``None``
    * ``temperature_c``   – module temperature in °C (float) or ``None``
    * ``supply_voltage``  – module supply voltage (float) or ``None``
    * ``alert``           – ``True`` when any DOM value is outside vendor limits
    """
    result: list[dict] = []
    ifaces = data.get("interfaces", {})
    if not isinstance(ifaces, dict):
        return result

    for name, idata in ifaces.items():
        details = idata.get("details", {})

        # tx/rx power and bias current
        tx_dbm: float | None = None
        rx_dbm: float | None = None
        bias_ma: float | None = None
        temp_c: float | None = None
        supply_v: float | None = None
        alert = False

        lanes = details.get("laneValues", {})
        if lanes:
            # Multi-lane (QSFP) – average across lanes
            tx_vals = [v.get("txPower") for v in lanes.values() if v.get("txPower") is not None]
            rx_vals = [v.get("rxPower") for v in lanes.values() if v.get("rxPower") is not None]
            bias_vals = [v.get("txBias") for v in lanes.values() if v.get("txBias") is not None]
            tx_dbm = round(sum(tx_vals) / len(tx_vals), 2) if tx_vals else None
            rx_dbm = round(sum(rx_vals) / len(rx_vals), 2) if rx_vals else None
            bias_ma = round(sum(bias_vals) / len(bias_vals), 2) if bias_vals else None
        else:
            tx_dbm = details.get("txPower")
            rx_dbm = details.get("rxPower")
            bias_ma = details.get("txBias")

        temp_c = details.get("temperature")
        supply_v = details.get("voltage")

        # Check DOM alert flags provided by EOS
        dom_alerts = idata.get("domAlerts", {})
        if dom_alerts:
            alert = any(dom_alerts.values())

        result.append(
            {
                "interface": name,
                "media_type": idata.get("mediaType", ""),
                "tx_power_dbm": tx_dbm,
                "rx_power_dbm": rx_dbm,
                "tx_bias_ma": bias_ma,
                "temperature_c": temp_c,
                "supply_voltage": supply_v,
                "alert": alert,
            }
        )

    return result


# ---------------------------------------------------------------------------
# BGP summary  (show bgp summary JSON)
# ---------------------------------------------------------------------------


def parse_bgp_summary_eos(data: dict) -> list[dict]:
    """Parse ``show bgp summary`` eAPI JSON response (IPv4 unicast).

    Returns a list of BGP peer dicts:

    * ``neighbor``       – peer IP address (str)
    * ``peer_as``        – remote AS number (int) or ``None``
    * ``state``          – session state (``'Established'`` / ``'Active'`` / …)
    * ``up_down``        – up/down time string
    * ``prefixes_rcvd``  – received prefix count (int)
    * ``is_established`` – ``True`` when state is ``'Established'``
    """
    peers: list[dict] = []
    # vrfs → default → peers
    vrfs = data.get("vrfs", {})
    if not isinstance(vrfs, dict):
        return peers

    for _vrf_name, vrf_data in vrfs.items():
        vrf_peers = vrf_data.get("peers", {})
        if not isinstance(vrf_peers, dict):
            continue
        for neighbor, pdata in vrf_peers.items():
            state_str = pdata.get("peerState", "")
            established = state_str == "Established"
            peers.append(
                {
                    "neighbor": neighbor,
                    "peer_as": pdata.get("asn") or pdata.get("peerAs"),
                    "state": state_str,
                    "up_down": pdata.get("upDownTime", ""),
                    "prefixes_rcvd": int(pdata.get("prefixReceived", 0) or 0),
                    "is_established": established,
                }
            )

    return peers


# ---------------------------------------------------------------------------
# BGP EVPN summary  (show bgp evpn summary JSON)
# ---------------------------------------------------------------------------


def parse_bgp_evpn_eos(data: dict) -> list[dict]:
    """Parse ``show bgp evpn summary`` eAPI JSON response.

    Returns the same per-peer structure as :func:`parse_bgp_summary_eos`.
    """
    return parse_bgp_summary_eos(data)


# ---------------------------------------------------------------------------
# OSPF neighbours  (show ip ospf neighbor JSON)
# ---------------------------------------------------------------------------


def parse_ospf_neighbors_eos(data: dict) -> list[dict]:
    """Parse ``show ip ospf neighbor`` eAPI JSON response.

    Returns a list of OSPF neighbour dicts:

    * ``neighbor_id``  – neighbour router ID (str)
    * ``interface``    – local interface name (str)
    * ``address``      – neighbour IP address (str)
    * ``state``        – OSPF adjacency state (str)
    * ``priority``     – DR priority (int)
    * ``dead_time``    – dead-timer countdown string
    * ``is_full``      – ``True`` when state starts with ``'Full'``
    """
    neighbors: list[dict] = []
    # instList → (instance) → neighbors → (neighbor_id) → adjacencies
    inst_list = data.get("instList", {})
    if not isinstance(inst_list, dict):
        return neighbors

    for _inst_id, inst_data in inst_list.items():
        for nbr_id, nbr_data in inst_data.get("neighbors", {}).items():
            for adj in nbr_data.get("adjacencies", []):
                state = adj.get("adjState", "")
                neighbors.append(
                    {
                        "neighbor_id": nbr_id,
                        "interface": adj.get("interfaceName", ""),
                        "address": adj.get("routerAddress", ""),
                        "state": state,
                        "priority": int(adj.get("priority", 0)),
                        "dead_time": adj.get("deadTime", ""),
                        "is_full": state.lower().startswith("full"),
                    }
                )

    return neighbors


# ---------------------------------------------------------------------------
# MLAG  (show mlag JSON)
# ---------------------------------------------------------------------------


def parse_mlag_eos(data: dict) -> dict:
    """Parse ``show mlag`` eAPI JSON response.

    Returns a dict with:

    * ``state``               – MLAG state (``'active'`` / ``'inactive'`` / …)
    * ``peer_state``          – MLAG peer state string
    * ``peer_link``           – peer-link interface name
    * ``peer_link_status``    – peer-link line-protocol status
    * ``local_interface``     – MLAG local interface (VLAN SVI)
    * ``local_ip``            – MLAG local IP address
    * ``peer_ip``             – MLAG peer IP address
    * ``config_sanity``       – config-sanity status string (``'consistent'`` / …)
    * ``is_active``           – ``True`` when state is ``'active'``
    * ``is_peer_active``      – ``True`` when peer_state is ``'active'``
    * ``peer_link_ok``        – ``True`` when peer-link is ``'up'``
    """
    if not isinstance(data, dict):
        return _empty_mlag()

    state = data.get("state", "")
    peer_state = data.get("peerState", "")
    peer_link = data.get("peerLink", "")
    peer_link_status = data.get("peerLinkStatus", "")
    local_intf = data.get("localInterface", "")
    local_ip = (
        data.get("localIntfStatus", {}).get("localIpAddr", "")
        if isinstance(data.get("localIntfStatus"), dict)
        else ""
    )
    peer_ip = data.get("peerAddress", "")
    config_sanity = data.get("configSanity", "")

    return {
        "state": state,
        "peer_state": peer_state,
        "peer_link": peer_link,
        "peer_link_status": peer_link_status,
        "local_interface": local_intf,
        "local_ip": local_ip,
        "peer_ip": peer_ip,
        "config_sanity": config_sanity,
        "is_active": state.lower() == "active",
        "is_peer_active": peer_state.lower() == "active",
        "peer_link_ok": peer_link_status.lower() == "up",
    }


def _empty_mlag() -> dict:
    """Return a zeroed MLAG result dict for use when MLAG data is unavailable."""
    return {
        "state": "",
        "peer_state": "",
        "peer_link": "",
        "peer_link_status": "",
        "local_interface": "",
        "local_ip": "",
        "peer_ip": "",
        "config_sanity": "",
        "is_active": False,
        "is_peer_active": False,
        "peer_link_ok": False,
    }


# ---------------------------------------------------------------------------
# MLAG config-sanity  (show mlag config-sanity JSON)
# ---------------------------------------------------------------------------


def parse_mlag_config_sanity_eos(data: dict) -> dict:
    """Parse ``show mlag config-sanity`` eAPI JSON response.

    Returns a dict with:

    * ``consistent``             – ``True`` when no inconsistencies are found
    * ``global_inconsistencies`` – list of global inconsistency description strings
    * ``interface_inconsistencies`` – list of per-interface inconsistency dicts
      (each with ``interface``, ``description``, ``local_value``, ``peer_value``)
    """
    if not isinstance(data, dict):
        return {"consistent": True, "global_inconsistencies": [], "interface_inconsistencies": []}

    global_incons: list[str] = []
    for key, val in data.get("globalConfiguration", {}).items():
        if isinstance(val, dict) and not val.get("consistent", True):
            global_incons.append(
                f"{key}: local={val.get('localValue', '')}, peer={val.get('peerValue', '')}"
            )

    iface_incons: list[dict] = []
    for intf_name, intf_data in data.get("interfaceConfiguration", {}).items():
        for check_key, check_val in intf_data.items():
            if isinstance(check_val, dict) and not check_val.get("consistent", True):
                iface_incons.append(
                    {
                        "interface": intf_name,
                        "description": check_key,
                        "local_value": check_val.get("localValue", ""),
                        "peer_value": check_val.get("peerValue", ""),
                    }
                )

    return {
        "consistent": len(global_incons) == 0 and len(iface_incons) == 0,
        "global_inconsistencies": global_incons,
        "interface_inconsistencies": iface_incons,
    }


# ---------------------------------------------------------------------------
# Environment  (show environment all JSON)
# ---------------------------------------------------------------------------


def parse_environment_eos(data: dict) -> dict:
    """Parse ``show environment all`` eAPI JSON response.

    Returns a dict with:

    * ``power_supplies``  – list of PSU dicts (name, status, ok)
    * ``fans``            – list of fan dicts (name, speed, status, ok)
    * ``temperatures``    – list of temperature sensor dicts
      (name, celsius, alert_raised, ok)
    * ``overall_ok``      – ``True`` when no component has a fault
    """
    power_supplies: list[dict] = []
    fans: list[dict] = []
    temperatures: list[dict] = []

    if not isinstance(data, dict):
        return {
            "power_supplies": power_supplies,
            "fans": fans,
            "temperatures": temperatures,
            "overall_ok": True,
        }

    # ---- Power supplies ----
    psu_slots = data.get("powerSupplySlots", [])
    if not isinstance(psu_slots, list):
        psu_slots = []
    for slot in psu_slots:
        name = slot.get("label", "")
        status = slot.get("state", "")
        ok = status.lower() in ("ok", "powerok", "present", "good")
        power_supplies.append({"name": name, "status": status, "ok": ok})

    # ---- Fans ----
    fan_trays = data.get("fanTraySlots", [])
    if not isinstance(fan_trays, list):
        fan_trays = []
    for tray in fan_trays:
        tray_name = tray.get("label", "")
        for fan in tray.get("fans", []):
            fan_name = f"{tray_name}/{fan.get('label', '')}"
            speed = fan.get("speed", 0)
            status = fan.get("status", "")
            ok = status.lower() in ("ok", "good", "present")
            fans.append({"name": fan_name, "speed": speed, "status": status, "ok": ok})

    # ---- Temperature sensors ----
    for sensor_name, sensor_data in data.get("shutdownOnOverheat", {}).items():
        pass  # informational only

    # EOS exposes temperature under "systemStatus" → "temperatureRecordOk" and
    # individual sensors under "shutdownTemps" / "tempSensors"
    for sensor in data.get("tempSensors", []):
        name = sensor.get("name", "")
        celsius = sensor.get("currentTemperature")
        alert = bool(sensor.get("alertRaised", False))
        ok = not alert
        temperatures.append(
            {
                "name": name,
                "celsius": celsius,
                "alert_raised": alert,
                "ok": ok,
            }
        )

    # Alternative key used in older EOS releases
    for sensor in data.get("shutdownTemps", []):
        name = sensor.get("name", "")
        celsius = sensor.get("currentTemperature")
        alert = bool(sensor.get("alertRaised", False))
        temperatures.append(
            {
                "name": name,
                "celsius": celsius,
                "alert_raised": alert,
                "ok": not alert,
            }
        )

    overall_ok = (
        all(p["ok"] for p in power_supplies)
        and all(f["ok"] for f in fans)
        and all(t["ok"] for t in temperatures)
    )

    return {
        "power_supplies": power_supplies,
        "fans": fans,
        "temperatures": temperatures,
        "overall_ok": overall_ok,
    }


# ---------------------------------------------------------------------------
# CLI text fallback parsers
# ---------------------------------------------------------------------------


def parse_bgp_summary_eos_text(output: str) -> list[dict]:
    """Parse ``show bgp summary`` plain-text output from Arista EOS.

    Handles output similar to::

        BGP summary information for VRF default
        Router identifier 10.0.0.1, local AS number 65001
        Neighbor Status Codes: m - Under maintenance
          Description              Neighbor V AS           MsgRcvd   MsgSent  InQ OutQ  Up/Down State   PfxRcd PfxAcc
          10.0.0.2                 4 65002         1000      1001    0    0 5d03h Estab   50     50
          10.0.0.3                 4 65003           50        51    0    0 00:05:23 Active

    Returns same structure as :func:`parse_bgp_summary_eos`.
    """
    peers: list[dict] = []
    # Look for lines with IP address + AS + state
    peer_re = re.compile(
        r"^\s*([\d.]+)\s+"  # neighbor IP
        r"\d+\s+"  # BGP version
        r"(\d+)\s+"  # peer AS
        r"\d+\s+\d+\s+\d+\s+\d+\s+"  # MsgRcvd MsgSent InQ OutQ
        r"(\S+)\s+"  # Up/Down
        r"(\S+)"  # State
        r"(?:\s+(\d+))?",  # optional PfxRcd
    )
    for line in output.splitlines():
        m = peer_re.match(line)
        if m:
            state = m.group(4)
            # EOS abbreviates "Established" as "Estab"
            if state.lower().startswith("estab"):
                state = "Established"
            pfx = int(m.group(5)) if m.group(5) else 0
            peers.append(
                {
                    "neighbor": m.group(1),
                    "peer_as": int(m.group(2)),
                    "state": state,
                    "up_down": m.group(3),
                    "prefixes_rcvd": pfx,
                    "is_established": state == "Established",
                }
            )
    return peers


def parse_ospf_neighbors_eos_text(output: str) -> list[dict]:
    """Parse ``show ip ospf neighbor`` plain-text output from Arista EOS.

    Handles output similar to::

        Neighbor ID     Pri   State           Dead Time   Address         Interface
        10.0.0.2          1   Full/DR         00:00:38    10.1.0.2        Ethernet1
        10.0.0.3          1   Full/BDR        00:00:36    10.1.0.3        Ethernet2
        10.0.0.4          0   ExStart/-       00:00:39    10.1.0.4        Ethernet3

    Returns same structure as :func:`parse_ospf_neighbors_eos`.
    """
    neighbors: list[dict] = []
    # Skip header line(s)
    header_re = re.compile(r"Neighbor\s+ID", re.IGNORECASE)
    row_re = re.compile(
        r"^\s*([\d.]+)\s+"  # Neighbor ID
        r"(\d+)\s+"  # Priority
        r"(\S+)\s+"  # State (e.g. Full/DR)
        r"(\S+)\s+"  # Dead Time
        r"([\d.]+)\s+"  # Address
        r"(\S+)",  # Interface
    )
    for line in output.splitlines():
        if header_re.search(line):
            continue
        m = row_re.match(line)
        if m:
            full_state = m.group(3)
            state = full_state.split("/")[0]
            neighbors.append(
                {
                    "neighbor_id": m.group(1),
                    "interface": m.group(6),
                    "address": m.group(5),
                    "state": state,
                    "priority": int(m.group(2)),
                    "dead_time": m.group(4),
                    "is_full": state.lower().startswith("full"),
                }
            )
    return neighbors


def parse_mlag_eos_text(output: str) -> dict:
    """Parse ``show mlag`` plain-text output from Arista EOS.

    Handles output similar to::

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
        system-id                          :  02:1c:73:00:00:99
        dual-primary detection             :            Disabled
        dual-primary interface errdisabled :               False

        MLAG Ports:
        Disabled                           :                   0
        Configured                         :                   0
        Inactive                           :                   0
        Active-partial                     :                   0
        Active-full                        :                   2

    Returns same structure as :func:`parse_mlag_eos`.
    """
    result = _empty_mlag()
    kv_re = re.compile(r"^(.+?)\s*:\s+(.+)$")

    for line in output.splitlines():
        m = kv_re.match(line.rstrip())
        if not m:
            continue
        key = m.group(1).strip().lower()
        val = m.group(2).strip()

        if "state" == key and "negotiation" not in line.lower():
            result["state"] = val
            result["is_active"] = val.lower() == "active"
        elif key == "peer-link status":
            result["peer_link_status"] = val
            result["peer_link_ok"] = val.lower() == "up"
        elif key == "peer-link":
            result["peer_link"] = val
        elif key == "local-interface":
            result["local_interface"] = val
        elif key == "peer-address":
            result["peer_ip"] = val
        elif key == "peer-config":
            result["config_sanity"] = val

    return result
