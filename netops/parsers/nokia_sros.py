"""Parsers for Nokia SR OS CLI output.

Covers classic CLI (7750, 7450, 7210, 7705, 7250 IXR, 7730 SXR) and
handles common formatting variations across TiMOS releases.
"""

from __future__ import annotations

import re

__all__ = [
    "parse_interfaces",
    "parse_bgp_summary",
    "parse_ospf_neighbors",
    "parse_system_info",
    "parse_chassis",
    "parse_cards",
    "parse_mda",
    "parse_bof",
    "parse_version",
    "parse_service_summary",
    "parse_lag",
    "parse_router_interface",
]


# ---------------------------------------------------------------------------
# Interfaces — show port
# ---------------------------------------------------------------------------


def parse_interfaces(output: str) -> list[dict]:
    """Parse ``show port`` output into a list of interface dicts.

    Returns
    -------
    list
        List of interface dicts.

    Each dict contains:

    * ``name``     – port identifier (e.g. ``'1/1/1'``, ``'1/1/c3/1'``)
    * ``status``   – administrative state: ``'Up'`` or ``'Down'``
    * ``protocol`` – operational state: ``'Up'`` or ``'Down'``
    * ``up``       – ``True`` when both admin and oper state are ``'Up'``

    Field names match the Cisco ``parse_cisco_interfaces`` convention so
    callers can treat output from both vendors uniformly.
    """
    interfaces = []
    for line in output.splitlines():
        # Columns: Port  Admin-State  Link  Port-State  Cfg-MTU  Oper-MTU ...
        match = re.match(
            r"^(\S+)\s+(Up|Down)\s+(Yes|No)\s+(Up|Down)\s+",
            line,
        )
        if match:
            admin = match.group(2)
            link = match.group(3) == "Yes"
            oper = match.group(4)
            interfaces.append(
                {
                    "name": match.group(1),
                    "status": admin,
                    "link": link,
                    "protocol": oper,
                    "up": admin == "Up" and oper == "Up",
                }
            )
    return interfaces


# ---------------------------------------------------------------------------
# BGP — show router bgp summary
# ---------------------------------------------------------------------------


def parse_bgp_summary(output: str) -> list[dict]:
    """Parse ``show router bgp summary`` output into a BGP peer list.

    Returns
    -------
    list
        List of BGP peer dicts.

    Each dict contains:

    * ``neighbor``    – peer IPv4 address
    * ``description`` – peer description string, or ``None``
    * ``peer_as``     – remote AS number (``int``)
    * ``received``    – prefixes received / Adj-RIB-In count (``int``)
    * ``sent``        – prefixes advertised (``int``)
    * ``active``      – active (best-path) prefixes (``int``)
    * ``up_down``     – session uptime or time-since-reset (e.g. ``'1d02h'``)
    * ``state``       – session state (e.g. ``'Established'``, ``'Active'``)
    """
    peers: list[dict] = []
    current_ip: str | None = None
    current_desc: str | None = None
    in_data = False

    for line in output.splitlines():
        # The column-header line containing "Remote AS" marks the start of data.
        if "Remote AS" in line:
            in_data = True
            continue

        if not in_data:
            continue

        stripped = line.strip()

        # Skip blank lines, decorative separators, and the summary footer.
        if not stripped or stripped.startswith("=") or stripped.startswith("No."):
            continue
        if re.match(r"^-{10,}", stripped):
            continue

        # Neighbour IP line: exactly one leading space followed by an IPv4 address.
        ip_match = re.match(r"^ (\d{1,3}(?:\.\d{1,3}){3})\s*$", line)
        if ip_match:
            current_ip = ip_match.group(1)
            current_desc = None
            continue

        # Peer metrics line: deeply indented (≥20 spaces) + remote-AS + counters.
        data_match = re.match(
            r"^\s{20,}(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)",
            line,
        )
        if data_match and current_ip is not None:
            peers.append(
                {
                    "neighbor": current_ip,
                    "description": current_desc,
                    "peer_as": int(data_match.group(1)),
                    "received": int(data_match.group(2)),
                    "sent": int(data_match.group(3)),
                    "active": int(data_match.group(4)),
                    "up_down": data_match.group(5),
                    "state": data_match.group(6),
                }
            )
            current_ip = None
            current_desc = None
            continue

        # Optional description line: single leading space, non-empty, appears
        # between the neighbour IP line and the metrics line.
        if current_ip is not None and re.match(r"^ \S", line):
            current_desc = stripped

    return peers


# ---------------------------------------------------------------------------
# OSPF — show router ospf neighbor
# ---------------------------------------------------------------------------


def parse_ospf_neighbors(output: str) -> list[dict]:
    """Parse ``show router ospf neighbor`` output into an adjacency list.

    Returns
    -------
    list
        List of OSPF neighbor dicts.

    Each dict contains:

    * ``interface``  – interface or link name (e.g. ``'to-core-1'``)
    * ``router_id``  – neighbour router-ID as an IPv4 string
    * ``state``      – OSPF adjacency state (e.g. ``'Full'``, ``'Init'``)
    * ``priority``   – DR election priority (``int``)
    * ``retx_queue`` – retransmit queue length (``int``)
    """
    neighbors = []
    for line in output.splitlines():
        match = re.match(
            r"^(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+"
            r"(Full|2Way|ExStart|Exchange|Loading|Init|Down|Attempt)\s+"
            r"(\d+)\s+(\d+)",
            line,
        )
        if match:
            neighbors.append(
                {
                    "interface": match.group(1),
                    "router_id": match.group(2),
                    "state": match.group(3),
                    "priority": int(match.group(4)),
                    "retx_queue": int(match.group(5)),
                }
            )
    return neighbors


# ---------------------------------------------------------------------------
# System Information — show system information
# ---------------------------------------------------------------------------

# Helpers for key: value parsing common across Nokia commands
_KV_RE = re.compile(r"^\s*([A-Za-z][\w /()-]*?)\s*:\s*(.+?)\s*$")


def _extract_kv(output: str) -> dict[str, str]:
    """Extract all ``Key : Value`` pairs from Nokia-style output."""
    kv: dict[str, str] = {}
    for line in output.splitlines():
        m = _KV_RE.match(line)
        if m:
            kv[m.group(1).strip()] = m.group(2).strip()
    return kv


def parse_system_info(output: str) -> dict:
    """Parse ``show system information`` output.

    Returns
    -------
    dict
        Dict with normalised keys:

        * ``system_name``   – configured system name
        * ``hostname``      – alias for system_name (for compatibility)
        * ``contact``       – admin contact string
        * ``location``      – system location
        * ``description``   – system description
        * ``object_id``     – SNMP sysObjectID
        * ``uptime``        – system uptime string
        * ``last_booted``   – last boot time
        * ``current_time``  – current time on the node
        * ``chassis_type``  – chassis model identifier
        * ``cpu_type``      – processor info
        * ``oper_version``  – running TiMOS version (if shown)
    """
    kv = _extract_kv(output)
    result: dict = {}

    _MAP = {
        "System Name": "system_name",
        "System Contact": "contact",
        "System Location": "location",
        "System Description": "description",
        "Object Id": "object_id",
        "System Up Time": "uptime",
        "Last Booted": "last_booted",
        "Current Time": "current_time",
        "Chassis Type": "chassis_type",
        "CPU Type": "cpu_type",
        # Some TiMOS versions include version here
        "BOF Source": "bof_source",
        "System Version": "oper_version",
    }

    for nokia_key, norm_key in _MAP.items():
        for kv_key, kv_val in kv.items():
            if kv_key.lower() == nokia_key.lower():
                result[norm_key] = kv_val
                break

    # Alias hostname
    if "system_name" in result:
        result["hostname"] = result["system_name"]

    return result


# ---------------------------------------------------------------------------
# Chassis — show chassis / show chassis detail
# ---------------------------------------------------------------------------


def parse_chassis(output: str) -> dict:
    """Parse ``show chassis`` or ``show chassis detail`` output.

    Returns
    -------
    dict
        Dict with:

        * ``chassis_type``   – e.g. ``'7750 SR-12'``, ``'7210 SAS-Sx 10/100GE'``
        * ``part_number``    – Nokia part number (e.g. ``'3HE04820AAAB01'``)
        * ``serial_number``  – chassis serial
        * ``clei_code``      – CLEI code
        * ``mac_address``    – base MAC address
        * ``firmware``       – firmware / FPGA version
        * ``hardware_data``  – hardware coding
        * ``oper_state``     – operational state (Up/Down)
        * ``admin_state``    – administrative state
        * ``temperature``    – temperature reading (if present)
        * ``num_slots``      – number of card slots
        * ``num_ports``      – total number of ports
        * ``num_power``      – number of power supply modules
        * ``num_fan``        – number of fan trays
    """
    kv = _extract_kv(output)
    result: dict = {}

    _MAP = {
        "Chassis Type": "chassis_type",
        "Type": "chassis_type",  # some models
        "Part Number": "part_number",
        "Part number": "part_number",
        "Serial Number": "serial_number",
        "Serial number": "serial_number",
        "CLEI Code": "clei_code",
        "Base MAC address": "mac_address",
        "Base MAC Address": "mac_address",
        "Hardware Data": "hardware_data",
        "Firmware Version": "firmware",
        "Firmware version": "firmware",
        "Admin State": "admin_state",
        "Oper State": "oper_state",
        "Temperature": "temperature",
        "Number of slots": "num_slots",
        "Number of Slots": "num_slots",
        "Number of ports": "num_ports",
        "Number of Ports": "num_ports",
        "Number of Power Supply Modules": "num_power",
        "Number of Fan Trays": "num_fan",
    }

    for nokia_key, norm_key in _MAP.items():
        for kv_key, kv_val in kv.items():
            if kv_key.lower() == nokia_key.lower():
                # Prefer existing value only if we have one already
                if norm_key not in result:
                    result[norm_key] = kv_val
                break

    return result


# ---------------------------------------------------------------------------
# Cards — show card
# ---------------------------------------------------------------------------


def parse_cards(output: str) -> list[dict]:
    """Parse ``show card`` output into a list of card dicts.

    Each dict contains:

    * ``slot``        – card slot number (str)
    * ``card_type``   – provisioned or equipped card type string
    * ``admin_state`` – ``'up'`` or ``'down'``
    * ``oper_state``  – ``'up'``, ``'down'``, ``'provisioned'``, etc.
    * ``serial``      – serial number (from ``show card detail``, may be None)
    * ``part_number`` – part number (from detail, may be None)
    * ``equipped_type`` – equipped type (may differ from provisioned)
    """
    cards: list[dict] = []

    # Classic table format:
    #  Slot  Provisioned Type                         Admin Oper
    # ---------------------------------------------------------------
    #    1   iom3-xp                                   up    up
    #    A   sfm5-12                                    up    up

    # Detect table header
    in_table = False
    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r"^-{10,}", stripped):
            in_table = True
            continue
        if not in_table:
            if "Provisioned" in line and "Oper" in line:
                in_table = True  # next line after dashes
            continue
        if not stripped:
            continue
        # End of table
        if stripped.startswith("="):
            break

        # Parse: slot  type  admin  oper
        # Slot can be numeric (1-20) or letter (A, B for switch fabric)
        m = re.match(
            r"^\s*(\S+)\s+(\S+(?:\s+\S+)*?)\s+(up|down)\s+(up|down|provisioned|empty|unprovisioned|booting|failed)\s*$",
            stripped,
            re.IGNORECASE,
        )
        if m:
            cards.append(
                {
                    "slot": m.group(1),
                    "card_type": m.group(2).strip(),
                    "admin_state": m.group(3).lower(),
                    "oper_state": m.group(4).lower(),
                    "serial": None,
                    "part_number": None,
                    "equipped_type": None,
                }
            )
            continue

    # Also handle show card detail format — key:value blocks per slot
    current_slot: str | None = None
    for line in output.splitlines():
        slot_hdr = re.match(r"^Card\s+(\S+)\s*$", line.strip())
        if slot_hdr:
            current_slot = slot_hdr.group(1)
            continue
        if current_slot:
            m = _KV_RE.match(line)
            if m:
                key = m.group(1).strip().lower()
                val = m.group(2).strip()
                # Find matching card entry
                for c in cards:
                    if c["slot"] == current_slot:
                        if "serial" in key and not c["serial"]:
                            c["serial"] = val
                        elif "part number" in key and not c["part_number"]:
                            c["part_number"] = val
                        elif "equipped type" in key and not c["equipped_type"]:
                            c["equipped_type"] = val
                        break

    return cards


# ---------------------------------------------------------------------------
# MDA — show mda
# ---------------------------------------------------------------------------


def parse_mda(output: str) -> list[dict]:
    """Parse ``show mda`` output into a list of MDA dicts.

    Each dict contains:

    * ``slot``        – slot/mda identifier (e.g. ``'1/1'``)
    * ``mda_type``    – provisioned MDA type
    * ``admin_state`` – ``'up'`` or ``'down'``
    * ``oper_state``  – operational state
    * ``serial``      – serial number (None if not in output)
    * ``equipped_type`` – equipped type
    """
    mdas: list[dict] = []
    in_table = False

    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r"^-{10,}", stripped):
            in_table = True
            continue
        if not in_table:
            if "Provisioned" in line and "Oper" in line:
                in_table = True
            continue
        if not stripped or stripped.startswith("="):
            if stripped.startswith("="):
                break
            continue

        # slot/mda  type  admin  oper
        m = re.match(
            r"^\s*(\d+/\d+)\s+(\S+(?:\s+\S+)*?)\s+(up|down)\s+(up|down|provisioned|empty|unprovisioned|failed)\s*$",
            stripped,
            re.IGNORECASE,
        )
        if m:
            mdas.append(
                {
                    "slot": m.group(1),
                    "mda_type": m.group(2).strip(),
                    "admin_state": m.group(3).lower(),
                    "oper_state": m.group(4).lower(),
                    "serial": None,
                    "equipped_type": None,
                }
            )

    return mdas


# ---------------------------------------------------------------------------
# BOF — show bof
# ---------------------------------------------------------------------------


def parse_bof(output: str) -> dict:
    """Parse ``show bof`` (Boot Options File) output.

    Returns
    -------
    dict
        Dict with:

        * ``primary_image``     – primary boot image path
        * ``secondary_image``   – secondary boot image path
        * ``tertiary_image``    – tertiary boot image path
        * ``primary_config``    – primary config file path
        * ``secondary_config``  – secondary config file path
        * ``address``           – management IP address
        * ``prefix_length``     – management prefix length
        * ``static_route``      – static route entries (list of str)
        * ``dns_domain``        – DNS domain name
        * ``dns_server``        – DNS server IP
        * ``autonegotiate``     – auto-negotiate setting
        * ``duplex``            – duplex setting
        * ``speed``             – speed setting
        * ``wait_time``         – boot wait time
        * ``persist``           – persist on/off
        * ``console_speed``     – console baud rate
    """
    # BOF output uses two formats:
    # 1. "key : value" (show bof on some versions)
    # 2. "    key    value" (whitespace-separated, indented, classic BOF)
    # Parse whitespace-separated BOF lines first (they take priority)
    _BOF_WS_RE = re.compile(r"^\s{4,}([\w-]+)\s+(.+?)\s*$")
    bof_kv: dict[str, str] = {}
    for line in output.splitlines():
        m = _BOF_WS_RE.match(line)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip()
            if key not in bof_kv and key != "static-route":
                bof_kv[key] = val

    # Merge with key:value style (don't override BOF whitespace keys)
    kv = _extract_kv(output)
    for k, v in bof_kv.items():
        kv[k] = v

    result: dict = {}

    _MAP = {
        "primary-image": "primary_image",
        "Primary Image": "primary_image",
        "secondary-image": "secondary_image",
        "Secondary Image": "secondary_image",
        "tertiary-image": "tertiary_image",
        "Tertiary Image": "tertiary_image",
        "primary-config": "primary_config",
        "Primary Config": "primary_config",
        "secondary-config": "secondary_config",
        "Secondary Config": "secondary_config",
        "address": "address",
        "Address": "address",
        "prefix-length": "prefix_length",
        "dns-domain": "dns_domain",
        "DNS Domain": "dns_domain",
        "dns-server": "dns_server",
        "autonegotiate": "autonegotiate",
        "duplex": "duplex",
        "speed": "speed",
        "wait-time": "wait_time",
        "persist": "persist",
        "console-speed": "console_speed",
    }

    for nokia_key, norm_key in _MAP.items():
        for kv_key, kv_val in kv.items():
            if kv_key.lower() == nokia_key.lower():
                if norm_key not in result:
                    result[norm_key] = kv_val
                break

    # Static routes can appear multiple times
    routes: list[str] = []
    for line in output.splitlines():
        m = re.search(r"static-route\s+(.+)", line)
        if m:
            routes.append(m.group(1).strip())
    if routes:
        result["static_route"] = routes

    return result


# ---------------------------------------------------------------------------
# Version — show version
# ---------------------------------------------------------------------------


def parse_version(output: str) -> dict:
    """Parse ``show version`` output.

    Returns
    -------
    dict
        Dict with:

        * ``timos_version``   – full TiMOS version string
        * ``version``         – short version number (e.g. ``'23.10.R1'``)
        * ``build_date``      – build date/time if present
        * ``sros_version``    – SR OS version if shown separately
        * ``cpm_type``        – CPM module type
        * ``chassis_type``    – chassis/platform type
    """
    result: dict = {}

    for line in output.splitlines():
        stripped = line.strip()

        # TiMOS-B-23.10.R1 both/x86_64 Nokia 7750 SR Copyright ...
        timos = re.match(r"^(TiMOS-\S+)", stripped)
        if timos:
            result["timos_version"] = timos.group(1)
            # Extract short version: TiMOS-B-23.10.R1 → 23.10.R1
            ver = re.search(r"TiMOS-\S+-([0-9]+\.[0-9]+\.\S+)", timos.group(1))
            if ver:
                result["version"] = ver.group(1)
            # Extract chassis from same line: "Nokia 7750 SR"
            chassis = re.search(
                r"(?:Nokia|Alcatel[- ]Lucent)\s+([\w\d][\w\d ./-]+?)(?:\s+Copyright|\s*$)", stripped
            )
            if chassis:
                result["chassis_type"] = chassis.group(1).strip()

        # Alternate version line from some releases
        ver2 = re.search(r"SROS\s+Version\s*:\s*(\S+)", stripped, re.IGNORECASE)
        if ver2:
            result["sros_version"] = ver2.group(1)

        # CPM type
        cpm = re.search(r"CPM\s+Type\s*:\s*(.+)", stripped, re.IGNORECASE)
        if cpm:
            result["cpm_type"] = cpm.group(1).strip()

        # Build info
        bld = re.search(r"Built on\s+(.+)", stripped, re.IGNORECASE)
        if bld:
            result["build_date"] = bld.group(1).strip()

    return result


# ---------------------------------------------------------------------------
# Services — show service service-using
# ---------------------------------------------------------------------------


def parse_service_summary(output: str) -> list[dict]:
    """Parse ``show service service-using`` output.

    Returns
    -------
    list
        List of dicts with:

        * ``service_id``   – service ID (int)
        * ``service_type`` – type string (e.g. ``'VPLS'``, ``'VPRN'``, ``'Epipe'``)
        * ``admin_state``  – ``'Up'`` or ``'Down'``
        * ``oper_state``   – ``'Up'`` or ``'Down'``
        * ``customer_id``  – customer ID (int)
        * ``name``         – service name
    """
    services: list[dict] = []
    in_table = False

    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r"^-{10,}", stripped):
            in_table = True
            continue
        if not in_table:
            continue
        if not stripped or stripped.startswith("="):
            if stripped.startswith("="):
                break
            continue

        # SvcId  SvcType  Adm  Opr  CustId  Name
        m = re.match(
            r"^\s*(\d+)\s+(\S+)\s+(Up|Down)\s+(Up|Down)\s+(\d+)\s+(.*?)\s*$",
            stripped,
            re.IGNORECASE,
        )
        if m:
            services.append(
                {
                    "service_id": int(m.group(1)),
                    "service_type": m.group(2),
                    "admin_state": m.group(3),
                    "oper_state": m.group(4),
                    "customer_id": int(m.group(5)),
                    "name": m.group(6).strip(),
                }
            )

    return services


# ---------------------------------------------------------------------------
# LAG — show lag
# ---------------------------------------------------------------------------


def parse_lag(output: str) -> list[dict]:
    """Parse ``show lag`` output.

    Returns
    -------
    list
        List of dicts with:

        * ``lag_id``       – LAG identifier (int)
        * ``admin_state``  – ``'up'`` or ``'down'``
        * ``oper_state``   – ``'up'`` or ``'down'``
        * ``port_count``   – number of member ports (int)
        * ``active_ports`` – number of active ports (int)
        * ``description``  – LAG description
        * ``lacp_mode``    – LACP mode (``'active'``, ``'passive'``, or ``None``)
        * ``members``      – list of member port strings
    """
    lags: list[dict] = []
    in_table = False

    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r"^-{10,}", stripped):
            in_table = True
            continue
        if not in_table:
            continue
        if not stripped or stripped.startswith("="):
            if stripped.startswith("="):
                break
            continue

        # Lag-id  Adm  Opr  Port-Count  Active-Ports  Description
        m = re.match(
            r"^\s*(\d+)\s+(up|down)\s+(up|down)\s+(\d+)\s+(\d+)\s*(.*?)\s*$",
            stripped,
            re.IGNORECASE,
        )
        if m:
            lags.append(
                {
                    "lag_id": int(m.group(1)),
                    "admin_state": m.group(2).lower(),
                    "oper_state": m.group(3).lower(),
                    "port_count": int(m.group(4)),
                    "active_ports": int(m.group(5)),
                    "description": m.group(6).strip(),
                    "lacp_mode": None,
                    "members": [],
                }
            )

    # Parse detail output for LACP and member info (show lag detail)
    current_lag: int | None = None
    for line in output.splitlines():
        lag_hdr = re.match(r"^LAG\s+(\d+)", line.strip())
        if lag_hdr:
            current_lag = int(lag_hdr.group(1))
            continue
        if current_lag is not None:
            # LACP mode
            lacp = re.search(r"LACP\s+Mode\s*:\s*(\S+)", line, re.IGNORECASE)
            if lacp:
                for lag in lags:
                    if lag["lag_id"] == current_lag:
                        lag["lacp_mode"] = lacp.group(1).lower()
                        break
            # Member port
            port = re.search(r"Port-id\s*:\s*(\S+)", line)
            if port:
                for lag in lags:
                    if lag["lag_id"] == current_lag:
                        lag["members"].append(port.group(1))
                        break

    return lags


# ---------------------------------------------------------------------------
# Router Interfaces — show router interface
# ---------------------------------------------------------------------------


def parse_router_interface(output: str) -> list[dict]:
    """Parse ``show router interface`` output.

    Returns
    -------
    list
        List of dicts with:

        * ``name``         – interface name
        * ``ip_address``   – IPv4 address (or ``None``)
        * ``admin_state``  – ``'Up'`` or ``'Down'``
        * ``oper_state``   – ``'Up'`` or ``'Down'`` (may include protocol state)
        * ``protocol``     – protocol state (``'Up'`` or ``'Down'``)
        * ``port``         – bound SAP or port (``None`` if system)
    """
    interfaces: list[dict] = []
    in_table = False

    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r"^-{10,}", stripped):
            in_table = True
            continue
        if not in_table:
            if "Adm" in line and "Opr" in line:
                in_table = True
            continue
        if not stripped or stripped.startswith("="):
            if stripped.startswith("="):
                break
            continue

        # Interface  IP Address  Adm  Opr(v4/v6)  Mode  Port/SapId
        # "system"  10.0.0.1/32  Up   Up/--  N/A  system
        m = re.match(
            r"^\s*(\S+)\s+(\d+\.\d+\.\d+\.\d+/\d+|-)?\s*(Up|Down)\s+(Up|Down)(?:/(Up|Down|-+))?\s+(\S+)?\s*(\S+)?\s*$",
            stripped,
            re.IGNORECASE,
        )
        if m:
            oper = m.group(4)
            interfaces.append(
                {
                    "name": m.group(1),
                    "ip_address": m.group(2) if m.group(2) and m.group(2) != "-" else None,
                    "admin_state": m.group(3),
                    "oper_state": oper,
                    "protocol": oper,
                    "port": (m.group(7) or m.group(6))
                    if m.lastindex and m.lastindex >= 6
                    else None,
                }
            )
            continue

        # Simpler format — some TiMOS versions:
        # Interface  IP Address       Adm  Opr
        m2 = re.match(
            r"^\s*(\S+)\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(Up|Down)\s+(Up|Down)\s*$",
            stripped,
            re.IGNORECASE,
        )
        if m2:
            interfaces.append(
                {
                    "name": m2.group(1),
                    "ip_address": m2.group(2),
                    "admin_state": m2.group(3),
                    "oper_state": m2.group(4),
                    "protocol": m2.group(4),
                    "port": None,
                }
            )

    return interfaces
