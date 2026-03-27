"""Parsers for Juniper JunOS CLI output.

Supports both plain-text (``show …``) and XML-like text output produced by
JunOS ``show`` commands.  All parsers operate on strings returned from the
device connection and do **not** require the ``lxml`` or ``ncclient`` libraries.

Parsers are grouped into:

* **Routing Engine** – CPU, memory, uptime (``show chassis routing-engine``)
* **FPC** – slot status and temperatures (``show chassis fpc``)
* **Interfaces** – error counters (``show interfaces extensive``)
* **BGP** – neighbour summary (``show bgp summary``)
* **OSPF** – neighbour table (``show ospf neighbor``)
* **Chassis alarms** – active alarms (``show chassis alarms``)
* **Chassis environment** – power/temperature/fans (``show chassis environment``)
* **Route summary** – routing table statistics (``show route summary``)
"""

from __future__ import annotations

import re

__all__ = [
    "parse_re_status",
    "parse_fpc_status",
    "parse_interface_errors_junos",
    "parse_bgp_summary_junos",
    "parse_ospf_neighbors_junos",
    "parse_chassis_alarms",
    "parse_chassis_environment",
    "parse_route_summary",
]


# ---------------------------------------------------------------------------
# Routing Engine (RE) status
# ---------------------------------------------------------------------------


def parse_re_status(output: str) -> list[dict]:
    """Parse ``show chassis routing-engine`` output.

    Each returned dict represents one Routing Engine slot and contains:

    * ``slot``          – RE slot index (``int``, 0 or 1)
    * ``mastership``    – mastership state (e.g. ``'Master'``, ``'Backup'``, ``'Disabled'``)
    * ``state``         – RE state (e.g. ``'Online'``, ``'Offline'``)
    * ``cpu_util``      – CPU utilisation % (``int``) or ``None``
    * ``memory_util``   – DRAM utilisation % (``int``) or ``None``
    * ``memory_total``  – total DRAM in MB (``int``) or ``None``
    * ``memory_used``   – used DRAM in MB (``int``) or ``None``
    * ``uptime``        – uptime string (e.g. ``'10 days, 3 hours, 22 minutes'``)
                         or ``None``
    * ``temperature``   – temperature in Celsius (``int``) or ``None``

    Returns an empty list when the output cannot be parsed.

    Example input::

        Routing Engine status:
          Slot 0:
            Current state                  Master
            Election priority              Master (default)
            Temperature                 40 degrees C / 104 degrees F
            Total memory                 2048 MB
            Memory utilization            65 percent
            CPU utilization:
              User                          2 percent
              Background                    0 percent
              Kernel                        3 percent
              Interrupt                     0 percent
              Idle                         95 percent
            Model                          RE-S-1800x4
            Start time:                    2024-01-01 00:00:00 UTC
            Uptime:                        10 days, 3 hours, 22 minutes, 15 seconds
    """
    routing_engines: list[dict] = []
    current: dict | None = None
    slot_re = re.compile(r"^\s+Slot\s+(\d+)\s*:", re.IGNORECASE)
    mastership_re = re.compile(r"Current state\s+(\S+.*)", re.IGNORECASE)
    temp_re = re.compile(r"Temperature\s+(\d+)\s+degrees", re.IGNORECASE)
    total_mem_re = re.compile(r"Total memory\s+(\d+)\s+MB", re.IGNORECASE)
    mem_util_re = re.compile(r"Memory utilization\s+(\d+)\s+percent", re.IGNORECASE)
    cpu_idle_re = re.compile(r"Idle\s+(\d+)\s+percent", re.IGNORECASE)
    uptime_re = re.compile(r"Uptime:\s+(.+)", re.IGNORECASE)

    for line in output.splitlines():
        m = slot_re.search(line)
        if m:
            if current is not None:
                routing_engines.append(current)
            current = {
                "slot": int(m.group(1)),
                "mastership": None,
                "state": None,
                "cpu_util": None,
                "memory_util": None,
                "memory_total": None,
                "memory_used": None,
                "uptime": None,
                "temperature": None,
            }
            continue

        if current is None:
            continue

        m = mastership_re.search(line)
        if m:
            val = m.group(1).split("(")[0].strip()
            current["mastership"] = val
            current["state"] = val
            continue

        m = temp_re.search(line)
        if m:
            current["temperature"] = int(m.group(1))
            continue

        m = total_mem_re.search(line)
        if m:
            current["memory_total"] = int(m.group(1))
            continue

        m = mem_util_re.search(line)
        if m:
            current["memory_util"] = int(m.group(1))
            if current["memory_total"] is not None:
                current["memory_used"] = int(current["memory_total"] * current["memory_util"] / 100)
            continue

        m = cpu_idle_re.search(line)
        if m:
            idle = int(m.group(1))
            current["cpu_util"] = max(0, 100 - idle)
            continue

        m = uptime_re.search(line)
        if m:
            current["uptime"] = m.group(1).strip()
            continue

    if current is not None:
        routing_engines.append(current)

    return routing_engines


# ---------------------------------------------------------------------------
# FPC (Flexible PIC Concentrator) status
# ---------------------------------------------------------------------------


def parse_fpc_status(output: str) -> list[dict]:
    """Parse ``show chassis fpc`` output.

    Each returned dict represents one FPC slot:

    * ``slot``          – FPC slot index (``int``)
    * ``state``         – operational state (e.g. ``'Online'``, ``'Offline'``,
                         ``'Empty'``, ``'Present'``)
    * ``cpu_util``      – CPU utilisation % (``int``) or ``None``
    * ``memory_used``   – DRAM used in MB (``int``) or ``None``
    * ``memory_total``  – total DRAM in MB (``int``) or ``None``
    * ``temperature``   – temperature in Celsius (``int``) or ``None``
    * ``ok``            – ``True`` when state is ``'Online'`` or ``'Empty'``

    Returns an empty list when the output cannot be parsed.

    Example input::

                         Temp  CPU Utilization (%)   Memory  Utilization (%)
        Slot State        (C)  Total  Interrupt      DRAM (MB) Heap     Buffer
        0  Online          43     3          0        2048    34         47
        1  Online          42     5          1        2048    36         49
        2  Empty           -      -          -           -     -          -
    """
    fpcs: list[dict] = []

    for line in output.splitlines():
        # Match lines like:  "  0  Online   43   3   0   2048   34   47"
        # or:                "  2  Empty    -    -   -    -      -    -"
        match = re.match(
            r"^\s*(\d+)\s+(Online|Offline|Empty|Present|Spare|Check|Diag|FW\s+\S+)"
            r"\s+(\d+|-)\s+(\d+|-)\s+(\d+|-)\s+(\d+|-)",
            line,
            re.IGNORECASE,
        )
        if match:
            state = match.group(2).strip()
            cpu_raw = match.group(4)
            mem_raw = match.group(6)
            temp_raw = match.group(3)

            fpcs.append(
                {
                    "slot": int(match.group(1)),
                    "state": state,
                    "cpu_util": int(cpu_raw) if cpu_raw != "-" else None,
                    "memory_used": None,
                    "memory_total": int(mem_raw) if mem_raw != "-" else None,
                    "temperature": int(temp_raw) if temp_raw != "-" else None,
                    "ok": state.lower() in ("online", "empty", "spare"),
                }
            )
    return fpcs


# ---------------------------------------------------------------------------
# Interface error counters
# ---------------------------------------------------------------------------


def parse_interface_errors_junos(output: str) -> list[dict]:
    """Parse ``show interfaces extensive`` (or ``show interfaces detail``) output.

    Extracts per-interface error counters.  Each returned dict contains:

    * ``name``           – interface name (e.g. ``'ge-0/0/0'``, ``'xe-0/1/0'``)
    * ``input_errors``   – total input errors (``int``)
    * ``output_errors``  – total output errors (``int``)
    * ``input_drops``    – input drops/discards (``int``)
    * ``output_drops``   – output drops/discards (``int``)
    * ``crc_errors``     – CRC/frame-check errors (``int``)
    * ``has_errors``     – ``True`` when any counter is > 0

    Returns an empty list when the output cannot be parsed.

    Example excerpt::

        Physical interface: ge-0/0/0, Enabled, Physical link is Up
          Input errors:
            Errors: 0, Drops: 0, Framing errors: 0, Runts: 0, Giants: 0, Policed discards: 0,
            L3 incompletes: 0, L2 channel errors: 0, L2 mismatch timeouts: 0, FIFO errors: 0,
            Resource errors: 0
          Output errors:
            Carrier transitions: 1, Errors: 0, Drops: 0, Collisions: 0, Aged packets: 0,
            FIFO errors: 0, HS link CRC errors: 0, MTU errors: 0, Resource errors: 0
    """
    interfaces: list[dict] = []
    current: dict | None = None

    # Physical interface header: "Physical interface: ge-0/0/0, ..."
    iface_re = re.compile(r"^Physical interface:\s+(\S+),", re.IGNORECASE)
    in_errors_re = re.compile(r"Input errors:", re.IGNORECASE)
    out_errors_re = re.compile(r"Output errors:", re.IGNORECASE)
    # Error counters on summary lines within the error block
    errors_val_re = re.compile(r"Errors:\s*(\d+)", re.IGNORECASE)
    drops_val_re = re.compile(r"Drops:\s*(\d+)", re.IGNORECASE)
    crc_re = re.compile(r"(?:CRC[- ]errors?|HS link CRC errors?):\s*(\d+)", re.IGNORECASE)

    _in_section = ""  # "input" | "output" | ""

    for line in output.splitlines():
        m = iface_re.match(line)
        if m:
            if current is not None:
                _finalise_iface(current)
                interfaces.append(current)
            current = {
                "name": m.group(1),
                "input_errors": 0,
                "output_errors": 0,
                "input_drops": 0,
                "output_drops": 0,
                "crc_errors": 0,
                "has_errors": False,
            }
            _in_section = ""
            continue

        if current is None:
            continue

        if in_errors_re.search(line):
            _in_section = "input"
            continue
        if out_errors_re.search(line):
            _in_section = "output"
            continue

        if _in_section == "input":
            m = errors_val_re.search(line)
            if m:
                current["input_errors"] += int(m.group(1))
            m = drops_val_re.search(line)
            if m:
                current["input_drops"] += int(m.group(1))
            m = crc_re.search(line)
            if m:
                current["crc_errors"] += int(m.group(1))
        elif _in_section == "output":
            m = errors_val_re.search(line)
            if m:
                current["output_errors"] += int(m.group(1))
            m = drops_val_re.search(line)
            if m:
                current["output_drops"] += int(m.group(1))

    if current is not None:
        _finalise_iface(current)
        interfaces.append(current)

    return interfaces


def _finalise_iface(iface: dict) -> None:
    """Set ``has_errors`` based on non-zero counters."""
    iface["has_errors"] = any(
        iface[k] > 0
        for k in ("input_errors", "output_errors", "input_drops", "output_drops", "crc_errors")
    )


# ---------------------------------------------------------------------------
# BGP neighbour summary
# ---------------------------------------------------------------------------


def parse_bgp_summary_junos(output: str) -> list[dict]:
    """Parse ``show bgp summary`` output from JunOS.

    Each returned dict contains:

    * ``neighbor``          – peer IPv4/IPv6 address (``str``)
    * ``peer_as``           – remote AS number (``int``)
    * ``state``             – session state (e.g. ``'Established'``, ``'Active'``,
                             ``'Idle'``, ``'Connect'``)
    * ``up_down``           – session uptime or time-since-reset string
    * ``prefixes_received`` – prefixes received (``int``) when Established,
                             otherwise ``None``
    * ``active_prefixes``   – active prefixes (``int``) or ``None``

    Returns an empty list when the output cannot be parsed.

    Example input::

        Groups: 2 Peers: 3 Down peers: 0
        Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending
          inet.0              40         38          0          0          0          0
        Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...
        10.0.0.1              65001      14621      14609       0       0    5d 3:14 Establ
          inet.0: 38/40/40/0
        10.0.0.2              65002       1823       1821       0       1   1:23:45 Active
        10.0.0.3              65003          0          0       0       0     never Connect
    """
    peers: list[dict] = []
    in_header = False

    # Header line detection
    header_re = re.compile(r"^Peer\s+AS\s+InPkt", re.IGNORECASE)
    # Fixed leading fields: IP  AS  InPkt  OutPkt  OutQ  Flaps  <rest>
    # <rest> is "Last Up/Dwn State" where Up/Dwn may contain a space (e.g. "5d 3:14")
    # so we capture the remaining text and split off the last word as the state.
    peer_re = re.compile(r"^(\d[\d.:a-fA-F:]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+(.+)$")
    # Continuation line with prefix counts: "  inet.0: 38/40/40/0"
    prefix_re = re.compile(r"^\s+\S+:\s*(\d+)/(\d+)/")

    for line in output.splitlines():
        if header_re.match(line):
            in_header = True
            continue
        if not in_header:
            continue

        # Continuation line (prefix counts for the last peer)
        m = prefix_re.match(line)
        if m and peers:
            peers[-1]["active_prefixes"] = int(m.group(1))
            if peers[-1]["prefixes_received"] is None:
                peers[-1]["prefixes_received"] = int(m.group(2))
            continue

        m = peer_re.match(line)
        if m:
            rest = m.group(5).strip()
            # The state is always the last whitespace-delimited token;
            # everything before it is the Last Up/Dwn value.
            parts = rest.split()
            raw_state = parts[-1] if parts else ""
            up_down = " ".join(parts[:-1]) if len(parts) > 1 else ""

            # "Establ" is JunOS's abbreviation for "Established"
            if raw_state.lower().startswith("establ"):
                state = "Established"
            else:
                state = raw_state

            peers.append(
                {
                    "neighbor": m.group(1),
                    "peer_as": int(m.group(2)),
                    "state": state,
                    "up_down": up_down,
                    "prefixes_received": None,
                    "active_prefixes": None,
                }
            )

    return peers


# ---------------------------------------------------------------------------
# OSPF neighbour table
# ---------------------------------------------------------------------------


def parse_ospf_neighbors_junos(output: str) -> list[dict]:
    """Parse ``show ospf neighbor`` output from JunOS.

    Each returned dict contains:

    * ``neighbor_id`` – OSPF Router-ID of the neighbour (``str``)
    * ``address``     – neighbour interface IP address (``str``)
    * ``interface``   – local interface name (``str``)
    * ``state``       – adjacency state (e.g. ``'Full'``, ``'ExStart'``, ``'2Way'``)
    * ``dead_time``   – dead-timer countdown in ``HH:MM:SS`` format (``str``)
    * ``priority``    – interface priority (``int``)
    * ``is_full``     – ``True`` when ``state == 'Full'``

    Returns an empty list when the output cannot be parsed.

    Example input::

        Address          Interface              State     ID               Pri  Dead
        10.0.0.2         ge-0/0/0.0             Full      192.168.1.2        1    33
        10.0.0.3         ge-0/0/1.0             Full      192.168.1.3        1    35
        10.0.0.4         ge-0/0/2.0             ExStart   192.168.1.4        0    38
    """
    neighbors: list[dict] = []

    for line in output.splitlines():
        match = re.match(
            r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)",
            line,
        )
        if match:
            state = match.group(3)
            neighbors.append(
                {
                    "neighbor_id": match.group(4),
                    "address": match.group(1),
                    "interface": match.group(2),
                    "state": state,
                    "dead_time": match.group(6),
                    "priority": int(match.group(5)),
                    "is_full": state.lower() == "full",
                }
            )
    return neighbors


# ---------------------------------------------------------------------------
# Chassis alarms
# ---------------------------------------------------------------------------


def parse_chassis_alarms(output: str) -> list[dict]:
    """Parse ``show chassis alarms`` output.

    Each returned dict represents one active alarm:

    * ``time``      – timestamp string (e.g. ``'2024-01-15 10:23:01 UTC'``)
    * ``class_``    – alarm class (``'Major'`` or ``'Minor'``)
    * ``description`` – alarm description string
    * ``is_major``  – ``True`` when class is ``'Major'``

    Returns an empty list when no alarms are present or the output cannot
    be parsed.

    Example input::

        2 alarms currently active
        Alarm time               Class  Description
        2024-01-15 10:23:01 UTC  Major  FPC 1 Major Errors
        2024-01-15 10:30:12 UTC  Minor  PEM Input Failure
    """
    alarms: list[dict] = []
    # Lines like: "2024-01-15 10:23:01 UTC  Major  FPC 1 Major Errors"
    alarm_re = re.compile(
        r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\w+)\s+(Major|Minor)\s+(.+)",
        re.IGNORECASE,
    )

    for line in output.splitlines():
        m = alarm_re.match(line.strip())
        if m:
            cls = m.group(2).capitalize()
            alarms.append(
                {
                    "time": m.group(1).strip(),
                    "class_": cls,
                    "description": m.group(3).strip(),
                    "is_major": cls == "Major",
                }
            )

    return alarms


# ---------------------------------------------------------------------------
# Chassis environment
# ---------------------------------------------------------------------------


def parse_chassis_environment(output: str) -> dict:
    """Parse ``show chassis environment`` output.

    Returns a dict with keys:

    * ``power_supplies`` – list of PSU dicts (``name``, ``status``, ``ok``)
    * ``fans``           – list of fan dicts (``name``, ``status``, ``ok``)
    * ``temperatures``   – list of temperature dicts
                          (``name``, ``celsius``, ``status``, ``ok``)
    * ``overall_ok``     – ``True`` when every parsed component is OK

    Returns a dict with empty lists when the output cannot be parsed.

    Example input::

        Class Item                           Status     Measurement
        Power Power Supply 0                 OK
        Power Power Supply 1                 Absent
        Cooling FPC 0 Fan 0                  OK        2250 RPM
        Cooling FPC 0 Fan 1                  OK        2250 RPM
        Temp  CPU                            OK         38 degrees C / 100 degrees F
        Temp  FPC 0                          OK         43 degrees C / 109 degrees F
    """
    power_supplies: list[dict] = []
    fans: list[dict] = []
    temperatures: list[dict] = []

    # Match component lines: "  Power  Power Supply 0   OK"
    row_re = re.compile(
        r"^\s*(Power|Cooling|Temp)\s+(.+?)\s{2,}(OK|Absent|Fail\w*|Testing|Check\w*)"
        r"(?:\s+(-?\d+)\s+degrees)?",
        re.IGNORECASE,
    )

    for line in output.splitlines():
        m = row_re.match(line)
        if not m:
            continue

        category = m.group(1).lower()
        name = m.group(2).strip()
        status = m.group(3).strip()
        celsius_raw = m.group(4)

        ok = status.lower() in ("ok", "absent")

        if category == "power":
            power_supplies.append({"name": name, "status": status, "ok": ok})
        elif category == "cooling":
            fans.append({"name": name, "status": status, "ok": ok})
        elif category == "temp":
            temperatures.append(
                {
                    "name": name,
                    "celsius": int(celsius_raw) if celsius_raw else None,
                    "status": status,
                    "ok": ok,
                }
            )

    overall_ok = all(item["ok"] for group in (power_supplies, fans, temperatures) for item in group)

    return {
        "power_supplies": power_supplies,
        "fans": fans,
        "temperatures": temperatures,
        "overall_ok": overall_ok,
    }


# ---------------------------------------------------------------------------
# Route summary
# ---------------------------------------------------------------------------


def parse_route_summary(output: str) -> list[dict]:
    """Parse ``show route summary`` output.

    Each returned dict represents one routing table:

    * ``table``          – routing table name (e.g. ``'inet.0'``, ``'inet6.0'``)
    * ``active_routes``  – number of active (best-path) routes (``int``)
    * ``holddown_routes``– routes in holddown state (``int``)
    * ``hidden_routes``  – hidden routes (``int``)
    * ``total_routes``   – total routes in the table (``int``)

    Returns an empty list when the output cannot be parsed.

    Example input::

        Routing table: inet.0
        Destinations: 1204  Routes: 1219  Holddown: 0  Hidden: 0
          Limit/Threshold: 1048576/1048576 destinations
          Direct:      3 routes,      3 active
          Local:       3 routes,      3 active
          BGP:      1213 routes,   1198 active
    """
    tables: list[dict] = []
    current_table: str | None = None

    table_re = re.compile(r"^Routing table:\s+(\S+)", re.IGNORECASE)
    dest_re = re.compile(
        r"Destinations:\s*(\d+)\s+Routes:\s*(\d+)\s+Holddown:\s*(\d+)\s+Hidden:\s*(\d+)",
        re.IGNORECASE,
    )

    for line in output.splitlines():
        m = table_re.match(line.strip())
        if m:
            current_table = m.group(1)
            continue

        m = dest_re.search(line)
        if m and current_table is not None:
            tables.append(
                {
                    "table": current_table,
                    "active_routes": int(m.group(1)),
                    "holddown_routes": int(m.group(3)),
                    "hidden_routes": int(m.group(4)),
                    "total_routes": int(m.group(2)),
                }
            )
            current_table = None  # Reset until next "Routing table:" line

    return tables
