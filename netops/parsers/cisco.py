"""Parsers for Cisco IOS/IOS-XE show command output.

Covers OSPF neighbor tables, device environment (temperature, fans, power
supplies) and ``show version`` (uptime, reload reason, IOS version).
"""

from __future__ import annotations

import re

__all__ = [
    "parse_ospf_neighbors",
    "parse_environment_cisco",
    "parse_version_cisco",
]


# ---------------------------------------------------------------------------
# OSPF neighbor parser
# ---------------------------------------------------------------------------


def parse_ospf_neighbors(output: str) -> list[dict]:
    """Parse ``show ip ospf neighbor`` output from Cisco IOS/IOS-XE.

    Returns
    -------
    list
        List of per-neighbor dicts. Returns an empty list when no neighbors
        are parsed.

    Each returned dict contains:

    * ``neighbor_id`` – OSPF router-ID of the neighbor (``str``)
    * ``priority``    – interface priority (``int``)
    * ``state``       – adjacency state string (e.g. ``'FULL/DR'``, ``'INIT/DROTHER'``)
    * ``dead_time``   – dead-timer countdown in ``HH:MM:SS`` format (``str``)
    * ``address``     – neighbor IP address (``str``)
    * ``interface``   – local interface name (``str``)
    * ``is_full``     – ``True`` when the state starts with ``'FULL'``

    Example input::

        Neighbor ID     Pri   State           Dead Time   Address         Interface
        192.168.1.2       1   FULL/DR         00:00:37    10.0.0.2        GigabitEthernet0/0
        192.168.1.3       1   FULL/BDR        00:00:38    10.0.0.3        GigabitEthernet0/0
        192.168.1.4       0   INIT/DROTHER    00:00:35    10.0.0.4        GigabitEthernet0/1
    """
    neighbors: list[dict] = []

    for line in output.splitlines():
        match = re.match(
            r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+(\d+:\d+:\d+)\s+"
            r"(\d+\.\d+\.\d+\.\d+)\s+(\S+)",
            line,
        )
        if match:
            state = match.group(3)
            neighbors.append(
                {
                    "neighbor_id": match.group(1),
                    "priority": int(match.group(2)),
                    "state": state,
                    "dead_time": match.group(4),
                    "address": match.group(5),
                    "interface": match.group(6),
                    "is_full": state.upper().startswith("FULL"),
                }
            )

    return neighbors


# ---------------------------------------------------------------------------
# Environment parser
# ---------------------------------------------------------------------------


def parse_environment_cisco(output: str) -> dict:
    """Parse ``show environment all`` output from Cisco IOS/IOS-XE.

    Handles both IOS (router) and IOS-XE (Catalyst switch) output formats.

    Returns
    -------
    dict
        Dict with keys:

        * ``fans``           – list of fan dicts (``name``, ``status``, ``ok``)
        * ``temperatures``   – list of temperature dicts
                               (``name``, ``celsius`` or ``None``, ``status``, ``ok``)
        * ``power_supplies`` – list of power-supply dicts (``name``, ``status``, ``ok``)
        * ``overall_ok``     – ``True`` when every reported component is OK;
                               ``True`` when no components were parsed (unknown state)

        Returns a dict with empty lists when the output cannot be parsed.

    Example IOS-XE input lines::

        Switch 1 FAN 1 is OK
        Switch 1: TEMPERATURE is OK
        SYSTEM INLET       : 28 Celsius, Critical threshold is 60 Celsius
        Switch 1: POWER-SUPPLY 1 is PRESENT
        Switch 1: POWER-SUPPLY 2 is NOT PRESENT
    """
    fans: list[dict] = []
    temperatures: list[dict] = []
    power_supplies: list[dict] = []

    for line in output.splitlines():
        # ----- Fan lines -----
        # IOS-XE:   "Switch 1 FAN 1 is OK"
        # IOS:      "FAN 1 is OK" / "FAN: OK"
        fan_match = re.search(
            r"(?:^|\s)FAN\s*(\d*)\s+(?:is\s+)?(\w+)",
            line,
            re.IGNORECASE,
        )
        if fan_match:
            name = f"FAN{fan_match.group(1)}" if fan_match.group(1) else "FAN"
            status = fan_match.group(2).upper()
            fans.append({"name": name, "status": status, "ok": status == "OK"})
            continue

        # ----- Temperature summary lines -----
        # IOS-XE:   "Switch 1: TEMPERATURE is OK"
        # IOS:      "Temperature: OK"
        temp_summary = re.search(
            r"TEMPERATURE\s+(?:is\s+)?(\w+)",
            line,
            re.IGNORECASE,
        )
        if temp_summary:
            status = temp_summary.group(1).upper()
            temperatures.append(
                {"name": "TEMPERATURE", "celsius": None, "status": status, "ok": status == "OK"}
            )
            continue

        # ----- Detailed temperature readings -----
        # IOS-XE:  "SYSTEM INLET       : 28 Celsius, Critical threshold is 60 Celsius"
        # IOS:     "  Inlet: 28 Celsius (Critical: 60)"
        temp_detail = re.match(
            r"^\s*([\w\s]+?)\s*:\s+(\d+)\s+[Cc]elsius",
            line,
        )
        if temp_detail:
            name = temp_detail.group(1).strip()
            celsius = int(temp_detail.group(2))
            # Determine OK/fail from any trailing keyword or absence of "FAIL"/"ALARM"
            fail = bool(re.search(r"\b(?:FAIL|ALARM|CRITICAL|SHUTDOWN)\b", line, re.IGNORECASE))
            status = "FAIL" if fail else "OK"
            temperatures.append(
                {"name": name, "celsius": celsius, "status": status, "ok": not fail}
            )
            continue

        # ----- Power supply lines -----
        # IOS-XE:  "Switch 1: POWER-SUPPLY 1 is PRESENT"
        # IOS:     "Power Supply 1: Normal"  /  "PS1: Normal"
        ps_match = re.search(
            r"(?:POWER[-\s]SUPPLY|Power Supply|PS)\s*(\d+)\s*[:\s]+(?:is\s+)?(\w+(?:\s+\w+)?)",
            line,
            re.IGNORECASE,
        )
        if ps_match:
            name = f"PS{ps_match.group(1)}"
            raw_status = ps_match.group(2).strip().upper()
            ok = raw_status in ("NORMAL", "OK", "GOOD", "PRESENT")
            power_supplies.append({"name": name, "status": raw_status, "ok": ok})
            continue

    components = fans + temperatures + power_supplies
    overall_ok = all(c["ok"] for c in components) if components else True

    return {
        "fans": fans,
        "temperatures": temperatures,
        "power_supplies": power_supplies,
        "overall_ok": overall_ok,
    }


# ---------------------------------------------------------------------------
# Version / uptime parser
# ---------------------------------------------------------------------------


def parse_version_cisco(output: str) -> dict:
    """Parse ``show version`` output from Cisco IOS/IOS-XE.

    Returns
    -------
    dict
        Dict with keys:

        * ``version``       – IOS/IOS-XE version string (``str`` or ``None``)
        * ``platform``      – hardware platform identifier (``str`` or ``None``)
        * ``uptime``        – uptime string as reported by the device (``str`` or ``None``)
        * ``reload_reason`` – last reload/restart reason (``str`` or ``None``)
        * ``image``         – system image file path (``str`` or ``None``)

        Returns a dict with all ``None`` values when the output cannot be parsed.

    Example input lines::

        Cisco IOS Software, Version 15.2(4)E8, RELEASE SOFTWARE (fc2)
        cisco WS-C3750X-48P (PowerPC405) processor ...
        Switch uptime is 2 weeks, 3 days, 4 hours, 5 minutes
        Last reload reason: Reload command
        System image file is "flash:c3750x-ipservicesk9-mz.152-4.E8.bin"
    """
    result: dict = {
        "version": None,
        "platform": None,
        "uptime": None,
        "reload_reason": None,
        "image": None,
    }

    for line in output.splitlines():
        # IOS:    "Cisco IOS Software, Version 15.2(4)E8, ..."
        # IOS-XE: "Cisco IOS XE Software, Version 16.12.4"
        if result["version"] is None:
            ver_match = re.search(r"\bVersion\s+([\d().a-zA-Z]+)", line)
            if ver_match:
                result["version"] = ver_match.group(1)

        # Platform: "cisco WS-C3750X-48P (PowerPC405) processor ..."
        # Require the word "processor" to avoid matching "Cisco IOS Software, ..."
        if result["platform"] is None:
            plat_match = re.match(r"^cisco\s+(\S+)\s+.+?\bprocessor\b", line, re.IGNORECASE)
            if plat_match:
                result["platform"] = plat_match.group(1)

        # Uptime: "Router uptime is 2 weeks, ..."  /  "Switch uptime is ..."
        uptime_match = re.search(r"\buptime\s+is\s+(.+)", line, re.IGNORECASE)
        if uptime_match:
            result["uptime"] = uptime_match.group(1).strip()

        # Reload reason (IOS-XE): "Last reload reason: Reload command"
        last_reload = re.search(r"[Ll]ast\s+reload\s+reason\s*:\s*(.+)", line)
        if last_reload and result["reload_reason"] is None:
            result["reload_reason"] = last_reload.group(1).strip()

        # Reload reason (IOS): "System restarted by reload at ..."
        if result["reload_reason"] is None:
            sys_restart = re.search(r"[Ss]ystem\s+restarted\s+by\s+(.+?)(?:\s+at\s+|$)", line)
            if sys_restart:
                result["reload_reason"] = sys_restart.group(1).strip()

        # Boot image
        if result["image"] is None:
            image_match = re.search(r'[Ss]ystem\s+image\s+file\s+is\s+"([^"]+)"', line)
            if image_match:
                result["image"] = image_match.group(1)

    return result


def parse_inventory_cisco(output: str) -> list[dict]:
    """Parse ``show inventory`` output from Cisco IOS/NX-OS/IOS-XE.

    Returns
    -------
    list
        List of dicts, each with:

        * ``name``   – component name (e.g. "Chassis", "Slot 1")
        * ``descr``  – description string
        * ``pid``    – product ID
        * ``vid``    – version ID
        * ``sn``     – serial number

    Example input::

        NAME: "Chassis", DESCR: "Nexus 9000 Series Chassis"
        PID: N9K-C93180YC-FX3, VID: V01, SN: FDO23456789
    """
    entries: list[dict] = []
    current_name = None
    current_descr = None

    for line in output.splitlines():
        # NAME: "...", DESCR: "..."
        name_match = re.match(r'^NAME:\s*"([^"]*)".*?DESCR:\s*"([^"]*)"', line, re.IGNORECASE)
        if name_match:
            current_name = name_match.group(1)
            current_descr = name_match.group(2)
            continue

        # PID: ..., VID: ..., SN: ...
        pid_match = re.match(
            r"^PID:\s*(\S*)\s*,\s*VID:\s*(\S*)\s*,\s*SN:\s*(\S*)", line, re.IGNORECASE
        )
        if pid_match and current_name is not None:
            entries.append(
                {
                    "name": current_name,
                    "descr": current_descr or "",
                    "pid": pid_match.group(1),
                    "vid": pid_match.group(2),
                    "sn": pid_match.group(3),
                }
            )
            current_name = None
            current_descr = None

    return entries


def parse_serial_cisco(output: str) -> str | None:
    """Extract the chassis serial number from ``show inventory`` output.

    Returns
    -------
    str or None
        The serial number string for the first entry whose name contains
        "chassis" (case-insensitive), or the first entry if no chassis
        is found. Returns ``None`` if parsing fails.
    """
    entries = parse_inventory_cisco(output)
    if not entries:
        return None

    # Prefer the chassis entry
    for e in entries:
        if "chassis" in e["name"].lower() and e["sn"]:
            return str(e["sn"])

    # Fall back to first entry with a serial
    for e in entries:
        if e["sn"]:
            return str(e["sn"])

    return None
