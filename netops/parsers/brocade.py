"""Parsers for Brocade FastIron / Network OS / Fabric OS CLI output."""

from __future__ import annotations

import re

__all__ = [
    "parse_interfaces",
    "parse_ip_routes",
    "parse_version",
    "parse_fabric",
]


def parse_interfaces(output: str) -> list[dict]:
    """Parse ``show interfaces`` or ``show interface brief`` output.

    Supports Brocade FastIron/ICX interface summary lines.

    Returns
    -------
    list
        List of per-interface dicts.

    Each returned dict contains:

    * ``name``     – interface identifier (e.g. ``'GigabitEthernet1/1/1'``)
    * ``status``   – administrative state: ``'up'`` or ``'down'``
    * ``protocol`` – line-protocol state: ``'up'`` or ``'down'``
    * ``up``       – ``True`` when both admin and line-protocol are ``'up'``

    The field names match the Cisco / Nokia parser convention so callers can
    treat output from all vendors uniformly.

    Handles both the detailed form::

        GigabitEthernet1/1/1 is up, line protocol is up

    and the brief tabular form::

        GigabitEthernet1/1/1    up         up        ...
    """
    interfaces: list[dict] = []

    for line in output.splitlines():
        # Detailed form: "GigabitEthernet1/1/1 is up, line protocol is up"
        detail = re.match(
            r"^(\S+)\s+is\s+(up|down|administratively down),"
            r"\s+line protocol is\s+(up|down)",
            line,
            re.IGNORECASE,
        )
        if detail:
            admin = detail.group(2).lower()
            proto = detail.group(3).lower()
            # Normalise "administratively down" → "down"
            status = "down" if "down" in admin else "up"
            interfaces.append(
                {
                    "name": detail.group(1),
                    "status": status,
                    "protocol": proto,
                    "up": status == "up" and proto == "up",
                }
            )
            continue

        # Brief tabular form: "GigabitEthernet1/1/1  up  up  ..."
        brief = re.match(
            r"^((?:GigabitEthernet|TenGigabitEthernet|FortyGigabitEthernet|"
            r"HundredGigabitEthernet|Ethernet|Management|Ve|Loopback|Tunnel)"
            r"\S*)\s+(up|down)\s+(up|down)",
            line,
            re.IGNORECASE,
        )
        if brief:
            status = brief.group(2).lower()
            proto = brief.group(3).lower()
            interfaces.append(
                {
                    "name": brief.group(1),
                    "status": status,
                    "protocol": proto,
                    "up": status == "up" and proto == "up",
                }
            )

    return interfaces


def parse_ip_routes(output: str) -> list[dict]:
    """Parse ``show ip route`` output from Brocade FastIron/ICX.

    Returns
    -------
    list
        List of per-route dicts. Returns an empty list when the output cannot be parsed.

    Each returned dict contains:

    * ``type``      – route type code (e.g. ``'B'``, ``'C'``, ``'S'``, ``'R'``)
    * ``network``   – destination prefix in CIDR notation (e.g. ``'10.0.0.0/8'``)
    * ``next_hop``  – next-hop IP address, or ``'DIRECT'`` for connected routes
    * ``interface`` – egress interface (e.g. ``'e1/1/1'``)
    * ``metric``    – route metric / cost (``int``)

    Example input lines::

        B    10.0.0.0/8         192.168.1.254    e1/1  1
        C    192.168.1.0/24     DIRECT           e1/2  1
        S    0.0.0.0/0          10.0.0.1         e1/1  1
    """
    routes: list[dict] = []

    for line in output.splitlines():
        match = re.match(
            r"^([BCSROEI\*?]\*?)\s+"
            r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s+"
            r"(\S+)\s+"
            r"(\S+)\s+"
            r"(\d+)",
            line,
        )
        if match:
            routes.append(
                {
                    "type": match.group(1).rstrip("*"),
                    "network": match.group(2),
                    "next_hop": match.group(3),
                    "interface": match.group(4),
                    "metric": int(match.group(5)),
                }
            )
    return routes


def parse_version(output: str) -> dict:
    """Parse ``show version`` output from a Brocade FastIron/ICX device.

    Returns
    -------
    dict
        Dict with keys:

        * ``model``    – hardware model string (e.g. ``'ICX7550-48'``)
        * ``version``  – software version string (e.g. ``'09.0.10T215'``)
        * ``vendor``   – always ``'Brocade'``

        Returns a dict with ``None`` values when the output cannot be parsed.

    Example input lines::

        HW: ICX7550-48
        SW: Version 09.0.10T215 Copyright (c) 1996-2023 Ruckus Networks, Inc.
    """
    result: dict = {"model": None, "version": None, "vendor": "Brocade"}

    for line in output.splitlines():
        hw = re.match(r"^HW:\s+(\S+)", line)
        if hw:
            result["model"] = hw.group(1)

        sw = re.search(r"Version\s+(\S+)", line)
        if sw and result["version"] is None:
            result["version"] = sw.group(1)

    return result


def parse_fabric(output: str) -> dict:
    """Parse ``show fabric`` output from a Brocade Fabric OS (FOS) SAN switch.

    Returns
    -------
    dict
        Dict with keys:

        * ``fabric_name`` – fabric name string, or ``None``
        * ``fabric_os``   – Fabric OS version string, or ``None``
        * ``switches``    – list of switch dicts, each containing ``name`` and
                            ``domain``
        * ``ports``       – list of port dicts, each containing ``port``,
                            ``state`` (``'Online'`` / ``'Offline'``)

        Returns a dict with empty defaults when the output cannot be parsed.

    Example input::

        Fabric Name: FabricA
        Fabric OS:  v9.1.0
        Switch: fc-sw-01 (domain 1)
          Port 0/1: Online
          Port 0/2: Offline
    """
    result: dict = {
        "fabric_name": None,
        "fabric_os": None,
        "switches": [],
        "ports": [],
    }

    for line in output.splitlines():
        fn = re.match(r"Fabric Name:\s+(.+)", line)
        if fn:
            result["fabric_name"] = fn.group(1).strip()
            continue

        fos = re.match(r"Fabric OS:\s+(\S+)", line)
        if fos:
            result["fabric_os"] = fos.group(1)
            continue

        sw = re.match(r"Switch:\s+(\S+)\s+\(domain\s+(\d+)\)", line)
        if sw:
            result["switches"].append({"name": sw.group(1), "domain": int(sw.group(2))})
            continue

        port = re.match(r"\s+Port\s+(\S+):\s+(Online|Offline)", line)
        if port:
            result["ports"].append({"port": port.group(1), "state": port.group(2)})

    return result
