"""Parsers for Nokia SR OS CLI output."""

from __future__ import annotations

import re


def parse_interfaces(output: str) -> list[dict]:

__all__ = ["parse_interfaces", "parse_bgp_summary", "parse_ospf_neighbors"]
    """Parse ``show port`` output into a list of interface dicts.

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


def parse_bgp_summary(output: str) -> list[dict]:
    """Parse ``show router bgp summary`` output into a BGP peer list.

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


def parse_ospf_neighbors(output: str) -> list[dict]:
    """Parse ``show router ospf neighbor`` output into an adjacency list.

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
