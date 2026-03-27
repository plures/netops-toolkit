"""Parsers for VLAN CLI output.

Supports Cisco IOS/IOS-XE:

* ``show vlan brief``        → :func:`parse_vlan_brief`
* ``show interfaces trunk``  → :func:`parse_interfaces_trunk`

Utility:

* :func:`expand_vlan_range` — expands VLAN range strings (``"1,10-20,100"``)
"""

from __future__ import annotations

import re

__all__ = ["expand_vlan_range", "parse_interfaces_trunk", "parse_vlan_brief"]


def expand_vlan_range(ranges: str) -> set[int]:
    """Expand a VLAN range string into a set of integer VLAN IDs.

    Handles comma-separated lists and dash-delimited ranges:

    * ``"10"``         → ``{10}``
    * ``"10,20,30"``   → ``{10, 20, 30}``
    * ``"10-14"``      → ``{10, 11, 12, 13, 14}``
    * ``"1,10-12,20"`` → ``{1, 10, 11, 12, 20}``
    * ``"none"``       → ``set()``
    * ``""``           → ``set()``

    Non-parseable tokens are silently ignored.

    Returns
    -------
    set
        Set of integer VLAN IDs.
    """
    vlans: set[int] = set()
    if not ranges or ranges.strip().lower() == "none":
        return vlans
    for part in ranges.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                vlans.update(range(int(lo.strip()), int(hi.strip()) + 1))
            except ValueError:
                pass
        else:
            try:
                vlans.add(int(part))
            except ValueError:
                pass
    return vlans


def parse_vlan_brief(output: str) -> list[dict]:
    """Parse ``show vlan brief`` output.

    Handles Cisco IOS and IOS-XE formats.

    Returns
    -------
    list
        List of per-VLAN dicts. Returns an empty list when the output cannot be parsed.

    Each returned dict contains:

    * ``vlan_id`` – VLAN ID (``int``)
    * ``name``    – VLAN name (``str``)
    * ``status``  – status string, e.g. ``'active'``, ``'act/unsup'``
    * ``ports``   – list of access-port names assigned to this VLAN
    """
    vlans: list[dict] = []
    in_data = False

    for line in output.splitlines():
        # Header line marks start of VLAN data
        if re.match(r"^VLAN\s+Name\s+Status", line):
            in_data = True
            continue

        if not in_data:
            continue

        # Skip separator line (---- ---- ----)
        if re.match(r"^-{4}", line):
            continue

        # Data line: <vlan_id>  <name>  <status>  [<port>, ...]
        m = re.match(r"^(\d{1,4})\s+(\S+)\s+(\S+)\s*(.*)", line)
        if m:
            ports_raw = m.group(4).strip()
            ports = [p.strip() for p in ports_raw.split(",") if p.strip()] if ports_raw else []
            vlans.append(
                {
                    "vlan_id": int(m.group(1)),
                    "name": m.group(2),
                    "status": m.group(3),
                    "ports": ports,
                }
            )
        elif vlans and re.match(r"^\s+\S", line):
            # Continuation line: port list wrapped to the next line
            extra = [p.strip() for p in line.split(",") if p.strip()]
            vlans[-1]["ports"].extend(extra)

    return vlans


def parse_interfaces_trunk(output: str) -> list[dict]:
    """Parse ``show interfaces trunk`` output.

    Handles Cisco IOS and IOS-XE formats.  The command output is divided into
    four stanzas; all four are parsed and merged per-port:

    1. Port / Mode / Encapsulation / Status / Native VLAN
    2. Port / VLANs allowed on trunk
    3. Port / VLANs allowed and active in management domain
    4. Port / VLANs in spanning tree forwarding state and not pruned

    Returns
    -------
    list
        List of per-interface trunk dicts. Returns an empty list when the
        output cannot be parsed or contains no trunking ports.

    Each returned dict contains:

    * ``port``             – interface name
    * ``mode``             – trunk mode (``'on'``, ``'auto'``, ``'desirable'``, …)
    * ``encapsulation``    – ``'802.1q'``, ``'isl'``, or ``'n-802.1q'``
    * ``status``           – ``'trunking'`` or ``'not-trunking'``
    * ``native_vlan``      – native VLAN ID (``int``)
    * ``allowed_vlans``    – raw allowed-VLAN string (e.g. ``'1-4094'``)
    * ``active_vlans``     – set of active VLAN IDs (``set[int]``)
    * ``forwarding_vlans`` – set of forwarding VLAN IDs (``set[int]``)
    """
    # section: 0=preamble, 1=mode/status, 2=allowed, 3=active, 4=forwarding
    section = 0
    trunks: dict[str, dict] = {}
    current_port: str | None = None

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Detect section headers
        if re.match(r"^Port\s+Mode\s+Encapsulation\s+Status", line):
            section = 1
            current_port = None
            continue
        if re.match(r"^Port\s+Vlans allowed on trunk", line):
            section = 2
            current_port = None
            continue
        if re.match(r"^Port\s+Vlans allowed and active", line):
            section = 3
            current_port = None
            continue
        if re.match(r"^Port\s+Vlans in spanning tree", line):
            section = 4
            current_port = None
            continue

        if section == 0:
            continue

        # --- Section 1: Port Mode Encapsulation Status NativeVlan ---
        if section == 1:
            m = re.match(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)", line)
            if m:
                port = m.group(1)
                current_port = port
                trunks.setdefault(
                    port,
                    {
                        "port": port,
                        "mode": m.group(2),
                        "encapsulation": m.group(3),
                        "status": m.group(4),
                        "native_vlan": int(m.group(5)),
                        "allowed_vlans": "",
                        "active_vlans": set(),
                        "forwarding_vlans": set(),
                    },
                )
            continue

        # --- Sections 2-4: Port <vlan-range> ---
        m = re.match(r"^(\S+)\s+(.*)", line)
        if m:
            port = m.group(1)
            current_port = port
            vlan_str = m.group(2).strip()
            if port not in trunks:
                continue
            if section == 2:
                trunks[port]["allowed_vlans"] = vlan_str
            elif section == 3:
                trunks[port]["active_vlans"] = expand_vlan_range(vlan_str)
            else:
                trunks[port]["forwarding_vlans"] = expand_vlan_range(vlan_str)
        elif current_port and current_port in trunks and re.match(r"^\s+\S", line):
            # Continuation line for a very long VLAN range
            if section == 2:
                trunks[current_port]["allowed_vlans"] += "," + stripped
            elif section == 3:
                trunks[current_port]["active_vlans"] |= expand_vlan_range(stripped)
            else:
                trunks[current_port]["forwarding_vlans"] |= expand_vlan_range(stripped)

    return list(trunks.values())
