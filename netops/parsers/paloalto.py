"""Parsers for Palo Alto Networks PAN-OS CLI output.

Supports structured output for the core ``show`` commands used by
health checks and security policy audits.
"""

from __future__ import annotations

import re

__all__ = [
    "parse_system_info",
    "parse_interfaces",
    "parse_routes",
    "parse_session_info",
    "parse_security_policy",
    "parse_security_policy_stats",
    "parse_ha_state",
]


def parse_system_info(output: str) -> dict:
    """Parse ``show system info`` output from a PAN-OS device.

    Returns a dict with keys:

    * ``hostname``         – device hostname (e.g. ``'pa-fw-01'``)
    * ``ip_address``       – management IP address
    * ``model``            – hardware model (e.g. ``'PA-3220'``)
    * ``serial``           – chassis serial number
    * ``panos_version``    – PAN-OS software version (e.g. ``'10.2.3'``)
    * ``app_version``      – application content version
    * ``threat_version``   – threat content version
    * ``url_version``      – URL filtering database version
    * ``ha_mode``          – HA operating mode (e.g. ``'Active-Passive'``), or ``None``
    * ``ha_state``         – local HA state (e.g. ``'active'``), or ``None``

    Returns a dict with ``None`` values for any field that cannot be parsed.

    Example input lines::

        Hostname: pa-fw-01
        IP address: 10.0.0.1
        Model: PA-3220
        Serial: 0123456789AB
        PAN-OS Version: 10.2.3
        App version: 8700-7709
        Threat version: 8700-7709
        URL filtering version: 20231201.20079
        HA mode: Active-Passive
        HA state: active
    """
    result: dict = {
        "hostname": None,
        "ip_address": None,
        "model": None,
        "serial": None,
        "panos_version": None,
        "app_version": None,
        "threat_version": None,
        "url_version": None,
        "ha_mode": None,
        "ha_state": None,
    }

    _fields = {
        "hostname": re.compile(r"^Hostname\s*:\s*(.+)", re.IGNORECASE),
        "ip_address": re.compile(r"^IP address\s*:\s*(.+)", re.IGNORECASE),
        "model": re.compile(r"^Model\s*:\s*(.+)", re.IGNORECASE),
        "serial": re.compile(r"^Serial\s*:\s*(.+)", re.IGNORECASE),
        "panos_version": re.compile(r"^PAN-OS [Vv]ersion\s*:\s*(.+)", re.IGNORECASE),
        "app_version": re.compile(r"^App [Vv]ersion\s*:\s*(.+)", re.IGNORECASE),
        "threat_version": re.compile(r"^Threat [Vv]ersion\s*:\s*(.+)", re.IGNORECASE),
        "url_version": re.compile(
            r"^URL filtering [Vv]ersion\s*:\s*(.+)", re.IGNORECASE
        ),
        "ha_mode": re.compile(r"^HA [Mm]ode\s*:\s*(.+)", re.IGNORECASE),
        "ha_state": re.compile(r"^HA [Ss]tate\s*:\s*(.+)", re.IGNORECASE),
    }

    for line in output.splitlines():
        line = line.strip()
        for key, pattern in _fields.items():
            if result[key] is None:
                m = pattern.match(line)
                if m:
                    result[key] = m.group(1).strip()

    return result


def parse_interfaces(output: str) -> list[dict]:
    """Parse ``show interface all`` output from a PAN-OS device.

    Each returned dict contains:

    * ``name``      – interface name (e.g. ``'ethernet1/1'``)
    * ``state``     – interface state: ``'up'`` or ``'down'``
    * ``ip``        – IP address with prefix length (e.g. ``'10.0.1.1/24'``),
                      or ``None`` when unassigned
    * ``vsys``      – virtual system the interface belongs to
    * ``zone``      – security zone, or ``None`` when not displayed
    * ``up``        – ``True`` when state is ``'up'``

    Returns an empty list when the output cannot be parsed.

    Example input lines::

        Name            State   IP (prefix)          VSys   Zone
        ethernet1/1     up      10.0.1.1/24          vsys1  trust
        ethernet1/2     up      203.0.113.1/30       vsys1  untrust
        ethernet1/3     down    unassigned           vsys1
        loopback.1      up      1.1.1.1/32           vsys1
    """
    interfaces: list[dict] = []

    for line in output.splitlines():
        # Match data rows; interface names start with a letter, no spaces
        m = re.match(
            r"^(\S+)\s+(up|down)\s+(\S+)\s+(\S+)(?:\s+(\S+))?",
            line,
            re.IGNORECASE,
        )
        if not m:
            continue
        name = m.group(1)
        # Skip header row
        if name.lower() in ("name", "interface"):
            continue
        state = m.group(2).lower()
        ip_field = m.group(3)
        ip = None if ip_field.lower() == "unassigned" else ip_field
        vsys = m.group(4)
        zone = m.group(5) if m.lastindex and m.lastindex >= 5 else None
        interfaces.append(
            {
                "name": name,
                "state": state,
                "ip": ip,
                "vsys": vsys,
                "zone": zone,
                "up": state == "up",
            }
        )

    return interfaces


def parse_routes(output: str) -> list[dict]:
    """Parse ``show routing route`` output from a PAN-OS device.

    Each returned dict contains:

    * ``destination`` – destination prefix in CIDR notation
    * ``nexthop``     – next-hop IP address, or ``'0.0.0.0'`` for connected routes
    * ``metric``      – route metric (``int``)
    * ``flags``       – raw flags string (e.g. ``'A S'``)
    * ``active``      – ``True`` when the ``A`` (active) flag is set
    * ``type``        – route type letter(s) extracted from flags
                        (``'C'`` connected, ``'S'`` static, ``'B'`` BGP, etc.)
    * ``age``         – route age string (e.g. ``'1d'``), or ``None``
    * ``interface``   – egress interface name

    Returns an empty list when the output cannot be parsed.

    Example input lines::

        destination         nexthop         metric  flags  age   interface
        0.0.0.0/0           10.0.0.1        10      A S    1d    ethernet1/2
        10.0.1.0/24         0.0.0.0         0       A C    -     ethernet1/1
        10.0.0.0/8          192.168.1.1     10      A B    1d    ethernet1/2
    """
    routes: list[dict] = []
    _route_types = {"C": "C", "S": "S", "B": "B", "R": "R", "O": "O", "H": "H"}

    for line in output.splitlines():
        m = re.match(
            r"^\s*(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s+"
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
            r"(\d+)\s+"
            r"([A-Za-z0-9?~ ]+?)\s{2,}"
            r"(-|\S+)\s+"
            r"(\S+)",
            line,
        )
        if not m:
            continue
        flags = m.group(4).strip()
        # Determine primary route type from flags
        route_type = "?"
        for letter in _route_types:
            if letter in flags:
                route_type = letter
                break
        routes.append(
            {
                "destination": m.group(1),
                "nexthop": m.group(2),
                "metric": int(m.group(3)),
                "flags": flags,
                "active": "A" in flags,
                "type": route_type,
                "age": None if m.group(5) == "-" else m.group(5),
                "interface": m.group(6),
            }
        )

    return routes


def parse_session_info(output: str) -> dict:
    """Parse ``show session info`` output from a PAN-OS device.

    Returns a dict with keys:

    * ``max_sessions``        – maximum supported sessions (``int``)
    * ``active_sessions``     – current active sessions (``int``)
    * ``active_tcp``          – active TCP sessions (``int``)
    * ``active_udp``          – active UDP sessions (``int``)
    * ``active_icmp``         – active ICMP sessions (``int``)
    * ``session_utilization`` – session table utilization percentage (``float``)

    Any field that cannot be parsed will be ``None``.

    Example input lines::

        Number of sessions supported:      131072
        Number of active sessions:         1234
        Number of active TCP sessions:     1000
        Number of active UDP sessions:     200
        Number of active ICMP sessions:    34
        Session utilization:               1%
    """
    result: dict = {
        "max_sessions": None,
        "active_sessions": None,
        "active_tcp": None,
        "active_udp": None,
        "active_icmp": None,
        "session_utilization": None,
    }

    patterns = {
        "max_sessions": re.compile(r"Number of sessions supported\s*:\s*(\d+)"),
        "active_sessions": re.compile(r"Number of active sessions\s*:\s*(\d+)"),
        "active_tcp": re.compile(r"Number of active TCP sessions\s*:\s*(\d+)"),
        "active_udp": re.compile(r"Number of active UDP sessions\s*:\s*(\d+)"),
        "active_icmp": re.compile(r"Number of active ICMP sessions\s*:\s*(\d+)"),
        "session_utilization": re.compile(r"Session utilization\s*:\s*(\d+(?:\.\d+)?)%"),
    }

    for line in output.splitlines():
        for key, pattern in patterns.items():
            if result[key] is None:
                m = pattern.search(line)
                if m:
                    val = m.group(1)
                    result[key] = float(val) if key == "session_utilization" else int(val)

    return result


def parse_security_policy(output: str) -> list[dict]:
    """Parse ``show running security-policy`` output from a PAN-OS device.

    Each returned dict represents one security rule and contains:

    * ``name``          – rule name
    * ``from_zones``    – list of source security zones
    * ``to_zones``      – list of destination security zones
    * ``sources``       – list of source address objects / prefixes
    * ``destinations``  – list of destination address objects / prefixes
    * ``applications``  – list of application names
    * ``services``      – list of service objects
    * ``action``        – rule action: ``'allow'``, ``'deny'``, or ``'drop'``

    Returns an empty list when the output cannot be parsed.

    Example input::

        Rule: web-access
          from trust
          to untrust
          source [ any ]
          destination [ any ]
          application [ web-browsing ssl ]
          service [ application-default ]
          action allow
        Rule: block-all
          from any
          to any
          source [ any ]
          destination [ any ]
          application [ any ]
          service [ any ]
          action deny
    """
    rules: list[dict] = []
    current: dict | None = None

    def _parse_list(raw: str) -> list[str]:
        """Extract tokens from ``[ a b c ]`` or bare ``any`` style values."""
        raw = raw.strip()
        if raw.startswith("[") and raw.endswith("]"):
            raw = raw[1:-1]
        return raw.split()

    for line in output.splitlines():
        # Rule header: "Rule: <name>"
        rule_match = re.match(r"^\s*Rule\s*:\s*(.+)", line, re.IGNORECASE)
        if rule_match:
            if current is not None:
                rules.append(current)
            current = {
                "name": rule_match.group(1).strip().strip('"'),
                "from_zones": [],
                "to_zones": [],
                "sources": [],
                "destinations": [],
                "applications": [],
                "services": [],
                "action": None,
            }
            continue

        if current is None:
            continue

        # Field lines — handle both "from trust" and "from [ trust dmz ]" forms
        from_m = re.match(r"^\s+from\s+(.+)", line, re.IGNORECASE)
        if from_m:
            current["from_zones"] = _parse_list(from_m.group(1))
            continue

        to_m = re.match(r"^\s+to\s+(.+)", line, re.IGNORECASE)
        if to_m:
            current["to_zones"] = _parse_list(to_m.group(1))
            continue

        src_m = re.match(r"^\s+source\s+(.+)", line, re.IGNORECASE)
        if src_m:
            current["sources"] = _parse_list(src_m.group(1))
            continue

        dst_m = re.match(r"^\s+destination\s+(.+)", line, re.IGNORECASE)
        if dst_m:
            current["destinations"] = _parse_list(dst_m.group(1))
            continue

        app_m = re.match(r"^\s+application\s+(.+)", line, re.IGNORECASE)
        if app_m:
            current["applications"] = _parse_list(app_m.group(1))
            continue

        svc_m = re.match(r"^\s+service\s+(.+)", line, re.IGNORECASE)
        if svc_m:
            current["services"] = _parse_list(svc_m.group(1))
            continue

        act_m = re.match(r"^\s+action\s+(\S+)", line, re.IGNORECASE)
        if act_m:
            current["action"] = act_m.group(1).lower()
            continue

    if current is not None:
        rules.append(current)

    return rules


def parse_security_policy_stats(output: str) -> list[dict]:
    """Parse ``show security policy statistics`` output from a PAN-OS device.

    Each returned dict contains:

    * ``name``          – rule name
    * ``hit_count``     – number of times the rule has been matched (``int``)
    * ``last_hit``      – last hit timestamp string, or ``None``

    Returns an empty list when the output cannot be parsed.

    Example input::

        Rule Name        Hit Count   Last Hit Date
        web-access       1523        2024-03-24 06:00:00
        block-malware    45          2024-03-23 12:00:00
        allow-dns        0           never
        unused-rule      0           never
    """
    stats: list[dict] = []

    for line in output.splitlines():
        # Skip header lines
        if re.match(r"^\s*Rule\s+Name", line, re.IGNORECASE):
            continue

        m = re.match(
            r"^\s*(\S+(?:\s+\S+)*?)\s{2,}(\d+)\s+(.+)$",
            line,
        )
        if not m:
            # Try simpler two-column form (name  hit_count)
            m2 = re.match(r"^\s*(\S+(?:\s+\S+)*?)\s{2,}(\d+)\s*$", line)
            if m2:
                stats.append(
                    {
                        "name": m2.group(1).strip(),
                        "hit_count": int(m2.group(2)),
                        "last_hit": None,
                    }
                )
            continue

        last_hit_raw = m.group(3).strip()
        stats.append(
            {
                "name": m.group(1).strip(),
                "hit_count": int(m.group(2)),
                "last_hit": None if last_hit_raw.lower() == "never" else last_hit_raw,
            }
        )

    return stats


def parse_ha_state(output: str) -> dict:
    """Parse ``show high-availability state`` output from a PAN-OS device.

    Returns a dict with keys:

    * ``enabled``        – ``True`` when HA is configured
    * ``mode``           – HA mode string (e.g. ``'Active-Passive'``), or ``None``
    * ``local_state``    – local HA state (e.g. ``'active'``), or ``None``
    * ``peer_state``     – peer HA state (e.g. ``'passive'``), or ``None``
    * ``peer_ip``        – peer management IP address, or ``None``
    * ``preemptive``     – ``True`` when preemptive failover is enabled

    Returns defaults (``enabled=False``, all other fields ``None`` / ``False``)
    when the output cannot be parsed or HA is not configured.

    Example input lines::

        Group 1:
          Mode: Active-Passive
          Local state: active
          Peer state: passive
          Peer IP: 192.168.1.2
          Preemptive: no
    """
    result: dict = {
        "enabled": False,
        "mode": None,
        "local_state": None,
        "peer_state": None,
        "peer_ip": None,
        "preemptive": False,
    }

    for line in output.splitlines():
        line_s = line.strip()

        # Presence of "Group" header indicates HA is configured
        if re.match(r"^Group\s+\d+", line_s, re.IGNORECASE):
            result["enabled"] = True
            continue

        mode_m = re.match(r"^Mode\s*:\s*(.+)", line_s, re.IGNORECASE)
        if mode_m:
            result["mode"] = mode_m.group(1).strip()
            continue

        local_m = re.match(r"^Local\s+state\s*:\s*(.+)", line_s, re.IGNORECASE)
        if local_m:
            result["local_state"] = local_m.group(1).strip()
            continue

        peer_state_m = re.match(r"^Peer\s+state\s*:\s*(.+)", line_s, re.IGNORECASE)
        if peer_state_m:
            result["peer_state"] = peer_state_m.group(1).strip()
            continue

        peer_ip_m = re.match(r"^Peer\s+IP\s*:\s*(.+)", line_s, re.IGNORECASE)
        if peer_ip_m:
            result["peer_ip"] = peer_ip_m.group(1).strip()
            continue

        preempt_m = re.match(r"^Preemptive\s*:\s*(.+)", line_s, re.IGNORECASE)
        if preempt_m:
            result["preemptive"] = preempt_m.group(1).strip().lower() == "yes"
            continue

    return result
