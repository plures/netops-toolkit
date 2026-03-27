"""Parsers for BGP CLI output.

Supports Cisco IOS/IOS-XE (``show ip bgp summary``) and
Cisco IOS-XR (``show bgp summary``).

Nokia SR-OS BGP output is handled by
:func:`netops.parsers.nokia_sros.parse_bgp_summary`.
"""

from __future__ import annotations

import re

__all__ = ["parse_bgp_summary_cisco", "updown_to_seconds"]


def parse_bgp_summary_cisco(output: str) -> list[dict]:
    """Parse ``show ip bgp summary`` / ``show bgp summary`` output.

    Handles Cisco IOS, IOS-XE, and IOS-XR formats.

    Returns
    -------
    list
        List of per-peer dicts. Returns an empty list when the output cannot be parsed.

    Each returned dict contains:

    * ``neighbor``          – peer IPv4/IPv6 address
    * ``peer_as``           – remote AS number (``int``)
    * ``msg_rcvd``          – BGP messages received (``int``)
    * ``msg_sent``          – BGP messages sent (``int``)
    * ``up_down``           – session uptime or time-since-reset string
    * ``state``             – ``'Established'`` or FSM state string
                              (e.g. ``'Active'``, ``'Idle'``, ``'Connect'``)
    * ``prefixes_received`` – prefixes received (``int``) when
                              ``state == 'Established'``, otherwise ``None``
    """
    peers: list[dict] = []
    in_data = False

    for line in output.splitlines():
        # The header line "Neighbor  V  AS …" marks the start of peer data.
        if re.match(r"^Neighbor\s+V\s+AS\s+", line):
            in_data = True
            continue

        if not in_data:
            continue

        stripped = line.strip()
        if not stripped:
            continue

        # Data line format (IOS/XE):
        #   <neighbor>  <V>  <AS>  <MsgRcvd>  <MsgSent>  <TblVer>  <InQ>  <OutQ>
        #   <Up/Down>  <State/PfxRcd>
        match = re.match(
            r"^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)",
            line,
        )
        if match:
            state_or_pfx = match.group(7)
            # A plain integer in the last column means the session is Established
            # and the value is the received-prefix count.
            if re.match(r"^\d+$", state_or_pfx):
                state: str = "Established"
                prefixes_received: int | None = int(state_or_pfx)
            else:
                state = state_or_pfx
                prefixes_received = None

            peers.append(
                {
                    "neighbor": match.group(1),
                    "peer_as": int(match.group(3)),
                    "msg_rcvd": int(match.group(4)),
                    "msg_sent": int(match.group(5)),
                    "up_down": match.group(6),
                    "state": state,
                    "prefixes_received": prefixes_received,
                }
            )

    return peers


def updown_to_seconds(updown: str) -> int | None:
    """Convert a BGP session up/down time string to total seconds.

    Handles the most common Cisco and Nokia SR-OS formats:

    * ``HH:MM:SS``  — e.g. ``'00:15:30'``
    * ``XdYh``      — e.g. ``'2d03h'``, ``'1d02h'``
    * ``XwYd``      — e.g. ``'1w2d'``
    * ``XhYm``      — Nokia SR-OS, e.g. ``'00h15m'``
    * ``never``     — session was never established → ``None``

    Returns
    -------
    int or None
        Total seconds as an integer, or ``None`` when the string is
        ``'never'`` or cannot be parsed.
    """
    if not updown or updown.lower() == "never":
        return None

    # HH:MM:SS
    m = re.match(r"^(\d+):(\d+):(\d+)$", updown)
    if m:
        return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))

    # XdYh  (e.g. "2d03h")
    m = re.match(r"^(\d+)d(\d+)h$", updown)
    if m:
        return int(m.group(1)) * 86400 + int(m.group(2)) * 3600

    # XwYd  (e.g. "1w2d")
    m = re.match(r"^(\d+)w(\d+)d$", updown)
    if m:
        return int(m.group(1)) * 604800 + int(m.group(2)) * 86400

    # XhYm  (Nokia SR-OS, e.g. "00h15m")
    m = re.match(r"^(\d+)h(\d+)m$", updown)
    if m:
        return int(m.group(1)) * 3600 + int(m.group(2)) * 60

    return None
