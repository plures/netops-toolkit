"""Parsers for health-check CLI output (CPU, memory, interface errors, logs).

Supports Cisco IOS/XE/XR/NXOS and Nokia SR-OS output formats.
"""

from __future__ import annotations

import re

__all__ = [
    "parse_cpu_cisco",
    "parse_cpu_nokia",
    "parse_memory_cisco",
    "parse_memory_nokia",
    "parse_interface_errors_cisco",
    "parse_interface_errors_nokia",
    "parse_logs_cisco",
    "parse_logs_nokia",
]


# ---------------------------------------------------------------------------
# CPU parsers
# ---------------------------------------------------------------------------


def parse_cpu_cisco(output: str) -> dict:
    """Parse ``show processes cpu`` output from Cisco IOS/XE/XR.

    Returns a dict with keys:
    * ``five_seconds``  – CPU % over the last 5 seconds (``float``)
    * ``one_minute``    – CPU % over the last 1 minute (``float``)
    * ``five_minutes``  – CPU % over the last 5 minutes (``float``)

    Returns an empty dict when the output cannot be parsed.

    Example input line::

        CPU utilization for five seconds: 12%/3%; one minute: 8%; five minutes: 6%
    """
    match = re.search(
        r"five seconds:\s+(\d+(?:\.\d+)?)%[^;]*;"
        r"\s+one minute:\s+(\d+(?:\.\d+)?)%;"
        r"\s+five minutes:\s+(\d+(?:\.\d+)?)%",
        output,
    )
    if match:
        return {
            "five_seconds": float(match.group(1)),
            "one_minute": float(match.group(2)),
            "five_minutes": float(match.group(3)),
        }
    return {}


def parse_cpu_nokia(output: str) -> dict:
    """Parse ``show system cpu`` output from Nokia SR-OS.

    Returns a dict with keys:
    * ``avg``  – average CPU utilization % (``float``)
    * ``peak`` – peak CPU utilization % (``float``)

    Returns an empty dict when the output cannot be parsed.

    Example input lines::

        CPU Usage             :  5%  12%
    """
    match = re.search(r"CPU Usage\s*:\s+(\d+(?:\.\d+)?)%\s+(\d+(?:\.\d+)?)%", output)
    if match:
        return {
            "avg": float(match.group(1)),
            "peak": float(match.group(2)),
        }
    return {}


# ---------------------------------------------------------------------------
# Memory parsers
# ---------------------------------------------------------------------------


def parse_memory_cisco(output: str) -> dict:
    """Parse ``show processes memory`` output from Cisco IOS/XE.

    Returns a dict with keys:
    * ``total``       – total bytes (``int``)
    * ``used``        – used bytes (``int``)
    * ``free``        – free bytes (``int``)
    * ``utilization`` – percentage used (``float``, 0–100)

    Returns an empty dict when the output cannot be parsed.

    Example input line::

        Processor  7F2B3C18  402702336   141058576   261643760   ...
    """
    match = re.search(
        r"Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)",
        output,
    )
    if match:
        total = int(match.group(1))
        used = int(match.group(2))
        free = int(match.group(3))
        utilization = round((used / total * 100) if total else 0.0, 2)
        return {"total": total, "used": used, "free": free, "utilization": utilization}
    return {}


def parse_memory_nokia(output: str) -> dict:
    """Parse ``show system memory-pools`` output from Nokia SR-OS.

    Returns a dict with keys:
    * ``total``       – total bytes (``int``)
    * ``used``        – used bytes (``int``)
    * ``free``        – free bytes (``int``)
    * ``utilization`` – percentage used (``float``, 0–100)

    Returns an empty dict when the output cannot be parsed.

    Example input lines::

        Total In Use          :      141058576
        Total Available       :      261643760
    """
    used_match = re.search(r"Total In Use\s*:\s+(\d+)", output)
    avail_match = re.search(r"Total Available\s*:\s+(\d+)", output)
    if used_match and avail_match:
        used = int(used_match.group(1))
        free = int(avail_match.group(1))
        total = used + free
        utilization = round((used / total * 100) if total else 0.0, 2)
        return {"total": total, "used": used, "free": free, "utilization": utilization}
    return {}


# ---------------------------------------------------------------------------
# Interface error parsers
# ---------------------------------------------------------------------------


def parse_interface_errors_cisco(output: str) -> list[dict]:
    """Parse ``show interfaces`` output for error counters on Cisco IOS/XE/XR.

    Each returned dict contains:
    * ``name``          – interface name (e.g. ``'GigabitEthernet0/0'``)
    * ``input_errors``  – total input errors (``int``)
    * ``output_errors`` – total output errors (``int``)
    * ``crc``           – CRC errors (``int``)
    * ``drops``         – total input/output drops (``int``)
    * ``has_errors``    – ``True`` when any counter is non-zero

    Returns an empty list when no interfaces are parsed.
    """
    interfaces: list[dict] = []
    current: dict | None = None

    for line in output.splitlines():
        # New interface header: "GigabitEthernet0/0 is up, ..."
        iface_match = re.match(r"^(\S+) is (?:up|down|administratively down)", line)
        if iface_match:
            if current is not None:
                current["has_errors"] = _has_errors(current)
                interfaces.append(current)
            current = {
                "name": iface_match.group(1),
                "input_errors": 0,
                "output_errors": 0,
                "crc": 0,
                "drops": 0,
            }
            continue

        if current is None:
            continue

        # Input errors: "0 input errors, 0 CRC, 0 frame, ..."
        in_err = re.search(r"(\d+) input errors", line)
        if in_err:
            current["input_errors"] = int(in_err.group(1))
        crc_match = re.search(r"(\d+) CRC", line)
        if crc_match:
            current["crc"] = int(crc_match.group(1))

        # Output errors: "0 output errors, 0 collisions, ..."
        out_err = re.search(r"(\d+) output errors", line)
        if out_err:
            current["output_errors"] = int(out_err.group(1))

        # Input drops: "0 input drops" or "Input queue: 0/75/0/0 (size/max/drops/flushes)"
        in_drops = re.search(r"(\d+) input drops", line)
        if in_drops:
            current["drops"] += int(in_drops.group(1))

        # Output drops: "0 output drops"
        out_drops = re.search(r"(\d+) output drops", line)
        if out_drops:
            current["drops"] += int(out_drops.group(1))

    if current is not None:
        current["has_errors"] = _has_errors(current)
        interfaces.append(current)

    return interfaces


def _has_errors(iface: dict) -> bool:
    return any(iface.get(k, 0) > 0 for k in ("input_errors", "output_errors", "crc", "drops"))


def parse_interface_errors_nokia(output: str) -> list[dict]:
    """Parse ``show port detail`` output for error counters on Nokia SR-OS.

    Each returned dict contains:
    * ``name``          – port identifier (e.g. ``'1/1/1'``)
    * ``input_errors``  – total input errors (``int``)
    * ``output_errors`` – total output errors (``int``)
    * ``crc``           – CRC/alignment errors (``int``)
    * ``drops``         – ingress/egress drops (``int``)
    * ``has_errors``    – ``True`` when any counter is non-zero

    Returns an empty list when no ports are parsed.
    """
    interfaces: list[dict] = []
    current: dict | None = None

    for line in output.splitlines():
        # Port header: "Port 1/1/1"
        port_match = re.match(r"^Port\s+(\d+/\d+/\S+)", line)
        if port_match:
            if current is not None:
                current["has_errors"] = _has_errors(current)
                interfaces.append(current)
            current = {
                "name": port_match.group(1),
                "input_errors": 0,
                "output_errors": 0,
                "crc": 0,
                "drops": 0,
            }
            continue

        if current is None:
            continue

        # Nokia SR-OS counter lines (various formats)
        crc_match = re.search(r"CRC/Align Errors\s*:\s+(\d+)", line, re.IGNORECASE)
        if crc_match:
            current["crc"] = int(crc_match.group(1))

        in_err = re.search(r"Input Errors\s*:\s+(\d+)", line, re.IGNORECASE)
        if in_err:
            current["input_errors"] = int(in_err.group(1))

        out_err = re.search(r"Output Errors\s*:\s+(\d+)", line, re.IGNORECASE)
        if out_err:
            current["output_errors"] = int(out_err.group(1))

        drops_match = re.search(r"(?:Ingress|Egress)\s+Drop\w*\s*:\s+(\d+)", line, re.IGNORECASE)
        if drops_match:
            current["drops"] += int(drops_match.group(1))

    if current is not None:
        current["has_errors"] = _has_errors(current)
        interfaces.append(current)

    return interfaces


# ---------------------------------------------------------------------------
# Log parsers
# ---------------------------------------------------------------------------

# Syslog severity levels 0–3 are considered critical/major for alerting.
# 0=emergency, 1=alert, 2=critical, 3=error
_CISCO_LOG_PATTERN = re.compile(
    r"%(?P<facility>[A-Z0-9_-]+)-(?P<severity>[0-3])-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<message>.*)"
)


def parse_logs_cisco(output: str) -> list[dict]:
    """Scan ``show logging`` output for severity 0–3 (critical/major) events.

    Each returned dict contains:
    * ``facility``  – syslog facility (e.g. ``'SYS'``)
    * ``severity``  – numeric severity 0–3 (``int``)
    * ``mnemonic``  – syslog mnemonic (e.g. ``'MALLOCFAIL'``)
    * ``message``   – event description

    Returns an empty list when no matching events are found.
    """
    events: list[dict] = []
    for line in output.splitlines():
        match = _CISCO_LOG_PATTERN.search(line)
        if match:
            events.append(
                {
                    "facility": match.group("facility"),
                    "severity": int(match.group("severity")),
                    "mnemonic": match.group("mnemonic"),
                    "message": match.group("message").strip(),
                }
            )
    return events


_NOKIA_LOG_SEVERITY = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T[\d:]+(?:\.\d+)?Z?)\s+"
    r"(?P<severity>CRITICAL|MAJOR)\s+"
    r"(?P<subject>\S+)\s+"
    r"(?P<message>.*)"
)


def parse_logs_nokia(output: str) -> list[dict]:
    """Scan Nokia SR-OS log output for CRITICAL and MAJOR severity events.

    Each returned dict contains:
    * ``timestamp`` – event timestamp string
    * ``severity``  – ``'CRITICAL'`` or ``'MAJOR'``
    * ``subject``   – log subject/application
    * ``message``   – event description

    Returns an empty list when no matching events are found.
    """
    events: list[dict] = []
    for line in output.splitlines():
        match = _NOKIA_LOG_SEVERITY.search(line)
        if match:
            events.append(
                {
                    "timestamp": match.group("timestamp"),
                    "severity": match.group("severity"),
                    "subject": match.group("subject"),
                    "message": match.group("message").strip(),
                }
            )
    return events
