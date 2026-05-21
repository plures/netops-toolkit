"""Community string registry — try multiple SNMP communities, learn from SSH.

The registry stores a prioritized list of SNMP community strings and
per-device overrides. During scanning:

1. For unknown devices: try all strings from the registry until one works
2. When SSH is available: extract community strings from running config
3. The command that works tells us the device family (bonus identification)

Storage: JSON file at NETOPS_COMMUNITY_REGISTRY (default: communities.json)

Structure:
{
    "strings": ["public", "private", "Pr1vat3!", "ro-community", ...],
    "devices": {
        "10.0.0.1": {"community": "Pr1vat3!", "vendor": "brocade_fastiron"},
        "10.0.0.2": {"community": "public", "vendor": "cisco_ios"}
    }
}
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

REGISTRY_FILE = Path(os.environ.get("NETOPS_COMMUNITY_REGISTRY", "communities.json"))

# Commands to extract SNMP community strings from running config, by vendor.
# The key insight: if a command works, we know the vendor family.
_COMMUNITY_EXTRACT_COMMANDS: dict[str, list[str]] = {
    "cisco_ios": [
        "show running-config | include snmp-server community",
    ],
    "cisco_nxos": [
        "show running-config | include snmp-server community",
    ],
    "cisco_xe": [
        "show running-config | include snmp-server community",
    ],
    "cisco_xr": [
        "show running-config snmp-server | include community",
    ],
    "brocade_fastiron": [
        "show running-config | include snmp-server community",
    ],
    "brocade_nos": [
        "show running-config | include snmp-server community",
    ],
    "juniper_junos": [
        "show configuration snmp | display set | match community",
    ],
    "arista_eos": [
        "show running-config section snmp | include community",
    ],
    "nokia_sros": [
        "admin display-config | match community",
    ],
}

# Parse patterns for extracting community strings from output
_COMMUNITY_PATTERNS: dict[str, str] = {
    "cisco_ios": r"snmp-server community (\S+)",
    "cisco_nxos": r"snmp-server community (\S+)",
    "cisco_xe": r"snmp-server community (\S+)",
    "cisco_xr": r"community (\S+)",
    "brocade_fastiron": r"snmp-server community (\S+)",
    "brocade_nos": r"snmp-server community (\S+)",
    "juniper_junos": r"community (\S+)",
    "arista_eos": r"community (\S+)",
    "nokia_sros": r"community \"?(\S+?)\"?",
}


class CommunityRegistry:
    """Manages a prioritized list of SNMP community strings with per-device cache."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else REGISTRY_FILE
        self._data: dict = {"strings": ["public"], "devices": {}}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Could not load community registry: {e}")

    def save(self) -> None:
        """Persist registry to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2))

    @property
    def strings(self) -> list[str]:
        """All known community strings, ordered by priority."""
        return self._data.get("strings", ["public"])

    @strings.setter
    def strings(self, value: list[str]) -> None:
        self._data["strings"] = list(value)

    def add_string(self, community: str) -> None:
        """Add a community string to the registry (deduplicated)."""
        if community not in self._data["strings"]:
            self._data["strings"].append(community)
            self.save()

    def get_device(self, host: str) -> dict | None:
        """Get cached community + vendor for a device."""
        return self._data.get("devices", {}).get(host)

    def set_device(self, host: str, community: str, vendor: str | None = None) -> None:
        """Cache the working community string (and optionally vendor) for a device."""
        self._data.setdefault("devices", {})[host] = {
            "community": community,
            "vendor": vendor,
        }
        # Also ensure the string is in our global list
        if community not in self._data["strings"]:
            self._data["strings"].append(community)
        self.save()

    def remove_device(self, host: str) -> None:
        """Remove cached entry for a device."""
        self._data.get("devices", {}).pop(host, None)
        self.save()

    def get_strings_for_host(self, host: str) -> list[str]:
        """Get ordered list of communities to try for a host.

        If we have a cached hit for this host, try that first.
        Otherwise return the full registry list.
        """
        cached = self.get_device(host)
        if cached and cached.get("community"):
            # Put the known-good one first, then the rest
            known = cached["community"]
            rest = [s for s in self.strings if s != known]
            return [known] + rest
        return list(self.strings)


def try_communities(
    host: str,
    registry: CommunityRegistry,
    snmp_port: int = 161,
    timeout: int = 2,
) -> tuple[str | None, str | None]:
    """Try all community strings from the registry against a host.

    Returns:
        (working_community, vendor) or (None, None) if none work.
    """
    import asyncio

    async def _probe(community: str) -> tuple[str | None, str | None]:
        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                CommunityData, ContextData, ObjectIdentity,
                ObjectType, SnmpEngine, UdpTransportTarget, get_cmd,
            )
            engine = SnmpEngine()
            transport = await UdpTransportTarget.create((host, snmp_port), timeout=timeout, retries=0)
            # Get sysDescr
            err_ind, err_st, _, var_binds = await get_cmd(
                engine, CommunityData(community, mpModel=1), transport,
                ContextData(), ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
            )
            if err_ind or err_st:
                return None, None
            sys_descr = str(var_binds[0][1]) if var_binds else ""
            # Get sysObjectID
            err_ind, err_st, _, var_binds = await get_cmd(
                engine, CommunityData(community, mpModel=1), transport,
                ContextData(), ObjectType(ObjectIdentity("1.3.6.1.2.1.1.2.0")),
            )
            sys_obj_id = str(var_binds[0][1]) if (not err_ind and not err_st and var_binds) else ""
            if sys_descr or sys_obj_id:
                from netops.inventory.scan import identify_vendor
                vendor = identify_vendor(sys_descr, sys_obj_id)
                return community, vendor
        except Exception:
            pass
        return None, None

    for community in registry.get_strings_for_host(host):
        try:
            result = asyncio.run(_probe(community))
            if result[0]:
                logger.info(f"  {host}: community '{community}' works → vendor={result[1]}")
                registry.set_device(host, community, result[1])
                return result
        except Exception:
            continue

    return None, None


def extract_communities_via_ssh(
    host: str,
    username: str,
    password: str,
    known_vendor: str | None = None,
    timeout: int = 15,
) -> tuple[list[str], str | None]:
    """SSH into a device and extract SNMP community strings from running config.

    Tries vendor-specific commands. The command that works also identifies
    the device family.

    Returns:
        (list_of_communities, detected_vendor) or ([], None) on failure.
    """
    import re

    from netops.core.connection import ConnectionParams, DeviceConnection

    # If vendor is known, try that first; otherwise try all
    if known_vendor and known_vendor != "unknown":
        vendors_to_try = [known_vendor]
    else:
        vendors_to_try = list(_COMMUNITY_EXTRACT_COMMANDS.keys())

    for vendor in vendors_to_try:
        commands = _COMMUNITY_EXTRACT_COMMANDS.get(vendor, [])
        pattern = _COMMUNITY_PATTERNS.get(vendor, r"community (\S+)")

        for cmd in commands:
            try:
                params = ConnectionParams(
                    host=host,
                    username=username,
                    password=password,
                    device_type=vendor,
                    timeout=timeout,
                )
                with DeviceConnection(params) as conn:
                    output = conn.send(cmd)
                    if output and output.strip():
                        # Parse communities from output
                        communities = re.findall(pattern, output)
                        if communities:
                            logger.info(
                                f"  {host}: extracted {len(communities)} community string(s) "
                                f"via {vendor} cmd: {cmd}"
                            )
                            return communities, vendor
            except Exception as e:
                logger.debug(f"  {host}: vendor={vendor} cmd='{cmd}' failed: {e}")
                continue

    return [], None
