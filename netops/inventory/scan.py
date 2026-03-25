"""
Subnet scanner — discover devices via SNMP/CDP/LLDP/ping sweep.

Usage:
    python -m netops.inventory.scan --subnet 10.0.0.0/24 --community public
    python -m netops.inventory.scan --subnet 10.0.0.0/24 --output fragment.json
    python -m netops.inventory.scan --subnet 10.0.0.0/24 --merge existing.yaml
    python -m netops.inventory.scan --csv hosts.csv --deep --user admin
    python -m netops.inventory.scan --hosts-file ips.txt --deep --user admin
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import csv
import ipaddress
import io
import json
import logging
import platform
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Standard SNMP OIDs (RFC 1213 / MIB-II system group)
# ---------------------------------------------------------------------------
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_OBJ_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

# CDP OIDs (Cisco proprietary — CISCO-CDP-MIB, enterprise 9.9.23)
OID_CDP_CACHE_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
OID_CDP_CACHE_ADDRESS = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
OID_CDP_CACHE_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

# LLDP OIDs (LLDP-MIB / IEEE 802.1AB)
OID_LLDP_REM_CHASSIS_ID = "1.3.6.1.2.1.127.1.4.1.5"
OID_LLDP_REM_SYS_NAME = "1.3.6.1.2.1.127.1.4.1.9"
OID_LLDP_REM_SYS_DESC = "1.3.6.1.2.1.127.1.4.1.10"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Scan result for a single host."""

    host: str
    reachable: bool
    hostname: Optional[str] = None
    sys_descr: Optional[str] = None
    sys_obj_id: Optional[str] = None
    vendor: Optional[str] = None
    location: Optional[str] = None
    cdp_neighbors: list[dict] = field(default_factory=list)
    lldp_neighbors: list[dict] = field(default_factory=list)
    error: Optional[str] = None
    # Deep-scan fields (populated via SSH when --deep is used)
    version: Optional[str] = None
    model: Optional[str] = None
    serial: Optional[str] = None
    uptime: Optional[str] = None
    image: Optional[str] = None
    hardware_revision: Optional[str] = None
    total_memory: Optional[str] = None
    free_memory: Optional[str] = None
    reload_reason: Optional[str] = None
    mac_address: Optional[str] = None
    config_register: Optional[str] = None
    cpu_type: Optional[str] = None
    flash_size: Optional[str] = None
    domain_name: Optional[str] = None
    interface_count: Optional[str] = None

    def to_inventory_entry(self) -> dict:
        """Convert to an inventory device dict (compatible with core.Inventory)."""
        entry: dict = {
            "host": self.host,
            "vendor": self.vendor or "unknown",
        }
        if self.location:
            entry["site"] = self.location
        # Deep-scan fields
        _optional = {
            "version": self.version,
            "model": self.model,
            "serial": self.serial,
            "uptime": self.uptime,
            "image": self.image,
            "hardware_revision": self.hardware_revision,
            "total_memory": self.total_memory,
            "free_memory": self.free_memory,
            "reload_reason": self.reload_reason,
            "mac_address": self.mac_address,
            "config_register": self.config_register,
            "cpu_type": self.cpu_type,
            "flash_size": self.flash_size,
            "domain_name": self.domain_name,
            "interface_count": self.interface_count,
        }
        for k, v in _optional.items():
            if v is not None:
                entry[k] = v
        if self.hostname:
            entry["hostname"] = self.hostname
        if self.sys_descr:
            entry.setdefault("tags", {})["sys_descr"] = self.sys_descr
        return entry


# ---------------------------------------------------------------------------
# Ping sweep
# ---------------------------------------------------------------------------


def ping_host(host: str, timeout: int = 1, count: int = 1) -> bool:
    """Return True if *host* responds to ICMP ping."""
    is_windows = platform.system().lower() == "windows"
    count_flag = "-n" if is_windows else "-c"
    timeout_flag = "-w" if is_windows else "-W"
    # On Windows, `ping -w` expects milliseconds; elsewhere, `ping -W` expects seconds.
    ping_timeout = timeout * 1000 if is_windows else timeout
    cmd = ["ping", count_flag, str(count), timeout_flag, str(ping_timeout), host]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def ping_sweep(
    subnet: str,
    max_workers: int = 50,
    timeout: int = 1,
) -> list[str]:
    """
    Ping sweep a subnet and return a sorted list of reachable IP address strings.

    Args:
        subnet: CIDR notation subnet (e.g. ``"10.0.0.0/24"``).
        max_workers: Thread pool size for concurrent pings.
        timeout: Per-host ping timeout in seconds.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())
    logger.info("Ping sweep of %s (%d hosts, %d workers)", subnet, len(hosts), max_workers)

    reachable: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_host, str(h), timeout): str(h) for h in hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                if future.result():
                    reachable.append(host)
                    logger.debug("%s is reachable", host)
            except Exception as exc:
                logger.warning("Ping check for %s raised: %s", host, exc)

    return sorted(reachable, key=lambda h: ipaddress.ip_address(h))


# ---------------------------------------------------------------------------
# SNMP helpers (asyncio — requires pysnmp >= 7.0)
# ---------------------------------------------------------------------------


def _require_pysnmp() -> None:
    """Raise a helpful ImportError if pysnmp is not installed."""
    try:
        import pysnmp.hlapi.v3arch.asyncio  # noqa: F401
    except ImportError:
        raise ImportError(
            "pysnmp is required for SNMP discovery. "
            "Install it with: pip install 'netops-toolkit[snmp]'"
        )


async def _snmp_get_async(
    engine: Any,
    host: str,
    oid: str,
    community: str,
    port: int,
    timeout: int,
) -> Optional[str]:
    """Async SNMP GET for a single OID. Returns the string value or ``None``."""
    from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore[import]
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        UdpTransportTarget,
        get_cmd,
    )

    transport = await UdpTransportTarget.create((host, port), timeout=timeout, retries=1)
    error_indication, error_status, _, var_binds = await get_cmd(
        engine,
        CommunityData(community, mpModel=1),
        transport,
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )
    if error_indication or error_status:
        return None
    for var_bind in var_binds:
        return str(var_bind[1])
    return None


async def _snmp_walk_async(
    engine: Any,
    host: str,
    oid: str,
    community: str,
    port: int,
    timeout: int,
) -> list[tuple[str, str]]:
    """
    Async SNMP WALK over an OID subtree.

    Returns a list of ``(oid_suffix, value)`` tuples where *oid_suffix* is
    the index portion after the base *oid*.
    """
    from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore[import]
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        UdpTransportTarget,
        walk_cmd,
    )

    transport = await UdpTransportTarget.create((host, port), timeout=timeout, retries=1)
    results: list[tuple[str, str]] = []
    async for error_indication, error_status, _, var_binds in walk_cmd(
        engine,
        CommunityData(community, mpModel=1),
        transport,
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    ):
        if error_indication or error_status:
            break
        for var_bind in var_binds:
            full_oid = str(var_bind[0])
            value = str(var_bind[1])
            suffix = full_oid[len(oid):].lstrip(".")
            results.append((suffix, value))
    return results


# ---------------------------------------------------------------------------
# Vendor identification
# ---------------------------------------------------------------------------


def identify_vendor(sys_descr: str, sys_obj_id: str = "") -> str:
    """
    Map *sysDescr* / *sysObjectID* to a Netmiko-compatible vendor string.

    Returns one of: ``cisco_ios``, ``cisco_xe``, ``cisco_xr``, ``cisco_nxos``,
    ``nokia_sros``, ``nokia_srl``, ``juniper_junos``, ``arista_eos``,
    ``brocade_fastiron``, ``brocade_nos``, or ``"unknown"``.
    """
    descr_lower = sys_descr.lower()

    if "ios xe" in descr_lower or "ios-xe" in descr_lower:
        return "cisco_xe"
    if "ios xr" in descr_lower:
        return "cisco_xr"
    if "nx-os" in descr_lower or "nxos" in descr_lower:
        return "cisco_nxos"
    if "cisco ios" in descr_lower:
        return "cisco_ios"
    if "nokia" in descr_lower and "srl" in descr_lower:
        return "nokia_srl"
    if "nokia" in descr_lower or "timos" in descr_lower:
        return "nokia_sros"
    if "juniper" in descr_lower or "junos" in descr_lower:
        return "juniper_junos"
    if "arista" in descr_lower:
        return "arista_eos"
    if "brocade network os" in descr_lower or "network os" in descr_lower:
        return "brocade_nos"
    if "brocade" in descr_lower or "foundry" in descr_lower or "fastiron" in descr_lower:
        return "brocade_fastiron"
    if "cisco" in descr_lower:
        return "cisco_ios"

    # Fall back to enterprise OID prefix
    if sys_obj_id:
        if ".1.3.6.1.4.1.9." in sys_obj_id:  # Cisco
            return "cisco_ios"
        if ".1.3.6.1.4.1.6527." in sys_obj_id:  # Nokia / Alcatel-Lucent SR OS
            return "nokia_sros"
        if ".1.3.6.1.4.1.2636." in sys_obj_id:  # Juniper
            return "juniper_junos"
        if ".1.3.6.1.4.1.30065." in sys_obj_id:  # Arista
            return "arista_eos"
        if ".1.3.6.1.4.1.1991." in sys_obj_id:  # Foundry Networks / Brocade FastIron
            return "brocade_fastiron"
        if ".1.3.6.1.4.1.1588." in sys_obj_id:  # Brocade Communications (NOS/FOS)
            return "brocade_nos"

    return "unknown"


# ---------------------------------------------------------------------------
# Per-host async SNMP scan
# ---------------------------------------------------------------------------


async def _scan_host_async(
    engine: Any,
    host: str,
    community: str,
    snmp_port: int,
    snmp_timeout: int,
) -> ScanResult:
    """Async: identify one reachable host via SNMP and discover CDP/LLDP neighbors."""
    result = ScanResult(host=host, reachable=True)

    # ---- System MIB (RFC 1213) ----
    sys_descr = await _snmp_get_async(engine, host, OID_SYS_DESCR, community, snmp_port, snmp_timeout)
    sys_name = await _snmp_get_async(engine, host, OID_SYS_NAME, community, snmp_port, snmp_timeout)
    sys_obj_id = await _snmp_get_async(engine, host, OID_SYS_OBJ_ID, community, snmp_port, snmp_timeout)
    sys_location = await _snmp_get_async(
        engine, host, OID_SYS_LOCATION, community, snmp_port, snmp_timeout
    )

    result.sys_descr = sys_descr
    result.sys_obj_id = sys_obj_id
    result.location = sys_location

    if sys_descr:
        result.vendor = identify_vendor(sys_descr, sys_obj_id or "")
    if sys_name:
        result.hostname = sys_name.split(".")[0]  # strip domain part

    # ---- CDP neighbors (Cisco-proprietary) ----
    try:
        device_ids = dict(
            await _snmp_walk_async(engine, host, OID_CDP_CACHE_DEVICE_ID, community, snmp_port, snmp_timeout)
        )
        platforms = dict(
            await _snmp_walk_async(engine, host, OID_CDP_CACHE_PLATFORM, community, snmp_port, snmp_timeout)
        )
        addresses = dict(
            await _snmp_walk_async(engine, host, OID_CDP_CACHE_ADDRESS, community, snmp_port, snmp_timeout)
        )
        for idx, device_id in device_ids.items():
            result.cdp_neighbors.append(
                {
                    "device_id": device_id,
                    "platform": platforms.get(idx, ""),
                    "address": addresses.get(idx, ""),
                    "protocol": "cdp",
                }
            )
    except Exception as exc:
        logger.debug("CDP walk failed for %s: %s", host, exc)

    # ---- LLDP neighbors (IEEE 802.1AB) ----
    try:
        lldp_sys_names = dict(
            await _snmp_walk_async(engine, host, OID_LLDP_REM_SYS_NAME, community, snmp_port, snmp_timeout)
        )
        lldp_sys_descs = dict(
            await _snmp_walk_async(engine, host, OID_LLDP_REM_SYS_DESC, community, snmp_port, snmp_timeout)
        )
        chassis_ids = dict(
            await _snmp_walk_async(
                engine, host, OID_LLDP_REM_CHASSIS_ID, community, snmp_port, snmp_timeout
            )
        )
        all_keys = set(lldp_sys_names) | set(lldp_sys_descs) | set(chassis_ids)
        for idx in all_keys:
            result.lldp_neighbors.append(
                {
                    "sys_name": lldp_sys_names.get(idx, ""),
                    "sys_desc": lldp_sys_descs.get(idx, ""),
                    "chassis_id": chassis_ids.get(idx, ""),
                    "protocol": "lldp",
                }
            )
    except Exception as exc:
        logger.debug("LLDP walk failed for %s: %s", host, exc)

    return result


# ---------------------------------------------------------------------------
# Full subnet scan (async core)
# ---------------------------------------------------------------------------


async def _scan_subnet_async(
    subnet: str,
    community: str,
    snmp_port: int,
    snmp_timeout: int,
    ping_workers: int,
    ping_timeout: int,
    snmp_concurrency: int,
    skip_ping: bool,
    skip_snmp: bool,
) -> list[ScanResult]:
    """Async implementation of the full subnet scan pipeline."""
    # Ping sweep (blocking subprocess calls) runs in a thread pool
    if skip_ping:
        network = ipaddress.ip_network(subnet, strict=False)
        reachable_hosts = [str(h) for h in network.hosts()]
    else:
        loop = asyncio.get_event_loop()
        reachable_hosts = await loop.run_in_executor(
            None,
            lambda: ping_sweep(subnet, max_workers=ping_workers, timeout=ping_timeout),
        )

    logger.info("Ping sweep found %d reachable hosts in %s", len(reachable_hosts), subnet)

    if not reachable_hosts or skip_snmp:
        return [ScanResult(host=h, reachable=True) for h in reachable_hosts]

    _require_pysnmp()

    from pysnmp.hlapi.v3arch.asyncio import SnmpEngine  # type: ignore[import]

    engine = SnmpEngine()
    sem = asyncio.Semaphore(snmp_concurrency)

    async def bounded_scan(host: str) -> ScanResult:
        """Scan a single host, respecting the global SNMP concurrency semaphore."""
        async with sem:
            try:
                return await _scan_host_async(engine, host, community, snmp_port, snmp_timeout)
            except Exception as exc:
                logger.warning("SNMP scan failed for %s: %s", host, exc)
                return ScanResult(host=host, reachable=True, error=str(exc))

    # Use a worker-queue pattern to avoid creating one coroutine per host at once.
    queue: asyncio.Queue[Optional[str]] = asyncio.Queue()
    for host in reachable_hosts:
        await queue.put(host)

    results: list[ScanResult] = []

    async def worker() -> None:
        """Async queue worker that processes hosts from the scan queue until it receives a sentinel."""
        while True:
            host = await queue.get()
            if host is None:
                queue.task_done()
                break
            try:
                result = await bounded_scan(host)
                results.append(result)
            finally:
                queue.task_done()

    num_workers = min(snmp_concurrency, len(reachable_hosts)) or 1
    workers = [asyncio.create_task(worker()) for _ in range(num_workers)]

    # Add sentinel values to signal workers to exit once the queue is drained.
    for _ in range(num_workers):
        await queue.put(None)

    await queue.join()
    await asyncio.gather(*workers)
    engine.close_dispatcher()

    return sorted(results, key=lambda r: ipaddress.ip_address(r.host))


# ---------------------------------------------------------------------------
# Public synchronous API
# ---------------------------------------------------------------------------


def scan_subnet(
    subnet: str,
    community: str = "public",
    snmp_port: int = 161,
    snmp_timeout: int = 2,
    ping_workers: int = 50,
    ping_timeout: int = 1,
    snmp_concurrency: int = 10,
    skip_ping: bool = False,
    skip_snmp: bool = False,
) -> list[ScanResult]:
    """
    Full subnet scan: ping sweep → SNMP identification → CDP/LLDP topology.

    Args:
        subnet: CIDR notation subnet (e.g. ``"10.0.0.0/24"``).
        community: SNMPv2c community string.
        snmp_port: SNMP UDP port (default 161).
        snmp_timeout: Per-host SNMP timeout in seconds.
        ping_workers: Ping sweep thread-pool size.
        ping_timeout: Per-host ping timeout in seconds.
        snmp_concurrency: Max simultaneous SNMP sessions.
        skip_ping: Skip ping sweep and probe all addresses in the subnet.
        skip_snmp: Skip SNMP — perform a ping-sweep only.

    Returns:
        Sorted list of :class:`ScanResult` objects (one per reachable host).

    Requires:
        ``pysnmp >= 7.0``. Install with ``pip install 'netops-toolkit[snmp]'``.
    """
    return asyncio.run(
        _scan_subnet_async(
            subnet=subnet,
            community=community,
            snmp_port=snmp_port,
            snmp_timeout=snmp_timeout,
            ping_workers=ping_workers,
            ping_timeout=ping_timeout,
            snmp_concurrency=snmp_concurrency,
            skip_ping=skip_ping,
            skip_snmp=skip_snmp,
        )
    )


def results_to_inventory_fragment(results: list[ScanResult]) -> dict:
    """
    Convert scan results to an inventory fragment (``{"devices": {...}}`` dict).

    The fragment is compatible with :class:`netops.core.Inventory` and can be
    written directly as a JSON file or merged into an existing inventory.
    """
    devices: dict = {}
    for r in results:
        if not r.reachable:
            continue
        name = r.hostname or r.host
        entry = r.to_inventory_entry()

        # Encode CDP/LLDP topology as a comma-separated ``neighbors`` tag
        neighbors: list[str] = []
        for n in r.cdp_neighbors:
            if n.get("device_id"):
                neighbors.append(f"cdp:{n['device_id']}")
        for n in r.lldp_neighbors:
            if n.get("sys_name"):
                neighbors.append(f"lldp:{n['sys_name']}")
        if neighbors:
            entry.setdefault("tags", {})["neighbors"] = ",".join(neighbors)

        devices[name] = entry
    return {"devices": devices}


def _load_yaml(path: Path) -> dict:
    """Load a YAML file, raising a helpful ImportError if PyYAML is missing."""
    try:
        import yaml  # type: ignore[import]

        return yaml.safe_load(path.read_text()) or {}
    except ImportError:
        raise ImportError("PyYAML required for YAML inventory: pip install pyyaml")


def _dump_yaml(path: Path, data: dict) -> None:
    """Write *data* to *path* as YAML, raising a helpful ImportError if PyYAML is missing."""
    try:
        import yaml  # type: ignore[import]

        path.write_text(yaml.dump(data, default_flow_style=False))
    except ImportError:
        raise ImportError("PyYAML required for YAML output: pip install pyyaml")


def merge_inventory(existing_path: str, fragment: dict) -> dict:
    """
    Merge a scan fragment into an existing inventory file.

    New devices are added. Existing entries are updated only where the
    current value is ``None``, ``"unknown"``, or ``""`` — manually-set
    values are never overwritten.

    Args:
        existing_path: Path to an existing YAML or JSON inventory file.
            If the file does not exist, an empty inventory is used as the base.
        fragment: Inventory fragment produced by :func:`results_to_inventory_fragment`.

    Returns:
        Merged inventory dict.
    """
    path = Path(existing_path)
    if path.exists():
        if path.suffix in (".yaml", ".yml"):
            existing = _load_yaml(path)
        else:
            existing = json.loads(path.read_text())
    else:
        existing = {}

    if existing.get("devices") is None:
        existing["devices"] = {}
    else:
        existing.setdefault("devices", {})
    for hostname, info in fragment.get("devices", {}).items():
        if hostname not in existing["devices"]:
            existing["devices"][hostname] = info
            logger.info("Added new device: %s", hostname)
        else:
            existing_entry = existing["devices"][hostname]
            for key, value in info.items():
                # Special-case dict-valued keys like "tags" to deep-merge
                # subkeys while preserving any existing non-placeholder values.
                if key == "tags" and isinstance(value, dict):
                    existing_tags = existing_entry.get("tags")
                    if isinstance(existing_tags, dict):
                        for tag_key, tag_value in value.items():
                            if (
                                tag_key not in existing_tags
                                or existing_tags[tag_key] in (None, "unknown", "")
                            ):
                                existing_tags[tag_key] = tag_value
                    elif existing_tags in (None, "unknown", "") or key not in existing_entry:
                        # If the existing "tags" value is a placeholder or missing,
                        # replace it entirely with the discovered tags dict.
                        existing_entry["tags"] = value
                    # If existing_tags is a non-dict, non-placeholder value, leave it as-is.
                else:
                    if key not in existing_entry or existing_entry[key] in (None, "unknown", ""):
                        existing_entry[key] = value
            logger.debug("Updated existing device: %s", hostname)

    return existing


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Deep scan — SSH login to enrich inventory with vendor, version, serial, model
# ---------------------------------------------------------------------------

# Vendor-specific show commands for deep scan enrichment
_DEEP_COMMANDS: dict[str, dict[str, str]] = {
    "cisco_ios": {
        "version": "show version",
        "inventory": "show inventory",
    },
    "cisco_nxos": {
        "version": "show version",
        "inventory": "show inventory",
    },
    "cisco_xe": {
        "version": "show version",
        "inventory": "show inventory",
    },
    "cisco_xr": {
        "version": "show version",
        "inventory": "show inventory",
    },
    "nokia_sros": {
        "version": "show version",
        "inventory": "show chassis detail",
    },
    "nokia_srl": {
        "version": "info from state /system/information",
        "inventory": "info from state /platform/chassis",
    },
    "juniper_junos": {
        "version": "show version",
        "inventory": "show chassis hardware",
    },
    "arista_eos": {
        "version": "show version",
        "inventory": "show inventory",
    },
    "brocade_fastiron": {
        "version": "show version",
        "inventory": "show inventory",
    },
    "brocade_nos": {
        "version": "show version",
        "inventory": "show inventory",
    },
}

# Vendor types to try during auto-detection (most common first)
_VENDOR_PROBE_ORDER: list[str] = [
    "cisco_ios",
    "cisco_nxos",
    "nokia_sros",
    "juniper_junos",
    "arista_eos",
    "cisco_xe",
    "cisco_xr",
    "nokia_srl",
    "brocade_fastiron",
    "brocade_nos",
]


def _parse_version_generic(output: str, vendor: str) -> dict:
    """Extract device info from show version (and related) output.

    Works across vendors by looking for common patterns.
    Returns dict with all discoverable inventory fields.
    """
    import re

    result: dict = {
        "version": None,
        "model": None,
        "serial": None,
        "hostname": None,
        "uptime": None,
        "image": None,
        "hardware_revision": None,
        "total_memory": None,
        "free_memory": None,
        "reload_reason": None,
        "mac_address": None,
        "config_register": None,
        "domain_name": None,
        "interface_count": None,
        "cpu_type": None,
        "flash_size": None,
    }

    for line in output.splitlines():
        stripped = line.strip()

        # --- Version ---
        if result["version"] is None:
            ver = re.search(r"\bVersion\s+([\d().a-zA-Z/:-]+)", line, re.IGNORECASE)
            if ver:
                result["version"] = ver.group(1).rstrip(",")
            timos = re.search(r"TiMOS-\S+-([\d.]+\S*)", line)
            if timos:
                result["version"] = timos.group(1)
            junos = re.search(r"Junos:\s+(\S+)", line)
            if junos:
                result["version"] = junos.group(1)
            eos = re.search(r"image version:\s+(\S+)", line, re.IGNORECASE)
            if eos:
                result["version"] = eos.group(1)

        # --- Model/platform ---
        if result["model"] is None:
            # Cisco: "cisco WS-C3750X-48P (PowerPC405) processor"
            plat = re.match(r"^[Cc]isco\s+(\S+)\s+.*processor", line)
            if plat:
                result["model"] = plat.group(1)
            # Cisco "Model number : ISR4331/K9"
            mnum = re.search(r"[Mm]odel\s+(?:number\s*)?[:\s]+(\S+)", stripped)
            if mnum:
                result["model"] = mnum.group(1)
            # Cisco NX-OS
            nxos = re.match(r"^\s*cisco\s+(Nexus\S+|N\d\S+)", line, re.IGNORECASE)
            if nxos:
                result["model"] = nxos.group(1)
            # Nokia
            nokia = re.search(r"\b(7\d{3}\s+\S+)", line)
            if nokia and "nokia" in vendor.lower():
                result["model"] = nokia.group(1)
            # Juniper
            junmod = re.search(r"^Model:\s+(\S+)", line, re.IGNORECASE)
            if junmod:
                result["model"] = junmod.group(1)
            # Arista
            ari = re.search(r"Arista\s+(DCS-\S+)", line)
            if ari:
                result["model"] = ari.group(1)

        # --- Serial ---
        if result["serial"] is None:
            bid = re.search(r"Processor [Bb]oard ID\s+(\S+)", line)
            if bid:
                result["serial"] = bid.group(1)
            sysser = re.search(r"System serial number\s*[:\s]+(\S+)", line, re.IGNORECASE)
            if sysser:
                result["serial"] = sysser.group(1)
            aser = re.search(r"Serial number:\s+(\S+)", line, re.IGNORECASE)
            if aser:
                result["serial"] = aser.group(1)
            # Juniper chassis serial
            jser = re.search(r"Chassis\s+\S+\s+\S+\s+\S+\s+(\S+)", line)
            if jser and "juniper" in vendor.lower():
                result["serial"] = jser.group(1)

        # --- Hostname ---
        if result["hostname"] is None:
            # Cisco: "router-01 uptime is ..."
            hup = re.match(r"^(\S+)\s+uptime\s+is", stripped)
            if hup:
                result["hostname"] = hup.group(1)
            # Nokia: "System Name : router-01"
            sname = re.search(r"System Name\s*:\s*(\S+)", stripped)
            if sname:
                result["hostname"] = sname.group(1)
            # Juniper: "Hostname: router-01"
            jhost = re.search(r"^Hostname:\s+(\S+)", stripped, re.IGNORECASE)
            if jhost:
                result["hostname"] = jhost.group(1)

        # --- Uptime ---
        if result["uptime"] is None:
            upt = re.search(r"uptime\s+is\s+(.+)", stripped, re.IGNORECASE)
            if upt:
                result["uptime"] = upt.group(1).strip()
            # Nokia: "System Up Time : 42 days, 03:15:22"
            nupt = re.search(r"System Up Time\s*:\s*(.+)", stripped)
            if nupt:
                result["uptime"] = nupt.group(1).strip()

        # --- Boot image ---
        if result["image"] is None:
            # Cisco: 'System image file is "flash:c2960-lanbasek9-mz.150-2.SE7.bin"'
            img = re.search(r'[Ss]ystem image file is\s+"([^"]+)"', stripped)
            if img:
                result["image"] = img.group(1)
            # Cisco: "BOOTLDR: ... (C2960-HBOOT-M), Version ..."
            # Arista: "System image file is ..."
            # NX-OS: "NXOS image file is: bootflash:///nxos.9.3.8.bin"
            nximg = re.search(r"NXOS image file is:\s*(\S+)", stripped)
            if nximg:
                result["image"] = nximg.group(1)

        # --- Hardware revision ---
        if result["hardware_revision"] is None:
            hrev = re.search(r"[Rr]evision\s+(\S+)", stripped)
            if hrev and "processor" in stripped.lower():
                result["hardware_revision"] = hrev.group(1).strip("()")

        # --- Memory ---
        if result["total_memory"] is None:
            # Cisco: "with 65536K/12288K bytes of memory"
            mem = re.search(r"with\s+([\d/K]+)\s+bytes of memory", stripped)
            if mem:
                result["total_memory"] = mem.group(1)
            # Cisco: "cisco ... processor ... with 4194304K bytes"
            mem2 = re.search(r"(\d+K)\s+bytes of (physical )?memory", stripped)
            if mem2:
                result["total_memory"] = mem2.group(1)
            # Arista: "Total memory: 32 GB"
            amem = re.search(r"Total memory:\s+(.+)", stripped, re.IGNORECASE)
            if amem:
                result["total_memory"] = amem.group(1)

        if result["free_memory"] is None:
            fmem = re.search(r"Free memory:\s+(.+)", stripped, re.IGNORECASE)
            if fmem:
                result["free_memory"] = fmem.group(1)

        # --- Reload reason ---
        if result["reload_reason"] is None:
            rr = re.search(r"[Ll]ast (?:reset|reload|reboot) (?:reason|from)\s+(.+)", stripped)
            if rr:
                result["reload_reason"] = rr.group(1).strip()
            rr2 = re.search(r"Reason:\s+(.+)", stripped)
            if rr2 and result["reload_reason"] is None:
                result["reload_reason"] = rr2.group(1).strip()

        # --- MAC address ---
        if result["mac_address"] is None:
            mac = re.search(r"[Bb]ase (?:ethernet|MAC) (?:MAC )?[Aa]ddress\s*:\s*(\S+)", stripped)
            if mac:
                result["mac_address"] = mac.group(1)
            mac2 = re.search(r"MAC [Aa]ddress\s*:\s*([0-9a-fA-F.:]+)", stripped)
            if mac2:
                result["mac_address"] = mac2.group(1)

        # --- Config register (Cisco) ---
        if result["config_register"] is None:
            creg = re.search(r"[Cc]onfiguration register is\s+(\S+)", stripped)
            if creg:
                result["config_register"] = creg.group(1)

        # --- CPU type ---
        if result["cpu_type"] is None:
            cpu = re.search(r"\((\w+)\)\s+processor", stripped)
            if cpu:
                result["cpu_type"] = cpu.group(1)

        # --- Flash ---
        if result["flash_size"] is None:
            fl = re.search(r"(\d+K)\s+bytes of flash", stripped, re.IGNORECASE)
            if fl:
                result["flash_size"] = fl.group(1)

        # --- Interface count ---
        if result["interface_count"] is None:
            ifc = re.search(r"(\d+)\s+(?:Ethernet|FastEthernet|GigabitEthernet|Ten\S+)\s+interface", stripped, re.IGNORECASE)
            if ifc:
                result["interface_count"] = ifc.group(1)

    return result


def _parse_serial_from_inventory(output: str, vendor: str) -> str | None:
    """Extract chassis serial from show inventory / show chassis output."""
    import re

    # Cisco-style: PID: ..., VID: ..., SN: ...
    for line in output.splitlines():
        sn_match = re.search(r"\bSN:\s*(\S+)", line)
        if sn_match and sn_match.group(1):
            return sn_match.group(1)

    # Nokia: "Serial number  : NS..."
    for line in output.splitlines():
        nokia_sn = re.search(r"Serial number\s*:\s*(\S+)", line, re.IGNORECASE)
        if nokia_sn:
            return nokia_sn.group(1)

    # Juniper: "Chassis  ... REV ... <serial>"
    for line in output.splitlines():
        jun_sn = re.search(r"^Chassis\s+\S+\s+\S+\s+\S+\s+(\S+)", line)
        if jun_sn:
            return jun_sn.group(1)

    return None


def _score_result(r: dict) -> int:
    """Score a scan result: 1 point per non-None field."""
    _SCORED_FIELDS = (
        "version", "model", "serial", "hostname", "uptime", "image",
        "mac_address", "total_memory", "reload_reason",
    )
    return sum(1 for k in _SCORED_FIELDS if r.get(k))


def _try_vendor_commands(conn: Any, vendor: str) -> dict:
    """Run a vendor's command set on an existing connection, return parsed results."""
    commands = _DEEP_COMMANDS.get(vendor, _DEEP_COMMANDS["cisco_ios"])
    r: dict = {"vendor": vendor}
    # Initialize all fields to None
    for fld in ("version", "model", "serial", "hostname", "uptime", "image",
                "hardware_revision", "total_memory", "free_memory", "reload_reason",
                "mac_address", "config_register", "cpu_type", "flash_size",
                "domain_name", "interface_count"):
        r[fld] = None

    try:
        ver_output = conn.send(commands["version"])
        parsed = _parse_version_generic(ver_output, vendor)
        for k, v in parsed.items():
            if v is not None:
                r[k] = v
    except Exception as e:
        logger.debug(f"    vendor={vendor} version cmd failed: {e}")

    if not r["serial"]:
        try:
            inv_output = conn.send(commands["inventory"])
            sn = _parse_serial_from_inventory(inv_output, vendor)
            if sn:
                r["serial"] = sn
        except Exception as e:
            logger.debug(f"    vendor={vendor} inventory cmd failed: {e}")

    return r


# Group vendors into families — once logged in with one, try all in the family
_VENDOR_FAMILIES: dict[str, list[str]] = {
    "cisco": ["cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos"],
    "nokia": ["nokia_sros", "nokia_srl"],
    "juniper": ["juniper_junos"],
    "arista": ["arista_eos"],
    "brocade": ["brocade_fastiron", "brocade_nos"],
}


def _get_family_vendors(vendor: str) -> list[str]:
    """Return all vendors in the same family, with *vendor* first."""
    for family_vendors in _VENDOR_FAMILIES.values():
        if vendor in family_vendors:
            others = [v for v in family_vendors if v != vendor]
            return [vendor] + others
    return [vendor]


def _deep_scan_host(
    host: str,
    username: str,
    password: str,
    known_vendor: str | None = None,
    timeout: int = 15,
) -> dict:
    """SSH into a host, auto-detect vendor if needed, pull version+serial.

    Once connected, tries command sets from all vendors in the same family
    (e.g. cisco_ios, cisco_xe, cisco_xr, cisco_nxos) and keeps whichever
    produces the most complete result (version + model + serial).

    Returns dict with keys: vendor, version, model, serial, error.
    """
    from netops.core.connection import ConnectionParams, DeviceConnection

    result: dict = {
        "vendor": known_vendor,
        "version": None,
        "model": None,
        "serial": None,
        "hostname": None,
        "uptime": None,
        "image": None,
        "hardware_revision": None,
        "total_memory": None,
        "free_memory": None,
        "reload_reason": None,
        "mac_address": None,
        "config_register": None,
        "cpu_type": None,
        "flash_size": None,
        "domain_name": None,
        "interface_count": None,
        "error": None,
    }

    # --- Step 1: Determine vendor for login ---
    if known_vendor and known_vendor != "unknown":
        vendors_to_try = [known_vendor]
    else:
        try:
            from netmiko import SSHDetect

            detect = SSHDetect(
                device_type="autodetect",
                host=host,
                username=username,
                password=password,
                timeout=timeout,
            )
            best = detect.autodetect()
            detect.connection.disconnect()
            if best and best != "autodetect":
                vendors_to_try = [best]
                result["vendor"] = best
                logger.info(f"  {host}: auto-detected vendor={best}")
            else:
                vendors_to_try = list(_VENDOR_PROBE_ORDER)
        except Exception as e:
            logger.debug(f"  {host}: autodetect failed ({e}), trying probe order")
            vendors_to_try = list(_VENDOR_PROBE_ORDER)

    # --- Step 2: Connect, then try all vendor command sets in the family ---
    for login_vendor in vendors_to_try:
        try:
            params = ConnectionParams(
                host=host,
                username=username,
                password=password,
                device_type=login_vendor,
                timeout=timeout,
            )
            with DeviceConnection(params) as conn:
                logger.info(f"  {host}: connected as {login_vendor}")

                family_vendors = _get_family_vendors(login_vendor)
                best_result = None
                best_score = -1

                for cmd_vendor in family_vendors:
                    logger.debug(f"  {host}: trying command set for {cmd_vendor}")
                    try:
                        candidate = _try_vendor_commands(conn, cmd_vendor)
                        score = _score_result(candidate)
                        logger.info(
                            f"  {host}: vendor={cmd_vendor} → "
                            f"version={candidate['version']}, model={candidate['model']}, "
                            f"serial={candidate['serial']} (score={score}/3)"
                        )
                        if score > best_score:
                            best_score = score
                            best_result = candidate
                        if score == 3:
                            break
                    except Exception as e:
                        logger.debug(f"  {host}: command set {cmd_vendor} error: {e}")
                        continue

                if best_result:
                    for k, v in best_result.items():
                        result[k] = v
                else:
                    result["vendor"] = login_vendor

                logger.info(
                    f"  {host}: FINAL vendor={result['vendor']}, version={result['version']}, "
                    f"model={result['model']}, serial={result['serial']}"
                )
                return result

        except Exception as e:
            logger.debug(f"  {host}: vendor={login_vendor} failed: {e}")
            continue

    result["error"] = "Could not connect with any vendor type"
    return result


def deep_enrich(
    fragment: dict,
    username: str,
    password: str,
    concurrency: int = 5,
    timeout: int = 15,
) -> dict:
    """Enrich an inventory fragment with SSH-gathered details.

    Connects to each device in the fragment, auto-detects vendor if unknown,
    and updates vendor, version, model, serial in-place.

    Args:
        fragment: Inventory fragment (``{"devices": {...}}``).
        username: SSH username for all devices.
        password: SSH password for all devices.
        concurrency: Max parallel SSH sessions.
        timeout: Per-device connection timeout in seconds.

    Returns:
        The enriched fragment (modified in-place and returned).
    """
    devices = fragment.get("devices", {})
    if not devices:
        return fragment

    enriched = 0
    failed = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {}
        for name, info in devices.items():
            host = info.get("host", name)
            known_vendor = info.get("vendor")
            if known_vendor == "unknown":
                known_vendor = None
            fut = pool.submit(
                _deep_scan_host, host, username, password, known_vendor, timeout
            )
            futures[fut] = (name, info)

        for fut in concurrent.futures.as_completed(futures):
            name, info = futures[fut]
            try:
                result = fut.result()
                updated = False

                if result.get("vendor") and info.get("vendor", "unknown") == "unknown":
                    info["vendor"] = result["vendor"]
                    updated = True

                # Propagate all deep-scan fields as top-level inventory keys
                _DEEP_FIELDS = (
                    "version", "model", "serial", "hostname", "uptime", "image",
                    "hardware_revision", "total_memory", "free_memory",
                    "reload_reason", "mac_address", "config_register",
                    "cpu_type", "flash_size", "domain_name", "interface_count",
                )
                for fld in _DEEP_FIELDS:
                    val = result.get(fld)
                    if val and not info.get(fld):
                        info[fld] = val
                        updated = True

                if updated:
                    enriched += 1
                    logger.info(f"Enriched {name}: {result}")
                if result.get("error"):
                    failed += 1

            except Exception as e:
                logger.warning(f"Deep scan failed for {name}: {e}")
                failed += 1

    print(
        f"🔬 Deep scan: {enriched} enriched, {failed} failed, "
        f"{len(devices) - enriched - failed} unchanged",
        file=sys.stderr,
    )
    return fragment

def _parse_hosts_file(path: str) -> List[str]:
    """Parse a CSV or plain-text file of IPs/hostnames.

    Supported formats:
    - CSV with 'ip', 'host', 'hostname', or 'address' column header
    - CSV with no header (first column treated as IP/host)
    - Plain text: one IP or hostname per line (comments with #, blank lines skipped)
    """
    text = Path(path).read_text(encoding="utf-8-sig")  # utf-8-sig strips BOM
    lines = text.strip().splitlines()
    if not lines:
        return []

    # Detect CSV by checking for comma or common header names
    first_line = lines[0].strip().lower()
    csv_headers = {"ip", "host", "hostname", "address", "ip_address", "target", "device"}

    if "," in first_line or first_line in csv_headers:
        reader = csv.DictReader(io.StringIO(text))
        if reader.fieldnames:
            # Find the best column
            fields_lower = {f.strip().lower(): f for f in reader.fieldnames}
            col = None
            for candidate in ("ip", "ip_address", "address", "host", "hostname", "target", "device"):
                if candidate in fields_lower:
                    col = fields_lower[candidate]
                    break
            if col:
                hosts = []
                for row in reader:
                    val = (row.get(col) or "").strip()
                    if val and not val.startswith("#"):
                        hosts.append(val)
                return hosts
        # Fallback: no recognized header — re-read as plain CSV, first column
        reader2 = csv.reader(io.StringIO(text))
        hosts = []
        for csv_row in reader2:
            if csv_row:
                val = csv_row[0].strip()
                if val and not val.startswith("#"):
                    hosts.append(val)
        return hosts

    # Plain text: one per line
    hosts = []
    for line in lines:
        val = line.strip().split("#")[0].strip()  # strip inline comments
        if val:
            hosts.append(val)
    return hosts


def main() -> None:
    """CLI entry point for the network device discovery scanner."""
    parser = argparse.ArgumentParser(
        description="Discover devices on a subnet via ping sweep + SNMP/CDP/LLDP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python -m netops.inventory.scan --subnet 10.0.0.0/24
  python -m netops.inventory.scan --subnet 10.0.0.0/24 --community public
  python -m netops.inventory.scan --csv hosts.csv --deep --user admin
  python -m netops.inventory.scan --hosts-file ips.txt --deep --user admin
  python -m netops.inventory.scan --subnet 10.0.0.0/24 --output fragment.json
  python -m netops.inventory.scan --subnet 10.0.0.0/24 --merge existing.yaml
""",
    )
    parser.add_argument("--subnet", help="Subnet in CIDR notation (e.g. 10.0.0.0/24)")
    parser.add_argument(
        "--csv", dest="hosts_file_csv",
        help="CSV file with IPs/hostnames (columns: ip, host, hostname, or address)",
    )
    parser.add_argument(
        "--hosts-file",
        help="Plain text file with one IP/hostname per line (also accepts CSV)",
    )
    parser.add_argument(
        "--community", default="public", help="SNMPv2c community string (default: public)"
    )
    parser.add_argument("--snmp-port", type=int, default=161, help="SNMP UDP port (default: 161)")
    parser.add_argument(
        "--snmp-timeout", type=int, default=2, help="Per-host SNMP timeout in seconds (default: 2)"
    )
    parser.add_argument(
        "--ping-workers", type=int, default=50, help="Ping sweep thread-pool size (default: 50)"
    )
    parser.add_argument(
        "--snmp-concurrency",
        type=int,
        default=10,
        help="Max simultaneous SNMP sessions (default: 10)",
    )
    parser.add_argument("--output", "-o", help="Write JSON inventory fragment to this file")
    parser.add_argument(
        "--merge", "-m", help="Merge scan results into this existing inventory file"
    )
    parser.add_argument(
        "--skip-ping",
        action="store_true",
        help="Skip ping sweep — probe every address in the subnet",
    )
    parser.add_argument(
        "--skip-snmp",
        action="store_true",
        help="Skip SNMP identification — perform a ping sweep only",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--deep",
        action="store_true",
        help="SSH into discovered hosts to detect vendor, version, model, and serial number",
    )
    parser.add_argument("--user", "-u", help="SSH username for deep scan")
    parser.add_argument(
        "--password", help="SSH password for deep scan (or set NETOPS_PASSWORD env var)"
    )
    parser.add_argument(
        "--ssh-timeout",
        type=int,
        default=15,
        help="Per-host SSH timeout in seconds for deep scan (default: 15)",
    )
    parser.add_argument(
        "--ssh-concurrency",
        type=int,
        default=5,
        help="Max parallel SSH sessions for deep scan (default: 5)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Determine scan targets: --subnet, --csv, or --hosts-file
    hosts_file = args.hosts_file_csv or args.hosts_file
    if not args.subnet and not hosts_file:
        parser.error("one of --subnet, --csv, or --hosts-file is required")
    if args.subnet and hosts_file:
        parser.error("--subnet cannot be combined with --csv / --hosts-file")

    if hosts_file:
        # File-based scan: parse hosts, build ScanResult for each, skip subnet sweep
        host_list = _parse_hosts_file(hosts_file)
        if not host_list:
            parser.error(f"no hosts found in {hosts_file}")
        print(
            f"📋 Loaded {len(host_list)} hosts from {hosts_file}",
            file=sys.stderr,
        )
        # Create minimal ScanResults — mark all as reachable (file implies intent to scan)
        results = [ScanResult(host=h, reachable=True) for h in host_list]
        fragment = results_to_inventory_fragment(results)
    else:
        results = scan_subnet(
            subnet=args.subnet,
            community=args.community,
            snmp_port=args.snmp_port,
            snmp_timeout=args.snmp_timeout,
            ping_workers=args.ping_workers,
            snmp_concurrency=args.snmp_concurrency,
            skip_ping=args.skip_ping,
            skip_snmp=args.skip_snmp,
        )
        fragment = results_to_inventory_fragment(results)

    # Deep scan enrichment (SSH login for vendor/version/serial/model)
    if args.deep:
        import os as _os

        deep_user = args.user
        deep_pass = args.password or _os.environ.get("NETOPS_PASSWORD")
        if not deep_user:
            parser.error("--deep requires --user (SSH username)")
        if not deep_pass:
            parser.error("--deep requires --password or NETOPS_PASSWORD env var")
        reachable_n = sum(1 for r in results if r.reachable)
        print(
            f"🔬 Starting deep scan of {reachable_n} hosts "
            f"({args.ssh_concurrency} parallel sessions)...",
            file=sys.stderr,
        )
        fragment = deep_enrich(
            fragment,
            username=deep_user,
            password=deep_pass,
            concurrency=args.ssh_concurrency,
            timeout=args.ssh_timeout,
        )

    reachable_count = sum(1 for r in results if r.reachable)
    snmp_count = sum(1 for r in results if r.sys_descr)
    cdp_total = sum(len(r.cdp_neighbors) for r in results)
    lldp_total = sum(len(r.lldp_neighbors) for r in results)
    print(
        f"🔍 Scan complete: {reachable_count} reachable, "
        f"{snmp_count} identified via SNMP, "
        f"{cdp_total} CDP neighbors, {lldp_total} LLDP neighbors",
        file=sys.stderr,
    )

    if args.merge:
        merged = merge_inventory(args.merge, fragment)
        merge_path = Path(args.merge)
        if merge_path.suffix in (".yaml", ".yml"):
            _dump_yaml(merge_path, merged)
        else:
            merge_path.write_text(json.dumps(merged, indent=2))
        print(f"✅ Merged into {args.merge}", file=sys.stderr)
    elif args.output:
        Path(args.output).write_text(json.dumps(fragment, indent=2))
        print(f"✅ Fragment written to {args.output}", file=sys.stderr)
    else:
        json.dump(fragment, sys.stdout, indent=2)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
