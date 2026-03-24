"""
Subnet scanner — discover devices via SNMP/CDP/LLDP/ping sweep.

Usage:
    python -m netops.inventory.scan --subnet 10.0.0.0/24 --community public
    python -m netops.inventory.scan --subnet 10.0.0.0/24 --output fragment.json
    python -m netops.inventory.scan --subnet 10.0.0.0/24 --merge existing.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import ipaddress
import json
import logging
import platform
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

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

    def to_inventory_entry(self) -> dict:
        """Convert to an inventory device dict (compatible with core.Inventory)."""
        entry: dict = {
            "host": self.host,
            "vendor": self.vendor or "unknown",
        }
        if self.location:
            entry["site"] = self.location
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
    engine,
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
    engine,
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
    engine,
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


def main():
    parser = argparse.ArgumentParser(
        description="Discover devices on a subnet via ping sweep + SNMP/CDP/LLDP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python -m netops.inventory.scan --subnet 10.0.0.0/24
  python -m netops.inventory.scan --subnet 10.0.0.0/24 --community public
  python -m netops.inventory.scan --subnet 10.0.0.0/24 --output fragment.json
  python -m netops.inventory.scan --subnet 10.0.0.0/24 --merge existing.yaml
""",
    )
    parser.add_argument("--subnet", required=True, help="Subnet in CIDR notation (e.g. 10.0.0.0/24)")
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
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

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
