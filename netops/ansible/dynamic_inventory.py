"""
Ansible dynamic inventory script backed by a netops inventory file.

Usage (as a standalone script)::

    # List all hosts and groups
    python -m netops.ansible.dynamic_inventory --list

    # Get host variables for a specific host
    python -m netops.ansible.dynamic_inventory --host router1

    # Specify inventory file (default: inventory.yaml)
    python -m netops.ansible.dynamic_inventory --list --inventory /path/to/inv.yaml

    # Use a vault file for per-device credentials
    python -m netops.ansible.dynamic_inventory --list --vault ~/.netops/vault.yaml

    # Control the on-disk cache
    python -m netops.ansible.dynamic_inventory --list --cache-ttl 600
    python -m netops.ansible.dynamic_inventory --list --no-cache
    python -m netops.ansible.dynamic_inventory --list --refresh-cache

Configure via environment variables:

* ``NETOPS_INVENTORY``       — path to the inventory file
* ``NETOPS_VAULT``           — path to the vault file
* ``NETOPS_INVENTORY_CACHE`` — path to the JSON cache file

When used as an Ansible inventory source pass the script path with ``-i``::

    ansible-playbook -i path/to/dynamic_inventory.py site.yml

The ``_meta.hostvars`` structure is always populated so Ansible does not
need to issue individual ``--host`` calls.

Auto-generated groups
---------------------
In addition to explicit device groups defined in the inventory file the
inventory builder automatically creates the following groups from device
metadata:

* ``vendor_<vendor>``   — e.g. ``vendor_cisco_ios``, ``vendor_nokia_sros``
* ``site_<site>``       — e.g. ``site_dc1``
* ``role_<role>``       — e.g. ``role_spine``, ``role_leaf``, ``role_core``

Cache
-----
Results are cached in a JSON file (default: ``~/.netops/inventory_cache.json``)
with a configurable TTL (default 300 s).  Pass ``--no-cache`` to skip caching
entirely or ``--refresh-cache`` to force a rebuild.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import cast

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment / defaults
# ---------------------------------------------------------------------------

_DEFAULT_CACHE_TTL = 300  # seconds
_DEFAULT_CACHE_PATH = Path.home() / ".netops" / "inventory_cache.json"


def _default_inventory_path() -> str:
    """Return the default inventory file path from env or fallback to ``inventory.yaml``."""
    return os.environ.get("NETOPS_INVENTORY", "inventory.yaml")


def _default_vault_path() -> str | None:
    """Return the vault path from ``NETOPS_VAULT`` environment variable, or ``None``."""
    return os.environ.get("NETOPS_VAULT")


def _default_cache_path() -> str:
    """Return the inventory cache file path from env or the default ``~/.netops/`` location."""
    return os.environ.get("NETOPS_INVENTORY_CACHE", str(_DEFAULT_CACHE_PATH))


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def _cache_valid(cache_path: str, ttl: int) -> bool:
    """Return True when the cache file exists and is younger than *ttl* seconds."""
    p = Path(cache_path)
    if not p.exists():
        return False
    age = time.time() - p.stat().st_mtime
    return age < ttl


def _load_cache(cache_path: str) -> dict | None:
    """Load and return the cached inventory dict, or *None* on failure."""
    try:
        return cast(dict, json.loads(Path(cache_path).read_text()))
    except Exception:  # noqa: BLE001
        return None


def _save_cache(cache_path: str, data: dict) -> None:
    """Write *data* as JSON to *cache_path*, creating parent dirs as needed."""
    p = Path(cache_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# Auto-group generation
# ---------------------------------------------------------------------------

_AUTO_GROUP_PREFIX = {
    "vendor": "vendor_",
    "site": "site_",
    "role": "role_",
}


def _safe_group_name(value: str) -> str:
    """Normalise a metadata value to a valid Ansible group name."""
    return value.lower().replace("-", "_").replace(" ", "_").replace("/", "_")


def _generate_auto_groups(devices: dict) -> dict[str, list[str]]:
    """Return a mapping of auto-group-name → [hostname, ...] from *devices*.

    ``devices`` should be the mapping returned by
    :py:attr:`netops.core.inventory.Inventory.devices`.
    """
    groups: dict[str, list[str]] = {}
    for hostname, device in devices.items():
        if device.vendor:
            g = f"vendor_{_safe_group_name(device.vendor)}"
            groups.setdefault(g, []).append(hostname)
        if device.site:
            g = f"site_{_safe_group_name(device.site)}"
            groups.setdefault(g, []).append(hostname)
        if device.role:
            g = f"role_{_safe_group_name(device.role)}"
            groups.setdefault(g, []).append(hostname)
    return groups


# ---------------------------------------------------------------------------
# Vault credential injection
# ---------------------------------------------------------------------------


def _inject_vault_credentials(
    hostvars: dict, devices: dict, vault_path: str | None
) -> None:
    """Mutate *hostvars* to add Ansible credential variables from the vault.

    Does nothing when *vault_path* is ``None`` or the vault cannot be opened
    without a password (no ``NETOPS_VAULT_PASSWORD`` env var set).
    """
    if not vault_path:
        return

    try:
        from netops.core.vault import CredentialVault  # local import — optional dep
    except ImportError:
        logger.debug("netops.core.vault not available; skipping vault injection")
        return

    # Only attempt vault access when a password is available non-interactively.
    password = os.environ.get("NETOPS_VAULT_PASSWORD")
    if not password:
        logger.debug("NETOPS_VAULT_PASSWORD not set; skipping vault credential injection")
        return

    try:
        vault = CredentialVault(vault_path=vault_path)
        vault.unlock(password)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not open vault %s: %s", vault_path, exc)
        return

    for hostname, device in devices.items():
        groups = list(device.groups)
        try:
            creds = vault.get_credentials(hostname, groups=groups)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Vault lookup failed for %s: %s", hostname, exc)
            continue
        if not creds:
            continue
        hv = hostvars.setdefault(hostname, {})
        if creds.get("username"):
            hv["ansible_user"] = creds["username"]
        if creds.get("password"):
            hv["ansible_password"] = creds["password"]
        if creds.get("enable_password"):
            hv["ansible_become_password"] = creds["enable_password"]


# ---------------------------------------------------------------------------
# Core builder
# ---------------------------------------------------------------------------


def build_inventory(
    inventory_path: str,
    vault_path: str | None = None,
    cache_path: str | None = None,
    cache_ttl: int = _DEFAULT_CACHE_TTL,
    no_cache: bool = False,
    refresh_cache: bool = False,
) -> dict:
    """Return an Ansible JSON inventory dict from a netops inventory file.

    Parameters
    ----------
    inventory_path:
        Path to the netops YAML/JSON inventory file.
    vault_path:
        Optional path to a :class:`~netops.core.vault.CredentialVault` file.
        When provided and ``NETOPS_VAULT_PASSWORD`` is set, per-device
        credentials are injected into the host vars.
    cache_path:
        Path for the JSON cache file.  Defaults to
        ``~/.netops/inventory_cache.json`` (or ``$NETOPS_INVENTORY_CACHE``).
    cache_ttl:
        Cache time-to-live in seconds (default 300).
    no_cache:
        When *True*, skip reading from and writing to the cache.
    refresh_cache:
        When *True*, ignore the existing cache and always rebuild.
    """
    if cache_path is None:
        cache_path = _default_cache_path()

    # Verify the inventory file exists before anything else so that a missing
    # file always raises FileNotFoundError (even when a valid cache exists).
    inv_file = Path(inventory_path)
    if not inv_file.exists():
        raise FileNotFoundError(f"inventory file not found: {inventory_path}")

    # Return cached result when still fresh and not forced to refresh.
    if not no_cache and not refresh_cache and _cache_valid(cache_path, cache_ttl):
        cached = _load_cache(cache_path)
        if cached is not None:
            logger.debug("Returning inventory from cache (%s)", cache_path)
            return cached

    from netops.core.inventory import Inventory  # local import keeps module light

    inv = Inventory.from_file(inventory_path)
    ansible_dict = inv.to_ansible()

    # ------------------------------------------------------------------ #
    # Build hostvars
    # ------------------------------------------------------------------ #
    hostvars: dict = {}
    for hostname, host_vars in ansible_dict["all"]["hosts"].items():
        hostvars[hostname] = host_vars

    # Inject vault credentials into hostvars
    _inject_vault_credentials(hostvars, inv.devices, vault_path)

    # ------------------------------------------------------------------ #
    # Build the top-level result (all group + explicit children)
    # ------------------------------------------------------------------ #
    all_children: dict[str, list[str]] = {}

    # Explicit groups defined in the inventory file
    for group, group_data in ansible_dict["all"]["children"].items():
        all_children[group] = list(group_data.get("hosts", {}).keys())

    # Auto-generated groups from device metadata
    for group, members in _generate_auto_groups(inv.devices).items():
        if group not in all_children:
            all_children[group] = members

    result: dict = {
        "_meta": {"hostvars": hostvars},
        "all": {
            "hosts": list(ansible_dict["all"]["hosts"].keys()),
            "children": list(all_children.keys()),
        },
    }

    # Emit each group as a top-level key with its member list
    for group, members in all_children.items():
        result[group] = {"hosts": members}

    # Persist cache
    if not no_cache:
        try:
            _save_cache(cache_path, result)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not write inventory cache to %s: %s", cache_path, exc)

    return result


def get_host_vars(
    inventory_path: str,
    hostname: str,
    vault_path: str | None = None,
    cache_path: str | None = None,
    cache_ttl: int = _DEFAULT_CACHE_TTL,
    no_cache: bool = False,
    refresh_cache: bool = False,
) -> dict:
    """Return variables for a single host."""
    full = build_inventory(
        inventory_path,
        vault_path=vault_path,
        cache_path=cache_path,
        cache_ttl=cache_ttl,
        no_cache=no_cache,
        refresh_cache=refresh_cache,
    )
    return cast(dict, full.get("_meta", {}).get("hostvars", {}).get(hostname, {}))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the Ansible dynamic inventory script."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m netops.ansible.dynamic_inventory",
        description="Ansible dynamic inventory backed by a netops inventory file",
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--list", action="store_true", help="Output all hosts and groups")
    mode_group.add_argument("--host", metavar="HOSTNAME", help="Output variables for a single host")
    parser.add_argument(
        "--inventory",
        "-i",
        default=_default_inventory_path(),
        help="Path to netops inventory file (default: $NETOPS_INVENTORY or inventory.yaml)",
    )
    parser.add_argument(
        "--vault",
        default=_default_vault_path(),
        help="Path to netops vault file for per-device credentials (default: $NETOPS_VAULT)",
    )
    parser.add_argument(
        "--cache-path",
        default=_default_cache_path(),
        help="Path for the JSON cache file (default: $NETOPS_INVENTORY_CACHE or ~/.netops/inventory_cache.json)",
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=_DEFAULT_CACHE_TTL,
        metavar="SECONDS",
        help=f"Cache time-to-live in seconds (default: {_DEFAULT_CACHE_TTL})",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable caching entirely",
    )
    parser.add_argument(
        "--refresh-cache",
        action="store_true",
        help="Ignore the existing cache and rebuild the inventory",
    )

    args = parser.parse_args(argv)

    try:
        if args.list:
            output = build_inventory(
                args.inventory,
                vault_path=args.vault,
                cache_path=args.cache_path,
                cache_ttl=args.cache_ttl,
                no_cache=args.no_cache,
                refresh_cache=args.refresh_cache,
            )
        else:
            output = get_host_vars(
                args.inventory,
                args.host,
                vault_path=args.vault,
                cache_path=args.cache_path,
                cache_ttl=args.cache_ttl,
                no_cache=args.no_cache,
                refresh_cache=args.refresh_cache,
            )
    except FileNotFoundError as exc:
        print(f"ERROR: inventory file not found: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
