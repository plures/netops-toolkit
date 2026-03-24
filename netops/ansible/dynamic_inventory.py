"""
Ansible dynamic inventory script backed by a netops inventory file.

Usage (as a standalone script)::

    # List all hosts and groups
    python -m netops.ansible.dynamic_inventory --list

    # Get host variables for a specific host
    python -m netops.ansible.dynamic_inventory --host router1

    # Specify inventory file (default: inventory.yaml)
    python -m netops.ansible.dynamic_inventory --list --inventory /path/to/inv.yaml

Configure via the environment variable ``NETOPS_INVENTORY`` or the
``--inventory`` flag.  When used as an Ansible inventory source pass the
script path with ``-i``::

    ansible-playbook -i path/to/dynamic_inventory.py site.yml

The ``_meta.hostvars`` structure is always populated so Ansible does not
need to issue individual ``--host`` calls.
"""

from __future__ import annotations

import json
import os
import sys


def _default_inventory_path() -> str:
    return os.environ.get("NETOPS_INVENTORY", "inventory.yaml")


def build_inventory(inventory_path: str) -> dict:
    """Return an Ansible JSON inventory dict from a netops inventory file."""
    from netops.core.inventory import Inventory  # local import keeps module light

    inv = Inventory.from_file(inventory_path)
    ansible_dict = inv.to_ansible()

    # Flatten host variables into _meta.hostvars as required by Ansible
    hostvars: dict = {}
    for hostname, host_vars in ansible_dict["all"]["hosts"].items():
        hostvars[hostname] = host_vars

    # Build the final structure expected by Ansible
    result: dict = {
        "_meta": {"hostvars": hostvars},
        "all": {
            "hosts": list(ansible_dict["all"]["hosts"].keys()),
            "children": list(ansible_dict["all"]["children"].keys()),
        },
    }

    # Add each group with its member list
    for group, group_data in ansible_dict["all"]["children"].items():
        result[group] = {"hosts": list(group_data.get("hosts", {}).keys())}

    return result


def get_host_vars(inventory_path: str, hostname: str) -> dict:
    """Return variables for a single host."""
    full = build_inventory(inventory_path)
    return full.get("_meta", {}).get("hostvars", {}).get(hostname, {})


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m netops.ansible.dynamic_inventory",
        description="Ansible dynamic inventory backed by a netops inventory file",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="Output all hosts and groups")
    group.add_argument("--host", metavar="HOSTNAME", help="Output variables for a single host")
    parser.add_argument(
        "--inventory",
        "-i",
        default=_default_inventory_path(),
        help="Path to netops inventory file (default: $NETOPS_INVENTORY or inventory.yaml)",
    )

    args = parser.parse_args(argv)

    try:
        if args.list:
            output = build_inventory(args.inventory)
        else:
            output = get_host_vars(args.inventory, args.host)
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
