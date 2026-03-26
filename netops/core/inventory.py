"""
Device inventory management.

Simple YAML/JSON inventory that maps to Ansible inventory format.

CLI usage::

    python -m netops.core.inventory export --format ansible --output ansible_inventory.yaml
    python -m netops.core.inventory export --format ansible-json --output ansible_inventory.json
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Device:
    """A network device in the inventory."""
    hostname: str
    host: str  # IP or FQDN
    vendor: str  # cisco_ios, nokia_sros, etc.
    transport: str = "ssh"
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    enable_password: Optional[str] = None
    key_file: Optional[str] = None
    groups: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    # Location/metadata
    site: Optional[str] = None
    role: Optional[str] = None  # core, distribution, access, edge

    def to_dict(self) -> dict:
        """Return a dict representation of the device, omitting ``None`` fields."""
        return {k: v for k, v in asdict(self).items() if v is not None}


class Inventory:
    """
    Device inventory with group support.

    Supports:
    - YAML/JSON file loading
    - Group-based filtering
    - Tag-based filtering
    - Export to Ansible inventory format
    """

    def __init__(self) -> None:
        """Initialise an empty inventory with no devices, groups, or defaults."""
        self.devices: dict[str, Device] = {}
        self.groups: dict[str, list[str]] = {}  # group -> [hostname]
        self.defaults: dict = {}  # Default connection params

    def add(self, device: Device) -> None:
        """Add *device* to the inventory, registering it under all its groups."""
        self.devices[device.hostname] = device
        for group in device.groups:
            self.groups.setdefault(group, []).append(device.hostname)

    def get(self, hostname: str) -> Optional[Device]:
        """Look up a device by hostname; returns ``None`` if not found."""
        return self.devices.get(hostname)

    def filter(self, group: str | None = None, vendor: str | None = None,
               role: str | None = None, site: str | None = None, tag: tuple | None = None) -> list[Device]:
        """Filter devices by criteria."""
        results = list(self.devices.values())
        if group:
            hostnames = set(self.groups.get(group, []))
            results = [d for d in results if d.hostname in hostnames]
        if vendor:
            results = [d for d in results if d.vendor == vendor]
        if role:
            results = [d for d in results if d.role == role]
        if site:
            results = [d for d in results if d.site == site]
        if tag:
            key, value = tag
            results = [d for d in results if d.tags.get(key) == value]
        return results

    @classmethod
    def from_file(cls, path: str | Path) -> "Inventory":
        """Load inventory from YAML or JSON file."""
        path = Path(path)
        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml
                data = yaml.safe_load(path.read_text())
            except ImportError:
                raise ImportError("PyYAML required for YAML inventory: pip install pyyaml")
        else:
            data = json.loads(path.read_text())

        inv = cls()
        inv.defaults = data.get("defaults", {})

        for name, info in data.get("devices", {}).items():
            # Merge defaults
            merged = {**inv.defaults, **info}
            device = Device(
                hostname=name,
                host=merged.get("host", name),
                vendor=merged.get("vendor", "autodetect"),
                transport=merged.get("transport", "ssh"),
                port=merged.get("port"),
                username=merged.get("username"),
                password=merged.get("password"),
                enable_password=merged.get("enable_password"),
                key_file=merged.get("key_file"),
                groups=merged.get("groups", []),
                tags=merged.get("tags", {}),
                site=merged.get("site"),
                role=merged.get("role"),
            )
            inv.add(device)

        return inv

    def to_ansible(self) -> dict:
        """Export as Ansible inventory format (JSON-compatible dict).

        The returned structure follows the Ansible JSON inventory spec:
        https://docs.ansible.com/ansible/latest/dev_guide/developing_inventory.html
        """
        ansible_inv: dict = {"all": {"hosts": {}, "children": {}}}

        for hostname, device in self.devices.items():
            host_vars: dict = {
                "ansible_host": device.host,
                "ansible_network_os": device.vendor,
                "ansible_connection": "ansible.netcommon.network_cli",
                "ansible_port": device.port or (23 if device.transport == "telnet" else 22),
                "netops_vendor": device.vendor,
                "netops_transport": device.transport,
            }
            if device.username:
                host_vars["ansible_user"] = device.username
            if device.site:
                host_vars["netops_site"] = device.site
            if device.role:
                host_vars["netops_role"] = device.role
            if device.tags:
                host_vars["netops_tags"] = device.tags
            ansible_inv["all"]["hosts"][hostname] = host_vars

        for group, hostnames in self.groups.items():
            ansible_inv["all"]["children"][group] = {
                "hosts": {h: {} for h in hostnames}
            }

        return ansible_inv

    def to_ansible_yaml(self) -> str:
        """Export as Ansible inventory in YAML format."""
        try:
            import yaml
        except ImportError as exc:
            raise ImportError("PyYAML required for YAML export: pip install pyyaml") from exc
        return str(yaml.dump(self.to_ansible(), default_flow_style=False, sort_keys=False))

    def to_ansible_json(self) -> str:
        """Export as Ansible inventory in JSON format."""
        return json.dumps(self.to_ansible(), indent=2)

    def to_file(self, path: str | Path, format: str = "yaml") -> None:
        """Save inventory to file."""
        path = Path(path)
        data = {
            "defaults": self.defaults,
            "devices": {name: d.to_dict() for name, d in self.devices.items()},
        }
        if format == "yaml":
            try:
                import yaml
                path.write_text(yaml.dump(data, default_flow_style=False))
            except ImportError:
                format = "json"
        if format == "json":
            path.write_text(json.dumps(data, indent=2))


def main() -> None:
    """CLI entry point: python -m netops.core.inventory export ..."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="python -m netops.core.inventory",
        description="netops inventory management",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    exp = sub.add_parser("export", help="Export inventory to various formats")
    exp.add_argument("--inventory", "-i", default="inventory.yaml", help="Source inventory file")
    exp.add_argument(
        "--format",
        "-f",
        choices=["ansible", "ansible-json", "ansible-yaml", "json", "yaml"],
        default="ansible",
        help=(
            "Output format: 'ansible'/'ansible-yaml' → Ansible YAML, "
            "'ansible-json' → Ansible JSON, 'json'/'yaml' → netops native"
        ),
    )
    exp.add_argument("--output", "-o", default="-", help="Output file (- for stdout)")

    args = parser.parse_args()

    if args.command == "export":
        inv = Inventory.from_file(args.inventory)

        fmt = args.format
        if fmt in ("ansible", "ansible-yaml"):
            content = inv.to_ansible_yaml()
        elif fmt == "ansible-json":
            content = inv.to_ansible_json()
        elif fmt == "json":
            content = json.dumps(
                {"defaults": inv.defaults,
                 "devices": {n: d.to_dict() for n, d in inv.devices.items()}},
                indent=2,
            )
        else:  # yaml / native
            try:
                import yaml
                content = yaml.dump(
                    {"defaults": inv.defaults,
                     "devices": {n: d.to_dict() for n, d in inv.devices.items()}},
                    default_flow_style=False,
                )
            except ImportError:
                print("PyYAML not installed; falling back to JSON", file=sys.stderr)
                content = json.dumps(
                    {"defaults": inv.defaults,
                     "devices": {n: d.to_dict() for n, d in inv.devices.items()}},
                    indent=2,
                )

        if args.output == "-":
            print(content, end="")
        else:
            Path(args.output).write_text(content)
            print(f"Written to {args.output}")


if __name__ == "__main__":
    main()
