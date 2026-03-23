"""
Device inventory management.

Simple YAML/JSON inventory that maps to Ansible inventory format.
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

    def __init__(self):
        self.devices: dict[str, Device] = {}
        self.groups: dict[str, list[str]] = {}  # group -> [hostname]
        self.defaults: dict = {}  # Default connection params

    def add(self, device: Device):
        self.devices[device.hostname] = device
        for group in device.groups:
            self.groups.setdefault(group, []).append(device.hostname)

    def get(self, hostname: str) -> Optional[Device]:
        return self.devices.get(hostname)

    def filter(self, group: str = None, vendor: str = None,
               role: str = None, site: str = None, tag: tuple = None) -> list[Device]:
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
        """Export as Ansible inventory format (JSON)."""
        ansible_inv = {"all": {"hosts": {}, "children": {}}}

        for hostname, device in self.devices.items():
            ansible_inv["all"]["hosts"][hostname] = {
                "ansible_host": device.host,
                "ansible_network_os": device.vendor,
                "ansible_connection": "ansible.netcommon.network_cli",
                "ansible_port": device.port or (23 if device.transport == "telnet" else 22),
            }
            if device.username:
                ansible_inv["all"]["hosts"][hostname]["ansible_user"] = device.username

        for group, hostnames in self.groups.items():
            ansible_inv["all"]["children"][group] = {
                "hosts": {h: {} for h in hostnames}
            }

        return ansible_inv

    def to_file(self, path: str | Path, format: str = "yaml"):
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
