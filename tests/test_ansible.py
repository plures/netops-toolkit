"""Tests for Ansible inventory export and dynamic inventory."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from netops.core.inventory import Device, Inventory

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_INVENTORY_YAML = textwrap.dedent("""\
    defaults:
      username: admin
      transport: ssh

    devices:
      router1:
        host: 10.0.0.1
        vendor: cisco_ios
        groups:
          - core
          - routers
        site: dc1
        role: core
        tags:
          environment: production

      router2:
        host: 10.0.0.2
        vendor: cisco_ios
        groups:
          - routers
        site: dc2

      pe1:
        host: 10.1.0.1
        vendor: nokia_sros
        groups:
          - pe_routers
        role: edge
""")


@pytest.fixture()
def sample_inventory(tmp_path: Path) -> Inventory:
    inv_file = tmp_path / "inventory.yaml"
    inv_file.write_text(SAMPLE_INVENTORY_YAML)
    return Inventory.from_file(inv_file)


@pytest.fixture()
def sample_inventory_file(tmp_path: Path) -> Path:
    inv_file = tmp_path / "inventory.yaml"
    inv_file.write_text(SAMPLE_INVENTORY_YAML)
    return inv_file


# ===========================================================================
# Inventory.to_ansible()
# ===========================================================================


class TestToAnsible:
    def test_returns_dict(self, sample_inventory: Inventory):
        result = sample_inventory.to_ansible()
        assert isinstance(result, dict)

    def test_top_level_all_key(self, sample_inventory: Inventory):
        result = sample_inventory.to_ansible()
        assert "all" in result

    def test_all_devices_present(self, sample_inventory: Inventory):
        result = sample_inventory.to_ansible()
        hosts = result["all"]["hosts"]
        assert "router1" in hosts
        assert "router2" in hosts
        assert "pe1" in hosts

    def test_host_vars_structure(self, sample_inventory: Inventory):
        result = sample_inventory.to_ansible()
        r1 = result["all"]["hosts"]["router1"]
        assert r1["ansible_host"] == "10.0.0.1"
        assert r1["ansible_network_os"] == "cisco_ios"
        assert r1["ansible_connection"] == "ansible.netcommon.network_cli"
        assert r1["ansible_port"] == 22
        assert r1["ansible_user"] == "admin"

    def test_host_vars_netops_extras(self, sample_inventory: Inventory):
        result = sample_inventory.to_ansible()
        r1 = result["all"]["hosts"]["router1"]
        assert r1["netops_vendor"] == "cisco_ios"
        assert r1["netops_transport"] == "ssh"
        assert r1["netops_site"] == "dc1"
        assert r1["netops_role"] == "core"
        assert r1["netops_tags"] == {"environment": "production"}

    def test_no_optional_keys_when_missing(self, sample_inventory: Inventory):
        result = sample_inventory.to_ansible()
        r2 = result["all"]["hosts"]["router2"]
        assert "netops_role" not in r2
        assert "netops_tags" not in r2

    def test_groups_in_children(self, sample_inventory: Inventory):
        result = sample_inventory.to_ansible()
        children = result["all"]["children"]
        assert "core" in children
        assert "routers" in children
        assert "pe_routers" in children

    def test_group_members(self, sample_inventory: Inventory):
        result = sample_inventory.to_ansible()
        routers_hosts = result["all"]["children"]["routers"]["hosts"]
        assert "router1" in routers_hosts
        assert "router2" in routers_hosts

    def test_telnet_uses_port_23(self):
        inv = Inventory()
        inv.add(Device(hostname="sw1", host="192.168.1.1", vendor="cisco_ios", transport="telnet"))
        result = inv.to_ansible()
        assert result["all"]["hosts"]["sw1"]["ansible_port"] == 23

    def test_custom_port_preserved(self):
        inv = Inventory()
        inv.add(Device(hostname="sw1", host="192.168.1.1", vendor="cisco_ios", port=8022))
        result = inv.to_ansible()
        assert result["all"]["hosts"]["sw1"]["ansible_port"] == 8022


# ===========================================================================
# Inventory.to_ansible_json()
# ===========================================================================


class TestToAnsibleJson:
    def test_returns_valid_json(self, sample_inventory: Inventory):
        raw = sample_inventory.to_ansible_json()
        parsed = json.loads(raw)
        assert "all" in parsed

    def test_json_matches_to_ansible(self, sample_inventory: Inventory):
        from_method = sample_inventory.to_ansible()
        from_json = json.loads(sample_inventory.to_ansible_json())
        assert from_method == from_json


# ===========================================================================
# Inventory.to_ansible_yaml()
# ===========================================================================


class TestToAnsibleYaml:
    def test_returns_string(self, sample_inventory: Inventory):
        raw = sample_inventory.to_ansible_yaml()
        assert isinstance(raw, str)
        assert "all:" in raw

    def test_yaml_parses_correctly(self, sample_inventory: Inventory):
        import yaml

        raw = sample_inventory.to_ansible_yaml()
        parsed = yaml.safe_load(raw)
        assert "all" in parsed
        assert "router1" in parsed["all"]["hosts"]

    def test_yaml_matches_to_ansible(self, sample_inventory: Inventory):
        import yaml

        from_method = sample_inventory.to_ansible()
        from_yaml = yaml.safe_load(sample_inventory.to_ansible_yaml())
        assert from_method == from_yaml


# ===========================================================================
# CLI: python -m netops.core.inventory export
# ===========================================================================


class TestInventoryCLI:
    def _run_cli(self, args: list[str]) -> "subprocess.CompletedProcess":  # type: ignore[name-defined]  # noqa: F821
        import subprocess
        import sys

        return subprocess.run(
            [sys.executable, "-m", "netops.core.inventory"] + args,
            capture_output=True,
            text=True,
        )

    def test_export_ansible_yaml_stdout(self, sample_inventory_file: Path):
        result = self._run_cli(
            ["export", "--format", "ansible", "--inventory", str(sample_inventory_file)]
        )
        assert result.returncode == 0
        import yaml

        parsed = yaml.safe_load(result.stdout)
        assert "all" in parsed

    def test_export_ansible_json_stdout(self, sample_inventory_file: Path):
        result = self._run_cli(
            ["export", "--format", "ansible-json", "--inventory", str(sample_inventory_file)]
        )
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert "all" in parsed

    def test_export_to_file(self, sample_inventory_file: Path, tmp_path: Path):
        out_file = tmp_path / "out.yaml"
        result = self._run_cli(
            [
                "export",
                "--format",
                "ansible",
                "--inventory",
                str(sample_inventory_file),
                "--output",
                str(out_file),
            ]
        )
        assert result.returncode == 0
        assert out_file.exists()
        import yaml

        parsed = yaml.safe_load(out_file.read_text())
        assert "all" in parsed

    def test_missing_inventory_exits_nonzero(self, tmp_path: Path):
        result = self._run_cli(
            ["export", "--format", "ansible", "--inventory", str(tmp_path / "missing.yaml")]
        )
        assert result.returncode != 0


# ===========================================================================
# Dynamic inventory
# ===========================================================================


class TestDynamicInventory:
    def _run(self, args: list[str]) -> "subprocess.CompletedProcess":  # type: ignore[name-defined]  # noqa: F821
        import subprocess
        import sys

        return subprocess.run(
            [sys.executable, "-m", "netops.ansible.dynamic_inventory"] + args,
            capture_output=True,
            text=True,
        )

    def test_list_returns_valid_json(self, sample_inventory_file: Path):
        result = self._run(["--list", "--inventory", str(sample_inventory_file)])
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert "_meta" in parsed
        assert "hostvars" in parsed["_meta"]

    def test_list_contains_all_hosts(self, sample_inventory_file: Path):
        result = self._run(["--list", "--inventory", str(sample_inventory_file)])
        parsed = json.loads(result.stdout)
        hostvars = parsed["_meta"]["hostvars"]
        assert "router1" in hostvars
        assert "router2" in hostvars
        assert "pe1" in hostvars

    def test_list_contains_groups(self, sample_inventory_file: Path):
        result = self._run(["--list", "--inventory", str(sample_inventory_file)])
        parsed = json.loads(result.stdout)
        assert "routers" in parsed
        assert "core" in parsed

    def test_host_returns_hostvars(self, sample_inventory_file: Path):
        result = self._run(["--host", "router1", "--inventory", str(sample_inventory_file)])
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert parsed["ansible_host"] == "10.0.0.1"

    def test_missing_inventory_nonzero(self, tmp_path: Path):
        result = self._run(["--list", "--inventory", str(tmp_path / "no.yaml")])
        assert result.returncode != 0

    def test_host_unknown_returns_empty(self, sample_inventory_file: Path):
        result = self._run(["--host", "nonexistent", "--inventory", str(sample_inventory_file)])
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert parsed == {}


# ===========================================================================
# build_inventory helper (unit test without subprocess)
# ===========================================================================


class TestBuildInventory:
    def test_meta_structure(self, sample_inventory_file: Path):
        from netops.ansible.dynamic_inventory import build_inventory

        result = build_inventory(str(sample_inventory_file))
        assert "_meta" in result
        assert "hostvars" in result["_meta"]

    def test_all_hosts_listed(self, sample_inventory_file: Path):
        from netops.ansible.dynamic_inventory import build_inventory

        result = build_inventory(str(sample_inventory_file))
        assert set(result["all"]["hosts"]) >= {"router1", "router2", "pe1"}

    def test_groups_listed(self, sample_inventory_file: Path):
        from netops.ansible.dynamic_inventory import build_inventory

        result = build_inventory(str(sample_inventory_file))
        assert "routers" in result["all"]["children"]

    def test_group_members(self, sample_inventory_file: Path):
        from netops.ansible.dynamic_inventory import build_inventory

        result = build_inventory(str(sample_inventory_file))
        assert "router1" in result["routers"]["hosts"]
        assert "router2" in result["routers"]["hosts"]
