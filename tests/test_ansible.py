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

        result = build_inventory(str(sample_inventory_file), no_cache=True)
        assert "_meta" in result
        assert "hostvars" in result["_meta"]

    def test_all_hosts_listed(self, sample_inventory_file: Path):
        from netops.ansible.dynamic_inventory import build_inventory

        result = build_inventory(str(sample_inventory_file), no_cache=True)
        assert set(result["all"]["hosts"]) >= {"router1", "router2", "pe1"}

    def test_groups_listed(self, sample_inventory_file: Path):
        from netops.ansible.dynamic_inventory import build_inventory

        result = build_inventory(str(sample_inventory_file), no_cache=True)
        assert "routers" in result["all"]["children"]

    def test_group_members(self, sample_inventory_file: Path):
        from netops.ansible.dynamic_inventory import build_inventory

        result = build_inventory(str(sample_inventory_file), no_cache=True)
        assert "router1" in result["routers"]["hosts"]
        assert "router2" in result["routers"]["hosts"]


# ===========================================================================
# Auto-group generation
# ===========================================================================


class TestAutoGroups:
    """Auto-generated groups from vendor / site / role metadata."""

    def _build(self, tmp_path: Path) -> dict:
        from netops.ansible.dynamic_inventory import build_inventory

        inv_file = tmp_path / "inventory.yaml"
        inv_file.write_text(SAMPLE_INVENTORY_YAML)
        return build_inventory(str(inv_file), no_cache=True)

    def test_vendor_groups_created(self, tmp_path: Path):
        result = self._build(tmp_path)
        assert "vendor_cisco_ios" in result
        assert "vendor_nokia_sros" in result

    def test_vendor_group_in_all_children(self, tmp_path: Path):
        result = self._build(tmp_path)
        assert "vendor_cisco_ios" in result["all"]["children"]
        assert "vendor_nokia_sros" in result["all"]["children"]

    def test_vendor_group_members(self, tmp_path: Path):
        result = self._build(tmp_path)
        assert "router1" in result["vendor_cisco_ios"]["hosts"]
        assert "router2" in result["vendor_cisco_ios"]["hosts"]
        assert "pe1" in result["vendor_nokia_sros"]["hosts"]
        assert "router1" not in result["vendor_nokia_sros"]["hosts"]

    def test_site_groups_created(self, tmp_path: Path):
        result = self._build(tmp_path)
        assert "site_dc1" in result
        assert "site_dc2" in result

    def test_site_group_members(self, tmp_path: Path):
        result = self._build(tmp_path)
        assert "router1" in result["site_dc1"]["hosts"]
        assert "router2" in result["site_dc2"]["hosts"]
        # pe1 has no site — should not appear in any site group
        assert "pe1" not in result["site_dc1"]["hosts"]
        assert "pe1" not in result["site_dc2"]["hosts"]

    def test_role_groups_created(self, tmp_path: Path):
        result = self._build(tmp_path)
        assert "role_core" in result
        assert "role_edge" in result

    def test_role_group_members(self, tmp_path: Path):
        result = self._build(tmp_path)
        assert "router1" in result["role_core"]["hosts"]
        assert "pe1" in result["role_edge"]["hosts"]

    def test_no_duplicate_auto_group_overrides_explicit(self, tmp_path: Path):
        """Explicit groups are never overwritten by an auto-group with the same name."""
        from netops.ansible.dynamic_inventory import build_inventory
        import textwrap

        yaml_text = textwrap.dedent("""\
            devices:
              sw1:
                host: 1.1.1.1
                vendor: cisco_ios
                groups:
                  - vendor_cisco_ios
        """)
        inv_file = tmp_path / "inventory.yaml"
        inv_file.write_text(yaml_text)
        result = build_inventory(str(inv_file), no_cache=True)
        # Group exists and sw1 is in it
        assert "vendor_cisco_ios" in result
        assert "sw1" in result["vendor_cisco_ios"]["hosts"]

    def test_safe_group_name_normalisation(self):
        from netops.ansible.dynamic_inventory import _safe_group_name

        assert _safe_group_name("Cisco IOS") == "cisco_ios"
        assert _safe_group_name("dc-1") == "dc_1"
        assert _safe_group_name("SPINE/LEAF") == "spine_leaf"


# ===========================================================================
# Cache layer
# ===========================================================================


class TestCache:
    def test_cache_written_on_build(self, sample_inventory_file: Path, tmp_path: Path):
        from netops.ansible.dynamic_inventory import build_inventory

        cache_file = tmp_path / "cache.json"
        build_inventory(str(sample_inventory_file), cache_path=str(cache_file))
        assert cache_file.exists()

    def test_cache_contains_valid_json(self, sample_inventory_file: Path, tmp_path: Path):
        from netops.ansible.dynamic_inventory import build_inventory

        cache_file = tmp_path / "cache.json"
        build_inventory(str(sample_inventory_file), cache_path=str(cache_file))
        data = json.loads(cache_file.read_text())
        assert "_meta" in data

    def test_cache_hit_returns_same_result(self, sample_inventory_file: Path, tmp_path: Path):
        from netops.ansible.dynamic_inventory import build_inventory

        cache_file = tmp_path / "cache.json"
        first = build_inventory(str(sample_inventory_file), cache_path=str(cache_file))
        second = build_inventory(str(sample_inventory_file), cache_path=str(cache_file))
        assert first == second

    def test_no_cache_skips_read_and_write(
        self, sample_inventory_file: Path, tmp_path: Path
    ):
        from netops.ansible.dynamic_inventory import build_inventory

        cache_file = tmp_path / "cache.json"
        build_inventory(str(sample_inventory_file), cache_path=str(cache_file), no_cache=True)
        assert not cache_file.exists()

    def test_refresh_cache_ignores_existing(
        self, sample_inventory_file: Path, tmp_path: Path
    ):
        import time
        from netops.ansible.dynamic_inventory import build_inventory

        cache_file = tmp_path / "cache.json"
        # Write a stale cache manually
        cache_file.write_text(json.dumps({"_meta": {"hostvars": {}}, "stale": True}))
        # A small sleep ensures mtime differs
        time.sleep(0.01)
        result = build_inventory(
            str(sample_inventory_file),
            cache_path=str(cache_file),
            refresh_cache=True,
        )
        # Result should be the real inventory, not the stale one
        assert "stale" not in result
        assert "router1" in result["all"]["hosts"]

    def test_expired_cache_triggers_rebuild(
        self, sample_inventory_file: Path, tmp_path: Path
    ):
        import time
        from netops.ansible.dynamic_inventory import build_inventory

        cache_file = tmp_path / "cache.json"
        # Write a fake cache and immediately expire it via a zero TTL
        cache_file.write_text(json.dumps({"_meta": {"hostvars": {}}, "stale": True}))
        time.sleep(0.01)
        result = build_inventory(
            str(sample_inventory_file),
            cache_path=str(cache_file),
            cache_ttl=0,  # always expired
        )
        assert "stale" not in result
        assert "router1" in result["all"]["hosts"]

    def test_missing_inventory_raises_even_with_valid_cache(
        self, tmp_path: Path
    ):
        from netops.ansible.dynamic_inventory import build_inventory

        cache_file = tmp_path / "cache.json"
        # Seed a valid-looking cache
        cache_file.write_text(json.dumps({"_meta": {"hostvars": {}}}))
        with pytest.raises(FileNotFoundError):
            build_inventory(
                str(tmp_path / "nonexistent.yaml"),
                cache_path=str(cache_file),
                cache_ttl=9999,
            )


# ===========================================================================
# CLI new flags
# ===========================================================================


class TestDynamicInventoryCLIExtended:
    def _run(self, args: list[str]) -> "subprocess.CompletedProcess":  # type: ignore[name-defined]  # noqa: F821
        import subprocess
        import sys

        return subprocess.run(
            [sys.executable, "-m", "netops.ansible.dynamic_inventory"] + args,
            capture_output=True,
            text=True,
        )

    def test_list_no_cache_flag(self, sample_inventory_file: Path, tmp_path: Path):
        result = self._run(
            ["--list", "--inventory", str(sample_inventory_file), "--no-cache"]
        )
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert "_meta" in parsed

    def test_list_refresh_cache_flag(self, sample_inventory_file: Path, tmp_path: Path):
        cache_file = tmp_path / "cache.json"
        result = self._run(
            [
                "--list",
                "--inventory",
                str(sample_inventory_file),
                "--refresh-cache",
                "--cache-path",
                str(cache_file),
            ]
        )
        assert result.returncode == 0
        assert cache_file.exists()

    def test_list_custom_cache_ttl(self, sample_inventory_file: Path, tmp_path: Path):
        cache_file = tmp_path / "cache.json"
        result = self._run(
            [
                "--list",
                "--inventory",
                str(sample_inventory_file),
                "--cache-ttl",
                "600",
                "--cache-path",
                str(cache_file),
            ]
        )
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert "vendor_cisco_ios" in parsed

    def test_auto_groups_present_in_list(self, sample_inventory_file: Path):
        result = self._run(
            ["--list", "--inventory", str(sample_inventory_file), "--no-cache"]
        )
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert "vendor_cisco_ios" in parsed
        assert "site_dc1" in parsed
        assert "role_core" in parsed

    def test_auto_groups_in_all_children(self, sample_inventory_file: Path):
        result = self._run(
            ["--list", "--inventory", str(sample_inventory_file), "--no-cache"]
        )
        parsed = json.loads(result.stdout)
        children = parsed["all"]["children"]
        assert "vendor_cisco_ios" in children
        assert "site_dc1" in children
        assert "role_core" in children


# ===========================================================================
# Vault credential injection
# ===========================================================================


class TestVaultInjection:
    """Vault credentials are injected into hostvars when available."""

    def _make_vault(self, tmp_path: Path, password: str = "test123") -> Path:
        """Create a vault with one device entry and return its path."""
        from netops.core.vault import CredentialVault

        vault_path = tmp_path / "vault.yaml"
        vault = CredentialVault(vault_path=str(vault_path))
        vault.init(password)
        vault.set_device("router1", username="vaultuser", password="vaultpass")
        vault.save(password)
        return vault_path

    def test_vault_credentials_injected(
        self, sample_inventory_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        from netops.ansible.dynamic_inventory import build_inventory

        vault_path = self._make_vault(tmp_path)
        monkeypatch.setenv("NETOPS_VAULT_PASSWORD", "test123")

        result = build_inventory(
            str(sample_inventory_file),
            vault_path=str(vault_path),
            no_cache=True,
        )
        hv = result["_meta"]["hostvars"]["router1"]
        assert hv["ansible_user"] == "vaultuser"
        assert hv["ansible_password"] == "vaultpass"

    def test_vault_missing_password_env_skips_injection(
        self, sample_inventory_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        from netops.ansible.dynamic_inventory import build_inventory

        vault_path = self._make_vault(tmp_path)
        monkeypatch.delenv("NETOPS_VAULT_PASSWORD", raising=False)

        result = build_inventory(
            str(sample_inventory_file),
            vault_path=str(vault_path),
            no_cache=True,
        )
        # Without the password env var the vault is not opened; no credentials added
        hv = result["_meta"]["hostvars"]["router1"]
        assert "ansible_password" not in hv

    def test_no_vault_path_no_injection(
        self, sample_inventory_file: Path, tmp_path: Path
    ):
        from netops.ansible.dynamic_inventory import build_inventory

        result = build_inventory(
            str(sample_inventory_file),
            vault_path=None,
            no_cache=True,
        )
        hv = result["_meta"]["hostvars"]["router1"]
        assert "ansible_password" not in hv
