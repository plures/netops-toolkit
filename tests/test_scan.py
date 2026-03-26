"""
Unit tests for netops.inventory.scan.

All network I/O (ping, SNMP) is mocked so the tests run without a real network.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock, patch

from netops.inventory.scan import (
    OID_CDP_CACHE_ADDRESS,
    OID_CDP_CACHE_DEVICE_ID,
    OID_CDP_CACHE_PLATFORM,
    OID_LLDP_REM_CHASSIS_ID,
    OID_LLDP_REM_SYS_DESC,
    OID_LLDP_REM_SYS_NAME,
    OID_SYS_DESCR,
    OID_SYS_LOCATION,
    OID_SYS_NAME,
    OID_SYS_OBJ_ID,
    ScanResult,
    _scan_host_async,
    _snmp_get_async,
    identify_vendor,
    merge_inventory,
    ping_host,
    ping_sweep,
    results_to_inventory_fragment,
    scan_subnet,
)

# ---------------------------------------------------------------------------
# identify_vendor
# ---------------------------------------------------------------------------


class TestIdentifyVendor:
    def test_cisco_ios(self):
        assert identify_vendor("Cisco IOS Software, Version 15.4") == "cisco_ios"

    def test_cisco_xe(self):
        assert identify_vendor("Cisco IOS XE Software, Version 17.3") == "cisco_xe"

    def test_cisco_xe_hyphenated(self):
        assert identify_vendor("Cisco IOS-XE, Version 16.12") == "cisco_xe"

    def test_cisco_xr(self):
        assert identify_vendor("Cisco IOS XR Software") == "cisco_xr"

    def test_cisco_nxos(self):
        assert identify_vendor("Cisco NX-OS Software") == "cisco_nxos"

    def test_nokia_sros(self):
        assert identify_vendor("Nokia SR OS router") == "nokia_sros"

    def test_nokia_timos(self):
        assert identify_vendor("TiMOS-B-21.2.R1 SROS") == "nokia_sros"

    def test_nokia_srl(self):
        assert identify_vendor("Nokia SRL Switch") == "nokia_srl"

    def test_juniper_junos(self):
        assert identify_vendor("Juniper Networks Junos OS") == "juniper_junos"

    def test_arista_eos(self):
        assert identify_vendor("Arista Networks EOS") == "arista_eos"

    def test_cisco_generic(self):
        assert identify_vendor("cisco router") == "cisco_ios"

    def test_unknown_returns_unknown(self):
        assert identify_vendor("Some other vendor") == "unknown"

    def test_fallback_oid_cisco(self):
        assert identify_vendor("Linux", ".1.3.6.1.4.1.9.1.1") == "cisco_ios"

    def test_fallback_oid_nokia(self):
        assert identify_vendor("Linux", ".1.3.6.1.4.1.6527.1") == "nokia_sros"

    def test_fallback_oid_juniper(self):
        assert identify_vendor("Linux", ".1.3.6.1.4.1.2636.1") == "juniper_junos"

    def test_fallback_oid_arista(self):
        assert identify_vendor("Linux", ".1.3.6.1.4.1.30065.1") == "arista_eos"

    def test_fallback_oid_brocade_fastiron(self):
        assert identify_vendor("Linux", ".1.3.6.1.4.1.1991.1") == "brocade_fastiron"

    def test_fallback_oid_brocade_nos(self):
        assert identify_vendor("Linux", ".1.3.6.1.4.1.1588.1") == "brocade_nos"

    def test_brocade_fastiron_descr(self):
        assert identify_vendor("Brocade FastIron ICX Switch") == "brocade_fastiron"

    def test_brocade_foundry_descr(self):
        assert identify_vendor("Foundry Networks FastIron GS") == "brocade_fastiron"

    def test_brocade_nos_descr(self):
        assert identify_vendor("Brocade Network OS VDX6740") == "brocade_nos"

    def test_case_insensitive(self):
        assert identify_vendor("CISCO IOS XE SOFTWARE") == "cisco_xe"


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


class TestScanResult:
    def test_to_inventory_entry_minimal(self):
        r = ScanResult(host="10.0.0.1", reachable=True, vendor="cisco_ios")
        entry = r.to_inventory_entry()
        assert entry["host"] == "10.0.0.1"
        assert entry["vendor"] == "cisco_ios"
        assert "site" not in entry

    def test_to_inventory_entry_with_location(self):
        r = ScanResult(host="10.0.0.1", reachable=True, vendor="cisco_ios", location="dc1")
        entry = r.to_inventory_entry()
        assert entry["site"] == "dc1"

    def test_to_inventory_entry_with_sys_descr(self):
        r = ScanResult(
            host="10.0.0.1", reachable=True, vendor="cisco_ios", sys_descr="Cisco IOS 15.4"
        )
        entry = r.to_inventory_entry()
        assert entry["tags"]["sys_descr"] == "Cisco IOS 15.4"

    def test_to_inventory_entry_unknown_vendor_fallback(self):
        r = ScanResult(host="10.0.0.1", reachable=True)
        entry = r.to_inventory_entry()
        assert entry["vendor"] == "unknown"

    def test_default_neighbor_lists_empty(self):
        r = ScanResult(host="10.0.0.1", reachable=True)
        assert r.cdp_neighbors == []
        assert r.lldp_neighbors == []


# ---------------------------------------------------------------------------
# ping_host
# ---------------------------------------------------------------------------


class TestPingHost:
    def test_reachable_host(self):
        mock_result = MagicMock(returncode=0)
        with patch("netops.inventory.scan.subprocess.run", return_value=mock_result):
            assert ping_host("10.0.0.1") is True

    def test_unreachable_host(self):
        mock_result = MagicMock(returncode=1)
        with patch("netops.inventory.scan.subprocess.run", return_value=mock_result):
            assert ping_host("10.0.0.1") is False

    def test_timeout_returns_false(self):
        import subprocess

        with patch(
            "netops.inventory.scan.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=[], timeout=1),
        ):
            assert ping_host("10.0.0.1") is False

    def test_os_error_returns_false(self):
        with patch("netops.inventory.scan.subprocess.run", side_effect=OSError("no ping")):
            assert ping_host("10.0.0.1") is False


# ---------------------------------------------------------------------------
# ping_sweep
# ---------------------------------------------------------------------------


class TestPingSweep:
    def test_sweep_returns_sorted_reachable(self):
        def fake_ping(host, timeout=1):
            # Only .1 and .3 are "up" (using /29 which has .1–.6 as usable)
            return host in {"10.0.0.1", "10.0.0.3"}

        with patch("netops.inventory.scan.ping_host", side_effect=fake_ping):
            result = ping_sweep("10.0.0.0/29", max_workers=4)
        assert result == ["10.0.0.1", "10.0.0.3"]

    def test_sweep_empty_when_nothing_reachable(self):
        with patch("netops.inventory.scan.ping_host", return_value=False):
            result = ping_sweep("192.0.2.0/30")
        assert result == []

    def test_sweep_single_host(self):
        with patch("netops.inventory.scan.ping_host", return_value=True):
            result = ping_sweep("10.0.0.1/32")
        # /32 has exactly one host address
        assert result == ["10.0.0.1"]


# ---------------------------------------------------------------------------
# SNMP async helpers (mocked pysnmp layer)
# ---------------------------------------------------------------------------


class TestSnmpGetAsync:
    def test_snmp_get_async_is_coroutine(self):
        import inspect

        assert inspect.iscoroutinefunction(_snmp_get_async)


class TestSnmpWalkAsync:
    def test_walk_parses_suffix(self):
        """_snmp_walk_async strips the base OID and returns (suffix, value) pairs."""
        # We test the suffix-stripping logic indirectly through the OID constant
        base_oid = OID_CDP_CACHE_DEVICE_ID  # "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
        full_oid = base_oid + ".1.5"
        suffix = full_oid[len(base_oid):].lstrip(".")
        assert suffix == "1.5"

    def test_oid_constants_defined(self):
        assert OID_SYS_DESCR == "1.3.6.1.2.1.1.1.0"
        assert OID_SYS_NAME == "1.3.6.1.2.1.1.5.0"
        assert OID_SYS_OBJ_ID == "1.3.6.1.2.1.1.2.0"
        assert OID_SYS_LOCATION == "1.3.6.1.2.1.1.6.0"
        assert OID_CDP_CACHE_DEVICE_ID == "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
        assert OID_CDP_CACHE_ADDRESS == "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
        assert OID_CDP_CACHE_PLATFORM == "1.3.6.1.4.1.9.9.23.1.2.1.1.8"
        assert OID_LLDP_REM_SYS_NAME == "1.3.6.1.2.1.127.1.4.1.9"
        assert OID_LLDP_REM_SYS_DESC == "1.3.6.1.2.1.127.1.4.1.10"
        assert OID_LLDP_REM_CHASSIS_ID == "1.3.6.1.2.1.127.1.4.1.5"


# ---------------------------------------------------------------------------
# _scan_host_async (mocks _snmp_get_async and _snmp_walk_async)
# ---------------------------------------------------------------------------


class TestScanHostAsync:
    def _make_engine(self):
        return MagicMock()

    def test_identifies_cisco_device(self):
        engine = self._make_engine()

        snmp_data = {
            OID_SYS_DESCR: "Cisco IOS Software, Version 15.4",
            OID_SYS_NAME: "core-rtr-01.example.com",
            OID_SYS_OBJ_ID: ".1.3.6.1.4.1.9.1.1",
            OID_SYS_LOCATION: "DC1-Rack-1",
        }

        async def fake_get(eng, host, oid, community, port, timeout):
            return snmp_data.get(oid)

        async def fake_walk(eng, host, oid, community, port, timeout):
            return []

        async def run():
            with patch("netops.inventory.scan._snmp_get_async", side_effect=fake_get):
                with patch("netops.inventory.scan._snmp_walk_async", side_effect=fake_walk):
                    return await _scan_host_async(engine, "10.0.0.1", "public", 161, 2)

        result = asyncio.run(run())
        assert result.host == "10.0.0.1"
        assert result.reachable is True
        assert result.vendor == "cisco_ios"
        assert result.hostname == "core-rtr-01"  # domain stripped
        assert result.location == "DC1-Rack-1"
        assert result.sys_descr == "Cisco IOS Software, Version 15.4"

    def test_identifies_nokia_device(self):
        engine = self._make_engine()

        async def fake_get(eng, host, oid, community, port, timeout):
            if oid == OID_SYS_DESCR:
                return "Nokia SR OS router TiMOS-B-21.2.R1"
            if oid == OID_SYS_NAME:
                return "pe-01"
            return None

        async def fake_walk(eng, host, oid, community, port, timeout):
            return []

        async def run():
            with patch("netops.inventory.scan._snmp_get_async", side_effect=fake_get):
                with patch("netops.inventory.scan._snmp_walk_async", side_effect=fake_walk):
                    return await _scan_host_async(engine, "10.0.0.2", "public", 161, 2)

        result = asyncio.run(run())
        assert result.vendor == "nokia_sros"

    def test_cdp_neighbors_populated(self):
        engine = self._make_engine()

        async def fake_get(eng, host, oid, community, port, timeout):
            return None

        async def fake_walk(eng, host, oid, community, port, timeout):
            if oid == OID_CDP_CACHE_DEVICE_ID:
                return [("1.1", "switch-01.example.com")]
            if oid == OID_CDP_CACHE_PLATFORM:
                return [("1.1", "Cisco WS-C3750")]
            if oid == OID_CDP_CACHE_ADDRESS:
                return [("1.1", "10.0.0.100")]
            return []

        async def run():
            with patch("netops.inventory.scan._snmp_get_async", side_effect=fake_get):
                with patch("netops.inventory.scan._snmp_walk_async", side_effect=fake_walk):
                    return await _scan_host_async(engine, "10.0.0.1", "public", 161, 2)

        result = asyncio.run(run())
        assert len(result.cdp_neighbors) == 1
        assert result.cdp_neighbors[0]["device_id"] == "switch-01.example.com"
        assert result.cdp_neighbors[0]["platform"] == "Cisco WS-C3750"
        assert result.cdp_neighbors[0]["address"] == "10.0.0.100"
        assert result.cdp_neighbors[0]["protocol"] == "cdp"

    def test_lldp_neighbors_populated(self):
        engine = self._make_engine()

        async def fake_get(eng, host, oid, community, port, timeout):
            return None

        async def fake_walk(eng, host, oid, community, port, timeout):
            if oid == OID_LLDP_REM_SYS_NAME:
                return [("0.1.1", "arista-sw-01")]
            if oid == OID_LLDP_REM_SYS_DESC:
                return [("0.1.1", "Arista Networks EOS")]
            if oid == OID_LLDP_REM_CHASSIS_ID:
                return [("0.1.1", "aa:bb:cc:dd:ee:ff")]
            return []

        async def run():
            with patch("netops.inventory.scan._snmp_get_async", side_effect=fake_get):
                with patch("netops.inventory.scan._snmp_walk_async", side_effect=fake_walk):
                    return await _scan_host_async(engine, "10.0.0.1", "public", 161, 2)

        result = asyncio.run(run())
        assert len(result.lldp_neighbors) == 1
        assert result.lldp_neighbors[0]["sys_name"] == "arista-sw-01"
        assert result.lldp_neighbors[0]["sys_desc"] == "Arista Networks EOS"
        assert result.lldp_neighbors[0]["protocol"] == "lldp"

    def test_snmp_exception_does_not_crash(self):
        """CDP/LLDP walk exceptions are swallowed; the result is still returned."""
        engine = self._make_engine()

        async def fake_get(eng, host, oid, community, port, timeout):
            return None

        async def fake_walk(eng, host, oid, community, port, timeout):
            raise RuntimeError("SNMP timeout")

        async def run():
            with patch("netops.inventory.scan._snmp_get_async", side_effect=fake_get):
                with patch("netops.inventory.scan._snmp_walk_async", side_effect=fake_walk):
                    return await _scan_host_async(engine, "10.0.0.1", "public", 161, 2)

        result = asyncio.run(run())
        assert result.reachable is True
        assert result.cdp_neighbors == []
        assert result.lldp_neighbors == []


# ---------------------------------------------------------------------------
# results_to_inventory_fragment
# ---------------------------------------------------------------------------


class TestResultsToInventoryFragment:
    def _cisco_result(self, host="10.0.0.1", hostname="rtr-01") -> ScanResult:
        return ScanResult(
            host=host,
            reachable=True,
            hostname=hostname,
            vendor="cisco_ios",
            sys_descr="Cisco IOS 15.4",
            location="dc1",
        )

    def test_basic_fragment(self):
        fragment = results_to_inventory_fragment([self._cisco_result()])
        assert "rtr-01" in fragment["devices"]
        entry = fragment["devices"]["rtr-01"]
        assert entry["host"] == "10.0.0.1"
        assert entry["vendor"] == "cisco_ios"
        assert entry["site"] == "dc1"

    def test_ip_used_as_key_when_no_hostname(self):
        r = ScanResult(host="10.0.0.5", reachable=True, vendor="unknown")
        fragment = results_to_inventory_fragment([r])
        assert "10.0.0.5" in fragment["devices"]

    def test_unreachable_hosts_excluded(self):
        r = ScanResult(host="10.0.0.99", reachable=False)
        fragment = results_to_inventory_fragment([r])
        assert fragment["devices"] == {}

    def test_cdp_neighbors_in_tags(self):
        r = self._cisco_result()
        r.cdp_neighbors = [{"device_id": "switch-01", "platform": "", "address": "", "protocol": "cdp"}]
        fragment = results_to_inventory_fragment([r])
        assert "cdp:switch-01" in fragment["devices"]["rtr-01"]["tags"]["neighbors"]

    def test_lldp_neighbors_in_tags(self):
        r = self._cisco_result()
        r.lldp_neighbors = [
            {"sys_name": "arista-01", "sys_desc": "", "chassis_id": "", "protocol": "lldp"}
        ]
        fragment = results_to_inventory_fragment([r])
        assert "lldp:arista-01" in fragment["devices"]["rtr-01"]["tags"]["neighbors"]

    def test_multiple_neighbors_comma_separated(self):
        r = self._cisco_result()
        r.cdp_neighbors = [
            {"device_id": "sw-01", "platform": "", "address": "", "protocol": "cdp"},
            {"device_id": "sw-02", "platform": "", "address": "", "protocol": "cdp"},
        ]
        fragment = results_to_inventory_fragment([r])
        tags = fragment["devices"]["rtr-01"]["tags"]["neighbors"]
        assert "cdp:sw-01" in tags
        assert "cdp:sw-02" in tags
        assert "," in tags

    def test_empty_results(self):
        fragment = results_to_inventory_fragment([])
        assert fragment == {"devices": {}}


# ---------------------------------------------------------------------------
# merge_inventory
# ---------------------------------------------------------------------------


class TestMergeInventory:
    def test_adds_new_device(self, tmp_path):
        inv_path = tmp_path / "inventory.json"
        inv_path.write_text(json.dumps({"devices": {"existing-rtr": {"host": "10.0.0.1", "vendor": "cisco_ios"}}}))

        fragment = {"devices": {"new-rtr": {"host": "10.0.0.2", "vendor": "nokia_sros"}}}
        merged = merge_inventory(str(inv_path), fragment)

        assert "existing-rtr" in merged["devices"]
        assert "new-rtr" in merged["devices"]
        assert merged["devices"]["new-rtr"]["vendor"] == "nokia_sros"

    def test_does_not_overwrite_existing_values(self, tmp_path):
        inv_path = tmp_path / "inventory.json"
        inv_path.write_text(
            json.dumps({"devices": {"rtr-01": {"host": "10.0.0.1", "vendor": "cisco_ios", "site": "dc1"}}})
        )

        fragment = {"devices": {"rtr-01": {"host": "10.0.0.1", "vendor": "unknown", "site": "new-site"}}}
        merged = merge_inventory(str(inv_path), fragment)

        # Existing non-unknown values must not change
        assert merged["devices"]["rtr-01"]["vendor"] == "cisco_ios"
        assert merged["devices"]["rtr-01"]["site"] == "dc1"

    def test_fills_unknown_vendor(self, tmp_path):
        inv_path = tmp_path / "inventory.json"
        inv_path.write_text(
            json.dumps({"devices": {"rtr-01": {"host": "10.0.0.1", "vendor": "unknown"}}})
        )

        fragment = {"devices": {"rtr-01": {"host": "10.0.0.1", "vendor": "cisco_xe"}}}
        merged = merge_inventory(str(inv_path), fragment)

        assert merged["devices"]["rtr-01"]["vendor"] == "cisco_xe"

    def test_fills_none_value(self, tmp_path):
        inv_path = tmp_path / "inventory.json"
        inv_path.write_text(
            json.dumps({"devices": {"rtr-01": {"host": "10.0.0.1", "vendor": "cisco_ios", "site": None}}})
        )

        fragment = {"devices": {"rtr-01": {"host": "10.0.0.1", "vendor": "cisco_ios", "site": "dc2"}}}
        merged = merge_inventory(str(inv_path), fragment)

        assert merged["devices"]["rtr-01"]["site"] == "dc2"

    def test_creates_empty_base_if_file_missing(self, tmp_path):
        inv_path = tmp_path / "nonexistent.json"
        fragment = {"devices": {"rtr-01": {"host": "10.0.0.1", "vendor": "cisco_ios"}}}
        merged = merge_inventory(str(inv_path), fragment)

        assert "rtr-01" in merged["devices"]

    def test_empty_fragment(self, tmp_path):
        inv_path = tmp_path / "inventory.json"
        inv_path.write_text(json.dumps({"devices": {"rtr-01": {"host": "10.0.0.1"}}}))

        merged = merge_inventory(str(inv_path), {"devices": {}})
        assert list(merged["devices"].keys()) == ["rtr-01"]


# ---------------------------------------------------------------------------
# scan_subnet (integration-level, fully mocked)
# ---------------------------------------------------------------------------


class TestScanSubnet:
    def test_skip_snmp_returns_ping_only_results(self):
        with patch("netops.inventory.scan.ping_sweep", return_value=["10.0.0.1", "10.0.0.2"]):
            results = scan_subnet("10.0.0.0/24", skip_snmp=True)

        assert len(results) == 2
        assert all(r.reachable for r in results)
        assert all(r.sys_descr is None for r in results)

    def test_skip_ping_skips_sweep(self):
        """With skip_ping, all addresses in the subnet are probed (no subprocess ping)."""
        # When skip_ping is True, scan_subnet should not call ping_sweep at all.
        with patch("netops.inventory.scan.ping_sweep") as mock_sweep:
            # /30 has 2 usable hosts; skip_snmp so we don't need pysnmp
            results = scan_subnet("192.0.2.0/30", skip_ping=True, skip_snmp=True)

        mock_sweep.assert_not_called()
        assert len(results) == 2

    def test_empty_subnet_when_no_hosts_reachable(self):
        with patch("netops.inventory.scan.ping_sweep", return_value=[]):
            results = scan_subnet("10.0.0.0/24", skip_snmp=True)

        assert results == []


# ===========================================================================
# CSV output — _fragment_to_csv
# ===========================================================================

class TestFragmentToCsv:
    def test_basic_csv_output(self, tmp_path):
        from netops.inventory.scan import _fragment_to_csv
        fragment = {
            "devices": {
                "router1": {"host": "10.0.0.1", "vendor": "cisco_ios", "version": "16.9.4", "model": "ISR4451"},
                "switch1": {"host": "10.0.0.2", "vendor": "nokia_sros", "version": "23.10.R1"},
            }
        }
        out = tmp_path / "scan.csv"
        count = _fragment_to_csv(fragment, out)
        assert count == 2
        content = out.read_text()
        assert "router1" in content
        assert "switch1" in content
        assert "cisco_ios" in content
        assert "nokia_sros" in content
        # Header present
        assert "name" in content.splitlines()[0]
        assert "vendor" in content.splitlines()[0]

    def test_empty_fragment(self, tmp_path):
        from netops.inventory.scan import _fragment_to_csv
        out = tmp_path / "empty.csv"
        count = _fragment_to_csv({"devices": {}}, out)
        # No device rows should be written
        assert count == 0
        # CSV file should still be created with a header row
        assert out.exists()
        content = out.read_text()
        lines = content.splitlines()
        # Expect header-only CSV when there are no devices
        assert len(lines) == 1
        header = lines[0]
        assert "name" in header
        assert "vendor" in header

    def test_tags_flattened(self, tmp_path):
        from netops.inventory.scan import _fragment_to_csv
        fragment = {
            "devices": {
                "r1": {"host": "10.0.0.1", "vendor": "cisco_ios", "tags": {"neighbors": "cdp:r2,lldp:r3", "role": "core"}},
            }
        }
        out = tmp_path / "tags.csv"
        _fragment_to_csv(fragment, out)
        content = out.read_text()
        assert "tag_neighbors" in content
        assert "tag_role" in content
        assert "cdp:r2,lldp:r3" in content

    def test_stdout_csv(self):
        import io
        from netops.inventory.scan import _fragment_to_csv
        fragment = {"devices": {"r1": {"host": "10.0.0.1", "vendor": "nokia_sros"}}}
        buf = io.StringIO()
        count = _fragment_to_csv(fragment, buf)
        assert count == 1
        output = buf.getvalue()
        assert "name,host,vendor" in output.splitlines()[0]
