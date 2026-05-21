"""Test that scan ALWAYS collects device info when creds are available.

No conditions. No 'only unknowns'. If you have creds, every device gets
deep_enrich called. Period.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def inv_file(tmp_path, monkeypatch):
    """Provide a temp inventory file and patch the TUI module to use it."""
    inv_path = tmp_path / "inventory.json"
    inv_path.write_text(json.dumps({"devices": {}}))
    import netops.tui as tui_mod
    monkeypatch.setattr(tui_mod, "INVENTORY_FILE", inv_path)
    return inv_path


@pytest.mark.asyncio
async def test_scan_enriches_ALL_devices_when_creds_provided(inv_file, monkeypatch):
    """Even devices with known vendors get deep enriched when SSH creds provided."""
    from netops.tui import NetopsTUI, ScanScreen
    import netops.tui as tui_mod

    # Track whether deep_enrich was called
    enrich_called = {"called": False, "fragment": None}

    def fake_deep_enrich(fragment, username, password, **kwargs):
        enrich_called["called"] = True
        enrich_called["fragment"] = json.loads(json.dumps(fragment))  # snapshot
        # Simulate enrichment — add version/model/serial
        for name, info in fragment.get("devices", {}).items():
            info["version"] = "17.06.05"
            info["model"] = "ISR4451"
            info["serial"] = "FTX1234ABCD"
        return fragment

    async def fake_scan_subnet_async(subnet, community, skip_snmp=False, **kw):
        from netops.inventory.scan import ScanResult
        # Return devices that ALREADY have known vendors (the key case)
        return [
            ScanResult(host="10.0.0.1", reachable=True, vendor="cisco_ios",
                       hostname="router-01", sys_descr="Cisco IOS XE"),
            ScanResult(host="10.0.0.2", reachable=True, vendor="nokia_sros",
                       hostname="pe-router", sys_descr="TiMOS-B-22.7.R2"),
            ScanResult(host="10.0.0.3", reachable=True, vendor="unknown",
                       hostname=None, sys_descr=None),
        ]

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        # Open scan modal via push_screen (same as existing tests)
        app.push_screen(ScanScreen())
        await pilot.pause()

        # Fill in subnet and creds
        subnet_input = app.screen.query_one("#scan-subnet")
        subnet_input.value = "10.0.0.0/24"
        await pilot.pause()

        user_input = app.screen.query_one("#scan-user")
        user_input.value = "admin"
        await pilot.pause()

        pass_input = app.screen.query_one("#scan-password")
        pass_input.value = "secret123"
        await pilot.pause()

        # Patch scan and enrich BEFORE clicking Scan
        monkeypatch.setattr(
            "netops.inventory.scan.scan_subnet_async", fake_scan_subnet_async
        )
        monkeypatch.setattr(
            "netops.inventory.scan.deep_enrich", fake_deep_enrich
        )

        await pilot.click("#btn-scan")
        # Give scan time to complete
        await pilot.pause(delay=2.0)

    # THE CRITICAL ASSERTION: deep_enrich was called even though 2/3 devices
    # already had known vendors. No conditional. Creds = enrich all.
    assert enrich_called["called"], (
        "deep_enrich was NOT called! The scan should ALWAYS enrich "
        "when credentials are provided, regardless of vendor status."
    )
    # Verify ALL devices were passed to deep_enrich (not just unknowns)
    enriched_devices = enrich_called["fragment"]["devices"]
    assert len(enriched_devices) == 3, (
        f"Expected all 3 devices passed to deep_enrich, got {len(enriched_devices)}"
    )


@pytest.mark.asyncio
async def test_scan_does_NOT_enrich_without_creds(inv_file, monkeypatch):
    """Without SSH creds, deep_enrich should NOT be called."""
    from netops.tui import NetopsTUI, ScanScreen

    enrich_called = {"called": False}

    def fake_deep_enrich(fragment, **kwargs):
        enrich_called["called"] = True
        return fragment

    async def fake_scan_subnet_async(subnet, community, skip_snmp=False, **kw):
        from netops.inventory.scan import ScanResult
        return [
            ScanResult(host="10.0.0.1", reachable=True, vendor="unknown",
                       hostname=None, sys_descr=None),
        ]

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.push_screen(ScanScreen())
        await pilot.pause()

        subnet_input = app.screen.query_one("#scan-subnet")
        subnet_input.value = "10.0.0.0/24"
        await pilot.pause()

        # NO creds entered

        monkeypatch.setattr(
            "netops.inventory.scan.scan_subnet_async", fake_scan_subnet_async
        )
        monkeypatch.setattr(
            "netops.inventory.scan.deep_enrich", fake_deep_enrich
        )
        await pilot.click("#btn-scan")
        await pilot.pause(delay=2.0)

    assert not enrich_called["called"], (
        "deep_enrich should NOT be called when no SSH credentials are provided"
    )


def test_deep_enrich_processes_known_vendor_devices():
    """deep_enrich processes devices even when they already have a known vendor.

    This tests the scan.py deep_enrich function directly — it should attempt
    SSH on ALL devices, not skip ones with known vendors.
    """
    from unittest.mock import patch as _patch
    from netops.inventory.scan import deep_enrich

    fragment = {
        "devices": {
            "router-01": {"host": "10.0.0.1", "vendor": "cisco_ios"},
            "switch-01": {"host": "10.0.0.2", "vendor": "arista_eos"},
            "mystery": {"host": "10.0.0.3", "vendor": "unknown"},
        }
    }

    hosts_scanned = []

    def mock_deep_scan_host(host, username, password, known_vendor=None, timeout=15, port=None):
        hosts_scanned.append(host)
        return {
            "vendor": known_vendor or "cisco_ios",
            "version": "17.06.05",
            "model": "C9300",
            "serial": "FCW1234",
            "hostname": None, "uptime": None, "image": None,
            "hardware_revision": None, "total_memory": None,
            "free_memory": None, "reload_reason": None,
            "mac_address": None, "config_register": None,
            "cpu_type": None, "flash_size": None,
            "domain_name": None, "interface_count": None,
            "error": None,
        }

    with _patch("netops.inventory.scan._deep_scan_host", mock_deep_scan_host):
        result = deep_enrich(fragment, username="admin", password="secret")

    # ALL 3 hosts must be scanned — not just the unknown one
    assert sorted(hosts_scanned) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"], (
        f"Expected all 3 hosts scanned, got: {hosts_scanned}. "
        "deep_enrich must not skip devices with known vendors."
    )
