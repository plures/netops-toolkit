"""TUI integration tests — uses Textual's run_test() pilot.

Tests TUI startup, modal rendering, keybindings, and data refresh.
Uses monkeypatch to set INVENTORY_FILE correctly.
"""

from __future__ import annotations

import json

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
async def test_tui_starts_and_renders_table(inv_file):
    """TUI starts, renders device table from inventory file."""
    inv_file.write_text(json.dumps({
        "devices": {
            "router-01": {"host": "10.0.0.1", "vendor": "cisco_ios", "model": "ISR4451"},
            "switch-01": {"host": "10.0.0.2", "vendor": "brocade_fastiron"},
        }
    }))

    from netops.tui import NetopsTUI
    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        table = app.query_one("#device-table")
        assert table.row_count == 2


@pytest.mark.asyncio
async def test_tui_refresh_reloads_inventory(inv_file):
    """Refresh picks up new devices from disk."""
    from netops.tui import NetopsTUI
    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        table = app.query_one("#device-table")
        assert table.row_count == 0

        # Write new data
        inv_file.write_text(json.dumps({
            "devices": {"new-device": {"host": "10.0.0.5", "vendor": "cisco_ios"}}
        }))
        # Focus table (action_refresh guards against input-focused state)
        table.focus()
        await pilot.pause()
        app.action_refresh()
        await pilot.pause()
        assert table.row_count == 1


@pytest.mark.asyncio
async def test_tui_scan_modal_opens(inv_file):
    """push_screen(ScanScreen()) puts scan modal on stack."""
    from netops.tui import NetopsTUI, ScanScreen

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.push_screen(ScanScreen())
        await pilot.pause()

        scan_screens = [s for s in app.screen_stack if isinstance(s, ScanScreen)]
        assert len(scan_screens) == 1

        # Verify subnet input exists
        subnet_input = app.screen.query_one("#scan-subnet")
        assert subnet_input is not None


@pytest.mark.asyncio
async def test_tui_health_modal_opens(inv_file):
    """push_screen(HealthScreen()) puts health modal on stack."""
    from netops.tui import HealthScreen, NetopsTUI

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.push_screen(HealthScreen())
        await pilot.pause()

        health_screens = [s for s in app.screen_stack if isinstance(s, HealthScreen)]
        assert len(health_screens) == 1

        # Verify host input exists
        host_input = app.screen.query_one("#health-host")
        assert host_input is not None


@pytest.mark.asyncio
async def test_tui_scan_modal_cancel_dismisses(inv_file):
    """Cancel button in scan modal dismisses it."""
    from netops.tui import NetopsTUI, ScanScreen

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.push_screen(ScanScreen())
        await pilot.pause()

        # Press escape to dismiss
        await pilot.press("escape")
        await pilot.pause()

        scan_screens = [s for s in app.screen_stack if isinstance(s, ScanScreen)]
        assert len(scan_screens) == 0
