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


@pytest.mark.asyncio
async def test_tui_scan_exposes_cli_tuning_controls(inv_file):
    """Scan modal exposes the timeout, concurrency, and probe controls from the CLI."""
    from netops.tui import NetopsTUI, ScanScreen
    from textual.widgets import Checkbox, Input

    app = NetopsTUI()
    async with app.run_test(size=(120, 50)) as pilot:
        app.push_screen(ScanScreen())
        await pilot.pause()
        screen = app.screen
        assert screen.query_one("#scan-snmp-port", Input).value == "161"
        assert screen.query_one("#scan-ssh-concurrency", Input).value == "5"
        assert screen.query_one("#scan-skip-ping", Checkbox) is not None
        assert screen.query_one("#scan-output", Input) is not None


@pytest.mark.asyncio
async def test_tui_opens_diff_and_bastion_tools(inv_file):
    """The CLI-only diff and active bastion features are available in the TUI."""
    from netops.tui import BastionScreen, DiffScreen, NetopsTUI

    app = NetopsTUI()
    async with app.run_test(size=(120, 50)) as pilot:
        app.action_diff()
        await pilot.pause()
        assert isinstance(app.screen, DiffScreen)
        await pilot.press("escape")
        await pilot.pause()
        app.action_bastion()
        await pilot.pause()
        assert isinstance(app.screen, BastionScreen)


@pytest.mark.asyncio
async def test_tui_forms_expose_cli_equivalent_options(inv_file):
    """Health, backup, and push forms retain their CLI safety and scope options."""
    from netops.tui import BackupScreen, ConfigPushScreen, HealthScreen, NetopsTUI
    from textual.widgets import Checkbox, Input

    app = NetopsTUI()
    async with app.run_test(size=(120, 50)) as pilot:
        app.push_screen(HealthScreen())
        await pilot.pause()
        assert app.screen.query_one("#health-inventory", Input) is not None
        assert app.screen.query_one("#health-threshold", Input) is not None
        assert app.screen.query_one("#health-fail-on-alert", Checkbox) is not None
        await pilot.press("escape")
        await pilot.pause()

        app.push_screen(BackupScreen())
        await pilot.pause()
        assert app.screen.query_one("#backup-inventory", Input) is not None
        assert app.screen.query_one("#backup-git", Checkbox) is not None
        await pilot.press("escape")
        await pilot.pause()

        app.push_screen(ConfigPushScreen())
        await pilot.pause()
        assert app.screen.query_one("#push-transport", Input).value == "ssh"
        assert app.screen.query_one("#push-changelog", Input) is not None


@pytest.mark.asyncio
async def test_tui_selection_drives_bulk_operation_hosts(inv_file):
    """Space selection is visible and takes precedence over the focused device."""
    from netops.tui import NetopsTUI
    from textual.widgets import DataTable

    app = NetopsTUI()
    app.inventory = {
        "devices": {
            "core-rtr-01": {"host": "10.0.0.1", "vendor": "cisco_ios"},
            "sw-floor2": {"host": "10.0.0.2", "vendor": "cisco_ios"},
        }
    }
    async with app.run_test(size=(120, 50)) as pilot:
        table = app.query_one("#device-table", DataTable)
        table.focus()
        await pilot.pause()
        app._selected_host = "core-rtr-01"
        app.action_toggle_selection()
        assert app.operation_hosts() == ["core-rtr-01"]
        assert "core-rtr-01" in app._selected_hosts
        app.action_toggle_all_selection()
        assert app.operation_hosts() == ["core-rtr-01", "sw-floor2"]


@pytest.mark.asyncio
async def test_tui_detail_cycles_basic_and_extended_fields(inv_file):
    """The detail pane follows the redesign's basic then extended behavior."""
    from netops.tui import NetopsTUI
    from textual.widgets import Static

    app = NetopsTUI()
    app.inventory = {
        "devices": {
            "router-01": {
                "host": "10.0.0.1",
                "vendor": "cisco_ios",
                "model": "ISR",
                "memory": "4 GB",
                "neighbors": ["switch-01"],
            }
        }
    }
    async with app.run_test(size=(120, 50)) as _pilot:
        app._selected_host = "router-01"
        app._detail_extended = False
        app._render_detail()
        detail = app.query_one("#detail-content", Static).render()
        assert "memory" not in str(detail).lower()
        app._detail_extended = True
        app._render_detail()
        detail = app.query_one("#detail-content", Static).render()
        assert "memory" in str(detail).lower()


def test_tui_settings_are_non_secret_and_persist(tmp_path, monkeypatch):
    """Settings store operational defaults only and retain them across launches."""
    import netops.tui as tui_mod

    monkeypatch.setattr(tui_mod, "SETTINGS_FILE", tmp_path / "tui-settings.json")
    settings = tui_mod.load_settings()
    assert "password" not in settings
    settings["ping_workers"] = 17
    tui_mod.save_settings(settings)
    assert tui_mod.load_settings()["ping_workers"] == 17


def test_tui_does_not_override_native_paste_handlers():
    """Textual owns bracketed paste and clipboard handling for input widgets."""
    from netops.tui import NetopsTUI, ScanScreen

    assert "on_paste" not in NetopsTUI.__dict__
    assert "on_paste" not in ScanScreen.__dict__
