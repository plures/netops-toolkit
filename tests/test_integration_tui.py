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
async def test_tui_scan_exposes_cli_tuning_defaults(inv_file, tmp_path, monkeypatch):
    """Scan uses persistent timeout and concurrency defaults instead of per-run fields."""
    from textual.widgets import Checkbox, Input, Label

    import netops.tui as tui_mod
    from netops.tui import NetopsTUI, ScanScreen

    monkeypatch.setattr(tui_mod, "SETTINGS_FILE", tmp_path / "tui-settings.json")
    app = NetopsTUI()
    async with app.run_test(size=(120, 50)) as pilot:
        app.push_screen(ScanScreen())
        await pilot.pause()
        screen = app.screen
        assert app.settings["snmp_port"] == 161
        assert app.settings["ssh_concurrency"] == 5
        assert "SNMP port 161" in str(screen.query_one("#scan-defaults-summary", Label).render())
        assert screen.query_one("#scan-skip-ping", Checkbox) is not None
        assert screen.query_one("#scan-output", Input) is not None


@pytest.mark.asyncio
async def test_tui_opens_diff_and_bastion_tools(inv_file):
    """The CLI-only diff and active bastion features are available in the TUI."""
    from textual.widgets import DataTable

    from netops.tui import BastionScreen, DiffScreen, NetopsTUI

    app = NetopsTUI()
    async with app.run_test(size=(120, 50)) as pilot:
        app.query_one("#device-table", DataTable).focus()
        await pilot.pause()
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
    from textual.widgets import Checkbox, Input, Label

    from netops.tui import BackupScreen, ConfigPushScreen, HealthScreen, NetopsTUI

    app = NetopsTUI()
    async with app.run_test(size=(120, 50)) as pilot:
        app.push_screen(HealthScreen())
        await pilot.pause()
        assert app.screen.query_one("#health-inventory", Input) is not None
        assert "Health defaults:" in str(app.screen.query_one("#health-defaults-summary", Label).render())
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
    from textual.widgets import DataTable

    from netops.tui import NetopsTUI

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
    from textual.widgets import Static

    from netops.tui import NetopsTUI

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


@pytest.mark.asyncio
async def test_tui_manual_inventory_editor_adds_a_device_without_a_scan(inv_file):
    """Operators can add an inventory target through the labelled TUI editor."""
    from textual.widgets import DataTable, Input, Label

    from netops.tui import InventoryEditorScreen, NetopsTUI

    app = NetopsTUI()
    async with app.run_test(size=(120, 100)) as pilot:
        app.action_add_inventory()
        await pilot.pause()
        assert isinstance(app.screen, InventoryEditorScreen)
        assert "Add inventory device" in str(app.screen.query_one("#inventory-editor-title", Label).render())

        values = {
            "#inventory-editor-hostname": "branch-rtr-01",
            "#inventory-editor-host": "192.0.2.44",
            "#inventory-editor-vendor": "cisco_ios",
            "#inventory-editor-transport": "ssh",
            "#inventory-editor-port": "2222",
            "#inventory-editor-model": "ISR4451",
            "#inventory-editor-site": "branch-01",
            "#inventory-editor-role": "edge",
            "#inventory-editor-groups": "routers, branch-01, routers",
            "#inventory-editor-tags": "environment=production,owner=noc",
        }
        for selector, value in values.items():
            app.screen.query_one(selector, Input).value = value

        await pilot.click("#btn-inventory-save")
        await pilot.pause()

        device = app.inventory["devices"]["branch-rtr-01"]
        assert device == {
            "host": "192.0.2.44",
            "vendor": "cisco_ios",
            "transport": "ssh",
            "port": 2222,
            "model": "ISR4451",
            "site": "branch-01",
            "role": "edge",
            "groups": ["routers", "branch-01"],
            "tags": {"environment": "production", "owner": "noc"},
        }
        assert json.loads(inv_file.read_text())["devices"]["branch-rtr-01"] == device
        assert app.query_one("#device-table", DataTable).row_count == 1
        assert app._selected_host == "branch-rtr-01"


@pytest.mark.asyncio
async def test_tui_manual_inventory_edit_retains_scan_metadata_and_renames_selection(inv_file):
    """Editing owned fields cannot discard discovery detail the editor does not show."""
    from textual.widgets import Input

    from netops.tui import InventoryEditorScreen, NetopsTUI

    app = NetopsTUI()
    app.inventory = {
        "devices": {
            "branch-rtr-01": {
                "host": "192.0.2.44",
                "vendor": "cisco_ios",
                "transport": "ssh",
                "memory": "4 GB",
                "mac_address": "00:11:22:33:44:55",
                "neighbors": ["branch-sw-01"],
                "community": "discovered-value",
            }
        }
    }
    app._selected_hosts = {"branch-rtr-01"}
    async with app.run_test(size=(120, 100)) as pilot:
        app.action_edit_inventory()
        await pilot.pause()
        assert isinstance(app.screen, InventoryEditorScreen)
        app.screen.query_one("#inventory-editor-hostname", Input).value = "branch-rtr-primary"
        app.screen.query_one("#inventory-editor-site", Input).value = "branch-01"
        app.screen.query_one("#inventory-editor-tags", Input).value = "owner=noc"

        await pilot.click("#btn-inventory-save")
        await pilot.pause()

        assert "branch-rtr-01" not in app.inventory["devices"]
        device = app.inventory["devices"]["branch-rtr-primary"]
        assert device["site"] == "branch-01"
        assert device["tags"] == {"owner": "noc"}
        assert device["memory"] == "4 GB"
        assert device["mac_address"] == "00:11:22:33:44:55"
        assert device["neighbors"] == ["branch-sw-01"]
        assert device["community"] == "discovered-value"
        assert app._selected_host == "branch-rtr-primary"
        assert app._selected_hosts == {"branch-rtr-primary"}


@pytest.mark.asyncio
async def test_tui_manual_inventory_editor_reports_current_validation_error(inv_file):
    """Invalid manual metadata stays in the editor with one current explanation."""
    from textual.widgets import Input, Label

    from netops.tui import NetopsTUI

    app = NetopsTUI()
    async with app.run_test(size=(120, 100)) as pilot:
        app.action_add_inventory()
        await pilot.pause()
        app.screen.query_one("#inventory-editor-hostname", Input).value = "branch router"
        app.screen.query_one("#inventory-editor-host", Input).value = "192.0.2.44"

        await pilot.click("#btn-inventory-save")
        await pilot.pause()

        validation = app.screen.query_one("#inventory-editor-validation", Label)
        assert "cannot contain spaces" in str(validation.render())
        assert app.inventory["devices"] == {}


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
