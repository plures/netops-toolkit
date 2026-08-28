"""Smoke tests for the TUI launching and basic interaction."""

import os
import subprocess
import sys

import pytest


@pytest.mark.asyncio
async def test_tui_launches():
    """The TUI app must start without crashing."""
    from netops.tui import NetopsTUI

    app = NetopsTUI()
    async with app.run_test() as _pilot:
        assert app.title == "netops-toolkit"


@pytest.mark.asyncio
async def test_tui_has_scan_panel():
    """The TUI must have the inventory scan panel accessible."""
    from netops.tui import NetopsTUI

    app = NetopsTUI()
    async with app.run_test() as _pilot:
        # The app should render without error
        # (if scan_subnet was still using asyncio.run, this wouldn't get here)
        assert app.is_running


@pytest.mark.asyncio
async def test_typing_in_input_doesnt_trigger_bindings():
    """Single-char app bindings must NOT fire when an Input has focus."""
    from textual.widgets import Input

    from netops.tui import NetopsTUI

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        search = app.query_one("#search-input", Input)
        search.focus()
        await pilot.press("p")
        await pilot.press("s")
        await pilot.press("h")
        await pilot.press("b")
        assert search.value == "pshb"
        # No modals pushed
        assert len(app.screen_stack) == 1


@pytest.mark.asyncio
async def test_space_selects_from_the_focused_table_without_exiting():
    """Space selection remains inside the focused table and leaves the TUI alive."""
    from textual.widgets import DataTable

    from netops.tui import NetopsTUI

    app = NetopsTUI()
    app.inventory = {"devices": {"edge-01": {"host": "10.0.0.1", "vendor": "cisco_ios"}}}
    async with app.run_test(size=(120, 40)) as pilot:
        table = app.query_one("#device-table", DataTable)
        table.focus()
        await pilot.press("space")
        await pilot.pause()
        assert app.is_running
        assert app._selected_hosts == {"edge-01"}


def test_compat_flag_configures_textual_before_the_app_imports():
    """Console-script imports honour --compat before Textual reads its settings."""
    environment = os.environ.copy()
    environment["TERM"] = "xterm-256color"
    environment.pop("NETOPS_TUI_COMPAT", None)
    environment.pop("TEXTUAL_COLOR_SYSTEM", None)
    script = (
        "import sys; "
        "sys.argv = ['netops-tui', '--compat']; "
        "import netops.tui; "
        "from textual.constants import COLOR_SYSTEM; "
        "print(COLOR_SYSTEM)"
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        env=environment,
        text=True,
    )

    assert result.stdout.strip() == "standard"


def test_compatibility_profile_uses_ascii_selection_markers(monkeypatch):
    """Compatibility terminals never need checkbox glyph support."""
    monkeypatch.setenv("NETOPS_TUI_COMPAT", "1")

    from netops.terminal import terminal_profile

    profile = terminal_profile()
    assert profile.compatibility_mode
    assert (profile.selected_marker, profile.unselected_marker) == ("[x]", "[ ]")


@pytest.mark.asyncio
async def test_paste_works_in_scan_modal():
    """Pasting text into scan modal Input fields must work."""
    from textual.events import Paste
    from textual.widgets import Input

    from netops.tui import NetopsTUI, ScanScreen

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(ScanScreen())
        await pilot.pause()
        screen = app.screen
        subnet_input = screen.query_one("#scan-subnet", Input)
        subnet_input.focus()
        await pilot.pause()
        app.post_message(Paste("10.0.0.0/24"))
        await pilot.pause()
        await pilot.pause()
        assert subnet_input.value == "10.0.0.0/24"


@pytest.mark.asyncio
async def test_paste_works_in_all_scan_fields():
    """Paste must work in every Input field in the scan modal."""
    from textual.events import Paste
    from textual.widgets import Input

    from netops.tui import NetopsTUI, ScanScreen

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(ScanScreen())
        await pilot.pause()
        screen = app.screen

        fields = ["#scan-subnet", "#scan-hosts-file", "#scan-community",
                  "#scan-user", "#scan-password"]
        for field_id in fields:
            inp = screen.query_one(field_id, Input)
            inp.focus()
            await pilot.pause()
            app.post_message(Paste(f"test-{field_id}"))
            await pilot.pause()
            await pilot.pause()
            assert inp.value == f"test-{field_id}", f"Paste failed for {field_id}: got '{inp.value}'"
            inp.value = ""  # clear for next


@pytest.mark.asyncio
async def test_scan_advanced_fields_and_actions_have_visible_labels():
    """Scan controls with default values must not rely on hidden placeholders."""
    from textual.widgets import Label

    from netops.tui import NetopsTUI, ScanScreen

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(ScanScreen())
        await pilot.pause()
        screen = app.screen
        expected_labels = {
            "#scan-snmp-port-label": "SNMP port",
            "#scan-snmp-timeout-label": "SNMP timeout (seconds)",
            "#scan-ping-workers-label": "Ping workers",
            "#scan-snmp-concurrency-label": "SNMP concurrency",
            "#scan-ssh-timeout-label": "SSH timeout (seconds)",
            "#scan-ssh-concurrency-label": "SSH concurrency",
        }
        for label_id, expected in expected_labels.items():
            assert str(screen.query_one(label_id, Label).render()) == expected

        assert {
            button.id: str(button.label)
            for button in screen.query("#scan-actions Button")
        } == {
            "btn-scan": "Scan",
            "btn-ping": "Ping Only",
            "btn-cancel-scan": "Cancel",
        }


@pytest.mark.asyncio
async def test_selected_device_prepopulates_health_check():
    """Selecting a device then pressing 'h' must pre-fill the host field."""
    from textual.widgets import DataTable, Input

    from netops.tui import NetopsTUI

    app = NetopsTUI()
    app.inventory = {"devices": {"core-rtr-01": {"host": "10.0.0.1", "vendor": "brocade_fastiron"}}}
    async with app.run_test(size=(120, 40)) as pilot:
        table = app.query_one("#device-table", DataTable)
        table.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert app._selected_host == "core-rtr-01"
        app.action_health()
        await pilot.pause()
        host_input = app.screen.query_one("#health-host", Input)
        assert host_input.value == "core-rtr-01"


@pytest.mark.asyncio
async def test_selected_device_prepopulates_config_push():
    """Selecting a device then pressing 'p' must pre-fill the host field."""
    from textual.widgets import DataTable, Input

    from netops.tui import NetopsTUI

    app = NetopsTUI()
    app.inventory = {"devices": {"sw-01": {"host": "10.0.0.5", "vendor": "cisco_ios"}}}
    async with app.run_test(size=(120, 40)) as pilot:
        table = app.query_one("#device-table", DataTable)
        table.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        app.action_push()
        await pilot.pause()
        host_input = app.screen.query_one("#push-hosts", Input)
        assert host_input.value == "sw-01"


@pytest.mark.asyncio
async def test_selected_device_prepopulates_backup():
    """Selecting a device then pressing 'b' must pre-fill the host field."""
    from textual.widgets import DataTable, Input

    from netops.tui import NetopsTUI

    app = NetopsTUI()
    app.inventory = {"devices": {"fw-01": {"host": "10.0.0.10", "vendor": "paloalto_panos"}}}
    async with app.run_test(size=(120, 40)) as pilot:
        table = app.query_one("#device-table", DataTable)
        table.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        app.action_backup()
        await pilot.pause()
        host_input = app.screen.query_one("#backup-hosts", Input)
        assert host_input.value == "fw-01"
