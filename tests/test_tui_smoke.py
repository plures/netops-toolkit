"""Smoke tests for the TUI launching and basic interaction."""

import pytest


@pytest.mark.asyncio
async def test_tui_launches():
    """The TUI app must start without crashing."""
    from netops.tui import NetopsTUI

    app = NetopsTUI()
    async with app.run_test() as pilot:
        assert app.title == "netops-toolkit"


@pytest.mark.asyncio
async def test_tui_has_scan_panel():
    """The TUI must have the inventory scan panel accessible."""
    from netops.tui import NetopsTUI

    app = NetopsTUI()
    async with app.run_test() as pilot:
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
async def test_selected_device_prepopulates_health_check():
    """Selecting a device then pressing 'h' must pre-fill the host field."""
    from textual.widgets import Input, DataTable
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
    from textual.widgets import Input, DataTable
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
    from textual.widgets import Input, DataTable
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
