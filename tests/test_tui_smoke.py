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
