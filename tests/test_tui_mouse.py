"""Mouse interaction tests for the TUI.

These test real click events through Textual's pilot — no mocking.
Catches crashes from mouse clicks on various UI areas.
"""

import asyncio

import pytest
from textual.widgets import DataTable, Footer, Header


@pytest.mark.asyncio
async def test_click_on_populated_table_row():
    """Clicking a row in a populated DataTable must not crash."""
    from netops.tui import NetopsTUI

    app = NetopsTUI()
    app.inventory = {"devices": {"router1": {"host": "10.0.0.1", "vendor": "cisco"}}}
    async with app.run_test(size=(120, 40)) as pilot:
        table = app.query_one("#device-table", DataTable)
        await pilot.click(table, offset=(10, 2))


@pytest.mark.asyncio
async def test_click_on_empty_table_area():
    """Clicking empty space in the DataTable must not crash."""
    from netops.tui import NetopsTUI

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        table = app.query_one("#device-table", DataTable)
        await pilot.click(table, offset=(10, 10))


@pytest.mark.asyncio
async def test_click_on_header():
    """Clicking the Header widget must not crash."""
    from netops.tui import NetopsTUI

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        header = app.query_one(Header)
        await pilot.click(header)


@pytest.mark.asyncio
async def test_click_on_footer():
    """Clicking the Footer widget must not crash."""
    from netops.tui import NetopsTUI

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        footer = app.query_one(Footer)
        await pilot.click(footer)


@pytest.mark.asyncio
async def test_datatable_cursor_type_is_row():
    """DataTable must use cursor_type='row' for proper mouse selection."""
    from netops.tui import NetopsTUI

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        table = app.query_one("#device-table", DataTable)
        assert table.cursor_type == "row"


@pytest.mark.asyncio
async def test_row_selected_with_none_key_no_crash():
    """RowSelected handler must guard against None row_key."""
    from netops.tui import NetopsTUI

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        # Simulate a RowSelected event with None key
        table = app.query_one("#device-table", DataTable)
        event = DataTable.RowSelected(table, cursor_row=0, row_key=None)
        app.on_data_table_row_selected(event)
        # No crash = pass
