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
    """Scan controls render labelled, visible, editable fields at a normal terminal width."""
    from textual.widgets import Input, Label

    from netops.tui import NetopsTUI, ScanScreen

    app = NetopsTUI()
    async with app.run_test(size=(80, 40)) as pilot:
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
        input_ids = {
            "#scan-snmp-port-label": "#scan-snmp-port",
            "#scan-snmp-timeout-label": "#scan-snmp-timeout",
            "#scan-ping-workers-label": "#scan-ping-workers",
            "#scan-snmp-concurrency-label": "#scan-snmp-concurrency",
            "#scan-ssh-timeout-label": "#scan-ssh-timeout",
            "#scan-ssh-concurrency-label": "#scan-ssh-concurrency",
        }
        for label_id, expected in expected_labels.items():
            label = screen.query_one(label_id, Label)
            field = screen.query_one(input_ids[label_id], Input)
            assert str(label.render()) == expected
            assert label.region.width >= len(expected)
            assert field.region.width >= 12
            assert field.region.height == 3
            assert field.region.y == label.region.bottom

            original_value = field.value
            unfocused_border = field.styles.border_top
            unfocused_color = field.styles.color
            unfocused_background = field.styles.background
            assert unfocused_border[0] == "solid"
            assert field.styles.border_left == unfocused_border
            assert field.styles.border_right == unfocused_border
            assert field.styles.border_bottom == unfocused_border
            assert field.styles.border_top == unfocused_border
            assert unfocused_color != unfocused_background
            assert unfocused_color.a > 0.5

            field.focus()
            await pilot.pause()
            focused_border = field.styles.border_top
            assert focused_border[0] == "solid"
            assert focused_border[1] != unfocused_border[1]
            assert field.styles.color == unfocused_color
            assert field.styles.background == unfocused_background
            field.blur()
            await pilot.pause()
            field.value = original_value

        snmp_port = screen.query_one("#scan-snmp-port", Input)
        snmp_port.focus()
        snmp_port.select_all()
        await pilot.press("1", "6", "2")
        assert snmp_port.value == "162"

        assert {
            button.id: str(button.label)
            for button in screen.query("#scan-actions Button")
        } == {
            "btn-scan": "Scan",
            "btn-ping": "Ping Only",
            "btn-cancel-scan": "Cancel",
        }


@pytest.mark.asyncio
async def test_every_modal_action_row_preserves_full_button_labels():
    """Action rows reserve all three terminal lines needed by Textual buttons."""
    from textual.widgets import Button

    from netops.tui import (
        BackupScreen,
        BastionScreen,
        ConfigPushScreen,
        DiffScreen,
        HealthScreen,
        NetopsTUI,
        ScanScreen,
        SettingsScreen,
        VaultScreen,
    )

    for screen_type in (
        ScanScreen,
        HealthScreen,
        DiffScreen,
        BastionScreen,
        SettingsScreen,
        VaultScreen,
        ConfigPushScreen,
        BackupScreen,
    ):
        app = NetopsTUI()
        async with app.run_test(size=(120, 100)) as pilot:
            app.push_screen(screen_type())
            await pilot.pause()
            buttons = list(app.screen.query(Button))
            assert buttons, f"{screen_type.__name__} must expose an action button"
            for button in buttons:
                assert str(button.label), f"{screen_type.__name__} has an unlabeled button"
                assert button.region.height >= 3, f"{button.id} is clipped to fewer than three rows"
            for action_row in app.screen.query(".modal-actions"):
                assert action_row.region.height >= 3
                siblings = list(action_row.parent.children)
                next_index = siblings.index(action_row) + 1
                if next_index < len(siblings):
                    assert action_row.region.bottom <= siblings[next_index].region.y


@pytest.mark.asyncio
async def test_running_config_without_credentials_opens_guided_vault():
    """The running-config action must explain the credential path, not just fail."""
    from textual.widgets import DataTable, Label

    from netops.tui import NetopsTUI, VaultScreen

    app = NetopsTUI()
    app.inventory = {"devices": {"edge-01": {"host": "10.0.0.1", "vendor": "cisco_ios"}}}
    async with app.run_test(size=(120, 40)) as pilot:
        table = app.query_one("#device-table", DataTable)
        table.focus()
        app.action_running_config()
        await pilot.pause()

        assert isinstance(app.screen, VaultScreen)
        guidance = app.screen.query_one(".vault-guidance", Label)
        assert "Running configuration needs SSH credentials" in str(guidance.render())


@pytest.mark.asyncio
async def test_nonfatal_worker_error_keeps_the_tui_running():
    """Background failures must not return the user to the terminal prompt."""
    from netops.tui import NetopsTUI

    async def fail() -> None:
        raise RuntimeError("simulated worker failure")

    app = NetopsTUI()
    async with app.run_test() as pilot:
        app.run_worker(fail(), name="test failure", exit_on_error=False)
        await pilot.pause()
        assert app.is_running


@pytest.mark.asyncio
async def test_unhandled_tui_event_is_contained_instead_of_exiting():
    """Textual's fatal default must not return users to the terminal prompt."""
    from netops.tui import NetopsTUI

    app = NetopsTUI()
    async with app.run_test() as pilot:
        app._handle_exception(RuntimeError("simulated event failure"))
        await pilot.pause()
        assert app.is_running


@pytest.mark.asyncio
async def test_vault_validation_log_replaces_previous_result(tmp_path):
    """Vault validation must show the current result, not stale failures."""
    from textual.widgets import Button, Input, Log

    from netops.tui import NetopsTUI, VaultScreen

    app = NetopsTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(VaultScreen())
        await pilot.pause()
        screen = app.screen
        screen.query_one("#vault-path", Input).value = str(tmp_path / "missing-vault.yaml")
        screen.query_one("#vault-master-password", Input).value = "test-password"
        unlock = screen.query_one("#btn-vault-unlock", Button)
        log = screen.query_one("#vault-log", Log)

        screen.on_button_pressed(Button.Pressed(unlock))
        assert log.line_count == 1

        screen.on_button_pressed(Button.Pressed(unlock))
        assert log.line_count == 1


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
