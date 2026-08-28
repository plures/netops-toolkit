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
async def test_operation_forms_show_defaults_and_open_settings():
    """Persistent tuning is summarized on forms and edited only in Settings."""
    from textual.widgets import Label

    from netops.tui import BackupScreen, HealthScreen, NetopsTUI, ScanScreen, SettingsScreen

    form_cases = (
        (ScanScreen, "#scan-defaults-summary", "Scan defaults:", "#scan-snmp-port"),
        (HealthScreen, "#health-defaults-summary", "Health defaults:", "#health-threshold"),
        (BackupScreen, "#backup-defaults-summary", "Backup defaults:", "#backup-workers"),
    )
    for screen_type, summary_id, expected_prefix, removed_field_id in form_cases:
        app = NetopsTUI()
        async with app.run_test(size=(100, 80)) as pilot:
            app.push_screen(screen_type())
            await pilot.pause()
            screen = app.screen
            summary = screen.query_one(summary_id, Label)
            assert str(summary.render()).startswith(expected_prefix)
            assert "Ctrl+O" in str(summary.render())
            assert not list(screen.query(removed_field_id))

            await pilot.press("ctrl+o")
            await pilot.pause()
            assert isinstance(app.screen, SettingsScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, screen_type)


@pytest.mark.asyncio
async def test_saving_settings_updates_the_originating_defaults_summary():
    """Editing a saved default should refresh the parent form after Settings closes."""
    from textual.widgets import Input, Label

    from netops.tui import HealthScreen, NetopsTUI, SettingsScreen

    app = NetopsTUI()
    async with app.run_test(size=(100, 80)) as pilot:
        app.push_screen(HealthScreen())
        await pilot.pause()
        await pilot.press("ctrl+o")
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen)

        cpu_input = app.screen.query_one("#settings-health-cpu-threshold", Input)
        cpu_input.value = "42"
        await pilot.click("#btn-settings-save")
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()

        assert isinstance(app.screen, HealthScreen)
        summary = app.screen.query_one("#health-defaults-summary", Label)
        assert "CPU alert 42.0%" in str(summary.render())


@pytest.mark.asyncio
async def test_settings_is_the_labelled_visible_home_for_tuning_defaults():
    """All persistent operation defaults are visible and editable in Settings."""
    from textual.widgets import Input, Label

    from netops.tui import NetopsTUI, SettingsScreen

    app = NetopsTUI()
    async with app.run_test(size=(100, 100)) as pilot:
        app.push_screen(SettingsScreen())
        await pilot.pause()
        screen = app.screen
        assert str(screen.query_one("#settings-title", Label).render()) == "⚙️ TUI Settings"
        for field_id in (
            "#settings-snmp-port",
            "#settings-snmp-timeout",
            "#settings-ping-workers",
            "#settings-snmp-concurrency",
            "#settings-ssh-timeout",
            "#settings-ssh-concurrency",
            "#settings-health-cpu-threshold",
            "#settings-health-mem-threshold",
            "#settings-backup-workers",
        ):
            field = screen.query_one(field_id, Input)
            assert "default-setting-input" in field.classes
            assert field.region.height == 1
            assert field.styles.background != screen.query_one("#settings-modal").styles.background


@pytest.mark.asyncio
async def test_modal_inputs_are_visible_in_all_operation_forms():
    """Terminal themes cannot make operation-specific inputs disappear."""
    from textual.containers import Horizontal
    from textual.widgets import Input

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
            inputs = list(app.screen.query(Input))
            assert inputs, f"{screen_type.__name__} must expose an editable input when applicable"
            for field in inputs:
                assert field.region.height == 1, f"{field.id} does not use compact input geometry"
                assert field.styles.color != field.styles.background
            for row in app.screen.query(Horizontal):
                assert len(list(row.query(Input))) <= 1, (
                    f"{screen_type.__name__} places multiple inputs in one row: {row.id}"
                )


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
