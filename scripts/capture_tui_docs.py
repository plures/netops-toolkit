"""Capture every user-facing netops TUI screen for the documentation gallery.

The renders deliberately use no inventory, credentials, or device output. This
keeps the screenshots safe to publish while showing the real UI layout.
"""
# ruff: noqa: E402, I001

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Callable

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from textual.screen import ModalScreen

from netops.tui import (
    BackupScreen,
    BastionScreen,
    ConfigPushScreen,
    ConfigViewScreen,
    DiffScreen,
    HealthScreen,
    NetopsTUI,
    ScanScreen,
    SettingsScreen,
    VaultScreen,
)


Capture = tuple[str, str, Callable[[], ModalScreen] | None, bool]
OUTPUT_DIR = REPOSITORY_ROOT / "docs" / "images"
CAPTURES: tuple[Capture, ...] = (
    ("tui-workspace.svg", "netops-toolkit TUI workspace", None, False),
    ("tui-scan-form.svg", "netops-toolkit inventory scan form", ScanScreen, False),
    ("tui-health-check.svg", "netops-toolkit health check", HealthScreen, False),
    ("tui-config-push.svg", "netops-toolkit configuration push", ConfigPushScreen, False),
    ("tui-config-backup.svg", "netops-toolkit configuration backup", BackupScreen, False),
    ("tui-config-diff.svg", "netops-toolkit configuration diff", DiffScreen, False),
    ("tui-active-bastion.svg", "netops-toolkit active bastion", BastionScreen, False),
    ("tui-settings.svg", "netops-toolkit settings", SettingsScreen, False),
    ("tui-credential-vault.svg", "netops-toolkit credential vault", VaultScreen, False),
    ("tui-running-config.svg", "netops-toolkit running configuration", lambda: ConfigViewScreen("selected device", ""), False),
    ("tui-help.svg", "netops-toolkit help", None, True),
)


async def capture_one(
    filename: str,
    title: str,
    screen_factory: Callable[[], ModalScreen] | None,
    show_help: bool,
) -> None:
    """Render one screen at a stable terminal size and write an SVG screenshot."""
    app = NetopsTUI()
    async with app.run_test(size=(120, 100)) as pilot:
        if screen_factory is not None:
            app.push_screen(screen_factory())
        elif show_help:
            app.action_help_screen()
        await pilot.pause()
        svg = app.export_screenshot(title=title, simplify=True)
        clean_svg = "\n".join(line.rstrip() for line in svg.splitlines())
        OUTPUT_DIR.joinpath(filename).write_text(
            f"{clean_svg}\n", encoding="utf-8"
        )


async def main() -> None:
    """Capture the documentation gallery without contacting any network device."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    for capture in CAPTURES:
        await capture_one(*capture)
    print(f"Captured {len(CAPTURES)} TUI screenshots in {OUTPUT_DIR}")


if __name__ == "__main__":
    asyncio.run(main())
