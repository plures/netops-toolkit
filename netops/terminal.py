"""Terminal capability choices kept independent from Textual widgets.

The TUI normally lets Textual detect the terminal. A small number of older or
enterprise terminal emulators advertise capabilities that they do not render
well. This module gives the launcher and UI one conservative, tested way to
select a portable display mode before importing optional TUI dependencies.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass

_TRUE_VALUES = {"1", "true", "yes", "on"}
_LOW_CAPABILITY_TERMS = {"ansi", "dumb", "linux", "vt100", "vt102", "vt220"}
_ASCII_REPLACEMENTS = (
    ("⚠️", "[warning]"),
    ("ℹ️", "[info]"),
    ("⚙️", "[settings]"),
    ("🔍", "[scan]"),
    ("🔎", "[diff]"),
    ("🔐", "[bastion]"),
    ("🔑", "[vault]"),
    ("🏥", "[health]"),
    ("💾", "[backup]"),
    ("✅", "[ok]"),
    ("❌", "[error]"),
    ("⚠", "[warning]"),
    ("ℹ", "[info]"),
    ("📄", "[file]"),
    ("📋", "[log]"),
    ("🚨", "[alert]"),
    ("🔬", "[probe]"),
    ("🔴", "[red]"),
    ("🔵", "[blue]"),
    ("·", " | "),
    ("—", "-"),
)


@dataclass(frozen=True)
class TerminalProfile:
    """Display choices that are safe for the terminal that launched the TUI."""

    compatibility_mode: bool
    source: str

    @property
    def selected_marker(self) -> str:
        """Return a reliably renderable selected-row marker."""
        return "[x]" if self.compatibility_mode else "☑"

    @property
    def unselected_marker(self) -> str:
        """Return a reliably renderable unselected-row marker."""
        return "[ ]" if self.compatibility_mode else "☐"


def terminal_profile(environment: Mapping[str, str] | None = None) -> TerminalProfile:
    """Choose an ASCII-safe profile when the terminal explicitly needs it.

    ``NETOPS_TUI_COMPAT=1`` is intentionally an opt-in for capable terminals
    that nevertheless render rich glyphs poorly. Known low-capability TERM
    values select the mode automatically, without making every modern terminal
    look less polished.
    """
    env = os.environ if environment is None else environment
    if env.get("NETOPS_TUI_COMPAT", "").strip().lower() in _TRUE_VALUES:
        return TerminalProfile(True, "NETOPS_TUI_COMPAT")

    terminal = env.get("TERM", "").strip().lower()
    if terminal in _LOW_CAPABILITY_TERMS:
        return TerminalProfile(True, f"TERM={terminal or 'unset'}")

    return TerminalProfile(False, "terminal auto-detection")


def configure_terminal_environment(environment: MutableMapping[str, str]) -> TerminalProfile:
    """Apply conservative Textual settings before Textual is imported.

    Textual reads its color-system override at import time. Limiting the
    compatibility renderer to the ANSI standard palette avoids true-colour
    assumptions while preserving usable contrast and keyboard interaction.
    """
    profile = terminal_profile(environment)
    if profile.compatibility_mode:
        environment.setdefault("TEXTUAL_COLOR_SYSTEM", "standard")
    return profile


def terminal_text(text: str, environment: Mapping[str, str] | None = None) -> str:
    """Use ASCII status text when a terminal cannot render rich glyphs."""
    if not terminal_profile(environment).compatibility_mode:
        return text
    for rich_text, ascii_text in _ASCII_REPLACEMENTS:
        text = text.replace(rich_text, ascii_text)
    return text
