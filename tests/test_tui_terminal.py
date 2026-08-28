"""Tests for terminal compatibility selection before Textual is imported."""

from netops.terminal import configure_terminal_environment, terminal_profile, terminal_text


def test_low_capability_term_uses_compatibility_mode():
    """Known legacy terminal identifiers select the portable renderer."""
    profile = terminal_profile({"TERM": "vt100"})

    assert profile.compatibility_mode
    assert profile.source == "TERM=vt100"


def test_modern_terminal_keeps_rich_default():
    """Modern terminals keep the higher-fidelity default display."""
    profile = terminal_profile({"TERM": "xterm-256color"})

    assert not profile.compatibility_mode
    assert profile.selected_marker == "☑"


def test_explicit_compatibility_limits_textual_to_standard_colours():
    """The launcher configures Textual before its constants are imported."""
    environment = {"TERM": "xterm", "NETOPS_TUI_COMPAT": "yes"}

    profile = configure_terminal_environment(environment)

    assert profile.compatibility_mode
    assert environment["TEXTUAL_COLOR_SYSTEM"] == "standard"


def test_compatibility_text_does_not_require_unicode_glyphs():
    """ASCII mode degrades app-owned visual status text safely."""
    text = terminal_text("🔍 Scan · ✅", {"NETOPS_TUI_COMPAT": "1"})

    assert text == "[scan] Scan  |  [ok]"
