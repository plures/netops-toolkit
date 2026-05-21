"""Dependency smoke tests — verify all imports work without mocking.

These catch missing deps that unit tests with mocks would miss.
"""

import importlib


def test_scan_imports_without_error():
    """scan module must import cleanly (catches missing pysnmp)."""
    mod = importlib.import_module("netops.inventory.scan")
    assert hasattr(mod, "scan_subnet_async")
    assert hasattr(mod, "scan_subnet")


def test_tui_imports_without_error():
    """TUI module must import cleanly (catches missing textual)."""
    mod = importlib.import_module("netops.tui")
    assert hasattr(mod, "NetopsTUI")


def test_core_imports_without_error():
    """Core modules must import cleanly."""
    importlib.import_module("netops.core.connection")
    importlib.import_module("netops.core.inventory")
    importlib.import_module("netops.core.vault")


def test_scan_subnet_async_callable():
    """scan_subnet_async must be importable and callable (not just exist)."""
    from netops.inventory.scan import scan_subnet_async
    assert callable(scan_subnet_async)
