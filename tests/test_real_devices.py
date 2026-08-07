"""Integration tests for MLXe and ME3600X device types.

Tests the real scan pipeline against mock SSH servers simulating
actual device output from nrush's environment.
"""

from __future__ import annotations

import time

import pytest

from tests.mock_ssh_server import mock_ssh_server

BASE_PORT = 22240


@pytest.fixture
def mlxe_server():
    """Start a mock Brocade MLXe SSH server."""
    with mock_ssh_server(port=BASE_PORT, personality="brocade_mlxe") as srv:
        time.sleep(0.3)
        yield srv


@pytest.fixture
def me3600x_server():
    """Start a mock Cisco ME3600X SSH server."""
    with mock_ssh_server(port=BASE_PORT + 1, personality="cisco_me3600x") as srv:
        time.sleep(0.3)
        yield srv


class TestMLXeDetection:
    """Tests for Brocade/Extreme MLXe (IronWare) device detection."""

    def test_mlxe_autodetect_identifies_brocade(self, mlxe_server):
        """MLXe with unknown vendor should detect as brocade_fastiron."""
        from netops.inventory.scan import _deep_scan_host

        result = _deep_scan_host(
            host="127.0.0.1",
            username="admin",
            password="admin123",
            known_vendor=None,
            timeout=5,  # Short timeout so SSHDetect falls back quickly
            port=BASE_PORT,
        )
        assert "brocade" in result["vendor"], f"Expected brocade, got {result['vendor']}"

    def test_mlxe_extracts_ironware_version(self, mlxe_server):
        """Should extract IronWare version, not 'FE 1: Version 1' garbage."""
        from netops.inventory.scan import _deep_scan_host

        result = _deep_scan_host(
            host="127.0.0.1",
            username="admin",
            password="admin123",
            known_vendor="brocade_fastiron",
            timeout=10,
            port=BASE_PORT,
        )
        assert result["version"] is not None, f"version not extracted: {result}"
        assert result["version"].startswith("6.3.0e"), f"Got version={result['version']}"
        assert result["version"] != "1", "Should not match 'FE 1: Version 1'"

    def test_mlxe_extracts_model(self, mlxe_server):
        """Should extract chassis model 'MLXe 4-slot'."""
        from netops.inventory.scan import _deep_scan_host

        result = _deep_scan_host(
            host="127.0.0.1",
            username="admin",
            password="admin123",
            known_vendor="brocade_fastiron",
            timeout=10,
            port=BASE_PORT,
        )
        assert result["model"] is not None, f"model not extracted: {result}"
        assert "MLXe" in result["model"], f"Expected MLXe in model, got {result['model']}"

    def test_mlxe_extracts_serial(self, mlxe_server):
        """Should extract chassis serial without trailing comma."""
        from netops.inventory.scan import _deep_scan_host

        result = _deep_scan_host(
            host="127.0.0.1",
            username="admin",
            password="admin123",
            known_vendor="brocade_fastiron",
            timeout=10,
            port=BASE_PORT,
        )
        assert result["serial"] == "BGD3830M026", f"Got serial={result['serial']}"
        assert "," not in (result["serial"] or ""), "Serial should not have trailing comma"

    def test_mlxe_extracts_memory(self, mlxe_server):
        """Should extract DRAM from '4096 MB DRAM INSTALLED'."""
        from netops.inventory.scan import _deep_scan_host

        result = _deep_scan_host(
            host="127.0.0.1",
            username="admin",
            password="admin123",
            known_vendor="brocade_fastiron",
            timeout=10,
            port=BASE_PORT,
        )
        assert result["total_memory"] is not None, f"memory not extracted: {result}"
        assert "4096" in result["total_memory"]


class TestME3600XDetection:
    """Tests for Cisco ME-3600X device detection."""

    def test_me3600x_identifies_as_cisco(self, me3600x_server):
        """ME3600X with unknown vendor should detect as cisco_ios or cisco_xe."""
        from netops.inventory.scan import _deep_scan_host

        result = _deep_scan_host(
            host="127.0.0.1",
            username="admin",
            password="admin123",
            known_vendor=None,
            timeout=5,
            port=BASE_PORT + 1,
        )
        assert "cisco" in result["vendor"], f"Expected cisco, got {result['vendor']}"

    def test_me3600x_extracts_version(self, me3600x_server):
        """Should extract version 15.6(1)S2."""
        from netops.inventory.scan import _deep_scan_host

        result = _deep_scan_host(
            host="127.0.0.1",
            username="admin",
            password="admin123",
            known_vendor="cisco_ios",
            timeout=10,
            port=BASE_PORT + 1,
        )
        assert result["version"] is not None, f"version not extracted: {result}"
        assert "15.6" in result["version"], f"Expected 15.6.x, got {result['version']}"

    def test_me3600x_extracts_model(self, me3600x_server):
        """Should extract model ME-3600X-24FS-M."""
        from netops.inventory.scan import _deep_scan_host

        result = _deep_scan_host(
            host="127.0.0.1",
            username="admin",
            password="admin123",
            known_vendor="cisco_ios",
            timeout=10,
            port=BASE_PORT + 1,
        )
        assert result["model"] is not None, f"model not extracted: {result}"
        assert "3600" in result["model"], f"Expected ME-3600X in model, got {result['model']}"

    def test_me3600x_extracts_serial(self, me3600x_server):
        """Should extract serial FOC1842R0PL."""
        from netops.inventory.scan import _deep_scan_host

        result = _deep_scan_host(
            host="127.0.0.1",
            username="admin",
            password="admin123",
            known_vendor="cisco_ios",
            timeout=10,
            port=BASE_PORT + 1,
        )
        assert result["serial"] == "FOC1842R0PL", f"Got serial={result['serial']}"


class TestDeepEnrichMultiVendor:
    """Test deep_enrich with a mix of device types from nrush's environment."""

    def test_enrich_mixed_mlxe_and_cisco(self, mlxe_server, me3600x_server):
        """Enrich a fragment with both Brocade MLXe and Cisco ME3600X."""

        _fragment = {
            "devices": {
                "core-mlxe-01": {
                    "host": "127.0.0.1",
                    "vendor": "unknown",
                },
                "dist-me3600-01": {
                    "host": "127.0.0.1",
                    "vendor": "unknown",
                },
            }
        }
        # Patch hosts to use different ports
        # Can't easily do this with deep_enrich's interface, so test individually
        from netops.inventory.scan import _deep_scan_host

        mlxe = _deep_scan_host("127.0.0.1", "admin", "admin123", None, 10, BASE_PORT)
        cisco = _deep_scan_host("127.0.0.1", "admin", "admin123", None, 10, BASE_PORT + 1)

        assert "brocade" in mlxe["vendor"]
        assert "cisco" in cisco["vendor"]
        assert mlxe["version"] != cisco["version"]
        assert mlxe["serial"] != cisco["serial"]
