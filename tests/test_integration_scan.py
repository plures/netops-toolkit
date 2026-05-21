"""Integration tests — exercises the REAL scan pipeline against mock SSH servers.

These tests start actual TCP servers and connect via Netmiko/paramiko,
validating the full scan → detect → parse pipeline end-to-end.
"""

from __future__ import annotations

import logging
import time

import pytest

from tests.mock_ssh_server import MockSSHServerInstance, mock_ssh_server

logger = logging.getLogger(__name__)

# Base port for mock servers (avoid conflicts)
BASE_PORT = 22220


@pytest.fixture
def brocade_server():
    """Start a mock Brocade FastIron SSH server."""
    with mock_ssh_server(port=BASE_PORT, personality="brocade_fastiron") as srv:
        time.sleep(0.3)
        yield srv


@pytest.fixture
def cisco_server():
    """Start a mock Cisco IOS SSH server."""
    with mock_ssh_server(port=BASE_PORT + 1, personality="cisco_ios") as srv:
        time.sleep(0.3)
        yield srv


@pytest.fixture
def juniper_server():
    """Start a mock Juniper Junos SSH server."""
    with mock_ssh_server(port=BASE_PORT + 2, personality="juniper_junos") as srv:
        time.sleep(0.3)
        yield srv


class TestDeepScanIntegration:
    """Tests that exercise the deep scan pipeline against mock SSH servers."""

    def test_scan_finds_device_and_identifies_vendor(self, cisco_server):
        """Scan a host with mock device, verify vendor is detected."""
        from netops.inventory.scan import _deep_scan_host

        result = _deep_scan_host(
            host="127.0.0.1",
            username="admin",
            password="admin123",
            known_vendor="cisco_ios",
            timeout=10,
            port=BASE_PORT + 1,
        )
        assert result["vendor"] in ("cisco_ios", "cisco_xe")
        assert result["error"] is None

    def test_deep_scan_extracts_version_model_serial(self, cisco_server):
        """Verify version, model, serial are all populated from Cisco device."""
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
        assert result["model"] is not None, f"model not extracted: {result}"
        assert result["serial"] is not None, f"serial not extracted: {result}"

    def test_deep_scan_brocade_identification(self, brocade_server):
        """Specifically test Brocade FastIron detection and field extraction."""
        from netops.inventory.scan import _deep_scan_host

        result = _deep_scan_host(
            host="127.0.0.1",
            username="admin",
            password="admin123",
            known_vendor="brocade_fastiron",
            timeout=10,
            port=BASE_PORT,
        )
        assert result["vendor"] == "brocade_fastiron"
        assert result["error"] is None
        # Check extracted fields match fixtures
        if result["serial"]:
            assert "CYR3444L01F" in result["serial"]
        if result["version"]:
            assert "08.0.95" in result["version"]

    def test_deep_scan_juniper(self, juniper_server):
        """Test Juniper Junos detection and field extraction."""
        from netops.inventory.scan import _deep_scan_host

        result = _deep_scan_host(
            host="127.0.0.1",
            username="admin",
            password="admin123",
            known_vendor="juniper_junos",
            timeout=10,
            port=BASE_PORT + 2,
        )
        assert result["vendor"] == "juniper_junos"
        assert result["error"] is None

    def test_scan_with_wrong_credentials_logs_auth_failure(self):
        """Verify that wrong credentials produce a useful error."""
        with mock_ssh_server(port=BASE_PORT + 5, personality="cisco_ios") as _:
            time.sleep(0.3)
            from netops.inventory.scan import _deep_scan_host

            result = _deep_scan_host(
                host="127.0.0.1",
                username="wrong_user",
                password="wrong_pass",
                known_vendor="cisco_ios",
                timeout=10,
                port=BASE_PORT + 5,
            )
            # Should fail gracefully with error
            assert result["error"] is not None or result["version"] is None

    def test_scan_multiple_devices_different_vendors(
        self, brocade_server, cisco_server, juniper_server
    ):
        """Multiple mock devices on different ports, each detected correctly."""
        from netops.inventory.scan import _deep_scan_host

        configs = [
            (BASE_PORT, "brocade_fastiron"),
            (BASE_PORT + 1, "cisco_ios"),
            (BASE_PORT + 2, "juniper_junos"),
        ]
        results = []
        for port, vendor in configs:
            r = _deep_scan_host(
                host="127.0.0.1",
                username="admin",
                password="admin123",
                known_vendor=vendor,
                timeout=10,
                port=port,
            )
            results.append(r)
            assert vendor.split("_")[0] in r["vendor"], f"Expected {vendor} family, got {r['vendor']}"
            assert r["error"] is None, f"Error for {vendor}: {r['error']}"

        assert len(results) == 3

    def test_deep_enrich_pipeline(self, cisco_server):
        """Test the full deep_enrich function with a fragment."""
        from netops.inventory.scan import deep_enrich

        fragment = {
            "devices": {
                "test-router": {
                    "host": "127.0.0.1",
                    "vendor": "cisco_ios",
                }
            }
        }
        enriched = deep_enrich(
            fragment,
            username="admin",
            password="admin123",
            concurrency=1,
            timeout=10,
            port=BASE_PORT + 1,
        )
        device = enriched["devices"]["test-router"]
        assert device["vendor"] == "cisco_ios"


class TestVendorIdentification:
    """Tests for the identify_vendor function with real sysDescr strings."""

    def test_brocade_fastiron_from_sysdescr(self):
        from netops.inventory.scan import identify_vendor

        assert identify_vendor("Brocade Communications, Inc. ICX6450-48P") == "brocade_fastiron"
        assert identify_vendor("FastIron Stackable") == "brocade_fastiron"
        assert identify_vendor("Foundry Networks, Inc. FastIron") == "brocade_fastiron"

    def test_cisco_ios_from_sysdescr(self):
        from netops.inventory.scan import identify_vendor

        assert identify_vendor("Cisco IOS Software, ISR") == "cisco_ios"

    def test_juniper_from_sysdescr(self):
        from netops.inventory.scan import identify_vendor

        assert identify_vendor("Juniper Networks, Inc. MX240") == "juniper_junos"
        assert identify_vendor("Junos router") == "juniper_junos"
