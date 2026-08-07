"""Tests for TUI async compatibility.

These verify the actual bug that was reported: asyncio.run() cannot be called
from a running event loop (i.e., from inside Textual's TUI).
"""

import asyncio
from unittest.mock import patch

import pytest

from netops.inventory.scan import scan_subnet_async


@pytest.mark.asyncio
async def test_scan_subnet_async_works_in_running_loop():
    """scan_subnet_async must work inside an already-running event loop (TUI)."""
    from netops.inventory.scan import scan_subnet_async

    with patch("netops.inventory.scan.ping_sweep", return_value=["192.168.1.1"]):
        results = await scan_subnet_async(
            subnet="192.168.1.0/30",
            community="public",
            skip_snmp=True,
        )
    assert len(results) == 1
    assert results[0].host == "192.168.1.1"
    assert results[0].reachable is True


@pytest.mark.asyncio
async def test_sync_asyncio_run_crashes_in_running_loop():
    """Prove the failure mode: asyncio.run() inside a running loop raises RuntimeError."""
    with pytest.raises(RuntimeError, match="cannot be called from a running event loop"):
        asyncio.run(asyncio.sleep(0))


@pytest.mark.asyncio
async def test_deep_enrich_via_executor():
    """deep_enrich (blocking SSH) must work via run_in_executor without crashing."""
    from netops.inventory.scan import deep_enrich

    result = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: deep_enrich({"devices": {}}, username="test", password="test"),
    )
    assert result == {"devices": {}}


@pytest.mark.asyncio
async def test_scan_subnet_async_empty_subnet():
    """scan_subnet_async handles a /30 with no reachable hosts."""
    with patch("netops.inventory.scan.ping_sweep", return_value=[]):
        results = await scan_subnet_async(subnet="10.0.0.0/30", skip_snmp=True)
    assert results == []


@pytest.mark.asyncio
async def test_scan_subnet_async_defaults():
    """scan_subnet_async has sensible defaults (community, skip_snmp, etc.)."""
    from netops.inventory.scan import scan_subnet_async

    with patch("netops.inventory.scan.ping_sweep", return_value=[]):
        # Only subnet is required
        results = await scan_subnet_async(subnet="10.0.0.0/30", skip_snmp=True)
    assert isinstance(results, list)
