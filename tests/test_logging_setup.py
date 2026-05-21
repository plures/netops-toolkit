"""Tests for logging setup and friendly vendor names."""

import os
import tempfile
from pathlib import Path

from netops.logging_setup import (
    VENDOR_FRIENDLY_NAMES,
    friendly_vendor_name,
    get_log_dir,
    setup_logging,
)


def test_friendly_vendor_names_known():
    """Known device types return friendly names."""
    assert friendly_vendor_name("cisco_ios") == "Cisco IOS"
    assert friendly_vendor_name("nokia_sros") == "Nokia SR-OS"
    assert friendly_vendor_name("juniper_junos") == "Juniper Junos"
    assert friendly_vendor_name("arista_eos") == "Arista EOS"
    assert friendly_vendor_name("brocade_fastiron") == "Brocade FastIron"
    assert friendly_vendor_name("vyatta_vyos") == "VyOS"
    assert friendly_vendor_name("cisco_xe") == "Cisco IOS-XE"
    assert friendly_vendor_name("cisco_xr") == "Cisco IOS-XR"
    assert friendly_vendor_name("cisco_nxos") == "Cisco NX-OS"
    assert friendly_vendor_name("nokia_srl") == "Nokia SR Linux"
    assert friendly_vendor_name("brocade_nos") == "Brocade Network OS"
    assert friendly_vendor_name("autodetect") == "Auto-detect"


def test_friendly_vendor_names_unknown():
    """Unknown device types return the raw string."""
    assert friendly_vendor_name("some_random_device") == "some_random_device"
    assert friendly_vendor_name("") == ""


def test_friendly_vendor_names_mapping_complete():
    """All entries in the mapping return non-empty strings."""
    for key, value in VENDOR_FRIENDLY_NAMES.items():
        assert value, f"Empty friendly name for {key}"
        assert isinstance(value, str)


def test_log_dir_default():
    """Default log dir is ~/.netops/logs/."""
    # Clear env var if set
    old = os.environ.pop("NETOPS_LOG_DIR", None)
    try:
        log_dir = get_log_dir()
        assert log_dir == Path.home() / ".netops" / "logs"
    finally:
        if old:
            os.environ["NETOPS_LOG_DIR"] = old


def test_log_dir_env_override():
    """NETOPS_LOG_DIR env var overrides default."""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ["NETOPS_LOG_DIR"] = tmpdir
        try:
            assert get_log_dir() == Path(tmpdir)
        finally:
            del os.environ["NETOPS_LOG_DIR"]


def test_setup_logging_creates_file():
    """setup_logging creates the log file."""
    import netops.logging_setup as mod

    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ["NETOPS_LOG_DIR"] = tmpdir
        # Reset the module state so we can re-run setup
        mod._LOG_CONFIGURED = False
        try:
            log_file = setup_logging()
            assert log_file.exists()
            assert log_file.parent == Path(tmpdir)
            assert "netops-" in log_file.name
            assert log_file.suffix == ".log"
            # Verify something was written
            content = log_file.read_text()
            assert "session started" in content
        finally:
            del os.environ["NETOPS_LOG_DIR"]
            mod._LOG_CONFIGURED = False
