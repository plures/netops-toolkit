"""Tests for logging setup and friendly vendor names."""

import logging
import os
import tempfile
from pathlib import Path

from netops.logging_setup import (
    VENDOR_FRIENDLY_NAMES,
    CappedFileHandler,
    friendly_vendor_name,
    get_log_dir,
    load_log_settings,
    setup_logging,
    shutdown_logging,
)
from netops.logging_setup import main as logs_main


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
            shutdown_logging()
            del os.environ["NETOPS_LOG_DIR"]
            assert mod._FILE_HANDLER is None


def test_capped_file_handler_drops_oldest_complete_entries_before_writing(tmp_path):
    """The configured cap retains recent complete entries instead of rotating forever."""
    path = tmp_path / "bounded.log"
    handler = CappedFileHandler(path, max_bytes=180)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger("netops.tests.bounded-log")
    previous_handlers = list(logger.handlers)
    previous_level = logger.level
    previous_propagate = logger.propagate
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        logger.info("oldest-entry %s", "a" * 65)
        logger.info("middle-entry %s", "b" * 65)
        logger.info("newest-entry %s", "c" * 65)
    finally:
        handler.flush()
        handler.close()
        logger.handlers = previous_handlers
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate

    content = path.read_text(encoding="utf-8")
    assert path.stat().st_size <= 180
    assert "newest-entry" in content
    assert "oldest-entry" not in content


def test_logging_cli_saves_shared_size_and_verbosity_defaults(tmp_path, monkeypatch, capsys):
    """TUI and scripts consume the same user-configurable logging defaults."""
    monkeypatch.setenv("NETOPS_LOG_SETTINGS", str(tmp_path / "logging.json"))

    assert logs_main(["configure", "--max-size-mb", "25", "--level", "warning"]) == 0

    assert load_log_settings() == {"max_bytes": 25 * 1024 * 1024, "level": "WARNING"}
    assert "25 MiB at WARNING" in capsys.readouterr().out

    assert logs_main(["show"]) == 0
    display = capsys.readouterr().out
    assert "Log cap: 25 MiB" in display
    assert "Log level: WARNING" in display
