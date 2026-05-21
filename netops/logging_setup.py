"""Centralized logging configuration for netops-toolkit.

Sets up automatic file logging at ~/.netops/logs/ (or NETOPS_LOG_DIR env var)
and provides the friendly vendor name mapping.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Friendly vendor name mapping
# ---------------------------------------------------------------------------

VENDOR_FRIENDLY_NAMES: dict[str, str] = {
    "cisco_ios": "Cisco IOS",
    "cisco_xe": "Cisco IOS-XE",
    "cisco_xr": "Cisco IOS-XR",
    "cisco_nxos": "Cisco NX-OS",
    "nokia_sros": "Nokia SR-OS",
    "nokia_srl": "Nokia SR Linux",
    "juniper_junos": "Juniper Junos",
    "arista_eos": "Arista EOS",
    "brocade_fastiron": "Brocade FastIron",
    "brocade_nos": "Brocade Network OS",
    "paloalto_panos": "Palo Alto PAN-OS",
    "vyatta_vyos": "VyOS",
    "yamaha": "Yamaha",
    "huawei": "Huawei VRP",
    "autodetect": "Auto-detect",
    "unknown": "Unknown",
}


def friendly_vendor_name(device_type: str) -> str:
    """Return a human-friendly display name for a netmiko device_type string."""
    return VENDOR_FRIENDLY_NAMES.get(device_type, device_type)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

_LOG_CONFIGURED = False


def get_log_dir() -> Path:
    """Return the log directory path (from NETOPS_LOG_DIR env or ~/.netops/logs/)."""
    env_dir = os.environ.get("NETOPS_LOG_DIR")
    if env_dir:
        return Path(env_dir)
    return Path.home() / ".netops" / "logs"


def setup_logging(level: int = logging.DEBUG) -> Path:
    """Configure logging to write to a dated file and return the log file path.

    Call this once at application startup. Subsequent calls are no-ops.
    Logs go to ~/.netops/logs/netops-YYYY-MM-DD.log (or NETOPS_LOG_DIR env var).
    """
    global _LOG_CONFIGURED
    if _LOG_CONFIGURED:
        return _get_current_log_path()

    log_dir = get_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)

    today = datetime.now().strftime("%Y-%m-%d")
    log_file = log_dir / f"netops-{today}.log"

    # File handler — captures everything at DEBUG level
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    # Add to root logger so all netops.* loggers are captured
    root_logger = logging.getLogger()
    root_logger.addHandler(file_handler)
    # Ensure root logger level allows DEBUG messages through to the handler
    if root_logger.level == logging.WARNING or root_logger.level == 0:
        root_logger.setLevel(logging.DEBUG)

    # Also configure netops namespace explicitly
    netops_logger = logging.getLogger("netops")
    netops_logger.setLevel(level)

    _LOG_CONFIGURED = True

    netops_logger.info("=== netops-toolkit session started ===")
    netops_logger.info("Log file: %s", log_file)

    return log_file


def _get_current_log_path() -> Path:
    """Return the current session's log file path."""
    log_dir = get_log_dir()
    today = datetime.now().strftime("%Y-%m-%d")
    return log_dir / f"netops-{today}.log"
