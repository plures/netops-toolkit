"""Centralized logging configuration for netops-toolkit.

Sets up automatic file logging at ~/.netops/logs/ (or NETOPS_LOG_DIR env var)
and provides the friendly vendor name mapping.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from netops.vendor_profiles import PROFILES, friendly_name

# ---------------------------------------------------------------------------
# Friendly vendor name mapping
# ---------------------------------------------------------------------------

VENDOR_FRIENDLY_NAMES: dict[str, str] = {
    profile.id: profile.display_name for profile in PROFILES.values()
}
VENDOR_FRIENDLY_NAMES.update({
    "paloalto_panos": "Palo Alto PAN-OS",
    "vyatta_vyos": "VyOS",
    "yamaha": "Yamaha",
    "huawei": "Huawei VRP",
    "autodetect": "Auto-detect",
    "unknown": "Unknown",
})


def friendly_vendor_name(device_type: str) -> str:
    """Return a human-friendly display name for a netmiko device_type string."""
    return VENDOR_FRIENDLY_NAMES.get(device_type, friendly_name(device_type))


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

_LOG_CONFIGURED = False
_FILE_HANDLER: CappedFileHandler | None = None

DEFAULT_LOG_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_LOG_LEVEL = "INFO"
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


def get_log_dir() -> Path:
    """Return the log directory path (from NETOPS_LOG_DIR env or ~/.netops/logs/)."""
    env_dir = os.environ.get("NETOPS_LOG_DIR")
    if env_dir:
        return Path(env_dir)
    return Path.home() / ".netops" / "logs"


def get_log_settings_path() -> Path:
    """Return the user-owned logging settings path."""
    configured = os.environ.get("NETOPS_LOG_SETTINGS")
    if configured:
        return Path(configured)
    return Path.home() / ".netops" / "logging.json"


def _log_level_name(value: str | int | None) -> str:
    """Normalize a supported Python log level to its stable user-facing name."""
    if value is None:
        return DEFAULT_LOG_LEVEL
    if isinstance(value, int):
        name = logging.getLevelName(value)
        if isinstance(name, str) and name in LOG_LEVELS:
            return name
    else:
        candidate = value.strip().upper()
        if candidate in LOG_LEVELS:
            return candidate
    raise ValueError(f"Log level must be one of: {', '.join(LOG_LEVELS)}")


def load_log_settings() -> dict[str, int | str]:
    """Load safe per-user logging defaults, ignoring a malformed settings file."""
    defaults: dict[str, int | str] = {
        "max_bytes": DEFAULT_LOG_MAX_BYTES,
        "level": DEFAULT_LOG_LEVEL,
    }
    try:
        raw = json.loads(get_log_settings_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return defaults
    if not isinstance(raw, dict):
        return defaults
    try:
        max_bytes = int(raw.get("max_bytes", DEFAULT_LOG_MAX_BYTES))
        level = _log_level_name(raw.get("level", DEFAULT_LOG_LEVEL))
    except (TypeError, ValueError):
        return defaults
    if max_bytes < 1024:
        return defaults
    return {"max_bytes": max_bytes, "level": level}


def save_log_settings(*, max_bytes: int, level: str | int) -> dict[str, int | str]:
    """Persist a bounded log size and verbosity level for TUI and CLI sessions."""
    if max_bytes < 1024:
        raise ValueError("Log size must be at least 1 KiB")
    settings: dict[str, int | str] = {
        "max_bytes": int(max_bytes),
        "level": _log_level_name(level),
    }
    path = get_log_settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return settings


class CappedFileHandler(logging.FileHandler):
    """Append UTF-8 logs while removing oldest complete entries before a write."""

    def __init__(self, filename: Path, *, max_bytes: int) -> None:
        if max_bytes < 1:
            raise ValueError("Log size cap must be positive")
        super().__init__(filename, encoding="utf-8")
        self.max_bytes = max_bytes

    def _trim_before_write(self, incoming: str) -> str:
        """Keep the newest complete existing lines so ``incoming`` fits the cap."""
        incoming_bytes = incoming.encode("utf-8")
        if len(incoming_bytes) > self.max_bytes:
            marker_bytes = b"[netops log entry truncated to fit configured cap]\n"
            if len(marker_bytes) >= self.max_bytes:
                incoming_bytes = marker_bytes[: self.max_bytes]
            else:
                budget = self.max_bytes - len(marker_bytes)
                tail = incoming_bytes[-budget:].decode("utf-8", errors="ignore").encode("utf-8")
                incoming_bytes = marker_bytes + tail
            incoming = incoming_bytes.decode("utf-8")
        self.flush()
        current_size = Path(self.baseFilename).stat().st_size if Path(self.baseFilename).exists() else 0
        if current_size + len(incoming_bytes) <= self.max_bytes:
            return incoming
        retained_limit = self.max_bytes - len(incoming_bytes)
        existing = Path(self.baseFilename).read_text(encoding="utf-8", errors="replace")
        retained: list[str] = []
        retained_size = 0
        for line in reversed(existing.splitlines(keepends=True)):
            line_size = len(line.encode("utf-8"))
            if retained_size + line_size > retained_limit:
                break
            retained.append(line)
            retained_size += line_size
        self.stream.seek(0)
        self.stream.truncate()
        self.stream.write("".join(reversed(retained)))
        self.flush()
        return incoming

    def emit(self, record: logging.LogRecord) -> None:
        """Trim first, then append one formatted entry without exceeding the cap."""
        try:
            message = self.format(record).replace("\r", "\\r").replace("\n", "\\n") + self.terminator
            self.stream.write(self._trim_before_write(message))
            self.flush()
        except Exception:
            self.handleError(record)


def _apply_log_settings(*, max_bytes: int, level: str | int) -> None:
    """Apply a validated setting to the active handler without restarting logging."""
    global _FILE_HANDLER
    level_name = _log_level_name(level)
    if _FILE_HANDLER is not None:
        _FILE_HANDLER.max_bytes = max_bytes
        _FILE_HANDLER.setLevel(getattr(logging, level_name))
    logging.getLogger("netops").setLevel(logging.DEBUG)


def setup_logging(level: str | int | None = None, max_bytes: int | None = None) -> Path:
    """Configure logging to write to a dated file and return the log file path.

    Call this once at application startup. Later calls apply the current level
    and cap to the existing handler. Logs go to
    ~/.netops/logs/netops-YYYY-MM-DD.log (or NETOPS_LOG_DIR env var).
    """
    global _FILE_HANDLER, _LOG_CONFIGURED
    saved = load_log_settings()
    resolved_max_bytes = int(max_bytes if max_bytes is not None else saved["max_bytes"])
    resolved_level = _log_level_name(level if level is not None else saved["level"])
    if resolved_max_bytes < 1024:
        raise ValueError("Log size must be at least 1 KiB")
    if _LOG_CONFIGURED:
        _apply_log_settings(max_bytes=resolved_max_bytes, level=resolved_level)
        return _get_current_log_path()

    log_dir = get_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)

    today = datetime.now().strftime("%Y-%m-%d")
    log_file = log_dir / f"netops-{today}.log"

    # File handler — bounded retention keeps the newest entries without
    # allowing unattended sessions to consume unbounded disk space.
    file_handler = CappedFileHandler(log_file, max_bytes=resolved_max_bytes)
    file_handler.setLevel(getattr(logging, resolved_level))
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    # Add to root logger so all netops.* loggers are captured
    root_logger = logging.getLogger()
    root_logger.addHandler(file_handler)
    _FILE_HANDLER = file_handler
    # Ensure root logger level allows DEBUG messages through to the handler
    if root_logger.level == logging.WARNING or root_logger.level == 0:
        root_logger.setLevel(logging.DEBUG)

    # Also configure netops namespace explicitly
    netops_logger = logging.getLogger("netops")
    netops_logger.setLevel(logging.DEBUG)

    _LOG_CONFIGURED = True

    netops_logger.info("=== netops-toolkit session started (%s, cap %s bytes) ===", resolved_level, resolved_max_bytes)
    netops_logger.info("Log file: %s", log_file)

    return log_file


def format_log_size(size_bytes: int) -> str:
    """Return a compact, user-facing representation of a byte count."""
    if size_bytes % (1024 * 1024) == 0:
        return f"{size_bytes // (1024 * 1024)} MiB"
    if size_bytes % 1024 == 0:
        return f"{size_bytes // 1024} KiB"
    return f"{size_bytes} bytes"


def main(argv: Sequence[str] | None = None) -> int:
    """Show or configure the shared bounded logging defaults from the CLI."""
    parser = argparse.ArgumentParser(
        prog="netops logs",
        description="Inspect or configure local netops-toolkit log retention and verbosity.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("show", help="Show the active log path and saved defaults")
    configure = subcommands.add_parser("configure", help="Save defaults for future TUI and CLI sessions")
    configure.add_argument(
        "--max-size-mb",
        type=int,
        help="Maximum size for the current daily log file in MiB (minimum: 1)",
    )
    configure.add_argument(
        "--level",
        choices=LOG_LEVELS,
        type=str.upper,
        help="Minimum file verbosity: DEBUG, INFO, WARNING, or ERROR",
    )
    args = parser.parse_args(argv)
    settings = load_log_settings()
    if args.command == "configure":
        max_bytes = settings["max_bytes"] if args.max_size_mb is None else args.max_size_mb * 1024 * 1024
        level = settings["level"] if args.level is None else args.level
        try:
            settings = save_log_settings(max_bytes=int(max_bytes), level=level)
        except ValueError as exc:
            parser.error(str(exc))
        _apply_log_settings(max_bytes=int(settings["max_bytes"]), level=str(settings["level"]))
        print(f"Saved log cap {format_log_size(int(settings['max_bytes']))} at {settings['level']} level.")
        return 0
    print(f"Log file: {_get_current_log_path()}")
    print(f"Log cap: {format_log_size(int(settings['max_bytes']))}")
    print(f"Log level: {settings['level']}")
    return 0


def shutdown_logging() -> None:
    """Detach and close the handler created by :func:`setup_logging`.

    This is safe to call repeatedly.  Closing the handler explicitly matters
    on Windows, where an open file handle prevents a log directory from being
    removed during tests or short-lived embedded runs.
    """
    global _FILE_HANDLER, _LOG_CONFIGURED
    if _FILE_HANDLER is not None:
        logging.getLogger().removeHandler(_FILE_HANDLER)
        _FILE_HANDLER.close()
        _FILE_HANDLER = None
    _LOG_CONFIGURED = False


def _get_current_log_path() -> Path:
    """Return the current session's log file path."""
    log_dir = get_log_dir()
    today = datetime.now().strftime("%Y-%m-%d")
    return log_dir / f"netops-{today}.log"
