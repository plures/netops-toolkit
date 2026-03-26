r"""Safe configuration push with pre/post diff and auto-rollback confirm timer.

Workflow:

1. Connect to the device and snapshot the running config (pre-change).
2. Optionally push the given commands (requires ``--commit`` flag; dry-run by
   default).
3. Snapshot the config again (post-change) and compute a unified diff.
4. If ``--confirm-timer N`` is set, start a countdown.  The operator must type
   ``confirm`` within *N* minutes or the pre-change config is restored
   (rollback).
5. Append a structured entry to a JSON-lines change log.

Usage::

    # Dry-run (default — no changes pushed):
    python -m netops.change.push --host router1 --commands changes.txt

    # Commit with 5-minute confirm timer:
    python -m netops.change.push --host router1 --commands changes.txt \\
        --commit --confirm-timer 5
"""

from __future__ import annotations

import argparse
import difflib
import getpass
import json
import logging
import os
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from netops.core.connection import ConnectionParams, DeviceConnection, Transport

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ChangeRecord:
    """Captures every meaningful attribute of a single config-push event."""

    host: str
    operator: str
    started_at: str  # ISO-8601 UTC
    commands: list[str]
    pre_config: str
    post_config: str | None = None
    diff: str | None = None
    committed: bool = False
    confirmed: bool = False
    rolled_back: bool = False
    error: str | None = None


# ---------------------------------------------------------------------------
# Device helpers
# ---------------------------------------------------------------------------


def _snapshot_config(conn: DeviceConnection, device_type: str) -> str:
    """Return the full running/candidate config as a string."""
    if "nokia" in device_type:
        return conn.send("admin display-config")
    if "juniper" in device_type:
        return conn.send("show configuration")
    return conn.send("show running-config")


def _push_commands(conn: DeviceConnection, commands: list[str]) -> str:
    """Send *commands* in config mode and return raw output."""
    return conn.send_config(commands)


def _rollback_to(conn: DeviceConnection, device_type: str, pre_config: str) -> str:
    """Best-effort rollback.

    Strategy (first match wins):

    * Cisco XR  → ``rollback configuration last 1``
    * Juniper   → ``rollback 1`` then ``commit``
    * All others → re-push every non-comment line of *pre_config*
    """
    if "cisco_xr" in device_type:
        return conn.send("rollback configuration last 1")
    if "juniper" in device_type:
        return conn.send_config(["rollback 1", "commit"])
    # Generic: rebuild from the pre-change snapshot
    restore_cmds = [
        line
        for line in pre_config.splitlines()
        if line.strip() and not line.strip().startswith("!")
    ]
    return conn.send_config(restore_cmds)


def _unified_diff(before: str, after: str, host: str) -> str:
    """Return a unified diff string between *before* and *after*."""
    lines_a = before.splitlines(keepends=True)
    lines_b = after.splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(lines_a, lines_b, fromfile=f"{host}:pre", tofile=f"{host}:post")
    )


# ---------------------------------------------------------------------------
# Confirm-timer logic
# ---------------------------------------------------------------------------


def _wait_for_confirmation(timeout_seconds: int) -> bool:
    """Prompt the operator and wait up to *timeout_seconds* for ``confirm``.

    Returns ``True`` if confirmed before the deadline, ``False`` otherwise.
    Reads from *sys.stdin* in a daemon thread so the main thread can poll the
    deadline without blocking.
    """
    confirmed_event = threading.Event()

    def _reader() -> None:
        """Read a single line from stdin and set the event if it equals 'confirm'."""
        try:
            line = sys.stdin.readline().strip().lower()
            if line == "confirm":
                confirmed_event.set()
        except (EOFError, OSError):
            pass

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    print(
        f"\n⏳  Type 'confirm' within {timeout_seconds // 60} minute(s) to keep changes,"
        " or wait for auto-rollback: ",
        end="",
        flush=True,
    )
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if confirmed_event.is_set():
            return True
        time.sleep(0.5)
    return False


# ---------------------------------------------------------------------------
# Core workflow
# ---------------------------------------------------------------------------


def run_push(
    params: ConnectionParams,
    commands: list[str],
    *,
    commit: bool = False,
    confirm_timer_minutes: int = 0,
    operator: str = "",
    changelog_path: Path | None = None,
) -> ChangeRecord:
    """Execute the full safe-push workflow.

    Parameters
    ----------
    params:
        Connection parameters for the target device.
    commands:
        Ordered list of configuration commands to apply.
    commit:
        When *False* (default) snapshot + diff are generated but nothing is
        pushed to the device.
    confirm_timer_minutes:
        If > 0 the operator must confirm within this many minutes after a
        successful push or the pre-change config is restored.
    operator:
        Human-readable identifier of the person or system executing the change.
    changelog_path:
        Optional path to a JSON-lines changelog file.  Each call appends one
        record.

    """
    started_at = datetime.now(timezone.utc).isoformat()
    record = ChangeRecord(
        host=params.host,
        operator=operator or getpass.getuser(),
        started_at=started_at,
        commands=commands,
        pre_config="",
    )

    try:
        with DeviceConnection(params) as conn:
            # 1. Pre-change snapshot
            logger.info("Taking pre-change config snapshot …")
            record.pre_config = _snapshot_config(conn, params.device_type)

            if not commit:
                logger.info("Dry-run mode — no changes pushed (use --commit to apply)")
                return record

            # 2. Push commands
            logger.info("Pushing %d command(s) to %s …", len(commands), params.host)
            _push_commands(conn, commands)
            record.committed = True

            # 3. Post-change snapshot + diff
            record.post_config = _snapshot_config(conn, params.device_type)
            record.diff = _unified_diff(record.pre_config, record.post_config, params.host)

            # 4. Confirm timer / auto-rollback
            if confirm_timer_minutes > 0:
                timeout_secs = confirm_timer_minutes * 60
                confirmed = _wait_for_confirmation(timeout_secs)
                if confirmed:
                    print("\n✅  Change confirmed.")
                    record.confirmed = True
                else:
                    print("\n⚠️   Confirm timer expired — rolling back …")
                    _rollback_to(conn, params.device_type, record.pre_config)
                    record.rolled_back = True
                    logger.warning("Auto-rollback executed for %s", params.host)
            else:
                record.confirmed = True

    except Exception as exc:
        record.error = str(exc)
        logger.error("Push failed for %s: %s", params.host, exc)

    finally:
        if changelog_path:
            append_changelog(record, changelog_path)

    return record


# ---------------------------------------------------------------------------
# Changelog helpers
# ---------------------------------------------------------------------------


def append_changelog(record: ChangeRecord, path: Path) -> None:
    """Append *record* as a JSON object to a newline-delimited log file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(record)) + "\n")


def load_changelog(path: Path) -> list[dict]:
    """Return all change records from *path* as a list of dicts."""
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_summary(record: ChangeRecord) -> None:
    """Print a human-readable summary of *record* to stdout."""
    sep = "=" * 60
    print(f"\n{sep}")
    print(f"  Host       : {record.host}")
    print(f"  Operator   : {record.operator}")
    print(f"  Started    : {record.started_at}")
    print(f"  Commands   : {len(record.commands)}")
    print(f"  Committed  : {'yes' if record.committed else 'no (dry-run)'}")
    if record.committed:
        print(f"  Confirmed  : {'yes' if record.confirmed else 'no'}")
        print(f"  Rolled back: {'yes' if record.rolled_back else 'no'}")
    if record.diff:
        print(f"\n--- Diff ---\n{record.diff}")
    if record.error:
        print(f"\n❌  Error: {record.error}")
    print(f"{sep}\n")


def main() -> None:
    """CLI entry point for safe config-push with pre/post diff and optional auto-rollback."""
    parser = argparse.ArgumentParser(
        description="Push config changes safely with pre/post diff and auto-rollback."
    )
    parser.add_argument("--host", required=True, help="Target device hostname or IP")
    parser.add_argument("--commands", required=True, help="File containing config commands (one per line)")
    parser.add_argument("--vendor", default="cisco_ios", help="Device type (default: cisco_ios)")
    parser.add_argument("--user", "-u", help="Username (or env NETOPS_USER)")
    parser.add_argument("--password", "-p", help="Password (or env NETOPS_PASSWORD)")
    parser.add_argument("--transport", choices=["ssh", "telnet"], default="ssh")
    parser.add_argument("--port", type=int, help="Override default port")
    parser.add_argument(
        "--confirm-timer",
        type=int,
        default=0,
        metavar="MINUTES",
        help="Auto-rollback if change is not confirmed within N minutes (0 = disabled)",
    )
    parser.add_argument(
        "--commit",
        action="store_true",
        help="Actually push changes (default is dry-run/read-only)",
    )
    parser.add_argument("--operator", help="Operator name written to the change log")
    parser.add_argument(
        "--changelog",
        default="~/.netops/changelog.jsonl",
        help="Path to JSON-lines changelog file (default: ~/.netops/changelog.jsonl)",
    )
    parser.add_argument("--json", action="store_true", help="Output result as JSON to stdout")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    username = args.user or os.environ.get("NETOPS_USER") or getpass.getuser()
    password = args.password or os.environ.get("NETOPS_PASSWORD")

    commands_path = Path(args.commands)
    if not commands_path.exists():
        print(f"❌  Commands file not found: {commands_path}", file=sys.stderr)
        sys.exit(1)

    commands = [
        line
        for line in commands_path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not commands:
        print("❌  No commands found in file.", file=sys.stderr)
        sys.exit(1)

    params = ConnectionParams(
        host=args.host,
        username=username,
        password=password,
        device_type=args.vendor,
        transport=Transport(args.transport),
        port=args.port,
    )

    changelog_path = Path(args.changelog).expanduser()

    record = run_push(
        params,
        commands,
        commit=args.commit,
        confirm_timer_minutes=args.confirm_timer,
        operator=args.operator or username,
        changelog_path=changelog_path,
    )

    if args.json:
        json.dump(asdict(record), sys.stdout, indent=2)
        print()
    else:
        _print_summary(record)

    sys.exit(0 if not record.error else 1)


if __name__ == "__main__":
    main()
