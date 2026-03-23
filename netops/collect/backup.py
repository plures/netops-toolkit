"""
Bulk configuration backup with diff tracking.

Collects running configs from all inventory devices, saves them with timestamps
to a per-device directory tree, and generates unified diffs against the previous
backup so unexpected changes are immediately visible.

Optional git integration commits every changed file to a local repository so the
full history is preserved.

Usage:
    python -m netops.collect.backup --inventory inv.yaml --output /var/backups/network/
    python -m netops.collect.backup --inventory inv.yaml --output /var/backups/network/ --git
    python -m netops.collect.backup --inventory inv.yaml --output /var/backups/network/ --workers 10
"""

from __future__ import annotations

import argparse
import difflib
import json
import logging
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from netops.collect.config import collect_config
from netops.core import Inventory
from netops.core.connection import ConnectionParams, Transport

logger = logging.getLogger(__name__)

_GIT_NOTHING_TO_COMMIT = "nothing to commit"


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------


def _latest_backup_before(device_dir: Path, current_filename: str) -> Optional[Path]:
    """Return the most recent *.cfg in *device_dir* that is not *current_filename*."""
    backups = sorted(f for f in device_dir.glob("*.cfg") if f.name != current_filename)
    return backups[-1] if backups else None


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


def generate_diff(old_path: Path, new_config: str) -> str:
    """Return a unified diff between *old_path* on disk and *new_config* text.

    Returns an empty string when the configs are identical.
    """
    old_lines = old_path.read_text().splitlines(keepends=True)
    new_lines = new_config.splitlines(keepends=True)
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=old_path.name,
        tofile="current",
        lineterm="\n",
    )
    return "".join(diff)


# ---------------------------------------------------------------------------
# Per-device save
# ---------------------------------------------------------------------------


def save_backup(result: dict, output_dir: Path, timestamp: str) -> dict:
    """Save one device's collected config to *output_dir* and compute a diff.

    Directory layout::

        <output_dir>/
          <host>/
            20240101-120000.cfg
            20240102-130000.cfg
            ...

    Returns a summary dict with keys:
        host, success, saved_path, diff, changed, error
    """
    summary: dict = {
        "host": result["host"],
        "success": result["success"],
        "saved_path": None,
        "diff": None,
        "changed": False,
        "error": result.get("error"),
    }

    if not result["success"]:
        return summary

    device_dir = output_dir / result["host"]
    device_dir.mkdir(parents=True, exist_ok=True)

    fname = f"{timestamp}.cfg"
    dest = device_dir / fname
    config_text = result["config"]
    dest.write_text(config_text)
    summary["saved_path"] = str(dest)

    # Diff against the previous backup (if any)
    previous = _latest_backup_before(device_dir, fname)
    if previous is not None:
        diff = generate_diff(previous, config_text)
        if diff:
            summary["diff"] = diff
            summary["changed"] = True

    return summary


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def git_init(output_dir: Path) -> bool:
    """Initialise a git repository in *output_dir* if one does not exist yet."""
    if (output_dir / ".git").is_dir():
        return True
    try:
        subprocess.run(
            ["git", "init"],
            cwd=output_dir,
            check=True,
            capture_output=True,
        )
        logger.info("Initialised git repository in %s", output_dir)
        return True
    except (OSError, subprocess.CalledProcessError) as exc:
        logger.warning("git init failed: %s", exc)
        return False


def git_commit(output_dir: Path, message: str) -> bool:
    """Stage all changes in *output_dir* and create a git commit.

    Returns True on success (including the *nothing to commit* case).
    """
    try:
        subprocess.run(
            ["git", "add", "."],
            cwd=output_dir,
            check=True,
            capture_output=True,
        )
        result = subprocess.run(
            ["git", "commit", "-m", message],
            cwd=output_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            logger.info("Git commit: %s", message)
            return True
        # Nothing to commit is not an error
        if _GIT_NOTHING_TO_COMMIT in result.stdout or _GIT_NOTHING_TO_COMMIT in result.stderr:
            logger.info("Git: nothing to commit")
            return True
        logger.warning("Git commit failed: %s", result.stderr)
        return False
    except (OSError, subprocess.CalledProcessError) as exc:
        logger.warning("Git operation failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------


def run_backup(
    params_list: list[ConnectionParams],
    output_dir: Path,
    *,
    workers: int = 5,
    git: bool = False,
    alert_on_change: bool = True,
    _timestamp: Optional[str] = None,
) -> list[dict]:
    """Collect configs from all devices and save them with diff tracking.

    Args:
        params_list: Connection parameters for each target device.
        output_dir: Root directory for the backup archive.
        workers: Maximum number of concurrent collection threads.
        git: When True, commit every changed file to a local git repository.
        alert_on_change: When True, write change alerts to *stderr*.
        _timestamp: Override the timestamp string (intended for tests only).

    Returns:
        A list of per-device summary dicts (see :func:`save_backup`).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = _timestamp or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    if git:
        git_init(output_dir)

    summaries: list[dict] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_params = {executor.submit(collect_config, p): p for p in params_list}
        for future in as_completed(future_to_params):
            params = future_to_params[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "host": params.host,
                    "success": False,
                    "config": None,
                    "error": str(exc),
                }
            summary = save_backup(result, output_dir, timestamp)
            summaries.append(summary)

    if git:
        changed_hosts = sorted(s["host"] for s in summaries if s["changed"])
        commit_msg = f"backup {timestamp}"
        if changed_hosts:
            commit_msg += f" — {len(changed_hosts)} change(s): {', '.join(changed_hosts)}"
        commit_ok = git_commit(output_dir, commit_msg)
        if not commit_ok:
            logger.error(
                "Git commit failed for backup %s in repository %s",
                timestamp,
                output_dir,
            )
            raise RuntimeError("Git commit failed; backup repository is not up to date")

    if alert_on_change:
        for s in summaries:
            if s["changed"]:
                print(f"⚠️  CHANGED: {s['host']}", file=sys.stderr)
                if s.get("diff"):
                    diff_lines = s["diff"].splitlines()
                    preview = diff_lines[:20]
                    for line in preview:
                        print(f"   {line}", file=sys.stderr)
                    remainder = len(diff_lines) - len(preview)
                    if remainder > 0:
                        print(f"   ... ({remainder} more lines)", file=sys.stderr)

    return summaries


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Bulk configuration backup with diff tracking"
    )
    parser.add_argument("--inventory", "-i", required=True, help="Inventory file (YAML/JSON)")
    parser.add_argument("--output", "-o", required=True, help="Output directory for backups")
    parser.add_argument("--group", "-g", help="Inventory group to target")
    parser.add_argument("--user", "-u", help="Username override")
    parser.add_argument("--password", "-p", help="Password (or use env NETOPS_PASSWORD)")
    parser.add_argument(
        "--workers", "-w", type=int, default=5, help="Concurrent workers (default: 5)"
    )
    parser.add_argument(
        "--git", action="store_true", help="Commit backups to a local git repository"
    )
    parser.add_argument(
        "--no-alert", action="store_true", help="Suppress change alerts on stderr"
    )
    parser.add_argument("--json", action="store_true", help="Output summary as JSON to stdout")
    args = parser.parse_args()

    password = args.password or os.environ.get("NETOPS_PASSWORD")

    inv = Inventory.from_file(args.inventory)
    devices = inv.filter(group=args.group) if args.group else list(inv.devices.values())

    if not devices:
        print("No devices found in inventory", file=sys.stderr)
        sys.exit(1)

    params_list = [
        ConnectionParams(
            host=d.host,
            username=d.username or args.user,
            password=d.password or password,
            device_type=d.vendor,
            transport=Transport(d.transport),
            port=d.port,
        )
        for d in devices
    ]

    summaries = run_backup(
        params_list,
        Path(args.output),
        workers=args.workers,
        git=args.git,
        alert_on_change=not args.no_alert,
    )

    if args.json:
        json.dump(summaries, sys.stdout, indent=2, default=str)
        return

    ok = sum(1 for s in summaries if s["success"])
    changed = sum(1 for s in summaries if s["changed"])
    failed = sum(1 for s in summaries if not s["success"])

    print(f"\n📦 Backup complete: {ok} ok, {changed} changed, {failed} failed")
    for s in sorted(summaries, key=lambda x: x["host"]):
        if s["success"]:
            marker = " ⚠️  CHANGED" if s["changed"] else ""
            print(f"  ✅ {s['host']} → {s['saved_path']}{marker}")
        else:
            print(f"  ❌ {s['host']}: {s['error']}")


if __name__ == "__main__":
    main()
