r"""Automated rollback with pre/post health validation.

Workflow:

1. Connect to the device and capture:
   - Running configuration (pre-change snapshot)
   - Health-check baseline (CPU, memory, interface errors, logs)
2. Optionally save the snapshot via backup integration.
3. Apply the configuration change (requires ``--commit``; dry-run by default).
4. Re-run health checks and capture a post-change snapshot + unified diff.
5. Compare pre/post health:
   - Any alert that was not firing before the change → validation FAILED.
   - Device unreachable after the change → validation FAILED.
6. On failure (when ``--rollback-on-failure`` is set):
   - Restore the pre-change configuration automatically.
7. Write a structured entry to a JSON-lines audit log (who/what/when/why).

Usage::

    # Dry-run (default — no changes pushed):
    python -m netops.change.rollback --host router1 --commands changes.txt

    # Commit with health validation and auto-rollback on failure:
    python -m netops.change.rollback --host router1 --commands changes.txt \\
        --commit --rollback-on-failure --validate-health

    # Include snapshot backup and custom thresholds:
    python -m netops.change.rollback --host router1 --commands changes.txt \\
        --commit --rollback-on-failure --validate-health \\
        --snapshot-dir /var/backups/network --cpu-threshold 70
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from netops.change.push import (
    _push_commands,
    _rollback_to,
    _snapshot_config,
    _unified_diff,
)
from netops.check.health import (
    DEFAULT_CPU_THRESHOLD,
    DEFAULT_MEM_THRESHOLD,
    run_health_check,
)
from netops.core.connection import ConnectionParams, DeviceConnection, Transport

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class RollbackRecord:
    """Full audit record for a single change-with-rollback event."""

    change_id: str  # UUID for cross-system correlation
    host: str
    operator: str
    reason: str  # change rationale / ticket reference
    started_at: str  # ISO-8601 UTC
    commands: list[str]
    pre_config: str = ""
    post_config: str | None = None
    diff: str | None = None
    pre_health: dict | None = None  # result of run_health_check() before change
    post_health: dict | None = None  # result of run_health_check() after change
    committed: bool = False
    validation_passed: bool | None = None  # None = validation was skipped
    rolled_back: bool = False
    rollback_reason: str | None = None
    snapshot_path: str | None = None  # path saved via backup integration
    completed_at: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _health_degraded(pre: dict | None, post: dict) -> tuple[bool, str]:
    """Compare pre/post health-check results and identify degradation.

    Returns ``(degraded, reason)`` where *degraded* is ``True`` when the
    post-change health is worse than the pre-change baseline.

    Rules:

    * If the device is unreachable after the change → degraded.
    * For every check whose alert flag transitioned ``False → True`` → degraded.

    When *pre* is ``None`` (no baseline) every alert in *post* is treated as new.
    """
    if not post.get("success", False):
        return True, "device unreachable after change"

    pre_checks = (pre or {}).get("checks", {})
    post_checks = post.get("checks", {})

    degraded_checks: list[str] = []
    for check_name, post_result in post_checks.items():
        pre_alert = pre_checks.get(check_name, {}).get("alert", False)
        post_alert = post_result.get("alert", False)
        if post_alert and not pre_alert:
            degraded_checks.append(check_name)

    if degraded_checks:
        return True, f"new alert(s) triggered post-change: {', '.join(degraded_checks)}"

    return False, ""


# ---------------------------------------------------------------------------
# Snapshot integration (optional backup)
# ---------------------------------------------------------------------------


def _save_pre_snapshot(host: str, config: str, snapshot_dir: Path, timestamp: str) -> str | None:
    """Save *config* to *snapshot_dir* using the standard backup directory layout.

    Returns the saved file path on success, or ``None`` if saving fails.
    """
    try:
        from netops.collect.backup import save_backup  # lazy import

        result = {"host": host, "success": True, "config": config, "error": None}
        summary = save_backup(result, snapshot_dir, timestamp)
        return summary.get("saved_path")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not save pre-change snapshot: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Core workflow
# ---------------------------------------------------------------------------


def run_rollback_push(
    params: ConnectionParams,
    commands: list[str],
    *,
    commit: bool = False,
    validate_health: bool = True,
    rollback_on_failure: bool = True,
    cpu_threshold: float = DEFAULT_CPU_THRESHOLD,
    mem_threshold: float = DEFAULT_MEM_THRESHOLD,
    operator: str = "",
    reason: str = "",
    audit_log_path: Path | None = None,
    snapshot_dir: Path | None = None,
) -> RollbackRecord:
    """Execute a configuration change with pre/post health validation.

    Parameters
    ----------
    params:
        Connection parameters for the target device.
    commands:
        Ordered list of configuration commands to apply.
    commit:
        When *False* (default) only a pre-change snapshot (and health check
        when *validate_health* is *True*) are collected — nothing is pushed.
    validate_health:
        When *True* run health checks before and after the change and compare
        them.  Any alert that was not present before the change causes
        validation to fail.
    rollback_on_failure:
        When *True* automatically restore the pre-change config if validation
        fails.
    cpu_threshold:
        CPU alert threshold percentage forwarded to :func:`run_health_check`.
    mem_threshold:
        Memory alert threshold percentage forwarded to :func:`run_health_check`.
    operator:
        Human-readable identifier of the person or system executing the change.
    reason:
        Change rationale or ticket reference written to the audit log.
    audit_log_path:
        Optional path to a JSON-lines audit log.  One record is appended per
        call, even when the change or rollback fails.
    snapshot_dir:
        Optional directory where pre-change snapshots are saved via the backup
        integration.

    """
    started_at = datetime.now(timezone.utc).isoformat()
    change_id = str(uuid.uuid4())

    record = RollbackRecord(
        change_id=change_id,
        host=params.host,
        operator=operator or getpass.getuser(),
        reason=reason,
        started_at=started_at,
        commands=commands,
    )

    try:
        # ------------------------------------------------------------------
        # Pre-change: config snapshot
        # ------------------------------------------------------------------
        logger.info("[%s] Taking pre-change config snapshot of %s …", change_id, params.host)
        with DeviceConnection(params) as conn:
            record.pre_config = _snapshot_config(conn, params.device_type)

        # Optional: persist snapshot via backup integration
        if snapshot_dir is not None:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            record.snapshot_path = _save_pre_snapshot(
                params.host, record.pre_config, snapshot_dir, ts
            )

        # ------------------------------------------------------------------
        # Pre-change: health check baseline
        # ------------------------------------------------------------------
        if validate_health:
            logger.info("[%s] Running pre-change health check …", change_id)
            record.pre_health = run_health_check(
                params,
                cpu_threshold=cpu_threshold,
                mem_threshold=mem_threshold,
            )
            if not record.pre_health.get("success"):
                record.error = "Pre-change health check failed: device unreachable"
                logger.error("[%s] %s", change_id, record.error)
                return record

        # ------------------------------------------------------------------
        # Dry-run exit
        # ------------------------------------------------------------------
        if not commit:
            logger.info("[%s] Dry-run mode — no changes pushed (use --commit to apply)", change_id)
            return record

        # ------------------------------------------------------------------
        # Apply change + post-change config snapshot
        # ------------------------------------------------------------------
        logger.info("[%s] Applying %d command(s) to %s …", change_id, len(commands), params.host)
        with DeviceConnection(params) as conn:
            _push_commands(conn, commands)
            record.committed = True
            record.post_config = _snapshot_config(conn, params.device_type)
            record.diff = _unified_diff(record.pre_config, record.post_config, params.host)

        # ------------------------------------------------------------------
        # Post-change: health validation
        # ------------------------------------------------------------------
        if validate_health:
            logger.info("[%s] Running post-change health check …", change_id)
            record.post_health = run_health_check(
                params,
                cpu_threshold=cpu_threshold,
                mem_threshold=mem_threshold,
            )
            degraded, reason_str = _health_degraded(record.pre_health, record.post_health)
            record.validation_passed = not degraded

            if degraded:
                logger.warning(
                    "[%s] Validation FAILED for %s: %s", change_id, params.host, reason_str
                )
                record.rollback_reason = reason_str
                if rollback_on_failure:
                    logger.warning("[%s] Auto-rolling back %s …", change_id, params.host)
                    with DeviceConnection(params) as conn:
                        _rollback_to(conn, params.device_type, record.pre_config)
                    record.rolled_back = True
                    logger.info("[%s] Rollback complete for %s", change_id, params.host)
            else:
                logger.info(
                    "[%s] Validation PASSED for %s — change committed",
                    change_id,
                    params.host,
                )
        else:
            record.validation_passed = True

    except Exception as exc:  # noqa: BLE001
        record.error = str(exc)
        logger.error("[%s] Push/rollback error for %s: %s", change_id, params.host, exc)

    finally:
        record.completed_at = datetime.now(timezone.utc).isoformat()
        if audit_log_path:
            append_audit_log(record, audit_log_path)

    return record


# ---------------------------------------------------------------------------
# Audit log helpers
# ---------------------------------------------------------------------------


def append_audit_log(record: RollbackRecord, path: Path) -> None:
    """Append *record* as a JSON object to a newline-delimited audit log file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(record)) + "\n")


def load_audit_log(path: Path) -> list[dict]:
    """Return all audit records from *path* as a list of dicts."""
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


def _print_summary(record: RollbackRecord) -> None:
    """Print a human-readable summary of *record* to stdout."""
    sep = "=" * 64
    print(f"\n{sep}")
    print(f"  Change ID  : {record.change_id}")
    print(f"  Host       : {record.host}")
    print(f"  Operator   : {record.operator}")
    print(f"  Reason     : {record.reason or '(none)'}")
    print(f"  Started    : {record.started_at}")
    print(f"  Commands   : {len(record.commands)}")
    print(f"  Committed  : {'yes' if record.committed else 'no (dry-run)'}")
    if record.committed:
        if record.validation_passed is None:
            print("  Validation : skipped")
        elif record.validation_passed:
            print("  Validation : ✅ PASSED")
        else:
            print(f"  Validation : ❌ FAILED ({record.rollback_reason})")
        print(f"  Rolled back: {'yes' if record.rolled_back else 'no'}")
    if record.snapshot_path:
        print(f"  Snapshot   : {record.snapshot_path}")
    if record.diff:
        print(f"\n--- Diff ---\n{record.diff}")
    if record.error:
        print(f"\n❌  Error: {record.error}")
    print(f"{sep}\n")


def main() -> None:
    """CLI entry point for config push with health-validated auto-rollback."""
    parser = argparse.ArgumentParser(
        description=("Push config changes with pre/post health validation and auto-rollback.")
    )
    parser.add_argument("--host", required=True, help="Target device hostname or IP")
    parser.add_argument(
        "--commands", required=True, help="File containing config commands (one per line)"
    )
    parser.add_argument("--vendor", default="cisco_ios", help="Device type (default: cisco_ios)")
    parser.add_argument("--user", "-u", help="Username (or env NETOPS_USER)")
    parser.add_argument("--password", "-p", help="Password (or env NETOPS_PASSWORD)")
    parser.add_argument("--transport", choices=["ssh", "telnet"], default="ssh")
    parser.add_argument("--port", type=int, help="Override default port")
    parser.add_argument(
        "--commit",
        action="store_true",
        help="Actually push changes (default is dry-run/read-only)",
    )
    parser.add_argument(
        "--rollback-on-failure",
        action="store_true",
        help="Automatically rollback if post-change health validation fails",
    )
    parser.add_argument(
        "--validate-health",
        action="store_true",
        help="Run health checks before and after the change and compare them",
    )
    parser.add_argument(
        "--cpu-threshold",
        type=float,
        default=DEFAULT_CPU_THRESHOLD,
        metavar="PCT",
        help=f"CPU alert threshold %% (default: {DEFAULT_CPU_THRESHOLD})",
    )
    parser.add_argument(
        "--mem-threshold",
        type=float,
        default=DEFAULT_MEM_THRESHOLD,
        metavar="PCT",
        help=f"Memory alert threshold %% (default: {DEFAULT_MEM_THRESHOLD})",
    )
    parser.add_argument("--operator", help="Operator name written to the audit log")
    parser.add_argument("--reason", default="", help="Change rationale / ticket reference")
    parser.add_argument(
        "--audit-log",
        default="~/.netops/audit.jsonl",
        help="Path to JSON-lines audit log file (default: ~/.netops/audit.jsonl)",
    )
    parser.add_argument(
        "--snapshot-dir",
        help="Directory for pre-change config snapshots (backup integration)",
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

    audit_log_path = Path(args.audit_log).expanduser()
    snapshot_dir = Path(args.snapshot_dir) if args.snapshot_dir else None

    record = run_rollback_push(
        params,
        commands,
        commit=args.commit,
        validate_health=args.validate_health,
        rollback_on_failure=args.rollback_on_failure,
        cpu_threshold=args.cpu_threshold,
        mem_threshold=args.mem_threshold,
        operator=args.operator or username,
        reason=args.reason,
        audit_log_path=audit_log_path,
        snapshot_dir=snapshot_dir,
    )

    if args.json:
        json.dump(asdict(record), sys.stdout, indent=2)
        print()
    else:
        _print_summary(record)

    if record.error or (record.validation_passed is False and not record.rolled_back):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
