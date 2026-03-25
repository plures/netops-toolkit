"""
Change approval workflow: plan → dry-run → review → approve → execute.

Workflow::

    1. Call :func:`generate_plan` with the *desired* config text and the
       *current* (running) config text for one or more devices.
    2. Inspect the returned :class:`ChangePlan`.  The plan includes a
       human-readable preview (semantic diff), risk score, and per-device
       :class:`ChangeStep` list.
    3. Export the plan to JSON/YAML for offline review with
       :func:`export_plan`.
    4. When approved, call :func:`apply_plan` (requires ``approved=True``).
       Dry-run mode never modifies any device.

Usage::

    # Generate and preview a plan (dry-run, no device changes):
    python -m netops.change.plan plan \\
        --host router1 --desired new_config.txt

    # Export plan to file for offline review:
    python -m netops.change.plan plan \\
        --host router1 --desired new_config.txt --export plan.json

    # Apply a previously exported + approved plan:
    python -m netops.change.plan apply --plan plan.json --approve

Public API::

    from netops.change.plan import (
        generate_plan, apply_plan, export_plan, load_plan,
        ChangePlan, ChangeStep, RiskLevel, DeviceRole,
    )
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml

from netops.change.diff import ConfigStyle, DiffResult, diff_configs, format_semantic, format_unified
from netops.change.push import _push_commands
from netops.core.connection import ConnectionParams, DeviceConnection, Transport

logger = logging.getLogger(__name__)

__all__ = [
    "RiskLevel",
    "DeviceRole",
    "ChangeStep",
    "ChangePlan",
    "generate_plan",
    "apply_plan",
    "export_plan",
    "load_plan",
]

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    """Overall risk classification for a change plan."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DeviceRole(str, Enum):
    """Criticality classification of a network device.

    Roles are ordered from lowest (ACCESS) to highest (CORE) criticality.
    The role influences the risk score of any change on that device.
    """

    ACCESS = "access"
    DISTRIBUTION = "distribution"
    EDGE = "edge"
    CORE = "core"
    UNKNOWN = "unknown"

    # Numeric weight used when computing the risk score (higher = more risky).
    @property
    def weight(self) -> int:
        """Return the numeric risk weight for this role (higher value = greater risk)."""
        return {
            DeviceRole.ACCESS: 1,
            DeviceRole.DISTRIBUTION: 2,
            DeviceRole.EDGE: 3,
            DeviceRole.CORE: 4,
            DeviceRole.UNKNOWN: 2,
        }[self]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ChangeStep:
    """A single per-device step inside a :class:`ChangePlan`."""

    host: str
    """Target device hostname or IP."""

    device_type: str
    """Netmiko device type string (e.g. ``cisco_ios``)."""

    device_role: DeviceRole
    """Criticality role of this device."""

    commands: list[str]
    """Ordered list of configuration commands to apply."""

    current_config: str = ""
    """Running config captured from the device (or provided as input)."""

    desired_config: str = ""
    """Target config (full desired state — used when ``commands`` is empty)."""

    diff_preview: str = ""
    """Human-readable semantic diff preview (populated by :func:`generate_plan`)."""

    unified_diff: str = ""
    """Classic unified diff string (populated by :func:`generate_plan`)."""

    has_security_changes: bool = False
    """True when the diff contains security-sensitive configuration lines."""

    applied: bool = False
    """True after this step has been successfully applied."""

    error: Optional[str] = None
    """Error message if this step failed during :func:`apply_plan`."""


@dataclass
class ChangePlan:
    """Full change plan: metadata + one :class:`ChangeStep` per device."""

    plan_id: str
    """UUID for cross-system correlation.  A fresh UUID is generated for each
    :func:`generate_plan` call.  The *structure* (steps, diff, risk score) is
    fully reproducible given the same input — only the ``plan_id`` will differ
    between two calls with identical arguments."""

    created_at: str
    """ISO-8601 UTC timestamp when the plan was generated."""

    operator: str
    """Human name / system that generated the plan."""

    description: str
    """Free-text description or ticket reference."""

    steps: list[ChangeStep] = field(default_factory=list)
    """Ordered list of per-device change steps."""

    risk_level: RiskLevel = RiskLevel.LOW
    """Overall risk level derived from scope and device criticality."""

    risk_score: float = 0.0
    """Numeric risk score (used to derive :attr:`risk_level`).

    Score components:

    * **device_weight** — based on :class:`DeviceRole` (1–4)
    * **change_scope** — number of diff entries (adds + removes + changes)
    * **security_bonus** — +3 for each step that touches security config
    * **multi_device_bonus** — +2 when more than one device is in the plan
    """

    dry_run: bool = True
    """When *True* the plan was generated without connecting to any device."""

    approved: bool = False
    """Set to *True* before calling :func:`apply_plan` to authorise execution."""

    applied_at: Optional[str] = None
    """ISO-8601 UTC timestamp when :func:`apply_plan` was called."""

    changelog_path: Optional[str] = None
    """Optional path to a JSON-lines changelog to append results to."""


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

_RISK_LOW_THRESHOLD = 6.0
_RISK_HIGH_THRESHOLD = 15.0


def _compute_risk(steps: list[ChangeStep], diff_results: list[DiffResult]) -> tuple[float, RiskLevel]:
    """Compute a numeric risk score and :class:`RiskLevel` for *steps*.

    The formula combines:

    * The maximum :class:`DeviceRole` weight across all devices.
    * The total number of config changes (adds + removes + changes).
    * A bonus for any steps that touch security-sensitive config lines.
    * A bonus when the plan touches more than one device.

    Returns ``(score, level)``.
    """
    if not steps:
        return 0.0, RiskLevel.LOW

    max_device_weight = max(s.device_role.weight for s in steps)

    total_changes = 0
    security_bonus = 0.0
    for diff in diff_results:
        total_changes += len(diff.added) + len(diff.removed) + len(diff.changed)
        if diff.security_changes:
            security_bonus += 3.0

    multi_device_bonus = 2.0 if len(steps) > 1 else 0.0

    score = (max_device_weight * total_changes) + security_bonus + multi_device_bonus

    if score >= _RISK_HIGH_THRESHOLD:
        level = RiskLevel.HIGH
    elif score >= _RISK_LOW_THRESHOLD:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    return score, level


# ---------------------------------------------------------------------------
# Plan generation
# ---------------------------------------------------------------------------


def generate_plan(
    steps_input: list[dict],
    *,
    operator: str = "",
    description: str = "",
    config_style: Optional[ConfigStyle] = None,
) -> ChangePlan:
    """Generate a :class:`ChangePlan` from desired-vs-current state.

    Parameters
    ----------
    steps_input:
        A list of dicts, one per device, with keys:

        ``host`` *(required)*
            Target device hostname or IP.
        ``device_type`` *(optional, default ``cisco_ios``)*
            Netmiko device-type string.
        ``device_role`` *(optional, default ``unknown``)*
            One of the :class:`DeviceRole` values (string).
        ``commands`` *(optional)*
            List of configuration commands.  Used as-is when
            ``current_config`` / ``desired_config`` are also provided;
            commands are derived automatically when only config texts are
            given.
        ``current_config`` *(optional)*
            The *before* config text.  When omitted the diff preview will be
            empty.
        ``desired_config`` *(optional)*
            The *after* / target config text.  Required when ``commands`` is
            not provided.

    operator:
        Human-readable name of the person or system generating the plan.
    description:
        Free-text plan description or ticket reference.
    config_style:
        Force a specific :class:`ConfigStyle` for diffing.  When *None*
        (default) the style is auto-detected.

    Returns
    -------
    ChangePlan
        A fully populated plan ready for export or review.  The plan is
        **never** applied here — call :func:`apply_plan` for that.
    """
    now = datetime.now(timezone.utc).isoformat()
    plan_id = str(uuid.uuid4())
    resolved_operator = operator or getpass.getuser()

    change_steps: list[ChangeStep] = []
    diff_results: list[DiffResult] = []

    for raw in steps_input:
        host = raw["host"]
        device_type = raw.get("device_type", "cisco_ios")
        role_str = raw.get("device_role", "unknown")
        try:
            device_role = DeviceRole(role_str)
        except ValueError:
            device_role = DeviceRole.UNKNOWN

        commands: list[str] = list(raw.get("commands") or [])
        current_config: str = raw.get("current_config", "")
        desired_config: str = raw.get("desired_config", "")

        # Build diff when we have both sides of the config
        diff_preview = ""
        unified = ""
        has_security = False
        diff: Optional[DiffResult] = None

        if current_config or desired_config:
            diff = diff_configs(current_config, desired_config, style=config_style)
            diff_results.append(diff)
            diff_preview = format_semantic(diff)
            unified = format_unified(diff)
            has_security = bool(diff.security_changes)

            # When no explicit commands list is supplied, derive them from
            # the added/changed lines in the diff so the step is actionable.
            if not commands:
                for entry in diff.added + diff.changed:
                    for ln in entry.after_lines:
                        stripped = ln.strip()
                        if stripped:
                            commands.append(stripped)

        change_steps.append(
            ChangeStep(
                host=host,
                device_type=device_type,
                device_role=device_role,
                commands=commands,
                current_config=current_config,
                desired_config=desired_config,
                diff_preview=diff_preview,
                unified_diff=unified,
                has_security_changes=has_security,
            )
        )

    score, level = _compute_risk(change_steps, diff_results)

    return ChangePlan(
        plan_id=plan_id,
        created_at=now,
        operator=resolved_operator,
        description=description,
        steps=change_steps,
        risk_level=level,
        risk_score=score,
        dry_run=True,
        approved=False,
    )


# ---------------------------------------------------------------------------
# Plan application
# ---------------------------------------------------------------------------


def apply_plan(
    plan: ChangePlan,
    *,
    connection_params: Optional[list[ConnectionParams]] = None,
    approved: bool = False,
    changelog_path: Optional[Path] = None,
) -> ChangePlan:
    """Apply an approved :class:`ChangePlan` to the target devices.

    **Dry-run guarantee**: if *approved* is ``False`` (the default) this
    function immediately returns the plan unchanged — no device is ever
    modified.

    Parameters
    ----------
    plan:
        The plan to apply.  Must have been generated by :func:`generate_plan`.
    connection_params:
        A list of :class:`~netops.core.connection.ConnectionParams`, one per
        step, in the same order as ``plan.steps``.  Required when *approved*
        is *True*.
    approved:
        Must be explicitly set to *True* to allow device modifications.
    changelog_path:
        Optional path to a JSON-lines file.  The applied plan dict is
        appended as a single line after successful completion.

    Returns
    -------
    ChangePlan
        The same plan object with each step's ``applied`` / ``error`` fields
        updated.
    """
    if not approved:
        logger.info("apply_plan called without approval — dry-run, no changes pushed")
        return plan

    plan.approved = True
    plan.applied_at = datetime.now(timezone.utc).isoformat()

    if connection_params is None:
        connection_params = []

    for idx, step in enumerate(plan.steps):
        if not step.commands:
            logger.info("Step %d (%s): no commands to apply — skipping", idx, step.host)
            step.applied = True
            continue

        if idx >= len(connection_params):
            step.error = f"No ConnectionParams provided for step {idx} ({step.host})"
            logger.error(step.error)
            continue

        params = connection_params[idx]
        try:
            logger.info("Applying %d command(s) to %s …", len(step.commands), step.host)
            with DeviceConnection(params) as conn:
                _push_commands(conn, step.commands)
            step.applied = True
            logger.info("Step %d (%s): applied successfully", idx, step.host)
        except Exception as exc:  # noqa: BLE001
            step.error = str(exc)
            logger.error("Step %d (%s): failed — %s", idx, step.host, exc)

    if changelog_path is not None:
        _append_plan_log(plan, changelog_path)

    return plan


# ---------------------------------------------------------------------------
# Export / import helpers
# ---------------------------------------------------------------------------


def _plan_to_dict(plan: ChangePlan) -> dict:
    """Serialise a :class:`ChangePlan` to a plain dict (JSON-safe)."""
    d = asdict(plan)
    # Enums → strings for JSON/YAML compatibility
    d["risk_level"] = plan.risk_level.value
    for i, step in enumerate(plan.steps):
        d["steps"][i]["device_role"] = step.device_role.value
    return d


def _dict_to_plan(d: dict) -> ChangePlan:
    """Deserialise a plain dict (from JSON/YAML) back into a :class:`ChangePlan`."""
    steps = []
    for sd in d.get("steps", []):
        sd = dict(sd)
        sd["device_role"] = DeviceRole(sd.get("device_role", "unknown"))
        steps.append(ChangeStep(**sd))

    d = dict(d)
    d["steps"] = steps
    d["risk_level"] = RiskLevel(d.get("risk_level", "low"))
    return ChangePlan(**d)


def export_plan(plan: ChangePlan, path: Path, *, fmt: str = "json") -> None:
    """Write *plan* to *path* in JSON or YAML format.

    Parameters
    ----------
    plan:
        The plan to serialise.
    path:
        Destination file path.  Parent directories are created if needed.
    fmt:
        ``"json"`` (default) or ``"yaml"``.

    Raises
    ------
    ValueError
        When *fmt* is not ``"json"`` or ``"yaml"``.
    """
    if fmt not in {"json", "yaml"}:
        raise ValueError(f"Unsupported export format: {fmt!r} — use 'json' or 'yaml'")

    path.parent.mkdir(parents=True, exist_ok=True)
    data = _plan_to_dict(plan)

    with path.open("w", encoding="utf-8") as fh:
        if fmt == "yaml":
            yaml.safe_dump(data, fh, default_flow_style=False, allow_unicode=True)
        else:
            json.dump(data, fh, indent=2)
            fh.write("\n")

    logger.info("Plan %s exported to %s (%s)", plan.plan_id, path, fmt)


def load_plan(path: Path) -> ChangePlan:
    """Load a :class:`ChangePlan` from a JSON or YAML file.

    The format is auto-detected from the file extension:
    ``.yaml`` / ``.yml`` → YAML; everything else → JSON.

    Parameters
    ----------
    path:
        Path to the exported plan file.

    Returns
    -------
    ChangePlan
        Deserialised plan.

    Raises
    ------
    FileNotFoundError
        When *path* does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"Plan file not found: {path}")

    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)

    return _dict_to_plan(data)


# ---------------------------------------------------------------------------
# Changelog helpers
# ---------------------------------------------------------------------------


def _append_plan_log(plan: ChangePlan, path: Path) -> None:
    """Append the plan dict as a single JSON line to *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_plan_to_dict(plan)) + "\n")


# ---------------------------------------------------------------------------
# Human-readable summary
# ---------------------------------------------------------------------------


def _print_plan_summary(plan: ChangePlan, *, verbose: bool = False) -> None:
    """Print a human-readable plan summary to stdout."""
    sep = "=" * 72
    risk_icons = {RiskLevel.LOW: "🟢", RiskLevel.MEDIUM: "🟡", RiskLevel.HIGH: "🔴"}
    icon = risk_icons.get(plan.risk_level, "")

    print(f"\n{sep}")
    print(f"  Plan ID    : {plan.plan_id}")
    print(f"  Created    : {plan.created_at}")
    print(f"  Operator   : {plan.operator}")
    if plan.description:
        print(f"  Description: {plan.description}")
    print(f"  Devices    : {len(plan.steps)}")
    print(f"  Risk       : {icon} {plan.risk_level.value.upper()} (score={plan.risk_score:.1f})")
    print(f"  Approved   : {'yes' if plan.approved else 'no (dry-run)'}")
    if plan.applied_at:
        print(f"  Applied at : {plan.applied_at}")
    print(sep)

    for i, step in enumerate(plan.steps, 1):
        sec_tag = "  ⚠ security-sensitive" if step.has_security_changes else ""
        print(f"\n  Step {i}/{len(plan.steps)}: {step.host} [{step.device_role.value}]{sec_tag}")
        print(f"    Commands : {len(step.commands)}")
        if step.applied:
            print("    Status   : ✅ applied")
        elif step.error:
            print(f"    Status   : ❌ error — {step.error}")
        else:
            print("    Status   : pending")
        if verbose and step.diff_preview:
            print()
            for line in step.diff_preview.splitlines():
                print(f"    {line}")

    print(f"\n{sep}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m netops.change.plan",
        description="Change approval workflow: generate plan → dry-run → review → approve → execute.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- plan ---------------------------------------------------------------
    p_plan = sub.add_parser("plan", help="Generate a change plan (dry-run)")
    p_plan.add_argument("--host", required=True, help="Target device hostname or IP")
    p_plan.add_argument(
        "--desired",
        required=True,
        metavar="FILE",
        help="File containing the desired (target) configuration",
    )
    p_plan.add_argument(
        "--current",
        metavar="FILE",
        help="File containing the current running config (omit to skip diff)",
    )
    p_plan.add_argument("--vendor", default="cisco_ios", help="Netmiko device type (default: cisco_ios)")
    p_plan.add_argument(
        "--role",
        default="unknown",
        choices=[r.value for r in DeviceRole],
        help="Device criticality role (default: unknown)",
    )
    p_plan.add_argument("--description", default="", help="Free-text description or ticket reference")
    p_plan.add_argument("--operator", help="Operator name")
    p_plan.add_argument(
        "--export",
        metavar="FILE",
        help="Export plan to FILE (JSON or YAML detected from extension)",
    )
    p_plan.add_argument("--format", choices=["json", "yaml"], default="json", help="Export format")
    p_plan.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Generate plan without connecting to any device (always true for 'plan')",
    )
    p_plan.add_argument("--verbose", action="store_true", help="Show full diff preview")
    p_plan.add_argument("--json", action="store_true", help="Emit plan as JSON to stdout")

    # ---- apply --------------------------------------------------------------
    p_apply = sub.add_parser("apply", help="Apply a previously generated plan")
    p_apply.add_argument(
        "--plan",
        required=True,
        metavar="FILE",
        help="Path to a previously exported plan file (JSON or YAML)",
    )
    p_apply.add_argument(
        "--approve",
        action="store_true",
        help="Explicitly approve the plan — required to push changes to devices",
    )
    p_apply.add_argument("--user", "-u", help="Username (or env NETOPS_USER)")
    p_apply.add_argument("--password", "-p", help="Password (or env NETOPS_PASSWORD)")
    p_apply.add_argument("--transport", choices=["ssh", "telnet"], default="ssh")
    p_apply.add_argument("--port", type=int, help="Override default port (applied to all steps)")
    p_apply.add_argument(
        "--changelog",
        default="~/.netops/plan_changelog.jsonl",
        help="JSON-lines changelog path (default: ~/.netops/plan_changelog.jsonl)",
    )
    p_apply.add_argument("--verbose", action="store_true", help="Show full plan summary")
    p_apply.add_argument("--json", action="store_true", help="Emit result as JSON to stdout")

    return parser


def _handle_plan_command(args: argparse.Namespace) -> None:
    """Handle the ``plan`` CLI subcommand."""
    desired_path = Path(args.desired)
    if not desired_path.exists():
        print(f"❌  Desired config file not found: {desired_path}", file=sys.stderr)
        sys.exit(1)

    desired_text = desired_path.read_text(encoding="utf-8")
    current_text = ""
    if args.current:
        current_path = Path(args.current)
        if not current_path.exists():
            print(f"❌  Current config file not found: {current_path}", file=sys.stderr)
            sys.exit(1)
        current_text = current_path.read_text(encoding="utf-8")

    step_input: dict = {
        "host": args.host,
        "device_type": args.vendor,
        "device_role": args.role,
        "desired_config": desired_text,
        "current_config": current_text,
    }

    username = args.operator or os.environ.get("NETOPS_USER") or getpass.getuser()
    plan = generate_plan(
        [step_input],
        operator=username,
        description=args.description,
    )

    if args.export:
        export_path = Path(args.export)
        fmt = args.format
        if export_path.suffix.lower() in {".yaml", ".yml"}:
            fmt = "yaml"
        export_plan(plan, export_path, fmt=fmt)
        print(f"✅  Plan exported to {export_path}")

    if args.json:
        json.dump(_plan_to_dict(plan), sys.stdout, indent=2)
        print()
    else:
        _print_plan_summary(plan, verbose=args.verbose)

    sys.exit(0)


def _handle_apply_command(args: argparse.Namespace) -> None:
    """Handle the ``apply`` CLI subcommand."""
    plan_path = Path(args.plan)
    if not plan_path.exists():
        print(f"❌  Plan file not found: {plan_path}", file=sys.stderr)
        sys.exit(1)

    plan = load_plan(plan_path)

    username = args.user or os.environ.get("NETOPS_USER") or getpass.getuser()
    password = args.password or os.environ.get("NETOPS_PASSWORD")

    params_list: list[ConnectionParams] = [
        ConnectionParams(
            host=step.host,
            username=username,
            password=password,
            device_type=step.device_type,
            transport=Transport(args.transport),
            port=args.port,
        )
        for step in plan.steps
    ]

    changelog_path = Path(args.changelog).expanduser()

    plan = apply_plan(
        plan,
        connection_params=params_list,
        approved=args.approve,
        changelog_path=changelog_path,
    )

    if args.json:
        json.dump(_plan_to_dict(plan), sys.stdout, indent=2)
        print()
    else:
        _print_plan_summary(plan, verbose=args.verbose)

    has_errors = any(s.error for s in plan.steps)
    sys.exit(1 if has_errors else 0)


def main() -> None:
    """CLI entry point for the change-plan generator and applier."""
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if args.command == "plan":
        _handle_plan_command(args)
    elif args.command == "apply":
        _handle_apply_command(args)


if __name__ == "__main__":
    main()
