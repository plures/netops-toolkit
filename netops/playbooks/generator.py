r"""Playbook generator — auto-generate Ansible remediation playbooks from health check failures.

Reads a health check report (produced by :func:`netops.check.health.run_health_check`
or :func:`netops.check.health.build_health_report`) and generates valid Ansible
YAML playbooks for each device with active alerts.

Generated playbooks:

* Use **vendor-specific** Ansible collection modules (e.g. ``cisco.ios.ios_command``)
* Include **pre/post validation** tasks that capture device state before and
  after remediation for comparison
* Wrap each remediation in a ``block/rescue`` structure so that the ``rescue``
  section runs the rollback tasks on failure
* Default to **dry-run mode** (``dry_run: "true"`` variable) — remediation
  tasks are guarded by ``when: not dry_run | bool`` so the playbook is safe
  to inspect in CI before live execution
* Prompt for **human review** before executing remediation (unless ``--no-pause``
  is passed to the CLI)

Usage::

    # Generate playbooks from a saved health report (dry-run, print to stdout)
    python -m netops.playbooks.generator generate \\
        --from-health-report health_report.json

    # Write playbooks to a directory (one file per device with failures)
    python -m netops.playbooks.generator generate \\
        --from-health-report health_report.json \\
        --output-dir ./remediation-playbooks/

    # Override vendor when the report does not carry device_type
    python -m netops.playbooks.generator generate \\
        --from-health-report health_report.json \\
        --vendor cisco_ios_xr

    # Mark playbook ready for live execution (dry_run=false in the vars block):
    python -m netops.playbooks.generator generate \\
        --from-health-report health_report.json \\
        --live

Public API::

    from netops.playbooks.generator import (
        FailureType,
        GeneratedPlaybook,
        extract_failures,
        generate_playbook,
        generate_playbooks_from_report,
    )
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import yaml

from netops.playbooks.templates.remediation import (
    VENDOR_COMMAND_MODULE,
    RemediationTemplate,
    get_template,
)

logger = logging.getLogger(__name__)

__all__ = [
    "FailureType",
    "GeneratedPlaybook",
    "extract_failures",
    "generate_playbook",
    "generate_playbooks_from_report",
]

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class FailureType(str, Enum):
    """Health-check failure categories that can be remediated."""

    CPU_HIGH = "cpu_high"
    MEMORY_HIGH = "memory_high"
    INTERFACE_ERRORS = "interface_errors"
    BGP_PEER_DOWN = "bgp_peer_down"
    OSPF_NEIGHBOR_DOWN = "ospf_neighbor_down"
    NTP_UNSYNC = "ntp_unsync"
    ENVIRONMENT_ALERT = "environment_alert"
    LOG_ALERTS = "log_alerts"


# Mapping from health-report check key → FailureType
_CHECK_KEY_TO_FAILURE: dict[str, FailureType] = {
    "cpu": FailureType.CPU_HIGH,
    "memory": FailureType.MEMORY_HIGH,
    "interface_errors": FailureType.INTERFACE_ERRORS,
    "bgp": FailureType.BGP_PEER_DOWN,
    "bgp_evpn": FailureType.BGP_PEER_DOWN,
    "ospf": FailureType.OSPF_NEIGHBOR_DOWN,
    "ntp": FailureType.NTP_UNSYNC,
    "environment": FailureType.ENVIRONMENT_ALERT,
    "logs": FailureType.LOG_ALERTS,
    # Vendor-specific check key aliases
    "re": FailureType.ENVIRONMENT_ALERT,
    "fpc": FailureType.ENVIRONMENT_ALERT,
    "mlag": FailureType.ENVIRONMENT_ALERT,
    "alarms": FailureType.ENVIRONMENT_ALERT,
    "routes": FailureType.ENVIRONMENT_ALERT,
}

# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------


@dataclass
class GeneratedPlaybook:
    """A complete Ansible playbook generated from health-check failures.

    Attributes
    ----------
    playbook_id:
        UUID string for correlation with health report entries.
    host:
        Ansible inventory hostname / IP targeted by the playbook.
    vendor:
        Device type string (e.g. ``cisco_ios``) used to select the correct
        Ansible collection modules.
    failure_types:
        List of :class:`FailureType` values that were detected and addressed.
    description:
        Human-readable summary used in the top-level play name.
    plays:
        List of Ansible play dicts ready for serialisation to YAML.
    dry_run:
        When ``True`` the generated vars block sets ``dry_run: "true"`` so
        remediation tasks are skipped unless the operator overrides the var.
    created_at:
        ISO-8601 UTC timestamp of generation.
    source_report_timestamp:
        Timestamp from the originating health check result.

    """

    playbook_id: str
    host: str
    vendor: str
    failure_types: list[FailureType]
    description: str
    plays: list[dict]
    dry_run: bool = True
    created_at: str = ""
    source_report_timestamp: str = ""

    def to_yaml(self) -> str:
        """Serialise the playbook plays to Ansible-compatible YAML."""
        return str(
            yaml.dump(
                self.plays,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )
        )

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dict representation of this playbook."""
        return {
            "playbook_id": self.playbook_id,
            "host": self.host,
            "vendor": self.vendor,
            "failure_types": [ft.value for ft in self.failure_types],
            "description": self.description,
            "dry_run": self.dry_run,
            "created_at": self.created_at,
            "source_report_timestamp": self.source_report_timestamp,
            "plays": self.plays,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _cmd_task(
    name: str,
    vendor: str,
    commands: list[str],
    register: str | None = None,
    when: str | None = None,
) -> dict:
    """Build an Ansible task dict using the correct vendor command module.

    For the generic ``ansible.netcommon.cli_command`` fallback, multiple
    commands are expanded into individual tasks (the module only accepts a
    single command).  For vendor modules that accept a ``commands:`` list,
    all commands are batched into a single task.
    """
    module = VENDOR_COMMAND_MODULE.get(vendor, VENDOR_COMMAND_MODULE["_default"])
    is_generic = module == VENDOR_COMMAND_MODULE["_default"]

    task: dict = {"name": name}
    if is_generic:
        # cli_command takes a single "command:" key
        task[module] = {"command": commands[0] if commands else ""}
    else:
        task[module] = {"commands": commands}

    if register:
        task["register"] = register
    if when:
        task["when"] = when
    return task


def _debug_task(name: str, msg: str) -> dict:
    """Build a simple ansible.builtin.debug task."""
    return {"name": name, "ansible.builtin.debug": {"msg": msg}}


def _pause_task(prompt: str) -> dict:
    """Build an ansible.builtin.pause task for human-review gating."""
    return {
        "name": "HUMAN-REVIEW: Pending human review before remediation",
        "ansible.builtin.pause": {"prompt": prompt},
        "when": "not dry_run | bool",
    }


def _build_remediation_block(
    failure_type: FailureType,
    template: RemediationTemplate,
    vendor: str,
    dry_run: bool,
) -> dict | None:
    """Build the ``block/rescue`` task group for a single remediation.

    Returns ``None`` when the template has no commands to run (e.g. checks
    that have no automated remediation — pre/post validation tasks are still
    included as informational tasks).
    """
    pre_cmds = template.commands_for(vendor, "pre")
    rem_cmds = template.commands_for(vendor, "remediation")
    post_cmds = template.commands_for(vendor, "post")
    rb_cmds = template.commands_for(vendor, "rollback")

    slug = failure_type.value.replace("_", "-")
    block_tasks: list[dict] = []

    # Pre-validation
    if pre_cmds:
        block_tasks.append(
            _cmd_task(
                name=f"PRE-CHECK: Capture state for {template.description}",
                vendor=vendor,
                commands=pre_cmds,
                register=f"pre_{slug.replace('-', '_')}",
            )
        )

    # Remediation (guarded by dry_run)
    if rem_cmds:
        block_tasks.append(
            _cmd_task(
                name=f"REMEDIATE: {template.description}",
                vendor=vendor,
                commands=rem_cmds,
                when="not dry_run | bool",
            )
        )
    else:
        block_tasks.append(
            _debug_task(
                name=f"REMEDIATE: {template.description}",
                msg=f"No automated remediation available. {template.rollback_note}",
            )
        )

    # Post-validation
    if post_cmds:
        block_tasks.append(
            _cmd_task(
                name=f"POST-CHECK: Verify state after {template.description}",
                vendor=vendor,
                commands=post_cmds,
                register=f"post_{slug.replace('-', '_')}",
            )
        )

    # Rescue / rollback section
    rescue_tasks: list[dict] = []
    if rb_cmds:
        rescue_tasks.append(
            _cmd_task(
                name=f"ROLLBACK: Undo {template.description}",
                vendor=vendor,
                commands=rb_cmds,
            )
        )
    rescue_tasks.append(
        _debug_task(
            name=f"ROLLBACK-NOTE: {failure_type.value}",
            msg=template.rollback_note or "No rollback procedure defined.",
        )
    )

    result: dict = {"block": block_tasks, "rescue": rescue_tasks}
    return result


def _build_play(
    host: str,
    vendor: str,
    failures: list[tuple[FailureType, dict]],
    dry_run: bool,
    include_pause: bool,
) -> dict:
    """Build a single Ansible play dict for all detected failures on *host*."""
    failure_labels = ", ".join(ft.value for ft, _ in failures)
    play: dict = {
        "name": f"Remediation playbook for {host} [{failure_labels}]",
        "hosts": host,
        "gather_facts": False,
        "vars": {
            "dry_run": str(dry_run).lower(),
        },
        "tasks": [],
    }

    tasks: list[dict] = []

    # Human-review gate (skipped in dry-run; the 'when' condition handles it)
    if include_pause:
        tasks.append(
            _pause_task(
                f"Remediation plan for {host} is ready. "
                "Review the task list above and press Enter to proceed, Ctrl-C to abort."
            )
        )

    for failure_type, _detail in failures:
        template = get_template(failure_type.value)
        if template is None:
            logger.warning("No template found for failure type %s — skipping", failure_type)
            continue

        block = _build_remediation_block(failure_type, template, vendor, dry_run)
        if block:
            tasks.append(block)

    play["tasks"] = tasks
    return play


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_failures(health_result: dict) -> list[tuple[FailureType, dict]]:
    """Extract alerting checks from a single device health-check result.

    Parameters
    ----------
    health_result:
        A result dict as returned by :func:`netops.check.health.run_health_check`
        or a vendor-specific equivalent.  Must contain a ``"checks"`` key
        mapping check names to check result dicts with an ``"alert"`` boolean.

    Returns
    -------
    list[tuple[FailureType, dict]]
        Ordered list of ``(failure_type, check_detail)`` pairs for every check
        where ``alert`` is ``True``.

    """
    failures: list[tuple[FailureType, dict]] = []
    seen: set[FailureType] = set()

    checks = health_result.get("checks", {})
    for check_key, check_data in checks.items():
        if not isinstance(check_data, dict):
            continue
        if not check_data.get("alert", False):
            continue

        failure_type = _CHECK_KEY_TO_FAILURE.get(check_key)
        if failure_type is None:
            logger.debug("No failure type mapping for check key %r — ignoring", check_key)
            continue

        # Deduplicate (e.g. bgp + bgp_evpn both map to BGP_PEER_DOWN)
        if failure_type in seen:
            continue
        seen.add(failure_type)

        failures.append((failure_type, check_data))

    return failures


def generate_playbook(
    health_result: dict,
    vendor: str | None = None,
    dry_run: bool = True,
    include_pause: bool = True,
) -> GeneratedPlaybook | None:
    """Generate a remediation playbook from a single device health-check result.

    Parameters
    ----------
    health_result:
        A result dict as returned by :func:`netops.check.health.run_health_check`.
    vendor:
        Override the device vendor string.  When ``None``, the value is taken
        from ``health_result["device_type"]`` if present; otherwise the generic
        ``_default`` module mapping is used.
    dry_run:
        When ``True`` (the default), remediation tasks are gated behind
        ``when: not dry_run | bool`` so the playbook can be safely reviewed
        before live execution.
    include_pause:
        When ``True``, inserts a ``ansible.builtin.pause`` task that requires
        operator acknowledgement before executing remediation tasks.  The pause
        is itself gated by ``when: not dry_run | bool`` so it never blocks
        dry-run or CI runs.

    Returns
    -------
    GeneratedPlaybook | None
        A :class:`GeneratedPlaybook` when at least one alerting check is found.
        Returns ``None`` when the device has no active alerts or the result is
        not successful.

    """
    if not health_result.get("success", False):
        return None

    failures = extract_failures(health_result)
    if not failures:
        return None

    host = health_result.get("host", "unknown")
    resolved_vendor = vendor or health_result.get("device_type", "_default")

    play = _build_play(host, resolved_vendor, failures, dry_run, include_pause)
    playbook_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    failure_types = [ft for ft, _ in failures]
    description = f"Auto-generated remediation for {host}: " + ", ".join(
        ft.value for ft in failure_types
    )

    return GeneratedPlaybook(
        playbook_id=playbook_id,
        host=host,
        vendor=resolved_vendor,
        failure_types=failure_types,
        description=description,
        plays=[play],
        dry_run=dry_run,
        created_at=created_at,
        source_report_timestamp=health_result.get("timestamp", ""),
    )


def generate_playbooks_from_report(
    health_report: dict,
    vendor: str | None = None,
    dry_run: bool = True,
    include_pause: bool = True,
    host_filter: str | None = None,
) -> list[GeneratedPlaybook]:
    """Generate remediation playbooks from an aggregated health report.

    Accepts the dict returned by :func:`netops.check.health.build_health_report`
    (which contains a ``"results"`` list) **or** a bare list of per-device
    health results.

    Parameters
    ----------
    health_report:
        Dict with a ``"results"`` key (from :func:`build_health_report`) or a
        bare list of per-device health result dicts.
    vendor:
        Global vendor override applied to all devices.  Per-device
        ``device_type`` fields take precedence when *vendor* is ``None``.
    dry_run:
        Passed to :func:`generate_playbook` for every device.
    include_pause:
        Passed to :func:`generate_playbook` for every device.
    host_filter:
        When given, only generate a playbook for the device whose ``host``
        field matches this value (case-insensitive substring match).

    Returns
    -------
    list[GeneratedPlaybook]
        One playbook per device that has at least one active alert.

    """
    if isinstance(health_report, list):
        results = health_report
    else:
        results = health_report.get("results", [])

    playbooks: list[GeneratedPlaybook] = []
    for result in results:
        if host_filter:
            if host_filter.lower() not in result.get("host", "").lower():
                continue

        pb = generate_playbook(result, vendor=vendor, dry_run=dry_run, include_pause=include_pause)
        if pb is not None:
            playbooks.append(pb)

    return playbooks


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for the playbook generator CLI."""
    parser = argparse.ArgumentParser(
        prog="python -m netops.playbooks.generator",
        description="Generate Ansible remediation playbooks from health-check reports.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- generate subcommand ----
    p_gen = sub.add_parser(
        "generate",
        help="Generate playbooks from a saved health report",
    )
    p_gen.add_argument(
        "--from-health-report",
        required=True,
        metavar="FILE",
        help="Path to a JSON health report (single result or build_health_report output)",
    )
    p_gen.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Directory to write playbook YAML files (one per device). "
        "When omitted, playbooks are printed to stdout.",
    )
    p_gen.add_argument(
        "--vendor",
        metavar="VENDOR",
        help="Override vendor/device_type for all devices (e.g. cisco_ios_xr)",
    )
    p_gen.add_argument(
        "--host",
        metavar="HOSTNAME",
        help="Filter: only generate a playbook for this host (substring match)",
    )
    p_gen.add_argument(
        "--live",
        action="store_true",
        help="Set dry_run=false in the generated playbook vars (enables live remediation tasks). "
        "Default is dry_run=true for safety.",
    )
    p_gen.add_argument(
        "--no-pause",
        action="store_true",
        help="Omit the human-review pause task from the generated playbook",
    )
    p_gen.add_argument(
        "--json",
        action="store_true",
        help="Output playbook metadata as JSON instead of YAML",
    )
    return parser


def _handle_generate(args: argparse.Namespace) -> None:
    """Handle the ``generate`` subcommand."""
    report_path = Path(args.from_health_report)
    if not report_path.exists():
        logger.error("Health report file not found: %s", report_path)
        sys.exit(1)

    try:
        raw = json.loads(report_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to read health report: %s", exc)
        sys.exit(1)

    dry_run = not args.live
    include_pause = not args.no_pause

    playbooks = generate_playbooks_from_report(
        raw,
        vendor=args.vendor,
        dry_run=dry_run,
        include_pause=include_pause,
        host_filter=args.host,
    )

    if not playbooks:
        print("No alerting devices found in the health report — no playbooks generated.")
        return

    output_dir = Path(args.output_dir) if args.output_dir else None
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    for pb in playbooks:
        if args.json:
            content = json.dumps(pb.to_dict(), indent=2)
            ext = "json"
        else:
            content = pb.to_yaml()
            ext = "yml"

        if output_dir:
            safe_host = pb.host.replace("/", "_").replace(":", "_")
            out_file = output_dir / f"remediate-{safe_host}.{ext}"
            out_file.write_text(content)
            print(f"Written: {out_file}")
        else:
            print(
                f"# --- Playbook for {pb.host} (failures: {[ft.value for ft in pb.failure_types]}) ---"
            )
            print(content)


def main() -> None:
    """CLI entry point for the remediation playbook generator."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "generate":
        _handle_generate(args)


if __name__ == "__main__":
    main()
