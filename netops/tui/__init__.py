#!/usr/bin/env python3
"""netops-tui — Terminal UI for netops-toolkit.

A textual-based TUI that wraps netops-toolkit for use on jumpboxes
without GUI access. Provides interactive access to:
- Inventory scan (ping sweep + SNMP + deep SSH)
- Config collection & diff
- Health checks
- VLAN audit
- Credential vault
- CSV/JSON export

Usage:
    netops-tui
    python -m netops.tui
"""

# ruff: noqa: E402

from __future__ import annotations

import asyncio
import csv
import json
import logging
import os
import sys
from pathlib import Path
from typing import cast

from netops.terminal import (
    TerminalProfile,
    configure_terminal_environment,
    terminal_profile,
    terminal_text,
)

# A console-script entry point imports this package before ``__main__`` can
# parse --compat. Honour the flag here as well, before Textual reads its
# environment-based colour settings.
if "--compat" in sys.argv:
    os.environ["NETOPS_TUI_COMPAT"] = "1"
configure_terminal_environment(os.environ)

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Log,
    Static,
    TextArea,
)

from netops.logging_setup import setup_logging


class TerminalLog(Log):
    """Log widget that applies terminal compatibility text at its boundary."""

    def write_line(self, line: str, scroll_end: bool | None = None) -> TerminalLog:
        """Write a line using the active terminal's safe text representation."""
        return super().write_line(terminal_text(line), scroll_end)


# ---------------------------------------------------------------------------
# Inventory data store (JSON file)
# ---------------------------------------------------------------------------

INVENTORY_FILE = Path(os.environ.get("NETOPS_INVENTORY", "inventory.json"))
SETTINGS_FILE = Path(os.environ.get("NETOPS_TUI_SETTINGS", Path.home() / ".netops" / "tui-settings.json"))

DEFAULT_SETTINGS = {
    "snmp_port": 161,
    "snmp_timeout": 2,
    "ping_workers": 50,
    "snmp_concurrency": 10,
    "ssh_timeout": 15,
    "ssh_concurrency": 5,
    "backup_workers": 5,
}


def load_inventory() -> dict:
    """Load the persisted inventory, or return an empty inventory."""
    if INVENTORY_FILE.exists():
        return json.loads(INVENTORY_FILE.read_text())
    return {"devices": {}}


def save_inventory(data: dict) -> None:
    """Persist an inventory to disk."""
    INVENTORY_FILE.write_text(json.dumps(data, indent=2))


def load_settings() -> dict:
    """Load user-scoped, non-secret TUI settings with safe defaults."""
    try:
        saved = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        saved = {}
    if not isinstance(saved, dict):
        saved = {}
    return {**DEFAULT_SETTINGS, **saved}


def save_settings(settings: dict) -> None:
    """Persist non-secret TUI defaults without storing credentials."""
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")


def export_csv(data: dict, path: str = "inventory.csv") -> int:
    """Export inventory devices to CSV and return the number written."""
    devices = data.get("devices", {})
    if not devices:
        return 0
    all_keys: set[str] = set()
    for info in devices.values():
        if isinstance(info, dict):
            all_keys.update(info.keys())
    fieldnames = ["hostname"] + sorted(all_keys)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for hostname, info in sorted(devices.items()):
            row = {"hostname": hostname}
            if isinstance(info, dict):
                for k, v in info.items():
                    row[k] = str(v) if not isinstance(v, str) else v
            writer.writerow(row)
    return len(devices)


def netops_app(screen: ModalScreen) -> NetopsTUI:
    """Return the running application typed as the concrete netops app."""
    return cast("NetopsTUI", screen.app)


class DeviceTable(DataTable):
    """Device list with table-scoped selection keys.

    Keeping Space on the focused table prevents it from falling through to an
    application-wide action while Textual is dispatching a terminal key event.
    That is safer for terminal emulators and avoids mutating a table from a
    parent binding during its own key handling.
    """

    BINDINGS = [
        *DataTable.BINDINGS,
        Binding("space,x", "toggle_selection", "Select"),
        Binding("ctrl+a", "toggle_all_selection", "Select all"),
    ]

    def action_toggle_selection(self) -> None:
        """Toggle the row under this table's cursor."""
        cast("NetopsTUI", self.app).toggle_focused_selection()

    def action_toggle_all_selection(self) -> None:
        """Toggle all inventory rows without falling through to the App."""
        cast("NetopsTUI", self.app).toggle_all_selection()


# ---------------------------------------------------------------------------
# Scan Screen
# ---------------------------------------------------------------------------

class ScanScreen(ModalScreen):
    """Modal for running an inventory scan."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        """Compose the inventory scan modal."""
        settings = netops_app(self).settings
        with Vertical(id="scan-modal"):
            yield Label(terminal_text("🔍 Inventory Scan"), id="scan-title")
            yield Input(placeholder="Subnets (e.g. 10.0.0.0/24, 192.168.1.0/24)", id="scan-subnet")
            yield Input(placeholder="Or path to hosts file (hosts.csv or ips.txt)", id="scan-hosts-file")
            yield Input(placeholder="SNMP communities (comma-sep, or leave blank for registry)", id="scan-community")
            yield Label("SNMP scan controls", classes="form-section-title")
            with Horizontal(classes="advanced-row"):
                with Vertical(classes="advanced-field"):
                    yield Label("SNMP port", id="scan-snmp-port-label", classes="field-label")
                    yield Input(value=str(settings["snmp_port"]), id="scan-snmp-port")
                with Vertical(classes="advanced-field"):
                    yield Label("SNMP timeout (seconds)", id="scan-snmp-timeout-label", classes="field-label")
                    yield Input(value=str(settings["snmp_timeout"]), id="scan-snmp-timeout")
            with Horizontal(classes="advanced-row"):
                with Vertical(classes="advanced-field"):
                    yield Label("Ping workers", id="scan-ping-workers-label", classes="field-label")
                    yield Input(value=str(settings["ping_workers"]), id="scan-ping-workers")
                with Vertical(classes="advanced-field"):
                    yield Label("SNMP concurrency", id="scan-snmp-concurrency-label", classes="field-label")
                    yield Input(value=str(settings["snmp_concurrency"]), id="scan-snmp-concurrency")
            yield Input(placeholder="SSH user (vault default if blank)", id="scan-user")
            yield Input(placeholder="SSH password (vault default if blank)", password=True, id="scan-password")
            yield Label("SSH scan controls", classes="form-section-title")
            with Horizontal(classes="advanced-row"):
                with Vertical(classes="advanced-field"):
                    yield Label("SSH timeout (seconds)", id="scan-ssh-timeout-label", classes="field-label")
                    yield Input(value=str(settings["ssh_timeout"]), id="scan-ssh-timeout")
                with Vertical(classes="advanced-field"):
                    yield Label("SSH concurrency", id="scan-ssh-concurrency-label", classes="field-label")
                    yield Input(value=str(settings["ssh_concurrency"]), id="scan-ssh-concurrency")
            with Horizontal(classes="advanced-row"):
                with Vertical(classes="advanced-options"):
                    yield Label("Discovery options", classes="field-label")
                    yield Checkbox("Probe every address (skip ping)", id="scan-skip-ping")
                    yield Checkbox("Ping only (skip SNMP)", id="scan-skip-snmp")
            yield Input(placeholder="Optional export file (.json or .csv)", id="scan-output")
            with Horizontal(id="scan-actions", classes="modal-actions"):
                yield Button("Scan", variant="primary", id="btn-scan")
                yield Button("Ping Only", variant="default", id="btn-ping")
                yield Button("Cancel", variant="error", id="btn-cancel-scan")
            yield Label("[dim]Tip: separate multiple subnets with commas[/dim]")
            yield TerminalLog(id="scan-log", highlight=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle scan modal button presses."""
        if event.button.id == "btn-cancel-scan":
            self.dismiss()
        elif event.button.id in ("btn-scan", "btn-ping"):
            skip_snmp = event.button.id == "btn-ping" or self.query_one("#scan-skip-snmp", Checkbox).value
            skip_ping = self.query_one("#scan-skip-ping", Checkbox).value
            subnet_text = self.query_one("#scan-subnet", Input).value.strip()
            hosts_file = self.query_one("#scan-hosts-file", Input).value.strip()
            if not subnet_text and not hosts_file:
                self.query_one("#scan-log", Log).write_line("❌ Enter subnet(s) or a hosts file path")
                return
            community_input = self.query_one("#scan-community", Input).value.strip()
            # Parse comma-separated communities or use registry
            if community_input:
                communities = [c.strip() for c in community_input.split(",") if c.strip()]
                # Add to registry for future use
                from netops.core.community import CommunityRegistry
                reg = CommunityRegistry()
                for c in communities:
                    reg.add_string(c)
                community = communities[0]  # Primary for initial scan
            else:
                community = "public"
            user = self.query_one("#scan-user", Input).value.strip()
            password = self.query_one("#scan-password", Input).value.strip()
            vault_credentials = netops_app(self).credentials_for()
            user = user or str(vault_credentials.get("username", ""))
            password = password or str(vault_credentials.get("password", ""))
            output = self.query_one("#scan-output", Input).value.strip()
            log = self.query_one("#scan-log", Log)
            try:
                snmp_port = self._positive_int("#scan-snmp-port", "SNMP port")
                snmp_timeout = self._positive_int("#scan-snmp-timeout", "SNMP timeout")
                ping_workers = self._positive_int("#scan-ping-workers", "ping workers")
                snmp_concurrency = self._positive_int("#scan-snmp-concurrency", "SNMP concurrency")
                ssh_timeout = self._positive_int("#scan-ssh-timeout", "SSH timeout")
                ssh_concurrency = self._positive_int("#scan-ssh-concurrency", "SSH concurrency")
            except ValueError as exc:
                log.write_line(f"❌ {exc}")
                return
            # Parse multiple subnets (comma or space separated)
            subnets = [s.strip() for s in subnet_text.replace(',', ' ').split() if s.strip()] if subnet_text else []
            log.write_line(f"🔍 Scanning {len(subnets)} subnet(s)..." if subnets else f"🔍 Scanning from {hosts_file}...")
            self.run_scan(
                subnets, hosts_file, community, user, password, skip_ping, skip_snmp,
                snmp_port, snmp_timeout, ping_workers, snmp_concurrency,
                ssh_timeout, ssh_concurrency, output, log,
            )

    def _positive_int(self, field_id: str, label: str) -> int:
        """Return a positive integer from an advanced scan field."""
        try:
            value = int(self.query_one(field_id, Input).value.strip())
        except ValueError as exc:
            raise ValueError(f"{label} must be a whole number") from exc
        if value < 1:
            raise ValueError(f"{label} must be at least 1")
        return value

    def run_scan(
        self, subnets, hosts_file, community, user, password, skip_ping, skip_snmp,
        snmp_port, snmp_timeout, ping_workers, snmp_concurrency, ssh_timeout,
        ssh_concurrency, output, log,
    ):
        """Run scan in background."""
        async def _scan():
            try:
                from netops.inventory.scan import (
                    deep_enrich,
                    results_to_inventory_fragment,
                    scan_subnet_async,
                )

                all_results = []

                # Scan from hosts file if provided
                if hosts_file:
                    import csv as _csv
                    from pathlib import Path

                    from netops.inventory.scan import ScanResult
                    hosts_path = Path(hosts_file)
                    if not hosts_path.exists():
                        log.write_line(f"  ❌ File not found: {hosts_file}")
                        return
                    hosts = []
                    text = hosts_path.read_text().strip()
                    if hosts_path.suffix == '.csv':
                        reader = _csv.DictReader(text.splitlines())
                        for row in reader:
                            h = row.get('host') or row.get('ip') or row.get('hostname') or row.get('address', '')
                            if h.strip():
                                hosts.append(h.strip())
                    else:
                        hosts = [
                            stripped
                            for line in text.splitlines()
                            if (stripped := line.strip()) and not stripped.startswith("#")
                        ]
                    log.write_line(f"  📋 Loaded {len(hosts)} hosts from {hosts_file}")
                    all_results.extend([ScanResult(host=h, reachable=True) for h in hosts])

                # Scan each subnet
                for i, subnet in enumerate(subnets):
                    log.write_line(f"  [{i+1}/{len(subnets)}] Scanning {subnet}...")
                    from netops.core.bastion import active_bastion
                    if active_bastion() is not None:
                        from netops.inventory.scan import scan_subnet_through_active_bastion
                        log.write_line("    🔐 Discovering SSH endpoints through the active bastion")
                        results = await asyncio.get_event_loop().run_in_executor(
                            None, lambda: scan_subnet_through_active_bastion(
                                subnet, max_workers=ping_workers, timeout=ssh_timeout
                            )
                        )
                    else:
                        results = await scan_subnet_async(
                            subnet=subnet,
                            community=community,
                            snmp_port=snmp_port,
                            snmp_timeout=snmp_timeout,
                            ping_workers=ping_workers,
                            snmp_concurrency=snmp_concurrency,
                            skip_ping=skip_ping,
                            skip_snmp=skip_snmp,
                        )
                    reachable = sum(1 for r in results if r.reachable)
                    log.write_line(f"    Found {reachable} reachable hosts")
                    all_results.extend(results)

                fragment = results_to_inventory_fragment(all_results)
                # Always collect full device info when creds are available
                if user and password:
                    device_count = len(fragment.get("devices", {}))
                    log.write_line(f"  🔬 Collecting device info via SSH ({device_count} device(s))...")
                    fragment = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: deep_enrich(
                            fragment,
                            username=user,
                            password=password,
                            concurrency=ssh_concurrency,
                            timeout=ssh_timeout,
                        ),
                    )
                    # Learn community strings from identified devices
                    try:
                        from netops.core.community import (
                            CommunityRegistry,
                            extract_communities_via_ssh,
                        )
                        reg = CommunityRegistry()
                        for dname, dinfo in fragment.get("devices", {}).items():
                            if isinstance(dinfo, dict) and dinfo.get("vendor", "unknown") != "unknown":
                                host_ip = dinfo.get("host", dname)
                                comms, _ = await asyncio.get_event_loop().run_in_executor(
                                    None,
                                    lambda h=host_ip, v=dinfo.get("vendor"): extract_communities_via_ssh(
                                        h, user, password, known_vendor=v
                                    ),
                                )
                                if comms:
                                    for c in comms:
                                        reg.add_string(c)
                                    reg.set_device(host_ip, comms[0], dinfo.get("vendor"))
                                    log.write_line(f"    🔑 {dname}: learned {len(comms)} community string(s)")
                    except Exception as e:
                        log.write_line(f"    ⚠️ Community extraction: {e}")

                    identified = sum(1 for d in fragment.get("devices", {}).values()
                                     if isinstance(d, dict) and d.get("vendor", "unknown") != "unknown")
                    log.write_line(f"    ✅ {identified}/{device_count} device(s) fully identified")

                # Merge with existing
                existing = load_inventory()
                for hostname, info in fragment.get("devices", {}).items():
                    existing.setdefault("devices", {})[hostname] = info

                save_inventory(existing)
                device_count = len(fragment.get("devices", {}))
                log.write_line(f"  ✅ {device_count} devices saved to {INVENTORY_FILE}")
                if output:
                    from netops.inventory.scan import _fragment_to_csv
                    output_path = Path(output)
                    if output_path.suffix.lower() == ".csv":
                        _fragment_to_csv(fragment, output_path)
                    else:
                        output_path.write_text(json.dumps(fragment, indent=2), encoding="utf-8")
                    log.write_line(f"  📄 Exported scan results to {output_path}")
                log.write_line("  Close this dialog and press 'r' to refresh the table")

            except ImportError as e:
                log.write_line(f"  ❌ Missing dependency: {e}")
            except Exception as e:
                log.write_line(f"  ❌ Error: {e}")

        self.run_worker(_scan(), name="inventory scan", group="inventory-scan", exit_on_error=False, exclusive=True)


# ---------------------------------------------------------------------------
# Health Check Screen
# ---------------------------------------------------------------------------

class HealthScreen(ModalScreen):
    """Modal for running health checks."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, selected_host: str | None = None):
        super().__init__()
        self._selected_host = selected_host

    def compose(self) -> ComposeResult:
        """Compose the health check modal."""
        with Vertical(id="health-modal"):
            yield Label(terminal_text("🏥 Health Check"), id="health-title")
            yield Input(placeholder="Hostname or IP", id="health-host",
                        value=self._selected_host or "")
            yield Input(placeholder="Optional inventory file (instead of a single host)", id="health-inventory")
            with Horizontal(classes="advanced-row"):
                yield Input(placeholder="Inventory group filter", id="health-group")
                yield Input(placeholder="Vendor for a single host (auto-detect when blank)", id="health-vendor")
                yield Input(placeholder="Thresholds, e.g. cpu=80,mem=85", id="health-threshold")
            yield Input(placeholder="SSH user (vault if blank)", id="health-user")
            yield Input(placeholder="SSH password (vault if blank)", password=True, id="health-pass")
            yield Input(placeholder="Optional JSON report output file", id="health-output")
            yield Checkbox("Mark the run failed when any alert is found", id="health-fail-on-alert")
            with Horizontal(classes="modal-actions"):
                yield Button("Check", variant="primary", id="btn-health-run")
                yield Button("Close", id="btn-health-close")
            yield TerminalLog(id="health-log", highlight=True)

    def on_error(self, event) -> None:
        """Global error handler — display errors, never crash."""
        logger = logging.getLogger("netops.tui")
        logger.error(f"Unhandled error: {event}", exc_info=True)
        # Try to show in status bar if possible
        try:
            from textual.widgets import Static
            status = self.query_one(".status-bar", Static)
            status.update(f"  ⚠️ Error (see logs): {str(event)[:60]}")
        except Exception:
            pass

    def on_exception(self, error: Exception) -> None:
        """Catch exceptions from workers/tasks — log, don't crash."""
        logger = logging.getLogger("netops.tui")
        logger.error(f"Background task error: {error}", exc_info=True)

    def on_mount(self) -> None:
        """Pre-populate vendor field if host is in inventory."""
        pass



    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle health modal button presses."""
        if event.button.id == "btn-health-close":
            self.dismiss()
        elif event.button.id == "btn-health-run":
            host = self.query_one("#health-host", Input).value.strip()
            inventory_path = self.query_one("#health-inventory", Input).value.strip()
            group = self.query_one("#health-group", Input).value.strip()
            vendor_input = self.query_one("#health-vendor", Input).value.strip()
            threshold_text = self.query_one("#health-threshold", Input).value.strip()
            output = self.query_one("#health-output", Input).value.strip()
            fail_on_alert = self.query_one("#health-fail-on-alert", Checkbox).value
            user = self.query_one("#health-user", Input).value.strip()
            password = self.query_one("#health-pass", Input).value.strip()
            log = self.query_one("#health-log", Log)
            if not inventory_path and not host:
                log.write_line("❌ Enter a host or an inventory file")
                return

            log.write_line(
                f"🔍 Checking inventory {inventory_path}..." if inventory_path
                else f"🔍 Checking {host}..."
            )

            async def _check():
                try:
                    from netops.check.health import (
                        DEFAULT_CPU_THRESHOLD,
                        DEFAULT_MEM_THRESHOLD,
                        _parse_thresholds,
                        run_health_check,
                    )
                    from netops.core.connection import (
                        ConnectionParams,
                        Transport,
                        jump_host_from_inventory,
                    )
                    from netops.core.inventory import Inventory

                    thresholds = _parse_thresholds(threshold_text)
                    cpu_threshold = thresholds.get("cpu", DEFAULT_CPU_THRESHOLD)
                    mem_threshold = thresholds.get("mem", DEFAULT_MEM_THRESHOLD)
                    if inventory_path:
                        inv = Inventory.from_file(inventory_path)
                        devices = inv.filter(group=group or None) if group else list(inv.devices.values())
                        if not devices:
                            raise ValueError("no devices matched the selected inventory/group")
                        params_list = []
                        for device in devices:
                            vault_credentials = self.app.credentials_for(device.hostname, device.groups)
                            params_list.append(
                                ConnectionParams(
                                    host=device.host,
                                    username=user or device.username or vault_credentials.get("username"),
                                    password=password or device.password or vault_credentials.get("password"),
                                    device_type=device.vendor,
                                    jump_host=jump_host_from_inventory(device),
                                    transport=Transport(device.transport) if device.transport else Transport.SSH,
                                    port=device.port,
                                    enable_password=device.enable_password or vault_credentials.get("enable_password"),
                                )
                            )
                    else:
                        inv = load_inventory()
                        device_info = inv.get("devices", {}).get(host, {})
                        vendor = vendor_input or device_info.get("vendor") or "autodetect"
                        vault_credentials = self.app.credentials_for(host, device_info.get("groups", []))
                        params_list = [
                            ConnectionParams(
                                host=device_info.get("host", host),
                                username=user or vault_credentials.get("username"),
                                password=password or vault_credentials.get("password"),
                                device_type=vendor,
                                enable_password=vault_credentials.get("enable_password"),
                            )
                        ]

                    results = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: [
                            run_health_check(
                                params, cpu_threshold=cpu_threshold, mem_threshold=mem_threshold
                            )
                            for params in params_list
                        ],
                    )
                    if output:
                        payload = results if len(results) != 1 else results[0]
                        Path(output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
                        log.write_line(f"  📄 Wrote JSON report to {output}")

                    for result in results:
                        icon = "🚨" if result.get("overall_alert") else "✅"
                        log.write_line(f"  {icon} {result['host']}")
                        if not result.get("success"):
                            log.write_line(f"    ❌ Connection failed: {result.get('error', 'unknown')}")
                            continue
                        for check_name, check_data in result.get("checks", {}).items():
                            alert = check_data.get("alert", False)
                            check_icon = "⚠️" if alert else "✅"
                            if "utilization" in check_data and check_data["utilization"] is not None:
                                summary = (
                                    f"{check_data['utilization']:.1f}% "
                                    f"(threshold {check_data.get('threshold', '?')}%)"
                                )
                            elif "with_errors" in check_data:
                                summary = (
                                    f"{check_data['with_errors']}/{check_data.get('total', 0)} "
                                    "interfaces with errors"
                                )
                            elif "critical_count" in check_data:
                                summary = (
                                    f"{check_data['critical_count']} critical, "
                                    f"{check_data.get('major_count', 0)} major"
                                )
                            else:
                                summary = "OK" if not alert else "ALERT"
                            log.write_line(f"    {check_icon} {check_name}: {summary}")

                    alerts = any(result.get("overall_alert") for result in results)
                    if alerts and fail_on_alert:
                        log.write_line("  🚨 Run marked failed: fail-on-alert selected")
                    else:
                        log.write_line("  🚨 ALERTS DETECTED" if alerts else "  ✅ All checks passed")

                except ImportError as e:
                    log.write_line(f"  ❌ Missing: {e}")
                except Exception as e:
                    log.write_line(f"  ❌ {e}")

            self.run_worker(_check(), name="health check", group="health-check", exit_on_error=False, exclusive=True)


# ---------------------------------------------------------------------------
# Config Diff Screen
# ---------------------------------------------------------------------------

class DiffScreen(ModalScreen):
    """Modal for the CLI-equivalent semantic configuration diff."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        """Compose the configuration diff modal."""
        with Vertical(id="diff-modal"):
            yield Label(terminal_text("🔎 Configuration Diff"), id="diff-title")
            yield Input(placeholder="Before (original) config file", id="diff-before")
            yield Input(placeholder="After (new) config file", id="diff-after")
            with Horizontal(classes="advanced-row"):
                yield Input(value="semantic", placeholder="Format: semantic, unified, json", id="diff-format")
                yield Input(placeholder="Style: auto, cisco, junos, flat", id="diff-style")
            yield Input(placeholder="Optional output file", id="diff-output")
            with Horizontal(classes="modal-actions"):
                yield Button("Compare", variant="primary", id="btn-diff-run")
                yield Button("Close", id="btn-diff-close")
            yield TerminalLog(id="diff-log", highlight=False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Run a semantic diff or close the modal."""
        if event.button.id == "btn-diff-close":
            self.dismiss()
            return
        if event.button.id != "btn-diff-run":
            return

        before = Path(self.query_one("#diff-before", Input).value.strip())
        after = Path(self.query_one("#diff-after", Input).value.strip())
        output = self.query_one("#diff-output", Input).value.strip()
        fmt = self.query_one("#diff-format", Input).value.strip().lower() or "semantic"
        style_name = self.query_one("#diff-style", Input).value.strip().lower()
        log = self.query_one("#diff-log", Log)
        if fmt not in {"semantic", "unified", "json"}:
            log.write_line("❌ Format must be semantic, unified, or json")
            return
        if style_name and style_name not in {"cisco", "junos", "flat"}:
            log.write_line("❌ Style must be auto, cisco, junos, or flat")
            return
        if not before.is_file() or not after.is_file():
            log.write_line("❌ Both before and after config files must exist")
            return

        async def _diff() -> None:
            try:
                from netops.change.diff import (
                    ConfigStyle,
                    diff_configs,
                    format_json,
                    format_semantic,
                    format_unified,
                )

                def build_output() -> str:
                    style = ConfigStyle(style_name) if style_name else None
                    result = diff_configs(
                        before.read_text(encoding="utf-8"),
                        after.read_text(encoding="utf-8"),
                        style=style,
                    )
                    if fmt == "unified":
                        return format_unified(result, fromfile=str(before), tofile=str(after))
                    if fmt == "json":
                        return format_json(result)
                    return format_semantic(result)

                rendered = await asyncio.get_event_loop().run_in_executor(None, build_output)
                if output:
                    Path(output).write_text(rendered, encoding="utf-8")
                    log.write_line(f"📄 Wrote {fmt} diff to {output}")
                for line in rendered.splitlines() or ["No differences found"]:
                    log.write_line(line)
            except Exception as exc:
                log.write_line(f"❌ {exc}")

        self.run_worker(_diff(), name="configuration diff", group="configuration-diff", exit_on_error=False, exclusive=True)


# ---------------------------------------------------------------------------
# Active Bastion Screen
# ---------------------------------------------------------------------------

class BastionScreen(ModalScreen):
    """Modal for managing the workstation-wide active SSH bastion."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        """Compose the active bastion management modal."""
        with Vertical(id="bastion-modal"):
            yield Label(terminal_text("🔐 Active SSH Bastion"), id="bastion-title")
            yield Input(placeholder="Bastion host", id="bastion-host")
            yield Input(placeholder="Bastion username", id="bastion-user")
            yield Input(value="22", placeholder="SSH port", id="bastion-port")
            yield Input(placeholder="Optional private key file", id="bastion-key-file")
            yield Input(placeholder="Password (not stored)", password=True, id="bastion-password")
            yield Input(placeholder="Private-key passphrase (not stored)", password=True, id="bastion-key-passphrase")
            with Horizontal(classes="modal-actions"):
                yield Button("Connect", variant="primary", id="btn-bastion-connect")
                yield Button("Status", id="btn-bastion-status")
                yield Button("Disconnect", variant="warning", id="btn-bastion-disconnect")
                yield Button("Close", id="btn-bastion-close")
            yield TerminalLog(id="bastion-log", highlight=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Connect, inspect, or disconnect the active bastion."""
        if event.button.id == "btn-bastion-close":
            self.dismiss()
            return
        log = self.query_one("#bastion-log", Log)

        async def _manage() -> None:
            try:
                from netops.core.bastion import (
                    ActiveBastionUnavailableError,
                    active_bastion,
                    connect_active_bastion,
                    disconnect_active_bastion,
                )

                if event.button.id == "btn-bastion-status":
                    try:
                        state = await asyncio.get_event_loop().run_in_executor(None, active_bastion)
                    except ActiveBastionUnavailableError as exc:
                        log.write_line(f"⚠️ Bastion is selected but unavailable: {exc}")
                        return
                    if state is None:
                        log.write_line("ℹ️ No active bastion is connected")
                    else:
                        log.write_line(
                            f"✅ Connected: {state.username}@{state.host}:{state.port} "
                            f"(local SOCKS {state.socks_host}:{state.socks_port})"
                        )
                    return
                if event.button.id == "btn-bastion-disconnect":
                    disconnected = await asyncio.get_event_loop().run_in_executor(
                        None, disconnect_active_bastion
                    )
                    log.write_line("✅ Bastion disconnected" if disconnected else "ℹ️ No active bastion to disconnect")
                    return
                if event.button.id != "btn-bastion-connect":
                    return

                host = self.query_one("#bastion-host", Input).value.strip()
                username = self.query_one("#bastion-user", Input).value.strip()
                key_file = self.query_one("#bastion-key-file", Input).value.strip() or None
                password = self.query_one("#bastion-password", Input).value or None
                key_passphrase = self.query_one("#bastion-key-passphrase", Input).value or None
                try:
                    port = int(self.query_one("#bastion-port", Input).value.strip())
                except ValueError:
                    log.write_line("❌ SSH port must be a whole number")
                    return
                if not host or not username:
                    log.write_line("❌ Bastion host and username are required")
                    return
                state = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: connect_active_bastion(
                        host, username, port, key_file, password, key_passphrase
                    ),
                )
                log.write_line(f"✅ Connected: {state.username}@{state.host}:{state.port}")
            except Exception as exc:
                log.write_line(f"❌ {exc}")

        self.run_worker(_manage(), name="active bastion", group="active-bastion", exit_on_error=False, exclusive=True)


# ---------------------------------------------------------------------------
# Settings and Credential Vault Screens
# ---------------------------------------------------------------------------

class SettingsScreen(ModalScreen):
    """Edit non-secret TUI defaults used by future operations."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        """Compose the user-scoped settings form."""
        settings = netops_app(self).settings
        with Vertical(id="settings-modal"):
            yield Label(terminal_text("⚙️ TUI Settings"), id="settings-title")
            yield Label("Scan defaults")
            with Horizontal(classes="advanced-row"):
                yield Input(value=str(settings["snmp_port"]), id="settings-snmp-port")
                yield Input(value=str(settings["snmp_timeout"]), id="settings-snmp-timeout")
                yield Input(value=str(settings["ping_workers"]), id="settings-ping-workers")
            yield Label("SNMP port · SNMP timeout (seconds) · ping workers")
            with Horizontal(classes="advanced-row"):
                yield Input(value=str(settings["snmp_concurrency"]), id="settings-snmp-concurrency")
                yield Input(value=str(settings["ssh_timeout"]), id="settings-ssh-timeout")
                yield Input(value=str(settings["ssh_concurrency"]), id="settings-ssh-concurrency")
            yield Label("SNMP concurrency · SSH timeout (seconds) · SSH concurrency")
            yield Label("Backup defaults")
            yield Input(value=str(settings["backup_workers"]), id="settings-backup-workers")
            yield Label("Concurrent backup workers")
            with Horizontal(classes="modal-actions"):
                yield Button("Save", variant="primary", id="btn-settings-save")
                yield Button("Cancel", id="btn-settings-cancel")
            yield TerminalLog(id="settings-log", highlight=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Persist valid settings or close without changing them."""
        if event.button.id == "btn-settings-cancel":
            self.dismiss()
            return
        if event.button.id != "btn-settings-save":
            return
        log = self.query_one("#settings-log", Log)
        fields = {
            "snmp_port": "#settings-snmp-port",
            "snmp_timeout": "#settings-snmp-timeout",
            "ping_workers": "#settings-ping-workers",
            "snmp_concurrency": "#settings-snmp-concurrency",
            "ssh_timeout": "#settings-ssh-timeout",
            "ssh_concurrency": "#settings-ssh-concurrency",
            "backup_workers": "#settings-backup-workers",
        }
        try:
            updated = {key: int(self.query_one(field_id, Input).value.strip()) for key, field_id in fields.items()}
        except ValueError:
            log.write_line("❌ All settings must be whole numbers")
            return
        if any(value < 1 for value in updated.values()) or not 1 <= updated["snmp_port"] <= 65535:
            log.write_line("❌ Values must be positive and the SNMP port must be 1–65535")
            return
        app = netops_app(self)
        app.settings = {**app.settings, **updated}
        try:
            save_settings(app.settings)
        except OSError as exc:
            log.write_line(f"❌ Could not save settings: {exc}")
            return
        log.write_line(f"✅ Saved settings to {SETTINGS_FILE}")


class VaultScreen(ModalScreen):
    """Unlock and manage encrypted device, group, and default credentials."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, reason: str | None = None) -> None:
        super().__init__()
        self._reason = reason

    def compose(self) -> ComposeResult:
        """Compose vault controls without exposing stored secrets."""
        from netops.core.vault import CredentialVault

        with Vertical(id="vault-modal"):
            yield Label(terminal_text("🔑 Credential Vault"), id="vault-title")
            yield Label("Saved credentials are encrypted on disk and persist between TUI sessions.")
            yield Label("Create a vault once. Later, enter that same password only to unlock it for this TUI session.")
            yield Label("The unlock password is never stored by netops-toolkit.")
            if self._reason:
                yield Label(self._reason, classes="vault-guidance")
            yield Input(value=str(CredentialVault.DEFAULT_VAULT_PATH), id="vault-path")
            yield Input(placeholder="Vault password to create or unlock saved credentials", password=True, id="vault-master-password")
            with Horizontal(classes="modal-actions"):
                yield Button("Unlock saved vault", variant="primary", id="btn-vault-unlock")
                yield Button("Create new vault", id="btn-vault-create")
            yield Label("Credential scope: default, group, or device")
            with Horizontal(classes="advanced-row"):
                yield Input(value="default", id="vault-scope")
                yield Input(placeholder="Group or device name (not needed for default)", id="vault-target")
            yield Input(placeholder="SSH username", id="vault-user")
            yield Input(placeholder="SSH password", password=True, id="vault-password")
            yield Input(placeholder="Optional enable password", password=True, id="vault-enable-password")
            with Horizontal(classes="modal-actions"):
                yield Button("Save credentials", variant="primary", id="btn-vault-save")
                yield Button("Delete scope", variant="warning", id="btn-vault-delete")
                yield Button("Close", id="btn-vault-close")
            yield TerminalLog(id="vault-log", highlight=True)

    def _scope(self) -> tuple[str, str]:
        """Validate and return the requested credential scope and target."""
        scope = self.query_one("#vault-scope", Input).value.strip().lower()
        target = self.query_one("#vault-target", Input).value.strip()
        if scope not in {"default", "group", "device"}:
            raise ValueError("Scope must be default, group, or device")
        if scope != "default" and not target:
            raise ValueError(f"A {scope} name is required")
        return scope, target

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Unlock, create, save, or delete vault entries with explicit feedback."""
        if event.button.id == "btn-vault-close":
            self.dismiss()
            return
        log = self.query_one("#vault-log", Log)
        log.clear()
        path = self.query_one("#vault-path", Input).value.strip()
        master_password = self.query_one("#vault-master-password", Input).value
        try:
            if event.button.id in {"btn-vault-unlock", "btn-vault-create"}:
                if not master_password:
                    raise ValueError("A vault master password is required")
                netops_app(self).open_vault(path, master_password, create=event.button.id == "btn-vault-create")
                log.write_line("✅ Vault ready. Saved credentials remain encrypted on disk after the TUI closes.")
                return
            scope, target = self._scope()
            if event.button.id == "btn-vault-save":
                username = self.query_one("#vault-user", Input).value.strip()
                password = self.query_one("#vault-password", Input).value
                enable_password = self.query_one("#vault-enable-password", Input).value or None
                if not username or not password:
                    raise ValueError("SSH username and password are required")
                netops_app(self).save_vault_credentials(scope, target, username, password, enable_password)
                log.write_line(f"✅ Saved {scope} credentials in the encrypted vault")
            elif event.button.id == "btn-vault-delete":
                deleted = netops_app(self).delete_vault_credentials(scope, target)
                log.write_line("✅ Credential scope deleted" if deleted else "ℹ️ Credential scope did not exist")
        except Exception as exc:
            log.write_line(f"❌ {exc}")


# ---------------------------------------------------------------------------
# Config Push Screen
# ---------------------------------------------------------------------------

class ConfigPushScreen(ModalScreen):
    """Modal for pushing config commands to devices."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, selected_host: str | None = None):
        super().__init__()
        self._selected_host = selected_host

    def compose(self) -> ComposeResult:
        """Compose the configuration push modal."""
        with Vertical(id="push-modal"):
            yield Label(terminal_text("⚙️ Config Push"), id="push-title")
            yield Input(placeholder="Hostname or IP (comma-separated for bulk)", id="push-hosts",
                        value=self._selected_host or "")
            yield Input(placeholder="SSH user (vault if blank)", id="push-user")
            yield Input(placeholder="SSH password (vault if blank)", password=True, id="push-pass")
            yield Input(placeholder="Vendor (cisco_ios, nokia_sros, etc. — leave blank to auto-detect)", id="push-vendor")
            with Horizontal(classes="advanced-row"):
                yield Input(value="ssh", placeholder="Transport: ssh or telnet", id="push-transport")
                yield Input(placeholder="Optional port override", id="push-port")
                yield Input(value="0", placeholder="Confirm timer minutes", id="push-confirm-timer")
            with Horizontal(classes="advanced-row"):
                yield Input(placeholder="Operator name (defaults to SSH user)", id="push-operator")
                yield Input(value="~/.netops/changelog.jsonl", placeholder="Change log path", id="push-changelog")
            yield Label("[dim]Commands (one per line):[/dim]")
            yield TextArea(id="push-commands")
            with Horizontal(classes="modal-actions"):
                yield Button("Dry Run", variant="primary", id="btn-push-dry")
                yield Button("Commit", variant="warning", id="btn-push-commit")
                yield Button("Cancel", id="btn-push-cancel")
            yield Label("[dim]Presets: press 'c' for SNMP community change template[/dim]")
            yield TerminalLog(id="push-log", highlight=True)

    def on_key(self, event) -> None:
        """Handle configuration editor shortcuts."""
        if event.key == "c":
            ta = self.query_one("#push-commands", TextArea)
            if not ta.text.strip():
                ta.load_text(
                    "! SNMP community string change\n"
                    "! Replace OLD_COMMUNITY and NEW_COMMUNITY\n"
                    "snmp-server community NEW_COMMUNITY RO\n"
                    "no snmp-server community OLD_COMMUNITY\n"
                )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle configuration push modal button presses."""
        if event.button.id == "btn-push-cancel":
            self.dismiss()
            return

        commit = event.button.id == "btn-push-commit"
        hosts_text = self.query_one("#push-hosts", Input).value.strip()
        user = self.query_one("#push-user", Input).value.strip()
        password = self.query_one("#push-pass", Input).value.strip()
        vendor = self.query_one("#push-vendor", Input).value.strip() or None
        transport = self.query_one("#push-transport", Input).value.strip().lower() or "ssh"
        port_text = self.query_one("#push-port", Input).value.strip()
        confirm_text = self.query_one("#push-confirm-timer", Input).value.strip()
        operator = self.query_one("#push-operator", Input).value.strip()
        changelog = self.query_one("#push-changelog", Input).value.strip()
        commands_text = self.query_one("#push-commands", TextArea).text.strip()
        log = self.query_one("#push-log", Log)

        if not all([hosts_text, commands_text]):
            log.write_line("❌ Hosts and commands are required")
            return
        if transport not in {"ssh", "telnet"}:
            log.write_line("❌ Transport must be ssh or telnet")
            return
        try:
            port = int(port_text) if port_text else None
            confirm_timer = int(confirm_text or "0")
        except ValueError:
            log.write_line("❌ Port and confirm timer must be whole numbers")
            return
        if port is not None and not 1 <= port <= 65535:
            log.write_line("❌ Port must be between 1 and 65535")
            return
        if confirm_timer < 0:
            log.write_line("❌ Confirm timer cannot be negative")
            return
        if confirm_timer:
            log.write_line(
                "❌ Confirmation timers require interactive terminal input; use netops push for this operation"
            )
            return

        hosts = [h.strip() for h in hosts_text.replace(',', ' ').split() if h.strip()]
        commands = [
            stripped
            for line in commands_text.splitlines()
            if (stripped := line.strip()) and not stripped.startswith("!")
        ]

        mode = "COMMIT" if commit else "DRY RUN"
        log.write_line(f"{'🔴' if commit else '🔵'} {mode} — {len(commands)} commands on {len(hosts)} host(s)")

        async def _push():
            try:
                from netops.change.push import run_push
                from netops.core.connection import ConnectionParams, Transport

                # Auto-detect vendor from inventory if not specified
                inv = load_inventory()

                for i, host in enumerate(hosts):
                    log.write_line(f"  [{i+1}/{len(hosts)}] {host}...")
                    dev_info = inv.get("devices", {}).get(host, {})
                    dev_vendor = vendor or dev_info.get("vendor", "cisco_ios")
                    vault_credentials = self.app.credentials_for(host, dev_info.get("groups", []))

                    try:
                        params = ConnectionParams(
                            host=dev_info.get("host", host),
                            username=user or dev_info.get("username") or vault_credentials.get("username"),
                            password=password or dev_info.get("password") or vault_credentials.get("password"),
                            device_type=dev_vendor,
                            transport=Transport(transport),
                            port=port,
                            enable_password=dev_info.get("enable_password") or vault_credentials.get("enable_password"),
                        )
                        record = await asyncio.get_event_loop().run_in_executor(
                            None,
                            lambda: run_push(
                                params,
                                commands,
                                commit=commit,
                                operator=operator or user,
                                changelog_path=Path(changelog).expanduser() if changelog else None,
                            ),
                        )
                        if record.error:
                            log.write_line(f"    ❌ {record.error}")
                        elif record.committed:
                            log.write_line("    ✅ Committed and recorded in the change log")
                        else:
                            log.write_line("    ✅ Dry run complete — no changes made")
                        if record.diff:
                            log.write_line("    📋 Post-change diff:")
                            for line in record.diff.splitlines()[:20]:
                                log.write_line(f"      {line}")
                    except Exception as e:
                        log.write_line(f"    ❌ {host}: {e}")

                log.write_line(f"  {'✅ Done' if commit else '✅ Dry run complete'}")

            except ImportError as e:
                log.write_line(f"  ❌ Missing: {e}")
            except Exception as e:
                log.write_line(f"  ❌ {e}")

        self.run_worker(_push(), name="configuration push", group="configuration-push", exit_on_error=False, exclusive=True)


# ---------------------------------------------------------------------------
# Config Backup Screen
# ---------------------------------------------------------------------------

class BackupScreen(ModalScreen):
    """Modal for backing up device configs."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, selected_host: str | None = None):
        super().__init__()
        self._selected_host = selected_host

    def compose(self) -> ComposeResult:
        """Compose the configuration backup modal."""
        with Vertical(id="backup-modal"):
            yield Label(terminal_text("💾 Config Backup"), id="backup-title")
            yield Input(placeholder="Hostnames (comma-separated, or 'all' for inventory)", id="backup-hosts",
                        value=self._selected_host or "")
            yield Input(placeholder="SSH user (vault if blank)", id="backup-user")
            yield Input(placeholder="SSH password (vault if blank)", password=True, id="backup-pass")
            yield Input(placeholder="Output directory (default: ./backups)", id="backup-dir")
            yield Input(
                value=str(INVENTORY_FILE),
                placeholder="Inventory file (YAML or JSON)",
                id="backup-inventory",
            )
            with Horizontal(classes="advanced-row"):
                yield Input(placeholder="Optional inventory group", id="backup-group")
                yield Input(value=str(netops_app(self).settings["backup_workers"]), placeholder="Concurrent workers", id="backup-workers")
                yield Checkbox("Commit changes to a local git repository", id="backup-git")
                yield Checkbox("Suppress change alerts", id="backup-no-alert")
            with Horizontal(classes="modal-actions"):
                yield Button("Backup", variant="primary", id="btn-backup-run")
                yield Button("Cancel", id="btn-backup-cancel")
            yield TerminalLog(id="backup-log", highlight=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle backup modal button presses."""
        if event.button.id == "btn-backup-cancel":
            self.dismiss()
            return

        hosts_text = self.query_one("#backup-hosts", Input).value.strip()
        user = self.query_one("#backup-user", Input).value.strip()
        password = self.query_one("#backup-pass", Input).value.strip()
        backup_dir = self.query_one("#backup-dir", Input).value.strip() or "./backups"
        inventory_path = self.query_one("#backup-inventory", Input).value.strip()
        group = self.query_one("#backup-group", Input).value.strip()
        git_enabled = self.query_one("#backup-git", Checkbox).value
        no_alert = self.query_one("#backup-no-alert", Checkbox).value
        log = self.query_one("#backup-log", Log)

        if not inventory_path:
            log.write_line("❌ An inventory file is required")
            return
        try:
            workers = int(self.query_one("#backup-workers", Input).value.strip())
            if workers < 1:
                raise ValueError
        except ValueError:
            log.write_line("❌ Concurrent workers must be at least 1")
            return

        log.write_line(f"💾 Backing up inventory from {inventory_path} to {backup_dir}/")

        async def _backup():
            try:
                from netops.collect.backup import run_backup
                from netops.core.connection import (
                    ConnectionParams,
                    Transport,
                    jump_host_from_inventory,
                )
                from netops.core.inventory import Inventory

                inv = Inventory.from_file(inventory_path)
                devices = inv.filter(group=group or None) if group else list(inv.devices.values())
                requested_hosts = {
                    host.strip() for host in hosts_text.replace(',', ' ').split()
                    if host.strip() and host.strip().lower() != "all"
                }
                if requested_hosts:
                    devices = [
                        device for device in devices
                        if device.hostname in requested_hosts or device.host in requested_hosts
                    ]
                if not devices:
                    raise ValueError("no devices matched the inventory, group, or host selection")
                params_list = []
                for device in devices:
                    vault_credentials = self.app.credentials_for(device.hostname, device.groups)
                    params_list.append(
                        ConnectionParams(
                            host=device.host,
                            username=user or device.username or vault_credentials.get("username"),
                            password=password or device.password or vault_credentials.get("password"),
                            device_type=device.vendor,
                            jump_host=jump_host_from_inventory(device),
                            transport=Transport(device.transport) if device.transport else Transport.SSH,
                            port=device.port,
                            enable_password=device.enable_password or vault_credentials.get("enable_password"),
                        )
                    )
                log.write_line(f"  Collecting {len(params_list)} device(s) with {workers} worker(s)...")
                summaries = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: run_backup(
                        params_list,
                        Path(backup_dir),
                        workers=workers,
                        git=git_enabled,
                        alert_on_change=not no_alert,
                    ),
                )
                for summary in sorted(summaries, key=lambda item: str(item.get("host", ""))):
                    if summary.get("success"):
                        status = "changed" if summary.get("changed") else "unchanged"
                        log.write_line(
                            f"    ✅ {summary.get('host')}: {status} "
                            f"({summary.get('saved_path', '')})"
                        )
                    else:
                        log.write_line(f"    ❌ {summary.get('host')}: {summary.get('error', 'backup failed')}")
                successful = sum(1 for summary in summaries if summary.get("success"))
                icon = "✅" if successful == len(summaries) else "⚠️"
                log.write_line(f"  {icon} {successful}/{len(summaries)} backups saved to {backup_dir}/")

            except Exception as e:
                log.write_line(f"  ❌ {e}")

        self.run_worker(_backup(), name="configuration backup", group="configuration-backup", exit_on_error=False, exclusive=True)


# ---------------------------------------------------------------------------
# Running Config View
# ---------------------------------------------------------------------------

class ConfigViewScreen(ModalScreen):
    """Scrollable on-demand running-config view with a clipboard action."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("y", "copy_config", "Copy config"),
    ]

    def __init__(self, hostname: str, config: str) -> None:
        super().__init__()
        self._hostname = hostname
        self._config = config

    def compose(self) -> ComposeResult:
        """Compose the fetched running-config reader."""
        with Vertical(id="config-view-modal"):
            yield Label(f"Running config — {self._hostname}", id="config-view-title", markup=False)
            yield Static(self._config, id="config-view-content", markup=False)
            yield Label("Press y to copy all text, or Escape to close.")

    def action_copy_config(self) -> None:
        """Request a terminal clipboard copy and confirm it to the user."""
        self.app.copy_to_clipboard(self._config)
        self.notify("Copied running config to the terminal clipboard")


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------

class NetopsTUI(App):
    """netops-toolkit Terminal UI."""

    TITLE = "netops-toolkit"
    SUB_TITLE = "Network Operations"
    CSS = """
    Screen {
        background: $surface;
    }
    #workspace {
        height: 1fr;
    }
    #main-panel {
        height: 1fr;
    }
    #device-table {
        height: 1fr;
    }
    #detail-panel {
        height: auto;
        max-height: 14;
        border-top: solid $primary;
        padding: 1;
    }
    #scan-modal, #health-modal, #push-modal, #backup-modal, #diff-modal, #bastion-modal, #settings-modal, #vault-modal, #config-view-modal {
        width: 70;
        height: 90%;
        overflow-y: auto;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    #scan-title, #health-title, #push-title, #backup-title, #diff-title, #bastion-title, #settings-title, #vault-title, #config-view-title {
        text-style: bold;
        color: $text;
        margin-bottom: 1;
    }
    #scan-log, #health-log, #push-log, #backup-log, #diff-log, #bastion-log, #settings-log, #vault-log {
        height: 10;
        margin-top: 1;
        border: solid $accent;
    }
    .status-bar {
        dock: bottom;
        height: 1;
        background: $primary;
        color: $text;
        padding: 0 1;
    }
    .advanced-row Input {
        width: 1fr;
    }
    .advanced-field {
        width: 1fr;
        height: auto;
    }
    .advanced-options {
        width: 2fr;
        height: auto;
    }
    .form-section-title {
        margin-top: 1;
        text-style: bold;
        color: $text;
    }
    .field-label {
        color: $text;
        text-style: bold;
    }
    .advanced-row Checkbox {
        width: auto;
        margin: 0 1;
    }
    .modal-actions {
        height: 3;
        min-height: 3;
        margin-top: 1;
    }
    .modal-actions Button {
        width: 1fr;
        min-width: 12;
        height: 3;
        color: $text;
        text-style: bold;
    }
    Button {
        color: $text;
        text-style: bold;
    }
    .vault-guidance {
        color: $warning;
        text-style: bold;
    }
    #btn-scan {
        background: $primary;
        color: $text;
    }
    #btn-ping {
        background: $surface;
        color: $text;
        border: solid $primary;
    }
    #btn-cancel-scan {
        background: $error;
        color: $text;
    }
    #config-view-content {
        height: 1fr;
        overflow-y: auto;
        border: solid $accent;
        padding: 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "scan", "Scan"),
        Binding("h", "health", "Health"),
        Binding("p", "push", "Config Push"),
        Binding("b", "backup", "Backup"),
        Binding("enter", "toggle_detail", "More detail"),
        Binding("c", "running_config", "Running config"),
        Binding("v", "vault", "Credentials"),
        Binding("o", "settings", "Settings"),
        Binding("f", "diff", "Config Diff"),
        Binding("j", "bastion", "Bastion"),
        Binding("e", "export", "Export CSV"),
        Binding("r", "refresh", "Refresh"),
        Binding("/", "search", "Search"),
        Binding("d", "delete", "Delete"),
        Binding("l", "view_logs", "View Logs"),
        Binding("?", "help_screen", "Help"),
        Binding("escape", "close_detail", "Close panel"),
    ]

    def __init__(self):
        super().__init__()
        self._log_file = setup_logging()
        self.inventory = load_inventory()
        self.settings = load_settings()
        self.terminal_profile: TerminalProfile = terminal_profile()
        self._selected_host: str | None = None
        self._selected_hosts: set[str] = set()
        self._detail_extended = False
        self._vault = None
        self._vault_password: str | None = None

    def notify(self, message: str, *args, **kwargs):
        """Notify with text compatible with the active terminal."""
        return super().notify(terminal_text(message), *args, **kwargs)

    def _handle_exception(self, error: Exception) -> None:
        """Contain Textual event failures instead of returning users to their shell.

        Textual's default implementation renders a fatal error then exits. The
        TUI performs remote operations and must keep the rest of the workspace
        available when one event, callback, or terminal interaction fails.
        """
        logging.getLogger("netops.tui").error(
            "Contained TUI exception; the application remains available",
            exc_info=(type(error), error, error.__traceback__),
        )
        try:
            self.notify(
                "Unexpected error contained; the TUI is still running. See the netops log for details.",
                severity="error",
                timeout=12,
            )
        except Exception:
            # A failure while the screen is mounting must not recurse into the
            # same handler or force a terminal exit.
            pass

    def compose(self) -> ComposeResult:
        """Compose the main TUI layout."""
        yield Header()
        with Vertical(id="workspace"):
            with Vertical(id="main-panel"):
                yield Input(placeholder=terminal_text("🔍 Search devices..."), id="search-input")
                yield DeviceTable(id="device-table", cursor_type="row")
            with Vertical(id="detail-panel"):
                yield Static("Select a device to view details", id="detail-content")
        yield Static(
            "",
            classes="status-bar",
        )
        yield Footer()

    def on_error(self, event) -> None:
        """Global error handler — display errors, never crash."""
        logger = logging.getLogger("netops.tui")
        logger.error(f"Unhandled error: {event}", exc_info=True)
        # Try to show in status bar if possible
        try:
            from textual.widgets import Static
            status = self.query_one(".status-bar", Static)
            status.update(terminal_text(f"  ⚠️ Error (see logs): {str(event)[:60]}"))
        except Exception:
            pass

    def on_exception(self, error: Exception) -> None:
        """Catch exceptions from workers/tasks — log, don't crash."""
        logger = logging.getLogger("netops.tui")
        logger.error(f"Background task error: {error}", exc_info=True)

    def on_mount(self) -> None:
        """Initialize the device table after mounting."""
        table = self.query_one("#device-table", DataTable)
        table.add_columns("", "Hostname", "Host", "Vendor", "Model", "Version", "Serial", "Site")
        self._populate_table()
        self._update_status()
        table.focus()

    def _populate_table(self, filter_text: str = "") -> None:
        table = self.query_one("#device-table", DataTable)
        table.clear()
        devices = self.inventory.get("devices", {})
        q = filter_text.lower()
        for hostname, info in sorted(devices.items()):
            if not isinstance(info, dict):
                continue
            row_text = f"{hostname} {info.get('host','')} {info.get('vendor','')} {info.get('model','')} {info.get('site','')}".lower()
            if q and q not in row_text:
                continue
            table.add_row(
                self.terminal_profile.selected_marker
                if hostname in self._selected_hosts
                else self.terminal_profile.unselected_marker,
                hostname,
                info.get("host", ""),
                info.get("vendor", ""),
                info.get("model", ""),
                info.get("version", ""),
                info.get("serial", ""),
                info.get("site", ""),
                key=hostname,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Track the device selected in the inventory table."""
        try:
            if event.row_key is None or event.row_key.value is None:
                return
            hostname = str(event.row_key.value)
            self._selected_host = hostname
            self._detail_extended = False
            self._render_detail()
        except Exception as e:
            logging.getLogger("netops.tui").error(f"Row selection error: {e}")

    def _render_detail(self) -> None:
        """Render basic or extended metadata for the selected device."""
        if not self._selected_host:
            return
        info = self.inventory.get("devices", {}).get(self._selected_host, {})
        if not isinstance(info, dict):
            return
        basic_fields = ("host", "vendor", "model", "serial", "version", "uptime", "community", "mac_address")
        extended_fields = (
            "memory", "flash", "interfaces", "reload_reason", "domain", "neighbors",
            "image", "site", "role", "groups", "tags",
        )
        fields = basic_fields + (extended_fields if self._detail_extended else ())
        mode = "Extended detail" if self._detail_extended else "Device detail"
        from rich.markup import escape

        lines = [f"[bold]{mode} — {escape(self._selected_host)}[/bold]"]
        for field in fields:
            value = info.get(field)
            if value in (None, "", [], {}):
                continue
            if isinstance(value, dict):
                lines.append(f"[dim]{field}:[/dim]")
                lines.extend(f"  {escape(str(key))}: {escape(str(item))}" for key, item in sorted(value.items()))
            elif isinstance(value, list):
                rendered = ", ".join(escape(str(item)) for item in value)
                lines.append(f"[dim]{field}:[/dim] {rendered}")
            else:
                lines.append(f"[dim]{field}:[/dim] {escape(str(value))}")
        if len(lines) == 1:
            lines.append("No inventory details are available yet. Run a deep scan to collect them.")
        hint = "Enter: basic detail" if self._detail_extended else "Enter: more detail"
        lines.extend(("", terminal_text(f"[dim]{hint} · c: running config · Space/x: select · Esc: close[/dim]")))
        self.query_one("#detail-panel", Vertical).display = True
        self.query_one("#detail-content", Static).update(terminal_text("\n".join(lines)))

    def _update_status(self) -> None:
        """Show inventory and multi-selection state in the persistent status bar."""
        count = len(self.inventory.get("devices", {}))
        selected = len(self._selected_hosts)
        self.query_one(".status-bar", Static).update(
            terminal_text(f"  {count} devices  |  {selected} selected  |  {INVENTORY_FILE}")
        )

    def _focused_hostname(self) -> str | None:
        """Return the current table host key without trusting a mouse event."""
        table = self.query_one("#device-table", DataTable)
        try:
            if table.cursor_row is None:
                return self._selected_host
            row = table.get_row_at(table.cursor_row)
            hostname = str(row[1]) if len(row) > 1 else ""
            return hostname if hostname in self.inventory.get("devices", {}) else self._selected_host
        except Exception:
            return self._selected_host

    def on_input_changed(self, event: Input.Changed) -> None:
        """Filter the device table when the search input changes."""
        if event.input.id == "search-input":
            self._populate_table(event.value)

    def _input_focused(self) -> bool:
        """Return True if an Input or TextArea widget currently has focus."""
        from textual.widgets import Input, TextArea
        focused = self.focused
        return isinstance(focused, (Input, TextArea))

    def action_scan(self) -> None:
        """Open the inventory scan modal."""
        if self._input_focused():
            return
        self.push_screen(ScanScreen())

    def action_health(self) -> None:
        """Open the health check modal."""
        if self._input_focused():
            return
        self.push_screen(HealthScreen(self._focused_hostname()))

    def action_push(self) -> None:
        """Open the configuration push modal."""
        if self._input_focused():
            return
        self.push_screen(ConfigPushScreen(", ".join(self.operation_hosts())))

    def action_backup(self) -> None:
        """Open the configuration backup modal."""
        if self._input_focused():
            return
        self.push_screen(BackupScreen(", ".join(self.operation_hosts())))

    def operation_hosts(self) -> list[str]:
        """Return selected devices, or the focused device when none are selected."""
        if self._selected_hosts:
            return sorted(self._selected_hosts)
        focused = self._focused_hostname()
        return [focused] if focused else []

    def toggle_focused_selection(self) -> None:
        """Toggle the selected flag for the focused device row."""
        if self._input_focused():
            return
        hostname = self._focused_hostname()
        if not hostname:
            self.notify("Select a device first", severity="warning")
            return
        if hostname in self._selected_hosts:
            self._selected_hosts.remove(hostname)
        else:
            self._selected_hosts.add(hostname)
        self.call_after_refresh(self._refresh_selection_view)

    def toggle_all_selection(self) -> None:
        """Select every inventory device, or clear the current selection."""
        if self._input_focused():
            return
        devices = {
            hostname for hostname, info in self.inventory.get("devices", {}).items()
            if isinstance(info, dict)
        }
        self._selected_hosts = set() if devices and self._selected_hosts == devices else devices
        self.call_after_refresh(self._refresh_selection_view)

    def _refresh_selection_view(self) -> None:
        """Refresh selection indicators after the current key event completes."""
        self._populate_table(self.query_one("#search-input", Input).value)
        self._update_status()

    def action_toggle_selection(self) -> None:
        """Keep the action available to extensions while the table owns keys."""
        self.toggle_focused_selection()

    def action_toggle_all_selection(self) -> None:
        """Keep the action available to extensions while the table owns keys."""
        self.toggle_all_selection()

    def action_toggle_detail(self) -> None:
        """Cycle the selected device detail pane between basic and extended metadata."""
        if self._input_focused():
            return
        hostname = self._focused_hostname()
        if not hostname:
            return
        self._selected_host = hostname
        self._detail_extended = not self._detail_extended
        self._render_detail()

    def action_running_config(self) -> None:
        """Fetch a selected device running config without persisting it to inventory."""
        if self._input_focused():
            return
        hostname = self._focused_hostname()
        if not hostname:
            self.notify("Select a device first", severity="warning")
            return
        info = self.inventory.get("devices", {}).get(hostname, {})
        if not isinstance(info, dict):
            self.notify("Selected inventory data is invalid", severity="error")
            return
        credentials = self.credentials_for(hostname, info.get("groups", []))
        if not credentials.get("username") or not credentials.get("password"):
            self.push_screen(
                VaultScreen(
                    "Running configuration needs SSH credentials. Create a vault on first use, or unlock your existing vault and save default, group, or device credentials."
                )
            )
            return

        async def fetch_config() -> None:
            try:
                from netops.core.connection import ConnectionParams, Transport

                params = ConnectionParams(
                    host=info.get("host", hostname),
                    username=credentials["username"],
                    password=credentials["password"],
                    device_type=info.get("vendor", "cisco_ios"),
                    transport=Transport(info.get("transport", "ssh")),
                    port=info.get("port"),
                    enable_password=credentials.get("enable_password"),
                )
                self.query_one("#detail-content", Static).update("[dim]Fetching running config…[/dim]")
                config = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self._fetch_running_config(params),
                )
                self.push_screen(ConfigViewScreen(hostname, config))
            except Exception as exc:
                self.notify(f"Could not fetch running config: {exc}", severity="error")
                self._render_detail()

        self.run_worker(fetch_config(), name="running configuration", group="running-configuration", exit_on_error=False, exclusive=True)

    @staticmethod
    def _fetch_running_config(params) -> str:
        """Open a bounded device session and obtain the vendor-aware configuration snapshot."""
        from netops.change.push import _snapshot_config
        from netops.core.connection import DeviceConnection

        with DeviceConnection(params) as connection:
            return _snapshot_config(connection, params.device_type)

    def action_vault(self) -> None:
        """Open the encrypted credential vault controls."""
        if not self._input_focused():
            self.push_screen(VaultScreen())

    def action_settings(self) -> None:
        """Open non-secret user settings."""
        if not self._input_focused():
            self.push_screen(SettingsScreen())

    def open_vault(self, path: str, password: str, *, create: bool) -> None:
        """Unlock or explicitly create the encrypted vault for this session only."""
        from netops.core.vault import CredentialVault

        vault = CredentialVault(Path(path).expanduser())
        if create:
            vault.init(password)
        else:
            vault.unlock(password)
        self._vault = vault
        self._vault_password = password

    def credentials_for(self, hostname: str | None = None, groups: object = None) -> dict:
        """Resolve session vault credentials device → group → global without persisting secrets."""
        if self._vault is None:
            return {}
        safe_groups = [str(group) for group in groups] if isinstance(groups, list) else []
        try:
            return self._vault.get_credentials(hostname or "", safe_groups) or {}
        except (RuntimeError, ValueError):
            return {}

    def _require_vault(self):
        """Return the session vault and master password, or explain how to unlock it."""
        if self._vault is None or self._vault_password is None:
            raise RuntimeError("Unlock or create a vault first")
        return self._vault, self._vault_password

    def save_vault_credentials(
        self,
        scope: str,
        target: str,
        username: str,
        password: str,
        enable_password: str | None,
    ) -> None:
        """Persist an encrypted credential entry at the requested scope."""
        vault, master_password = self._require_vault()
        if scope == "default":
            vault.set_default(username, password, enable_password)
        elif scope == "group":
            vault.set_group(target, username, password, enable_password)
        else:
            vault.set_device(target, username, password, enable_password)
        vault.save(master_password)

    def delete_vault_credentials(self, scope: str, target: str) -> bool:
        """Delete a single encrypted credential scope after an explicit user request."""
        vault, master_password = self._require_vault()
        if scope == "default":
            deleted = vault.delete_default()
        elif scope == "group":
            deleted = vault.delete_group(target)
        else:
            deleted = vault.delete_device(target)
        vault.save(master_password)
        return deleted

    def action_diff(self) -> None:
        """Open the semantic configuration diff modal."""
        if self._input_focused():
            return
        self.push_screen(DiffScreen())

    def action_bastion(self) -> None:
        """Open the workstation-wide active bastion modal."""
        if self._input_focused():
            return
        self.push_screen(BastionScreen())

    def action_help_screen(self) -> None:
        """Show the keyboard shortcut help."""
        help_text = """[bold]netops-toolkit TUI — Help[/bold]

[bold]Keys:[/bold]
  s  — Scan subnets (ping + SNMP + SSH deep scan)
  h  — Health check a device
  p  — Push config to devices (bulk SNMP community change, etc.)
  b  — Backup device configs
  Space / Ctrl+A — Select one / all devices for bulk operations
  Enter — Toggle basic and extended device detail
  c  — Fetch the selected device running config
  v  — Unlock and manage credential vault entries
  o  — Set non-secret scan and backup defaults
  f  — Compare configuration files
  j  — Connect, inspect, or disconnect the active bastion
  e  — Export inventory to CSV
  /  — Search/filter devices
  d  — Delete selected device
  r  — Refresh table from file
  ?  — This help
  q  — Quit

[bold]Scan:[/bold]
  Enter multiple subnets separated by commas
  Or point to a hosts file (.csv or .txt)
  Deep scan adds SSH login for model/serial/version
  Tune SNMP/SSH timeouts and concurrency, or export the discovered fragment
  Blank SSH fields resolve the session vault's global credentials

[bold]Config Push:[/bold]
  Enter commands one per line
  Press 'c' in the commands box for SNMP community change template
  Dry Run = preview only, Commit = apply changes
  Supports bulk push to multiple devices

[bold]Config Backup:[/bold]
  Selected devices are used when any are selected; otherwise the focused device
  Use v to save credentials once, then reuse device/group/default vault entries

[bold]Configuration Diff:[/bold]
  Compare before/after config files as semantic, unified, or JSON output
  Select cisco, junos, or flat syntax, or leave style blank to auto-detect

[bold]Active Bastion:[/bold]
  SSH device connections route through it; Telnet is rejected while a bastion is active
  Passwords and key passphrases are passed only to the local service, not saved

[bold]Data:[/bold]
  Inventory saved to: inventory.json
  CSV export: inventory.csv
  Backups: ./backups/

[bold]Clipboard:[/bold]
  Inputs and command editors use Textual's native copy/paste support.
  Bracketed paste must be supported by the terminal or remote client.

Press Escape to close this help.
"""
        self.notify(help_text, timeout=30)

    def action_export(self) -> None:
        """Export the inventory to CSV."""
        if self._input_focused():
            return
        count = export_csv(self.inventory)
        self.notify(f"Exported {count} devices to inventory.csv")

    def action_refresh(self) -> None:
        """Refresh the device table."""
        if self._input_focused():
            return
        self.inventory = load_inventory()
        self._selected_hosts.intersection_update(self.inventory.get("devices", {}).keys())
        self._populate_table()
        count = len(self.inventory.get("devices", {}))
        self._update_status()
        self.notify(f"Refreshed: {count} devices")

    def action_search(self) -> None:
        """Focus the inventory search input."""
        if self._input_focused():
            return
        search = self.query_one("#search-input", Input)
        if search.has_focus:
            search.value = ""
            self._populate_table()
            self.query_one("#device-table", DataTable).focus()
        else:
            search.focus()

    def action_close_detail(self) -> None:
        """Close detail panel and return focus to the device table."""
        self.query_one("#detail-panel", Vertical).display = False
        self.query_one("#device-table", DataTable).focus()

    def action_view_logs(self) -> None:
        """Show the log file location and recent entries."""
        if self._input_focused():
            return
        from netops.logging_setup import _get_current_log_path
        log_path = _get_current_log_path()
        if log_path.exists():
            # Show last 20 lines
            lines = log_path.read_text().splitlines()[-20:]
            content = f"📋 Log file: {log_path}\n\n" + "\n".join(lines)
        else:
            content = f"📋 Log file: {log_path}\n\n(No logs yet)"
        self.notify(content, timeout=30)

    def action_delete(self) -> None:
        """Delete the currently selected device."""
        if self._input_focused():
            return
        hostname = self._focused_hostname()
        if hostname and hostname in self.inventory.get("devices", {}):
            del self.inventory["devices"][hostname]
            self._selected_hosts.discard(hostname)
            save_inventory(self.inventory)
            self._selected_host = None
            self.query_one("#detail-content", Static).update("Select a device to view details")
            self._populate_table()
            self._update_status()
            self.notify(f"Deleted {hostname}")


def main():
    """Run the interactive netops TUI."""
    app = NetopsTUI()
    app.run()


if __name__ == "__main__":
    main()
