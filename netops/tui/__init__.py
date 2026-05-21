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

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
import sys
from pathlib import Path

from netops.logging_setup import friendly_vendor_name, setup_logging

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Log,
    OptionList,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)


# ---------------------------------------------------------------------------
# Inventory data store (JSON file)
# ---------------------------------------------------------------------------

INVENTORY_FILE = Path(os.environ.get("NETOPS_INVENTORY", "inventory.json"))


def load_inventory() -> dict:
    if INVENTORY_FILE.exists():
        return json.loads(INVENTORY_FILE.read_text())
    return {"devices": {}}


def save_inventory(data: dict) -> None:
    INVENTORY_FILE.write_text(json.dumps(data, indent=2))


def export_csv(data: dict, path: str = "inventory.csv") -> int:
    devices = data.get("devices", {})
    if not devices:
        return 0
    all_keys = set()
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


# ---------------------------------------------------------------------------
# Scan Screen
# ---------------------------------------------------------------------------

class ScanScreen(ModalScreen):
    """Modal for running an inventory scan."""

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def on_paste(self, event: "Paste") -> None:
        """Route paste events to the focused input widget in this modal."""
        from textual.widgets import Input, TextArea
        focused = self.app.focused
        if isinstance(focused, Input):
            focused.insert_text_at_cursor(event.text)
            event.prevent_default()
            event.stop()
        elif isinstance(focused, TextArea):
            focused.insert(event.text)
            event.prevent_default()
            event.stop()

    def compose(self) -> ComposeResult:
        with Vertical(id="scan-modal"):
            yield Label("🔍 Inventory Scan", id="scan-title")
            yield Input(placeholder="Subnets (e.g. 10.0.0.0/24, 192.168.1.0/24)", id="scan-subnet")
            yield Input(placeholder="Or path to hosts file (hosts.csv or ips.txt)", id="scan-hosts-file")
            yield Input(placeholder="SNMP communities (comma-sep, or leave blank for registry)", id="scan-community")
            yield Input(placeholder="SSH user (collects full device info)", id="scan-user")
            yield Input(placeholder="SSH password", password=True, id="scan-password")
            with Horizontal():
                yield Button("Scan", variant="primary", id="btn-scan")
                yield Button("Ping Only", variant="default", id="btn-ping")
                yield Button("Cancel", variant="error", id="btn-cancel-scan")
            yield Label("[dim]Tip: separate multiple subnets with commas[/dim]")
            yield Log(id="scan-log", highlight=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel-scan":
            self.dismiss()
        elif event.button.id in ("btn-scan", "btn-ping"):
            skip_snmp = event.button.id == "btn-ping"
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
            log = self.query_one("#scan-log", Log)
            # Parse multiple subnets (comma or space separated)
            subnets = [s.strip() for s in subnet_text.replace(',', ' ').split() if s.strip()] if subnet_text else []
            log.write_line(f"🔍 Scanning {len(subnets)} subnet(s)..." if subnets else f"🔍 Scanning from {hosts_file}...")
            self.run_scan(subnets, hosts_file, community, user, password, skip_snmp, log)

    def run_scan(self, subnets, hosts_file, community, user, password, skip_snmp, log):
        """Run scan in background."""
        async def _scan():
            try:
                from netops.inventory.scan import scan_subnet_async, results_to_inventory_fragment, deep_enrich

                all_results = []

                # Scan from hosts file if provided
                if hosts_file:
                    from netops.inventory.scan import ScanResult
                    from pathlib import Path
                    import csv as _csv
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
                        hosts = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith('#')]
                    log.write_line(f"  📋 Loaded {len(hosts)} hosts from {hosts_file}")
                    all_results.extend([ScanResult(host=h, reachable=True) for h in hosts])

                # Scan each subnet
                for i, subnet in enumerate(subnets):
                    log.write_line(f"  [{i+1}/{len(subnets)}] Scanning {subnet}...")
                    results = await scan_subnet_async(
                        subnet=subnet,
                        community=community,
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
                        ),
                    )
                    # Learn community strings from identified devices
                    try:
                        from netops.core.community import CommunityRegistry, extract_communities_via_ssh
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
                log.write_line("  Close this dialog and press 'r' to refresh the table")

            except ImportError as e:
                log.write_line(f"  ❌ Missing dependency: {e}")
            except Exception as e:
                log.write_line(f"  ❌ Error: {e}")

        asyncio.get_event_loop().create_task(_scan())


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
        with Vertical(id="health-modal"):
            yield Label("🏥 Health Check", id="health-title")
            yield Input(placeholder="Hostname or IP", id="health-host",
                        value=self._selected_host or "")
            yield Input(placeholder="SSH user", id="health-user")
            yield Input(placeholder="SSH password", password=True, id="health-pass")
            with Horizontal():
                yield Button("Check", variant="primary", id="btn-health-run")
                yield Button("Close", id="btn-health-close")
            yield Log(id="health-log", highlight=True)

    def on_error(self, event) -> None:
        """Global error handler — display errors, never crash."""
        import traceback
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
        import traceback
        logger = logging.getLogger("netops.tui")
        logger.error(f"Background task error: {error}", exc_info=True)

    def on_mount(self) -> None:
        """Pre-populate vendor field if host is in inventory."""
        pass



    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-health-close":
            self.dismiss()
        elif event.button.id == "btn-health-run":
            host = self.query_one("#health-host", Input).value.strip()
            user = self.query_one("#health-user", Input).value.strip()
            password = self.query_one("#health-pass", Input).value.strip()
            log = self.query_one("#health-log", Log)
            if not all([host, user, password]):
                log.write_line("❌ Host, user, and password required")
                return

            # Auto-resolve vendor from inventory or auto-detect
            inv = load_inventory()
            device_info = inv.get("devices", {}).get(host, {})
            if device_info.get("vendor") and device_info["vendor"] != "unknown":
                vendor = device_info["vendor"]
            else:
                vendor = "autodetect"

            log.write_line(f"🔍 Checking {host} (device family: {friendly_vendor_name(vendor)})...")

            async def _check():
                try:
                    from netops.check.health import run_health_check
                    from netops.core.connection import ConnectionParams

                    params = ConnectionParams(
                        host=host,
                        username=user,
                        password=password,
                        device_type=vendor,
                    )
                    result = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: run_health_check(params)
                    )

                    if not result.get("success"):
                        log.write_line(f"  ❌ Connection failed: {result.get('error', 'unknown')}")
                        return

                    for check_name, check_data in result.get("checks", {}).items():
                        alert = check_data.get("alert", False)
                        icon = "⚠️" if alert else "✅"
                        # Build summary from check data
                        if "utilization" in check_data and check_data["utilization"] is not None:
                            summary = f"{check_data['utilization']:.1f}% (threshold {check_data.get('threshold', '?')}%)"
                        elif "with_errors" in check_data:
                            summary = f"{check_data['with_errors']}/{check_data.get('total', 0)} interfaces with errors"
                        elif "critical_count" in check_data:
                            summary = f"{check_data['critical_count']} critical, {check_data.get('major_count', 0)} major"
                        else:
                            summary = "OK" if not alert else "ALERT"
                        log.write_line(f"  {icon} {check_name}: {summary}")

                    overall = "🚨 ALERTS DETECTED" if result.get("overall_alert") else "✅ All checks passed"
                    log.write_line(f"  {overall}")

                except ImportError as e:
                    log.write_line(f"  ❌ Missing: {e}")
                except Exception as e:
                    log.write_line(f"  ❌ {e}")

            asyncio.get_event_loop().create_task(_check())


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
        with Vertical(id="push-modal"):
            yield Label("⚙️ Config Push", id="push-title")
            yield Input(placeholder="Hostname or IP (comma-separated for bulk)", id="push-hosts",
                        value=self._selected_host or "")
            yield Input(placeholder="SSH user", id="push-user")
            yield Input(placeholder="SSH password", password=True, id="push-pass")
            yield Input(placeholder="Vendor (cisco_ios, nokia_sros, etc. — leave blank to auto-detect)", id="push-vendor")
            yield Label("[dim]Commands (one per line):[/dim]")
            yield TextArea(id="push-commands")
            with Horizontal():
                yield Button("Dry Run", variant="primary", id="btn-push-dry")
                yield Button("Commit", variant="warning", id="btn-push-commit")
                yield Button("Cancel", id="btn-push-cancel")
            yield Label("[dim]Presets: press 'c' for SNMP community change template[/dim]")
            yield Log(id="push-log", highlight=True)

    def on_key(self, event) -> None:
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
        if event.button.id == "btn-push-cancel":
            self.dismiss()
            return

        commit = event.button.id == "btn-push-commit"
        hosts_text = self.query_one("#push-hosts", Input).value.strip()
        user = self.query_one("#push-user", Input).value.strip()
        password = self.query_one("#push-pass", Input).value.strip()
        vendor = self.query_one("#push-vendor", Input).value.strip() or None
        commands_text = self.query_one("#push-commands", TextArea).text.strip()
        log = self.query_one("#push-log", Log)

        if not all([hosts_text, user, password, commands_text]):
            log.write_line("❌ All fields required")
            return

        hosts = [h.strip() for h in hosts_text.replace(',', ' ').split() if h.strip()]
        commands = [l.strip() for l in commands_text.splitlines() if l.strip() and not l.startswith('!')]

        mode = "COMMIT" if commit else "DRY RUN"
        log.write_line(f"{'🔴' if commit else '🔵'} {mode} — {len(commands)} commands on {len(hosts)} host(s)")

        async def _push():
            try:
                from netops.change.push import push_config, ChangeRecord
                from netops.core.connection import DeviceConnection, ConnectionParams

                # Auto-detect vendor from inventory if not specified
                inv = load_inventory()

                for i, host in enumerate(hosts):
                    log.write_line(f"  [{i+1}/{len(hosts)}] {host}...")
                    dev_info = inv.get("devices", {}).get(host, {})
                    dev_vendor = vendor or dev_info.get("vendor", "cisco_ios")

                    try:
                        conn = DeviceConnection(
                            host=host,
                            username=user,
                            password=password,
                            device_type=dev_vendor,
                        )
                        conn.connect()

                        if commit:
                            output = conn.send_config_set(commands)
                            log.write_line(f"    ✅ Committed")
                            for line in output.splitlines()[-3:]:
                                log.write_line(f"    {line}")
                        else:
                            log.write_line(f"    📋 Would send: {commands[0]}{'...' if len(commands) > 1 else ''}")
                            log.write_line(f"    ℹ️ Dry run — no changes made")

                        conn.disconnect()
                    except Exception as e:
                        log.write_line(f"    ❌ {host}: {e}")

                log.write_line(f"  {'✅ Done' if commit else '✅ Dry run complete'}")

            except ImportError as e:
                log.write_line(f"  ❌ Missing: {e}")
            except Exception as e:
                log.write_line(f"  ❌ {e}")

        asyncio.get_event_loop().create_task(_push())


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
        with Vertical(id="backup-modal"):
            yield Label("💾 Config Backup", id="backup-title")
            yield Input(placeholder="Hostnames (comma-separated, or 'all' for inventory)", id="backup-hosts",
                        value=self._selected_host or "")
            yield Input(placeholder="SSH user", id="backup-user")
            yield Input(placeholder="SSH password", password=True, id="backup-pass")
            yield Input(placeholder="Output directory (default: ./backups)", id="backup-dir")
            with Horizontal():
                yield Button("Backup", variant="primary", id="btn-backup-run")
                yield Button("Cancel", id="btn-backup-cancel")
            yield Log(id="backup-log", highlight=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-backup-cancel":
            self.dismiss()
            return

        hosts_text = self.query_one("#backup-hosts", Input).value.strip()
        user = self.query_one("#backup-user", Input).value.strip()
        password = self.query_one("#backup-pass", Input).value.strip()
        backup_dir = self.query_one("#backup-dir", Input).value.strip() or "./backups"
        log = self.query_one("#backup-log", Log)

        if not all([hosts_text, user, password]):
            log.write_line("❌ Hosts, user, and password required")
            return

        # Resolve hosts
        inv = load_inventory()
        if hosts_text.lower() == 'all':
            hosts = list(inv.get("devices", {}).keys())
        else:
            hosts = [h.strip() for h in hosts_text.replace(',', ' ').split() if h.strip()]

        log.write_line(f"💾 Backing up {len(hosts)} device(s) to {backup_dir}/")

        async def _backup():
            try:
                from netops.core.connection import DeviceConnection
                from pathlib import Path
                from datetime import datetime

                out = Path(backup_dir)
                out.mkdir(parents=True, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")

                for i, host in enumerate(hosts):
                    log.write_line(f"  [{i+1}/{len(hosts)}] {host}...")
                    dev_info = inv.get("devices", {}).get(host, {})
                    vendor = dev_info.get("vendor", "cisco_ios")

                    try:
                        conn = DeviceConnection(
                            host=dev_info.get("host", host),
                            username=user,
                            password=password,
                            device_type=vendor,
                        )
                        conn.connect()
                        config = conn.send_command("show running-config")
                        conn.disconnect()

                        filename = f"{host}_{ts}.cfg"
                        (out / filename).write_text(config)
                        log.write_line(f"    ✅ {filename} ({len(config)} bytes)")
                    except Exception as e:
                        log.write_line(f"    ❌ {host}: {e}")

                log.write_line(f"  ✅ Backups saved to {backup_dir}/")

            except Exception as e:
                log.write_line(f"  ❌ {e}")

        asyncio.get_event_loop().create_task(_backup())


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
    #device-table {
        height: 1fr;
    }
    #detail-panel {
        width: 40;
        border-left: solid $primary;
        padding: 1;
    }
    #scan-modal, #health-modal, #push-modal, #backup-modal {
        width: 70;
        height: 35;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    #scan-title, #health-title, #push-title, #backup-title {
        text-style: bold;
        color: $text;
        margin-bottom: 1;
    }
    #scan-log, #health-log, #push-log, #backup-log {
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
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "scan", "Scan"),
        Binding("h", "health", "Health"),
        Binding("p", "push", "Config Push"),
        Binding("b", "backup", "Backup"),
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
        self._selected_host: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="main-panel"):
                yield Input(placeholder="🔍 Search devices...", id="search-input")
                yield DataTable(id="device-table", cursor_type="row")
            with Vertical(id="detail-panel"):
                yield Static("Select a device", id="detail-content")
        yield Static(
            f"  {len(self.inventory.get('devices', {}))} devices  |  {INVENTORY_FILE}",
            classes="status-bar",
        )
        yield Footer()

    def on_error(self, event) -> None:
        """Global error handler — display errors, never crash."""
        import traceback
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
        import traceback
        logger = logging.getLogger("netops.tui")
        logger.error(f"Background task error: {error}", exc_info=True)

    def on_mount(self) -> None:
        table = self.query_one("#device-table", DataTable)
        table.add_columns("Hostname", "Host", "Vendor", "Model", "Version", "Serial", "Site")
        self._populate_table()

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
        try:
            if event.row_key is None or event.row_key.value is None:
                return
            hostname = str(event.row_key.value)
            info = self.inventory.get("devices", {}).get(hostname, {})
            detail = f"[bold]{hostname}[/bold]\n\n"
            if isinstance(info, dict):
                for k, v in sorted(info.items()):
                    if k == "tags" and isinstance(v, dict):
                        detail += f"[dim]{k}:[/dim]\n"
                        for tk, tv in v.items():
                            detail += f"  {tk}: {tv}\n"
                    else:
                        detail += f"[dim]{k}:[/dim] {v}\n"
            self._selected_host = hostname
            self.query_one("#detail-content", Static).update(detail)
        except Exception as e:
            logging.getLogger("netops.tui").error(f"Row selection error: {e}")

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-input":
            self._populate_table(event.value)



    def on_paste(self, event: "Paste") -> None:
        """Route paste events to the focused input widget."""
        from textual.widgets import Input, TextArea
        focused = self.focused
        if isinstance(focused, Input):
            focused.insert_text_at_cursor(event.text)
            event.prevent_default()
            event.stop()
        elif isinstance(focused, TextArea):
            focused.insert(event.text)
            event.prevent_default()
            event.stop()

    def _input_focused(self) -> bool:
        """Return True if an Input or TextArea widget currently has focus."""
        from textual.widgets import Input, TextArea
        focused = self.focused
        return isinstance(focused, (Input, TextArea))

    def action_scan(self) -> None:
        if self._input_focused():
            return
        self.push_screen(ScanScreen())

    def action_health(self) -> None:
        if self._input_focused():
            return
        self.push_screen(HealthScreen(self._selected_host))

    def action_push(self) -> None:
        if self._input_focused():
            return
        self.push_screen(ConfigPushScreen(self._selected_host))

    def action_backup(self) -> None:
        if self._input_focused():
            return
        self.push_screen(BackupScreen(self._selected_host))

    def action_help_screen(self) -> None:
        help_text = """[bold]netops-toolkit TUI — Help[/bold]

[bold]Keys:[/bold]
  s  — Scan subnets (ping + SNMP + SSH deep scan)
  h  — Health check a device
  p  — Push config to devices (bulk SNMP community change, etc.)
  b  — Backup device configs
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

[bold]Config Push:[/bold]
  Enter commands one per line
  Press 'c' in the commands box for SNMP community change template
  Dry Run = preview only, Commit = apply changes
  Supports bulk push to multiple devices

[bold]Config Backup:[/bold]
  Type 'all' to backup every device in inventory
  Or list specific hostnames

[bold]Data:[/bold]
  Inventory saved to: inventory.json
  CSV export: inventory.csv
  Backups: ./backups/

Press Escape to close this help.
"""
        self.notify(help_text, timeout=30)

    def action_export(self) -> None:
        if self._input_focused():
            return
        count = export_csv(self.inventory)
        self.notify(f"Exported {count} devices to inventory.csv")

    def action_refresh(self) -> None:
        if self._input_focused():
            return
        self.inventory = load_inventory()
        self._populate_table()
        count = len(self.inventory.get("devices", {}))
        self.query_one(".status-bar", Static).update(
            f"  {count} devices  |  {INVENTORY_FILE}"
        )
        self.notify(f"Refreshed: {count} devices")

    def action_search(self) -> None:
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
        """Close detail panel and clear search."""
        self.query_one("#detail-content", Static).update("Select a device")
        search = self.query_one("#search-input", Input)
        search.value = ""
        self._populate_table()
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
        if self._input_focused():
            return
        table = self.query_one("#device-table", DataTable)
        if table.cursor_row is not None:
            row_key = table.get_row_at(table.cursor_row)
            hostname = row_key[0] if row_key else None
            if hostname and hostname in self.inventory.get("devices", {}):
                del self.inventory["devices"][hostname]
                save_inventory(self.inventory)
                self._populate_table()
                self.notify(f"Deleted {hostname}")


def main():
    app = NetopsTUI()
    app.run()


if __name__ == "__main__":
    main()
