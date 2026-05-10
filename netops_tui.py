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
    python -m netops_tui
    python netops_tui.py
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import sys
from pathlib import Path

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

    def compose(self) -> ComposeResult:
        with Vertical(id="scan-modal"):
            yield Label("🔍 Inventory Scan", id="scan-title")
            yield Input(placeholder="Subnets (e.g. 10.0.0.0/24, 192.168.1.0/24)", id="scan-subnet")
            yield Input(placeholder="Or path to hosts file (hosts.csv or ips.txt)", id="scan-hosts-file")
            yield Input(placeholder="SNMP community (default: public)", id="scan-community")
            yield Input(placeholder="SSH user (for deep scan, optional)", id="scan-user")
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
            community = self.query_one("#scan-community", Input).value.strip() or "public"
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
                from netops.inventory.scan import scan_subnet, results_to_inventory_fragment, deep_enrich

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
                    results = scan_subnet(
                        subnet=subnet,
                        community=community,
                        skip_snmp=skip_snmp,
                    )
                    reachable = sum(1 for r in results if r.reachable)
                    log.write_line(f"    Found {reachable} reachable hosts")
                    all_results.extend(results)

                fragment = results_to_inventory_fragment(all_results)

                if user and password and not skip_snmp:
                    log.write_line(f"  🔬 Deep scan with SSH ({user})...")
                    fragment = deep_enrich(
                        fragment,
                        username=user,
                        password=password,
                    )

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

    def compose(self) -> ComposeResult:
        with Vertical(id="health-modal"):
            yield Label("🏥 Health Check", id="health-title")
            yield Input(placeholder="Hostname or IP", id="health-host")
            yield Input(placeholder="SSH user", id="health-user")
            yield Input(placeholder="SSH password", password=True, id="health-pass")
            with Horizontal():
                yield Button("Check", variant="primary", id="btn-health-run")
                yield Button("Close", id="btn-health-close")
            yield Log(id="health-log", highlight=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-health-close":
            self.dismiss()
        elif event.button.id == "btn-health-run":
            host = self.query_one("#health-host", Input).value.strip()
            user = self.query_one("#health-user", Input).value.strip()
            password = self.query_one("#health-pass", Input).value.strip()
            log = self.query_one("#health-log", Log)
            if not all([host, user, password]):
                log.write_line("❌ All fields required")
                return
            log.write_line(f"🔍 Checking {host}...")

            async def _check():
                try:
                    from netops.check.cisco import CiscoHealthCheck
                    from netops.core.connection import DeviceConnection

                    inv = load_inventory()
                    device_info = inv.get("devices", {}).get(host, {})
                    vendor = device_info.get("vendor", "cisco_ios")

                    conn = DeviceConnection(
                        host=host,
                        username=user,
                        password=password,
                        device_type=vendor,
                    )
                    conn.connect()
                    checker = CiscoHealthCheck(conn)
                    result = checker.run_all()
                    conn.disconnect()

                    for check_name, status in result.items():
                        icon = "✅" if status.get("ok") else "⚠️"
                        log.write_line(f"  {icon} {check_name}: {status.get('summary', '')}")

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

    def compose(self) -> ComposeResult:
        with Vertical(id="push-modal"):
            yield Label("⚙️ Config Push", id="push-title")
            yield Input(placeholder="Hostname or IP (comma-separated for bulk)", id="push-hosts")
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

    def compose(self) -> ComposeResult:
        with Vertical(id="backup-modal"):
            yield Label("💾 Config Backup", id="backup-title")
            yield Input(placeholder="Hostnames (comma-separated, or 'all' for inventory)", id="backup-hosts")
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
        Binding("?", "help_screen", "Help"),
    ]

    def __init__(self):
        super().__init__()
        self.inventory = load_inventory()

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="main-panel"):
                yield Input(placeholder="🔍 Search devices...", id="search-input")
                yield DataTable(id="device-table")
            with Vertical(id="detail-panel"):
                yield Static("Select a device", id="detail-content")
        yield Static(
            f"  {len(self.inventory.get('devices', {}))} devices  |  {INVENTORY_FILE}",
            classes="status-bar",
        )
        yield Footer()

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
        self.query_one("#detail-content", Static).update(detail)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-input":
            self._populate_table(event.value)

    def action_scan(self) -> None:
        self.push_screen(ScanScreen())

    def action_health(self) -> None:
        self.push_screen(HealthScreen())

    def action_push(self) -> None:
        self.push_screen(ConfigPushScreen())

    def action_backup(self) -> None:
        self.push_screen(BackupScreen())

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
        count = export_csv(self.inventory)
        self.notify(f"Exported {count} devices to inventory.csv")

    def action_refresh(self) -> None:
        self.inventory = load_inventory()
        self._populate_table()
        count = len(self.inventory.get("devices", {}))
        self.query_one(".status-bar", Static).update(
            f"  {count} devices  |  {INVENTORY_FILE}"
        )
        self.notify(f"Refreshed: {count} devices")

    def action_search(self) -> None:
        self.query_one("#search-input", Input).focus()

    def action_delete(self) -> None:
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
