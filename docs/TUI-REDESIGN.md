# Netops-Toolkit TUI Redesign — Design Spec

## Layout Change: Split Horizontal

```
┌─────────────────────────────────────────────────────────────┐
│ Header: netops-toolkit                                       │
├─────────────────────────────────────────────────────────────┤
│ [Search: _______________]                                    │
│                                                              │
│  ☐ Hostname        IP            Vendor         Model       │
│  ☐ core-rtr-01    10.0.0.1      Brocade FI     ICX6450     │
│  ☑ sw-floor2      10.0.0.5      Cisco IOS      C3750       │
│  ☑ fw-edge-01     10.0.0.10     Palo Alto      PA-3260     │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│ ── Device Detail (sw-floor2) ────────────────────────────── │
│                                                              │
│  Host: 10.0.0.5          Vendor: Cisco IOS                  │
│  Model: WS-C3750-48P     Serial: FOC1234X5YZ               │
│  Version: 15.2(4)E10     Uptime: 142 days                   │
│  Memory: 256MB / 128MB   Image: c3750-ipservicesk9-mz.bin  │
│  Community: C1sc0RO       MAC: 00:1A:2B:3C:4D:5E           │
│                                                              │
│  [Enter] More detail  [c] Running config  [Esc] Close       │
├─────────────────────────────────────────────────────────────┤
│ Footer: s=Scan h=Health p=Push b=Backup Space=Select        │
└─────────────────────────────────────────────────────────────┘
```

### Detail Pane Behavior
- **Default view**: Basic inventory (host, vendor, model, serial, version, uptime, community, MAC)
- **Enter/More**: Cycle to extended detail (memory, flash, interfaces, reload reason, domain, neighbors)
- **c**: Show running config (fetched on-demand via SSH, not stored permanently by default)
- **Esc**: Close detail pane, return focus to table

## Multi-Select

- Space bar toggles selection on current row (checkbox column)
- Ctrl+A selects all / deselects all
- Selection count shown in status bar: "3 selected"
- Bulk operations (push, backup) operate on selection if any selected, else on focused row

## Bulk Config Push (Generic)

Not limited to community strings. The push modal accepts:
- Commands (free-form, one per line)
- Vendor auto-detected per device (different command syntax per vendor)
- Pre-built templates for common ops:
  - SNMP community change
  - NTP server change
  - Syslog destination
  - Banner MOTD
  - User account creation

### SNMP Community Change Template
```
# Cisco IOS/XE/NX-OS:
no snmp-server community {old_community} RO
snmp-server community {new_community} RO

# Brocade FastIron:
no snmp-server community {old_community} ro
snmp-server community {new_community} ro

# Juniper:
delete snmp community {old_community}
set snmp community {new_community} authorization read-only
```

After push: verify community works via SNMP probe → update inventory.

## Credential Management

### Hierarchy (resolved at operation time):
1. **Per-device creds** (highest priority) — stored in vault, keyed by hostname
2. **Per-group creds** — vault group entries (e.g., "core-routers" group)
3. **Global creds** (fallback) — vault default entry

### UX in TUI:
- New keybind: `v` = Vault/Credentials
- Vault screen shows: Global creds, per-group, per-device overrides
- Set global once → all operations use it unless overridden
- Credential fields in scan/health/push/backup pre-fill from vault
- If vault has creds, those fields show "[from vault]" placeholder

### Resolution logic:
```python
def resolve_creds(hostname: str, vault: CredentialVault) -> tuple[str, str]:
    # 1. Check per-device
    device_creds = vault.get_device(hostname)
    if device_creds:
        return device_creds.username, device_creds.password
    # 2. Check groups (device may belong to multiple)
    for group in vault.get_groups_for_device(hostname):
        group_creds = vault.get_group(group)
        if group_creds:
            return group_creds.username, group_creds.password
    # 3. Fall back to global
    default = vault.get_default()
    if default:
        return default.username, default.password
    return "", ""
```

## Scan — Collect Everything

Default scan collects ALL available info:
- IP (ping)
- Vendor (SNMP + SSH auto-detect)
- Hostname, model, serial, version, uptime (SSH show version)
- MAC address, memory, flash, image (SSH show version extended)
- Interface count (SSH show interfaces)
- SNMP community string (SSH running config extraction)
- CDP/LLDP neighbors (SNMP or SSH)
- Running config (stored separately in backups/, not in inventory.json)

Running config is NOT stored in the inventory file (too large). It's:
- Fetched on-demand when user presses `c` in detail view
- Stored in `backups/<hostname>/running-config-<date>.txt` when explicitly backed up

## Fault Tolerance

### Rules:
1. No exception ever crashes the app
2. No background task freezes the UI
3. Escape ALWAYS dismisses the current modal
4. Mouse events are always safe (guarded handlers)
5. Errors render in the log pane or status bar, never as stacktraces

### Implementation:
- Global `on_error` handler on the App class
- All async tasks wrapped in try/except
- All event handlers wrapped in try/except
- Modal BINDINGS always include escape→dismiss (already done)
- DataTable row_selected always guards None
- Timeouts on all network operations (already in ConnectionParams)

## Test-First Development Order

1. Build mock SSH server (in progress — subagent)
2. Write integration tests for bulk push (mock server responds to config commands)
3. Implement bulk push
4. Write tests for credential vault integration
5. Implement vault auto-fill
6. Write tests for new layout (Textual pilot — verify bottom pane renders)
7. Implement layout change
8. Write fault tolerance tests (post invalid events, verify no crash)
9. Implement global error handler
10. Full QA pass against mock server
11. Release
