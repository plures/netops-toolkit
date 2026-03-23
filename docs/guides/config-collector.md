# Config Collector Guide

Collect running configurations from one device or your entire inventory.

## What It Does

- Connects to each device
- Runs `show running-config` (Cisco) or `admin display-config` (Nokia)
- Saves the config to a file or prints it as JSON

## Quick Start

### Collect from one device

```bash
python -m netops.collect.config \
  --host 10.0.0.1 \
  --vendor cisco_ios \
  --user admin \
  --password 'secret'
```

**Output:**
```
✅ 10.0.0.1: 347 lines collected
```

### Collect from your entire inventory

```bash
python -m netops.collect.config \
  --inventory my-inventory.yaml
```

### Collect from a specific group

```bash
python -m netops.collect.config \
  --inventory my-inventory.yaml \
  --group core
```

This only connects to devices in the `core` group.

## Step-by-Step: Daily Config Backup

### Step 1: Make a backup folder

```bash
mkdir -p /var/backups/network
```

### Step 2: Run the collector with `--output`

```bash
python -m netops.collect.config \
  --inventory my-inventory.yaml \
  --output /var/backups/network/
```

**What happens:**
- Connects to each device in your inventory
- Saves each config as `<ip>_<timestamp>.cfg`
- Prints a summary

```
✅ 10.0.0.1 → /var/backups/network/10.0.0.1_20260323-140000.cfg (347 lines)
✅ 10.0.0.2 → /var/backups/network/10.0.0.2_20260323-140005.cfg (512 lines)
❌ 10.0.1.1: Connection timed out
```

### Step 3: Automate it with cron (optional)

```bash
# Edit crontab
crontab -e

# Add this line to run every night at 2am
0 2 * * * cd /path/to/netops-toolkit && .venv/bin/python -m netops.collect.config --inventory my-inventory.yaml --output /var/backups/network/ >> /var/log/netops-backup.log 2>&1
```

## JSON Output

For scripting or piping to other tools:

```bash
python -m netops.collect.config \
  --inventory my-inventory.yaml \
  --group routers \
  --json
```

**Output:**
```json
[
  {
    "host": "10.0.0.1",
    "device_type": "cisco_ios",
    "collected_at": "2026-03-23T14:00:00+00:00",
    "success": true,
    "config": "!\nversion 15.7\n...",
    "lines": 347
  }
]
```

You can pipe this to `jq` for filtering:

```bash
# Show only failed devices
python -m netops.collect.config -i inv.yaml --json | jq '.[] | select(.success == false)'

# Count lines per device
python -m netops.collect.config -i inv.yaml --json | jq '.[] | "\(.host): \(.lines) lines"'
```

## All Options

| Option | Short | What It Does |
|--------|-------|-------------|
| `--inventory` | `-i` | Inventory file (YAML or JSON) |
| `--group` | `-g` | Only target this group |
| `--host` | | Single device IP/hostname |
| `--vendor` | | Device type (default: `cisco_ios`) |
| `--user` | `-u` | Username |
| `--password` | `-p` | Password (or use `NETOPS_PASSWORD` env var) |
| `--transport` | | `ssh` or `telnet` (default: `ssh`) |
| `--output` | `-o` | Directory to save config files |
| `--json` | | Print JSON to stdout |

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Authentication failed` | Check username/password. Try connecting manually with SSH first. |
| `Connection timed out` | Check IP is reachable (`ping`). Check port (SSH=22, Telnet=23). Firewall? |
| `No matching key exchange` | Old device with weak crypto. Try adding `--transport ssh2` or use Telnet. |
| `Command not found` | Wrong vendor type. A Nokia device won't understand `show running-config`. |
| Empty config | Some devices need `enable` mode. Set `enable_password` in inventory. |
