# Interface Checker Guide

Check interface status on your network devices. Find what's down, what has errors.

## What It Does

- Connects to a device
- Runs `show ip interface brief` (Cisco) or `show port` (Nokia)
- Parses the output into a clean, readable summary
- Optionally shows only down interfaces

## Quick Start

### Check all interfaces on a device

```bash
python -m netops.check.interfaces \
  --host 10.0.0.1 \
  --vendor cisco_ios \
  --user admin \
  --password 'secret'
```

**Output:**
```
📊 10.0.0.1: 24/28 interfaces up, 4 down
  ✅ GigabitEthernet0/0 (10.0.0.1) — up/up
  ✅ GigabitEthernet0/1 (10.0.0.2) — up/up
  ❌ GigabitEthernet0/2 — administratively down/down
  ❌ GigabitEthernet0/3 — down/down
  ...
```

### Show only down interfaces

```bash
python -m netops.check.interfaces \
  --host 10.0.0.1 \
  --vendor cisco_ios \
  --user admin \
  --down-only
```

**Output:**
```
📊 10.0.0.1: 24/28 interfaces up, 4 down
  ❌ GigabitEthernet0/2 — administratively down/down
  ❌ GigabitEthernet0/3 — down/down
  ❌ Serial0/0/0 — down/down
  ❌ Tunnel0 — up/down
```

## Step-by-Step: Morning Health Check

### Step 1: Check your core routers

```bash
python -m netops.check.interfaces --host 10.0.0.1 --vendor cisco_ios -u admin --down-only
python -m netops.check.interfaces --host 10.0.0.2 --vendor nokia_sros -u admin --down-only
```

### Step 2: Get JSON for a report or ticket

```bash
python -m netops.check.interfaces \
  --host 10.0.0.1 \
  --vendor cisco_ios \
  -u admin \
  --down-only \
  --json
```

**Output:**
```json
{
  "host": "10.0.0.1",
  "success": true,
  "interfaces": [
    {
      "name": "GigabitEthernet0/3",
      "ip": null,
      "status": "down",
      "protocol": "down",
      "up": false
    }
  ],
  "summary": {
    "total": 28,
    "up": 24,
    "down": 4
  }
}
```

### Step 3: Quick script to check multiple devices

```bash
#!/bin/bash
# check-all-core.sh
echo "=== Core Router Health Check ==="
echo ""

for host in 10.0.0.1 10.0.0.2 10.0.0.3; do
  python -m netops.check.interfaces \
    --host $host \
    --vendor cisco_ios \
    -u admin \
    --down-only
  echo ""
done
```

Make it executable:

```bash
chmod +x check-all-core.sh
./check-all-core.sh
```

## All Options

| Option | Short | What It Does |
|--------|-------|-------------|
| `--host` | | Device IP or hostname (required) |
| `--vendor` | | Device type (default: `cisco_ios`) |
| `--user` | `-u` | Username |
| `--password` | `-p` | Password (or use `NETOPS_PASSWORD` env var) |
| `--down-only` | | Only show down interfaces |
| `--json` | | JSON output to stdout |

## What the Status Means

| Status | Protocol | What It Means |
|--------|----------|--------------|
| up | up | ✅ Working normally |
| up | down | ⚠️ Layer 1 OK but Layer 2 problem (protocol issue) |
| down | down | ❌ Interface is down (cable? remote end?) |
| admin down | down | 🔒 Intentionally shut down (`shutdown` command) |

## Troubleshooting

| Problem | Fix |
|---------|-----|
| No interfaces shown | Wrong vendor type — check `--vendor` matches your device |
| Parse error | Device output format may differ. Open an issue with the raw output. |
| Timeout | Device is slow to respond. Increase timeout in inventory. |
