# Inventory Management Guide

Your inventory file is the foundation — it tells every script which devices exist, how to connect, and how they're organized.

> **Auto-discovery:** Don't want to type every device by hand? The [Network Scanner](scan.md) can discover devices automatically via ping sweep and SNMP, and produce an inventory fragment you can merge straight into this file.

## What It Does

- Stores all your device info in one YAML or JSON file
- Groups devices for targeted operations
- Tags devices for flexible filtering
- Exports to Ansible inventory format when you're ready

## Step-by-Step: Build Your Inventory

### Step 1: Start with the example

```bash
cp examples/inventory.yaml my-inventory.yaml
```

### Step 2: Add your real devices

Open `my-inventory.yaml` and replace the examples:

```yaml
defaults:
  username: admin
  transport: ssh

devices:
  # === CORE ROUTERS ===
  core-rtr-01:
    host: 10.0.0.1
    vendor: cisco_ios
    role: core
    site: main-dc
    groups: [routers, core, main-dc]
    enable_password: enablesecret

  core-rtr-02:
    host: 10.0.0.2
    vendor: nokia_sros
    role: core
    site: main-dc
    groups: [routers, core, main-dc]

  # === DISTRIBUTION SWITCHES ===
  dist-sw-01:
    host: 10.0.1.1
    vendor: cisco_ios
    role: distribution
    site: main-dc
    groups: [switches, distribution, main-dc]

  dist-sw-02:
    host: 10.0.1.2
    vendor: cisco_ios
    role: distribution
    site: branch-01
    groups: [switches, distribution, branch-01]

  # === ACCESS SWITCHES ===
  access-sw-01:
    host: 10.0.2.1
    vendor: cisco_ios
    role: access
    site: floor-3
    groups: [switches, access, floor-3]
    transport: telnet        # Old switch, no SSH
    port: 23

  # === PE ROUTERS ===
  pe-rtr-01:
    host: 10.1.0.1
    vendor: nokia_sros
    role: edge
    site: pop-east
    groups: [routers, pe, pop-east]
    username: nokia-admin    # Different credentials
    password: different-pass
```

### Step 3: Understand groups

Groups let you target specific sets of devices. A device can be in multiple groups.

```yaml
groups: [routers, core, main-dc]
```

This device is in three groups. You can target any of them:

```bash
# All routers (core + PE + edge)
python -m netops.collect.config -i my-inventory.yaml --group routers

# Just core devices
python -m netops.collect.config -i my-inventory.yaml --group core

# Everything at main-dc
python -m netops.collect.config -i my-inventory.yaml --group main-dc
```

### Step 4: Use tags for extra metadata

Tags are key-value pairs for flexible filtering:

```yaml
  core-rtr-01:
    host: 10.0.0.1
    vendor: cisco_ios
    tags:
      environment: production
      contract: gold
      managed_by: noc
      os_version: "15.7"
```

### Step 5: Override defaults per device

The `defaults` section sets values for all devices. Any device can override:

```yaml
defaults:
  username: admin
  transport: ssh

devices:
  normal-router:
    host: 10.0.0.1
    vendor: cisco_ios
    # Uses defaults: admin, ssh

  legacy-switch:
    host: 10.0.1.1
    vendor: cisco_ios
    username: legacy-user    # Override username
    transport: telnet        # Override transport
    port: 23
```

## Step-by-Step: Export to Ansible

When your team is ready for Ansible:

### Step 1: Use the inventory in Python

```python
from netops.core import Inventory

inv = Inventory.from_file("my-inventory.yaml")

# Export to Ansible format
ansible_inv = inv.to_ansible()

# Save it
import json
with open("ansible_inventory.json", "w") as f:
    json.dump(ansible_inv, f, indent=2)
```

### Step 2: Use with Ansible

```bash
ansible-inventory -i ansible_inventory.json --list
ansible -i ansible_inventory.json routers -m ping
```

## Tips

### Organize by site

```yaml
devices:
  # main-dc
  main-dc-core-01: { host: 10.0.0.1, vendor: cisco_ios, groups: [main-dc, core] }
  main-dc-core-02: { host: 10.0.0.2, vendor: nokia_sros, groups: [main-dc, core] }

  # branch-01
  branch-01-rtr-01: { host: 10.1.0.1, vendor: cisco_ios, groups: [branch-01, routers] }
  branch-01-sw-01:  { host: 10.1.0.2, vendor: cisco_ios, groups: [branch-01, switches] }
```

### Use consistent naming

Pick a convention and stick with it:

```
<site>-<role>-<number>
main-dc-core-01
branch-01-access-03
pop-east-pe-01
```

### Keep credentials out of the inventory

For production, use environment variables:

```bash
export NETOPS_PASSWORD='shared-password'
```

Or wait for the credential vault feature (issue #8).

### Start small

Don't try to add 500 devices at once. Start with:
1. Your 2-3 most important core devices
2. Run a config backup — make sure it works
3. Add more devices gradually
4. Organize into groups as patterns emerge

## File Format: JSON Alternative

If you prefer JSON:

```json
{
  "defaults": {
    "username": "admin",
    "transport": "ssh"
  },
  "devices": {
    "core-rtr-01": {
      "host": "10.0.0.1",
      "vendor": "cisco_ios",
      "groups": ["routers", "core"]
    }
  }
}
```

Both YAML and JSON work everywhere. YAML is easier to read; JSON is easier to generate from scripts.

## Auto-Discovery

Instead of building your inventory by hand, you can scan a subnet to discover devices automatically:

```bash
python -m netops.inventory.scan --subnet 10.0.0.0/24 --merge my-inventory.yaml
```

See the [Network Scanner Guide](scan.md) for full details.
