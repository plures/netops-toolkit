# Getting Started

This guide gets you from zero to running your first command.

## What You Need

- Python 3.10 or newer
- Network access to your devices (SSH or Telnet)
- Device credentials (username/password)

## Step 1: Install

```bash
# Clone the repo
git clone https://github.com/plures/netops-toolkit.git
cd netops-toolkit

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate    # Linux/Mac
# .venv\Scripts\activate     # Windows

# Install
pip install -e .
```

This installs the `netops` package and its dependencies (netmiko, paramiko, pyyaml).

## Step 2: Create Your Inventory File

Copy the example and edit it with your real devices:

```bash
cp examples/inventory.yaml my-inventory.yaml
```

Open `my-inventory.yaml` in any text editor:

```yaml
defaults:
  username: admin          # Default username for all devices
  transport: ssh           # Default: ssh (options: ssh, telnet)

devices:
  # Give each device a short name
  core-rtr-01:
    host: 10.0.0.1         # IP address or hostname
    vendor: cisco_ios       # See vendor list below
    role: core              # Optional: core, distribution, access
    site: dc1               # Optional: location name
    groups: [routers, core] # Optional: for filtering

  nokia-pe-01:
    host: 10.0.0.2
    vendor: nokia_sros
    groups: [routers, pe]

  old-switch-01:
    host: 10.0.1.1
    vendor: cisco_ios
    transport: telnet       # Override default for this device
    port: 23
    groups: [switches]
```

### Vendor Names

| Vendor/Platform | Use This |
|----------------|----------|
| Cisco IOS | `cisco_ios` |
| Cisco IOS-XE | `cisco_xe` |
| Cisco IOS-XR | `cisco_xr` |
| Cisco NX-OS | `cisco_nxos` |
| Nokia SR OS | `nokia_sros` |
| Nokia SR Linux | `nokia_srl` |
| Juniper Junos | `juniper_junos` |
| Arista EOS | `arista_eos` |
| Don't know | `autodetect` |

## Step 3: Test a Connection

Try collecting the config from one device:

```bash
python -m netops.collect.config \
  --host 10.0.0.1 \
  --vendor cisco_ios \
  --user admin \
  --password 'yourpassword'
```

If it works, you'll see:

```
✅ 10.0.0.1: 347 lines collected
```

If it fails, you'll see the error:

```
❌ 10.0.0.1: Authentication failed
```

## Step 4: Set Up Password (Optional)

Instead of typing your password every time, set an environment variable:

```bash
# Add to your .bashrc or .profile
export NETOPS_PASSWORD='yourpassword'
```

Now you can skip `--password`:

```bash
python -m netops.collect.config --host 10.0.0.1 --vendor cisco_ios --user admin
```

## What's Next?

- [Config Collector](config-collector.md) — back up configs from all your devices
- [Interface Checker](interface-checker.md) — check what's up and what's down
- [Inventory Management](inventory-management.md) — organize your devices into groups
- [Auto-Inventory Pipeline](auto-inventory.md) — automatically discover devices via scan and feed them to Ansible
