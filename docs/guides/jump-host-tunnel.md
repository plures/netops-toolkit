# SSH Jump-Host Tunneling (Bastion)

## Who this is for

You have a Linux jump box (bastion) that's the only thing with network
reachability to your switches, but it isn't maintained, its Python is old,
and you don't want to run netops-toolkit *on* it. You have a Windows
machine where you can install a current Python as your own user (no admin
rights needed). This guide gets you running the full toolkit natively on
Windows, using the jump box for exactly one thing: as SSH network
transport to reach the devices.

**What changes for you:**
- netops-toolkit runs entirely on your Windows machine (discovery, health
  checks, config collection, reports - all of it).
- The jump box never runs any netops-toolkit code, never needs a newer
  Python, and needs no maintenance beyond staying reachable over SSH.
- Reports, backups, and inventory files land directly on your Windows
  machine - no extra step copying files to/from Linux.

## How it works

netops-toolkit opens an SSH connection to the jump box using
[Paramiko](https://www.paramiko.org/), then asks that connection for a
`direct-tcpip` channel pointed at the target switch's IP and port. That
channel is handed to [Netmiko](https://github.com/ktbyers/netmiko) via its
`sock=` parameter - Netmiko treats it exactly like a normal TCP socket and
runs the same vendor-aware CLI logic on top of it as it would for a direct
connection. The jump box is not used to run Netmiko, Python, or any
netops-toolkit code; it only relays SSH bytes.

```
Windows (netops-toolkit)
   │
   │ 1. SSH connect (Paramiko)
   ▼
Jump box / bastion (pure network transport, no toolkit code runs here)
   │
   │ 2. direct-tcpip channel → switch:22
   ▼
Switch (Netmiko CLI session runs *through* the channel, driven from Windows)
```

This mechanism was chosen over local SSH port-forwarding or spawning an
external OpenSSH client subprocess because it needs no local port
allocation/lifecycle management and adds no new dependency beyond the
`paramiko` version already required by netops-toolkit. See "Why this
approach" below for the full comparison.

## Windows setup (no admin rights)

1. Install Python for your own user (e.g. from python.org, "Install for me
   only" — no admin prompt).
2. `pip install --user netops-toolkit` (or clone the repo and
   `pip install --user -e .`).
3. Confirm `paramiko` is available (it's a core dependency, installed
   automatically): `python -c "import paramiko; print(paramiko.__version__)"`.

No changes are needed on the jump box. It only needs to keep accepting SSH
connections and forwarding TCP to your switches, which it presumably
already does today.

## Inventory configuration

Add jump-host fields to your inventory YAML, either per-device or once in
`defaults:` so every device in the file tunnels through the same bastion:

```yaml
defaults:
  username: admin
  transport: ssh
  jump_host: bastion.example.com
  jump_username: netops
  # jump_port defaults to 22; set jump_key_file to use key auth on the bastion

devices:
  core-sw-01:
    host: 10.0.3.1          # only reachable FROM the jump box, not from Windows directly
    vendor: cisco_ios
    role: core

  edge-sw-02:
    host: 10.0.3.2
    vendor: arista_eos
    role: edge
    # Per-device override: tunnel through a different bastion for this one device
    jump_host: other-bastion.example.com
    jump_port: 2222
```

Fields:

| Field           | Meaning                                              |
|-----------------|-------------------------------------------------------|
| `jump_host`     | Bastion hostname/IP. Omit entirely for direct (non-tunneled) connections — this is fully backward compatible. |
| `jump_port`     | Bastion SSH port. Defaults to `22`.                    |
| `jump_username` | Username on the bastion. If omitted, resolved from the credential vault when the calling integration unlocks it. |
| `jump_password` | Bastion password. Prefer the encrypted vault rather than putting this in YAML. |
| `jump_key_file` | Private key path for key-based bastion auth. If omitted, password auth is used. |
| `jump_key_passphrase` | Private-key passphrase. Prefer the encrypted vault rather than putting this in YAML. |

Devices with no `jump_host` set (the common case today) connect exactly as
before — there is no behavior change for non-tunneled devices.

## Jump-box credentials (vault)

Bastion credentials use the exact same encrypted vault as device
credentials (`netops/core/vault.py`, AES-256-GCM) — no separate secrets
mechanism. Store the bastion's password once, keyed by the bastion's own
hostname:

```bash
python -m netops.core.vault set --device bastion.example.com --user netops
```

When an integration passes an unlocked `CredentialVault` to
`resolve_jump_host_params()` (or `jump_host_from_inventory()`),
netops-toolkit looks up credentials for `jump_host` through the vault the
same way it looks up device credentials — environment-variable override,
then the device entry. For password authentication, the vault's encrypted
`password` is the bastion password. For a `jump_key_file`, that same
encrypted field is used as the key passphrase; no parallel secrets store is
introduced.

The existing standalone check/collect CLI commands do not currently unlock
the vault for device credentials either; use the inventory fields or a GUI/
programmatic caller that has already unlocked the vault. This is deliberate
scope honesty, not a second credential mechanism.

## Programmatic usage

If you're calling `netops.core.connection` directly (as the CLI tools do):

```python
from netops.core.connection import ConnectionParams, JumpHostParams, DeviceConnection

jump = JumpHostParams(host="bastion.example.com", username="netops", password="jumppw")
params = ConnectionParams(
    host="10.0.3.1",
    username="admin",
    password="devicepw",
    device_type="cisco_ios",
    jump_host=jump,
)

with DeviceConnection(params) as conn:
    print(conn.send("show version"))
```

Or resolve jump-host params straight from an inventory `Device` and the
vault:

```python
from netops.core.connection import resolve_jump_host_params
from netops.core.vault import CredentialVault

vault = CredentialVault()
vault.unlock(master_password)

jump = resolve_jump_host_params(
    device.jump_host,
    device.jump_port,
    device.jump_username,
    device.jump_password,
    device.jump_key_file,
    device.jump_key_passphrase,
    vault=vault,
)
```

## Limitations

- Telnet transport cannot be tunneled through a jump host (`ConnectionParams`
  raises `ValueError` if you combine `transport=Transport.TELNET` with
  `jump_host`) — jump-host tunneling is an SSH-to-SSH mechanism.
- Each device connection opens its own `direct-tcpip` channel on a fresh
  SSH session to the bastion. For large fleets this means one bastion SSH
  login per device in the run, same as an equivalent `ssh -J` fan-out would
  do; the bastion's own connection limits still apply.

## Why this approach (design rationale)

Three tunnel mechanisms were considered for the Windows→bastion→switch
path; a fourth (single shared/multiplexed bastion connection reused across
devices) was noted but not implemented in this pass:

1. **Paramiko in-process `direct-tcpip` channel → Netmiko `sock=`
   (chosen).** No local port ever gets bound, nothing to clean up, no new
   dependency (paramiko is already a core requirement). Netmiko's own
   documented pattern for jump-host support. Risk: relies on Netmiko/
   Paramiko fully supporting the target vendor's SSH quirks through a
   channel object rather than a raw socket — mitigated by this being
   Netmiko's own sanctioned mechanism, not a workaround.
2. **Local SSH port-forward (`127.0.0.1:<ephemeral>` → bastion → device),
   Netmiko pointed at the local port.** More "standard" and easier to
   reason about in isolation, but requires managing ephemeral port
   lifecycle (allocation, collision avoidance, cleanup on error) for every
   device in a scan/health-check run across potentially hundreds of
   devices. Rejected for this pass as unnecessary complexity given option
   1 works; could be revisited if a future vendor proves incompatible
   with in-process channels.
3. **Spawn a real OpenSSH client subprocess with `-J`/`ProxyJump` (Windows
   ships OpenSSH natively).** Avoids reimplementing any SSH logic in
   Python, but adds process-management/lifecycle complexity (spawn, health
   monitoring, cleanup, cross-platform argument quoting) for a problem
   Paramiko already solves in-process. Rejected: higher operational
   surface area for no functional gain over option 1.
4. **Single shared/multiplexed bastion connection reused across all
   devices in a run** (open one SSH session to the bastion, open many
   `direct-tcpip` channels on it). Would reduce bastion login count for
   large fleets. Not implemented in this pass — `DeviceConnection` is
   scoped to a single device's lifecycle today, and sharing a `paramiko.SSHClient`
   across concurrent `DeviceConnection` instances needs an explicit
   pooling/lifecycle owner above `DeviceConnection` that doesn't exist yet.
   Flagged as honest follow-up work, not implemented as a stub.

Option 1 was selected: it satisfies the real constraint (jump box does
zero toolkit work, Windows does everything, no extra moving parts) with
the least new surface area, and reuses an already-required dependency.
