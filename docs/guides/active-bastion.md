# Active Bastion Routing

Select a bastion once and netops-toolkit routes subsequent TCP device
connections through it automatically. This applies to CLI commands and Python
callers using `DeviceConnection`. It does not require an inventory entry, a `jump_host` field, a local
forwarded port, or command-specific proxy arguments.

```powershell
netops bastion connect --host bastion.example.com --username netops --password-stdin
```

The command starts a user-local service. It keeps one SSH session to the
bastion and exposes an authenticated loopback-only SOCKS endpoint to the
toolkit. The password is sent to that service over stdin, never written to the
active-bastion state file, and is retained only in the service's memory.

Check or end the session with:

```powershell
netops bastion status
netops bastion disconnect
```

While connected, ordinary calls keep their normal shape:

```python
from netops.core.connection import ConnectionParams, DeviceConnection

with DeviceConnection(ConnectionParams(host="10.0.3.1", username="admin", password="device-password")) as conn:
    print(conn.send("show version"))
```

The connection is routed through the selected bastion automatically. Existing
per-device `jump_host` inventory fields remain supported for compatibility,
but the active bastion is the recommended workstation-wide mode.

## Discovery

`netops scan --subnet 10.0.3.0/24` also detects the active bastion. It probes
each address's SSH port through the bastion and then performs normal deep SSH
collection when credentials are supplied. SSH forwarding is TCP-only, so the
scanner does not run local ICMP or UDP/SNMP probes against the remote network.

## Host keys

On first connection, the selected bastion's host key is stored in
`~/.netops/known_hosts`. A changed key is rejected on later connections. Review
an unexpected key change with the network owner before removing its known-hosts
entry.
