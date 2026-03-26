# netops-toolkit

Modular network automation utilities for telco operations.

A collection of small, composable Python tools for common network engineering tasks.
Each utility does one thing well and can be combined with others to build workflows.
Designed for telco NOC/engineering teams moving from manual CLI work to automation.

---

## Features

| Area | Capability |
|------|------------|
| **Discovery** | Ping sweep + SNMP fingerprint → auto-populated inventory |
| **Config backup** | Bulk collection with timestamped snapshots |
| **Health checks** | CPU, memory, interface errors, log analysis across vendors |
| **BGP monitor** | Peer up/down, prefix deviation, flap detection |
| **VLAN audit** | Trunk/access consistency, orphan VLAN detection |
| **Config diff** | Semantic-aware diff (unified / tree / JSON) with security highlighting |
| **Safe push** | Dry-run by default, pre/post health validation, automatic rollback |
| **Change planning** | Risk assessment, step ordering, dry-run simulation |
| **Credential vault** | AES-256-GCM encrypted credential store with env override |
| **Reporting** | HTML/PDF health reports, email scheduling |
| **Ansible bridge** | Dynamic inventory, `netops_facts` module, playbook generator |

---

## Quick Start

```bash
pip install netops-toolkit
```

```python
from netops.core.inventory import Inventory
from netops.check.health import run_health_check

inventory = Inventory.from_yaml("inventory.yaml")
for device in inventory.devices:
    result = run_health_check(device.connection_params())
    print(result)
```

See the [Getting Started](guides/getting-started.md) guide for a full walkthrough.

---

## Documentation

- **[Guides](guides/getting-started.md)** — Step-by-step tutorials for every feature
- **[API Reference](api/README.md)** — Complete Python API documentation
- **[CLI Reference](guides/cli-reference.md)** — All command-line flags and options

---

## Installation

```bash
# Core
pip install netops-toolkit

# With report generation (HTML/PDF)
pip install "netops-toolkit[report]"
pip install "netops-toolkit[report-pdf]"

# With SNMP support
pip install "netops-toolkit[snmp]"

# With Ansible modules
pip install "netops-toolkit[ansible]"

# Development
pip install "netops-toolkit[dev]"

# Documentation site
pip install "netops-toolkit[docs]"
```

---

## Supported Equipment

| Vendor | Platforms | Status |
|--------|-----------|--------|
| Cisco | IOS, IOS-XE, IOS-XR, NX-OS | ✅ Core |
| Nokia | SR OS (SROS), SRL | ✅ Core |
| Brocade | FastIron/ICX, Network OS/VDX | ✅ Core |
| Palo Alto | PAN-OS | ✅ Core |
| Juniper | Junos | ✅ Core |
| Arista | EOS | ✅ Core |
| Generic | Any CLI-based device | ✅ Via raw transport |

---

## License

MIT — see [LICENSE](https://github.com/plures/netops-toolkit/blob/main/LICENSE).
