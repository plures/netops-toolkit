# API Reference

Complete API reference for the **netops-toolkit** Python library.

---

## Modules

| Section | Description |
|---------|-------------|
| [Core](core.md) | Connection management, device inventory, credential vault |
| [Check](check.md) | Health checks, BGP monitoring, interface status, VLAN audit, vendor-specific checks |
| [Change](change.md) | Semantic diff, change planning, safe push, automated rollback |
| [Collect](collect.md) | Configuration collection and bulk backup with diff tracking |
| [Parsers](parsers.md) | Vendor-specific CLI and eAPI output parsers |
| [Playbooks](playbooks.md) | Ansible remediation playbook generation |
| [Report](report.md) | HTML/PDF report generation, health dashboard, email delivery, scheduling |
| [Ansible](ansible.md) | Dynamic inventory script and Ansible modules |
| [Inventory](inventory.md) | Subnet scanner and device discovery |

---

## Quick Reference

### `netops.core`

| Module | Key Classes / Functions |
|--------|------------------------|
| [`netops.core.connection`](core.md#netopscoreconnection) | `Transport`, `AuthMethod`, `ConnectionParams`, `DeviceConnection` |
| [`netops.core.inventory`](core.md#netopscoreinventory) | `Device`, `Inventory` |
| [`netops.core.vault`](core.md#netopscorevault) | `CredentialVault`, `main()` |

### `netops.check`

| Module | Key Functions |
|--------|--------------|
| [`netops.check.health`](check.md#netopscheckhealth) | `run_health_check()`, `build_health_report()` |
| [`netops.check.bgp`](check.md#netopscheckbgp) | `check_bgp_peers()`, `build_bgp_report()` |
| [`netops.check.interfaces`](check.md#netopscheckinterfaces) | `check_interfaces()` |
| [`netops.check.vlan`](check.md#netopscheckvlan) | `audit_vlans()`, `build_vlan_report()` |
| [`netops.check.arista`](check.md#netopscheckarista) | `run_health_check()`, `build_eos_health_report()` |
| [`netops.check.cisco`](check.md#netopscheckcisco) | `run_cisco_health_check()`, `build_cisco_health_report()` |
| [`netops.check.juniper`](check.md#netopscheckjuniper) | `run_health_check()`, `build_junos_health_report()` |
| [`netops.check.paloalto`](check.md#netopscheckpaloalto) | `run_health_check()`, `run_policy_audit()` |

### `netops.change`

| Module | Key Classes / Functions |
|--------|------------------------|
| [`netops.change.diff`](change.md#netopschangediff) | `ConfigStyle`, `DiffResult`, `diff_configs()`, `format_semantic()` |
| [`netops.change.plan`](change.md#netopschangeplan) | `ChangePlan`, `ChangeStep`, `generate_plan()`, `apply_plan()` |
| [`netops.change.push`](change.md#netopschangepush) | `ChangeRecord`, `run_push()`, `load_changelog()` |
| [`netops.change.rollback`](change.md#netopschangerollback) | `RollbackRecord`, `run_rollback_push()`, `load_audit_log()` |

### `netops.collect`

| Module | Key Functions |
|--------|--------------|
| [`netops.collect.config`](collect.md#netopscollectconfig) | `collect_config()` |
| [`netops.collect.backup`](collect.md#netopscollectbackup) | `run_backup()`, `generate_diff()`, `git_commit()` |

### `netops.parsers`

| Module | Vendor / Format |
|--------|----------------|
| [`netops.parsers.arista`](parsers.md#netopsparsersarista) | Arista EOS eAPI JSON + CLI text |
| [`netops.parsers.bgp`](parsers.md#netopsparsersbgp) | Cisco IOS/XE/XR BGP CLI |
| [`netops.parsers.brocade`](parsers.md#netopsparsersbrocade) | Brocade FastIron / FOS CLI |
| [`netops.parsers.cisco`](parsers.md#netopsparserscisco) | Cisco IOS/IOS-XE CLI |
| [`netops.parsers.health`](parsers.md#netopsparsershealth) | CPU/memory/errors/logs (multi-vendor) |
| [`netops.parsers.juniper`](parsers.md#netopsparsersjuniper) | Juniper JunOS CLI |
| [`netops.parsers.nokia_sros`](parsers.md#netopsparsersnokia_sros) | Nokia SR-OS CLI |
| [`netops.parsers.paloalto`](parsers.md#netopsparserspaloalto) | Palo Alto PAN-OS CLI |
| [`netops.parsers.vlan`](parsers.md#netopsparsersvlan) | Cisco VLAN CLI |

### `netops.playbooks`

| Module | Key Classes / Functions |
|--------|------------------------|
| [`netops.playbooks.generator`](playbooks.md#netopsplaybooksgenerator) | `FailureType`, `GeneratedPlaybook`, `generate_playbook()`, `generate_playbooks_from_report()` |
| [`netops.playbooks.templates.remediation`](playbooks.md#netopsplaybookstemplatesremediation) | `RemediationTemplate`, `REMEDIATION_TEMPLATES`, `get_template()` |

### `netops.report`

| Module | Key Classes / Functions |
|--------|------------------------|
| [`netops.report.generator`](report.md#netopsreportgenerator) | `ReportGenerator`, `generate_report()` |
| [`netops.report.health_dashboard`](report.md#netopsreporthealth_dashboard) | `aggregate_dashboard()`, `format_table()`, `render_html()` |
| [`netops.report.mailer`](report.md#netopsreportmailer) | `ReportMailer` |
| [`netops.report.scheduler`](report.md#netopsreportscheduler) | `ReportScheduler`, `ScheduledReport` |

### `netops.ansible`

| Module | Key Functions |
|--------|--------------|
| [`netops.ansible.dynamic_inventory`](ansible.md#netopsansibledynamic_inventory) | `build_inventory()`, `get_host_vars()` |
| [`netops.ansible.modules.netops_command`](ansible.md#netopsansiblemodulesnetops_command) | `run_module()` |
| [`netops.ansible.modules.netops_facts`](ansible.md#netopsansiblemodulesnetops_facts) | `run_module()` |

### `netops.inventory`

| Module | Key Classes / Functions |
|--------|------------------------|
| [`netops.inventory.scan`](inventory.md#netopsinventoryscan) | `ScanResult`, `scan_subnet()`, `ping_sweep()`, `deep_enrich()`, `merge_inventory()` |

---

## See Also

- [User Guides](../guides/README.md) — step-by-step guides for common workflows
- [Examples](https://github.com/plures/netops-toolkit/tree/main/examples) — runnable example scripts
