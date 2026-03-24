# netops_health

Ansible role that runs configurable health checks (CPU, memory, interfaces,
BGP, OSPF) against network devices using the netops-toolkit modules and
optionally fails the play when a CRITICAL threshold is breached.

## Requirements

- `netops-toolkit[ansible]` installed on the control node.
- The `netops_facts` Ansible module must be on the module path (bundled under
  `netops/ansible/modules/`).

## Role Variables

| Variable | Default | Description |
|---|---|---|
| `netops_health_check_cpu` | `true` | Enable CPU utilisation check. |
| `netops_health_check_memory` | `true` | Enable memory utilisation check. |
| `netops_health_check_interfaces` | `true` | Enable interface state check. |
| `netops_health_check_bgp` | `true` | Enable BGP session check. |
| `netops_health_check_ospf` | `false` | Enable OSPF neighbour check. |
| `netops_health_cpu_critical` | `90` | CPU % threshold for CRITICAL. |
| `netops_health_memory_critical` | `90` | Memory % threshold for CRITICAL. |
| `netops_health_fail_on_critical` | `true` | Fail the play on any CRITICAL finding. |
| `netops_health_report_path` | `""` | Write JSON report here (empty = skip). |
| `netops_health_username` | `ansible_user` | Device login username. |
| `netops_health_password` | `ansible_password` | Device login password. |
| `netops_health_port` | `ansible_port` (22) | SSH port. |
| `netops_health_vendor` | `ansible_network_os` (cisco_ios) | Vendor string. |

## Dependencies

None.

## Example Playbook

```yaml
- name: Health-check all routers
  hosts: routers
  gather_facts: false
  roles:
    - role: netops_health
      vars:
        netops_health_check_ospf: true
        netops_health_fail_on_critical: true
        netops_health_report_path: /tmp/health_reports
```

## Molecule Tests

```bash
cd netops/ansible/roles/netops_health
molecule test
```

## License

MIT
