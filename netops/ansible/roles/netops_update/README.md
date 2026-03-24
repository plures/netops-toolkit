# netops_update

Ansible role that orchestrates a network OS upgrade with pre/post health
validation and automatic rollback on failure.

## Requirements

- `netops-toolkit[ansible]` installed on the control node.
- The `netops_command` module must be on the module path.
- The `netops_health` role must be accessible (bundled in this toolkit).

## Role Variables

| Variable | Default | Description |
|---|---|---|
| `netops_update_image` | `""` | Target image filename. |
| `netops_update_image_dest` | `flash:/` | Destination path on the device. |
| `netops_update_image_src` | `""` | Source URL/path (empty = skip transfer). |
| `netops_update_dry_run` | `true` | Skip actual upgrade — only validate. |
| `netops_update_reload_wait` | `300` | Seconds to wait after reload. |
| `netops_update_pre_checks` | `true` | Run health check before upgrade. |
| `netops_update_post_checks` | `true` | Run health check after upgrade. |
| `netops_update_cpu_critical` | `90` | CPU % threshold for pre/post checks. |
| `netops_update_memory_critical` | `90` | Memory % threshold for pre/post checks. |
| `netops_update_rollback_on_failure` | `true` | Roll back if post-checks fail. |
| `netops_update_username` | `ansible_user` | Device login username. |
| `netops_update_password` | `ansible_password` | Device login password. |
| `netops_update_port` | `ansible_port` (22) | SSH port. |
| `netops_update_vendor` | `ansible_network_os` (cisco_ios) | Vendor string. |

## Dependencies

- `netops_health` (included in this toolkit).

## Example Playbook

```yaml
- name: Upgrade IOS-XE on distribution switches
  hosts: distribution_switches
  gather_facts: false
  serial: 1
  roles:
    - role: netops_update
      vars:
        netops_update_dry_run: false
        netops_update_image: cat9k_iosxe.17.09.05.SPA.bin
        netops_update_image_src: tftp://10.0.0.10/images/cat9k_iosxe.17.09.05.SPA.bin
        netops_update_rollback_on_failure: true
```

## Molecule Tests

```bash
cd netops/ansible/roles/netops_update
molecule test
```

## License

MIT
