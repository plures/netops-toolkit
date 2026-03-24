# netops_backup

Ansible role that retrieves the running configuration of network devices and
saves it to the Ansible control node with a configurable retention policy.

## Requirements

- `netops-toolkit[ansible]` installed on the control node.
- The `netops_command` Ansible module must be on the module path (bundled with
  this toolkit under `netops/ansible/modules/`).

## Role Variables

| Variable | Default | Description |
|---|---|---|
| `netops_backup_dir` | `/var/backups/netops` | Root directory for backup files. |
| `netops_backup_retention` | `10` | Number of backup copies to keep per device. |
| `netops_backup_timestamp_format` | `%Y%m%d_%H%M%S` | Timestamp appended to each filename. |
| `netops_backup_username` | `ansible_user` | Device login username. |
| `netops_backup_password` | `ansible_password` | Device login password. |
| `netops_backup_port` | `ansible_port` (22) | SSH port. |
| `netops_backup_vendor` | `ansible_network_os` (cisco_ios) | Vendor string for netops. |
| `netops_backup_ignore_unreachable` | `false` | Skip rather than fail on unreachable devices. |
| `netops_backup_file_prefix` | `""` | Optional filename prefix. |

## Dependencies

None.

## Example Playbook

```yaml
- name: Backup all network devices
  hosts: network_devices
  gather_facts: false
  roles:
    - role: netops_backup
      vars:
        netops_backup_dir: /opt/config_backups
        netops_backup_retention: 30
```

## Molecule Tests

```bash
cd netops/ansible/roles/netops_backup
molecule test
```

## License

MIT
