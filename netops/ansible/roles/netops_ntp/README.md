# netops_ntp

Ansible role that standardises NTP configuration on network devices: adds
servers, removes unwanted ones, optionally configures authentication and
timezone, and validates that at least one peer is synchronised.

## Requirements

- `netops-toolkit[ansible]` installed on the control node.
- The `netops_command` module must be on the module path.

## Role Variables

| Variable | Default | Description |
|---|---|---|
| `netops_ntp_servers` | `[]` | NTP server addresses to configure. **Required.** |
| `netops_ntp_servers_absent` | `[]` | Addresses to remove from the device. |
| `netops_ntp_source_interface` | `""` | Source interface (empty = device default). |
| `netops_ntp_auth_key_id` | `""` | Auth key ID (empty = no auth). |
| `netops_ntp_auth_key_type` | `md5` | Key hash type (`md5`/`sha1`). |
| `netops_ntp_auth_key_value` | `""` | Auth key secret. |
| `netops_ntp_validate_sync` | `true` | Wait and check for NTP sync after config. |
| `netops_ntp_sync_timeout` | `60` | Seconds to wait for sync. |
| `netops_ntp_timezone` | `""` | Timezone string (empty = skip). |
| `netops_ntp_username` | `ansible_user` | Device login username. |
| `netops_ntp_password` | `ansible_password` | Device login password. |
| `netops_ntp_port` | `ansible_port` (22) | SSH port. |
| `netops_ntp_vendor` | `ansible_network_os` (cisco_ios) | Vendor string. |

## Dependencies

None.

## Example Playbook

```yaml
- name: Standardise NTP across all devices
  hosts: all
  gather_facts: false
  roles:
    - role: netops_ntp
      vars:
        netops_ntp_servers:
          - 192.168.1.10
          - 192.168.1.11
        netops_ntp_servers_absent:
          - 10.0.0.5   # old NTP server to remove
        netops_ntp_source_interface: Loopback0
        netops_ntp_timezone: "UTC"
        netops_ntp_validate_sync: true
```

### With NTP Authentication

```yaml
- name: NTP with MD5 authentication
  hosts: routers
  gather_facts: false
  roles:
    - role: netops_ntp
      vars:
        netops_ntp_servers:
          - 10.0.0.1
        netops_ntp_auth_key_id: "1"
        netops_ntp_auth_key_type: md5
        netops_ntp_auth_key_value: "{{ vault_ntp_key }}"
```

## Molecule Tests

```bash
cd netops/ansible/roles/netops_ntp
molecule test
```

## License

MIT
