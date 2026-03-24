# netops_acl

Ansible role that deploys Access Control Lists to network devices with an
optional diff preview and a safety guard against accidental ACL removal.

## Requirements

- `netops-toolkit[ansible]` installed on the control node.
- The `netops_command` module must be on the module path.

## Role Variables

| Variable | Default | Description |
|---|---|---|
| `netops_acl_list` | `[]` | List of ACL definitions (name + rules). **Required.** |
| `netops_acl_diff_only` | `false` | Print current ACL state — do not apply. |
| `netops_acl_abort_on_empty_diff` | `true` | Abort if post-deploy ACL is empty. |
| `netops_acl_interface` | `""` | Bind ACL to this interface (optional). |
| `netops_acl_direction` | `in` | Direction for interface binding (`in`/`out`). |
| `netops_acl_username` | `ansible_user` | Device login username. |
| `netops_acl_password` | `ansible_password` | Device login password. |
| `netops_acl_port` | `ansible_port` (22) | SSH port. |
| `netops_acl_vendor` | `ansible_network_os` (cisco_ios) | Vendor string. |

## ACL Definition Format

```yaml
netops_acl_list:
  - name: MGMT-IN
    rules:
      - "10 permit tcp 10.0.0.0 0.0.0.255 any eq 22"
      - "20 deny ip any any log"
  - name: MGMT-OUT
    rules:
      - "10 permit ip any any"
```

## Dependencies

None.

## Example Playbook

```yaml
- name: Deploy management ACLs
  hosts: core_routers
  gather_facts: false
  roles:
    - role: netops_acl
      vars:
        netops_acl_list:
          - name: MGMT-IN
            rules:
              - "10 permit tcp 10.0.0.0 0.0.0.255 any eq 22"
              - "20 deny ip any any log"
        netops_acl_interface: GigabitEthernet0/0
        netops_acl_direction: in
```

### Preview Only (diff mode)

```yaml
- name: Preview ACL changes
  hosts: core_routers
  gather_facts: false
  roles:
    - role: netops_acl
      vars:
        netops_acl_diff_only: true
        netops_acl_list:
          - name: MGMT-IN
            rules:
              - "10 permit tcp 10.0.0.0 0.0.0.255 any eq 22"
```

## Molecule Tests

```bash
cd netops/ansible/roles/netops_acl
molecule test
```

## License

MIT
