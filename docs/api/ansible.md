# `netops.ansible` — Ansible Integration

Dynamic inventory script, custom modules, and Ansible roles for
netops-toolkit integration.

---

## `netops.ansible.dynamic_inventory`

Ansible dynamic inventory provider.

Builds an Ansible-compatible inventory from the netops YAML inventory file,
auto-generating `vendor_*`, `site_*`, and `role_*` groups. Supports
CredentialVault integration and file-based caching.

**CLI usage:**
```
ansible-playbook -i netops/ansible/dynamic_inventory.py site.yml
python netops/ansible/dynamic_inventory.py --list
python netops/ansible/dynamic_inventory.py --host core-rtr-01
python netops/ansible/dynamic_inventory.py --refresh-cache
```

::: netops.ansible.dynamic_inventory

---

## `netops.ansible.modules.netops_command`

Ansible module: run arbitrary commands on network devices via netops transport.

::: netops.ansible.modules.netops_command

---

## `netops.ansible.modules.netops_facts`

Ansible module: gather structured facts from network devices.

Returns `ansible_facts.netops` with categories:
`health`, `interfaces`, `bgp`, `vlans`.

**Module options:**
- `gather_subset` — `all` | `health` | `interfaces` | `bgp` | `vlans`
  (default: `all`)

::: netops.ansible.modules.netops_facts
