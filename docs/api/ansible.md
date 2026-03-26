# `netops.ansible` — Ansible Integration

Dynamic inventory and Ansible modules for netops-backed automation.

---

## `netops.ansible.dynamic_inventory`

Ansible dynamic inventory script backed by a netops inventory file.

**Usage as a standalone script:**
```
python -m netops.ansible.dynamic_inventory --list
python -m netops.ansible.dynamic_inventory --host router1
python -m netops.ansible.dynamic_inventory --list --inventory /path/to/inv.yaml
python -m netops.ansible.dynamic_inventory --list --vault ~/.netops/vault.yaml
python -m netops.ansible.dynamic_inventory --list --cache-ttl 600
python -m netops.ansible.dynamic_inventory --list --no-cache
python -m netops.ansible.dynamic_inventory --list --refresh-cache
```

**As an Ansible inventory source:**
```
ansible-playbook -i path/to/dynamic_inventory.py site.yml
```

**Environment variables:**
- `NETOPS_INVENTORY` — path to the inventory file
- `NETOPS_VAULT` — path to the vault file
- `NETOPS_INVENTORY_CACHE` — path to the JSON cache file

**Auto-generated groups** (in addition to explicit device groups):
- `vendor_<vendor>` — e.g. `vendor_cisco_ios`, `vendor_nokia_sros`
- `site_<site>` — e.g. `site_dc1`
- `role_<role>` — e.g. `role_spine`, `role_leaf`, `role_core`

**Cache:** Results are cached in a JSON file (default:
`~/.netops/inventory_cache.json`) with a configurable TTL (default 300 s).
Pass `--no-cache` to skip caching entirely or `--refresh-cache` to force a
rebuild.

The `_meta.hostvars` structure is always populated so Ansible does not need
to issue individual `--host` calls.

### Functions

#### `build_inventory(inventory_path: str, vault_path: Optional[str] = None, cache_path: Optional[str] = None, cache_ttl: int = _DEFAULT_CACHE_TTL, no_cache: bool = False, refresh_cache: bool = False) -> dict`
Return an Ansible JSON inventory dict from a netops inventory file.

**Parameters:**
- `inventory_path` — path to the netops YAML/JSON inventory file
- `vault_path` — optional path to a `CredentialVault` file; when provided and `NETOPS_VAULT_PASSWORD` is set, per-device credentials are injected into the host vars
- `cache_path` — path for the JSON cache file; defaults to `~/.netops/inventory_cache.json` (or `$NETOPS_INVENTORY_CACHE`)
- `cache_ttl` — cache time-to-live in seconds (default: 300)
- `no_cache` — when `True`, skip reading from and writing to the cache
- `refresh_cache` — when `True`, ignore the existing cache and always rebuild

#### `get_host_vars(inventory_path: str, hostname: str, vault_path: Optional[str] = None, cache_path: Optional[str] = None, cache_ttl: int = _DEFAULT_CACHE_TTL, no_cache: bool = False, refresh_cache: bool = False) -> dict`
Return variables for a single host.

#### `main(argv: list[str] | None = None) -> int`
CLI entry point for the Ansible dynamic inventory script.

---

## `netops.ansible.modules.netops_command`

**Ansible module: `netops_command`**

Thin Ansible wrapper around netops utilities. Sends one or more commands to
a network device using the Netmiko connection backend and returns the raw
output.

**Module options:**
- `host` — IP address or FQDN of the target device
- `vendor` — device vendor/OS type (Netmiko `device_type`)
- `username` — SSH username
- `password` — SSH password
- `port` — TCP port (default: `22`)
- `commands` — list of CLI commands to execute
- `wait_for` — optional list of output strings to wait for before returning (passed to Netmiko `expect_string`)

**Return values:**
- `output` — list of raw command output strings, one per command
- `stdout` — concatenated output of all commands

**Example playbook usage:**
```yaml
- name: Run show commands
  netops_command:
    host: "{{ ansible_host }}"
    vendor: cisco_ios
    username: admin
    password: "{{ vault_password }}"
    commands:
      - show version
      - show interfaces status

- name: Capture BGP summary
  netops_command:
    host: "{{ ansible_host }}"
    vendor: cisco_ios
    username: admin
    password: "{{ vault_password }}"
    commands:
      - show bgp summary
  register: bgp_raw

- name: Parse BGP output
  set_fact:
    bgp_peers: "{{ bgp_raw.output[0] | netops_parse_bgp }}"
```

### Functions

#### `run_module() -> None`
Entry point called by Ansible.

---

## `netops.ansible.modules.netops_facts`

**Ansible module: `netops_facts`**

Collect structured device facts from a network device using netops utilities
and return them as Ansible facts (`ansible_facts`).

**Module options:**
- `host` — IP address or FQDN of the target device; defaults to `{{ inventory_hostname }}` when omitted
- `vendor` — device vendor/OS type (e.g. `cisco_ios`, `nokia_sros`); maps to Netmiko `device_type`
- `username` — SSH username
- `password` — SSH password (mark `no_log: true` in your playbook)
- `port` — TCP port (default: `22`)
- `transport` — `ssh` (default) or `telnet`
- `gather` — list of fact categories to collect; supported values: `health`, `interfaces`, `bgp`, `vlans`, `all` (default: `all`)
- `inventory` — path to a netops inventory YAML/JSON file; when provided, device connection details are read from it (`host` must still name the inventory hostname)

**Return values:**

`ansible_facts.netops` — dict with a key per gathered category, e.g.:
```yaml
ansible_facts:
  netops:
    health:
      cpu_percent: 12
      memory_percent: 45
    interfaces:
      - name: GigabitEthernet0/0
        status: up
        protocol: up
```

**Example playbook usage:**
```yaml
- name: Collect device facts
  netops_facts:
    host: "{{ ansible_host }}"
    vendor: cisco_ios
    username: admin
    password: "{{ vault_password }}"
    gather:
      - health
      - interfaces

- name: Show CPU usage
  debug:
    var: ansible_facts.netops.health.cpu_percent
```

### Functions

#### `run_module() -> None`
Entry point called by Ansible.
