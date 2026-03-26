# `netops.core` — Core Modules

Connection management, device inventory, and credential vault.

---

## `netops.core.connection`

Unified device connection manager. Handles SSH, SSH2, and Telnet connections
with a single interface. Uses Netmiko under the hood for vendor-aware CLI
interaction.

### Classes

#### `Transport`

Supported connection transports for device communication.

**Values:**
- `SSH` — `"ssh"`
- `SSH2` — `"ssh2"` (legacy SSH implementations)
- `TELNET` — `"telnet"`

---

#### `AuthMethod`

Authentication mechanisms accepted when connecting to a device.

**Values:**
- `PASSWORD` — password authentication
- `KEY` — public-key authentication
- `KEY_PASSWORD` — key + passphrase

---

#### `ConnectionParams`

Everything needed to connect to a device.

**Fields:**
- `host: str` — IP address or hostname
- `username: str | None` — login username
- `password: Optional[str]` — login password
- `transport: Transport` — connection transport (default: `Transport.SSH`)
- `auth_method: AuthMethod` — authentication method (default: `AuthMethod.PASSWORD`)
- `port: Optional[int]` — TCP port; `None` = auto (22 for SSH, 23 for Telnet)
- `key_file: Optional[str]` — path to SSH private key file
- `device_type: str` — Netmiko device type (default: `"autodetect"`)
- `timeout: int` — connection timeout in seconds (default: `30`)
- `enable_password: Optional[str]` — enable/privilege-mode password
- `extras: dict` — vendor-specific override parameters

**Properties:**

##### `effective_port`
Return the resolved TCP port (explicit override, or 23 for Telnet, 22 otherwise).

---

#### `DeviceConnection`

Unified connection to a network device.

Supports context-manager usage:

```python
params = ConnectionParams(host="10.0.0.1", username="admin", password="secret")
with DeviceConnection(params) as conn:
    output = conn.send("show version")
    config = conn.send("show running-config")
```

**Methods:**

##### `connect()`
Establish connection using configured transport.

##### `disconnect()`
Close the connection.

##### `send(command: str, expect_string: str | None = None) -> str`
Send a command and return output.

##### `send_config(commands: list[str]) -> str`
Send configuration commands.

---

## `netops.core.inventory`

Device inventory management. Simple YAML/JSON inventory that maps to Ansible
inventory format.

**CLI usage:**
```
python -m netops.core.inventory export --format ansible --output ansible_inventory.yaml
python -m netops.core.inventory export --format ansible-json --output ansible_inventory.json
```

### Classes

#### `Device`

A network device in the inventory.

**Fields:**
- `hostname: str` — device hostname (inventory key)
- `host: str` — IP address or resolvable DNS name
- `vendor: str` — Netmiko device type (e.g. `"cisco_ios"`, `"nokia_sros"`)
- `transport: str` — connection transport (default: `"ssh"`)
- `port: Optional[int]` — TCP port override
- `username: Optional[str]` — login username
- `password: Optional[str]` — login password
- `enable_password: Optional[str]` — enable password
- `key_file: Optional[str]` — path to SSH private key
- `groups: list[str]` — list of inventory groups this device belongs to
- `tags: dict[str, str]` — arbitrary key/value metadata tags
- `site: Optional[str]` — site/location label
- `role: Optional[str]` — device role (e.g. `"core"`, `"spine"`, `"leaf"`)

**Methods:**

##### `to_dict() -> dict`
Return a dict representation of the device, omitting `None` fields.

---

#### `Inventory`

Device inventory with group support.

Supports YAML/JSON file loading, group-based filtering, tag-based filtering,
and export to Ansible inventory format.

**Methods:**

##### `add(device: Device) -> None`
Add *device* to the inventory, registering it under all its groups.

##### `get(hostname: str) -> Optional[Device]`
Look up a device by hostname; returns `None` if not found.

##### `filter(group: str | None = None, vendor: str | None = None, role: str | None = None, site: str | None = None, tag: tuple | None = None) -> list[Device]`
Filter devices by criteria.

##### `from_file(path: str | Path) -> 'Inventory'`  *(classmethod)*
Load inventory from YAML or JSON file.

##### `to_ansible() -> dict`
Export as Ansible inventory format (JSON-compatible dict). The returned
structure follows the
[Ansible JSON inventory spec](https://docs.ansible.com/ansible/latest/dev_guide/developing_inventory.html).

##### `to_ansible_yaml() -> str`
Export as Ansible inventory in YAML format.

##### `to_ansible_json() -> str`
Export as Ansible inventory in JSON format.

##### `to_file(path: str | Path, format: str = 'yaml') -> None`
Save inventory to file.

### Functions

#### `main() -> None`
CLI entry point: `python -m netops.core.inventory export ...`

---

## `netops.core.vault`

Credential vault — encrypted storage for device credentials.

Stores per-device, per-group, and default credentials in an AES-256-GCM
encrypted YAML file. The encryption key is derived from a master password
using PBKDF2-HMAC-SHA256.

**Lookup order for `CredentialVault.get_credentials`:**
1. Environment variables (`NETOPS_CRED_<HOSTNAME>_USER` / `_PASS` / `_ENABLE`)
2. Device-specific entry
3. First matching group entry
4. Default entry

Environment variable names are normalised: hyphens and dots in the hostname
are replaced with underscores and the whole name is upper-cased (e.g.
`core-rtr-01` → `NETOPS_CRED_CORE_RTR_01_USER`).

**CLI usage:**
```
python -m netops.core.vault init [--vault VAULT_FILE]
python -m netops.core.vault set --device HOSTNAME --user USER [--vault VAULT_FILE]
python -m netops.core.vault set --group  GROUP   --user USER [--vault VAULT_FILE]
python -m netops.core.vault set --default        --user USER [--vault VAULT_FILE]
python -m netops.core.vault get --device HOSTNAME            [--vault VAULT_FILE]
python -m netops.core.vault delete --device HOSTNAME         [--vault VAULT_FILE]
python -m netops.core.vault delete --group  GROUP            [--vault VAULT_FILE]
python -m netops.core.vault delete --default                 [--vault VAULT_FILE]
```

The master password may be provided via `NETOPS_VAULT_PASSWORD` to avoid
interactive prompts (useful in CI pipelines).

### Classes

#### `CredentialVault`

Encrypted credential store backed by a YAML file.

**Parameters:**
- `vault_path` — path to the vault file (created by `init`).

**Methods:**

##### `init(password: str) -> None`
Create a new, empty vault protected by *password*. Raises `FileExistsError`
if the vault already exists.

##### `unlock(password: str) -> None`
Decrypt and load the vault. Must be called before any read/write operation.

##### `save(password: str) -> None`
Re-derive the key from *password*, then encrypt and persist the vault. Call
this after `unlock` to persist any changes made in memory.

##### `set_device(hostname: str, username: str, password: str, enable_password: Optional[str] = None) -> None`
Store credentials for a specific device *hostname*.

##### `set_group(group: str, username: str, password: str, enable_password: Optional[str] = None) -> None`
Store credentials for all devices in *group*.

##### `set_default(username: str, password: str, enable_password: Optional[str] = None) -> None`
Store fallback credentials used when no device or group entry matches.

##### `delete_device(hostname: str) -> bool`
Remove the device entry for *hostname*. Returns `True` if it existed.

##### `delete_group(group: str) -> bool`
Remove the group entry for *group*. Returns `True` if it existed.

##### `delete_default() -> bool`
Clear the default credentials entry. Returns `True` if it existed.

##### `get_credentials(hostname: str, groups: Optional[list[str]] = None) -> Optional[dict]`
Return a credentials dict for *hostname*, or `None` if nothing matches.

Lookup priority:
1. Environment variables (`NETOPS_CRED_<HOSTNAME>_USER`, `_PASS`, `_ENABLE`)
2. Device-specific vault entry
3. First matching group vault entry
4. Default vault entry

The returned dict always has `username` and `password` keys; it optionally
contains `enable_password`.

### Functions

#### `main(argv: list[str] | None = None) -> int`
CLI entry point for the credential vault management tool.
