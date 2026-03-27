# `netops.core` — Core Modules

Connection management, device inventory, and credential vault.

---

## `netops.core.connection`

Unified device connection manager. Handles SSH, SSH2, and Telnet connections
with a single interface. Uses Netmiko under the hood for vendor-aware CLI
interaction.

::: netops.core.connection

---

## `netops.core.inventory`

Device inventory management. Simple YAML/JSON inventory that maps to Ansible
inventory format.

**CLI usage:**
```
python -m netops.core.inventory export --format ansible --output ansible_inventory.yaml
python -m netops.core.inventory export --format ansible-json --output ansible_inventory.json
```

::: netops.core.inventory

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

**CLI usage:**
```
python -m netops.core.vault init [--vault VAULT_FILE]
python -m netops.core.vault set --device HOSTNAME --user USER [--vault VAULT_FILE]
python -m netops.core.vault set --group  GROUP   --user USER [--vault VAULT_FILE]
python -m netops.core.vault set --default        --user USER [--vault VAULT_FILE]
python -m netops.core.vault get --device HOSTNAME            [--vault VAULT_FILE]
python -m netops.core.vault delete --device HOSTNAME         [--vault VAULT_FILE]
```

::: netops.core.vault
