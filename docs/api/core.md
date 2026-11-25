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

The companion export path reuses the same private hydrated-data constructor as
`Inventory.from_file`, preserving defaults, device overrides and explicit group
registration without reopening a path or consulting credentials.

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

The global `--vault FILE` option must appear before the vault subcommand, for
example `python -m netops.core.vault --vault secrets.yaml set --default --user admin`.

### Companion credential boundary

The [private companion credential resolver](ansible-credentials.md) preserves
the native vault lookup seam and adds operation-scoped, memory-only delivery
under [host admission](ansible-admission.md). It does not change native
connection constructors, export passwords into inventory, or turn a vault
unlock into dispatch authority. [Protected artifacts and owned state](ansible-artifacts.md)
describe the separate persistence boundary; credentials and consent must not be
reconstructed from persisted receipts. [Dependency readiness](dependencies.md)
does not unlock the vault or certify a controller or route.

## `netops.core.bastion`

The active-bastion CLI is exposed through the dispatcher:

```
netops bastion connect --host BASTION --username USER [--password-stdin]
netops bastion status
netops bastion disconnect
```

See [Active Bastion Routing](../guides/active-bastion.md) for the operational
model and protocol limitations.

State publication uses POSIX owner-only mode on POSIX, but Windows must use
actual owner-only protected DACLs. The Windows writer reuses the existing
no-reparse, handle-pinned storage primitives and requires an already protected
owner-only parent; it never repairs an existing directory ACL. A new exclusive
temporary file is protected before bearer-token bytes are written, flushed,
and renamed by its verified handle. An unsafe parent fails without publishing
the token. Windows `stat().st_mode` is not proof of mode `0600`.
The Windows default now creates only a new protected `.netops-bastion` parent;
existing defaults and explicit parents must pass real protection proof. Existing
legacy `.netops/active-bastion.json` selection is preserved and read through the
same protected parent/single-link handle checks before token use. Unsafe legacy
state fails closed instead of permitting direct routing. Log creation/truncation
also uses a proved native handle; no log/state ACL is repaired or token put in argv.
See the [native state boundary](https://github.com/plures/netops-toolkit/blob/main/documentation/core/core-architecture.md).

::: netops.core.vault
