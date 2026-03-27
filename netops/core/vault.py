"""Credential vault — encrypted storage for device credentials.

Stores per-device, per-group, and default credentials in an AES-256-GCM
encrypted YAML file.  The encryption key is derived from a master password
using PBKDF2-HMAC-SHA256.

Lookup order for :meth:`CredentialVault.get_credentials`:

1. Environment variables (``NETOPS_CRED_<HOSTNAME>_USER`` / ``_PASS`` /
   ``_ENABLE``)
2. Device-specific entry
3. First matching group entry
4. Default entry

Environment variable names are normalised: hyphens and dots in the hostname
are replaced with underscores and the whole name is upper-cased, e.g.
``core-rtr-01`` → ``NETOPS_CRED_CORE_RTR_01_USER``.

CLI usage::

    python -m netops.core.vault init [--vault VAULT_FILE]
    python -m netops.core.vault set --device HOSTNAME --user USER [--vault VAULT_FILE]
    python -m netops.core.vault set --group  GROUP   --user USER [--vault VAULT_FILE]
    python -m netops.core.vault set --default        --user USER [--vault VAULT_FILE]
    python -m netops.core.vault get --device HOSTNAME            [--vault VAULT_FILE]
    python -m netops.core.vault delete --device HOSTNAME         [--vault VAULT_FILE]
    python -m netops.core.vault delete --group  GROUP            [--vault VAULT_FILE]
    python -m netops.core.vault delete --default                 [--vault VAULT_FILE]

The master password may be provided via the ``NETOPS_VAULT_PASSWORD``
environment variable to avoid interactive prompts (useful in CI pipelines).
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 600_000
_SALT_BYTES = 32
_NONCE_BYTES = 12
_KEY_BYTES = 32  # AES-256


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from *password* and *salt* via PBKDF2-HMAC-SHA256."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode())


def _encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt *plaintext*.  Returns ``(nonce, ciphertext+tag)``."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ct


def _decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """AES-256-GCM decrypt.  Raises :class:`ValueError` on authentication failure."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError("Wrong password or corrupted vault") from exc


# ---------------------------------------------------------------------------
# Vault file format helpers
# ---------------------------------------------------------------------------


def _encode(data: bytes) -> str:
    """Base64-encode *data* and return it as a UTF-8 string."""
    return base64.b64encode(data).decode()


def _decode(s: str) -> bytes:
    """Decode a base64-encoded string back to raw bytes."""
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# CredentialVault
# ---------------------------------------------------------------------------


class CredentialVault:
    """Encrypted credential store backed by a YAML file.

    Parameters
    ----------
    vault_path:
        Path to the vault file (will be created by :meth:`init`).

    """

    DEFAULT_VAULT_PATH = Path.home() / ".netops" / "vault.yaml"

    def __init__(self, vault_path: str | Path | None = None) -> None:
        """Initialise with an optional vault file path (defaults to ``~/.netops/vault.yaml``)."""
        self._path = Path(vault_path) if vault_path else self.DEFAULT_VAULT_PATH
        self._key: bytes | None = None
        # In-memory store: {"devices": {...}, "groups": {...}, "defaults": {...}}
        self._data: dict = {"devices": {}, "groups": {}, "defaults": {}}

    # ------------------------------------------------------------------
    # Vault lifecycle
    # ------------------------------------------------------------------

    def init(self, password: str) -> None:
        """Create a new, empty vault protected by *password*.

        Raises :class:`FileExistsError` if the vault already exists.
        """
        if self._path.exists():
            raise FileExistsError(f"Vault already exists: {self._path}")

        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._key = _derive_key(password, os.urandom(_SALT_BYTES))
        self._data = {"devices": {}, "groups": {}, "defaults": {}}
        self._write(password)
        logger.info("Vault initialised at %s", self._path)

    def unlock(self, password: str) -> None:
        """Decrypt and load the vault.  Must be called before any read/write operation."""
        if not self._path.exists():
            raise FileNotFoundError(f"Vault not found: {self._path}")

        try:
            import yaml
        except ImportError:  # pragma: no cover
            raise ImportError("pyyaml is required: pip install pyyaml")

        raw = yaml.safe_load(self._path.read_text())
        _check_vault_header(raw)

        salt = _decode(raw["salt"])
        nonce = _decode(raw["nonce"])
        ciphertext = _decode(raw["ciphertext"])

        self._key = _derive_key(password, salt)
        plaintext = _decrypt(nonce, ciphertext, self._key)
        self._data = json.loads(plaintext)
        logger.debug("Vault unlocked: %s", self._path)

    def save(self, password: str) -> None:
        """Re-derive the key from *password*, then encrypt and persist the vault.

        Call this after :meth:`unlock` to persist any changes made in memory.
        """
        if not self._path.exists() and not self._key:
            raise RuntimeError("Vault has not been initialised or unlocked")
        self._write(password)

    # ------------------------------------------------------------------
    # Credential management
    # ------------------------------------------------------------------

    def set_device(
        self,
        hostname: str,
        username: str,
        password: str,
        enable_password: str | None = None,
    ) -> None:
        """Store credentials for a specific device *hostname*."""
        _require_unlocked(self._key)
        entry: dict = {"username": username, "password": password}
        if enable_password is not None:
            entry["enable_password"] = enable_password
        self._data["devices"][hostname] = entry

    def set_group(
        self,
        group: str,
        username: str,
        password: str,
        enable_password: str | None = None,
    ) -> None:
        """Store credentials for all devices in *group*."""
        _require_unlocked(self._key)
        entry: dict = {"username": username, "password": password}
        if enable_password is not None:
            entry["enable_password"] = enable_password
        self._data["groups"][group] = entry

    def set_default(
        self,
        username: str,
        password: str,
        enable_password: str | None = None,
    ) -> None:
        """Store fallback credentials used when no device or group entry matches."""
        _require_unlocked(self._key)
        entry: dict = {"username": username, "password": password}
        if enable_password is not None:
            entry["enable_password"] = enable_password
        self._data["defaults"] = entry

    def delete_device(self, hostname: str) -> bool:
        """Remove the device entry for *hostname*.  Returns ``True`` if it existed."""
        _require_unlocked(self._key)
        return self._data["devices"].pop(hostname, None) is not None

    def delete_group(self, group: str) -> bool:
        """Remove the group entry for *group*.  Returns ``True`` if it existed."""
        _require_unlocked(self._key)
        return self._data["groups"].pop(group, None) is not None

    def delete_default(self) -> bool:
        """Clear the default credentials entry.  Returns ``True`` if it existed."""
        _require_unlocked(self._key)
        had = bool(self._data.get("defaults"))
        self._data["defaults"] = {}
        return had

    # ------------------------------------------------------------------
    # Credential lookup
    # ------------------------------------------------------------------

    def get_credentials(
        self,
        hostname: str,
        groups: list[str] | None = None,
    ) -> dict | None:
        """Return a credentials dict for *hostname*, or ``None`` if nothing matches.

        Lookup priority:

        1. Environment variables (``NETOPS_CRED_<HOSTNAME>_USER``, ``_PASS``,
           ``_ENABLE``)
        2. Device-specific vault entry
        3. First matching group vault entry
        4. Default vault entry

        The returned dict always has ``username`` and ``password`` keys; it
        optionally contains ``enable_password``.
        """
        env_creds = _env_credentials(hostname)
        if env_creds:
            return env_creds

        _require_unlocked(self._key)

        if hostname in self._data.get("devices", {}):
            return dict(self._data["devices"][hostname])

        for group in groups or []:
            if group in self._data.get("groups", {}):
                return dict(self._data["groups"][group])

        defaults = self._data.get("defaults", {})
        if defaults:
            return dict(defaults)

        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write(self, password: str) -> None:
        """Serialise, encrypt, and write the vault file."""
        try:
            import yaml
        except ImportError:  # pragma: no cover
            raise ImportError("pyyaml is required: pip install pyyaml")

        salt = os.urandom(_SALT_BYTES)
        key = _derive_key(password, salt)
        plaintext = json.dumps(self._data, separators=(",", ":")).encode()
        nonce, ciphertext = _encrypt(plaintext, key)

        vault_doc = {
            "version": 1,
            "salt": _encode(salt),
            "nonce": _encode(nonce),
            "ciphertext": _encode(ciphertext),
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(yaml.dump(vault_doc, default_flow_style=False))
        # Keep the in-memory key consistent with the new salt
        self._key = key


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _check_vault_header(raw: object) -> None:
    """Raise ``ValueError`` if *raw* is not a valid vault file structure."""
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise ValueError("Unrecognised vault format")
    for field in ("salt", "nonce", "ciphertext"):
        if field not in raw:
            raise ValueError(f"Vault file missing field: {field}")


def _require_unlocked(key: bytes | None) -> None:
    """Raise ``RuntimeError`` if *key* is ``None`` (vault not yet unlocked)."""
    if key is None:
        raise RuntimeError("Vault is locked — call unlock() first")


def _env_key_prefix(hostname: str) -> str:
    """Normalise *hostname* to an environment variable prefix component."""
    return re.sub(r"[^A-Z0-9]", "_", hostname.upper())


def _env_credentials(hostname: str) -> dict | None:
    """Return credentials sourced purely from environment variables, or ``None``."""
    prefix = f"NETOPS_CRED_{_env_key_prefix(hostname)}"
    user = os.environ.get(f"{prefix}_USER")
    passwd = os.environ.get(f"{prefix}_PASS")
    if user and passwd:
        creds: dict = {"username": user, "password": passwd}
        enable = os.environ.get(f"{prefix}_ENABLE")
        if enable:
            creds["enable_password"] = enable
        return creds
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _prompt_password(prompt: str = "Vault password: ") -> str:
    """Read master password from env var or interactive prompt."""
    pw = os.environ.get("NETOPS_VAULT_PASSWORD")
    if pw:
        return pw
    return getpass.getpass(prompt)


def _prompt_credential_password(prompt: str = "Device password: ") -> str:
    """Prompt for a device credential password with confirmation."""
    while True:
        pw = getpass.getpass(prompt)
        confirm = getpass.getpass("Confirm password: ")
        if pw == confirm:
            return pw
        print("Passwords do not match, try again.")


def _cli_init(args: argparse.Namespace) -> int:
    """CLI handler for the ``init`` sub-command — create a new vault."""
    vault = CredentialVault(args.vault)
    try:
        pw = _prompt_password("New vault password: ")
        vault.init(pw)
        print(f"Vault initialised: {vault._path}")
    except FileExistsError as exc:
        print(f"Error: {exc}")
        return 1
    return 0


def _cli_set(args: argparse.Namespace) -> int:
    """CLI handler for the ``set`` sub-command — store credentials in the vault."""
    vault = CredentialVault(args.vault)
    master_pw = _prompt_password()
    try:
        vault.unlock(master_pw)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1

    cred_user = args.user
    cred_pass = _prompt_credential_password()
    enable_pw: str | None = None
    if args.enable:
        enable_pw = getpass.getpass("Enable password (blank to skip): ") or None

    if args.device:
        vault.set_device(args.device, cred_user, cred_pass, enable_pw)
        label = f"device '{args.device}'"
    elif args.group:
        vault.set_group(args.group, cred_user, cred_pass, enable_pw)
        label = f"group '{args.group}'"
    else:
        vault.set_default(cred_user, cred_pass, enable_pw)
        label = "defaults"

    vault.save(master_pw)
    print(f"Credentials stored for {label}.")
    return 0


def _cli_get(args: argparse.Namespace) -> int:
    """CLI handler for the ``get`` sub-command — retrieve and display credentials."""
    vault = CredentialVault(args.vault)
    master_pw = _prompt_password()
    try:
        vault.unlock(master_pw)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1

    groups = args.groups.split(",") if args.groups else []
    creds = vault.get_credentials(args.device, groups)
    if creds is None:
        print(f"No credentials found for device '{args.device}'.")
        return 1

    print(f"username:       {creds['username']}")
    print(f"password:       {'*' * len(creds['password'])}")
    if creds.get("enable_password"):
        print(f"enable_password: {'*' * len(creds['enable_password'])}")
    return 0


def _cli_delete(args: argparse.Namespace) -> int:
    """CLI handler for the ``delete`` sub-command — remove credentials from the vault."""
    vault = CredentialVault(args.vault)
    master_pw = _prompt_password()
    try:
        vault.unlock(master_pw)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1

    if args.device:
        removed = vault.delete_device(args.device)
        label = f"device '{args.device}'"
    elif args.group:
        removed = vault.delete_group(args.group)
        label = f"group '{args.group}'"
    else:
        removed = vault.delete_default()
        label = "defaults"

    if not removed:
        print(f"No entry found for {label}.")
        return 1

    vault.save(master_pw)
    print(f"Credentials deleted for {label}.")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for the vault CLI."""
    parser = argparse.ArgumentParser(
        prog="python -m netops.core.vault",
        description="Manage encrypted credential vault.",
    )
    parser.add_argument(
        "--vault",
        metavar="FILE",
        default=None,
        help="Path to vault file (default: ~/.netops/vault.yaml)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # init
    sub.add_parser("init", help="Initialise a new vault")

    # set
    p_set = sub.add_parser("set", help="Add or update credentials")
    target = p_set.add_mutually_exclusive_group(required=True)
    target.add_argument("--device", metavar="HOSTNAME", help="Target device hostname")
    target.add_argument("--group", metavar="GROUP", help="Target device group")
    target.add_argument("--default", dest="default", action="store_true", help="Set default creds")
    p_set.add_argument("--user", required=True, metavar="USERNAME", help="Username to store")
    p_set.add_argument(
        "--enable",
        action="store_true",
        help="Also prompt for an enable / privileged-exec password",
    )

    # get
    p_get = sub.add_parser("get", help="Show credentials for a device (passwords masked)")
    p_get.add_argument("--device", required=True, metavar="HOSTNAME")
    p_get.add_argument(
        "--groups",
        metavar="GROUP1,GROUP2",
        default="",
        help="Comma-separated list of groups the device belongs to",
    )

    # delete
    p_del = sub.add_parser("delete", help="Remove a credentials entry")
    del_target = p_del.add_mutually_exclusive_group(required=True)
    del_target.add_argument("--device", metavar="HOSTNAME")
    del_target.add_argument("--group", metavar="GROUP")
    del_target.add_argument("--default", dest="default", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the credential vault management tool."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    handlers = {
        "init": _cli_init,
        "set": _cli_set,
        "get": _cli_get,
        "delete": _cli_delete,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    import sys

    sys.exit(main())
