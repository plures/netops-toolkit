"""
Unit tests for netops.core.vault.

No real files are written unless tmp_path is used — all crypto operations
run against in-memory state to keep the suite fast.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from netops.core.vault import (
    CredentialVault,
    _decode,
    _decrypt,
    _derive_key,
    _encode,
    _encrypt,
    _env_credentials,
    _env_key_prefix,
)


# ---------------------------------------------------------------------------
# Low-level crypto helpers
# ---------------------------------------------------------------------------


class TestDeriveKey:
    def test_returns_32_bytes(self):
        key = _derive_key("password", b"a" * 32)
        assert len(key) == 32

    def test_same_password_same_salt_deterministic(self):
        salt = b"b" * 32
        assert _derive_key("pw", salt) == _derive_key("pw", salt)

    def test_different_password_different_key(self):
        salt = b"c" * 32
        assert _derive_key("pw1", salt) != _derive_key("pw2", salt)

    def test_different_salt_different_key(self):
        assert _derive_key("pw", b"d" * 32) != _derive_key("pw", b"e" * 32)


class TestEncryptDecrypt:
    def test_round_trip(self):
        key = _derive_key("secret", b"s" * 32)
        nonce, ct = _encrypt(b"hello world", key)
        assert _decrypt(nonce, ct, key) == b"hello world"

    def test_wrong_key_raises_value_error(self):
        key1 = _derive_key("right", b"s" * 32)
        key2 = _derive_key("wrong", b"s" * 32)
        nonce, ct = _encrypt(b"data", key1)
        with pytest.raises(ValueError, match="Wrong password or corrupted vault"):
            _decrypt(nonce, ct, key2)

    def test_nonce_randomised(self):
        key = _derive_key("pw", b"n" * 32)
        nonce1, _ = _encrypt(b"x", key)
        nonce2, _ = _encrypt(b"x", key)
        assert nonce1 != nonce2

    def test_empty_plaintext(self):
        key = _derive_key("pw", b"e" * 32)
        nonce, ct = _encrypt(b"", key)
        assert _decrypt(nonce, ct, key) == b""


class TestEncodeDecodeHelpers:
    def test_encode_decode_round_trip(self):
        data = os.urandom(64)
        assert _decode(_encode(data)) == data


# ---------------------------------------------------------------------------
# Environment variable helpers
# ---------------------------------------------------------------------------


class TestEnvKeyPrefix:
    def test_plain_hostname(self):
        assert _env_key_prefix("router01") == "ROUTER01"

    def test_hyphens_become_underscores(self):
        assert _env_key_prefix("core-rtr-01") == "CORE_RTR_01"

    def test_dots_become_underscores(self):
        assert _env_key_prefix("core.rtr.01") == "CORE_RTR_01"

    def test_mixed(self):
        assert _env_key_prefix("Site-A.router") == "SITE_A_ROUTER"


class TestEnvCredentials:
    def test_returns_none_when_no_vars_set(self):
        with patch.dict(os.environ, {}, clear=False):
            assert _env_credentials("core-rtr-01") is None

    def test_returns_creds_when_both_vars_set(self):
        env = {
            "NETOPS_CRED_CORE_RTR_01_USER": "admin",
            "NETOPS_CRED_CORE_RTR_01_PASS": "secret",
        }
        with patch.dict(os.environ, env):
            creds = _env_credentials("core-rtr-01")
        assert creds == {"username": "admin", "password": "secret"}

    def test_returns_none_when_only_user_set(self):
        env = {"NETOPS_CRED_HOST_USER": "admin"}
        with patch.dict(os.environ, env):
            assert _env_credentials("host") is None

    def test_includes_enable_password_when_set(self):
        env = {
            "NETOPS_CRED_RTR_USER": "op",
            "NETOPS_CRED_RTR_PASS": "pass",
            "NETOPS_CRED_RTR_ENABLE": "enable",
        }
        with patch.dict(os.environ, env):
            creds = _env_credentials("rtr")
        assert creds["enable_password"] == "enable"

    def test_no_enable_password_key_when_env_not_set(self):
        env = {
            "NETOPS_CRED_RTR_USER": "op",
            "NETOPS_CRED_RTR_PASS": "pass",
        }
        with patch.dict(os.environ, env):
            creds = _env_credentials("rtr")
        assert "enable_password" not in creds


# ---------------------------------------------------------------------------
# CredentialVault — unit-level (no disk)
# ---------------------------------------------------------------------------


class TestCredentialVaultInit:
    def test_init_creates_file(self, tmp_path):
        vault_file = tmp_path / "vault.yaml"
        vault = CredentialVault(vault_file)
        vault.init("masterpass")
        assert vault_file.exists()

    def test_init_twice_raises_file_exists_error(self, tmp_path):
        vault_file = tmp_path / "vault.yaml"
        CredentialVault(vault_file).init("pw")
        with pytest.raises(FileExistsError):
            CredentialVault(vault_file).init("pw")

    def test_init_creates_parent_directory(self, tmp_path):
        vault_file = tmp_path / "nested" / "dir" / "vault.yaml"
        CredentialVault(vault_file).init("pw")
        assert vault_file.exists()


class TestCredentialVaultUnlock:
    def test_wrong_password_raises_value_error(self, tmp_path):
        vf = tmp_path / "vault.yaml"
        CredentialVault(vf).init("correct")
        with pytest.raises(ValueError):
            CredentialVault(vf).unlock("wrong")

    def test_missing_vault_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            CredentialVault(tmp_path / "missing.yaml").unlock("pw")

    def test_correct_password_succeeds(self, tmp_path):
        vf = tmp_path / "vault.yaml"
        CredentialVault(vf).init("pw")
        vault = CredentialVault(vf)
        vault.unlock("pw")  # should not raise


class TestCredentialVaultLocked:
    """Operations that require an unlocked vault must raise RuntimeError."""

    def test_set_device_requires_unlock(self, tmp_path):
        vf = tmp_path / "vault.yaml"
        CredentialVault(vf).init("pw")
        vault = CredentialVault(vf)  # NOT unlocked
        with pytest.raises(RuntimeError, match="locked"):
            vault.set_device("host", "u", "p")

    def test_get_credentials_requires_unlock(self, tmp_path):
        vf = tmp_path / "vault.yaml"
        CredentialVault(vf).init("pw")
        vault = CredentialVault(vf)
        with pytest.raises(RuntimeError, match="locked"):
            vault.get_credentials("host")


class TestCredentialVaultSetGet:
    @pytest.fixture()
    def vault(self, tmp_path):
        vf = tmp_path / "vault.yaml"
        v = CredentialVault(vf)
        v.init("master")
        v.unlock("master")
        return v

    def test_set_and_get_device(self, vault):
        vault.set_device("core-rtr-01", "admin", "secret")
        creds = vault.get_credentials("core-rtr-01")
        assert creds == {"username": "admin", "password": "secret"}

    def test_set_device_with_enable_password(self, vault):
        vault.set_device("rtr", "admin", "secret", enable_password="enable123")
        creds = vault.get_credentials("rtr")
        assert creds["enable_password"] == "enable123"

    def test_device_not_found_falls_back_to_group(self, vault):
        vault.set_group("core", "group_user", "group_pass")
        creds = vault.get_credentials("unknown-host", groups=["core"])
        assert creds["username"] == "group_user"

    def test_device_not_found_no_group_falls_back_to_default(self, vault):
        vault.set_default("default_user", "default_pass")
        creds = vault.get_credentials("unknown-host")
        assert creds["username"] == "default_user"

    def test_device_takes_priority_over_group(self, vault):
        vault.set_device("rtr-01", "device_user", "device_pass")
        vault.set_group("core", "group_user", "group_pass")
        creds = vault.get_credentials("rtr-01", groups=["core"])
        assert creds["username"] == "device_user"

    def test_group_takes_priority_over_default(self, vault):
        vault.set_group("edge", "group_user", "group_pass")
        vault.set_default("default_user", "default_pass")
        creds = vault.get_credentials("unknown-host", groups=["edge"])
        assert creds["username"] == "group_user"

    def test_first_matching_group_wins(self, vault):
        vault.set_group("group-a", "user_a", "pass_a")
        vault.set_group("group-b", "user_b", "pass_b")
        creds = vault.get_credentials("host", groups=["group-a", "group-b"])
        assert creds["username"] == "user_a"

    def test_no_match_returns_none(self, vault):
        assert vault.get_credentials("unknown-host") is None

    def test_env_overrides_vault(self, vault, monkeypatch):
        vault.set_device("rtr", "vault_user", "vault_pass")
        monkeypatch.setenv("NETOPS_CRED_RTR_USER", "env_user")
        monkeypatch.setenv("NETOPS_CRED_RTR_PASS", "env_pass")
        creds = vault.get_credentials("rtr")
        assert creds["username"] == "env_user"
        assert creds["password"] == "env_pass"


class TestCredentialVaultPersistence:
    def test_credentials_survive_save_and_reload(self, tmp_path):
        vf = tmp_path / "vault.yaml"

        v1 = CredentialVault(vf)
        v1.init("master")
        v1.unlock("master")
        v1.set_device("rtr-01", "admin", "secret123")
        v1.save("master")

        v2 = CredentialVault(vf)
        v2.unlock("master")
        creds = v2.get_credentials("rtr-01")
        assert creds == {"username": "admin", "password": "secret123"}

    def test_multiple_entries_persist(self, tmp_path):
        vf = tmp_path / "vault.yaml"

        v1 = CredentialVault(vf)
        v1.init("master")
        v1.unlock("master")
        v1.set_device("rtr-01", "admin", "pass1")
        v1.set_group("core", "group_user", "group_pass")
        v1.set_default("ro_user", "ro_pass")
        v1.save("master")

        v2 = CredentialVault(vf)
        v2.unlock("master")
        assert v2.get_credentials("rtr-01")["username"] == "admin"
        assert v2.get_credentials("new-host", groups=["core"])["username"] == "group_user"
        assert v2.get_credentials("other")["username"] == "ro_user"


class TestCredentialVaultDelete:
    @pytest.fixture()
    def vault(self, tmp_path):
        vf = tmp_path / "vault.yaml"
        v = CredentialVault(vf)
        v.init("master")
        v.unlock("master")
        return v

    def test_delete_device_removes_entry(self, vault):
        vault.set_device("rtr", "u", "p")
        assert vault.delete_device("rtr") is True
        assert vault.get_credentials("rtr") is None

    def test_delete_device_returns_false_when_not_found(self, vault):
        assert vault.delete_device("nonexistent") is False

    def test_delete_group_removes_entry(self, vault):
        vault.set_group("g", "u", "p")
        assert vault.delete_group("g") is True
        assert vault.get_credentials("x", groups=["g"]) is None

    def test_delete_default_clears_default(self, vault):
        vault.set_default("u", "p")
        assert vault.delete_default() is True
        assert vault.get_credentials("x") is None

    def test_delete_default_returns_false_when_empty(self, vault):
        assert vault.delete_default() is False


class TestVaultFileFormat:
    """Verify the on-disk format is valid YAML with required fields."""

    def test_vault_file_is_valid_yaml(self, tmp_path):
        import yaml

        vf = tmp_path / "vault.yaml"
        CredentialVault(vf).init("pw")
        data = yaml.safe_load(vf.read_text())
        assert data["version"] == 1
        assert "salt" in data
        assert "nonce" in data
        assert "ciphertext" in data

    def test_vault_file_contains_no_plaintext_passwords(self, tmp_path):
        vf = tmp_path / "vault.yaml"
        v = CredentialVault(vf)
        v.init("master")
        v.unlock("master")
        v.set_device("rtr", "admin", "super_secret_password")
        v.save("master")
        raw = vf.read_text()
        assert "super_secret_password" not in raw
        assert "admin" not in raw
