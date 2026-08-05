"""Tests for SSH jump-host / bastion tunneling in netops.core.connection.

The jump box is used purely as network transport (an SSH bastion): a Paramiko
``direct-tcpip`` channel is opened through it and handed to Netmiko's
``ConnectHandler`` via the ``sock=`` kwarg. No netops-toolkit code ever runs
on the jump host. See docs/guides/jump-host-tunnel.md.

No real jump box or switch is required - the Paramiko/Netmiko layers are
mocked at the seam (``paramiko.SSHClient`` and ``netmiko.ConnectHandler``),
while the real ``DeviceConnection``/``resolve_jump_host_params`` code paths
execute for real.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from netops.core.connection import (
    AuthMethod,
    ConnectionParams,
    DeviceConnection,
    JumpHostParams,
    Transport,
    resolve_jump_host_params,
)


class TestJumpHostParams:
    def test_defaults(self):
        jh = JumpHostParams(host="bastion.example.com")
        assert jh.port == 22
        assert jh.auth_method == AuthMethod.PASSWORD
        assert jh.timeout == 30


class TestResolveJumpHostParams:
    def test_returns_none_when_no_jump_host(self):
        assert resolve_jump_host_params(None) is None
        assert resolve_jump_host_params("") is None

    def test_builds_params_from_explicit_fields(self):
        jh = resolve_jump_host_params(
            "bastion.example.com", jump_port=2222, jump_username="netops"
        )
        assert jh is not None
        assert jh.host == "bastion.example.com"
        assert jh.port == 2222
        assert jh.username == "netops"
        assert jh.auth_method == AuthMethod.PASSWORD

    def test_key_file_selects_key_auth_method(self):
        jh = resolve_jump_host_params("bastion.example.com", jump_key_file="/keys/id_rsa")
        assert jh is not None
        assert jh.key_file == "/keys/id_rsa"
        assert jh.auth_method == AuthMethod.KEY

    def test_vault_password_becomes_key_passphrase_for_key_auth(self):
        vault = MagicMock()
        vault.get_credentials.return_value = {"username": "vaulted", "password": "keyphrase"}
        jh = resolve_jump_host_params(
            "bastion.example.com", jump_key_file="/keys/id_rsa", vault=vault
        )
        assert jh is not None
        assert jh.password is None
        assert jh.key_passphrase == "keyphrase"
        assert jh.auth_method == AuthMethod.KEY_PASSWORD

    def test_vault_supplies_credentials_when_available(self):
        vault = MagicMock()
        vault.get_credentials.return_value = {"username": "vaulted", "password": "s3cr3t"}
        jh = resolve_jump_host_params("bastion.example.com", vault=vault)
        assert jh is not None
        assert jh.username == "vaulted"
        assert jh.password == "s3cr3t"
        vault.get_credentials.assert_called_once_with("bastion.example.com")

    def test_explicit_username_overrides_vault(self):
        vault = MagicMock()
        vault.get_credentials.return_value = {"username": "vaulted", "password": "s3cr3t"}
        jh = resolve_jump_host_params(
            "bastion.example.com", jump_username="explicit", vault=vault
        )
        assert jh is not None
        assert jh.username == "explicit"


class TestDeviceConnectionWithoutJumpHost:
    """Regression: behavior with no jump_host set must be identical to today."""

    @patch("netmiko.ConnectHandler")
    def test_no_jump_host_does_not_open_paramiko_channel(self, mock_connect_handler):
        mock_connect_handler.return_value = MagicMock()
        params = ConnectionParams(host="10.0.0.1", username="admin", password="pw")
        conn = DeviceConnection(params)

        with patch("paramiko.SSHClient") as mock_ssh_client:
            conn.connect()
            mock_ssh_client.assert_not_called()

        called_kwargs = mock_connect_handler.call_args.kwargs
        assert "sock" not in called_kwargs
        assert called_kwargs["host"] == "10.0.0.1"
        assert conn._jump_client is None

    @patch("netmiko.ConnectHandler")
    def test_disconnect_without_jump_host_does_not_touch_jump_client(self, mock_connect_handler):
        mock_connection = MagicMock()
        mock_connect_handler.return_value = mock_connection
        params = ConnectionParams(host="10.0.0.1", username="admin", password="pw")
        conn = DeviceConnection(params)
        conn.connect()
        conn.disconnect()
        mock_connection.disconnect.assert_called_once()


class TestDeviceConnectionWithJumpHost:
    def _fake_paramiko_client(self):
        client = MagicMock()
        transport = MagicMock()
        channel = MagicMock(name="direct-tcpip-channel")
        transport.open_channel.return_value = channel
        client.get_transport.return_value = transport
        return client, transport, channel

    @patch("netmiko.ConnectHandler")
    def test_tunnel_opened_with_correct_target_and_sock_passed_to_netmiko(
        self, mock_connect_handler
    ):
        mock_connect_handler.return_value = MagicMock()
        client, transport, channel = self._fake_paramiko_client()

        jump = JumpHostParams(host="bastion.example.com", username="netops", password="jumppw")
        params = ConnectionParams(
            host="10.0.0.5",
            username="admin",
            password="devicepw",
            port=22,
            jump_host=jump,
        )
        conn = DeviceConnection(params)

        with patch("paramiko.SSHClient", return_value=client) as mock_ssh_client_cls:
            with patch("paramiko.AutoAddPolicy"):
                conn.connect()

        mock_ssh_client_cls.assert_called_once()
        client.connect.assert_called_once()
        connect_call_kwargs = client.connect.call_args.kwargs
        assert connect_call_kwargs["hostname"] == "bastion.example.com"
        assert connect_call_kwargs["port"] == 22
        assert connect_call_kwargs["username"] == "netops"
        assert connect_call_kwargs["password"] == "jumppw"

        transport.open_channel.assert_called_once()
        open_channel_kwargs = transport.open_channel.call_args.kwargs
        assert open_channel_kwargs["dest_addr"] == ("10.0.0.5", 22)

        netmiko_kwargs = mock_connect_handler.call_args.kwargs
        assert netmiko_kwargs["sock"] is channel
        assert netmiko_kwargs["host"] == "10.0.0.5"
        # sock-based connections must not also request key/agent auth toggles
        assert "use_keys" not in netmiko_kwargs
        assert "allow_agent" not in netmiko_kwargs

        assert conn._jump_client is client

    @patch("netmiko.ConnectHandler")
    def test_key_auth_jump_host_passes_key_filename_and_passphrase(self, mock_connect_handler):
        mock_connect_handler.return_value = MagicMock()
        client, _, _ = self._fake_paramiko_client()

        jump = JumpHostParams(
            host="bastion.example.com",
            username="netops",
            key_file="/keys/id_rsa",
            key_passphrase="phrase",
            auth_method=AuthMethod.KEY_PASSWORD,
        )
        params = ConnectionParams(host="10.0.0.5", username="admin", jump_host=jump)
        conn = DeviceConnection(params)

        with patch("paramiko.SSHClient", return_value=client):
            with patch("paramiko.AutoAddPolicy"):
                conn.connect()

        connect_kwargs = client.connect.call_args.kwargs
        assert connect_kwargs["key_filename"] == "/keys/id_rsa"
        assert connect_kwargs["passphrase"] == "phrase"
        assert "password" not in connect_kwargs

    @patch("netmiko.ConnectHandler")
    def test_disconnect_closes_both_device_connection_and_jump_client(
        self, mock_connect_handler
    ):
        mock_connection = MagicMock()
        mock_connect_handler.return_value = mock_connection
        client, _, _ = self._fake_paramiko_client()

        jump = JumpHostParams(host="bastion.example.com", username="netops", password="jumppw")
        params = ConnectionParams(host="10.0.0.5", username="admin", jump_host=jump)
        conn = DeviceConnection(params)

        with patch("paramiko.SSHClient", return_value=client):
            with patch("paramiko.AutoAddPolicy"):
                conn.connect()
        conn.disconnect()

        mock_connection.disconnect.assert_called_once()
        client.close.assert_called_once()
        assert conn._jump_client is None

    def test_telnet_transport_with_jump_host_raises(self):
        jump = JumpHostParams(host="bastion.example.com", username="netops", password="jumppw")
        params = ConnectionParams(
            host="10.0.0.5", username="admin", transport=Transport.TELNET, jump_host=jump
        )
        conn = DeviceConnection(params)
        with pytest.raises(ValueError, match="only supported for SSH"):
            conn.connect()

    @patch("netmiko.ConnectHandler")
    def test_transport_none_raises_runtime_error(self, mock_connect_handler):
        client = MagicMock()
        client.get_transport.return_value = None
        jump = JumpHostParams(host="bastion.example.com", username="netops", password="jumppw")
        params = ConnectionParams(host="10.0.0.5", username="admin", jump_host=jump)
        conn = DeviceConnection(params)
        with patch("paramiko.SSHClient", return_value=client):
            with patch("paramiko.AutoAddPolicy"):
                with pytest.raises(RuntimeError, match="Failed to establish transport"):
                    conn.connect()


class TestInventoryJumpHostFields:
    def test_device_jump_host_fields_default_absent(self, tmp_path):
        from netops.core.inventory import Inventory

        inv_file = tmp_path / "inv.yaml"
        inv_file.write_text(
            "devices:\n"
            "  sw1:\n"
            "    host: 10.0.0.1\n"
            "    vendor: cisco_ios\n"
        )
        inv = Inventory.from_file(inv_file)
        dev = inv.get("sw1")
        assert dev.jump_host is None
        assert dev.jump_port == 22

    def test_jump_host_from_inventory_maps_all_auth_fields(self):
        from netops.core.connection import jump_host_from_inventory
        from netops.core.inventory import Device

        device = Device(
            hostname="sw1",
            host="10.0.0.1",
            vendor="cisco_ios",
            jump_host="bastion.example.com",
            jump_username="netops",
            jump_key_file="/keys/id_rsa",
            jump_key_passphrase="phrase",
        )
        jh = jump_host_from_inventory(device)
        assert jh is not None
        assert jh.host == "bastion.example.com"
        assert jh.auth_method == AuthMethod.KEY_PASSWORD
        assert jh.key_passphrase == "phrase"

    def test_device_jump_host_fields_from_yaml(self, tmp_path):
        from netops.core.inventory import Inventory

        inv_file = tmp_path / "inv.yaml"
        inv_file.write_text(
            "defaults:\n"
            "  jump_host: bastion.example.com\n"
            "  jump_username: netops\n"
            "devices:\n"
            "  sw1:\n"
            "    host: 10.0.0.1\n"
            "    vendor: cisco_ios\n"
            "  sw2:\n"
            "    host: 10.0.0.2\n"
            "    vendor: cisco_ios\n"
            "    jump_host: other-bastion.example.com\n"
            "    jump_port: 2222\n"
            "    jump_key_file: /keys/id_rsa\n"
            "    jump_key_passphrase: phrase\n"
        )
        inv = Inventory.from_file(inv_file)
        sw1 = inv.get("sw1")
        sw2 = inv.get("sw2")
        assert sw1.jump_host == "bastion.example.com"
        assert sw1.jump_username == "netops"
        assert sw1.jump_port == 22
        assert sw2.jump_host == "other-bastion.example.com"
        assert sw2.jump_port == 2222
        assert sw2.jump_key_file == "/keys/id_rsa"
        assert sw2.jump_key_passphrase == "phrase"
