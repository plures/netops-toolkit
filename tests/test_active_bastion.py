"""Tests for workstation-wide bastion routing."""

from __future__ import annotations

import socket
import threading
from unittest.mock import MagicMock, patch

from netops.core.bastion import _socks_authenticate, _socks_connect
from netops.core.connection import ConnectionParams, DeviceConnection, JumpHostParams
from netops.inventory.scan import scan_subnet_through_active_bastion


def test_active_bastion_socket_is_given_to_netmiko() -> None:
    active_socket = MagicMock()
    netmiko_connection = MagicMock()
    with patch("netmiko.ConnectHandler", return_value=netmiko_connection) as connect_handler:
        with patch(
            "netops.core.bastion.open_active_bastion_socket", return_value=active_socket
        ) as open_socket:
            connection = DeviceConnection(ConnectionParams(host="10.0.0.5", username="netops"))
            connection.connect()
            connection.disconnect()

    open_socket.assert_called_once_with("10.0.0.5", 22, 30)
    assert connect_handler.call_args.kwargs["sock"] is active_socket
    assert "use_keys" not in connect_handler.call_args.kwargs
    assert "allow_agent" not in connect_handler.call_args.kwargs
    active_socket.close.assert_called_once()


def test_explicit_legacy_jump_host_does_not_use_active_bastion() -> None:
    jump = JumpHostParams(host="legacy-bastion", username="netops", password="secret")
    with patch("netmiko.ConnectHandler", return_value=MagicMock()):
        with patch("paramiko.SSHClient") as ssh_client:
            ssh_client.return_value.get_transport.return_value.open_channel.return_value = MagicMock()
            with patch("netops.core.bastion.open_active_bastion_socket") as open_socket:
                connection = DeviceConnection(
                    ConnectionParams(host="10.0.0.5", username="netops", jump_host=jump)
                )
                connection.connect()
                connection.disconnect()

    open_socket.assert_not_called()


def test_socks_authentication_and_connect_request() -> None:
    client, server = socket.socketpair()
    observed: dict[str, bytes] = {}

    def server_side() -> None:
        observed["methods"] = server.recv(3)
        server.sendall(b"\x05\x02")
        observed["authentication"] = server.recv(42)
        server.sendall(b"\x01\x00")
        observed["connect"] = server.recv(10)
        server.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

    worker = threading.Thread(target=server_side)
    worker.start()
    try:
        _socks_authenticate(client, "x" * 32)
        _socks_connect(client, "192.0.2.9", 22)
    finally:
        client.close()
        server.close()
        worker.join(timeout=2)

    assert observed["methods"] == b"\x05\x01\x02"
    assert observed["authentication"] == b"\x01\x06netops\x20" + (b"x" * 32)
    assert observed["connect"] == b"\x05\x01\x00\x01\xc0\x00\x02\x09\x00\x16"


def test_subnet_discovery_probes_ssh_through_active_bastion() -> None:
    first_socket = MagicMock()
    with patch("netops.core.bastion.active_bastion", return_value=MagicMock()):
        with patch(
            "netops.core.bastion.open_active_bastion_socket",
            side_effect=[first_socket, OSError("connection refused")],
        ) as open_socket:
            results = scan_subnet_through_active_bastion("192.0.2.0/30", max_workers=1)

    assert [result.host for result in results] == ["192.0.2.1"]
    assert open_socket.call_args_list[0].args == ("192.0.2.1", 22, 3)
    first_socket.close.assert_called_once()
