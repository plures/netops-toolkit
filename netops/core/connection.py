"""Unified device connection manager.

Handles SSH, SSH2, and Telnet connections with a single interface.
Uses Netmiko under the hood for vendor-aware CLI interaction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from types import TracebackType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netmiko.base_connection import BaseConnection

logger = logging.getLogger(__name__)


class Transport(Enum):
    """Supported connection transports for device communication."""

    SSH = "ssh"
    SSH2 = "ssh2"  # Legacy SSH implementations
    TELNET = "telnet"


class AuthMethod(Enum):
    """Authentication mechanisms accepted when connecting to a device."""

    PASSWORD = "password"
    KEY = "key"
    KEY_PASSWORD = "key_password"  # Key + passphrase


@dataclass
class JumpHostParams:
    """Connection parameters for an SSH jump box / bastion used purely as network transport.

    The jump host is never sent netops-toolkit CLI commands - it is only used to
    open an SSH ``direct-tcpip`` channel that Netmiko's ``ConnectHandler`` treats
    as a pre-established socket (via the ``sock=`` kwarg) when talking to the
    real target device. See ``docs/guides/jump-host-tunnel.md``.
    """

    host: str
    username: str | None = None
    password: str | None = None
    auth_method: AuthMethod = AuthMethod.PASSWORD
    port: int = 22
    key_file: str | None = None
    key_passphrase: str | None = None
    timeout: int = 30


@dataclass
class ConnectionParams:
    """Everything needed to connect to a device."""

    host: str
    username: str | None = None
    password: str | None = None
    transport: Transport = Transport.SSH
    auth_method: AuthMethod = AuthMethod.PASSWORD
    port: int | None = None  # None = auto (22/23)
    key_file: str | None = None
    device_type: str = "autodetect"  # Netmiko device_type
    timeout: int = 30
    enable_password: str | None = None
    # Optional SSH jump-host / bastion tunnel used purely as network transport
    jump_host: JumpHostParams | None = None
    # Vendor-specific overrides
    extras: dict = field(default_factory=dict)

    @property
    def effective_port(self) -> int:
        """Return the resolved TCP port (explicit override, or 23 for Telnet, 22 otherwise)."""
        if self.port:
            return self.port
        return 23 if self.transport == Transport.TELNET else 22


class DeviceConnection:
    """Unified connection to a network device.

    Usage:
        params = ConnectionParams(host="10.0.0.1", username="admin", password="secret")
        with DeviceConnection(params) as conn:
            output = conn.send("show version")
            config = conn.send("show running-config")
    """

    def __init__(self, params: ConnectionParams) -> None:
        """Initialise the connection manager with the given connection parameters."""
        self.params = params
        self._connection: BaseConnection | None = None
        self._jump_client: object | None = None  # paramiko.SSHClient, kept alive for channel lifetime

    def __enter__(self) -> DeviceConnection:
        """Connect on entering the context manager block."""
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Disconnect when leaving the context manager block."""
        self.disconnect()

    def connect(self) -> None:
        """Establish connection using configured transport."""
        try:
            from netmiko import ConnectHandler
        except ImportError:
            raise ImportError("netmiko is required: pip install netmiko")

        device_params = {
            "device_type": self._resolve_device_type(),
            "host": self.params.host,
            "username": self.params.username,
            "port": self.params.effective_port,
            "timeout": self.params.timeout,
        }

        if self.params.password:
            device_params["password"] = self.params.password
        if self.params.enable_password:
            device_params["secret"] = self.params.enable_password
        if self.params.key_file:
            device_params["key_file"] = self.params.key_file
        else:
            # Disable key-based auth when no key file is specified
            # Prevents netmiko from searching for ~/.ssh/id_rsa (fails on Windows)
            device_params["use_keys"] = False
            device_params["allow_agent"] = False

        # Telnet override
        if self.params.transport == Transport.TELNET:
            device_params["device_type"] = self._telnet_device_type()

        if self.params.jump_host:
            if self.params.transport == Transport.TELNET:
                raise ValueError("Jump-host tunneling is only supported for SSH transports")
            device_params["sock"] = self._open_jump_channel()
            # Netmiko's paramiko backend refuses to also open its own socket
            # when a pre-established `sock` is supplied; drop conflicting keys.
            device_params.pop("use_keys", None)
            device_params.pop("allow_agent", None)

        logger.info(f"Connecting to {self.params.host} via {self.params.transport.value}")
        try:
            self._connection = ConnectHandler(**device_params)
            if self.params.enable_password:
                self._connection.enable()
        except Exception:
            # A direct-tcpip channel is owned by its SSHClient. If Netmiko
            # rejects or loses the device-side session, promptly close that
            # client rather than leaving a bastion session behind.
            if self._jump_client is not None:
                self._jump_client.close()  # type: ignore[attr-defined]
                self._jump_client = None
            raise

        logger.info(f"Connected to {self.params.host}")

    def _open_jump_channel(self) -> object:
        """Open a ``direct-tcpip`` SSH channel to the target device through the jump host.

        Returns a Paramiko ``Channel`` object suitable for Netmiko's ``sock=`` kwarg.
        The jump host itself never runs any netops-toolkit code - it is used purely
        as network transport (an SSH bastion). See ``docs/guides/jump-host-tunnel.md``
        for the rationale behind this mechanism over local port-forwarding or an
        external OpenSSH subprocess.
        """
        try:
            import paramiko
        except ImportError:
            raise ImportError("paramiko is required for jump-host tunneling: pip install paramiko")

        jump = self.params.jump_host
        assert jump is not None  # for type checkers; guarded by caller

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {
            "hostname": jump.host,
            "port": jump.port,
            "username": jump.username,
            "timeout": jump.timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if jump.key_file:
            connect_kwargs["key_filename"] = jump.key_file
            if jump.key_passphrase:
                connect_kwargs["passphrase"] = jump.key_passphrase
        elif jump.password:
            connect_kwargs["password"] = jump.password

        logger.info(
            "Opening jump-host tunnel via %s:%s -> %s:%s",
            jump.host,
            jump.port,
            self.params.host,
            self.params.effective_port,
        )
        try:
            client.connect(**connect_kwargs)
            transport = client.get_transport()
            if transport is None:
                raise RuntimeError(f"Failed to establish transport to jump host {jump.host}")

            channel = transport.open_channel(
                "direct-tcpip",
                dest_addr=(self.params.host, self.params.effective_port),
                src_addr=("127.0.0.1", 0),
                timeout=jump.timeout,
            )
        except Exception:
            client.close()
            raise

        # Keep the SSHClient alive for the lifetime of the channel/connection;
        # closing it prematurely would tear down the tunnel.
        self._jump_client = client
        return channel

    def disconnect(self) -> None:
        """Close the connection."""
        if self._connection:
            self._connection.disconnect()
            logger.info(f"Disconnected from {self.params.host}")
        if self._jump_client is not None:
            self._jump_client.close()  # type: ignore[attr-defined]
            self._jump_client = None
            logger.info(f"Closed jump-host tunnel for {self.params.host}")

    def send(self, command: str, expect_string: str | None = None) -> str:
        """Send a command and return output."""
        if not self._connection:
            raise RuntimeError("Not connected")
        kwargs = {}
        if expect_string:
            kwargs["expect_string"] = expect_string
        return str(self._connection.send_command(command, **kwargs))

    def send_config(self, commands: list[str]) -> str:
        """Send configuration commands."""
        if not self._connection:
            raise RuntimeError("Not connected")
        return str(self._connection.send_config_set(commands))

    def _resolve_device_type(self) -> str:
        """Map our device_type to Netmiko device_type."""
        mapping = {
            "cisco_ios": "cisco_ios",
            "cisco_xe": "cisco_xe",
            "cisco_xr": "cisco_xr",
            "cisco_nxos": "cisco_nxos",
            "nokia_sros": "nokia_sros",
            "nokia_srl": "nokia_srl",
            "juniper_junos": "juniper_junos",
            "arista_eos": "arista_eos",
            "paloalto_panos": "paloalto_panos",
            "autodetect": "autodetect",
        }
        return mapping.get(self.params.device_type, self.params.device_type)

    def _telnet_device_type(self) -> str:
        """Append _telnet to device type for Netmiko."""
        dt = self._resolve_device_type()
        if dt == "autodetect":
            return "autodetect"
        if not dt.endswith("_telnet"):
            return f"{dt}_telnet"
        return dt


def resolve_jump_host_params(
    jump_host: str | None,
    jump_port: int = 22,
    jump_username: str | None = None,
    jump_password: str | None = None,
    jump_key_file: str | None = None,
    jump_key_passphrase: str | None = None,
    vault: object | None = None,
) -> JumpHostParams | None:
    """Build :class:`JumpHostParams` from inventory-declared jump-host fields.

    Returns ``None`` if *jump_host* is not set (the common, non-tunneled case).
    Jump-box credentials are resolved through the same :class:`~netops.core.vault.CredentialVault`
    lookup used for device credentials (env vars -> device entry -> group -> default),
    keyed by the jump host's own hostname so operators can store bastion creds once
    and reuse them across every device that tunnels through it. If *vault* is an
    unlocked ``CredentialVault`` instance and no explicit username/key is given, its
    credentials for the jump host are used.
    """
    if not jump_host:
        return None

    username = jump_username
    password = jump_password
    key_file = jump_key_file
    key_passphrase = jump_key_passphrase

    if vault is not None:
        creds = vault.get_credentials(jump_host)  # type: ignore[attr-defined]
        if creds:
            username = username or creds.get("username")
            # A vault's encrypted `password` field is the jump-box password
            # for password auth, and the private-key passphrase for key auth.
            # This deliberately reuses the existing vault schema/trust model.
            if key_file:
                key_passphrase = key_passphrase or creds.get("password")
            else:
                password = password or creds.get("password")

    auth_method = (
        AuthMethod.KEY_PASSWORD if key_file and key_passphrase else AuthMethod.KEY
    ) if key_file else AuthMethod.PASSWORD

    return JumpHostParams(
        host=jump_host,
        username=username,
        password=password,
        auth_method=auth_method,
        port=jump_port,
        key_file=key_file,
        key_passphrase=key_passphrase,
    )


def jump_host_from_inventory(device: object, vault: object | None = None) -> JumpHostParams | None:
    """Translate a :class:`netops.core.inventory.Device`'s bastion fields.

    Keeping this mapping at the connection boundary means every inventory-driven
    command uses exactly the same tunnel semantics rather than independently
    rebuilding a partial set of jump-host parameters.
    """
    return resolve_jump_host_params(
        getattr(device, "jump_host", None),
        getattr(device, "jump_port", 22),
        getattr(device, "jump_username", None),
        getattr(device, "jump_password", None),
        getattr(device, "jump_key_file", None),
        getattr(device, "jump_key_passphrase", None),
        vault,
    )
