"""
Unified device connection manager.

Handles SSH, SSH2, and Telnet connections with a single interface.
Uses Netmiko under the hood for vendor-aware CLI interaction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class Transport(Enum):
    SSH = "ssh"
    SSH2 = "ssh2"  # Legacy SSH implementations
    TELNET = "telnet"


class AuthMethod(Enum):
    PASSWORD = "password"
    KEY = "key"
    KEY_PASSWORD = "key_password"  # Key + passphrase


@dataclass
class ConnectionParams:
    """Everything needed to connect to a device."""
    host: str
    username: str
    password: Optional[str] = None
    transport: Transport = Transport.SSH
    auth_method: AuthMethod = AuthMethod.PASSWORD
    port: Optional[int] = None  # None = auto (22/23)
    key_file: Optional[str] = None
    device_type: str = "autodetect"  # Netmiko device_type
    timeout: int = 30
    enable_password: Optional[str] = None
    # Vendor-specific overrides
    extras: dict = field(default_factory=dict)

    @property
    def effective_port(self) -> int:
        if self.port:
            return self.port
        return 23 if self.transport == Transport.TELNET else 22


class DeviceConnection:
    """
    Unified connection to a network device.

    Usage:
        params = ConnectionParams(host="10.0.0.1", username="admin", password="secret")
        with DeviceConnection(params) as conn:
            output = conn.send("show version")
            config = conn.send("show running-config")
    """

    def __init__(self, params: ConnectionParams):
        self.params = params
        self._connection = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def connect(self):
        """Establish connection using configured transport."""
        try:
            from netmiko import ConnectHandler
        except ImportError:
            raise ImportError(
                "netmiko is required: pip install netmiko"
            )

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

        # Telnet override
        if self.params.transport == Transport.TELNET:
            device_params["device_type"] = self._telnet_device_type()

        logger.info(f"Connecting to {self.params.host} via {self.params.transport.value}")
        self._connection = ConnectHandler(**device_params)

        if self.params.enable_password:
            self._connection.enable()

        logger.info(f"Connected to {self.params.host}")

    def disconnect(self):
        """Close the connection."""
        if self._connection:
            self._connection.disconnect()
            logger.info(f"Disconnected from {self.params.host}")

    def send(self, command: str, expect_string: str = None) -> str:
        """Send a command and return output."""
        if not self._connection:
            raise RuntimeError("Not connected")
        kwargs = {}
        if expect_string:
            kwargs["expect_string"] = expect_string
        return self._connection.send_command(command, **kwargs)

    def send_config(self, commands: list[str]) -> str:
        """Send configuration commands."""
        if not self._connection:
            raise RuntimeError("Not connected")
        return self._connection.send_config_set(commands)

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
