"""Mock SSH server using paramiko for integration testing.

Supports multiple device personalities (brocade_fastiron, cisco_ios, juniper_junos)
and responds to commands based on configured personality.
"""

from __future__ import annotations

import logging
import socket
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

import paramiko

logger = logging.getLogger(__name__)

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# RSA host key generated on-the-fly for tests
_HOST_KEY = paramiko.RSAKey.generate(2048)


# ---------------------------------------------------------------------------
# Device personalities — maps command patterns to fixture file responses
# ---------------------------------------------------------------------------

def _load_fixture(filename: str) -> str:
    path = FIXTURES_DIR / filename
    if path.exists():
        return path.read_text()
    return ""


PERSONALITIES: dict[str, dict[str, str]] = {
    "brocade_fastiron": {
        "show version": _load_fixture("brocade_fastiron_show_version.txt"),
        "show inventory": _load_fixture("brocade_fastiron_show_inventory.txt"),
        "show running-config | include snmp-server community": _load_fixture(
            "brocade_fastiron_show_run_snmp.txt"
        ),
        "skip-page-display": "",
        "terminal length": "",
    },
    "brocade_mlxe": {
        "show version": _load_fixture("brocade_mlxe_show_version.txt"),
        "show inventory": "Chassis: MLXe 4-slot (Serial #: BGD3830M026, Part #: 40-1001086-01)",
        "show running-config | include snmp-server community": "snmp-server community public ro",
        "skip-page-display": "",
        "terminal length": "",
    },
    "cisco_ios": {
        "show version": _load_fixture("cisco_ios_show_version.txt"),
        "show inventory": _load_fixture("cisco_ios_show_inventory.txt"),
        "show running-config | include snmp-server community": _load_fixture(
            "cisco_ios_show_run_snmp.txt"
        ),
        "terminal length 0": "",
        "terminal width 511": "",
    },
    "cisco_me3600x": {
        "show version": _load_fixture("cisco_me3600x_show_version.txt"),
        "show inventory": 'NAME: "Chassis", DESCR: "ME-3600X-24FS-M"\nPID: ME-3600X-24FS-M, VID: V01, SN: FOC1842R0PL',
        "terminal length 0": "",
        "terminal width 511": "",
    },
    "juniper_junos": {
        "show version": _load_fixture("juniper_show_version.txt"),
        "show chassis hardware": _load_fixture("juniper_show_chassis_hardware.txt"),
        "show configuration snmp | display set | match community": _load_fixture(
            "juniper_show_snmp.txt"
        ),
        "set cli screen-width 511": "Screen width set to 511",
        "set cli screen-length 0": "Screen length set to 0",
        "set cli timestamp disable": "",
    },
}


# ---------------------------------------------------------------------------
# SSH Server Implementation
# ---------------------------------------------------------------------------


class MockSSHServer(paramiko.ServerInterface):
    """Paramiko server interface that accepts a fixed username/password."""

    def __init__(self, username: str = "admin", password: str = "admin123"):
        self.username = username
        self.password = password
        self.event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        if username == self.username and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        self.event.set()
        return True


def _handle_client(
    client_socket: socket.socket,
    personality: str,
    username: str,
    password: str,
) -> None:
    """Handle a single SSH client connection."""
    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(_HOST_KEY)

        server = MockSSHServer(username=username, password=password)
        transport.start_server(server=server)

        channel = transport.accept(timeout=10)
        if channel is None:
            return

        # Wait for shell or exec request
        server.event.wait(10)

        commands = PERSONALITIES.get(personality, {})

        # Interactive shell simulation
        # Send a prompt, read commands, respond
        if personality == "juniper_junos":
            prompt = "admin@router>"
        else:
            prompt = f"{personality.split('_')[0]}#"
        channel.sendall(f"\r\n{prompt} ".encode())

        buffer = b""
        while True:
            try:
                data = channel.recv(4096)
                if not data:
                    break
                buffer += data

                # Process complete lines
                while b"\n" in buffer or b"\r" in buffer:
                    # Split on any line ending
                    for sep in (b"\r\n", b"\n", b"\r"):
                        if sep in buffer:
                            line, buffer = buffer.split(sep, 1)
                            break
                    else:
                        break

                    cmd = line.decode("utf-8", errors="ignore").strip()
                    if not cmd:
                        channel.sendall(f"\r\n{prompt} ".encode())
                        continue

                    if cmd in ("exit", "quit", "logout"):
                        channel.sendall(b"\r\nConnection closed.\r\n")
                        channel.close()
                        return

                    # Echo the command (Netmiko expects to see it)
                    channel.sendall(f"{cmd}\r\n".encode())

                    # Find matching command response
                    response = None
                    for pattern, resp in commands.items():
                        if pattern in cmd or cmd in pattern:
                            response = resp
                            break

                    if response:
                        channel.sendall(f"{response}\r\n{prompt} ".encode())
                    else:
                        channel.sendall(
                            f"% Unknown command: {cmd}\r\n{prompt} ".encode()
                        )

            except (OSError, EOFError):
                break

    except Exception as e:
        logger.debug(f"Mock SSH handler error: {e}")
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_socket.close()
        except Exception:
            pass


class MockSSHServerInstance:
    """A running mock SSH server instance."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 2222,
        personality: str = "cisco_ios",
        username: str = "admin",
        password: str = "admin123",
    ):
        self.host = host
        self.port = port
        self.personality = personality
        self.username = username
        self.password = password
        self._server_socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        """Start the SSH server in a background thread."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)
        self._running = True

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        logger.info(f"Mock SSH server ({self.personality}) listening on {self.host}:{self.port}")

    def _accept_loop(self) -> None:
        """Accept connections in a loop until stopped."""
        while self._running:
            try:
                client_socket, addr = self._server_socket.accept()
                logger.debug(f"Mock SSH: connection from {addr}")
                handler = threading.Thread(
                    target=_handle_client,
                    args=(client_socket, self.personality, self.username, self.password),
                    daemon=True,
                )
                handler.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self) -> None:
        """Stop the SSH server."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)
        logger.info(f"Mock SSH server stopped on {self.host}:{self.port}")


@contextmanager
def mock_ssh_server(
    host: str = "127.0.0.1",
    port: int = 2222,
    personality: str = "cisco_ios",
    username: str = "admin",
    password: str = "admin123",
) -> Generator[MockSSHServerInstance, None, None]:
    """Context manager that starts and stops a mock SSH server."""
    server = MockSSHServerInstance(
        host=host, port=port, personality=personality,
        username=username, password=password,
    )
    server.start()
    try:
        yield server
    finally:
        server.stop()
