"""Workstation-wide SSH bastion service.

The service owns one SSH connection to the selected bastion and exposes a
loopback-only SOCKS5 endpoint.  Toolkit callers do not need inventory-specific
jump-host fields: :func:`open_active_bastion_socket` supplies a ready TCP
socket whenever a bastion is active.

Only connection metadata and a random local-session token are written to disk.
The bastion password or key passphrase is passed to the child over stdin and
remains only in that child process's memory.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import ipaddress
import json
import logging
import os
import secrets
import select
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_STATE_ENV = "NETOPS_BASTION_STATE"
_DEFAULT_STATE_PATH = Path.home() / ".netops" / "active-bastion.json"
_DEFAULT_KNOWN_HOSTS_PATH = Path.home() / ".netops" / "known_hosts"


@dataclass(frozen=True)
class ActiveBastion:
    """Non-secret details required to use the active local SOCKS service."""

    host: str
    port: int
    username: str
    key_file: str | None
    socks_host: str
    socks_port: int
    control_host: str
    control_port: int
    token: str
    pid: int


def state_path() -> Path:
    """Return the user-scoped active-bastion state path."""
    return Path(os.environ.get(_STATE_ENV, _DEFAULT_STATE_PATH))


def _read_state(path: Path | None = None) -> ActiveBastion | None:
    path = path or state_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return ActiveBastion(
            host=str(raw["host"]),
            port=int(raw["port"]),
            username=str(raw["username"]),
            key_file=raw.get("key_file"),
            socks_host=str(raw["socks_host"]),
            socks_port=int(raw["socks_port"]),
            control_host=str(raw["control_host"]),
            control_port=int(raw["control_port"]),
            token=str(raw["token"]),
            pid=int(raw["pid"]),
        )
    except (FileNotFoundError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def active_bastion() -> ActiveBastion | None:
    """Return the live active bastion, or ``None`` when routing is disabled."""
    state = _read_state()
    if state is None:
        return None
    try:
        response = _control_request(state, "status")
    except OSError:
        return None
    return state if response.get("connected") is True else None


def open_active_bastion_socket(host: str, port: int, timeout: int | float) -> socket.socket | None:
    """Open a TCP socket to *host* through the active bastion, if one exists.

    The returned socket is already connected to the target and is suitable for
    Netmiko's ``sock=`` argument.  ``None`` means no global bastion is active;
    callers should retain their normal direct connection behavior in that case.
    """
    state = active_bastion()
    if state is None:
        return None

    sock = socket.create_connection((state.socks_host, state.socks_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        _socks_authenticate(sock, state.token)
        _socks_connect(sock, host, port)
        return sock
    except Exception:
        sock.close()
        raise


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("bastion SOCKS service closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _socks_authenticate(sock: socket.socket, token: str) -> None:
    token_bytes = token.encode("ascii")
    if len(token_bytes) > 255:
        raise ValueError("invalid active-bastion session token")
    sock.sendall(b"\x05\x01\x02")
    version, method = _recv_exact(sock, 2)
    if version != 5 or method != 2:
        raise OSError("active bastion rejected SOCKS authentication")
    sock.sendall(b"\x01\x06netops" + bytes([len(token_bytes)]) + token_bytes)
    version, status = _recv_exact(sock, 2)
    if version != 1 or status != 0:
        raise OSError("active bastion authentication failed")


def _socks_connect(sock: socket.socket, host: str, port: int) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            raise ValueError("target hostname is too long for SOCKS5")
        request = b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded
    else:
        atyp = b"\x01" if address.version == 4 else b"\x04"
        request = b"\x05\x01\x00" + atyp + address.packed
    sock.sendall(request + port.to_bytes(2, "big"))
    version, reply, _reserved, atyp = _recv_exact(sock, 4)
    if version != 5 or reply != 0:
        raise OSError(f"active bastion could not connect to {host}:{port} (SOCKS {reply})")
    address_length = {1: 4, 4: 16}.get(atyp)
    if atyp == 3:
        address_length = _recv_exact(sock, 1)[0]
    if address_length is None:
        raise OSError("active bastion returned an invalid SOCKS response")
    _recv_exact(sock, address_length + 2)


def _control_request(state: ActiveBastion, command: str) -> dict[str, Any]:
    with socket.create_connection((state.control_host, state.control_port), timeout=2) as control:
        control.sendall((json.dumps({"token": state.token, "command": command}) + "\n").encode("utf-8"))
        response = control.makefile("r", encoding="utf-8").readline()
    parsed = json.loads(response)
    if not isinstance(parsed, dict):
        raise OSError("invalid active-bastion control response")
    return parsed


def _find_open_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _known_hosts_path() -> Path:
    return Path(os.environ.get("NETOPS_KNOWN_HOSTS", _DEFAULT_KNOWN_HOSTS_PATH))


class _SshTransport:
    def __init__(self, profile: ActiveBastion, password: str | None, key_passphrase: str | None) -> None:
        self._profile = profile
        self._password = password
        self._key_passphrase = key_passphrase
        self._client: Any | None = None
        self._lock = threading.Lock()

    def open_channel(self, host: str, port: int, timeout: float) -> Any:
        with self._lock:
            client = self._connect_if_needed()
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                self.close()
                client = self._connect_if_needed()
                transport = client.get_transport()
            if transport is None:
                raise OSError("SSH bastion transport is unavailable")
            return transport.open_channel(
                "direct-tcpip",
                dest_addr=(host, port),
                src_addr=("127.0.0.1", 0),
                timeout=timeout,
            )

    def _connect_if_needed(self) -> Any:
        if self._client is not None:
            transport = self._client.get_transport()
            if transport is not None and transport.is_active():
                return self._client
            self.close()

        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover - a core dependency
            raise RuntimeError("paramiko is required for active bastion routing") from exc

        known_hosts = _known_hosts_path()
        known_hosts.parent.mkdir(parents=True, exist_ok=True)
        known_hosts.touch(exist_ok=True)

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.load_host_keys(str(known_hosts))
        # Trust on first use and persist the selected bastion's key. Subsequent
        # key changes are rejected by Paramiko's known-host checking.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict[str, Any] = {
            "hostname": self._profile.host,
            "port": self._profile.port,
            "username": self._profile.username,
            "timeout": 30,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self._profile.key_file:
            kwargs["key_filename"] = self._profile.key_file
            if self._key_passphrase:
                kwargs["passphrase"] = self._key_passphrase
        elif self._password:
            kwargs["password"] = self._password
        client.connect(**kwargs)
        self._client = client
        return client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def is_connected(self) -> bool:
        """Return whether the retained Paramiko transport is currently live."""
        with self._lock:
            if self._client is None:
                return False
            transport = self._client.get_transport()
            return bool(transport and transport.is_active())


class _ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _SocksHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        service: _BastionService = self.server.service  # type: ignore[attr-defined]
        try:
            version, methods_count = _recv_exact(self.request, 2)
            if version != 5:
                return
            methods = _recv_exact(self.request, methods_count)
            if 2 not in methods:
                self.request.sendall(b"\x05\xff")
                return
            self.request.sendall(b"\x05\x02")
            version = _recv_exact(self.request, 1)[0]
            username_length = _recv_exact(self.request, 1)[0]
            username = _recv_exact(self.request, username_length)
            password_length = _recv_exact(self.request, 1)[0]
            password = _recv_exact(self.request, password_length)
            if version != 1 or username != b"netops" or not secrets.compare_digest(
                password.decode("ascii", errors="ignore"), service.state.token
            ):
                self.request.sendall(b"\x01\x01")
                return
            self.request.sendall(b"\x01\x00")

            version, command, _reserved, atyp = _recv_exact(self.request, 4)
            if version != 5 or command != 1:
                self.request.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            host = self._read_target(atyp)
            port = int.from_bytes(_recv_exact(self.request, 2), "big")
            channel = service.transport.open_channel(host, port, timeout=30)
            self.request.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            self._bridge(channel)
        except Exception as exc:
            logger.debug("active bastion SOCKS request failed: %s", exc)
            try:
                self.request.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass

    def _read_target(self, atyp: int) -> str:
        if atyp == 1:
            return str(ipaddress.IPv4Address(_recv_exact(self.request, 4)))
        if atyp == 4:
            return str(ipaddress.IPv6Address(_recv_exact(self.request, 16)))
        if atyp == 3:
            length = _recv_exact(self.request, 1)[0]
            return _recv_exact(self.request, length).decode("idna")
        raise OSError("unsupported SOCKS address type")

    def _bridge(self, channel: Any) -> None:
        try:
            while True:
                readable, _, _ = select.select([self.request, channel], [], [])
                if self.request in readable:
                    chunk = self.request.recv(65536)
                    if not chunk:
                        return
                    channel.sendall(chunk)
                if channel in readable:
                    chunk = channel.recv(65536)
                    if not chunk:
                        return
                    self.request.sendall(chunk)
        finally:
            channel.close()


class _ControlHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        service: _BastionService = self.server.service  # type: ignore[attr-defined]
        try:
            request = json.loads(self.rfile.readline().decode("utf-8"))
            token = str(request.get("token", ""))
            command = request.get("command")
            if not secrets.compare_digest(token, service.state.token):
                response: dict[str, Any] = {"ok": False, "error": "unauthorized"}
            elif command == "status":
                response = {"ok": True, "connected": service.transport.is_connected()}
            elif command == "disconnect":
                response = {"ok": True, "connected": False}
                threading.Thread(target=service.stop, daemon=True).start()
            else:
                response = {"ok": False, "error": "unknown command"}
        except (json.JSONDecodeError, OSError, TypeError, ValueError):
            response = {"ok": False, "error": "invalid request"}
        self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))


class _BastionService:
    def __init__(self, state: ActiveBastion, password: str | None, key_passphrase: str | None) -> None:
        self.state = state
        self.transport = _SshTransport(state, password, key_passphrase)
        self._stopped = threading.Event()
        self._socks = _ThreadingServer((state.socks_host, state.socks_port), _SocksHandler)
        self._control = _ThreadingServer((state.control_host, state.control_port), _ControlHandler)
        self._socks.service = self  # type: ignore[attr-defined]
        self._control.service = self  # type: ignore[attr-defined]
        self._started = False

    def run(self) -> None:
        self.transport._connect_if_needed()
        for server in (self._socks, self._control):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        self._started = True
        self._stopped.wait()

    def stop(self) -> None:
        if self._stopped.is_set():
            return
        self._stopped.set()
        for server in (self._socks, self._control):
            if self._started:
                server.shutdown()
            server.server_close()
        self.transport.close()


def _write_state(state: ActiveBastion, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(asdict(state), indent=2), encoding="utf-8")
    temporary.replace(path)


def connect_active_bastion(
    host: str,
    username: str,
    port: int = 22,
    key_file: str | None = None,
    password: str | None = None,
    key_passphrase: str | None = None,
) -> ActiveBastion:
    """Start a local active-bastion service and return its non-secret state."""
    if not host.strip() or not username.strip():
        raise ValueError("bastion host and username are required")
    if not 1 <= port <= 65535:
        raise ValueError("bastion port must be between 1 and 65535")

    disconnect_active_bastion()
    path = state_path()
    token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    state = ActiveBastion(
        host=host.strip(),
        port=port,
        username=username.strip(),
        key_file=key_file or None,
        socks_host="127.0.0.1",
        socks_port=_find_open_port(),
        control_host="127.0.0.1",
        control_port=_find_open_port(),
        token=token,
        pid=0,
    )
    log_path = path.with_suffix(".log")
    args = [
        sys.executable,
        "-m",
        "netops.core.bastion",
        "serve",
        "--state-file",
        str(path),
        "--host",
        state.host,
        "--port",
        str(state.port),
        "--username",
        state.username,
        "--socks-port",
        str(state.socks_port),
        "--control-port",
        str(state.control_port),
        "--token",
        state.token,
    ]
    if state.key_file:
        args.extend(["--key-file", state.key_file])
    with log_path.open("w", encoding="utf-8") as log:
        child = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        assert child.stdin is not None
        child.stdin.write(json.dumps({"password": password, "key_passphrase": key_passphrase}))
        child.stdin.close()

    for _ in range(50):
        time.sleep(0.1)
        saved = _read_state(path)
        if saved and active_bastion() is not None:
            return saved
        if child.poll() is not None:
            detail = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
            raise RuntimeError(f"could not connect to bastion {host}: {detail.strip()}")
    child.terminate()
    child.wait(timeout=5)
    path.unlink(missing_ok=True)
    raise TimeoutError(f"timed out connecting to bastion {host}")


def disconnect_active_bastion() -> bool:
    """Stop the active service, if present, without relying on a PID kill."""
    state = _read_state()
    if state is None:
        return False
    try:
        _control_request(state, "disconnect")
    except OSError:
        pass
    state_path().unlink(missing_ok=True)
    return True


def _serve(args: argparse.Namespace) -> int:
    secret = json.loads(sys.stdin.read() or "{}")
    state = ActiveBastion(
        host=args.host,
        port=args.port,
        username=args.username,
        key_file=args.key_file,
        socks_host="127.0.0.1",
        socks_port=args.socks_port,
        control_host="127.0.0.1",
        control_port=args.control_port,
        token=args.token,
        pid=os.getpid(),
    )
    service = _BastionService(state, secret.get("password"), secret.get("key_passphrase"))

    def stop(_signum: int, _frame: Any) -> None:
        service.stop()

    signal.signal(signal.SIGTERM, stop)
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, stop)
    try:
        service.transport._connect_if_needed()
        _write_state(state, Path(args.state_file))
        service.run()
    finally:
        service.stop()
        Path(args.state_file).unlink(missing_ok=True)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netops bastion", description="Manage the active SSH bastion")
    sub = parser.add_subparsers(dest="command", required=True)
    connect = sub.add_parser("connect", help="Select and connect the workstation-wide bastion")
    connect.add_argument("--host", required=True)
    connect.add_argument("--username", required=True)
    connect.add_argument("--port", type=int, default=22)
    connect.add_argument("--key-file")
    connect.add_argument("--password-stdin", action="store_true")
    connect.add_argument("--key-passphrase-stdin", action="store_true")
    sub.add_parser("status", help="Show the active bastion")
    sub.add_parser("disconnect", help="Disconnect the active bastion")
    serve = sub.add_parser("serve", help=argparse.SUPPRESS)
    serve.add_argument("--state-file", required=True)
    serve.add_argument("--host", required=True)
    serve.add_argument("--username", required=True)
    serve.add_argument("--port", type=int, required=True)
    serve.add_argument("--key-file")
    serve.add_argument("--socks-port", type=int, required=True)
    serve.add_argument("--control-port", type=int, required=True)
    serve.add_argument("--token", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the active-bastion command-line interface."""
    args = _build_parser().parse_args(argv)
    if args.command == "serve":
        return _serve(args)
    if args.command == "connect":
        password = sys.stdin.readline().rstrip("\r\n") if args.password_stdin else None
        key_passphrase = sys.stdin.readline().rstrip("\r\n") if args.key_passphrase_stdin else None
        if not args.key_file and password is None:
            password = getpass.getpass("Bastion password: ")
        if args.key_file and key_passphrase is None and not args.key_passphrase_stdin:
            key_passphrase = getpass.getpass("Private-key passphrase (blank for none): ") or None
        try:
            state = connect_active_bastion(
                args.host, args.username, args.port, args.key_file, password, key_passphrase
            )
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            print(f"Bastion connection failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({"connected": True, "host": state.host, "port": state.port, "username": state.username}))
        return 0
    if args.command == "disconnect":
        print(json.dumps({"disconnected": disconnect_active_bastion()}))
        return 0
    state = active_bastion()
    print(
        json.dumps(
            {
                "connected": state is not None,
                "host": state.host if state else None,
                "port": state.port if state else None,
                "username": state.username if state else None,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
