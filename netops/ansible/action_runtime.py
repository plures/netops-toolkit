"""Private pre-fork action client and fixed in-process native engine adapter."""

from __future__ import annotations

import os
import socket
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import NoReturn, Protocol, cast

from netops.core.connection import ConnectionParams, DeviceConnection, Transport

from . import contracts as c
from ._action_health import _gather_native, _handlers, _HealthSelection
from ._action_mutation import _MutationSpec, _run_mutation
from .controller_content import _encode_content, _NativeRead
from .controller_observations import _ControllerIo
from .controller_protocol import DispatchBinding, ProtocolError, _closed, _integer, _string
from .controller_transport import _SocketFrames, _unix_family
from .credential_routes import _inspect

_CLIENT: _ActionClient | None = None
_CONFIG_COMMANDS = {
    "cisco_ios": "show running-config", "cisco_xe": "show running-config",
    "cisco_nxos": "show running-config", "arista_eos": "show running-config",
    "nokia_sros": "admin display-config",
}


class _NativeActionsPort(Protocol):
    def supports(self, kind: str) -> bool: ...

    def run(
        self, kind: str, credential: dict[str, object], jump: object,
    ) -> dict[str, object] | _NativeRead: ...


class _StrictConnection(DeviceConnection):
    """Use native send engines without ambient bastion or host-key enrollment."""

    def __init__(self, credential: dict[str, object], jump: object) -> None:
        self._credential, self._selected_jump = credential, jump
        fields = credential["fields"]
        if not isinstance(fields, dict):
            raise ProtocolError()
        super().__init__(ConnectionParams(
            host=_string(credential["host"]), username=_string(fields["username"]),
            password=_string(fields["password"]) if "password" in fields else None,
            transport=Transport.SSH, port=_integer(credential["port"], 1, 65535),
            device_type=_string(credential["vendor"]), timeout=10,
        ))

    @staticmethod
    def _files(credential: dict[str, object]) -> tuple[str | None, str]:
        known = _string(credential["known_hosts_ref"])
        _inspect(Path(known), "known-hosts")
        key: str | None = None
        if credential["key_ref"] is not None:
            key = _string(credential["key_ref"])
            _inspect(Path(key), "private-key")
        return key, known

    def connect(self) -> None:
        """Connect on the exact selected strict route, never implicit direct fallback."""
        import paramiko
        from netmiko import ConnectHandler
        from netmiko.base_connection import BaseConnection

        key, known = self._files(self._credential)
        fields = self._credential["fields"]
        assert isinstance(fields, dict)
        private_socket: object | None = None
        client: paramiko.SSHClient | None = None
        try:
            if self._selected_jump is not None:
                jump = self._selected_jump
                if not isinstance(jump, dict):
                    raise ProtocolError(c.ReasonCode.ROUTE_UNAVAILABLE)
                jump_key, jump_known = self._files(jump)
                jump_fields = jump["fields"]
                if not isinstance(jump_fields, dict):
                    raise ProtocolError()
                client = paramiko.SSHClient()
                client.load_host_keys(jump_known)
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                client.connect(
                    hostname=_string(jump["host"]), port=_integer(jump["port"], 1, 65535),
                    username=_string(jump_fields["username"]),
                    password=_string(jump_fields["password"]) if "password" in jump_fields else None,
                    key_filename=jump_key,
                    passphrase=_string(jump_fields["key_passphrase"])
                    if "key_passphrase" in jump_fields else None,
                    allow_agent=False, look_for_keys=False,
                    timeout=10, auth_timeout=10, banner_timeout=10,
                )
                transport = client.get_transport()
                if transport is None or not transport.is_active():
                    raise ProtocolError(c.ReasonCode.ROUTE_UNAVAILABLE)
                private_socket = transport.open_channel(
                    "direct-tcpip", (self.params.host, self.params.effective_port),
                    ("127.0.0.1", 0), timeout=10,
                )
                self._jump_client = client
            parameters: dict[str, object] = {
                "device_type": self.params.device_type, "host": self.params.host,
                "port": self.params.effective_port, "username": self.params.username,
                "password": self.params.password, "use_keys": key is not None,
                "allow_agent": False, "ssh_strict": True, "system_host_keys": False,
                "alt_host_keys": True, "alt_key_file": known,
                "conn_timeout": 10, "auth_timeout": 10, "banner_timeout": 10,
                "session_log": None,
            }
            if key is not None:
                parameters["key_file"] = key
            if "key_passphrase" in fields:
                parameters["passphrase"] = _string(fields["key_passphrase"])
            if "enable_password" in fields:
                parameters["secret"] = _string(fields["enable_password"])
            if private_socket is not None:
                parameters["sock"] = private_socket
            self._connection = cast(BaseConnection, ConnectHandler(**parameters))
        except BaseException:
            if client is not None:
                client.close()
            self._jump_client = None
            raise

    def disconnect(self) -> None:
        """Close both selected resources without value-bearing native log lines."""
        primary: BaseException | None = None
        connection, jump = self._connection, self._jump_client
        self._connection, self._jump_client = None, None
        try:
            if connection is not None:
                connection.disconnect()
        except BaseException as error:
            primary = error
        try:
            if jump is not None:
                close = getattr(jump, "close")
                close()
        except BaseException:
            if primary is None:
                raise
        if primary is not None:
            raise primary


class _NativeActions:
    """Collection and actual native health owners; mutation remains separate."""

    def supports(self, kind: str) -> bool:
        return kind in ("collect", "gather")

    def run(
        self, kind: str, credential: dict[str, object], jump: object,
    ) -> dict[str, object] | _NativeRead:
        return self.run_selected(kind, credential, jump, _HealthSelection())

    def run_selected(
        self, kind: str, credential: dict[str, object], jump: object,
        selection: _HealthSelection, check: Callable[[], None] = lambda: None,
    ) -> dict[str, object] | _NativeRead:
        """Consume trusted host selection, never a device-supplied command string."""
        vendor = _string(credential["vendor"])
        if not self.supports(kind) or (kind == "collect" and vendor not in _CONFIG_COMMANDS):
            return _result("unsupported", False)
        if kind == "gather":
            connection = _StrictConnection(credential, jump)
            if not any(name in _handlers(vendor, selection)[0] for name in selection.checks):
                return _gather_native(connection, vendor, selection, check)
            result: dict[str, object] | None = None
            try:
                check()
                connection.connect()
                result = _gather_native(connection, vendor, selection, check)
            finally:
                try:
                    connection.disconnect()
                except BaseException:
                    if result is None:
                        raise
                    result["status"] = "failed"
                    health = result["health"]
                    assert isinstance(health, dict)
                    health["connection_cleanup_failed"] = True
            return result
        # Native DeviceConnection.send is reused in-process. No module staging,
        # raw native exception or sensitive collected bytes reach callbacks.
        with _StrictConnection(credential, jump) as collection:
            output = collection.send(
                _CONFIG_COMMANDS[vendor],
            )
            lines = len(output.splitlines())
        result = _result("succeeded", True, line_count=lines)
        return _NativeRead(result, output.encode("utf-8"))


def _result(
    status: str, attempted: bool, *, line_count: int = 0,
) -> dict[str, object]:
    return {
        "status": status, "attempted": attempted, "changed": False,
        "remote_state": "unchanged", "line_count": line_count,
    }


class _ActionClient:
    """Memory-only auth read once before Ansible forks; sockets are never shared."""

    def __init__(
        self, bootstrap: dict[str, object], native: _NativeActionsPort | None = None,
    ) -> None:
        item = _closed(bootstrap, {"protocol", "socket", "auth", "intents"})
        _integer(item["protocol"], 1, 1)
        self._socket = _string(item["socket"])
        self._auth = _string(item["auth"], 64)
        if len(self._auth) != 64 or len(bytes.fromhex(self._auth)) != 32:
            raise ProtocolError()
        self._owner_pid = os.getpid()
        self._native = native if native is not None else _NativeActions()
        self._io = _ControllerIo()
        raw = item["intents"]
        if type(raw) is not list or not 1 <= len(raw) <= 4096:
            raise ProtocolError()
        assert isinstance(raw, list)
        self._intents: dict[str, tuple[DispatchBinding, str]] = {}
        self._mutations: dict[str, _MutationSpec] = {}
        self._health: dict[str, _HealthSelection] = {}
        self._mutation_requested: set[str] = set()
        for value in raw:
            mutation = isinstance(value, dict) and "mutation" in value
            health = isinstance(value, dict) and "health" in value
            entry = _closed(value, {"handle", "binding", "kind"} | (
                {"mutation"} if mutation else set()
            ) | ({"health"} if health else set()))
            binding = DispatchBinding._parse(entry["binding"])
            handle = _string(entry["handle"])
            kind = _string(entry["kind"])
            if (
                handle != binding.occurrence_id or handle in self._intents
                or kind not in ("collect", "gather", "apply", "rollback")
            ):
                raise ProtocolError()
            if mutation:
                if kind not in ("apply", "rollback"):
                    raise ProtocolError()
                self._mutations[handle] = _MutationSpec._parse(entry["mutation"])
                self._mutations[handle]._validate_kind(kind)
            elif kind in ("apply", "rollback"):
                raise ProtocolError(c.ReasonCode.INPUT_BINDING_INVALID)
            if health:
                if kind != "gather":
                    raise ProtocolError()
                self._health[handle] = _HealthSelection.parse(entry["health"])
            self._intents[handle] = (binding, kind)

    def __repr__(self) -> str:
        return "<private>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("private-value")

    def _request(
        self, kind: str, binding: DispatchBinding, result: object = None,
    ) -> dict[str, object]:
        with self._io.span(
            "action.channel", binding.operation_id, binding.controller_digest,
            target=binding.target_id, step=binding.occurrence_id,
        ):
            return self._exchange(kind, binding, result)

    def _exchange(
        self, kind: str, binding: DispatchBinding, result: object,
    ) -> dict[str, object]:
        channel = socket.socket(_unix_family(), socket.SOCK_STREAM)
        channel.settimeout(2.0)
        frames = _SocketFrames(channel)
        try:
            channel.connect(self._socket)
            frames.send({
                "auth": self._auth, "kind": kind, "binding": binding._wire(), "result": result,
            })
            channel.shutdown(socket.SHUT_WR)
            response = frames.receive_one(2.0)
            if response.get("kind") == "rejected":
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
            return response
        finally:
            frames.close()

    def execute(self, handle: str) -> dict[str, object]:
        # Only the qualified fork path may inherit this private client. A spawn
        # import has no client; same-process direct invocation also fails closed.
        if os.name != "posix" or os.getpid() == self._owner_pid or handle not in self._intents:
            raise ProtocolError(c.ReasonCode.CREDENTIAL_SCOPE_INVALID)
        return self._execute(handle)

    def _execute(self, handle: str) -> dict[str, object]:
        # Pure orchestration seam for ordinary unit tests. The installed action
        # entry always calls execute, including its real fork ownership guard.
        original, kind = self._intents[handle]
        if kind not in ("apply", "rollback") and not self._native.supports(kind):
            result = _result("unsupported", False)
            self._request("complete", original, result)
            return result
        attempted = False
        try:
            response = _closed(
                self._request("dispatch", original), {"kind", "credential", "jump"},
            )
            if response["kind"] != "credential" or type(response["credential"]) is not dict:
                raise ProtocolError()
            credential = response["credential"]
            assert isinstance(credential, dict)
            binding = replace(original, phase="task", sequence=1)
            task = _closed(self._request("dispatch", binding), {"kind"})
            if task["kind"] != "admitted":
                raise ProtocolError()
            attempted = True
            with self._io.span(
                "action.native", binding.operation_id, binding.controller_digest,
                target=binding.target_id, step=binding.occurrence_id,
            ):
                native = (
                    _run_mutation(
                        kind, self._mutations[handle], credential, response["jump"],
                        lambda: self._check(binding),
                        lambda: self._admit_mutation(original),
                        self._io, binding.operation_id, binding.controller_digest,
                        target=binding.target_id, step=binding.occurrence_id,
                    ) if kind in ("apply", "rollback")
                    else self._native.run_selected(
                        kind, credential, response["jump"],
                        self._health.get(handle, _HealthSelection()),
                        lambda: self._check(binding),
                    ) if type(self._native) is _NativeActions
                    else self._native.run(kind, credential, response["jump"])
                )
            if type(native) is _NativeRead:
                content_receipt = _closed(self._request(
                    "content", binding, _encode_content(native.content),
                ), {"kind"})
                if content_receipt["kind"] != "content-received":
                    raise ProtocolError()
                result = native.result
            else:
                assert isinstance(native, dict)
                result = native
            from .worker_broker import _safe_action_result

            _safe_action_result(result, original.target_id, kind)
        except Exception:
            result = _result("failed", attempted)
            if kind in ("apply", "rollback"):
                issued = handle in self._mutation_requested
                result.update(
                    changed=issued, remote_state="uncertain" if issued else "unchanged",
                    mutation={
                        "issued": issued, "committed": False, "confirmed": False,
                        "rolled_back": False, "poststate_verified": False,
                        "cleanup_failed": False, "connection_opened": False,
                    },
                )
        # A late completion is a fact, never a new task/credential/mutation.
        complete = _closed(self._request(
            "complete", replace(original, phase="task", sequence=1), result,
        ), {"kind"})
        if complete["kind"] != "completed":
            raise ProtocolError()
        return result

    def _check(self, binding: DispatchBinding) -> None:
        # A check carries no fresh budget and never repeats a spent phase.
        response = _closed(self._request("check", binding), {"kind"})
        if response["kind"] != "checked":
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)

    def _admit_mutation(self, binding: DispatchBinding) -> None:
        self._mutation_requested.add(binding.occurrence_id)
        response = _closed(self._request(
            "dispatch", replace(binding, phase="mutation", sequence=2),
        ), {"kind"})
        if response["kind"] != "admitted":
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)


def _install_client(client: _ActionClient | None) -> None:
    global _CLIENT
    _CLIENT = client
