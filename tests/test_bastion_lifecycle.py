"""Lifecycle tests for the workstation-wide bastion process (connect/status/reconnect/stop).

These exercise the public process-lifecycle API with the subprocess and
Paramiko transport boundaries mocked, complementing test_active_bastion.py's
coverage of the SOCKS/control protocol helpers.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from netops.core.bastion import (
    ActiveBastion,
    ActiveBastionUnavailableError,
    _BastionService,
    _SshTransport,
    _write_state,
    active_bastion,
    connect_active_bastion,
    disconnect_active_bastion,
    main,
)


def _parse_serve_args(args: list[str]) -> dict[str, str]:
    flags: dict[str, str] = {}
    it = iter(args[4:])  # skip [sys.executable, "-m", "netops.core.bastion", "serve"]
    for flag in it:
        flags[flag] = next(it)
    return flags


class _FakeChild:
    def __init__(self) -> None:
        self.stdin = MagicMock()
        self.terminated = False
        self._exit_code: int | None = None

    def poll(self) -> int | None:
        return self._exit_code

    def terminate(self) -> None:
        self.terminated = True
        self._exit_code = -15

    def wait(self, timeout: float | None = None) -> int:
        return self._exit_code or 0


def test_connect_active_bastion_passes_token_over_stdin_not_argv(tmp_path: Path, monkeypatch) -> None:
    """The bearer token must never appear in the child process's argv."""
    state_file = tmp_path / "active-bastion.json"
    monkeypatch.setenv("NETOPS_BASTION_STATE", str(state_file))

    fake_child = _FakeChild()
    captured: dict[str, object] = {}

    def fake_popen(args: list[str], **kwargs: object) -> _FakeChild:
        assert "--token" not in args
        captured["args"] = args
        return fake_child

    def fake_stdin_write(data: str) -> None:
        payload = json.loads(data)
        captured["stdin_payload"] = payload
        flags = _parse_serve_args(captured["args"])  # type: ignore[arg-type]
        written = ActiveBastion(
            host=flags["--host"],
            port=int(flags["--port"]),
            username=flags["--username"],
            key_file=None,
            socks_host="127.0.0.1",
            socks_port=int(flags["--socks-port"]),
            control_host="127.0.0.1",
            control_port=int(flags["--control-port"]),
            token=payload["token"],
            pid=4242,
        )
        _write_state(written, Path(flags["--state-file"]))

    fake_child.stdin.write.side_effect = fake_stdin_write

    with (
        patch("netops.core.bastion.subprocess.Popen", side_effect=fake_popen),
        patch("netops.core.bastion._control_request", return_value={"ok": True, "connected": True}),
    ):
        state = connect_active_bastion("bastion.example.com", "netops", 22, None, "hunter2")  # noqa: S106

    assert state.host == "bastion.example.com"
    assert captured["stdin_payload"]["token"] == state.token
    assert captured["stdin_payload"]["password"] == "hunter2"  # noqa: S105
    # Only the non-secret state file (with owner-only permissions) is left on disk.
    assert state_file.exists()
    assert (state_file.stat().st_mode & 0o777) == 0o600


def test_connect_active_bastion_raises_when_child_process_exits(tmp_path: Path, monkeypatch) -> None:
    state_file = tmp_path / "active-bastion.json"
    monkeypatch.setenv("NETOPS_BASTION_STATE", str(state_file))

    fake_child = _FakeChild()
    fake_child._exit_code = 1

    with patch("netops.core.bastion.subprocess.Popen", return_value=fake_child):
        with pytest.raises(RuntimeError, match="could not connect to bastion"):
            connect_active_bastion("bastion.example.com", "netops", 22, None, "hunter2")  # noqa: S106


def test_disconnect_active_bastion_notifies_control_endpoint_and_clears_state(monkeypatch) -> None:
    state = ActiveBastion(
        host="bastion.example.com",
        port=22,
        username="netops",
        key_file=None,
        socks_host="127.0.0.1",
        socks_port=1,
        control_host="127.0.0.1",
        control_port=2,
        token="t" * 32,
        pid=99,
    )
    with (
        patch("netops.core.bastion._read_state", return_value=state),
        patch("netops.core.bastion._control_request", return_value={"ok": True}) as control_request,
        patch("netops.core.bastion.state_path", return_value=Path("/tmp/does-not-exist.json")),
    ):
        assert disconnect_active_bastion() is True

    control_request.assert_called_once_with(state, "disconnect")


def test_disconnect_active_bastion_is_false_when_nothing_selected() -> None:
    with patch("netops.core.bastion._read_state", return_value=None):
        assert disconnect_active_bastion() is False


def test_active_bastion_fails_closed_when_control_endpoint_unreachable() -> None:
    """A selected-but-unreachable bastion must not be treated as "no bastion"."""
    state = ActiveBastion(
        host="bastion.example.com",
        port=22,
        username="netops",
        key_file=None,
        socks_host="127.0.0.1",
        socks_port=1,
        control_host="127.0.0.1",
        control_port=2,
        token="t" * 32,
        pid=99,
    )
    with (
        patch("netops.core.bastion._read_state", return_value=state),
        patch("netops.core.bastion._control_request", side_effect=OSError("refused")),
    ):
        with pytest.raises(ActiveBastionUnavailableError):
            active_bastion()


def test_status_command_reports_disconnected_when_bastion_unreachable(monkeypatch, capsys) -> None:
    """The CLI `status` command must not crash when the bastion is unhealthy."""
    state = ActiveBastion(
        host="bastion.example.com",
        port=22,
        username="netops",
        key_file=None,
        socks_host="127.0.0.1",
        socks_port=1,
        control_host="127.0.0.1",
        control_port=2,
        token="t" * 32,
        pid=99,
    )
    with (
        patch("netops.core.bastion._read_state", return_value=state),
        patch("netops.core.bastion._control_request", side_effect=OSError("refused")),
    ):
        assert main(["status"]) == 0

    printed = json.loads(capsys.readouterr().out)
    assert printed["connected"] is False


def test_ssh_transport_reconnects_when_previous_transport_drops(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NETOPS_KNOWN_HOSTS", str(tmp_path / "known_hosts"))
    profile = ActiveBastion(
        host="bastion.example.com",
        port=22,
        username="netops",
        key_file=None,
        socks_host="127.0.0.1",
        socks_port=1,
        control_host="127.0.0.1",
        control_port=2,
        token="t" * 32,
        pid=0,
    )
    dead_client = MagicMock()
    dead_transport = MagicMock()
    dead_transport.is_active.return_value = False
    dead_client.get_transport.return_value = dead_transport

    new_client = MagicMock()
    new_transport = MagicMock()
    new_transport.is_active.return_value = True
    channel = MagicMock()
    new_transport.open_channel.return_value = channel
    new_client.get_transport.return_value = new_transport

    transport = _SshTransport(profile, "hunter2", None)  # noqa: S106
    transport._client = dead_client

    with patch("paramiko.SSHClient", return_value=new_client):
        result = transport.open_channel("10.0.0.9", 22, timeout=5)

    dead_client.close.assert_called_once()
    new_client.connect.assert_called_once()
    new_transport.open_channel.assert_called_once()
    assert result is channel


def test_bastion_service_stop_is_idempotent_and_releases_transport() -> None:
    state = ActiveBastion(
        host="bastion.example.com",
        port=22,
        username="netops",
        key_file=None,
        socks_host="127.0.0.1",
        socks_port=0,
        control_host="127.0.0.1",
        control_port=0,
        token="t" * 32,
        pid=0,
    )
    service = _BastionService(state, "hunter2", None)  # noqa: S106
    mock_client = MagicMock()
    service.transport._client = mock_client

    try:
        service.stop()
        service.stop()  # must be safe to call again after shutdown
    finally:
        service._socks.server_close()
        service._control.server_close()

    mock_client.close.assert_called_once()
