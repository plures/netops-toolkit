"""Tests for netops.collect.config — device configuration collection.

All network I/O (DeviceConnection) is mocked so tests run without real devices.
"""

from __future__ import annotations

from netops.collect.config import collect_config
from netops.core.connection import ConnectionParams


def _make_params(device_type: str = "cisco_ios") -> ConnectionParams:
    return ConnectionParams(
        host="10.0.0.1",
        username="admin",
        password="secret",
        device_type=device_type,
    )


class _MockConn:
    """Minimal send()-capable connection stub."""

    def __init__(self, response: str) -> None:
        self._response = response

    def send(self, command: str, **_kwargs: object) -> str:  # noqa: ARG002
        return self._response


def _fake_device_connection(response: str) -> object:
    """Return a context-manager stub that yields a _MockConn."""

    class _FakeConn:
        def __enter__(self_inner) -> _MockConn:
            return _MockConn(response)

        def __exit__(self_inner, *_args: object) -> None:
            pass

    return _FakeConn()


# ===========================================================================
# collect_config
# ===========================================================================


class TestCollectConfig:
    def test_success_cisco_returns_config(self, monkeypatch: object) -> None:
        monkeypatch.setattr(
            "netops.collect.config.DeviceConnection",
            lambda _p: _fake_device_connection("hostname rtr1\ninterface Gi0/0\n"),
        )
        result = collect_config(_make_params())

        assert result["success"] is True
        assert result["config"] == "hostname rtr1\ninterface Gi0/0\n"
        assert result["lines"] == 2
        assert result["host"] == "10.0.0.1"
        assert result["error"] is None

    def test_success_sets_device_type(self, monkeypatch: object) -> None:
        monkeypatch.setattr(
            "netops.collect.config.DeviceConnection",
            lambda _p: _fake_device_connection("config\n"),
        )
        result = collect_config(_make_params())
        assert result["device_type"] == "cisco_ios"

    def test_success_nokia_uses_display_config(self, monkeypatch: object) -> None:
        """Nokia path sends 'admin display-config' instead of 'show running-config'."""
        sent_commands: list[str] = []

        class _TrackingConn:
            def send(self_inner, command: str, **_: object) -> str:
                sent_commands.append(command)
                return "configure\n    system\n"

        class _FakeConn:
            def __enter__(self_inner) -> _TrackingConn:
                return _TrackingConn()

            def __exit__(self_inner, *_: object) -> None:
                pass

        monkeypatch.setattr(
            "netops.collect.config.DeviceConnection",
            lambda _p: _FakeConn(),
        )
        result = collect_config(_make_params(device_type="nokia_sros"))

        assert result["success"] is True
        assert any("display-config" in cmd for cmd in sent_commands)

    def test_exception_marks_failure(self, monkeypatch: object) -> None:
        def _raise(_p: object) -> None:
            raise OSError("connection refused")

        monkeypatch.setattr("netops.collect.config.DeviceConnection", _raise)
        result = collect_config(_make_params())

        assert result["success"] is False
        assert result["config"] is None
        assert "connection refused" in (result["error"] or "")

    def test_collected_at_present(self, monkeypatch: object) -> None:
        monkeypatch.setattr(
            "netops.collect.config.DeviceConnection",
            lambda _p: _fake_device_connection(""),
        )
        result = collect_config(_make_params())
        assert "collected_at" in result
        assert result["collected_at"]  # non-empty string
