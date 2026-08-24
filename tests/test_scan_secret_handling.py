"""Secret-boundary tests for deep scan and the app event-stream contract."""

from __future__ import annotations

import io
import json
import logging
from unittest.mock import patch

import pytest

from netops.core.community import CommunityRegistry
from netops.inventory.scan import _emit_event_stream, deep_enrich, main


def test_deep_enrich_stores_communities_without_putting_them_in_inventory(tmp_path, caplog):
    """Collected SNMP communities stay in the privileged registry and logs redact them."""
    caplog.set_level(logging.INFO, logger="netops.inventory.scan")
    registry = CommunityRegistry(tmp_path / "communities.json")
    fragment = {"devices": {"edge": {"host": "10.0.0.9", "vendor": "cisco_ios"}}}

    with patch(
        "netops.inventory.scan._deep_scan_host",
        return_value={
            "vendor": "cisco_ios",
            "version": "17.9",
            "communities": ["not-for-inventory"],
        },
    ):
        result = deep_enrich(
            fragment,
            username="admin",
            password="ssh-password",
            community_registry=registry,
        )

    assert "communities" not in result["devices"]["edge"]
    assert registry.get_device("10.0.0.9")["community"] == "not-for-inventory"
    assert "not-for-inventory" not in caplog.text


def test_deep_enrich_continues_when_community_registry_write_fails(caplog):
    """Registry persistence is auxiliary to SSH inventory enrichment."""

    class FailingRegistry:
        def set_device(self, host, community, vendor=None):
            raise OSError("registry read-only")

    caplog.set_level(logging.INFO, logger="netops.inventory.scan")
    fragment = {"devices": {"edge": {"host": "10.0.0.9", "vendor": "unknown"}}}

    with patch(
        "netops.inventory.scan._deep_scan_host",
        return_value={
            "vendor": "cisco_ios",
            "version": "17.9",
            "model": "C9300",
            "communities": ["not-for-logs"],
        },
    ):
        result = deep_enrich(
            fragment,
            username="admin",
            **{"password": "ssh-secret"},
            community_registry=FailingRegistry(),
        )

    assert result["devices"]["edge"]["vendor"] == "cisco_ios"
    assert result["devices"]["edge"]["version"] == "17.9"
    assert result["devices"]["edge"]["model"] == "C9300"
    assert "10.0.0.9" in caplog.text
    assert "not-for-logs" not in caplog.text


def test_event_stream_emits_the_desktop_jsonl_contract(capsys):
    """The desktop client receives real scan rows rather than a file artifact."""
    _emit_event_stream(
        {
            "devices": {
                "router-01": {
                    "host": "192.0.2.1",
                    "vendor": "cisco_ios",
                    "version": "17.9",
                    "model": "C9300",
                    "serial": "ABC123",
                }
            }
        },
        duration_ms=25,
    )

    lines = capsys.readouterr().out.splitlines()
    assert '"type": "device"' in lines[0]
    assert '"type": "complete"' in lines[-1]


def test_scan_cli_event_stream_is_jsonl_for_the_desktop(tmp_path, monkeypatch, capsys):
    """The CLI event mode uses stdout only for structured app events."""
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("192.0.2.10\n")
    monkeypatch.setattr(
        "sys.argv",
        ["scan", "--hosts-file", str(hosts), "--event-stream"],
    )

    main()

    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [event["type"] for event in events] == ["device", "progress", "complete"]
    assert events[0]["ip"] == "192.0.2.10"


def test_scan_cli_password_stdin_uses_exact_stdin_value(tmp_path, monkeypatch):
    """stdin-selected credentials take precedence over every ambient source."""
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("192.0.2.10\n")
    monkeypatch.setenv("NETOPS_PASSWORD", "env-secret")
    monkeypatch.setattr("sys.stdin", io.StringIO("stdin-secret\n"))
    monkeypatch.setattr(
        "sys.argv",
        [
            "scan",
            "--hosts-file",
            str(hosts),
            "--user",
            "admin",
            "--password-stdin",
        ],
    )

    with patch("netops.inventory.scan.deep_enrich", side_effect=lambda fragment, **kwargs: fragment) as enrich:
        main()

    assert enrich.call_args.kwargs["password"] == "stdin-secret"


@pytest.mark.parametrize("stdin_text", ["\n", ""])
def test_scan_cli_password_stdin_blank_or_eof_does_not_use_environment(
    tmp_path,
    monkeypatch,
    stdin_text,
):
    """Blank and EOF stdin are not replaced with NETOPS_PASSWORD."""
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("192.0.2.10\n")
    monkeypatch.setenv("NETOPS_PASSWORD", "env-secret")
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    monkeypatch.setattr(
        "sys.argv",
        [
            "scan",
            "--hosts-file",
            str(hosts),
            "--user",
            "admin",
            "--password-stdin",
        ],
    )

    with patch("netops.inventory.scan.deep_enrich") as enrich, pytest.raises(SystemExit):
        main()

    enrich.assert_not_called()


def test_scan_cli_password_env_is_used_without_password_stdin(tmp_path, monkeypatch):
    """Environment fallback remains available when stdin mode is not selected."""
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("192.0.2.10\n")
    monkeypatch.setenv("NETOPS_PASSWORD", "env-secret")
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    monkeypatch.setattr(
        "sys.argv",
        ["scan", "--hosts-file", str(hosts), "--user", "admin"],
    )

    with patch("netops.inventory.scan.deep_enrich", side_effect=lambda fragment, **kwargs: fragment) as enrich:
        main()

    assert enrich.call_args.kwargs["password"] == "env-secret"
