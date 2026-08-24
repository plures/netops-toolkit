"""Secret-boundary tests for deep scan and the app event-stream contract."""

from __future__ import annotations

import json
from unittest.mock import patch

from netops.core.community import CommunityRegistry
from netops.inventory.scan import _emit_event_stream, deep_enrich, main


def test_deep_enrich_stores_communities_without_putting_them_in_inventory(tmp_path, caplog):
    """Collected SNMP communities stay in the privileged registry and logs redact them."""
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
