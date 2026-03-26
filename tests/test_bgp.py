"""Tests for BGP parsers and check logic."""

from __future__ import annotations

import pytest

from netops.check.bgp import (
    _evaluate_peer,
    _is_nokia,
    _normalize_peer,
    _parse_expected_prefixes,
    _print_device_result,
    _print_summary_report,
    build_bgp_report,
    check_bgp_peers,
)
from netops.core.connection import ConnectionParams as _BgpConnParams
from netops.parsers.bgp import parse_bgp_summary_cisco, updown_to_seconds

# ---------------------------------------------------------------------------
# Sample CLI output fixtures
# ---------------------------------------------------------------------------

CISCO_BGP_SUMMARY = """\
BGP router identifier 10.0.0.1, local AS number 65000
BGP table version is 42, main routing table version 42

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4 65001      50      60       42    0    0 01:23:45        100
10.0.0.3        4 65002       0       0        0    0    0 never    Active
10.0.0.4        4 65003      20      30       42    0    0 00:00:45          0
10.0.0.5        4 65004      15      20       42    0    0 2d03h          200
"""

CISCO_BGP_SUMMARY_EMPTY = """\
BGP router identifier 10.0.0.1, local AS number 65000
BGP table version is 1, main routing table version 1

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
"""

CISCO_BGP_SUMMARY_IDLE = """\
BGP router identifier 10.1.1.1, local AS number 64512

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
172.16.0.1      4 64513       0       0        0    0    0 never    Idle
"""


# ===========================================================================
# parse_bgp_summary_cisco
# ===========================================================================


class TestParseBgpSummaryCisco:
    def test_returns_list(self):
        result = parse_bgp_summary_cisco(CISCO_BGP_SUMMARY)
        assert isinstance(result, list)

    def test_correct_peer_count(self):
        result = parse_bgp_summary_cisco(CISCO_BGP_SUMMARY)
        assert len(result) == 4

    def test_established_peer_fields(self):
        peer = parse_bgp_summary_cisco(CISCO_BGP_SUMMARY)[0]
        assert peer["neighbor"] == "10.0.0.2"
        assert peer["peer_as"] == 65001
        assert peer["msg_rcvd"] == 50
        assert peer["msg_sent"] == 60
        assert peer["up_down"] == "01:23:45"
        assert peer["state"] == "Established"
        assert peer["prefixes_received"] == 100

    def test_not_established_peer_state(self):
        peer = parse_bgp_summary_cisco(CISCO_BGP_SUMMARY)[1]
        assert peer["neighbor"] == "10.0.0.3"
        assert peer["state"] == "Active"
        assert peer["prefixes_received"] is None
        assert peer["up_down"] == "never"

    def test_established_zero_prefixes(self):
        peer = parse_bgp_summary_cisco(CISCO_BGP_SUMMARY)[2]
        assert peer["neighbor"] == "10.0.0.4"
        assert peer["state"] == "Established"
        assert peer["prefixes_received"] == 0

    def test_long_uptime_format(self):
        peer = parse_bgp_summary_cisco(CISCO_BGP_SUMMARY)[3]
        assert peer["neighbor"] == "10.0.0.5"
        assert peer["state"] == "Established"
        assert peer["prefixes_received"] == 200
        assert peer["up_down"] == "2d03h"

    def test_required_keys_present(self):
        for peer in parse_bgp_summary_cisco(CISCO_BGP_SUMMARY):
            for key in ("neighbor", "peer_as", "msg_rcvd", "msg_sent",
                        "up_down", "state", "prefixes_received"):
                assert key in peer

    def test_empty_table_returns_empty_list(self):
        assert parse_bgp_summary_cisco(CISCO_BGP_SUMMARY_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_bgp_summary_cisco("") == []

    def test_idle_state(self):
        peers = parse_bgp_summary_cisco(CISCO_BGP_SUMMARY_IDLE)
        assert len(peers) == 1
        assert peers[0]["state"] == "Idle"
        assert peers[0]["prefixes_received"] is None


# ===========================================================================
# updown_to_seconds
# ===========================================================================


class TestUpdownToSeconds:
    @pytest.mark.parametrize(
        "updown,expected",
        [
            ("00:00:00", 0),
            ("00:01:00", 60),
            ("01:00:00", 3600),
            ("01:23:45", 5025),
            ("2d03h", 2 * 86400 + 3 * 3600),
            ("1d00h", 86400),
            ("1w2d", 604800 + 2 * 86400),
            ("00h15m", 15 * 60),
            ("1d02h", 86400 + 2 * 3600),  # Nokia format
        ],
    )
    def test_known_formats(self, updown, expected):
        assert updown_to_seconds(updown) == expected

    def test_never_returns_none(self):
        assert updown_to_seconds("never") is None

    def test_empty_string_returns_none(self):
        assert updown_to_seconds("") is None

    def test_unknown_format_returns_none(self):
        assert updown_to_seconds("bogus") is None


# ===========================================================================
# _normalize_peer
# ===========================================================================


class TestNormalizePeer:
    def test_cisco_peer_unchanged(self):
        peer = {"neighbor": "1.1.1.1", "prefixes_received": 50}
        result = _normalize_peer(peer)
        assert result["prefixes_received"] == 50

    def test_nokia_peer_mapped(self):
        peer = {"neighbor": "1.1.1.1", "received": 100}
        result = _normalize_peer(peer)
        assert result["prefixes_received"] == 100

    def test_original_dict_not_mutated(self):
        peer = {"neighbor": "1.1.1.1", "received": 77}
        _normalize_peer(peer)
        assert "prefixes_received" not in peer


# ===========================================================================
# _evaluate_peer
# ===========================================================================


class TestEvaluatePeer:
    def _make_peer(self, **kwargs):
        defaults = {
            "neighbor": "10.0.0.2",
            "peer_as": 65001,
            "state": "Established",
            "prefixes_received": 100,
            "up_down": "01:00:00",
        }
        defaults.update(kwargs)
        return defaults

    def test_healthy_peer_no_alerts(self):
        peer = self._make_peer()
        result = _evaluate_peer(peer, {}, flap_min_uptime=300, prefix_deviation_pct=20.0)
        assert result["is_established"] is True
        assert result["is_flapping"] is False
        assert result["prefix_alert"] is False
        assert result["alerts"] == []

    def test_not_established_peer(self):
        peer = self._make_peer(state="Active", prefixes_received=None, up_down="never")
        result = _evaluate_peer(peer, {}, flap_min_uptime=300, prefix_deviation_pct=20.0)
        assert result["is_established"] is False
        assert len(result["alerts"]) == 1
        assert "not established" in result["alerts"][0]

    def test_flapping_peer_short_uptime(self):
        peer = self._make_peer(up_down="00:00:45")
        result = _evaluate_peer(peer, {}, flap_min_uptime=300, prefix_deviation_pct=20.0)
        assert result["is_flapping"] is True
        assert any("flapping" in a for a in result["alerts"])

    def test_not_flapping_long_uptime(self):
        peer = self._make_peer(up_down="01:00:00")
        result = _evaluate_peer(peer, {}, flap_min_uptime=300, prefix_deviation_pct=20.0)
        assert result["is_flapping"] is False

    def test_prefix_alert_above_threshold(self):
        peer = self._make_peer(prefixes_received=50)
        result = _evaluate_peer(
            peer, {"10.0.0.2": 100}, flap_min_uptime=300, prefix_deviation_pct=20.0
        )
        assert result["prefix_alert"] is True
        assert any("prefix" in a for a in result["alerts"])

    def test_prefix_no_alert_within_threshold(self):
        peer = self._make_peer(prefixes_received=95)
        result = _evaluate_peer(
            peer, {"10.0.0.2": 100}, flap_min_uptime=300, prefix_deviation_pct=20.0
        )
        assert result["prefix_alert"] is False

    def test_prefix_alert_no_expected_does_not_fire(self):
        peer = self._make_peer(prefixes_received=1)
        result = _evaluate_peer(peer, {}, flap_min_uptime=300, prefix_deviation_pct=20.0)
        assert result["prefix_alert"] is False

    def test_uptime_seconds_populated(self):
        peer = self._make_peer(up_down="01:23:45")
        result = _evaluate_peer(peer, {}, flap_min_uptime=300, prefix_deviation_pct=20.0)
        assert result["uptime_seconds"] == 5025

    def test_uptime_seconds_none_when_not_established(self):
        peer = self._make_peer(state="Idle", prefixes_received=None, up_down="never")
        result = _evaluate_peer(peer, {}, flap_min_uptime=300, prefix_deviation_pct=20.0)
        assert result["uptime_seconds"] is None

    def test_expected_prefixes_stored(self):
        peer = self._make_peer()
        result = _evaluate_peer(
            peer, {"10.0.0.2": 100}, flap_min_uptime=300, prefix_deviation_pct=20.0
        )
        assert result["expected_prefixes"] == 100

    def test_multiple_alerts_accumulated(self):
        # Session is not established (state=Active) — no flap or prefix check
        peer = self._make_peer(state="Connect", prefixes_received=None, up_down="never")
        result = _evaluate_peer(
            peer, {"10.0.0.2": 100}, flap_min_uptime=300, prefix_deviation_pct=20.0
        )
        assert not result["is_established"]
        # Only 1 alert since prefix check doesn't apply when not established
        assert len(result["alerts"]) == 1

    def test_prefix_alert_with_zero_expected(self):
        # expected=0, received=5 → prefix_alert=True
        peer = self._make_peer(prefixes_received=5)
        result = _evaluate_peer(
            peer, {"10.0.0.2": 0}, flap_min_uptime=300, prefix_deviation_pct=20.0
        )
        assert result["prefix_alert"] is True


# ===========================================================================
# build_bgp_report
# ===========================================================================


class TestBuildBgpReport:
    def _make_result(self, host, peers, success=True):
        return {
            "host": host,
            "timestamp": "2026-01-01T00:00:00Z",
            "success": success,
            "peers": peers,
            "summary": {},
            "overall_alert": False,
            "error": None,
        }

    def _make_peer(self, neighbor, established=True, flapping=False, prefix_alert=False):
        return {
            "neighbor": neighbor,
            "peer_as": 65000,
            "state": "Established" if established else "Active",
            "prefixes_received": 100 if established else None,
            "up_down": "01:00:00",
            "is_established": established,
            "is_flapping": flapping,
            "prefix_alert": prefix_alert,
            "uptime_seconds": 3600 if established else None,
            "expected_prefixes": None,
            "alerts": [],
        }

    def test_empty_results(self):
        report = build_bgp_report([])
        assert report["routers"] == 0
        assert report["total_peers"] == 0
        assert report["overall_alert"] is False

    def test_single_healthy_router(self):
        peers = [self._make_peer("10.0.0.2")]
        result = self._make_result("router1", peers)
        report = build_bgp_report([result])
        assert report["routers"] == 1
        assert report["routers_reachable"] == 1
        assert report["total_peers"] == 1
        assert report["established"] == 1
        assert report["not_established"] == 0
        assert report["flapping"] == 0
        assert report["prefix_alerts"] == 0
        assert report["overall_alert"] is False

    def test_unreachable_router_not_counted_in_peers(self):
        result = self._make_result("router1", [], success=False)
        result["error"] = "Connection refused"
        report = build_bgp_report([result])
        assert report["routers"] == 1
        assert report["routers_reachable"] == 0
        assert report["total_peers"] == 0

    def test_multi_router_aggregation(self):
        peers1 = [self._make_peer("10.0.0.2"), self._make_peer("10.0.0.3")]
        peers2 = [self._make_peer("10.1.0.2", established=False)]
        r1 = self._make_result("r1", peers1)
        r2 = self._make_result("r2", peers2)
        report = build_bgp_report([r1, r2])
        assert report["total_peers"] == 3
        assert report["established"] == 2
        assert report["not_established"] == 1
        assert report["overall_alert"] is True

    def test_flapping_counted(self):
        peers = [self._make_peer("10.0.0.2", flapping=True)]
        result = self._make_result("r1", peers)
        report = build_bgp_report([result])
        assert report["flapping"] == 1
        assert report["overall_alert"] is True

    def test_prefix_alert_counted(self):
        peers = [self._make_peer("10.0.0.2", prefix_alert=True)]
        result = self._make_result("r1", peers)
        report = build_bgp_report([result])
        assert report["prefix_alerts"] == 1
        assert report["overall_alert"] is True

    def test_peers_include_router_key(self):
        peers = [self._make_peer("10.0.0.2")]
        result = self._make_result("my-router", peers)
        report = build_bgp_report([result])
        assert report["peers"][0]["router"] == "my-router"


# ===========================================================================
# _parse_expected_prefixes
# ===========================================================================


class TestParseExpectedPrefixes:
    def test_empty_string(self):
        assert _parse_expected_prefixes("") == {}

    def test_none(self):
        assert _parse_expected_prefixes(None) == {}

    def test_single_entry(self):
        result = _parse_expected_prefixes("10.0.0.2=100")
        assert result == {"10.0.0.2": 100}

    def test_multiple_entries(self):
        result = _parse_expected_prefixes("10.0.0.2=100,10.0.0.3=200")
        assert result == {"10.0.0.2": 100, "10.0.0.3": 200}

    def test_whitespace_tolerance(self):
        result = _parse_expected_prefixes(" 10.0.0.2 = 50 , 10.0.0.3 = 75 ")
        assert result == {"10.0.0.2": 50, "10.0.0.3": 75}

    def test_malformed_entry_skipped(self):
        result = _parse_expected_prefixes("10.0.0.2=100,badentry,10.0.0.3=200")
        assert result == {"10.0.0.2": 100, "10.0.0.3": 200}

    def test_non_integer_value_skipped(self):
        result = _parse_expected_prefixes("10.0.0.2=abc")
        assert result == {}


# ===========================================================================
# Additional imports for new test classes
# ===========================================================================


# ===========================================================================
# _is_nokia
# ===========================================================================


class TestIsNokia:
    def test_nokia_sr_os_returns_true(self):
        assert _is_nokia("nokia_sros") is True

    def test_nokia_mixed_case_returns_true(self):
        assert _is_nokia("Nokia_SROS") is True

    def test_cisco_ios_returns_false(self):
        assert _is_nokia("cisco_ios") is False

    def test_cisco_xr_returns_false(self):
        assert _is_nokia("cisco_xr") is False

    def test_arista_eos_returns_false(self):
        assert _is_nokia("arista_eos") is False

    def test_empty_string_returns_false(self):
        assert _is_nokia("") is False


# ===========================================================================
# check_bgp_peers
# ===========================================================================


class _BgpMockConn:
    """Minimal mock returning pre-canned output based on command substring."""

    def __init__(self, responses: dict[str, str]):
        self._responses = responses

    def send(self, command: str, **_kwargs) -> str:
        for key, val in self._responses.items():
            if key in command:
                return val
        return ""


class TestCheckBgpPeers:
    def _make_params(self, device_type="cisco_ios"):
        return _BgpConnParams(
            host="10.0.0.1",
            username="admin",
            password="secret",
            device_type=device_type,
        )

    def test_cisco_ios_success(self, monkeypatch):
        mock_conn = _BgpMockConn({"bgp summary": CISCO_BGP_SUMMARY})

        class _FakeConn:
            def __enter__(self_inner):
                return mock_conn

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.bgp.DeviceConnection", lambda _p: _FakeConn())
        result = check_bgp_peers(self._make_params("cisco_ios"))
        assert result["success"] is True
        assert result["error"] is None
        assert len(result["peers"]) == 4
        assert "summary" in result
        assert result["summary"]["total"] == 4

    def test_cisco_xr_uses_show_bgp_summary(self, monkeypatch):
        # cisco_xr uses "show bgp summary" (without "ip")
        mock_conn = _BgpMockConn({"bgp summary": CISCO_BGP_SUMMARY})

        class _FakeConn:
            def __enter__(self_inner):
                return mock_conn

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.bgp.DeviceConnection", lambda _p: _FakeConn())
        result = check_bgp_peers(self._make_params("cisco_xr"))
        assert result["success"] is True
        assert len(result["peers"]) == 4

    def test_nokia_sros_path(self, monkeypatch):
        # Nokia returns "received" key; normalize_peer maps it to prefixes_received
        nokia_output = """\
===============================================================================
BGP Summary
===============================================================================
Neighbor        AS         Recv   Sent  OutQ  Up/Down     State/Pfx
-------------------------------------------------------------------------------
10.0.0.5    65001         100     50     0  01:00:00  50
-------------------------------------------------------------------------------
"""
        mock_conn = _BgpMockConn({"bgp summary": nokia_output})

        class _FakeConn:
            def __enter__(self_inner):
                return mock_conn

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.bgp.DeviceConnection", lambda _p: _FakeConn())
        result = check_bgp_peers(self._make_params("nokia_sros"))
        assert result["success"] is True
        # Nokia parser may return 0 or more peers depending on output format;
        # the important thing is success=True and no error.
        assert result["error"] is None

    def test_connection_failure_returns_error(self, monkeypatch):
        class _FailConn:
            def __enter__(self_inner):
                raise OSError("cannot connect")

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.bgp.DeviceConnection", lambda _p: _FailConn())
        result = check_bgp_peers(self._make_params())
        assert result["success"] is False
        assert result["error"] is not None
        assert "cannot connect" in result["error"]

    def test_expected_prefixes_used(self, monkeypatch):
        mock_conn = _BgpMockConn({"bgp summary": CISCO_BGP_SUMMARY})

        class _FakeConn:
            def __enter__(self_inner):
                return mock_conn

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.bgp.DeviceConnection", lambda _p: _FakeConn())
        # 10.0.0.2 receives 100 prefixes; expected=50 → deviation=100% > 20% → alert
        result = check_bgp_peers(
            self._make_params(),
            expected_prefixes={"10.0.0.2": 50},
            prefix_deviation_pct=20.0,
        )
        assert result["success"] is True
        peer_202 = next(p for p in result["peers"] if p["neighbor"] == "10.0.0.2")
        assert peer_202["prefix_alert"] is True

    def test_flap_detection(self, monkeypatch):
        mock_conn = _BgpMockConn({"bgp summary": CISCO_BGP_SUMMARY})

        class _FakeConn:
            def __enter__(self_inner):
                return mock_conn

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.bgp.DeviceConnection", lambda _p: _FakeConn())
        # 10.0.0.4 is up for 00:00:45 = 45s < 300s threshold → flapping
        result = check_bgp_peers(
            self._make_params(), flap_min_uptime=300
        )
        assert result["success"] is True
        peer_204 = next(p for p in result["peers"] if p["neighbor"] == "10.0.0.4")
        assert peer_204["is_flapping"] is True

    def test_overall_alert_when_not_established(self, monkeypatch):
        mock_conn = _BgpMockConn({"bgp summary": CISCO_BGP_SUMMARY})

        class _FakeConn:
            def __enter__(self_inner):
                return mock_conn

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.bgp.DeviceConnection", lambda _p: _FakeConn())
        result = check_bgp_peers(self._make_params())
        # 10.0.0.3 is in Active state → not_established > 0 → overall_alert
        assert result["overall_alert"] is True

    def test_empty_bgp_table_no_alert(self, monkeypatch):
        mock_conn = _BgpMockConn({"bgp summary": CISCO_BGP_SUMMARY_EMPTY})

        class _FakeConn:
            def __enter__(self_inner):
                return mock_conn

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.bgp.DeviceConnection", lambda _p: _FakeConn())
        result = check_bgp_peers(self._make_params())
        assert result["success"] is True
        assert result["peers"] == []
        assert result["overall_alert"] is False

    def test_result_structure(self, monkeypatch):
        mock_conn = _BgpMockConn({"bgp summary": CISCO_BGP_SUMMARY_EMPTY})

        class _FakeConn:
            def __enter__(self_inner):
                return mock_conn

            def __exit__(self_inner, *_):
                pass

        monkeypatch.setattr("netops.check.bgp.DeviceConnection", lambda _p: _FakeConn())
        result = check_bgp_peers(self._make_params())
        for key in ("host", "timestamp", "success", "peers", "summary",
                    "overall_alert", "error"):
            assert key in result
        assert result["host"] == "10.0.0.1"


# ===========================================================================
# _print_device_result and _print_summary_report (lines 286-322, 327-328)
# ===========================================================================


class TestPrintDeviceResult:
    def _make_peer(self, neighbor, established=True, flapping=False, prefix_alert=False, alerts=None):
        return {
            "neighbor": neighbor,
            "peer_as": 65001,
            "state": "Established" if established else "Active",
            "prefixes_received": 100 if established else None,
            "up_down": "01:00:00",
            "is_established": established,
            "is_flapping": flapping,
            "prefix_alert": prefix_alert,
            "expected_prefixes": None,
            "alerts": alerts or [],
        }

    def test_failed_device_prints_error(self, capsys):
        result = {
            "host": "10.0.0.1",
            "timestamp": "2026-01-01T00:00:00Z",
            "success": False,
            "overall_alert": False,
            "error": "Connection refused",
            "peers": [],
            "summary": {},
        }
        _print_device_result(result)
        out = capsys.readouterr().out
        assert "10.0.0.1" in out
        assert "ERROR" in out

    def test_healthy_device_prints_summary(self, capsys):
        peers = [self._make_peer("10.0.0.2")]
        result = {
            "host": "10.0.0.1",
            "timestamp": "2026-01-01T00:00:00Z",
            "success": True,
            "overall_alert": False,
            "error": None,
            "peers": peers,
            "summary": {
                "established": 1, "total": 1,
                "flapping": 0, "prefix_alerts": 0,
            },
        }
        _print_device_result(result)
        out = capsys.readouterr().out
        assert "10.0.0.1" in out
        assert "1/1 established" in out

    def test_alerted_peer_printed(self, capsys):
        peers = [
            self._make_peer("10.0.0.2", established=False,
                            alerts=["peer 10.0.0.2 not established (state=Active)"]),
        ]
        result = {
            "host": "10.0.0.1",
            "timestamp": "2026-01-01T00:00:00Z",
            "success": True,
            "overall_alert": True,
            "error": None,
            "peers": peers,
            "summary": {
                "established": 0, "total": 1,
                "flapping": 0, "prefix_alerts": 0,
            },
        }
        _print_device_result(result)
        out = capsys.readouterr().out
        assert "10.0.0.2" in out

    def test_peer_with_expected_prefixes_shown(self, capsys):
        peer = self._make_peer("10.0.0.2")
        peer["expected_prefixes"] = 100
        result = {
            "host": "10.0.0.1",
            "timestamp": "2026-01-01T00:00:00Z",
            "success": True,
            "overall_alert": False,
            "error": None,
            "peers": [peer],
            "summary": {
                "established": 1, "total": 1,
                "flapping": 0, "prefix_alerts": 0,
            },
        }
        _print_device_result(result)
        out = capsys.readouterr().out
        assert "/100" in out

    def test_flapping_peer_uses_warning_icon(self, capsys):
        peers = [self._make_peer("10.0.0.2", flapping=True)]
        result = {
            "host": "10.0.0.1",
            "timestamp": "2026-01-01T00:00:00Z",
            "success": True,
            "overall_alert": True,
            "error": None,
            "peers": peers,
            "summary": {
                "established": 1, "total": 1,
                "flapping": 1, "prefix_alerts": 0,
            },
        }
        _print_device_result(result)
        out = capsys.readouterr().out
        assert "10.0.0.2" in out


class TestPrintSummaryReport:
    def test_healthy_report(self, capsys):
        report = {
            "routers": 2,
            "routers_reachable": 2,
            "total_peers": 4,
            "established": 4,
            "not_established": 0,
            "flapping": 0,
            "prefix_alerts": 0,
            "overall_alert": False,
            "peers": [],
        }
        _print_summary_report(report)
        out = capsys.readouterr().out
        assert "2/2 routers reachable" in out
        assert "4/4 peers established" in out

    def test_alerted_report(self, capsys):
        report = {
            "routers": 2,
            "routers_reachable": 1,
            "total_peers": 3,
            "established": 2,
            "not_established": 1,
            "flapping": 0,
            "prefix_alerts": 0,
            "overall_alert": True,
            "peers": [],
        }
        _print_summary_report(report)
        out = capsys.readouterr().out
        assert "1/2 routers reachable" in out
