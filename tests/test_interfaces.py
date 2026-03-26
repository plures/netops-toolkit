"""Tests for interface status check and parser functions."""

from __future__ import annotations

from netops.check.interfaces import check_interfaces, parse_cisco_interfaces
from netops.core.connection import ConnectionParams

# ---------------------------------------------------------------------------
# Sample CLI output fixtures
# ---------------------------------------------------------------------------

CISCO_INTF_BRIEF = """\
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up
GigabitEthernet0/1     unassigned      YES NVRAM  administratively down down
GigabitEthernet0/2     192.168.1.1     YES NVRAM  up                    up
GigabitEthernet0/3     unassigned      YES NVRAM  down                  down
"""

CISCO_INTF_BRIEF_ALL_UP = """\
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up
GigabitEthernet0/1     172.16.0.1      YES NVRAM  up                    up
"""

CISCO_INTF_BRIEF_EMPTY = """\
Interface              IP-Address      OK? Method Status                Protocol
"""

NOKIA_PORT_OUTPUT = """\
Port          Admin Link Port    Cfg  Oper MTU   Interface
              State  State State Enc  Enc
-------------------------------------------------------------------------------
1/1/1         Up    Yes  Up     null null 9212   10-Gig Ethernet
1/1/2         Up    No   Down   null null 9212   10-Gig Ethernet
1/1/3         Down  No   Down   null null 9212   10-Gig Ethernet
"""


# ---------------------------------------------------------------------------
# _MockConn helper
# ---------------------------------------------------------------------------


class _MockConn:
    def __init__(self, responses: dict[str, str]):
        self._responses = responses

    def send(self, command: str, **_kwargs) -> str:
        for key, value in self._responses.items():
            if key in command:
                return value
        return ""


# ===========================================================================
# parse_cisco_interfaces
# ===========================================================================


class TestParseCiscoInterfaces:
    def test_returns_list(self):
        result = parse_cisco_interfaces(CISCO_INTF_BRIEF)
        assert isinstance(result, list)

    def test_correct_interface_count(self):
        result = parse_cisco_interfaces(CISCO_INTF_BRIEF)
        assert len(result) == 4

    def test_interface_fields_present(self):
        result = parse_cisco_interfaces(CISCO_INTF_BRIEF)
        for iface in result:
            for key in ("name", "ip", "status", "protocol", "up"):
                assert key in iface

    def test_up_interface(self):
        result = parse_cisco_interfaces(CISCO_INTF_BRIEF)
        gi00 = next(i for i in result if i["name"] == "GigabitEthernet0/0")
        assert gi00["ip"] == "10.0.0.1"
        assert gi00["status"] == "up"
        assert gi00["protocol"] == "up"
        assert gi00["up"] is True

    def test_admin_down_interface(self):
        result = parse_cisco_interfaces(CISCO_INTF_BRIEF)
        gi01 = next(i for i in result if i["name"] == "GigabitEthernet0/1")
        assert gi01["ip"] is None
        assert gi01["status"] == "administratively down"
        assert gi01["up"] is False

    def test_down_interface(self):
        result = parse_cisco_interfaces(CISCO_INTF_BRIEF)
        gi03 = next(i for i in result if i["name"] == "GigabitEthernet0/3")
        assert gi03["status"] == "down"
        assert gi03["up"] is False

    def test_unassigned_ip_returns_none(self):
        result = parse_cisco_interfaces(CISCO_INTF_BRIEF)
        gi01 = next(i for i in result if i["name"] == "GigabitEthernet0/1")
        assert gi01["ip"] is None

    def test_assigned_ip_present(self):
        result = parse_cisco_interfaces(CISCO_INTF_BRIEF)
        gi02 = next(i for i in result if i["name"] == "GigabitEthernet0/2")
        assert gi02["ip"] == "192.168.1.1"

    def test_all_up_interfaces(self):
        result = parse_cisco_interfaces(CISCO_INTF_BRIEF_ALL_UP)
        assert len(result) == 2
        assert all(i["up"] for i in result)

    def test_empty_output_returns_empty_list(self):
        assert parse_cisco_interfaces(CISCO_INTF_BRIEF_EMPTY) == []

    def test_blank_string_returns_empty_list(self):
        assert parse_cisco_interfaces("") == []

    def test_header_line_not_parsed(self):
        result = parse_cisco_interfaces(CISCO_INTF_BRIEF)
        names = [i["name"] for i in result]
        assert "Interface" not in names

    def test_up_count(self):
        result = parse_cisco_interfaces(CISCO_INTF_BRIEF)
        up_count = sum(1 for i in result if i["up"])
        assert up_count == 2

    def test_down_count(self):
        result = parse_cisco_interfaces(CISCO_INTF_BRIEF)
        down_count = sum(1 for i in result if not i["up"])
        assert down_count == 2


# ===========================================================================
# check_interfaces — Cisco path
# ===========================================================================


class TestCheckInterfacesCisco:
    def _make_params(self, device_type: str = "cisco_ios") -> ConnectionParams:
        return ConnectionParams(host="192.0.2.1", username="admin", device_type=device_type)

    def _fake_conn(self, responses: dict[str, str]):
        class _FakeConn:
            def __enter__(self_inner):
                return _MockConn(responses)

            def __exit__(self_inner, *_):
                pass

        return _FakeConn()

    def test_success_flag_set(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.interfaces.DeviceConnection",
            lambda _p: self._fake_conn({"show ip interface brief": CISCO_INTF_BRIEF}),
        )
        result = check_interfaces(self._make_params())
        assert result["success"] is True

    def test_host_in_result(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.interfaces.DeviceConnection",
            lambda _p: self._fake_conn({"show ip interface brief": CISCO_INTF_BRIEF}),
        )
        result = check_interfaces(self._make_params())
        assert result["host"] == "192.0.2.1"

    def test_interfaces_list_populated(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.interfaces.DeviceConnection",
            lambda _p: self._fake_conn({"show ip interface brief": CISCO_INTF_BRIEF}),
        )
        result = check_interfaces(self._make_params())
        assert len(result["interfaces"]) == 4

    def test_summary_fields_present(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.interfaces.DeviceConnection",
            lambda _p: self._fake_conn({"show ip interface brief": CISCO_INTF_BRIEF}),
        )
        result = check_interfaces(self._make_params())
        for key in ("total", "up", "down"):
            assert key in result["summary"]

    def test_summary_totals_correct(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.interfaces.DeviceConnection",
            lambda _p: self._fake_conn({"show ip interface brief": CISCO_INTF_BRIEF}),
        )
        result = check_interfaces(self._make_params())
        assert result["summary"]["total"] == 4
        assert result["summary"]["up"] == 2
        assert result["summary"]["down"] == 2

    def test_down_only_filters_correctly(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.interfaces.DeviceConnection",
            lambda _p: self._fake_conn({"show ip interface brief": CISCO_INTF_BRIEF}),
        )
        result = check_interfaces(self._make_params(), down_only=True)
        assert result["success"] is True
        assert all(not i["up"] for i in result["interfaces"])
        assert len(result["interfaces"]) == 2

    def test_down_only_false_returns_all(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.interfaces.DeviceConnection",
            lambda _p: self._fake_conn({"show ip interface brief": CISCO_INTF_BRIEF}),
        )
        result = check_interfaces(self._make_params(), down_only=False)
        assert len(result["interfaces"]) == 4

    def test_all_up_no_down_interfaces(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.interfaces.DeviceConnection",
            lambda _p: self._fake_conn({"show ip interface brief": CISCO_INTF_BRIEF_ALL_UP}),
        )
        result = check_interfaces(self._make_params(), down_only=True)
        assert result["success"] is True
        assert result["interfaces"] == []

    def test_error_handling(self, monkeypatch):
        def _raise(_p):
            raise ConnectionError("timeout")

        monkeypatch.setattr("netops.check.interfaces.DeviceConnection", _raise)
        result = check_interfaces(self._make_params())
        assert result["success"] is False
        assert "timeout" in result["error"]

    def test_error_result_has_empty_interfaces(self, monkeypatch):
        def _raise(_p):
            raise OSError("unreachable")

        monkeypatch.setattr("netops.check.interfaces.DeviceConnection", _raise)
        result = check_interfaces(self._make_params())
        assert result["interfaces"] == []
        assert result["summary"] == {}


# ===========================================================================
# check_interfaces — Nokia path
# ===========================================================================


class TestCheckInterfacesNokia:
    def _make_params(self, device_type: str = "nokia_sros") -> ConnectionParams:
        return ConnectionParams(host="10.0.0.5", username="admin", device_type=device_type)

    def _fake_conn(self, responses: dict[str, str]):
        class _FakeConn:
            def __enter__(self_inner):
                return _MockConn(responses)

            def __exit__(self_inner, *_):
                pass

        return _FakeConn()

    def test_success_flag_set(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.interfaces.DeviceConnection",
            lambda _p: self._fake_conn({"show port": NOKIA_PORT_OUTPUT}),
        )
        result = check_interfaces(self._make_params())
        assert result["success"] is True

    def test_interfaces_populated(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.interfaces.DeviceConnection",
            lambda _p: self._fake_conn({"show port": NOKIA_PORT_OUTPUT}),
        )
        result = check_interfaces(self._make_params())
        assert len(result["interfaces"]) == 3

    def test_summary_totals(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.interfaces.DeviceConnection",
            lambda _p: self._fake_conn({"show port": NOKIA_PORT_OUTPUT}),
        )
        result = check_interfaces(self._make_params())
        assert result["summary"]["total"] == 3
        assert result["summary"]["up"] == 1
        assert result["summary"]["down"] == 2

    def test_down_only_filters_correctly(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.interfaces.DeviceConnection",
            lambda _p: self._fake_conn({"show port": NOKIA_PORT_OUTPUT}),
        )
        result = check_interfaces(self._make_params(), down_only=True)
        assert result["success"] is True
        assert all(not i["up"] for i in result["interfaces"])
        assert len(result["interfaces"]) == 2

    def test_empty_nokia_output(self, monkeypatch):
        monkeypatch.setattr(
            "netops.check.interfaces.DeviceConnection",
            lambda _p: self._fake_conn({"show port": ""}),
        )
        result = check_interfaces(self._make_params())
        assert result["success"] is True
        assert result["interfaces"] == []
        assert result["summary"]["total"] == 0

    def test_error_handling(self, monkeypatch):
        def _raise(_p):
            raise RuntimeError("nokia unreachable")

        monkeypatch.setattr("netops.check.interfaces.DeviceConnection", _raise)
        result = check_interfaces(self._make_params())
        assert result["success"] is False
        assert "nokia unreachable" in result["error"]
