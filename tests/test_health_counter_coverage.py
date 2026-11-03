"""Regression tests for verified interface error-counter coverage (PLU-41).

Synthetic CLI samples only. No network connections or device writes.
"""

from __future__ import annotations

import pytest

from netops.check.health import check_interface_errors
from netops.parsers.health import (
    parse_interface_errors_brocade,
    parse_interface_errors_cisco,
    parse_interface_errors_nokia,
)


class FixtureConnection:
    def __init__(self, text: str):
        self.text = text

    def send(self, _command: str) -> str:
        return self.text


CISCO_HEADER = "GigabitEthernet0/0 is up, line protocol is up\n"
NOKIA_HEADER = "Port 1/1/1\n"
BROCADE_HEADER = "GigabitEthernet1/1/1 is up, line protocol is up\n"

VENDORS = (
    ("cisco_ios", CISCO_HEADER, "  0 input errors\n", "  0 output errors\n"),
    ("nokia_sros", NOKIA_HEADER, "  Input Errors : 0\n", "  Output Errors : 0\n"),
    ("brocade", BROCADE_HEADER, "  0 input errors\n", "  0 output errors\n"),
)


@pytest.mark.parametrize("vendor,header,in_line,out_line", VENDORS)
def test_both_observed_zero_counters_are_healthy(vendor, header, in_line, out_line):
    result = check_interface_errors(FixtureConnection(header + in_line + out_line), vendor)
    assert result["total"] == 1
    assert result["with_errors"] == 0
    assert result["alert"] is False
    assert "error" not in result
    assert result["interfaces"][0]["input_errors_observed"] is True
    assert result["interfaces"][0]["output_errors_observed"] is True


@pytest.mark.parametrize("vendor,header,in_line,out_line", VENDORS)
def test_header_only_cannot_masquerade_as_zero_errors(vendor, header, in_line, out_line):
    result = check_interface_errors(FixtureConnection(header), vendor)
    assert result["total"] == 1
    assert result["alert"] is False
    assert "Incomplete" in result["error"]


@pytest.mark.parametrize("vendor,header,in_line,out_line", VENDORS)
def test_missing_output_counter_is_unknown(vendor, header, in_line, out_line):
    result = check_interface_errors(FixtureConnection(header + in_line), vendor)
    assert result["total"] == 1
    assert result["interfaces"][0]["input_errors_observed"] is True
    assert not result["interfaces"][0].get("output_errors_observed")
    assert "Incomplete" in result["error"]


@pytest.mark.parametrize("vendor,header,in_line,out_line", VENDORS)
def test_missing_input_counter_is_unknown(vendor, header, in_line, out_line):
    result = check_interface_errors(FixtureConnection(header + out_line), vendor)
    assert result["total"] == 1
    assert "Incomplete" in result["error"]


def test_mixed_complete_and_incomplete_interfaces_cannot_pass():
    output = (
        CISCO_HEADER
        + "  0 input errors\n  0 output errors\n"
        + "GigabitEthernet0/1 is up, line protocol is up\n"
    )
    result = check_interface_errors(FixtureConnection(output), "cisco_ios")
    assert result["total"] == 2
    assert "GigabitEthernet0/1" in result["error"]


def test_known_errors_remain_alerts_even_if_other_counter_is_unobserved():
    output = CISCO_HEADER + "  7 input errors\n"
    result = check_interface_errors(FixtureConnection(output), "cisco_ios")
    assert result["alert"] is True
    assert result["with_errors"] == 1
    assert "Incomplete" in result["error"]


@pytest.mark.parametrize(
    "parser,header",
    [
        (parse_interface_errors_cisco, CISCO_HEADER),
        (parse_interface_errors_nokia, NOKIA_HEADER),
        (parse_interface_errors_brocade, BROCADE_HEADER),
    ],
)
def test_parser_never_marks_missing_counters_as_observed(parser, header):
    parsed = parser(header)
    assert len(parsed) == 1
    assert parsed[0]["has_errors"] is False
    assert not parsed[0].get("input_errors_observed")
    assert not parsed[0].get("output_errors_observed")
