"""Author source controls; original independent failed assertions are untouched."""

from __future__ import annotations

import copy
import json

import pytest

from netops.ansible import _action_health as h
from netops.ansible import contracts as c
from netops.ansible.controller_protocol import ProtocolError
from netops.ansible.worker_broker import _safe_action_result
from tests.test_nov20_health_provenance_author import Device
from tests.test_nov20_producer_numeric_provenance import callback


@pytest.mark.parametrize("user,system,idle", [
    ("10.0", "2.0", "88.0"),       # full accounted sample
    ("5.0", "1.5", "92.123"),      # other, unreported components
    ("33.4", "33.4", "33.3"),      # independent tenth-percent rounding
    ("0", "0", "100"),
    ("100", "0", "0"),
    ("0.10", "0.20", "99.70"),     # exact decimal sum, not binary float sum
    ("33.334", "33.334", "33.333"), # precision-derived half-unit intervals
])
def test_real_pan_parser_valid_same_row_rounding_and_unreported_components(user, system, idle):
    output = (
        f"%Cpu(s): {user} us, {system} sy, 0 ni, {idle} id, 0 wa, 0 hi, 0 si\n"
        "Mem: 3 total, 1 used, 2 free"
    )
    expected = round(100.0 - float(idle), 2)
    result = h._gather_native(
        Device({"show system resources follow duration 1": output}),
        "paloalto_panos", h._HealthSelection(("cpu", "memory"), expected, 100.0),
    )
    cpu = result["health"]["checks"]["cpu"]
    assert cpu == {
        "status": "succeeded", "vendor": "paloalto_panos", "parser": "netops.check.health",
        "utilization": expected, "threshold": expected, "alert": True,
        "raw": {
            "user": float(user), "system": float(system), "idle": float(idle),
            "utilization": expected,
        },
    }
    target = _safe_action_result(result, "router", "gather")
    assert target.findings[0].result == "alert"
    assert target.findings[1].result == "pass"
    assert json.loads(c.canonical_bytes(target))["native_payload"]["health"] == result["health"]


@pytest.mark.parametrize("user,system,idle", [
    ("100.0", "100.0", "88.0"),
    ("13.0", "0.0", "88.0"),
    ("10.0", "3.0", "88.0"),
    ("10", "3", "88"),
    ("33.334", "33.334", "33.334"),  # exceeds original three-place rounding budget
    ("33.4000", "33.4000", "33.3000"),  # trailing-zero precision is not lost at producer
    ("0.2", "0.2", "99.8"),         # exceeds even the tenth-percent budget
])
def test_real_pan_parser_rejects_impossible_cpu_without_poisoning_memory(user, system, idle):
    result = h._gather_native(
        Device({"show system resources follow duration 1": (
            f"%Cpu(s): {user} us, {system} sy, 0 ni, {idle} id\n"
            "Mem: 3 total, 1 used, 2 free"
        )}), "paloalto_panos", h._HealthSelection(("cpu", "memory")),
    )
    assert result["health"]["checks"]["cpu"]["reason"] == "reading-unavailable"
    target = _safe_action_result(result, "router", "gather")
    assert [finding.result for finding in target.findings] == ["unknown", "pass"]
    assert target.findings[0].reading is None


@pytest.mark.parametrize("number_type", [int, float])
@pytest.mark.parametrize("user,system", [(100, 100), (13, 0), (10, 3)])
def test_callback_component_guard_is_load_bearing_for_integer_and_float_wire(
    number_type, user, system,
):
    result = callback("paloalto_panos", "health", json.dumps({
        "user": number_type(user), "system": number_type(system),
        "idle": number_type(88), "utilization": 12.0,
    }))
    with pytest.raises(ProtocolError):
        _safe_action_result(result, "router", "gather")


@pytest.mark.parametrize("average,peak,valid", [
    ("12", "11", False), ("12.001", "12.000", False),
    ("12.00", "12.00", True), ("0", "0", True), ("100", "100", True),
    ("12", "99", True),
])
def test_real_nokia_same_row_average_peak_not_other_temporal_windows(average, peak, valid):
    result = h._gather_native(
        Device({"show system cpu": f"CPU Usage : {average}% {peak}%"}),
        "nokia_sros", h._HealthSelection(("cpu",), float(average)),
    )
    target = _safe_action_result(result, "router", "gather")
    assert target.findings[0].result == ("alert" if valid else "unknown")
    if valid:
        assert result["health"]["checks"]["cpu"]["raw"] == {
            "avg": float(average), "peak": float(peak),
        }


def test_distinct_cisco_cpu_windows_are_not_incorrectly_compared():
    result = callback()
    result["health"]["checks"]["cpu"]["raw"]["five_seconds"] = 100.0
    result["health"]["checks"]["cpu"]["raw"]["five_minutes"] = 0.0
    assert _safe_action_result(result, "router", "gather").findings[0].reading == 12.0


def test_corrected_retry_allows_exact_numeric_raw_not_secret_or_unknown_fields():
    """New author retry of old blanket-absence error, not an edit to independent history."""
    result = callback()
    target = _safe_action_result(result, "router", "gather")
    expected = {
        "cpu": {"five_seconds": 12.0, "one_minute": 12.0, "five_minutes": 10.0},
        "memory": {"total": 1000, "used": 250, "free": 750, "utilization": 25.0},
    }
    wire = json.loads(c.canonical_bytes(target))
    for name, golden in expected.items():
        assert wire["native_payload"]["health"]["checks"][name]["raw"] == golden
    for name in expected:
        for field in ("password", "command", "stdout", "config", "arbitrary"):
            bad = copy.deepcopy(result)
            bad["health"]["checks"][name]["raw"][field] = "author-private-nov21-secret"
            with pytest.raises(ProtocolError):
                _safe_action_result(bad, "router", "gather")
    assert "author-private-nov21-secret" not in c.canonical_bytes(target).decode()
