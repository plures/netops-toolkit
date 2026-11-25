"""Independent raw numeric rounding, impossible CPU sums and zero boundaries."""

from __future__ import annotations

import json

import pytest

from netops.ansible import contracts as c
from netops.ansible.controller_protocol import ProtocolError
from netops.ansible.worker_broker import _safe_action_result
from tests.test_nov20_producer_numeric_provenance import callback


@pytest.mark.parametrize("vendor,owner,total,used,free,percentage", [
    ("cisco_ios", "cisco", 3, 1, 2, 33.33),
    ("cisco_xe", "cisco", 3, 1, 2, 33.33),
    ("nokia_sros", "health", 3, 1, 2, 33.33),
    ("brocade_fastiron", "health", 3072, 1024, 2048, 33.33),
    ("paloalto_panos", "health", 1048576, 262144, 524288, 25.0),
    ("arista_eos", "arista", 3072, 1024, None, 33.3),
])
def test_ac008_native_memory_rounding_and_units_are_not_flattened(
    vendor, owner, total, used, free, percentage,
):
    cpu = {
        "cisco_ios": '{"five_seconds":12.0,"one_minute":12.0,"five_minutes":10.0}',
        "cisco_xe": '{"five_seconds":12.0,"one_minute":12.0,"five_minutes":10.0}',
        "nokia_sros": '{"avg":12.0,"peak":15.0}',
        "brocade_fastiron": '{"five_seconds":12.0}',
        "paloalto_panos": '{"user":10.0,"system":2.0,"idle":88.0,"utilization":12.0}',
        "arista_eos": '{"cpu_utilization":12.0}',
    }[vendor]
    raw = {"total": total, "used": used, "utilization": percentage}
    if free is not None:
        raw["free"] = free
    value = callback(vendor, owner, cpu, json.dumps(raw))
    value["health"]["checks"]["memory"]["utilization"] = percentage
    target = _safe_action_result(value, "router", "gather")
    assert target.findings[1].reading == percentage
    assert target.native_payload["health"]["checks"]["memory"]["raw"] == c.public_object(raw)
    wrong = 33.33 if vendor == "arista_eos" else percentage + 0.01
    value["health"]["checks"]["memory"]["utilization"] = wrong
    value["health"]["checks"]["memory"]["raw"]["utilization"] = wrong
    with pytest.raises(ProtocolError):
        _safe_action_result(value, "router", "gather")


@pytest.mark.parametrize("raw", [
    {"user": 100.0, "system": 100.0, "idle": 88.0, "utilization": 12.0},
    {"user": 13.0, "system": 0.0, "idle": 88.0, "utilization": 12.0},
    {"user": 10.0, "system": 3.0, "idle": 88.0, "utilization": 12.0},
])
def test_ac008_panos_impossible_cpu_component_sum_rejected(raw):
    value = callback(
        "paloalto_panos", "health", json.dumps(raw),
        '{"total":1000,"used":250,"free":500,"utilization":25.0}',
    )
    with pytest.raises(ProtocolError):
        _safe_action_result(value, "router", "gather")


def test_ac008_nokia_peak_cannot_be_below_same_sample_average():
    value = callback("nokia_sros", "health", '{"avg":12.0,"peak":11.0}')
    with pytest.raises(ProtocolError):
        _safe_action_result(value, "router", "gather")


@pytest.mark.parametrize("check", ["interfaces", "bgp", "vlans", "environment"])
@pytest.mark.parametrize("total,count", [
    (0, 0), (1, 2), (True, 0), (1, False), (1, 0.5),
    (4097, 0), (c.MAX_SAFE_INT + 1, 0), (1, -1), ("1", 0),
])
def test_ac008_record_count_overflow_boolean_impossible_and_missing_are_not_zero(check, total, count):
    value = callback()
    value["health"]["checks"] = {
        check: {
            "status": "succeeded", "alert": False, "vendor": "cisco_ios",
            "parser": "netops.check.health" if check == "vlans" else "netops.check.cisco",
            "total": total, "with_errors": count,
            **({"temperatures_celsius": []} if check == "environment" else {}),
        },
    }
    with pytest.raises(ProtocolError):
        _safe_action_result(value, "router", "gather")
