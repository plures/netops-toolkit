"""Independent FR-027/028 closed numeric provenance; no live device/platform claim.

Expected raw families follow the documented native parsers, not callback output.
The historical blanket-raw assertion is intentionally neither edited nor reused.
"""

from __future__ import annotations

import copy
import json

import pytest

from netops.ansible import contracts as c
from netops.ansible.controller_protocol import ProtocolError
from netops.ansible.worker_broker import _safe_action_result

SECRET = "nov20-producer-proof-secret-never-return"
CISCO_CPU = '{"five_minutes":10.0,"five_seconds":12.0,"one_minute":12.0}'
FLAT_MEMORY = '{"free":750,"total":1000,"used":250,"utilization":25.0}'
FAMILIES = [
    ("cisco_ios", "cisco", CISCO_CPU, FLAT_MEMORY),
    ("cisco_xe", "cisco", CISCO_CPU, FLAT_MEMORY),
    ("juniper", "juniper", '{"cpu_utilization":12.0}', '{"mem_utilization":25.0}'),
    ("juniper_junos", "juniper", '{"cpu_utilization":12.0}', '{"mem_utilization":25.0}'),
    ("arista_eos", "arista", '{"cpu_utilization":12.0}',
     '{"total":1024000,"used":256000,"utilization":25.0}'),
    ("nokia_sros", "health", '{"avg":12.0,"peak":15.0}', FLAT_MEMORY),
    ("brocade_fastiron", "health",
     '{"five_seconds":10.0,"one_minute":12.0,"one_second":14.0}', FLAT_MEMORY),
    ("brocade_fastiron", "health", '{"five_seconds":12.0}', FLAT_MEMORY),
    # PAN-OS permits buff/cache; free + used may legitimately be less than total.
    ("paloalto_panos", "health",
     '{"idle":88.0,"system":2.0,"user":10.0,"utilization":12.0}',
     '{"free":500,"total":1000,"used":250,"utilization":25.0}'),
]


def callback(vendor="cisco_ios", parser="cisco", cpu=CISCO_CPU, memory=FLAT_MEMORY):
    """Construct an independent closed callback fixture, never invoke a device."""
    return {
        "status": "succeeded", "attempted": True, "changed": False,
        "remote_state": "unchanged", "line_count": 0,
        "health": {
            "checks": {
                "cpu": {
                    "status": "succeeded", "alert": False, "vendor": vendor,
                    "parser": "netops.check." + parser, "utilization": 12.0,
                    "threshold": 70.0, "raw": json.loads(cpu),
                },
                "memory": {
                    "status": "succeeded", "alert": False, "vendor": vendor,
                    "parser": "netops.check." + parser, "utilization": 25.0,
                    "threshold": 80.0, "raw": json.loads(memory),
                },
            },
            "overall_alert": False, "connection_cleanup_failed": False,
        },
    }


@pytest.mark.parametrize("vendor,parser,cpu,memory", FAMILIES)
def test_ac008_every_supported_vendor_complete_target_literal(vendor, parser, cpu, memory):
    target = _safe_action_result(callback(vendor, parser, cpu, memory), "router", "gather")
    owner = "netops.check." + parser
    expected = (
        '{"attempted":true,"changed":false,"errors":[],"findings":['
        '{"category":"health","check":"cpu","expected":null,"parser":"' + owner + '",'
        '"raw_source_ref":null,"reading":12.0,"result":"pass","severity":"info",'
        '"threshold":70.0,"vendor":"' + vendor + '"},'
        '{"category":"health","check":"memory","expected":null,"parser":"' + owner + '",'
        '"raw_source_ref":null,"reading":25.0,"result":"pass","severity":"info",'
        '"threshold":80.0,"vendor":"' + vendor + '"}],'
        '"native_payload":{"health":{"checks":{"cpu":{"alert":false,"parser":"' + owner + '",'
        '"raw":' + cpu + ',"status":"succeeded","threshold":70.0,'
        '"utilization":12.0,"vendor":"' + vendor + '"},'
        '"memory":{"alert":false,"parser":"' + owner + '","raw":' + memory + ','
        '"status":"succeeded","threshold":80.0,"utilization":25.0,"vendor":"' + vendor + '"}},'
        '"connection_cleanup_failed":false,"overall_alert":false},"line_count":0},'
        '"remote_state":"unchanged","selected":true,"status":"succeeded",'
        '"target_id":"router","unapplied_effects":[]}'
    )
    assert c.canonical_bytes(target).decode() == expected


@pytest.mark.parametrize("vendor,parser,cpu,memory", FAMILIES)
@pytest.mark.parametrize("check", ["cpu", "memory"])
@pytest.mark.parametrize("fault", ["wrong-family", "missing-measurement", "extra-key", "contradiction"])
def test_ac008_each_vendor_rejects_non_owned_or_inconsistent_raw(
    vendor, parser, cpu, memory, check, fault,
):
    value = callback(vendor, parser, cpu, memory)
    record = value["health"]["checks"][check]
    raw = record["raw"]
    if fault == "wrong-family":
        record["raw"] = {"peak": record["utilization"]}
    elif fault == "missing-measurement":
        raw.clear()
    elif fault == "extra-key":
        raw["secret"] = SECRET
    else:
        # A finite bounded number is not enough: it must describe this reading.
        record["utilization"] = 13.0 if check == "cpu" else 26.0
    with pytest.raises(ProtocolError):
        _safe_action_result(value, "router", "gather")


@pytest.mark.parametrize("check,raw", [
    ("cpu", {"peak": 12.0}),
    ("cpu", {"five_seconds": 12.0, "one_minute": 99.0, "five_minutes": 10.0}),
    ("memory", {"total": 0, "used": 2, "free": 4, "utilization": 99.0}),
])
def test_ac008_original_three_independent_callback_failures_unchanged(check, raw):
    value = callback()
    value["health"]["checks"][check]["raw"] = raw
    with pytest.raises(ProtocolError):
        _safe_action_result(value, "router", "gather")


@pytest.mark.parametrize("vendor,parser,cpu,memory", FAMILIES)
@pytest.mark.parametrize("check", ["cpu", "memory"])
@pytest.mark.parametrize("bad", [True, False, None, "12", SECRET, float("nan"),
                                 float("inf"), -1, 101])
def test_ac008_every_vendor_rejects_nonfinite_boolean_string_or_invalid_percent(
    vendor, parser, cpu, memory, check, bad,
):
    value = callback(vendor, parser, cpu, memory)
    raw = value["health"]["checks"][check]["raw"]
    percentage = next(key for key in raw if key not in ("total", "used", "free"))
    raw[percentage] = bad
    with pytest.raises(ProtocolError):
        _safe_action_result(value, "router", "gather")


@pytest.mark.parametrize("key", ["total", "used", "free"])
@pytest.mark.parametrize("bad", [True, False, None, "250", -1, 1.5, float("nan"),
                                 c.MAX_SAFE_INT + 1])
def test_ac008_memory_counter_types_and_exact_integer_bound(key, bad):
    value = callback()
    value["health"]["checks"]["memory"]["raw"][key] = bad
    with pytest.raises(ProtocolError):
        _safe_action_result(value, "router", "gather")


@pytest.mark.parametrize("vendor,parser,cpu,memory", FAMILIES)
def test_ac008_memory_zero_total_and_impossible_sums_are_not_healthy(
    vendor, parser, cpu, memory,
):
    for replacement in (
        {"total": 0, "used": 0, "free": 0, "utilization": 0.0},
        {"total": 1000, "used": 1001, "free": 0, "utilization": 25.0},
        {"total": 1000, "used": 250, "free": 1000, "utilization": 25.0},
    ):
        value = callback(vendor, parser, cpu, memory)
        value["health"]["checks"]["memory"]["raw"] = replacement
        with pytest.raises(ProtocolError):
            _safe_action_result(value, "router", "gather")


@pytest.mark.parametrize("vendor,parser,cpu,memory", FAMILIES)
@pytest.mark.parametrize("check", ["cpu", "memory"])
@pytest.mark.parametrize("forbidden", ["command", "stdout", "stderr", "error", "password",
                                      "hostname", "unknown", "raw_output"])
def test_ac008_forbidden_extra_fields_rejected_not_silently_removed(
    vendor, parser, cpu, memory, check, forbidden, caplog,
):
    value = callback(vendor, parser, cpu, memory)
    value["health"]["checks"][check][forbidden] = SECRET
    with pytest.raises(ProtocolError) as caught:
        _safe_action_result(value, "router", "gather")
    assert SECRET not in str(caught.value) + caplog.text


@pytest.mark.parametrize("path", ["envelope", "health", "check", "raw"])
def test_ac008_unknown_callback_secret_never_crosses_boundary(path, caplog):
    value = callback()
    targets = {
        "envelope": value, "health": value["health"],
        "check": value["health"]["checks"]["cpu"],
        "raw": value["health"]["checks"]["cpu"]["raw"],
    }
    targets[path]["unknown-secret-field"] = SECRET
    with pytest.raises(ProtocolError) as caught:
        _safe_action_result(value, "router", "gather")
    assert SECRET not in str(caught.value) + caplog.text


@pytest.mark.parametrize("field,bad", [
    ("vendor", "unknown"), ("vendor", "made-up-vendor"),
    ("vendor", True), ("parser", "netops.check.health"),
    ("parser", "netops.check." + SECRET), ("parser", True),
])
def test_ac008_parser_owner_host_and_unknown_vendor_rejected(field, bad):
    value = callback()
    value["health"]["checks"]["cpu"][field] = bad
    with pytest.raises(ProtocolError):
        _safe_action_result(value, "router", "gather")


@pytest.mark.parametrize("check", ["cpu", "memory"])
@pytest.mark.parametrize("reading", [0.0, 100.0])
def test_ac008_valid_zero_and_hundred_percent_boundaries(check, reading):
    value = callback()
    record = value["health"]["checks"][check]
    record["utilization"] = reading
    record["threshold"] = 100.0
    record["alert"] = reading == 100
    if check == "cpu":
        record["raw"] = {"five_seconds": reading, "one_minute": reading, "five_minutes": reading}
    else:
        record["raw"] = {
            "total": 1000, "used": int(reading * 10),
            "free": 1000 - int(reading * 10), "utilization": reading,
        }
    value["health"]["overall_alert"] = record["alert"]
    value["status"] = "failed" if record["alert"] else "succeeded"
    target = _safe_action_result(value, "router", "gather")
    finding = next(item for item in target.findings if item.check == check)
    assert finding.reading == reading and finding.result == ("alert" if reading == 100 else "pass")


def test_ac008_callback_inputs_are_not_mutated_by_validation():
    value = callback()
    before = copy.deepcopy(value)
    _safe_action_result(value, "router", "gather")
    assert value == before
