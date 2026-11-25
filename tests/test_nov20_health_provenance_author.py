"""Owner-specific FR-027/033 numeric provenance, not native tuple qualification."""

from __future__ import annotations

import copy
import json

import pytest

from netops.ansible import _action_health as h
from netops.ansible import action_runtime as action
from netops.ansible import contracts as c
from netops.ansible.controller_protocol import ProtocolError
from netops.ansible.worker_broker import _safe_action_result

CPU = "CPU utilization for five seconds: 13%/1%; one minute: 12%; five minutes: 10%"
MEMORY = "Processor ABCDEF 3 1 2"
JUNOS = """Routing Engine status:
  Slot 0:
    Current state Master
    Memory utilization 25 percent
    CPU utilization:
      Idle 88 percent
  Slot 1:
    Current state Backup
    Memory utilization 35 percent
    CPU utilization:
      Idle 80 percent
"""
PAN = (
    "%Cpu(s): 5.0 us, 1.5 sy, 0.0 ni, 92.123 id\n"
    "MiB Mem : 16384.0 total, 8192.0 free, 6144.0 used, 2048.0 buff/cache"
)
EOS = json.dumps({
    "memTotal": 7, "memFree": 5,
    "systemStats": {"cpuInfo": {"0": {"%idle": 82.84}}},
})
SECRET = "author-private-health-credential-not-output"


class Device:
    """Only the external device transport is replaced, not native health owners."""

    def __init__(self, responses):
        self.responses = responses
        self.commands = []
        self.closed = False
        self.cleanup_fails = False

    def send(self, command):
        self.commands.append(command)
        value = self.responses[command]
        if isinstance(value, BaseException):
            raise value
        return value

    def send_command(self, command, **kwargs):
        return self.send(command)

    def disconnect(self):
        self.closed = True
        if self.cleanup_fails:
            raise RuntimeError(SECRET)


def gathered(vendor="cisco_ios", checks=("cpu", "memory"), check=lambda: None):
    return h._gather_native(
        Device({"show processes cpu": CPU, "show processes memory": MEMORY}),
        vendor, h._HealthSelection(checks), check,
    )


def callback(result):
    return _safe_action_result(result, "router", "gather")


PROFILES = [
    (
        vendor, {"show processes cpu": CPU, "show processes memory": MEMORY},
        12.0, {"five_seconds": 13.0, "one_minute": 12.0, "five_minutes": 10.0},
        33.33, {"total": 3, "used": 1, "free": 2, "utilization": 33.33},
    ) for vendor in ("cisco_ios", "cisco_xe")
] + [
    (
        "nokia_sros", {
            "show system cpu": "CPU Usage : 2.1% 4.8%",
            "show system memory-pools": "Total In Use : 1\nTotal Available : 2",
        }, 2.1, {"avg": 2.1, "peak": 4.8},
        33.33, {"total": 3, "used": 1, "free": 2, "utilization": 33.33},
    ),
    (
        "paloalto_panos", {"show system resources follow duration 1": PAN},
        7.88, {"user": 5.0, "system": 1.5, "idle": 92.123, "utilization": 7.88},
        37.5, {
            "total": 17179869184, "used": 6442450944, "free": 8589934592, "utilization": 37.5,
        },
    ),
    (
        "paloalto_panos", {"show system resources follow duration 1": (
            "%Cpu(s): 0 us, 0 sy, 0 ni, 100 id\nMem: 3 total, 1 used, 2 free"
        )}, 0.0, {"user": 0.0, "system": 0.0, "idle": 100.0, "utilization": 0.0},
        33.33, {"total": 3072, "used": 1024, "free": 2048, "utilization": 33.33},
    ),
    *[
        (
            vendor, {"show chassis routing-engine": JUNOS},
            20.0, {"cpu_utilization": 20.0}, 35.0, {"mem_utilization": 35.0},
        ) for vendor in ("juniper", "juniper_junos")
    ],
    (
        "arista_eos", {"show version | json": EOS},
        17.2, {"cpu_utilization": 17.2}, 28.6,
        {"total": 7168, "used": 2048, "utilization": 28.6},
    ),
    *[
        (
            "brocade_fastiron", {
                "show cpu": "\n".join(
                    {"one_second": "1-second average: 40 percent",
                     "five_seconds": "5-second average: 23 percent",
                     "one_minute": "60-second average: 11 percent"}[key] for key in keys
                ),
                "show memory": "Total DRAM: 3 KBytes\nUsed DRAM: 1 KBytes\nFree DRAM: 2 KBytes",
            }, 11.0 if "one_minute" in keys else 23.0,
            {key: {"one_second": 40.0, "five_seconds": 23.0, "one_minute": 11.0}[key]
             for key in keys},
            33.33, {"total": 3072, "used": 1024, "free": 2048, "utilization": 33.33},
        ) for keys in (
            ("five_seconds",), ("one_minute",), ("one_second", "five_seconds"),
            ("one_second", "one_minute"), ("five_seconds", "one_minute"),
            ("one_second", "five_seconds", "one_minute"),
        )
    ],
]


@pytest.mark.parametrize("vendor,responses,cpu,cpu_raw,memory,memory_raw", PROFILES)
@pytest.mark.parametrize("inclusive", [False, True])
def test_actual_native_owner_payloads_have_exact_closed_numeric_goldens(
    monkeypatch, vendor, responses, cpu, cpu_raw, memory, memory_raw, inclusive,
):
    device = Device(responses)
    monkeypatch.setattr("netmiko.ConnectHandler", lambda **kwargs: device)
    monkeypatch.setattr(
        action._StrictConnection, "_files",
        staticmethod(lambda credential: (None, "AUTHOR-known-hosts-port")),
    )
    credential = {
        "host": "192.0.2.50", "port": 22, "vendor": vendor,
        "fields": {"username": "author-user", "password": SECRET},
        "known_hosts_ref": "AUTHOR-known-hosts-port", "key_ref": None,
    }
    selection = h._HealthSelection(
        ("cpu", "memory"), cpu if inclusive else 100.0, memory if inclusive else 100.0,
    )
    result = action._NativeActions().run_selected("gather", credential, None, selection)
    assert device.closed
    expected = {
        name: {
            "status": "succeeded", "vendor": vendor, "parser": (
                "netops.check.arista" if vendor == "arista_eos"
                else "netops.check.juniper" if vendor.startswith("juniper")
                else "netops.check.cisco" if vendor.startswith("cisco") else "netops.check.health"
            ), "utilization": value, "threshold": threshold, "alert": inclusive, "raw": raw,
        } for name, value, threshold, raw in (
            ("cpu", cpu, selection.cpu_threshold, cpu_raw),
            ("memory", memory, selection.memory_threshold, memory_raw),
        )
    }
    assert result["health"] == {
        "checks": expected, "overall_alert": inclusive, "connection_cleanup_failed": False,
    }
    target = callback(result)
    assert target.status == (c.OutcomeStatus.FAILED if inclusive else c.OutcomeStatus.SUCCEEDED)
    assert [finding.result for finding in target.findings] == [
        "alert" if inclusive else "pass",
    ] * 2
    assert [finding.reading for finding in target.findings] == [cpu, memory]
    assert json.loads(c.canonical_bytes(target))["native_payload"]["health"] == result["health"]
    assert SECRET not in c.canonical_bytes(target).decode()


@pytest.mark.parametrize("fault", ["wrong-owner", "cpu-contradiction", "impossible-memory"])
def test_three_independent_reproduced_provenance_negatives_reject(fault):
    result = gathered()
    checks = result["health"]["checks"]
    if fault == "wrong-owner":
        checks["cpu"]["raw"] = {"peak": 12.0}
    elif fault == "cpu-contradiction":
        checks["cpu"]["raw"]["one_minute"] = 99.0
    else:
        checks["memory"]["utilization"] = 25.0
        checks["memory"]["raw"] = {"total": 0, "used": 2, "free": 4, "utilization": 99.0}
    with pytest.raises(ProtocolError):
        callback(result)


@pytest.mark.parametrize("vendor,responses,cpu,cpu_raw,memory,memory_raw", PROFILES)
@pytest.mark.parametrize("name", ["cpu", "memory"])
@pytest.mark.parametrize("fault", ["missing", "extra", "mismatch", "text", "nested", "bool", "nan"])
def test_each_owner_callback_enforces_required_keys_and_numeric_types(
    vendor, responses, cpu, cpu_raw, memory, memory_raw, name, fault,
):
    result = h._gather_native(Device(responses), vendor, h._HealthSelection(("cpu", "memory")))
    reading = result["health"]["checks"][name]
    source = (
        "mem_utilization" if vendor.startswith("juniper") and name == "memory"
        else "cpu_utilization" if vendor.startswith("juniper") or vendor == "arista_eos" and name == "cpu"
        else "utilization" if name == "memory" or vendor == "paloalto_panos"
        else "avg" if vendor == "nokia_sros"
        else "one_minute" if "one_minute" in reading["raw"] else "five_seconds"
    )
    if fault == "missing":
        del reading["raw"][source]
    elif fault == "extra":
        reading["raw"]["password"] = SECRET
    elif fault == "mismatch":
        reading["utilization"] += 0.01
    else:
        reading["raw"][source] = {
            "text": "12", "nested": {"value": 12}, "bool": True, "nan": float("nan"),
        }[fault]
    with pytest.raises(ProtocolError):
        callback(result)


@pytest.mark.parametrize("number", [
    True, None, "12", b"12", [], {}, float("inf"), float("-inf"), float("nan"),
    -1, 100.01, 10**400,
])
def test_percent_rejects_nonfinite_nested_text_bool_and_overflow_without_coercion(number):
    result = gathered()
    result["health"]["checks"]["cpu"]["raw"]["five_seconds"] = number
    with pytest.raises(ProtocolError):
        callback(result)


@pytest.mark.parametrize("field", ["total", "used", "free"])
@pytest.mark.parametrize("number", [True, -1, 1.0, "1", c.MAX_SAFE_INT + 1, None, {}, []])
def test_memory_counts_are_exact_safe_integers(field, number):
    result = gathered(checks=("memory",))
    result["health"]["checks"]["memory"]["raw"][field] = number
    with pytest.raises(ProtocolError):
        callback(result)


@pytest.mark.parametrize("counts", [
    {"total": 0, "used": 0, "free": 0, "utilization": 0.0},
    {"total": 3, "used": 4, "free": 0, "utilization": 100.0},
    {"total": 3, "used": 1, "free": 4, "utilization": 33.33},
    {"total": 3, "used": 1, "free": 1, "utilization": 33.33},
    {"total": 3, "used": 1, "free": 2, "utilization": 33.3},
])
def test_memory_impossible_counts_and_inconsistent_owner_rounding_reject(counts):
    result = gathered(checks=("memory",))
    result["health"]["checks"]["memory"]["raw"] = counts
    with pytest.raises(ProtocolError):
        callback(result)


@pytest.mark.parametrize("vendor,raw,value", [
    ("arista_eos", {"total": 7169, "used": 2048, "utilization": 28.6}, 28.6),
    ("arista_eos", {"total": 7168, "used": 2049, "utilization": 28.6}, 28.6),
    ("arista_eos", {"total": 7168, "used": 2048, "utilization": 28.57}, 28.57),
    ("arista_eos", {"total": (c.MAX_SAFE_INT // 1024 + 1) * 1024,
                    "used": 0, "utilization": 0.0}, 0.0),
    ("paloalto_panos", {"total": 10, "used": 8, "free": 3, "utilization": 80.0}, 80.0),
])
def test_eos_checked_kib_conversion_and_pan_cache_accounting_reject_impossible(vendor, raw, value):
    with pytest.raises(ProtocolError):
        h._numeric_provenance("memory", vendor, value, raw)


@pytest.mark.parametrize("counts", [
    {"total": c.MAX_SAFE_INT, "used": c.MAX_SAFE_INT, "free": 0, "utilization": 100.0},
    {"total": c.MAX_SAFE_INT, "used": 0, "free": c.MAX_SAFE_INT, "utilization": 0.0},
])
def test_exact_safe_counter_endpoints_preserve_real_zero_and_full_readings(counts):
    assert h._numeric_provenance("memory", "cisco_ios", counts["utilization"], counts) == counts


def test_pan_idle_source_agreement_and_all_fields_remain_mandatory():
    raw = {"user": 5.0, "system": 1.5, "idle": 92.123, "utilization": 7.88}
    assert h._numeric_provenance("cpu", "paloalto_panos", 7.88, raw) == raw
    with pytest.raises(ProtocolError):
        h._numeric_provenance("cpu", "paloalto_panos", 7.89, {**raw, "utilization": 7.89})
    for field in raw:
        with pytest.raises(ProtocolError):
            h._numeric_provenance(
                "cpu", "paloalto_panos", 7.88, {key: val for key, val in raw.items() if key != field},
            )


@pytest.mark.parametrize("path", ["callback", "health", "check", "raw"])
@pytest.mark.parametrize("key", [
    "credentials", "password", "username", "token", "key", "hostvars", "environment",
    "config", "argv", "command", "stdout", "stderr", "logs", "processes",
])
def test_no_arbitrary_text_or_extra_fields_at_any_private_callback_boundary(path, key):
    result = gathered()
    levels = {
        "callback": result, "health": result["health"],
        "check": result["health"]["checks"]["cpu"],
        "raw": result["health"]["checks"]["cpu"]["raw"],
    }
    levels[path][key] = SECRET
    with pytest.raises(ProtocolError):
        callback(result)


@pytest.mark.parametrize("name", ["cpu", "memory"])
@pytest.mark.parametrize("vendor", ["juniper", "juniper_junos"])
def test_junos_requires_every_engine_reading_and_selected_max_upstream(name, vendor):
    source = "cpu_util" if name == "cpu" else "memory_util"
    normalized = "cpu_utilization" if name == "cpu" else "mem_utilization"
    native = {
        normalized: 30.0, "routing_engines": [{source: 30}, {source: None}],
    }
    with pytest.raises(ProtocolError):
        h._reading(name, vendor, native, h._HealthSelection((name,)))
    native["routing_engines"][1][source] = 40
    with pytest.raises(ProtocolError):
        h._reading(name, vendor, native, h._HealthSelection((name,)))


def test_producer_does_not_emit_bad_provenance_when_owner_returns_invalid_counts(monkeypatch):
    monkeypatch.setattr(h.cisco, "check_cisco_memory", lambda *args: {
        "utilization": 25.0, "raw": {"total": 0, "used": 2, "free": 4, "utilization": 99.0},
    })
    result = gathered()
    target = callback(result)
    assert [finding.result for finding in target.findings] == ["pass", "unknown"]
    assert result["health"]["checks"]["memory"]["reason"] == "reading-unavailable"


def test_selection_partial_failure_cleanup_and_cancellation_preserve_completed_facts(monkeypatch):
    device = Device({"show processes cpu": CPU, "show processes memory": RuntimeError(SECRET)})
    result = h._gather_native(device, "cisco_ios", h._HealthSelection(("cpu", "memory", "ospf")))
    assert device.commands == ["show processes cpu", "show processes memory"]
    assert [finding.result for finding in callback(result).findings] == ["pass", "unknown", "unknown"]
    assert SECRET not in c.canonical_bytes(callback(result)).decode()
    clean = gathered(checks=("cpu",))
    clean["health"]["connection_cleanup_failed"] = True
    clean["status"] = "failed"
    assert callback(clean).status == c.OutcomeStatus.FAILED
    assert callback(clean).findings[0].result == "pass"
    calls = []

    def cancel():
        calls.append(None)
        if len(calls) >= 2:
            raise ProtocolError(c.ReasonCode.CONTROL_LOST)

    cancelled = gathered(checks=("cpu", "memory"), check=cancel)
    assert [finding.result for finding in callback(cancelled).findings] == ["pass", "unknown"]
    assert cancelled["health"]["checks"]["memory"]["status"] == "failed"
    assert "raw" not in cancelled["health"]["checks"]["memory"]


def test_unknown_vendor_wrong_parser_and_unsupported_success_never_gain_provenance():
    for change in ({"vendor": "unknown"}, {"vendor": []}, {"parser": "netops.check.health"}):
        result = gathered(checks=("cpu",))
        result["health"]["checks"]["cpu"].update(change)
        with pytest.raises(ProtocolError):
            callback(result)
    result = gathered(checks=("cpu",))
    result["health"]["checks"]["ospf"] = copy.deepcopy(result["health"]["checks"].pop("cpu"))
    with pytest.raises(ProtocolError):
        callback(result)
