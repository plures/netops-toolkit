"""Fixed native health owners with bounded, credential-free reading facts."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal, localcontext
from typing import cast

from netops.check import arista, cisco, health, juniper
from netops.core.connection import DeviceConnection
from netops.parsers.arista import parse_vlan_eos
from netops.parsers.vlan import parse_vlan_brief

from . import contracts as c
from .controller_protocol import ProtocolError, _closed

_CHECKS = ("cpu", "memory", "interfaces", "bgp", "vlans", "environment")
_CISCO = ("cisco_ios", "cisco_xe")
_JUNOS = ("juniper", "juniper_junos")
_FLAT = ("nokia_sros", "brocade_fastiron", "paloalto_panos")
_EOS = ("arista_eos",)
_VENDORS = (*_CISCO, *_JUNOS, *_FLAT, *_EOS, "unknown")
_MAX_READING_BYTES = 512 * 1024
_MAX_RECORDS = 4096
_PAN_CPU = re.compile(
    r"%Cpu\(s\):\s+(\d+(?:\.\d+)?)\s+us,\s+(\d+(?:\.\d+)?)\s+sy,"
    r"[^,]*,\s+(\d+(?:\.\d+)?)\s+id",
)


def _panos_cpu_components(numbers: tuple[Decimal, ...]) -> None:
    """Bound same-row top components by their independently reported precision.

    The parser retains floats (at least a decimal place), not original trailing
    zeros. The source-text boundary also calls this with the original decimals,
    so losing those zeros cannot enlarge the producer's rounding interval.
    Utilization's separately rounded two-decimal value is NOT the budget.
    Unreported nice/interrupt/IO components may occupy the remaining budget.
    """
    with localcontext() as context:
        # Exact addition even for the smallest finite float accepted by the wire.
        context.prec = 340
        rounding = sum(
            (min(Decimal("0.1"), Decimal(1).scaleb(cast(int, number.as_tuple().exponent))) / 2
             for number in numbers),
            Decimal(0),
        )
        if sum(numbers, Decimal(0)) > Decimal(100) + rounding:
            raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)


def _counter(value: object) -> int:
    """Accept an actual bounded integer measurement, including measured zero."""
    if type(value) is not int or not isinstance(value, int) or not 0 <= value <= c.MAX_SAFE_INT:
        raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
    return value


def _junos_interface_counters(output: str) -> dict[str, tuple[int, int]]:
    """Require both total error measurements in every native physical block."""
    measured: dict[str, tuple[int, int]] = {}
    blocks = re.split(r"(?im)^(?=Physical interface:\s+\S+,)", output)[1:]
    for block in blocks:
        header = re.match(r"Physical interface:\s+(\S+),", block, re.IGNORECASE)
        assert header is not None
        name = header.group(1)
        if name in measured:
            raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
        counters: dict[str, int] = {}
        section = ""
        for line in block.splitlines()[1:]:
            if re.search(r"Input errors:", line, re.IGNORECASE):
                section = "input"
            elif re.search(r"Output errors:", line, re.IGNORECASE):
                section = "output"
            elif section:
                # Do not mistake "Framing errors" or "FIFO errors" for the
                # actual total Errors measurement. Reject partial numeric text.
                for match in re.finditer(r"(?:^|,)\s*Errors:\s*([^,\s]+)", line, re.IGNORECASE):
                    token = match.group(1)
                    if re.fullmatch(r"[0-9]+", token) is None:
                        raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
                    counters[section] = _counter(counters.get(section, 0) + int(token))
        if set(counters) != {"input", "output"}:
            raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
        measured[name] = (counters["input"], counters["output"])
    if not 1 <= len(measured) <= _MAX_RECORDS:
        raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
    return measured


def _eos_interface_counters(data: object) -> dict[str, tuple[int, int]]:
    """Require present total counters before the native parser's default zeros."""
    if not isinstance(data, dict):
        raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
    interfaces = data.get("interfaces")
    if not isinstance(interfaces, dict) or not 1 <= len(interfaces) <= _MAX_RECORDS:
        raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
    measured = {}
    for name, interface in interfaces.items():
        if not isinstance(interface, dict):
            raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
        counters = interface.get("interfaceCounters")
        if not isinstance(counters, dict) or not {"inputErrors", "outputErrors"} <= counters.keys():
            raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
        measured[name] = (_counter(counters["inputErrors"]), _counter(counters["outputErrors"]))
    return measured


def _eos_numbers(value: object, depth: int = 0) -> None:
    """Validate native numeric conversions before their legacy catch/log boundary."""
    if depth > 12:
        raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
    if isinstance(value, dict):
        for name, item in value.items():
            if name in (
                "memTotal", "memFree", "inputErrors", "outputErrors", "inDiscards",
                "outDiscards", "alignmentErrors", "prefixReceived",
            ) and (type(item) is not int or not 0 <= item <= c.MAX_SAFE_INT):
                raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
            if name == "%idle":
                _percent(item)
            _eos_numbers(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > _MAX_RECORDS:
            raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
        for item in value:
            _eos_numbers(item, depth + 1)


def _percent(value: object) -> float:
    if (
        type(value) not in (int, float) or not isinstance(value, (int, float))
        or not 0 <= value <= 100 or not math.isfinite(value)
    ):
        raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
    return float(value)


def _numeric_provenance(name: str, vendor: object, value: float, raw: object) -> dict:
    """Validate the native owner's closed measurements at both private boundaries."""
    if not isinstance(vendor, str) or vendor not in (*_CISCO, *_JUNOS, *_FLAT, *_EOS):
        raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
    if type(raw) is not dict or not isinstance(raw, dict):
        raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
    if vendor in _JUNOS or (vendor in _EOS and name == "cpu"):
        source = "mem_utilization" if name == "memory" else "cpu_utilization"
        parsed = _closed(raw, {source})
    elif name == "cpu":
        if vendor in _CISCO:
            source = "one_minute"
            parsed = _closed(raw, {"five_seconds", "one_minute", "five_minutes"})
        elif vendor == "nokia_sros":
            source = "avg"
            parsed = _closed(raw, {"avg", "peak"})
            # The native parser takes these two columns from the SAME CPU row,
            # unlike IOS's distinct five-second/one-minute/five-minute windows.
            if _percent(parsed["peak"]) < _percent(parsed["avg"]):
                raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
        elif vendor == "brocade_fastiron":
            source = "one_minute" if "one_minute" in raw else "five_seconds"
            if source not in raw or set(raw) - {"one_second", "five_seconds", "one_minute"}:
                raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
            parsed = dict(raw)
        else:
            source = "utilization"
            parsed = _closed(raw, {"user", "system", "idle", "utilization"})
            if _percent(parsed[source]) != round(100.0 - _percent(parsed["idle"]), 2):
                raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
            _panos_cpu_components(tuple(
                Decimal(str(_percent(parsed[key]))) for key in ("user", "system", "idle")
            ))
    else:
        source = "utilization"
        parsed = _closed(raw, {"total", "used", "utilization"} | (
            set() if vendor in _EOS else {"free"}
        ))
        total, used = _counter(parsed["total"]), _counter(parsed["used"])
        if total == 0 or used > total:
            raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
        if vendor in _EOS:
            # Native EOS ratios are rounded to ONE decimal in KiB, unlike
            # the flat parsers' two decimals. Check the original unit boundary.
            if total % 1024 or used % 1024:
                raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
            expected = round((used // 1024) / (total // 1024) * 100, 1)
        else:
            free = _counter(parsed["free"])
            # PAN top can also account for buff/cache, intentionally not
            # exposed by its bounded parser; the residual may be positive.
            if free > total or used + free > total or (
                vendor != "paloalto_panos" and used + free != total
            ):
                raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
            expected = round(used / total * 100, 2)
        if _percent(parsed[source]) != expected:
            raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
    for key, number in parsed.items():
        if key not in ("total", "used", "free"):
            _percent(number)
    if _percent(parsed[source]) != value:
        raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
    return parsed


@dataclass(frozen=True)
class _HealthSelection:
    """Host-bound nonsecret checks/thresholds, never executable commands or authority."""

    checks: tuple[str, ...] = _CHECKS
    cpu_threshold: float = 80.0
    memory_threshold: float = 85.0

    def __post_init__(self) -> None:
        if (
            type(self.checks) is not tuple or not self.checks
            or len(set(self.checks)) != len(self.checks)
            or any(name not in (*_CHECKS, "ospf") for name in self.checks)
        ):
            raise ProtocolError(c.ReasonCode.INPUT_BINDING_INVALID)
        _percent(self.cpu_threshold)
        _percent(self.memory_threshold)

    def wire(self) -> dict[str, object]:
        """Return closed nonsecret selection for the private frame only."""
        return {
            "checks": list(self.checks), "cpu_threshold": self.cpu_threshold,
            "memory_threshold": self.memory_threshold,
        }

    @classmethod
    def parse(cls, value: object) -> _HealthSelection:
        """Reject injected commands, unknown check names and invalid thresholds."""
        item = _closed(value, {"checks", "cpu_threshold", "memory_threshold"})
        checks = item["checks"]
        if type(checks) is not list or not isinstance(checks, list):
            raise ProtocolError()
        if any(type(name) is not str for name in checks):
            raise ProtocolError()
        return cls(
            cast(tuple[str, ...], tuple(checks)),
            _percent(item["cpu_threshold"]), _percent(item["memory_threshold"]),
        )


class _ReadingConnection:
    """Pass only allowlisted read commands; native errors become fixed safe text."""

    def __init__(self, connection: DeviceConnection, commands: frozenset[str]) -> None:
        self._connection, self._commands = connection, commands
        self.line_count = 0
        self.interface_counters: dict[str, tuple[int, int]] = {}
        self.panos_cpu: tuple[Decimal, ...] | None = None

    def send(self, command: str) -> str:
        if command not in self._commands:
            raise ProtocolError(c.ReasonCode.OPERATION_UNSUPPORTED)
        try:
            output = self._connection.send(command)
            if (
                type(output) is not str or not output.strip()
                or len(output.encode("utf-8")) > _MAX_READING_BYTES
            ):
                raise ValueError()
            if command == "show chassis routing-engine":
                for match in re.finditer(r"Idle\s+(\d+)\s+percent", output, re.IGNORECASE):
                    _percent(int(match.group(1)))
            if command == "show system resources follow duration 1":
                pan_sample = _PAN_CPU.search(output)
                self.panos_cpu = (
                    tuple(Decimal(token) for token in pan_sample.groups())
                    if pan_sample is not None else None
                )
            if command == "show interfaces extensive":
                self.interface_counters = _junos_interface_counters(output)
            if command == "show interfaces" and not output.lstrip().startswith("{"):
                blocks = re.split(r"(?m)^(?=\S+ is (?:up|down|administratively down))", output)
                for block in blocks:
                    if re.match(r"^\S+ is (?:up|down|administratively down)", block) and (
                        re.search(r"\d+ input errors", block) is None
                        or re.search(r"\d+ output errors", block) is None
                    ):
                        raise ValueError()
            if command in self._commands and output.lstrip().startswith("{"):
                data = json.loads(output)
                _eos_numbers(data)
                if command in ("show interfaces | json", "show interfaces"):
                    self.interface_counters = _eos_interface_counters(data)
        except Exception:
            # Existing native helpers log their caught exception. Supply only
            # this closed reason, never the device/native credential-bearing text.
            raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE) from None
        self.line_count += len(output.splitlines())
        return output


def _records(value: object) -> list[dict]:
    if (
        type(value) is not list or not isinstance(value, list)
        or not 1 <= len(value) <= _MAX_RECORDS
        or any(type(item) is not dict for item in value)
    ):
        raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
    return cast(list[dict], value)


def _reading(
    name: str, vendor: str, native: dict, selection: _HealthSelection,
) -> dict[str, object]:
    """Retain numeric measurements/counts and parser provenance, never raw output."""
    if native.get("error") is not None:
        raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
    facts: dict[str, object]
    if name in ("cpu", "memory"):
        field = "cpu_utilization" if name == "cpu" else "mem_utilization"
        value = _percent(
            native.get("cpu_utilization" if name == "cpu" else "memory_util")
            if vendor in _EOS else native.get(field) if vendor in _JUNOS
            else native.get("utilization"),
        )
        if vendor in _JUNOS:
            engines = _records(native.get("routing_engines"))
            measurements = [
                _percent(engine.get("cpu_util" if name == "cpu" else "memory_util"))
                for engine in engines
            ]
            if max(measurements) != value:
                raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
        threshold = selection.cpu_threshold if name == "cpu" else selection.memory_threshold
        facts = {"utilization": value, "threshold": threshold, "alert": value >= threshold}
        parsed: object
        if vendor in _JUNOS:
            parsed = {field: value}
        elif vendor in _EOS:
            parsed = {"cpu_utilization": value} if name == "cpu" else {
                "total": _counter(native.get("memory_total_kb")) * 1024,
                "used": _counter(native.get("memory_used_kb")) * 1024,
                "utilization": value,
            }
        else:
            parsed = native.get("raw")
        facts["raw"] = _numeric_provenance(name, vendor, value, parsed)
    elif name in ("interfaces", "bgp", "vlans"):
        key = {"interfaces": "interfaces", "bgp": "peers", "vlans": "vlans"}[name]
        rows = _records(native.get(key))
        if name == "interfaces":
            if any(type(row.get("has_errors")) is not bool for row in rows):
                raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
            count = sum(row["has_errors"] for row in rows)
        elif name == "bgp":
            if any(type(row.get("state")) is not str for row in rows):
                raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
            count = sum(row["state"].lower() != "established" for row in rows)
        else:
            if any(type(row.get("vlan_id")) is not int or not 1 <= row["vlan_id"] <= 4094
                   or type(row.get("status")) is not str for row in rows):
                raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
            count = sum(row["status"].lower() != "active" for row in rows)
        facts = {"total": len(rows), "with_errors": count, "alert": count > 0}
    else:
        rows = _records(
            native.get("temperatures", []) + native.get("fans", [])
            + native.get("power_supplies", []),
        )
        if any(type(row.get("ok")) is not bool for row in rows):
            raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
        count = sum(not row["ok"] for row in rows)
        temperatures = [
            row["celsius"] for row in rows if type(row.get("celsius")) is int
        ]
        facts = {
            "total": len(rows), "with_errors": count, "alert": count > 0,
            "temperatures_celsius": temperatures,
        }
    facts.update(status="succeeded", vendor=vendor, parser=_parser_owner(vendor, name))
    return facts


def _parser_owner(vendor: str, name: str) -> str:
    return "netops.check." + ("arista" if vendor in _EOS else "juniper" if vendor in _JUNOS else (
        "cisco" if vendor in _CISCO and name != "vlans" else "health"
    ))


def _handlers(
    vendor: str, selection: _HealthSelection,
) -> tuple[dict[str, Callable[[DeviceConnection], dict]], frozenset[str]]:
    """Select only existing vendor owners; unsupported formats never use Cisco fallback."""
    if vendor in _CISCO:
        return {
            "cpu": lambda conn: cisco.check_cisco_cpu(conn, selection.cpu_threshold),
            "memory": lambda conn: cisco.check_cisco_memory(conn, selection.memory_threshold),
            "interfaces": cisco.check_cisco_interfaces, "bgp": cisco.check_cisco_bgp,
            "vlans": lambda conn: {"vlans": parse_vlan_brief(conn.send("show vlan brief"))},
            "environment": cisco.check_cisco_environment,
        }, frozenset((
            "show processes cpu", "show processes memory", "show interfaces",
            "show ip bgp summary", "show vlan brief", "show environment all",
        ))
    if vendor in _JUNOS:
        return {
            "cpu": lambda conn: juniper.check_junos_re(
                conn, selection.cpu_threshold, selection.memory_threshold,
            ),
            "memory": lambda conn: juniper.check_junos_re(
                conn, selection.cpu_threshold, selection.memory_threshold,
            ),
            "interfaces": juniper.check_junos_interfaces, "bgp": juniper.check_junos_bgp,
            "environment": juniper.check_junos_environment,
        }, frozenset((
            "show chassis routing-engine", "show interfaces extensive",
            "show bgp summary", "show chassis environment",
        ))
    if vendor in _EOS:
        return {
            "cpu": lambda conn: arista.check_eos_cpu_memory(
                conn, selection.cpu_threshold, selection.memory_threshold,
            ),
            "memory": lambda conn: arista.check_eos_cpu_memory(
                conn, selection.cpu_threshold, selection.memory_threshold,
            ),
            "interfaces": arista.check_eos_interfaces, "bgp": arista.check_eos_bgp,
            "environment": arista.check_eos_environment,
            "vlans": lambda conn: {"vlans": parse_vlan_eos(arista._send_json(conn, "show vlan"))},
        }, frozenset(
            command + suffix for command in (
                "show version", "show interfaces", "show bgp summary",
                "show environment all", "show vlan",
            ) for suffix in (" | json", "")
        )
    if vendor in _FLAT:
        cpu, memory = {
            "nokia_sros": ("show system cpu", "show system memory-pools"),
            "brocade_fastiron": ("show cpu", "show memory"),
            "paloalto_panos": (
                "show system resources follow duration 1", "show system resources follow duration 1",
            ),
        }[vendor]
        handlers: dict[str, Callable[[DeviceConnection], dict]] = {
            "cpu": lambda conn: health.check_cpu(conn, vendor, selection.cpu_threshold),
            "memory": lambda conn: health.check_memory(conn, vendor, selection.memory_threshold),
        }
        commands = {cpu, memory}
        if vendor != "paloalto_panos":
            handlers["interfaces"] = lambda conn: health.check_interface_errors(conn, vendor)
            commands.add("show port detail" if vendor == "nokia_sros" else "show interfaces")
        return handlers, frozenset(commands)
    return {}, frozenset()


def _gather_native(
    connection: DeviceConnection, vendor: str, selection: _HealthSelection,
    check: Callable[[], None] = lambda: None,
) -> dict[str, object]:
    """Run every selected check independently, preserving readings after later failures."""
    handlers, commands = _handlers(vendor, selection)
    vendor = vendor if vendor in _VENDORS else "unknown"
    guarded = _ReadingConnection(connection, commands)
    checks: dict[str, object] = {}
    lost = False
    for name in selection.checks:
        try:
            if lost:
                raise ProtocolError(c.ReasonCode.CONTROL_LOST)
            check()
        except Exception:
            lost = True
            checks[name] = {
                "status": "failed", "alert": False, "vendor": vendor,
                "parser": _parser_owner(vendor, name), "reason": "reading-unavailable",
            }
            continue
        if name not in handlers:
            checks[name] = {
                "status": "unsupported", "alert": False, "vendor": vendor,
                "parser": "unsupported", "reason": "operation-unsupported",
            }
            continue
        try:
            native = handlers[name](cast(DeviceConnection, guarded))
            if name == "cpu" and vendor == "paloalto_panos" and guarded.panos_cpu is not None:
                _panos_cpu_components(guarded.panos_cpu)
            if name == "interfaces" and vendor in (*_JUNOS, *_EOS):
                rows = _records(native.get("interfaces"))
                fields = ("input_errors", "output_errors") if vendor in _JUNOS else (
                    "in_errors", "out_errors",
                )
                parsed = {
                    row.get("name"): (_counter(row.get(fields[0])), _counter(row.get(fields[1])))
                    for row in rows
                }
                if not guarded.interface_counters or parsed != guarded.interface_counters:
                    raise ProtocolError(c.ReasonCode.READING_UNAVAILABLE)
            checks[name] = _reading(name, vendor, native, selection)
        except Exception:
            checks[name] = {
                "status": "failed", "alert": False, "vendor": vendor,
                "parser": _parser_owner(vendor, name), "reason": "reading-unavailable",
            }
        try:
            check()
        except Exception:
            lost = True
    statuses = [cast(dict, value)["status"] for value in checks.values()]
    alerts = any(cast(dict, value)["alert"] for value in checks.values())
    return {
        "status": "succeeded" if all(status == "succeeded" for status in statuses) and not alerts
        else "unsupported" if all(status == "unsupported" for status in statuses) else "failed",
        "attempted": any(status != "unsupported" for status in statuses), "changed": False,
        "remote_state": "unchanged", "line_count": guarded.line_count,
        "health": {"checks": checks, "overall_alert": alerts, "connection_cleanup_failed": False},
    }


def _validate_health(
    value: object, target_id: str,
) -> tuple[dict[str, object], tuple[c.Finding, ...], tuple[c.SafeError, ...]]:
    """Validate every callback fact; unknown/malformed/unsupported is never a pass."""
    item = _closed(value, {"checks", "overall_alert", "connection_cleanup_failed"})
    checks = item["checks"]
    if (
        type(checks) is not dict or not isinstance(checks, dict) or not 1 <= len(checks) <= 7
        or any(name not in (*_CHECKS, "ospf") for name in checks)
        or type(item["overall_alert"]) is not bool
        or type(item["connection_cleanup_failed"]) is not bool
    ):
        raise ProtocolError()
    findings: list[c.Finding] = []
    errors: list[c.SafeError] = []
    alert = False
    for name, raw in checks.items():
        if not isinstance(raw, dict):
            raise ProtocolError()
        status = raw.get("status")
        common = {"status", "alert", "vendor", "parser"}
        measurement: object = None
        threshold: object = None
        if status in ("failed", "unsupported"):
            reading = _closed(raw, common | {"reason"})
            reason = "reading-unavailable" if status == "failed" else "operation-unsupported"
            if reading["reason"] != reason or reading["alert"] is not False:
                raise ProtocolError()
            errors.append(c.SafeError(
                c.ErrorCategory.POLICY if status == "failed" else c.ErrorCategory.UNSUPPORTED,
                c.ReasonCode(reason), c.Stage.EVALUATE, target_id=target_id,
                next_action="Inspect selected supported check and reading provenance; never use zero.",
            ))
        elif status == "succeeded":
            if name in ("cpu", "memory"):
                reading = _closed(raw, common | {"utilization", "threshold", "raw"})
                measurement, threshold = _percent(reading["utilization"]), _percent(reading["threshold"])
                _numeric_provenance(name, reading["vendor"], measurement, reading["raw"])
                expected_alert = measurement >= threshold
            else:
                reading = _closed(raw, common | {"total", "with_errors"} | (
                    {"temperatures_celsius"} if name == "environment" else set()
                ))
                total, count = reading["total"], reading["with_errors"]
                if (type(total) is not int or type(count) is not int
                    or not isinstance(total, int) or not isinstance(count, int)
                    or not 1 <= total <= _MAX_RECORDS or not 0 <= count <= total):
                    raise ProtocolError()
                if name == "environment":
                    temperatures = reading["temperatures_celsius"]
                    if (type(temperatures) is not list or not isinstance(temperatures, list)
                        or len(temperatures) > total
                        or any(type(temp) is not int or not -50 <= temp <= 200 for temp in temperatures)):
                        raise ProtocolError()
                measurement = count
                expected_alert = count > 0
            if type(reading["alert"]) is not bool or reading["alert"] != expected_alert:
                raise ProtocolError()
        else:
            raise ProtocolError()
        vendor, parser = reading["vendor"], reading["parser"]
        if (
            vendor not in _VENDORS or not isinstance(vendor, str)
            or parser != ("unsupported" if status == "unsupported" else _parser_owner(vendor, name))
            or (status == "succeeded" and name not in _handlers(vendor, _HealthSelection())[0])
        ):
            raise ProtocolError()
        alert = alert or reading["alert"] is True
        findings.append(c.Finding(
            name, "health", "error" if status != "succeeded" or reading["alert"] else "info",
            "unknown" if status != "succeeded" else "alert" if reading["alert"] else "pass",
            c.public_value(measurement), c.public_value(threshold), vendor=vendor, parser=str(parser),
        ))
        if reading["alert"] is True:
            errors.append(c.SafeError(
                c.ErrorCategory.POLICY, c.ReasonCode.HEALTH_ALERT, c.Stage.EVALUATE,
                target_id=target_id, next_action="Inspect measured health alert; connection is not health.",
            ))
    if item["overall_alert"] != alert:
        raise ProtocolError()
    return dict(item), tuple(findings), tuple(errors)
