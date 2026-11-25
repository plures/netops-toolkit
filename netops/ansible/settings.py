"""Pure C01 settings values; bootstrap and protected publication belong to hosts.

No filesystem, environment, clock, consent or qualification lookup occurs here.
Native owner references are optional selections, not adopted environment values.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, fields, replace
from pathlib import PurePosixPath, PureWindowsPath
from typing import Literal

from .contracts import (
    DEFAULT_TARGET_LIMIT,
    MAX_CONTENT_BYTES,
    MAX_TARGET_LIMIT,
    ContractError,
    counter,
    text,
)


def _integer(value: object, low: int, high: int) -> int:
    result = counter(value)
    if not low <= result <= high:
        raise ContractError()
    return result


def _boolean(value: object) -> bool:
    if type(value) is not bool or not isinstance(value, bool):
        raise ContractError()
    return value


def _choice(value: object, allowed: tuple[str, ...]) -> str:
    result = text(value)
    if result not in allowed:
        raise ContractError()
    return result


def _optional(value: object, *, path: bool = False) -> str | None:
    if value is None:
        return None
    result = text(value)
    if path:
        windows, posix = PureWindowsPath(result), PurePosixPath(result)
        if (
            not (windows.is_absolute() or posix.is_absolute())
            or ".." in windows.parts or ".." in posix.parts
            or "://" in result or result.startswith(("\\\\", "//"))
        ):
            raise ContractError()
    return result


def _threshold(value: object) -> float:
    if type(value) not in (int, float) or not isinstance(value, (int, float)):
        raise ContractError()
    if isinstance(value, float) and not math.isfinite(value):
        raise ContractError()
    if not 0 <= value <= 100:
        raise ContractError()
    return float(value)


@dataclass(frozen=True)
class AnsibleSettings:
    """Companion kill switch and local flight, never authority."""

    enabled: bool = False
    mode: str = "audit"
    enhanced: bool = False

    def __post_init__(self) -> None:
        """Validate exact flags and closed mode."""
        _boolean(self.enabled)
        _choice(self.mode, ("audit", "enforce"))
        _boolean(self.enhanced)


@dataclass(frozen=True)
class ControllerSettings:
    """Selected controller identities still require host qualification."""

    id: str | None = None
    wsl_distribution: str | None = None
    start_timeout_seconds: int = 30

    def __post_init__(self) -> None:
        """Reject command/path-shaped identities, without claiming readiness."""
        for value in (self.id, self.wsl_distribution):
            name = _optional(value)
            if name is not None and any(not (c.isalnum() or c in "._-") for c in name):
                raise ContractError()
        _integer(self.start_timeout_seconds, 1, 120)


@dataclass(frozen=True)
class InventorySettings:
    """Source-bound cache tuning; zero disables caching."""

    cache_ttl_seconds: int = 300

    def __post_init__(self) -> None:
        """Validate TTL without reading or refreshing a cache."""
        _integer(self.cache_ttl_seconds, 0, 86400)


@dataclass(frozen=True)
class DiagnosticsSettings:
    """Retention only for explicitly persisted diagnostic artifacts."""

    retention_days: int = 7

    def __post_init__(self) -> None:
        """Reject invalid diagnostic retention."""
        _integer(self.retention_days, 1, 365)


@dataclass(frozen=True)
class ExecutionSettings:
    """Bounded selection, protocol queues and operation timeout."""

    target_limit: int = DEFAULT_TARGET_LIMIT
    ssh_concurrency: int = 5
    ping_concurrency: int = 50
    snmp_concurrency: int = 10
    timeout_seconds: int = 300

    def __post_init__(self) -> None:
        """Validate all absolute bounds without clipping work."""
        _integer(self.target_limit, 1, MAX_TARGET_LIMIT)
        _integer(self.ssh_concurrency, 1, 50)
        _integer(self.ping_concurrency, 1, 50)
        _integer(self.snmp_concurrency, 1, 10)
        _integer(self.timeout_seconds, 1, 3600)


@dataclass(frozen=True)
class AuthorizationSettings:
    """Grant duration configuration; not a grant or consent receipt."""

    ttl_seconds: int = 60

    def __post_init__(self) -> None:
        """Freshness cannot be disabled or extended by tuning overrides."""
        _integer(self.ttl_seconds, 1, 300)


@dataclass(frozen=True)
class ObservationSettings:
    """Maximum execution observation age; supplied ages confer no freshness."""

    max_age_seconds: int = 60

    def __post_init__(self) -> None:
        """Validate positive bounded observation freshness."""
        _integer(self.max_age_seconds, 1, 300)


@dataclass(frozen=True)
class BackupSettings:
    """Backup preferences never implicitly select prune or Git effects."""

    retention_count: int = 10
    git: bool = False

    def __post_init__(self) -> None:
        """Require exact positive retention and explicit boolean Git preference."""
        counter(self.retention_count, positive=True)
        _boolean(self.git)


@dataclass(frozen=True)
class HealthSettings:
    """Native default thresholds; explicit role-specific 90 remains valid."""

    cpu_threshold: float = 80.0
    memory_threshold: float = 85.0

    def __post_init__(self) -> None:
        """Normalize finite percentages, never bool or healthy-on-error values."""
        for name in ("cpu_threshold", "memory_threshold"):
            object.__setattr__(self, name, _threshold(getattr(self, name)))


@dataclass(frozen=True)
class LoggingSettings:
    """A non-effectful snapshot of native logging defaults, not initialization."""

    level: str = "INFO"
    max_bytes: int = 10 * 1024 * 1024

    def __post_init__(self) -> None:
        """Keep native bounded logging constraints without changing its owner."""
        _choice(self.level, ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"))
        counter(self.max_bytes, positive=True)
        if self.max_bytes < 1024:
            raise ContractError()


@dataclass(frozen=True)
class SettingsSnapshot:
    """Complete immutable version-1 settings consumed as one bound value."""

    ansible: AnsibleSettings = AnsibleSettings()
    controller: ControllerSettings = ControllerSettings()
    inventory: InventorySettings = InventorySettings()
    diagnostics: DiagnosticsSettings = DiagnosticsSettings()
    execution: ExecutionSettings = ExecutionSettings()
    authorization: AuthorizationSettings = AuthorizationSettings()
    observation: ObservationSettings = ObservationSettings()
    backup: BackupSettings = BackupSettings()
    health: HealthSettings = HealthSettings()
    logging: LoggingSettings = LoggingSettings()
    NETOPS_STATE_ROOT: str | None = None
    NETOPS_INVENTORY: str | None = None
    NETOPS_VAULT: str | None = None
    NETOPS_INVENTORY_CACHE: str | None = None
    NETOPS_TUI_SETTINGS: str | None = None
    NETOPS_LOG_DIR: str | None = None
    NETOPS_LOG_SETTINGS: str | None = None
    schema: Literal["1.0"] = "1.0"

    def __post_init__(self) -> None:
        """Revalidate all typed groups and explicit paths without host I/O."""
        if type(self.schema) is not str or self.schema != "1.0":
            raise ContractError()
        for name, kind in (
            ("ansible", AnsibleSettings), ("controller", ControllerSettings),
            ("inventory", InventorySettings), ("diagnostics", DiagnosticsSettings),
            ("execution", ExecutionSettings), ("authorization", AuthorizationSettings),
            ("observation", ObservationSettings), ("backup", BackupSettings),
            ("health", HealthSettings), ("logging", LoggingSettings),
        ):
            group = getattr(self, name)
            if type(group) is not kind:
                raise ContractError()
            group.__post_init__()
        for field in fields(self):
            if field.name.startswith("NETOPS_"):
                _optional(getattr(self, field.name), path=True)


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError()
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ContractError()


def _group(root: Mapping[str, object], name: str, expected: tuple[str, ...]) -> Mapping[str, object]:
    value = root[name]
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ContractError()
    return value


def load_settings(data: bytes) -> SettingsSnapshot:
    """Decode a complete settings document, never default malformed input."""
    if type(data) is not bytes or len(data) > MAX_CONTENT_BYTES:
        raise ContractError()
    try:
        value: object = json.loads(data, object_pairs_hook=_pairs, parse_constant=_constant)
        if not isinstance(value, dict) or set(value) != {f.name for f in fields(SettingsSnapshot)}:
            raise ContractError()
        if value["schema"] != "1.0":
            raise ContractError()
        a = _group(value, "ansible", ("enabled", "mode", "enhanced"))
        c = _group(value, "controller", ("id", "wsl_distribution", "start_timeout_seconds"))
        i = _group(value, "inventory", ("cache_ttl_seconds",))
        d = _group(value, "diagnostics", ("retention_days",))
        e = _group(value, "execution", ("target_limit", "ssh_concurrency", "ping_concurrency",
                                      "snmp_concurrency", "timeout_seconds"))
        auth = _group(value, "authorization", ("ttl_seconds",))
        obs = _group(value, "observation", ("max_age_seconds",))
        b = _group(value, "backup", ("retention_count", "git"))
        h = _group(value, "health", ("cpu_threshold", "memory_threshold"))
        log = _group(value, "logging", ("level", "max_bytes"))
        return SettingsSnapshot(
            ansible=AnsibleSettings(_boolean(a["enabled"]), text(a["mode"]), _boolean(a["enhanced"])),
            controller=ControllerSettings(_optional(c["id"]), _optional(c["wsl_distribution"]),
                                          counter(c["start_timeout_seconds"])),
            inventory=InventorySettings(counter(i["cache_ttl_seconds"])),
            diagnostics=DiagnosticsSettings(counter(d["retention_days"])),
            execution=ExecutionSettings(
                counter(e["target_limit"]), counter(e["ssh_concurrency"]),
                counter(e["ping_concurrency"]), counter(e["snmp_concurrency"]),
                counter(e["timeout_seconds"]),
            ),
            authorization=AuthorizationSettings(counter(auth["ttl_seconds"])),
            observation=ObservationSettings(counter(obs["max_age_seconds"])),
            backup=BackupSettings(counter(b["retention_count"]), _boolean(b["git"])),
            health=HealthSettings(_threshold(h["cpu_threshold"]), _threshold(h["memory_threshold"])),
            logging=LoggingSettings(text(log["level"]), counter(log["max_bytes"])),
            NETOPS_STATE_ROOT=_optional(value["NETOPS_STATE_ROOT"], path=True),
            NETOPS_INVENTORY=_optional(value["NETOPS_INVENTORY"], path=True),
            NETOPS_VAULT=_optional(value["NETOPS_VAULT"], path=True),
            NETOPS_INVENTORY_CACHE=_optional(value["NETOPS_INVENTORY_CACHE"], path=True),
            NETOPS_TUI_SETTINGS=_optional(value["NETOPS_TUI_SETTINGS"], path=True),
            NETOPS_LOG_DIR=_optional(value["NETOPS_LOG_DIR"], path=True),
            NETOPS_LOG_SETTINGS=_optional(value["NETOPS_LOG_SETTINGS"], path=True),
        )
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        raise ContractError() from None


def resolve_settings(snapshot: SettingsSnapshot, overrides: Mapping[str, object]) -> SettingsSnapshot:
    """Apply closed tuning-only dotted overrides, retaining every safety value."""
    if type(snapshot) is not SettingsSnapshot or not isinstance(overrides, Mapping):
        raise ContractError()
    snapshot.__post_init__()
    allowed = {
        "execution": ("target_limit", "ssh_concurrency", "ping_concurrency", "snmp_concurrency",
                      "timeout_seconds"),
        "controller": ("start_timeout_seconds",),
        "diagnostics": ("retention_days",),
        "backup": ("retention_count",),
        "health": ("cpu_threshold", "memory_threshold"),
    }
    result = snapshot
    for key, value in overrides.items():
        if type(key) is not str or key.count(".") != 1:
            raise ContractError()
        group, name = key.split(".")
        if name not in allowed.get(group, ()):
            raise ContractError()
        result = replace(result, **{group: replace(getattr(result, group), **{name: value})})
    return result
