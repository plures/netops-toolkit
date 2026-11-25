"""Original C01 immutable configuration, closed decoding and tuning boundaries."""

import json
from dataclasses import FrozenInstanceError, replace

import pytest

from netops.ansible import contracts as c


def settings_api():
    from netops.ansible.settings import SettingsSnapshot, load_settings, resolve_settings

    return SettingsSnapshot, load_settings, resolve_settings


def test_complete_defaults_and_immutable_roundtrip():
    snapshot_type, load, resolve = settings_api()
    value = snapshot_type()
    assert (value.ansible.enabled, value.ansible.mode, value.ansible.enhanced) == (False, "audit", False)
    assert (value.controller.id, value.controller.wsl_distribution) == (None, None)
    assert value.NETOPS_STATE_ROOT is None
    assert value.inventory.cache_ttl_seconds == 300
    assert value.diagnostics.retention_days == 7
    assert (value.execution.target_limit, value.execution.ssh_concurrency,
            value.execution.ping_concurrency, value.execution.snmp_concurrency,
            value.execution.timeout_seconds) == (100, 5, 50, 10, 300)
    assert value.controller.start_timeout_seconds == 30
    assert (value.authorization.ttl_seconds, value.observation.max_age_seconds) == (60, 60)
    assert (value.backup.retention_count, value.backup.git) == (10, False)
    assert (value.health.cpu_threshold, value.health.memory_threshold) == (80.0, 85.0)
    assert load(c.canonical_bytes(value)) == value
    assert resolve(value, {}) is value
    with pytest.raises(FrozenInstanceError):
        value.execution.target_limit = 5


@pytest.mark.parametrize(("key", "low", "high"), [
    ("inventory.cache_ttl_seconds", 0, 86400),
    ("diagnostics.retention_days", 1, 365),
    ("execution.target_limit", 1, 4096),
    ("execution.ssh_concurrency", 1, 50),
    ("execution.ping_concurrency", 1, 50),
    ("execution.snmp_concurrency", 1, 10),
    ("execution.timeout_seconds", 1, 3600),
    ("controller.start_timeout_seconds", 1, 120),
    ("authorization.ttl_seconds", 1, 300),
    ("observation.max_age_seconds", 1, 300),
    ("backup.retention_count", 1, c.MAX_SAFE_INT),
])
def test_every_integer_setting_exact_range(key, low, high):
    snapshot_type, load, _ = settings_api()
    group, field = key.split(".")
    for candidate in (low, high, low - 1, high + 1, True, 1.0, "1", None):
        wire = json.loads(c.canonical_bytes(snapshot_type()))
        wire[group][field] = candidate
        if type(candidate) is int and low <= candidate <= high:
            assert getattr(getattr(load(json.dumps(wire).encode()), group), field) == candidate
        else:
            with pytest.raises(c.ContractError):
                load(json.dumps(wire).encode())


@pytest.mark.parametrize("key", [
    "ansible.enabled", "ansible.mode", "ansible.enhanced", "controller.id",
    "controller.wsl_distribution", "NETOPS_STATE_ROOT", "authorization.ttl_seconds",
    "observation.max_age_seconds", "inventory.cache_ttl_seconds", "backup.git",
    "consent", "qualified", "registry_digest", "NETOPS_VAULT", "NETOPS_LOG_DIR",
])
def test_forbidden_safety_and_owner_overrides(key):
    snapshot_type, _, resolve = settings_api()
    with pytest.raises(c.ContractError):
        resolve(snapshot_type(), {key: True})


def test_tuning_precedence_preserves_original_snapshot():
    snapshot_type, _, resolve = settings_api()
    stored = snapshot_type()
    updated = resolve(stored, {"execution.target_limit": 4096, "execution.timeout_seconds": 20,
                               "health.cpu_threshold": 90.0, "backup.retention_count": 12})
    assert updated.execution.target_limit == 4096
    assert updated.execution.timeout_seconds == 20
    assert updated.health.cpu_threshold == 90.0
    assert updated.backup.retention_count == 12
    assert updated.ansible is stored.ansible
    assert stored.execution.target_limit == 100
    for bad in ({"execution.target_limit": 4097}, {"health.cpu_threshold": float("nan")},
                {"execution": {"target_limit": 2}}, {"execution.timeout_seconds": True}):
        with pytest.raises(c.ContractError):
            resolve(stored, bad)


def test_strict_complete_settings_no_fallback_or_unknown_fields():
    snapshot_type, load, resolve = settings_api()
    base = json.loads(c.canonical_bytes(snapshot_type()))
    for bad in (b"{}", b'{"schema":"1.0","schema":"1.0"}', b'{"x":NaN}', b"[]"):
        with pytest.raises(c.ContractError):
            load(bad)
    for group in base:
        missing = dict(base)
        del missing[group]
        with pytest.raises(c.ContractError):
            load(json.dumps(missing).encode())
    for key, candidate in (("schema", "2.0"), ("unexpected", True),
                           ("NETOPS_STATE_ROOT", "relative"), ("NETOPS_STATE_ROOT", r"C:\safe\..\escape")):
        bad = dict(base)
        bad[key] = candidate
        with pytest.raises(c.ContractError):
            load(json.dumps(bad).encode())
    with pytest.raises(c.ContractError):
        resolve(replace(snapshot_type()), {"execution.timeout_seconds": float("inf")})


@pytest.mark.parametrize(("group", "field", "valid", "invalid"), [
    ("ansible", "enabled", True, (1, "true", None)),
    ("ansible", "enhanced", True, (0, "false", None)),
    ("ansible", "mode", "enforce", (True, "off", None)),
    ("controller", "id", "controller-1", (True, "", "cmd.exe /c")),
    ("controller", "wsl_distribution", "Ubuntu-24.04", (1, "", r"C:\evil.exe")),
    ("backup", "git", True, (1, "true", None)),
    ("logging", "level", "DEBUG", (1, "TRACE", None)),
    ("logging", "max_bytes", 1024, (True, 1023, 1.0, c.MAX_SAFE_INT + 1)),
    ("health", "cpu_threshold", 90.0, (True, -1.0, 100.1, float("nan"), float("inf"), "90")),
    ("health", "memory_threshold", 100.0, (False, -1, 101, float("-inf"), None)),
])
def test_remaining_every_type_and_boundary(group, field, valid, invalid):
    snapshot_type, load, _ = settings_api()
    for candidate in (valid,) + invalid:
        value = json.loads(c.canonical_bytes(snapshot_type()))
        value[group][field] = candidate
        if candidate is valid:
            assert getattr(getattr(load(json.dumps(value).encode()), group), field) == valid
        else:
            with pytest.raises(c.ContractError):
                load(json.dumps(value).encode())
    value[group]["unexpected"] = True
    with pytest.raises(c.ContractError):
        load(json.dumps(value).encode())
    del value[group][field]
    with pytest.raises(c.ContractError):
        load(json.dumps(value).encode())


@pytest.mark.parametrize("key", [
    "NETOPS_STATE_ROOT", "NETOPS_INVENTORY", "NETOPS_VAULT", "NETOPS_INVENTORY_CACHE",
    "NETOPS_TUI_SETTINGS", "NETOPS_LOG_DIR", "NETOPS_LOG_SETTINGS",
])
def test_explicit_native_owner_references_are_not_environment_reads(key):
    snapshot_type, load, resolve = settings_api()
    for path in (r"C:\owned\selected", "/owned/selected"):
        value = json.loads(c.canonical_bytes(snapshot_type()))
        value[key] = path
        assert getattr(load(json.dumps(value).encode()), key) == path
    for path in ("relative", r"C:relative", r"\\shared\path", "https://host", r"C:\x\..\y", 1, True):
        value[key] = path
        with pytest.raises(c.ContractError):
            load(json.dumps(value).encode())
    with pytest.raises(c.ContractError):
        resolve(snapshot_type(), {key: r"C:\other"})


def test_corrupt_snapshot_rejected_instead_of_defaulted():
    from netops.ansible import settings

    snapshot_type, load, resolve = settings_api()
    with pytest.raises(c.ContractError):
        snapshot_type(execution={})
    for schema in ("2.0", True, 1.0):
        with pytest.raises(c.ContractError):
            snapshot_type(schema=schema)
    for field in ("execution", "authorization", "observation"):
        defaults = snapshot_type()
        value = replace(defaults, **{field: replace(getattr(defaults, field))})
        object.__setattr__(getattr(value, field), next(iter(getattr(value, field).__dataclass_fields__)), True)
        with pytest.raises(c.ContractError):
            resolve(value, {})
    with pytest.raises(c.ContractError):
        load("not-bytes")
    with pytest.raises(c.ContractError):
        load(b" " * (c.MAX_CONTENT_BYTES + 1))
    with pytest.raises(c.ContractError):
        load(b'{"broken":')
    with pytest.raises(c.ContractError):
        resolve(snapshot_type(), [])
    for invalid in ("bogus", "execution.foo", 1):
        with pytest.raises(c.ContractError):
            resolve(snapshot_type(), {invalid: 1})
    assert settings._optional(None) is None
