"""Static and Jinja contract tests for the PLU-43 Ansible health role.

These are synthetic tests of expression semantics, not Ansible/Molecule or
real Cisco/Nokia device integration. Do not use as deployment qualification.
"""

from pathlib import Path

import pytest
import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment

ROLE = Path(__file__).resolve().parents[1] / "netops/ansible/roles/netops_health"
ENV = NativeEnvironment(undefined=StrictUndefined)
# Ansible supplies its own bool filter; vanilla Jinja does not.
# These synthetic tests pass Python booleans, so bool() matches that subset.
ENV.filters["bool"] = bool


def _tasks() -> list[dict]:
    data = yaml.safe_load((ROLE / "tasks/main.yml").read_text(encoding="utf-8"))
    assert isinstance(data, list)
    return data


def _task(name: str) -> dict:
    return next(task for task in _tasks() if task["name"] == name)


def _defaults() -> dict:
    return yaml.safe_load((ROLE / "defaults/main.yml").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("cpu", "memory", "interfaces", "bgp", "expected"),
    [
        (True, True, False, False, ["health"]),
        (True, False, False, False, ["health"]),
        (False, True, False, False, ["health"]),
        (True, True, True, False, ["health", "interfaces"]),
        (True, True, False, True, ["health", "bgp"]),
        (False, False, True, False, ["interfaces"]),
        (False, False, False, True, ["bgp"]),
        (True, True, True, True, ["health", "interfaces", "bgp"]),
        (False, False, False, False, []),
    ],
)
def test_gather_contains_only_supported_nonempty_selectors(
    cpu: bool, memory: bool, interfaces: bool, bgp: bool, expected: list[str]
) -> None:
    expression = _task("Build supported fact categories without empty or unsupported selectors")[
        "ansible.builtin.set_fact"
    ]["_netops_health_gather"]
    actual = ENV.from_string(expression).render(
        netops_health_check_cpu=cpu,
        netops_health_check_memory=memory,
        netops_health_check_interfaces=interfaces,
        netops_health_check_bgp=bgp,
    )
    assert actual == expected
    assert not set(actual).difference({"health", "interfaces", "bgp"})


def _passes(name: str, field: str, value: object, evidence: str) -> bool:
    assertions = _task(name)["ansible.builtin.assert"]["that"]
    obs = {field: value, "evidence": {"cpu": evidence, "memory": evidence}}
    if value is None:
        del obs[field]
    context = {
        "_netops_health_observation": obs,
        "netops_health_cpu_critical": 90,
        "netops_health_memory_critical": 90,
    }
    for assertion in assertions:
        if not ENV.compile_expression(assertion)(**context):
            return False
    return True


@pytest.mark.parametrize(
    ("value", "evidence", "expected"),
    [
        (0, "OBSERVED", True),
        (89.9, "OBSERVED", True),
        (90, "OBSERVED", False),
        (99, "OBSERVED", False),
        (0, "UNKNOWN", False),
        (None, "UNKNOWN", False),
        (99, "UNSUPPORTED", False),
    ],
)
def test_cpu_fail_closed(value: object, evidence: str, expected: bool) -> None:
    assert _passes(
        "Reject missing CPU evidence or critical CPU utilization",
        "cpu_percent",
        value,
        evidence,
    ) is expected


@pytest.mark.parametrize(
    ("value", "evidence", "expected"),
    [
        (0, "OBSERVED", True),
        (89.9, "OBSERVED", True),
        (90, "OBSERVED", False),
        (99, "OBSERVED", False),
        (0, "UNKNOWN", False),
        (None, "UNKNOWN", False),
        (99, "UNSUPPORTED", False),
    ],
)
def test_memory_fail_closed(value: object, evidence: str, expected: bool) -> None:
    assert _passes(
        "Reject missing memory evidence or critical memory utilization",
        "memory_percent",
        value,
        evidence,
    ) is expected


def test_default_collectors_do_not_claim_uncertified_health() -> None:
    defaults = _defaults()
    assert defaults["netops_health_check_cpu"] is True
    assert defaults["netops_health_check_memory"] is True
    assert defaults["netops_health_check_interfaces"] is False
    assert defaults["netops_health_check_bgp"] is False
    assert defaults["netops_health_check_ospf"] is False
    assert defaults["netops_health_fail_on_critical"] is True
    assert "default('')" in defaults["netops_health_vendor"]


def test_role_uses_nested_evidence_and_never_defaults_missing_to_zero() -> None:
    content = (ROLE / "tasks/main.yml").read_text(encoding="utf-8")
    assert "_health_facts.ansible_facts.netops.health" in content
    assert "evidence.cpu" in content and "evidence.memory" in content
    assert "default(0)" not in content
    assert "netops_memory_used_pct" not in content
    assert "netops_cpu |" not in content


def test_ospf_is_explicitly_rejected() -> None:
    conditions = _task("Reject unsupported or uncertifiable requested health checks")[
        "ansible.builtin.assert"
    ]["that"]
    assert "not (netops_health_check_ospf | bool)" in conditions


def test_no_checks_does_not_succeed() -> None:
    assertions = _task("Refuse empty health checks")["ansible.builtin.assert"]["that"]
    assert "_netops_health_gather | length > 0" in assertions
