"""O03 author native semantic controls, not independent qualification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from netops.ansible import contracts as c
from netops.ansible.policy import LocalReferencePolicyEngine, PolicyIdentity, load_policy
from netops.ansible.workflows import WorkflowService, hydrate_inputs
from netops.change.diff import ConfigStyle, diff_configs, parse_config


class Bomb:
    def __getattr__(self, name):
        raise AssertionError("unexpected effect: " + name)


class Clock:
    def monotonic(self):
        return 1.0


@pytest.fixture
def pure_composition():
    root = Path(__file__).parents[1] / "netops/ansible/policy"
    source = (root / "ansible_molecule.px").read_bytes()
    contracts = (root / "ansible_molecule.contracts.px").read_bytes()
    bundle = (root / "bundle.json").read_bytes()
    metadata = json.loads(bundle)
    identity = PolicyIdentity(
        canonical_revision=metadata["canonical_revision"],
        source_sha256=hashlib.sha256(source).hexdigest(),
        contracts_sha256=hashlib.sha256(contracts).hexdigest(),
        bundle_sha256=hashlib.sha256(bundle).hexdigest(),
        rule_manifest=tuple(item["id"] for item in metadata["manifest"]),
        reducer_version=metadata["reducer_version"],
    )
    engine = LocalReferencePolicyEngine(load_policy(source, contracts, bundle, identity))
    bomb = Bomb()
    service = WorkflowService(engine, bomb, bomb, bomb, bomb, bomb, bomb, bomb)
    request = c.OperationRequest(
        "a7a197a2-7f68-4a9f-b79c-7e9a21ffab81", "compare.compare",
        c.Mode.PREVIEW, c.Scope(()),
        c.Context("local", "a" * 64, "author-fixture", "b" * 64,
                  identity, "c" * 64, "d" * 64),
    )
    return service, request


def input_source(kind, value, *, parser="parser-1", vendor="vendor-1", fmt="text"):
    content = value.encode() if isinstance(value, str) else json.dumps(value).encode()
    return c.InputSource(
        c.InputRef(kind, "selected-" + kind, hashlib.sha256(content).hexdigest()),
        fmt, content, parser, vendor,
    )


def bound(request, *sources):
    request = replace(request, inputs=tuple(item.source for item in sources))
    return request, hydrate_inputs(request, sources, Clock())


def test_native_duplicate_directives_do_not_disappear():
    result = diff_configs("a\na\na\na\n", "a\na\n", style="flat")
    assert len(result.removed) == 2


def test_native_detects_junos_bracket_structure():
    value = "system {\n    host-name r1;\n}\n"
    assert ConfigStyle.detect(value) == ConfigStyle.JUNOS
    assert len(parse_config(value, ConfigStyle.JUNOS)) == 1


@pytest.mark.parametrize(("style", "before", "after"), [
    ("cisco", "interface Eth1\n description before\n", "interface Eth1\n description after\n"),
    ("junos", "set system host-name before\n", "set system host-name after\n"),
    ("flat", "a\nb\n", "a\nc\n"),
])
def test_bound_style_comparison_is_repeatable_and_effect_free(pure_composition, style, before, after):
    service, request = pure_composition
    request, loaded = bound(
        request, input_source("before", before, parser=style),
        input_source("after", after, parser=style),
    )
    with patch("builtins.open", side_effect=AssertionError("hidden read")), \
            patch("pathlib.Path.open", side_effect=AssertionError("hidden read")), \
            patch("time.monotonic", side_effect=AssertionError("clock")), \
            patch("logging.Logger._log", side_effect=AssertionError("log")):
        first = service.preview(request, loaded)
        second = service.preview(request, loaded)
    assert c.canonical_bytes(first) == c.canonical_bytes(second)
    assert first.native_payload["comparison"]["status"] == "drift"
    assert first.effects == ()


def test_normalization_and_missing_are_not_fabricated_healthy(pure_composition):
    service, request = pure_composition
    request, loaded = bound(
        request, input_source("before", "a\nb\n", parser="flat"),
        input_source("after", "b\na\n", parser="flat"),
    )
    assert service.preview(request, loaded).native_payload["comparison"]["status"] == "no-change"
    request, loaded = bound(
        request, input_source("before", "", parser="flat"),
        input_source("after", "", parser="flat"),
    )
    assert service.preview(request, loaded).native_payload["comparison"]["status"] == "blocked"


@pytest.mark.parametrize(("parser", "vendor", "before", "after"), [
    ("unknown-parser", "vendor-1", "a\n", "b\n"),
    ("junos", "cisco_ios", "set system host-name a\n", "set system host-name b\n"),
    ("junos", "vendor-1", "system {\n host-name a;\n", "system {\n host-name b;\n}\n"),
    ("flat", "vendor-1", "<script>x</script>", "b\n"),
])
def test_invalid_or_unsupported_parser_input_rejects_before_native_owner(
    pure_composition, parser, vendor, before, after,
):
    service, request = pure_composition
    request, loaded = bound(
        request, input_source("before", before, parser=parser, vendor=vendor),
        input_source("after", after, parser=parser, vendor=vendor),
    )
    with patch("netops.ansible.workflows.diff_configs", side_effect=AssertionError("parser entered")):
        with pytest.raises(c.ContractError):
            service.preview(request, loaded)


def test_swapped_digest_tamper_and_vendor_mismatch_reject(pure_composition):
    service, request = pure_composition
    request, loaded = bound(request, input_source("before", "a"), input_source("after", "b"))
    with pytest.raises(c.ContractError):
        service.preview(request, replace(loaded, contents=tuple(reversed(loaded.contents))))
    corrupted = replace(loaded.contents[0], content=b"tampered")
    with pytest.raises(c.ContractError):
        service.preview(request, replace(loaded, contents=(corrupted, loaded.contents[1])))
    corrupted = replace(loaded.contents[1], vendor_revision="juniper_junos")
    with pytest.raises(c.ContractError):
        service.preview(request, replace(loaded, contents=(loaded.contents[0], corrupted)))


def test_bound_pair_with_distinct_vendor_identities_rejects_before_diff(pure_composition):
    service, request = pure_composition
    request, loaded = bound(
        request, input_source("before", "interface Eth1\n", vendor="cisco_ios"),
        input_source("after", "interface Eth1\n", vendor="juniper_junos"),
    )
    with pytest.raises(c.ContractError):
        service.preview(request, loaded)


def test_loaded_content_digest_guard_is_independently_load_bearing():
    from netops.ansible.workflows import _content

    source = input_source("before", "a\n")
    item = c.LoadedInput(source.source, "text", b"tampered\n", "parser-1", "vendor-1")
    with pytest.raises(c.ContractError):
        _content(item)


def alert(host="r1"):
    return {
        "host": host, "device_type": "cisco_ios", "success": True,
        "timestamp": "2026-11-19T22:00:00Z", "checks": {"cpu": {"alert": True}},
    }


def test_remediation_is_real_guarded_yaml_deterministic_without_time_or_uuid(pure_composition):
    service, request = pure_composition
    request = replace(request, operation="compare.generate", scope=c.Scope(("r1",)))
    request, loaded = bound(request, input_source("findings", alert(), fmt="json"))
    with patch("uuid.uuid4", side_effect=AssertionError("volatile uuid")), \
            patch("builtins.open", side_effect=AssertionError("read")), \
            patch("time.monotonic", side_effect=AssertionError("clock")), \
            patch("logging.Logger._log", side_effect=AssertionError("log")):
        first = service.preview(request, loaded)
        second = service.preview(request, loaded)
    assert c.canonical_bytes(first) == c.canonical_bytes(second)
    payload = first.native_payload
    plays = yaml.safe_load(payload["generated_yaml"])
    assert plays[0]["hosts"] == "r1"
    assert plays[0]["vars"]["dry_run"] == "true"
    tasks = plays[0]["tasks"]
    assert tasks[0]["ansible.builtin.pause"]
    assert tasks[0]["when"] == "not dry_run | bool"
    assert any("block" in task and "rescue" in task for task in tasks)
    assert payload["collect_authorized"] is False
    assert payload["apply_authorized"] is False
    assert first.effects == ()


@pytest.mark.parametrize("host", ["all", "r1:r2", "{{ lookup('pipe','bad') }}", "*"])
def test_generation_never_accepts_executable_target_patterns(pure_composition, host):
    service, request = pure_composition
    request = replace(request, operation="compare.generate", scope=c.Scope(("r1",)))
    request, loaded = bound(request, input_source("findings", alert(host), fmt="json"))
    with pytest.raises(c.ContractError):
        service.preview(request, loaded)


def test_unsupported_alert_is_not_no_active_alert(pure_composition):
    service, request = pure_composition
    request = replace(request, operation="compare.remediation-preview")
    value = alert()
    value["checks"] = {"unknown": {"alert": True}}
    request, loaded = bound(request, input_source("findings", value, fmt="json"))
    payload = service.preview(request, loaded).native_payload
    assert payload["coverage"][0]["status"] == "unsupported"
    assert payload["generated"] == ()


def test_native_generic_command_does_not_drop_later_commands():
    from netops.playbooks.generator import _cmd_task

    task = _cmd_task("pre", "_default", ["show a", "show b"])
    assert task["loop"] == ["show a", "show b"]
