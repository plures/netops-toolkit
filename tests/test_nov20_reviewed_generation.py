"""Independent frozen AC-009 source/selection guards and actual canonical output."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from unittest.mock import patch

import pytest
import yaml

from netops.ansible import contracts as c
from netops.ansible.execution import _Rejected
from netops.ansible.workflows import bind_settings, hydrate_inputs
from netops.dependencies._installation import _installed_parts
from tests.test_companion_compare import bound, input_source
from tests.test_companion_compare import pure_composition as pure_composition
from tests.test_workflow_execution import Clock
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed
from tests.test_workflow_execution import policy as policy


def record(host="r1"):
    return {
        "host": host, "device_type": "cisco_ios", "success": True,
        "timestamp": "2026-11-20T06:30:00Z", "checks": {"cpu": {"alert": True}},
    }


def generation(sources, value, targets=("r1",)):
    content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ref = c.InputRef("findings", "owned-findings", hashlib.sha256(content).hexdigest())
    request = replace(
        sources.value.request, operation="compare.generate", mode=c.Mode.OUTPUT,
        scope=c.Scope(targets), inputs=(ref,), output_intent=c.OutputIntent(("yaml",), "owned"),
    )
    observations = tuple(c.Observation(
        "original-source-" + target, target, c.digest(request.context), request.context.route_digest,
        request.context.controller_id, ref, ref.digest, "2026-11-20T06:30:00Z", 0.0,
    ) for target in targets)
    sources.value = replace(
        sources.value, request=request,
        sources=(c.InputSource(ref, "json", content, "parser-1", "vendor-1",
                               observations=observations),),
    )
    return request


@pytest.mark.parametrize("disposition", ["failed", "no-alert", "unsupported", "empty", "missing"])
def test_no_eligible_generation_never_reviews_or_publishes_empty_success(output_composed, disposition):
    service, host, sources, effects, filesystem, _ = output_composed
    item = record()
    if disposition == "failed":
        item["success"] = False
    elif disposition == "no-alert":
        item["checks"] = {"cpu": {"alert": False}}
    elif disposition == "unsupported":
        item["checks"] = {"unregistered-check": {"alert": True}}
    value = {"results": []} if disposition == "empty" else {} if disposition == "missing" else item
    request = generation(sources, value)
    outcome = service.execute(request)
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert outcome.exit_code != 0
    assert outcome.artifacts == () and filesystem.bindings == [] and effects.calls == []
    # No fake consent or synthetic effect selection: use the original review.
    with pytest.raises((c.ContractError, _Rejected)):
        host.review(service, request)
    assert filesystem.bindings == [] and effects.calls == []


def test_mixed_generation_preserves_failed_and_missing_exact_selected_coverage(output_composed):
    service, host, sources, effects, filesystem, _ = output_composed
    failed = record("r2")
    failed["success"] = False
    request = generation(sources, {"results": [record(), failed]}, ("r1", "r2", "r3"))
    loaded = bind_settings(
        request, hydrate_inputs(request, sources.value.sources, Clock()), sources.value.settings,
    )
    preview = service.preview(request, loaded)
    assert c.canonical_bytes(preview.native_payload["coverage"]) == (
        b'[{"status":"unexecuted","target_id":"r1"},{"status":"failed","target_id":"r2"},'
        b'{"status":"missing","target_id":"r3"}]'
    )
    assert len(preview.native_payload["generated"]) == 1
    grant = host.review(service, request)
    outcome = service.execute(request, grant)
    assert outcome.status != c.OutcomeStatus.SUCCEEDED and outcome.exit_code != 0
    assert tuple(target.target_id for target in outcome.targets) == ("r1", "r2", "r3")
    assert outcome.targets[1].status == c.OutcomeStatus.FAILED
    assert outcome.targets[2].status != c.OutcomeStatus.SUCCEEDED
    assert len(outcome.artifacts) == len(filesystem.bindings) == 1
    assert filesystem.content == preview.native_payload["generated_yaml"].encode()
    assert b"hosts: r1" in filesystem.content and b"hosts: r2" not in filesystem.content
    assert effects.calls == []
    assert service.execute(request, grant).status != c.OutcomeStatus.SUCCEEDED
    assert len(filesystem.bindings) == 1


def test_original_one_use_generation_consent_is_guarded_and_deterministic(output_composed):
    service, host, sources, effects, filesystem, _ = output_composed
    request = generation(sources, record())
    loaded = bind_settings(
        request, hydrate_inputs(request, sources.value.sources, Clock()), sources.value.settings,
    )
    first = service.preview(request, loaded)
    assert c.canonical_bytes(first) == c.canonical_bytes(service.preview(request, loaded))
    assert first.native_payload["collect_authorized"] is False
    assert first.native_payload["apply_authorized"] is False
    assert filesystem.bindings == [] and effects.calls == []
    grant = host.review(service, request)
    result = service.execute(request, grant)
    assert result.status == c.OutcomeStatus.SUCCEEDED and result.exit_code == 0
    assert len(result.artifacts) == len(filesystem.bindings) == 1
    assert filesystem.content == first.native_payload["generated_yaml"].encode()
    play = yaml.safe_load(filesystem.content)[0]
    assert play["hosts"] == "r1" and play["vars"]["dry_run"] == "true"
    assert play["tasks"][0]["when"] == "not dry_run | bool"
    assert any(task.get("block") and task.get("rescue") for task in play["tasks"])
    assert effects.calls == []
    assert service.execute(request, grant).status != c.OutcomeStatus.SUCCEEDED
    assert len(filesystem.bindings) == 1


@pytest.mark.parametrize("mutation", [
    "results-object", "results-scalar", "record-scalar", "missing-host", "duplicate-host",
    "nonselected-host", "unknown-vendor", "vendor-scalar", "success-number",
    "checks-array", "check-scalar", "alert-number", "missing-alert", "host-pattern",
])
def test_malformed_generation_refused_before_native_owner(pure_composition, mutation):
    service, request = pure_composition
    request = replace(request, operation="compare.generate", scope=c.Scope(("r1",)))
    item = record()
    value = {"results": [item]}
    if mutation == "results-object":
        value = {"results": item}
    elif mutation == "results-scalar":
        value = {"results": 4}
    elif mutation == "record-scalar":
        value = {"results": [4]}
    elif mutation == "missing-host":
        item.pop("host")
    elif mutation == "duplicate-host":
        value["results"].append(dict(item))
    elif mutation == "nonselected-host":
        item["host"] = "r2"
    elif mutation == "unknown-vendor":
        item["device_type"] = "unqualified"
    elif mutation == "vendor-scalar":
        item["device_type"] = 4
    elif mutation == "success-number":
        item["success"] = 1
    elif mutation == "checks-array":
        item["checks"] = []
    elif mutation == "check-scalar":
        item["checks"] = {"cpu": 4}
    elif mutation == "alert-number":
        item["checks"] = {"cpu": {"alert": 1}}
    elif mutation == "missing-alert":
        item["checks"] = {"cpu": {}}
    else:
        item["host"] = "{{ lookup('pipe', 'unsafe') }}"
    request, loaded = bound(request, input_source("findings", value, fmt="json"))
    with pytest.raises(c.ContractError):
        service.preview(request, loaded)


@pytest.mark.parametrize(("parser", "before"), [
    ("junos", "set system host-name a\nsystem {\n}\n"),
    ("junos", "system {{\n}\n"),
    ("junos", "system { }\n"),
    ("junos", "system {\n host-name a\n}\n"),
    ("junos", "}\n"),
    ("junos", "system {\n host-name a;\n"),
    ("junos", "system {\n host-name a; }\n"),
    ("cisco", "set system host-name a\n"),
    ("flat", "system {\n}\n"),
    ("flat", "a\x00b\n"),
    ("flat", '{"config":"a"}'),
    ("flat", '["a"]'),
])
def test_malformed_mixed_config_is_refused_before_parser(pure_composition, parser, before):
    service, request = pure_composition
    request, loaded = bound(
        request, input_source("before", before, parser=parser),
        input_source("after", "set system host-name b\n" if parser == "junos" else "b\n",
                     parser=parser),
    )
    with patch("netops.ansible.workflows.diff_configs",
               side_effect=AssertionError("malformed input reached native parser")):
        with pytest.raises(c.ContractError):
            service.preview(request, loaded)


@pytest.mark.parametrize("name", [
    "Lib/site-packages/setuptools/script (dev).tmpl",
    "Lib/site-packages/setuptools/script.tmpl",
    "Lib/site-packages/pkg/data (1)/legal-file.txt",
])
def test_legitimate_installed_data_is_not_rejected_as_executable_selection(name):
    assert _installed_parts(name) == tuple(name.split("/"))


@pytest.mark.parametrize("name", [
    "../outside", "a/../b", "a/./b", "/absolute", "a//b", "C:/outside",
    "a\\outside", "a/file:secret", "a/file.", "a/file ", "a/ file", "a/CON",
    "a/con.txt", "a/COM1.data", "a/lpt9", "a/NUL .txt", "a/aux", "a/PRN",
    "a/\x00file", "a/{{lookup}}", "a/*", "a/é", "a/" + "x" * 161,
])
def test_installed_data_grammar_retains_traversal_ads_alias_reserved_rejection(name):
    with pytest.raises(c.ContractError):
        _installed_parts(name)


@pytest.mark.parametrize("intent", [
    c.OutputIntent(("json",), "owned"),
    c.OutputIntent(("pdf",), "owned"),
    c.OutputIntent(("yaml", "json"), "owned"),
    c.OutputIntent(("yaml",), "owned", retention=True),
    c.OutputIntent(("yaml",), "owned", git=True),
])
def test_generation_wrong_output_kind_and_separate_retention_git_never_get_consent(
    output_composed, intent,
):
    service, host, sources, effects, filesystem, _ = output_composed
    request = replace(generation(sources, record()), output_intent=intent)
    sources.value = replace(sources.value, request=request)
    with pytest.raises((c.ContractError, _Rejected)):
        host.review(service, request)
    assert service.execute(request).status != c.OutcomeStatus.SUCCEEDED
    assert filesystem.bindings == [] and effects.calls == []


def test_actual_output_facts_reject_nonexistent_occurrence_before_consent(output_composed):
    service, host, sources, effects, filesystem, _ = output_composed
    request = generation(sources, record())
    loaded = bind_settings(
        request, hydrate_inputs(request, sources.value.sources, Clock()), sources.value.settings,
    )
    plan = service.preview(request, loaded)
    with pytest.raises(c.ContractError):
        host._facts(plan, 1000, effect=replace(plan.effects[0], ordinal=1))
    assert filesystem.bindings == [] and effects.calls == []


def test_actual_remediation_no_alert_whole_literal_preserves_native_none(pure_composition):
    from netops.ansible.workflows import _remediation, _validate_loaded

    service, request = pure_composition
    request = replace(request, operation="compare.remediation-preview", scope=c.Scope(("r1",)))
    value = record()
    value["checks"] = {"cpu": {"alert": False}}
    request, loaded = bound(request, input_source("findings", value, fmt="json"))
    projection = _remediation(request, loaded, _validate_loaded(request, loaded))
    assert c.canonical_bytes(projection) == (
        b'{"apply_authorized":false,"collect_authorized":false,'
        b'"coverage":[{"status":"no-active-alert","target_id":"r1"}],"dry_run":true,'
        b'"execution_performed":false,"generated":[],"generated_yaml":null}'
    )


@pytest.mark.parametrize("mutation", ["output-kind", "generated-content"])
def test_actual_admitted_save_revalidates_kind_and_content_before_publication(
    output_composed, monkeypatch, mutation,
):
    """Source fault injection after genuine original broker entry, not fake consent."""
    service, host, sources, effects, filesystem, _ = output_composed
    request = generation(sources, record())
    grant = host.review(service, request)
    original_entry = host._entry
    entered = []

    def mutate_after_real_entry(permit, binding, plan, effect, kind):
        original_entry(permit, binding, plan, effect, kind)
        entered.append(kind)
        if mutation == "output-kind":
            object.__setattr__(plan, "output_intent", c.OutputIntent(("json",), "owned"))
        else:
            object.__setattr__(plan, "native_payload", c.public_object({
                **dict(plan.native_payload), "generated_yaml": None,
            }))

    monkeypatch.setattr(host, "_entry", mutate_after_real_entry)
    outcome = service.execute(request, grant)
    assert entered == ["save"], "The actual original one-use permit must enter first"
    assert outcome.status != c.OutcomeStatus.SUCCEEDED and outcome.exit_code != 0
    assert outcome.artifacts == () and filesystem.bindings == [] and effects.calls == []
