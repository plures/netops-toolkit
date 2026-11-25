"""Corrective author controls through the real host; not independent acceptance."""

from __future__ import annotations

from dataclasses import replace

import pytest
import yaml

from netops.ansible import contracts as c
from netops.ansible.execution import _Rejected
from netops.dependencies._installation import _installed_parts
from tests.test_companion_compare import (
    alert,
    bound,
    input_source,
)
from tests.test_companion_compare import (
    pure_composition as pure_composition,
)
from tests.test_nov20_independent_public_output import replace_input
from tests.test_nov20_output_setup_proof import generated_request, local_only
from tests.test_workflow_execution import (
    composed as composed,
)
from tests.test_workflow_execution import (
    output_composed as output_composed,
)
from tests.test_workflow_execution import (
    policy as policy,
)


def generation(output_composed, results, targets=("r1",)):
    service, host, sources, backend, filesystem, _ = output_composed
    request = generated_request(sources)
    request = replace(request, scope=c.Scope(targets))
    sources.value = replace(sources.value, request=request)
    request = replace_input(
        sources, request, "findings", c.canonical_bytes(c.public_object({"results": results})),
    )
    selected_source = sources.value.sources[0]
    sources.value = replace(sources.value, sources=(replace(
        selected_source, observations=tuple(
            replace(
                selected_source.observations[0], observation_id="bound-" + target,
                target_id=target, source=selected_source.source,
                content_digest=selected_source.source.digest,
            ) for target in targets
        ),
    ),))
    local_only(sources)
    return service, host, request, backend, filesystem


@pytest.mark.parametrize(("results", "disposition"), [
    ([{**alert(), "success": False}], "failed"),
    ([{**alert(), "checks": {"cpu": {"alert": False}}}], "no-active-alert"),
    ([{**alert(), "checks": {"unsupported": {"alert": True}}}], "unsupported"),
    ([], "missing"),
])
def test_public_no_eligible_source_cannot_review_or_publish(output_composed, results, disposition):
    service, host, request, backend, filesystem = generation(output_composed, results)
    with pytest.raises(_Rejected, match="output-rejected"):
        host.review(service, request)
    outcome = service.execute(request)
    assert outcome.status != c.OutcomeStatus.SUCCEEDED
    assert outcome.exit_code != 0 and not outcome.artifacts
    assert outcome.targets[0].native_payload["generation"]["status"] == disposition
    assert not outcome.targets[0].attempted
    assert filesystem.bindings == [] and backend.calls == []


def test_public_mixed_generation_retains_ordered_failed_missing_and_unsupported(output_composed):
    results = [
        {**alert("r2"), "success": False},
        alert("r1"),
        {**alert("r4"), "checks": {"unknown": {"alert": True}}},
    ]
    service, host, request, backend, filesystem = generation(
        output_composed, results, ("r3", "r2", "r1", "r4"),
    )
    grant = host.review(service, request)
    plan, _ = host._load(service, request)
    assert [row["target_id"] for row in plan.native_payload["coverage"]] == ["r3", "r2", "r1", "r4"]
    expected = plan.native_payload["generated_yaml"].encode()
    assert filesystem.bindings == []
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.PARTIAL and outcome.exit_code == 4
    assert [row.target_id for row in outcome.targets] == ["r3", "r2", "r1", "r4"]
    assert [row.status for row in outcome.targets] == [
        c.OutcomeStatus.BLOCKED, c.OutcomeStatus.FAILED,
        c.OutcomeStatus.SUCCEEDED, c.OutcomeStatus.UNSUPPORTED,
    ]
    assert len(outcome.artifacts) == len(filesystem.bindings) == 1
    assert filesystem.content == expected
    assert [play["hosts"] for play in yaml.safe_load(expected)] == ["r1"]
    assert backend.calls == []


def test_public_valid_generation_is_exact_guarded_one_use_output(output_composed):
    service, host, request, backend, filesystem = generation(output_composed, [alert()])
    grant = host.review(service, request)
    plan, _ = host._load(service, request)
    expected = plan.native_payload["generated_yaml"].encode()
    outcome = service.execute(request, grant)
    assert outcome.status == c.OutcomeStatus.SUCCEEDED and outcome.exit_code == 0
    assert len(outcome.artifacts) == len(filesystem.bindings) == 1
    assert filesystem.content == expected
    assert b"not dry_run | bool" in expected and b"rescue:" in expected
    assert backend.calls == []
    assert not service.execute(request, grant).artifacts
    assert len(filesystem.bindings) == 1


def test_failed_source_takes_precedence_over_unsupported_check(pure_composition):
    service, request = pure_composition
    request = replace(request, operation="compare.generate", scope=c.Scope(("r1",)))
    request, loaded = bound(request, input_source(
        "findings", {**alert(), "success": False, "checks": {"unknown": {"alert": True}}},
        fmt="json",
    ))
    plan = service.preview(request, loaded)
    assert plan.native_payload["coverage"][0]["status"] == "failed"
    assert plan.native_payload["generated_yaml"] is None


def test_generation_facts_cannot_admit_empty_plays_even_with_output_safe_marker(output_composed):
    service, host, request, _, filesystem = generation(output_composed, [alert()])
    plan, _ = host._load(service, request)
    plan = replace(plan, native_payload=c.public_object({
        **dict(plan.native_payload), "generated": (), "generated_yaml": "[]\n",
    }))
    host._output_safe.add(plan.plan_digest)
    facts = host._facts(plan, plan.deadline_ms).values
    assert facts["compare"]["inputs_bound"] is False
    assert facts["compare"]["vendor_supported"] is False
    assert filesystem.bindings == []


@pytest.mark.parametrize("mutation", [
    [{"host": "r1", "device_type": "unknown", "success": True, "checks": {}}],
    [{**alert(), "success": 1}],
    [{**alert(), "checks": []}],
    [{**alert(), "checks": {"cpu": {"alert": 1}}}],
    [{**alert(), "checks": {"cpu": []}}],
    [alert(), alert()],
    [alert("r2")],
    [alert("all")],
    ["invalid"],
])
def test_malformed_generation_is_rejected_before_public_output(output_composed, mutation):
    service, host, request, backend, filesystem = generation(output_composed, mutation)
    with pytest.raises(c.ContractError):
        host.review(service, request)
    assert not service.execute(request).artifacts
    assert filesystem.bindings == [] and backend.calls == []


@pytest.mark.parametrize("path", [
    "Lib/site-packages/setuptools/script (dev).tmpl",
    "Lib/site-packages/setuptools/script.tmpl",
    "Lib/site-packages/dist-info/LICENSE (BSD).txt",
])
def test_legitimate_owned_installed_data_names(path):
    assert _installed_parts(path) == tuple(path.split("/"))


@pytest.mark.parametrize("path", [
    "", "/absolute", "C:/absolute", "../escape", "Lib/../escape",
    "Lib//file", "Lib/file:stream", "Lib/file\\escape", "Lib/NUL.txt",
    "Lib/COM1.txt", "Lib/LPT9 .txt", "Lib/file.", "Lib/file ",
    "Lib/ file", "Lib/\x00file", "Lib/<file>", "Lib/file?", "Lib/file*",
    "Lib/é.txt", "Lib/" + "x" * 161, "/".join(["x"] * 33),
])
def test_installed_data_names_retain_closed_platform_security(path):
    with pytest.raises(c.ContractError):
        _installed_parts(path)


def test_installed_member_correction_does_not_change_managed_archive_grammar():
    from netops.dependencies._managed import _parts

    with pytest.raises(c.ContractError):
        _parts("Lib/site-packages/setuptools/script (dev).tmpl")


