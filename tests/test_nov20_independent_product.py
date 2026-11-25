"""Frozen O03/O04 contract probes, independently authored by the tester."""

from __future__ import annotations

import builtins
import hashlib
import json
import socket
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import LocalReferencePolicyEngine, PolicyIdentity, load_policy
from netops.ansible.workflows import WorkflowService, hydrate_inputs
from netops.change.diff import diff_configs
from netops.report import generator

OP = "60000000-0000-4000-8000-000000000006"
D = "2" * 64


class ForbiddenPort:
    """Any effectful port access during preview is a test failure."""

    def __getattr__(self, name):
        raise AssertionError("forbidden preview port: " + name)


class HydrationClock:
    def monotonic(self):
        return 10.0


@pytest.fixture(scope="module")
def product_policy():
    root = Path(c.__file__).parent / "policy"
    source = (root / "ansible_molecule.px").read_bytes()
    contracts = (root / "ansible_molecule.contracts.px").read_bytes()
    bundle = (root / "bundle.json").read_bytes()
    parsed = json.loads(bundle)
    identity = PolicyIdentity(
        canonical_revision=parsed["canonical_revision"],
        source_sha256=hashlib.sha256(source).hexdigest(),
        contracts_sha256=hashlib.sha256(contracts).hexdigest(),
        bundle_sha256=hashlib.sha256(bundle).hexdigest(),
        rule_manifest=tuple(item["id"] for item in parsed["manifest"]),
        reducer_version=parsed["reducer_version"],
    )
    return identity, LocalReferencePolicyEngine(load_policy(source, contracts, bundle, identity))


def product_case(policy, operation, contents, *, mode=c.Mode.PREVIEW, targets=()):
    identity, engine = policy
    refs = tuple(c.InputRef(kind, kind + ".fixture", hashlib.sha256(data).hexdigest())
                 for kind, data, _, _ in contents)
    request = c.OperationRequest(
        OP, operation, mode, c.Scope(targets),
        c.Context("fixture-controller", D, "fixture-source", D, identity, D, D), refs,
    )
    sources = tuple(c.InputSource(ref, fmt, data, "parser-1", vendor)
                    for ref, (_, data, fmt, vendor) in zip(refs, contents))
    loaded = hydrate_inputs(request, sources, HydrationClock())
    bomb = ForbiddenPort()
    service = WorkflowService(engine, bomb, bomb, bomb, bomb, bomb, bomb, bomb)
    return service, request, loaded


def pair_case(policy, before=b"hostname old\n", after=b"hostname new\n", vendor="flat"):
    return product_case(policy, "compare.compare", (
        ("before", before, "text", vendor), ("after", after, "text", vendor),
    ))


@pytest.mark.parametrize(("vendor", "before", "after"), [
    ("cisco_ios", b"interface Gi0/1\n description old\n", b"interface Gi0/1\n description new\n"),
    ("junos", b"set system host-name old\n", b"set system host-name new\n"),
    ("flat", b"hostname old\n", b"hostname new\n"),
])
def test_compare_changed_and_noop_native_ownership(product_policy, vendor, before, after):
    service, request, loaded = pair_case(product_policy, before, after, vendor)
    first = service.preview(request, loaded)
    assert first.native_payload["execution_performed"] is False
    assert first.native_payload["native_payload"]["entries"]
    assert diff_configs(
        before.decode(), after.decode(), style="cisco" if vendor == "cisco_ios" else vendor,
    ).has_changes
    service, request, loaded = pair_case(product_policy, before, before, vendor)
    noop = service.preview(request, loaded).native_payload["native_payload"]
    assert not any(noop["summary"][key] for key in ("added", "removed", "changed"))


@pytest.mark.parametrize("mode", [c.Mode.PREVIEW, c.Mode.CHECK])
def test_compare_preview_exact_repeat_without_io_or_credentials(product_policy, mode):
    service, request, loaded = pair_case(product_policy)
    request = replace(request, mode=mode)
    # Rehydrate outside the pure preview boundary.
    loaded = hydrate_inputs(request, tuple(c.InputSource(
        item.source, item.format, item.content, item.parser_revision, item.vendor_revision,
    ) for item in loaded.contents), HydrationClock())
    with patch.object(builtins, "open", side_effect=AssertionError("file I/O")), \
            patch.object(Path, "open", side_effect=AssertionError("path I/O")), \
            patch.object(socket, "socket", side_effect=AssertionError("network I/O")):
        first = c.canonical_bytes(service.preview(request, loaded))
        second = c.canonical_bytes(service.preview(request, loaded))
    assert first == second
    assert b'"execution_performed":false' in first


@pytest.mark.parametrize("corruption", [
    "content", "swapped", "missing", "request-digest", "context-digest",
    "binding-digest", "parser", "vendor", "kind", "schema",
])
def test_compare_loaded_binding_failclosed(product_policy, corruption):
    service, request, loaded = pair_case(product_policy)
    if corruption == "content":
        loaded = replace(loaded, contents=(
            replace(loaded.contents[0], content=b"hostname tampered\n"), loaded.contents[1],
        ))
    elif corruption == "swapped":
        loaded = replace(loaded, contents=tuple(reversed(loaded.contents)))
    elif corruption == "missing":
        loaded = replace(loaded, contents=loaded.contents[:1])
    elif corruption in ("request-digest", "context-digest", "binding-digest"):
        loaded = replace(loaded, **{corruption.replace("-", "_"): "3" * 64})
    elif corruption in ("parser", "vendor"):
        field = "parser_revision" if corruption == "parser" else "vendor_revision"
        loaded = replace(loaded, contents=(
            replace(loaded.contents[0], **{field: "different-v2"}), loaded.contents[1],
        ))
    elif corruption == "kind":
        loaded = replace(loaded, contents=(
            replace(loaded.contents[0], source=replace(loaded.contents[0].source, kind="findings")),
            loaded.contents[1],
        ))
    else:
        object.__setattr__(loaded, "schema_version", "99.0")
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(request, loaded)


@pytest.mark.parametrize(("before_vendor", "after_vendor"), [
    ("cisco_ios", "junos"), ("unknown-parser-v99", "unknown-parser-v99"),
])
def test_compare_semantic_vendor_mismatch_is_not_nochange_success(
    product_policy, before_vendor, after_vendor,
):
    service, request, loaded = product_case(product_policy, "compare.compare", (
        ("before", b"hostname old\n", "text", before_vendor),
        ("after", b"hostname old\n", "text", after_vendor),
    ))
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(request, loaded)


@pytest.mark.parametrize("data", [
    b'{"status":"succeeded","status":"failed"}',
    b'{"status":NaN}',
    b'{"password":"NOV20_DO_NOT_DISCLOSE"}',
    b'{"nested":{"private_key":"NOV20_DO_NOT_DISCLOSE"}}',
])
def test_report_malicious_loaded_json_rejected_without_sentinel(product_policy, data):
    with pytest.raises(c.ContractError) as caught:
        product_case(product_policy, "report.aggregate", (("outcomes", data, "json", "v1"),))
    assert "NOV20_DO_NOT_DISCLOSE" not in str(caught.value)


def report_fixture():
    return {
        "title": '<script>alert("title")</script>',
        "generated_at": "2026-11-20T06:30:00Z",
        "period": '<img src=x onerror="period()">',
        "sections": [{
            "name": '<svg onload="section()">',
            "type": "unknown",
            "data": {"status": "failed", "details": "</pre><script>alert('payload')</script>"},
        }],
        "overall_alert": True,
    }


def test_native_report_real_html_escapes_actual_html_j2_and_json():
    html = generator.ReportGenerator().generate_html(report_fixture())
    for forbidden in ("<script>alert", '<img src=x onerror=', '<svg onload=', "</pre><script>"):
        assert forbidden not in html
    assert "&lt;script&gt;" in html or "\\u003cscript\\u003e" in html
    assert "failed" in html


def test_native_report_render_in_memory_has_no_output_write(tmp_path):
    report = generator.ReportGenerator(output_dir=str(tmp_path))
    html = report.generate_html(report_fixture())
    assert isinstance(html, str) and "<!DOCTYPE html>" in html
    assert list(tmp_path.iterdir()) == []


def test_native_report_cli_is_real_callable_entrypoint():
    assert callable(getattr(generator, "main", None)), "Frozen O04 requires generator.main(argv)"


def test_native_report_failed_source_not_healthy(product_policy):
    identity, _ = product_policy
    request = c.OperationRequest(
        OP, "report.aggregate", c.Mode.PREVIEW, c.Scope(("router",)),
        c.Context("fixture-controller", D, "fixture-source", D, identity, D, D),
    )
    source = c.aggregate_outcome(
        request, (c.TargetOutcome("router", c.OutcomeStatus.FAILED, True),),
        errors=(c.SafeError(c.ErrorCategory.EXECUTION, c.ReasonCode.READING_UNAVAILABLE,
                            c.Stage.EVALUATE),),
    )
    data = generator.ReportGenerator().build_report(sections=[{
        "name": "failed source", "type": "companion",
        "data": json.loads(c.canonical_bytes(source)),
    }])
    assert data["overall_alert"] is True


def test_native_report_truncated_companion_outcome_is_rejected():
    with pytest.raises(c.ContractError):
        generator.ReportGenerator().build_report(sections=[{
            "name": "malformed", "type": "companion",
            "data": {"status": "failed", "targets": [], "errors": []},
        }])


def test_report_mixed_coverage_unknown_cleanup_minimized_and_pure(product_policy):
    from netops.report.companion import project_outcome

    identity, _ = product_policy
    request = c.OperationRequest(
        OP, "report.aggregate", c.Mode.PREVIEW, c.Scope(("good", "bad", "blocked", "not-attempted")),
        c.Context("fixture-controller", D, "fixture-source", D, identity, D, D),
    )
    error = c.SafeError(c.ErrorCategory.EXECUTION, c.ReasonCode.READING_UNAVAILABLE,
                        c.Stage.EVALUATE)
    source = c.aggregate_outcome(request, (
        c.TargetOutcome("good", c.OutcomeStatus.SUCCEEDED, True),
        c.TargetOutcome("bad", c.OutcomeStatus.FAILED, True,
                        errors=(error,), remote_state="uncertain"),
        c.TargetOutcome("blocked", c.OutcomeStatus.BLOCKED, False),
        c.TargetOutcome("not-attempted", c.OutcomeStatus.CANCELLED, False),
    ), cleanup=c.CleanupOutcome("failed", ("owned-cleanup-ref",), (error,)))
    value = c.public_value(json.loads(c.canonical_bytes(source)))
    with patch.object(builtins, "open", side_effect=AssertionError("file I/O")), \
            patch.object(socket, "socket", side_effect=AssertionError("network I/O")):
        first = project_outcome(value, request.scope.target_ids + ("missing",))
        assert c.canonical_bytes(first) == c.canonical_bytes(
            project_outcome(value, request.scope.target_ids + ("missing",)),
        )
    assert first["selected_count"] == 5
    assert first["counts"]["succeeded"] == 1
    assert first["counts"]["failed"] == 1
    assert first["counts"]["blocked"] == 2
    assert first["counts"]["cancelled"] == 1
    assert first["missing_count"] == 1 and first["coverage_complete"] is False
    assert first["overall_alert"] is True and first["source_status"] != "succeeded"
    assert first["remote_uncertain"] is True
    assert first["cleanup"]["status"] == "failed"
    assert first["cleanup"]["remaining_refs"] == ("owned-cleanup-ref",)
    assert first["execution_performed"] is False


def test_remediation_deterministic_guarded_unexecuted_no_apply(product_policy):
    content = json.dumps({
        "results": [{
            "host": "router", "device_type": "cisco_ios", "success": True,
            "timestamp": "2026-11-20T06:30:00Z",
            "checks": {"cpu": {"alert": True, "usage_percent": 99}},
        }],
    }).encode()
    service, request, loaded = product_case(product_policy, "compare.remediation-preview", (
        ("findings", content, "json", "vendor-1"),
    ), targets=("router",))
    first = service.preview(request, loaded).native_payload
    second = service.preview(request, loaded).native_payload
    assert c.canonical_bytes(first) == c.canonical_bytes(second)
    assert first["execution_performed"] is False
    assert first["collect_authorized"] is False and first["apply_authorized"] is False
    assert first["dry_run"] is True
    assert first["generated"], "Active native alert must produce real inspectable guarded intent"
    playbook = first["generated_yaml"]
    assert "dry_run" in playbook and "not dry_run" in playbook
    assert "rescue:" in playbook and "pause:" in playbook


@pytest.mark.parametrize("host", ["all", "ungrouped", "{{secret}}", "router:all", "router;apply"])
def test_remediation_device_text_cannot_be_executable_selection(product_policy, host):
    content = json.dumps({
        "host": host, "device_type": "cisco_ios", "success": True,
        "checks": {"cpu": {"alert": True}},
    }).encode()
    service, request, loaded = product_case(product_policy, "compare.generate", (
        ("findings", content, "json", "vendor-1"),
    ))
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(request, loaded)


def test_native_report_pdf_is_real_or_truthfully_unavailable():
    try:
        pdf = generator.ReportGenerator().generate_pdf(report_fixture())
    except (ImportError, OSError) as error:
        # Optional unavailable capability is not PDF qualification. Guidance must be truthful.
        assert "PDF" in str(error) or "weasyprint" in str(error) or "library" in str(error)
        return
    assert type(pdf) is bytes
    assert pdf.startswith(b"%PDF-")
    assert b"%%EOF" in pdf[-1024:]
    assert b"/Type /Page" in pdf
    assert not pdf.startswith(b"<!DOCTYPE")
