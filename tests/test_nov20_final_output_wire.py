"""Final frozen AC-009 local wire and source-attribution proofs, not platform claims."""

from __future__ import annotations

import json
from dataclasses import replace
from uuid import NAMESPACE_URL, uuid5

from netops.ansible import contracts as c
from netops.ansible.execution import EffectResult, ExecutionHost
from netops.ansible.workflows import _remediation, _validate_loaded
from tests.test_nov20_reviewed_generation import generation, record
from tests.test_nov20_reviewed_nonempty_wire import EXPECTED_GENERATED_NATIVE, OP
from tests.test_workflow_execution import composed as composed
from tests.test_workflow_execution import output_composed as output_composed
from tests.test_workflow_execution import policy as policy

# Frozen retained CPU template, explicit complete text including ordering,
# quoting, line wrapping and final newline. No production serializer builds it.
EXPECTED_YAML_JSON = (
    b'"- gather_facts: false\\n'
    b'  hosts: r1\\n'
    b'  name: Remediation playbook for r1 [cpu_high]\\n'
    b'  tasks:\\n'
    b'  - ansible.builtin.pause:\\n'
    b'      prompt: Remediation plan for r1 is ready. Review the task list above and press\\n'
    b'        Enter to proceed, Ctrl-C to abort.\\n'
    b"    name: 'HUMAN-REVIEW: Pending human review before remediation'\\n"
    b'    when: not dry_run | bool\\n'
    b'  - block:\\n'
    b'    - cisco.ios.ios_command:\\n'
    b'        commands:\\n'
    b'        - show processes cpu sorted\\n'
    b'        - show processes cpu history\\n'
    b"      name: 'PRE-CHECK: Capture state for Investigate high CPU utilisation'\\n"
    b'      register: pre_cpu_high\\n'
    b'    - ansible.builtin.debug:\\n'
    b'        msg: No automated remediation available. High CPU has no automated remediation.\\n'
    b'          Escalate to NOC for manual investigation.\\n'
    b"      name: 'REMEDIATE: Investigate high CPU utilisation'\\n"
    b'    - cisco.ios.ios_command:\\n'
    b'        commands:\\n'
    b'        - show processes cpu sorted\\n'
    b"      name: 'POST-CHECK: Verify state after Investigate high CPU utilisation'\\n"
    b'      register: post_cpu_high\\n'
    b'    rescue:\\n'
    b'    - ansible.builtin.debug:\\n'
    b'        msg: High CPU has no automated remediation. Escalate to NOC for manual investigation.\\n'
    b"      name: 'ROLLBACK-NOTE: cpu_high'\\n"
    b'  vars:\\n'
    b"    dry_run: 'true'\\n"
    b'"'
)
EXPECTED_WRAPPER = (
    b'{"apply_authorized":false,"collect_authorized":false,'
    b'"coverage":[{"status":"unexecuted","target_id":"r1"}],'
    b'"dry_run":true,"execution_performed":false,"generated":['
    + EXPECTED_GENERATED_NATIVE.replace(
        b'"playbook_id":"60000000-0000-4000-8000-000000000006"',
        b'"playbook_id":"f055b3a1-d42e-5512-971f-9af2878ad4c7"',
    ) + b'],"generated_yaml":' + EXPECTED_YAML_JSON + b'}'
)


def test_positive_companion_wrapper_complete_literal_and_yaml_publication(output_composed):
    """Actual original canonical host and one-use consent publish the fixed literal."""
    service, host, sources, effects, filesystem, _ = output_composed
    sources.value = replace(
        sources.value, request=replace(sources.value.request, operation_id=OP),
    )
    request = generation(sources, record())
    from netops.ansible.workflows import bind_settings, hydrate_inputs
    from tests.test_workflow_execution import Clock

    loaded = bind_settings(
        request, hydrate_inputs(request, sources.value.sources, Clock()), sources.value.settings,
    )
    assert loaded.binding_digest == "7d53feaf186bc3b6fe7dca184fa85ae1d814e150ce018ba557959eb41991f6cd"
    assert str(uuid5(NAMESPACE_URL, loaded.binding_digest + ":r1")) == (
        "f055b3a1-d42e-5512-971f-9af2878ad4c7"
    )
    projection = _remediation(request, loaded, _validate_loaded(request, loaded))
    assert c.canonical_bytes(projection) == EXPECTED_WRAPPER
    plan = service.preview(request, loaded)
    assert plan.native_payload["generated_yaml"].encode() == json.loads(EXPECTED_YAML_JSON).encode()
    assert filesystem.bindings == [] and effects.calls == []
    result = service.execute(request, host.review(service, request))
    assert result.status == c.OutcomeStatus.SUCCEEDED and result.exit_code == 0
    assert len(result.artifacts) == len(filesystem.bindings) == 1
    assert filesystem.content == json.loads(EXPECTED_YAML_JSON).encode()
    assert effects.calls == []


def test_mixed_generation_no_active_alert_keeps_unattempted_unchanged_source(output_composed):
    """A saved r1 plan must not attribute physical publication to no-alert r2."""
    service, host, sources, effects, filesystem, _ = output_composed
    no_alert = record("r2")
    no_alert["checks"] = {"cpu": {"alert": False}}
    request = generation(sources, {"results": [record(), no_alert]}, ("r1", "r2"))
    result = service.execute(request, host.review(service, request))
    assert result.status == c.OutcomeStatus.PARTIAL and result.exit_code == 4
    assert len(result.artifacts) == len(filesystem.bindings) == 1
    assert result.targets[0].attempted is True and result.targets[0].changed is True
    target = result.targets[1]
    assert target.attempted is False and target.changed is False
    assert target.selected is True and target.status != c.OutcomeStatus.SUCCEEDED
    assert target.remote_state == "unchanged"
    assert c.canonical_bytes(target.native_payload) == (
        b'{"execution_performed":false,'
        b'"generation":{"status":"no-active-alert","target_id":"r2"}}'
    )
    assert b"hosts: r2" not in filesystem.content and effects.calls == []


def test_generation_source_request_binding_rejects_foreign_selected_coverage(output_composed):
    """Source-only aggregation guard: another request cannot replace selected facts."""
    _, _, sources, effects, filesystem, _ = output_composed
    request = generation(sources, record())
    foreign = c.public_object({
        "request_digest": "0" * 64,
        "coverage": ({"target_id": "r1", "status": "failed"},),
        "execution_performed": False, "collect_authorized": False, "apply_authorized": False,
    })
    result = ExecutionHost._outcome(
        request, (EffectResult(c.StepOutcome(
            request.operation_id + ":0", c.OutcomeStatus.SUCCEEDED, True, changed=True,
        )),), None, source_generation=foreign,
    )
    assert result.status == c.OutcomeStatus.SUCCEEDED and result.exit_code == 0
    assert result.targets[0].attempted is True and result.targets[0].changed is True
    assert "generation" not in result.steps[0].native_payload
    assert "generation" not in result.targets[0].native_payload
    assert filesystem.bindings == [] and effects.calls == []
