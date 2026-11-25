"""Author managed-source binding units; synthetic records never qualify a tuple."""

from dataclasses import replace
from pathlib import Path

import pytest

from netops.ansible import contracts as c
from netops.ansible.controller_installation import _ManagedInstallationVerifier
from netops.ansible.controller_protocol import ProtocolError
from netops.ansible.policy import contracts as lc
from netops.dependencies._installation import _InstallationSpec, _Wheel
from netops.dependencies._managed import ManagedMember
from tests.policy.test_lifecycle_execution import OWNER
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_i02_public_flow import public_case


def binding_case(tmp_path, policy):
    case = public_case(tmp_path, policy)
    manifest, port = case[4].manifests[0], case[3]
    wheels = tuple(_Wheel(f"wheels/{name}.whl", name, "1.0", "b" * 64)
                   for name in ("netops-toolkit", "ansible-core", "molecule"))
    # This Linux descriptor is a unit fixture, not an available interpreter,
    # production lock, installation proof or platform-qualified generation.
    spec = _InstallationSpec(str(tmp_path / "source-python"), "a" * 64,
                             "3.12.10", "linux", wheels, controller=True)
    manifest = replace(manifest, installation=spec, members=tuple(
        ManagedMember(wheel.member, wheel.digest, 1) for wheel in wheels
    ))
    generation = lc.GenerationBinding(manifest.generation_id, 0,
                                      manifest.content_digest, c.digest(manifest))
    members = ({"path": "bin/python", "kind": "file", "digest": "c" * 64, "executable": True},)
    receipt = {
        "schema": "i02-installed-generation-v1", "generation_id": manifest.generation_id,
        "descriptor_digest": c.digest(manifest), "python_member": "bin/python",
        "manifest": members, "installation_digest": c.digest(c.public_value(members)),
    }
    verification = {
        "generation_id": generation.generation_id, "content_digest": generation.content_digest,
        "manifest_digest": generation.manifest_digest, "context_digest": c.digest(manifest.context),
        "registry_digest": manifest.context.context.registry_digest,
        "policy_digest": manifest.context.context.policy_identity.bundle_sha256,
        "qualification_digest": "d" * 64,
    }
    root = c.wire(port.read("managed-root").payload)
    root["generations"] = [{"generation_id": generation.generation_id,
                            "manifest": c.wire(manifest), "state": "staged",
                            "installation_receipt": receipt}]
    root["root_manifest"]["registered_manifests"] = [c.wire(manifest)]
    root["root_manifest"]["registered_qualifications"] = [{
        "generation_binding": c.wire(generation), "scope": c.wire(manifest.scope),
        "context": c.wire(manifest.context), "consuming_contexts": manifest.consuming_contexts,
        "report_digest": "e" * 64, "qualification_digest": "d" * 64,
    }]
    port.seed("managed-root", root)
    control = c.wire(port.read("managed-control").payload)
    control["pointer"] = c.wire(lc.PresentPointer(
        "present", generation.generation_id, c.digest((generation, 1)), 1,
    ))
    control["verification"] = verification
    port.seed("managed-control", control)
    resource = "dependency-installation-" + c.digest(generation)
    port.seed(resource, {
        "schema": "i02-installation-receipt-v1", "generation_binding": c.wire(generation),
        "context_digest": c.digest(manifest.context),
        "registry_digest": manifest.context.context.registry_digest,
        "consuming_contexts": manifest.consuming_contexts, "receipt": receipt,
    })
    verifier = _ManagedInstallationVerifier(
        Path(tmp_path) / ("installation-" + c.digest(generation.generation_id)),
        "managed-root", "managed-control", OWNER, manifest,
    )
    return verifier, c.ControllerContext(manifest.context.context), port, resource


def test_managed_selection_reads_exact_registered_active_receipt_but_q03_still_blocks(tmp_path, policy):
    verifier, context, state, _ = binding_case(tmp_path, policy)
    members, digest = verifier._selection(context, state)
    assert members[-1]["path"] == "netops-installation.json"
    assert len(digest) == 64
    # There is intentionally no executable/file tree or packaged real Q03
    # qualification. Synthetic host qualification fields cannot enable it.
    assert verifier.verify(context, state) is None


@pytest.mark.parametrize("fault", (
    "registered", "retained", "staging", "qualification", "pointer", "admission",
    "activation-context", "receipt-context", "receipt-registry", "receipt-generation",
    "receipt-digest", "owner", "staged-receipt",
))
def test_managed_binding_drift_is_rejected_before_any_qualification(tmp_path, policy, fault):
    verifier, context, state, installed = binding_case(tmp_path, policy)
    # First reach the actual selection path, so a missing fake fixture does
    # not make all negative controls vacuously pass.
    verifier._selection(context, state)
    resource = ("managed-root" if fault in (
        "registered", "retained", "staging", "qualification", "staged-receipt")
                else "managed-control" if fault in ("pointer", "admission", "activation-context")
                else installed)
    data = c.wire(state.read(resource).payload)
    if fault == "registered":
        data["root_manifest"]["registered_manifests"] = []
    elif fault == "retained":
        data["generations"] = []
    elif fault == "staging":
        data["generations"][0]["state"] = "staging"
    elif fault == "qualification":
        data["root_manifest"]["registered_qualifications"] = []
    elif fault == "staged-receipt":
        data["generations"][0]["installation_receipt"]["installation_digest"] = "f" * 64
    elif fault == "pointer":
        data["pointer"] = c.wire(lc.AbsentPointer("absent", 0))
    elif fault == "admission":
        data["admission_enabled"] = False
    elif fault == "activation-context":
        data["verification"]["context_digest"] = "f" * 64
    elif fault == "receipt-context":
        data["context_digest"] = "f" * 64
    elif fault == "receipt-registry":
        data["registry_digest"] = "f" * 64
    elif fault == "receipt-generation":
        data["generation_binding"]["manifest_digest"] = "f" * 64
    elif fault == "receipt-digest":
        data["receipt"]["installation_digest"] = "f" * 64
    state.seed(resource, data, owner="f" * 64 if fault == "owner" else OWNER)
    with pytest.raises(ProtocolError):
        verifier._selection(context, state)
    assert verifier.verify(context, state) is None
