"""Independent consuming-guard negative cases; mocked producer is not source authority."""

import pickle
from copy import deepcopy
from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy.authorization import AuthorizationError
from tests.test_i02_author_lifecycle import Cancel
from tests.test_owned_source_author import Clock, source_case


@pytest.mark.parametrize("drift", [
    "scope", "context", "consuming-context", "members", "archive",
    "python", "python-digest", "python-version", "platform", "wheel-member", "wheel-digest",
])
def test_ac001_ac003_manifest_drift_never_reuses_producer_authority(tmp_path, drift):
    source, _, manifest = source_case(tmp_path)
    manifest = deepcopy(manifest)
    if drift == "scope":
        manifest = replace(manifest, scope=c.InstallScope(("native.stdlib",), (), True, False))
    elif drift == "context":
        context = replace(manifest.context.context, mapping_digest="9" * 64)
        manifest = replace(manifest, context=c.InstallContext(context))
    elif drift == "consuming-context":
        manifest = replace(manifest, consuming_contexts=("9" * 64,))
    elif drift == "members":
        object.__setattr__(
            manifest, "members", (replace(manifest.members[0], digest="9" * 64),),
        )
    elif drift == "archive":
        manifest = replace(manifest, archive="tar")
    else:
        spec = manifest.installation
        if drift == "python":
            spec = replace(spec, python=spec.python + ".substituted")
        elif drift == "python-digest":
            spec = replace(spec, python_digest="9" * 64)
        elif drift == "python-version":
            spec = replace(spec, python_version="3.12.11")
        elif drift == "platform":
            spec = replace(spec, platform="linux" if spec.platform == "win32" else "win32")
        else:
            change = {"member": "another.whl"} if drift == "wheel-member" else {"digest": "9" * 64}
            spec = replace(spec, wheels=(replace(spec.wheels[0], **change),))
        # Fault injection after construction exercises the consuming guard,
        # not merely the descriptor constructor's independent membership check.
        object.__setattr__(manifest, "installation", spec)
    with pytest.raises((AuthorizationError, c.ContractError)):
        source.guard(manifest, Clock(), Cancel(), 100.0)


@pytest.mark.parametrize("drift", ["serialized-capability", "producer-identity", "foreign-issuer"])
def test_ac001_receipt_or_copied_capability_cannot_recreate_live_actor(tmp_path, drift):
    source, host, manifest = source_case(tmp_path)
    if drift == "serialized-capability":
        source._issued = pickle.loads(pickle.dumps(source._issued))
    elif drift == "producer-identity":
        host.identity = "9" * 64
    else:
        source._issued = replace(source._issued, _issuer=object())
    with pytest.raises(AuthorizationError):
        source.guard(manifest, Clock(), Cancel(), 100.0)


@pytest.mark.parametrize("terminal", ["cancel", "deadline"])
def test_ac003_original_budget_remains_terminal_when_inspection_finishes(tmp_path, terminal):
    source, host, manifest = source_case(tmp_path)
    clock, cancel = Clock(), Cancel()
    inspect = host.inspect
    stopped = False

    def observe(*args):
        nonlocal stopped
        result = inspect(*args)
        stopped = True
        return result

    host.inspect = observe
    cancel.is_cancelled = lambda: stopped and terminal == "cancel"
    clock.monotonic = lambda: 100.0 if stopped and terminal == "deadline" else 10.0
    expected = InterruptedError if terminal == "cancel" else TimeoutError
    with pytest.raises(expected):
        source.guard(manifest, clock, cancel, 100.0)
