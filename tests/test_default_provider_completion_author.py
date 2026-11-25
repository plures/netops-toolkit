"""SOURCE controls: only publisher/probe/process boundaries are synthetic.

Nothing here qualifies a publisher, OS feature, runtime, WSL or container tier.
The public managed test uses real protected trees, offline pip, ledger and broker.
"""

import hashlib
import io
import json
import platform
import stat
import sys
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.ansible.policy.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    TrustedConsentAdapter,
    TrustedLifecycleConsentAdapter,
)
from netops.dependencies import _composition, _default_family, _setup
from netops.dependencies._assets import AssetResponse, HttpsAssetTransport, LockedAsset
from netops.dependencies._composition import ManagedLifecycleState
from netops.dependencies._default_family import _default_metadata
from netops.dependencies._family_bridge import _requirement
from netops.dependencies._family_consent import _ScopeReviews
from netops.dependencies._family_lock import (
    _CatalogueUnavailable,
    _FamilyLock,
    _PublisherSnapshot,
    _Release,
    _Requirement,
)
from netops.dependencies._family_provider import _Authority
from netops.dependencies._guided import _existing_python
from netops.dependencies._installation import _InstallationSpec, _NativeFile, _Wheel
from netops.dependencies._managed import (
    ManagedArchive,
    ManagedMember,
    ProtectedGenerationFiles,
)
from netops.dependencies._platform_host import _arguments, _Command, _NativePlatformIO
from netops.dependencies._python_metadata import _PythonFile, _PythonOrgMetadata
from netops.dependencies.runs import OwnedGenerationRuns
from netops.dependencies.service import DependencyRegistry, DependencyService
from tests.policy.test_lifecycle_execution import OWNER, Review
from tests.policy.test_lifecycle_execution import policy as policy
from tests.test_family_provider_author import TARGET, Cancel, Clock, D, ScopeReview, admitted
from tests.test_guided_first_run_author import report_from, service_case
from tests.test_i02_offline_installation import Cancel as ProcessCancel
from tests.test_i02_public_flow import public_case


@pytest.mark.parametrize("failure", ["entry", "exit", "backward", "invalid"])
def test_observation_never_fabricates_missing_or_invalid_duration(monkeypatch, failure):
    observed = []
    primary = RuntimeError("actual primary")
    values = iter({
        "entry": [OSError(), 12.0], "exit": [10.0, OSError()],
        "backward": [12.0, 10.0], "invalid": [float("nan"), 12.0],
    }[failure])

    def clock():
        value = next(values)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(_composition, "time", SimpleNamespace(monotonic=clock))
    monkeypatch.setattr(_composition._NATIVE_LOG, "debug",
                        lambda message, extra: observed.append(extra))
    with pytest.raises(RuntimeError) as error:
        with _composition._native_phase("cas-owned-tree", Clock(), Cancel(), 20.0):
            raise primary
    assert error.value is primary
    assert len(observed) == 1 and "duration" not in observed[0]
    assert observed[0]["remaining_seconds"] == 10.0
    assert observed[0]["status"] == "raised"


def test_default_catalogue_has_real_clients_but_no_unretained_http_or_readiness(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("No network grant or retained catalogue exists.")

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", forbidden)
    metadata = _default_metadata(DependencyRegistry.load())
    planning = metadata.family_planning
    sources = {item.source: item for item in planning.sources}
    assert type(sources["python.org"].port) is _PythonOrgMetadata
    assert all(
        _requirement(entry).source in sources for entry in DependencyRegistry.load().entries
    )
    target = next(target for target in planning.targets if target.context == "native")
    for source in sources.values():
        requirements = [
            _requirement(entry) for entry in DependencyRegistry.load().entries
            if _requirement(entry).source == source.source
        ]
        assert requirements
        assert all(requirement.family in source.families for requirement in requirements)
        for requirement in requirements:
            with pytest.raises(_CatalogueUnavailable):
                source.port.observe(requirement, target, Clock(), Cancel(), 20.0)
    assert metadata.installation is None and metadata.archives == ()


def native_metadata_case():
    body = b"SOURCE-only official-transport response fixture, not a released interpreter"
    artifact = LockedAsset(
        "python.org", "native-python", "https://www.python.org/ftp/python/3.12.10/source.zip",
        hashlib.sha256(body).hexdigest(), len(body),
    )
    document = {"id": 123, "url": artifact.url, "filesize": artifact.size}
    content = json.dumps(document).encode()
    release = _Release(
        _Requirement("native-python", "python", "python.org", "native", ">=3.9"),
        "3.12.10", "zip", ("linux",), ("x86_64",), (),
        hashlib.sha256(content).hexdigest(), artifact,
        members=(ManagedMember("source.txt", artifact.sha256, artifact.size),),
    )
    return release, document, content


def retained_resource(monkeypatch, content):
    def files(package):
        assert package == "netops.dependencies"

        def join(name):
            assert name == "publisher-catalogue.json"
            return SimpleNamespace(read_bytes=lambda: content)

        return SimpleNamespace(joinpath=join)

    monkeypatch.setattr(_default_family, "resources", SimpleNamespace(files=files))


def test_default_composer_consumes_native_file_ids_from_its_installed_resource(monkeypatch):
    release, _, _ = native_metadata_case()
    retained_resource(monkeypatch, json.dumps({
        "schema": "netops-publisher-catalogue-v1", "releases": [],
        "python_files": [{"release": c.wire(release), "file_id": 123}],
    }).encode())
    metadata = _default_metadata(DependencyRegistry.load())
    native = next(source for source in metadata.family_planning.sources
                  if source.source == "python.org")
    assert native.port.files == (_PythonFile(release, 123),)
    assert native.metadata_digest == native.port.digest


@pytest.mark.parametrize("content", [
    b"invalid json", b"\xff", b'{"schema":"netops-publisher-catalogue-v1","releases":[]}',
    b'{"schema":"unknown","releases":[],"python_files":[]}',
    b'{"schema":"netops-publisher-catalogue-v1","releases":[],"python_files":[{}]}',
])
def test_corrupt_default_catalogue_retains_public_selection_and_checkpoint(
    tmp_path, monkeypatch, capsys, content,
):
    from netops import setup

    root = tmp_path / "not-created"
    service_case(root, monkeypatch, status="missing")
    retained_resource(monkeypatch, content)
    monkeypatch.setattr("builtins.input", lambda _: "install")
    assert setup.main(["install", "--root", str(root), "--capability", "native.stdlib"]) == 3
    result = report_from(capsys.readouterr().out)
    assert result["status"] == "NeedsInput" and result["checkpoint"]
    assert result["selection"]["components"] == [["native-python", "install"]]
    assert result["planning_failure"]["category"] == "contract"
    assert result["consent_issued"] is False and result["effects_performed"] == []
    assert result["needs"][0]["reason"] == "source-precomposition-contract"
    assert not root.exists()


@pytest.mark.parametrize("fault", [None, "id", "url", "size", "hash", "redirect", "late", "cancel"])
def test_official_native_adapter_confirms_only_exact_retained_file_metadata(monkeypatch, fault):
    release, document, content = native_metadata_case()
    clock, cancel = Clock(), Cancel()
    if fault in ("id", "url", "size"):
        key = {"id": "id", "url": "url", "size": "filesize"}[fault]
        document[key] = "not-the-pinned-value"
        content = json.dumps(document).encode()
        release = replace(release, metadata_digest=hashlib.sha256(content).hexdigest())
    if fault == "hash":
        content += b" "
    calls = []

    def response(self, url, timeout, limit, supplied_clock, supplied_cancel):
        calls.append((url, timeout, limit))
        if fault == "late":
            clock.value = 20.0
        if fault == "cancel":
            cancel.value = True
        return AssetResponse("https://other.invalid/file" if fault == "redirect" else url, content)

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", response)
    client = _PythonOrgMetadata((_PythonFile(release, 123),), HttpsAssetTransport())
    if fault is None:
        observed = client.observe(release.requirement, TARGET, clock, cancel, 20.0)
        assert observed.releases == (release,) and observed.metadata_digest == client.digest
    else:
        with pytest.raises((c.ContractError, TimeoutError, InterruptedError)):
            client.observe(release.requirement, TARGET, clock, cancel, 20.0)
    assert calls == [("https://www.python.org/api/v2/downloads/release_file/123/", 10.0, 1048577)]


@pytest.mark.parametrize("fault", [None, "hash", "cancel", "deadline"])
def test_actual_native_process_boundary_checks_pins_before_closed_dispatch(tmp_path, policy,
                                                                          monkeypatch, fault):
    values = admitted(tmp_path, policy, "runtime")
    _, _, _, operation, broker, permit, effect, cancel, _, _, clock = values
    authority = _Authority(broker, permit, effect, operation, clock, cancel, 20.0)
    authority._admit()
    authority.enter(operation)
    tool = tmp_path / "podman.exe"
    tool.write_bytes(b"SOURCE-only pinned executable fixture; never executed")
    digest = hashlib.sha256(tool.read_bytes()).hexdigest()
    call = _Command("runtime-version", str(tool), digest, str(tmp_path), operation.resource_id)
    calls = []

    def process(command, cwd, given_clock, given_cancel, deadline, *, accepted):
        calls.append((command, cwd, deadline, accepted))
        return b"podman version 1.0"

    monkeypatch.setattr("netops.dependencies._installation_process._run", process)
    if fault == "hash":
        tool.write_bytes(b"substitution")
    elif fault == "cancel":
        cancel.value = True
    elif fault == "deadline":
        clock.value = 20.0
    if fault is None:
        assert _NativePlatformIO().run(call, authority) == b"podman version 1.0"
        assert calls == [((str(tool), "--version"), tmp_path, 20.0, (0,))]
    else:
        with pytest.raises(AuthorizationError):
            _NativePlatformIO().run(call, authority)
        assert calls == []


@pytest.mark.parametrize("damage", ["kind", "tool", "root", "resource", "payload", "feature"])
def test_closed_platform_model_cannot_carry_arbitrary_commands_or_global_targets(tmp_path, damage):
    values = dict(kind="runtime-version", tool=str(tmp_path / "podman"),
                  tool_digest=D, root=str(tmp_path), resource_id="family-" + "a" * 40)
    values.update({
        "kind": {"kind": "arbitrary-shell"}, "tool": {"tool": str(tmp_path / "sh")},
        "root": {"root": "relative"}, "resource": {"resource_id": "users-docker"},
        "payload": {"payload": str(tmp_path / "unexpected")},
        "feature": {"feature": "arbitrary-feature"},
    }[damage])
    with pytest.raises(c.ContractError):
        _Command(**values)


def wheel_fixture():
    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, "w") as archive:
        files = {
            "netops/__init__.py": b'"""SOURCE-only installed test package."""\n',
            "netops/__main__.py": b'"""SOURCE-only module invocation boundary."""\n',
            "netops_toolkit-1.0.dist-info/METADATA":
                b"Metadata-Version: 2.1\nName: netops-toolkit\nVersion: 1.0\n",
            "netops_toolkit-1.0.dist-info/WHEEL":
                b"Wheel-Version: 1.0\nGenerator: source-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        }
        files["netops_toolkit-1.0.dist-info/RECORD"] = (
            "\n".join(path + ",," for path in (*files, "netops_toolkit-1.0.dist-info/RECORD")) + "\n"
        ).encode()
        for path, content in files.items():
            archive.writestr(path, content)
    return wheel.getvalue()


def archive_fixture(dependency, files):
    data = io.BytesIO()
    members = []
    with zipfile.ZipFile(data, "w") as archive:
        for path, content, executable in files:
            info = zipfile.ZipInfo(path)
            info.external_attr = (stat.S_IFREG | (0o700 if executable else 0o600)) << 16
            archive.writestr(info, content)
            members.append(ManagedMember(path, hashlib.sha256(content).hexdigest(),
                                         len(content), executable))
    content = data.getvalue()
    asset = LockedAsset("python.org", dependency, "https://www.python.org/source-test-" + dependency
                        + ".zip", hashlib.sha256(content).hexdigest(), len(content))
    return ManagedArchive(asset, "zip", tuple(members)), content


def platform_public_case(tmp_path, policy):
    control = tmp_path / "c"
    control.mkdir()
    original, scope, context, port, _, _, engine, _ = public_case(control, policy)
    old_manifest = original.state.manifests[0]
    wheel = wheel_fixture()
    wheel_name = "wheels/netops_toolkit-1.0-py3-none-any.whl"
    windows = sys.platform == "win32"
    tool_name = "dism.exe" if windows else "podman"
    tool = b"SOURCE-only tool bytes; external process boundary is fake"
    tool_member = "tools/" + tool_name
    native_archive, native_content = archive_fixture("native-python", (
        (wheel_name, wheel, False), (tool_member, tool, True),
    ))
    spec = _InstallationSpec(
        _existing_python(), hashlib.sha256(Path(_existing_python()).read_bytes()).hexdigest(),
        platform.python_version(), sys.platform,
        (_Wheel(wheel_name, "netops-toolkit", "1.0", hashlib.sha256(wheel).hexdigest()),),
        native_files=(_NativeFile(tool_member, tool_member, hashlib.sha256(tool).hexdigest(), True),),
    )
    adapter = next(iter(original.adapters.values()))
    consuming = replace(
        adapter.contexts["native"], platform=sys.platform, architecture=platform.machine(),
        python=str(tmp_path / "h" / ("installation-" + c.digest(old_manifest.generation_id))
                   / ("Scripts" if windows else "bin") / ("python.exe" if windows else "python")),
    )
    adapter.contexts = {"native": consuming}
    original_probe = adapter.probe

    def observe(entry, context, deadline):
        result = original_probe(entry, context, deadline)
        return replace(result, version=spec.python_version) if entry.id == "native-python" else result

    adapter.probe = observe
    target = replace(TARGET, platform=sys.platform, architecture=platform.machine(),
                     python=spec.python_version, context_digest=consuming.digest,
                     wheel_tags=("py3-none-any",))
    native_requirement = _requirement(original.registry.entry("native-python"))
    family = "os-feature" if windows else "runtime"
    wanted = _Requirement("platform-control", family, "host-platform", "native")
    scopes = ("os", "wsl", "elevation") if windows else ("runtime",)
    platform_release = _Release(
        wanted, "1.0", "host-feature" if windows else "zip",
        (sys.platform,), (target.architecture,), (), D,
        None if windows else replace(native_archive.asset, source_id="host-platform",
                                     dependency=wanted.name),
        scopes=scopes, resource="Microsoft-Windows-Subsystem-Linux" if windows else "podman-rootless",
        members=() if windows else native_archive.members,
    )
    # On Linux the binary archive supplies the wheel and tool as well. This is
    # a synthetic source snapshot, explicitly not official release metadata.
    native_release = _Release(
        native_requirement, spec.python_version, "zip", (sys.platform,), (target.architecture,),
        (wanted,), D, native_archive.asset, members=native_archive.members,
    )
    if not windows:
        # Do not duplicate member contributions across two artifacts.
        runtime_archive, runtime_content = archive_fixture(wanted.name, ((tool_member, tool, True),))
        runtime_archive = replace(runtime_archive, asset=replace(
            runtime_archive.asset, source_id="python.org",
        ))
        wanted = replace(wanted, source="python.org")
        platform_release = replace(platform_release, requirement=wanted,
                                   artifact=runtime_archive.asset, members=runtime_archive.members)
        native_archive, native_content = archive_fixture("native-python", ((wheel_name, wheel, False),))
        native_release = replace(native_release, artifact=native_archive.asset,
                                 members=native_archive.members, requires=(wanted,))
        archives = (runtime_archive, native_archive)
        content = {runtime_archive.asset.url: runtime_content, native_archive.asset.url: native_content}
    else:
        archives = (native_archive,)
        content = {native_archive.asset.url: native_content}
    releases = (platform_release, native_release)
    observations = tuple(_PublisherSnapshot(
        source, c.digest(target), tuple(item for item in releases if item.requirement.source == source),
        D, 9.0, 60.0,
    ) for source in dict.fromkeys(item.requirement.source for item in releases))
    lock = _FamilyLock((native_requirement,), (target,), releases, observations, original.registry.digest)
    manifest = replace(old_manifest, asset=archives[0].asset, archive="zip", archives=archives,
                       members=tuple(item for archive in archives for item in archive.members),
                       installation=spec, consuming_contexts=(consuming.digest,))
    facts = port.read("managed-root")
    root_manifest = c.public_object({
        **dict(facts.payload["root_manifest"]), "registered_manifests": (c.wire(manifest),),
        "family_locks": ((manifest.generation_id, c.wire(lock)),),
    })
    port.seed("managed-root", {**dict(facts.payload), "root_manifest": root_manifest})
    root_binding = lc.OwnedRootBinding("managed-root", c.digest(root_manifest))
    ledger_id = "family-ledger-" + c.digest(manifest.generation_id)
    port.seed(ledger_id, {
        "schema": "netops-family-resources-v1", "root": c.wire(root_binding),
        "lock_digest": lock.digest, "resources": (), "pending": (),
    })
    root = _setup._owned(tmp_path / "h", True)

    class Transport:
        def read(self, url, timeout, limit):
            return AssetResponse(url, content[url])

    runs = OwnedGenerationRuns(
        port, "managed-root", "managed-control", OWNER, policy[0],
        (lc.GenerationBinding(manifest.generation_id, 0, manifest.content_digest, c.digest(manifest)),),
        manifest.generation_id,
    )
    runs.initialize()
    state = ManagedLifecycleState(
        port, "managed-root", "managed-control", OWNER, policy[0], (manifest,),
        ProtectedGenerationFiles(root), Transport(), runs=runs,
        family_locks=((manifest.generation_id, lock),), family_reviews=_ScopeReviews(ScopeReview()),
    )
    review = Review()
    broker = AuthorizationBroker(
        None, TrustedConsentAdapter(review), lifecycle_state=state,
        lifecycle_consent=TrustedLifecycleConsentAdapter(review),
    )
    service = DependencyService(
        original.registry, original.adapters, state, engine, broker, original.clock, original.events,
    )
    return service, scope, context, port, state, lock, ledger_id, root


def test_public_managed_lifecycle_calls_real_typed_host_and_retires_owned_families(
    tmp_path, policy, monkeypatch,
):
    values = platform_public_case(tmp_path, policy)
    service, scope, context, port, state, lock, ledger_id, root = values
    calls = []
    enabled = False

    def external(self, call, authority):
        nonlocal enabled
        assert type(authority) is _Authority and authority._used
        call.__post_init__()
        calls.append((_arguments(call), call.kind))
        if call.kind == "feature-query":
            return b"State : Enabled\r\n" if enabled else b"State : Disabled\r\n"
        if call.kind == "feature-enable":
            enabled = True
            return b""
        assert call.kind == "runtime-version"
        return b"podman version 1.0\n"

    monkeypatch.setattr(_NativePlatformIO, "run", external)
    plan = service.plan(scope, context)
    assert not plan.blocked
    result = service.provision(plan, service.review(plan, 10.0, 20.0), ProcessCancel())
    assert all(item.status == c.OutcomeStatus.SUCCEEDED for item in result.steps), (
        tuple((item.kind, item.status) for item in result.steps),
        tuple((error.reason, error.stage, error.detail) for error in result.errors), calls,
    )
    assert calls and len(port.read(ledger_id).payload["resources"]) == 2
    assert state.pointer() == lc.AbsentPointer("absent", 0)
    uninstall = service.plan_uninstall(state.manifests[0].generation_id, context)
    assert len(uninstall.effects) == 3
    broker = service.authorization
    consent = broker._lifecycle_consent.review(uninstall, 10.0, 20.0)
    removed = service.uninstall(uninstall, consent)
    assert removed.status == c.OutcomeStatus.SUCCEEDED, removed
    assert port.read(ledger_id).payload["resources"] == ()
    assert port.read(ledger_id).payload["pending"] == ()
    assert not any(path.name.startswith(("installation-", "generation-", "platform-"))
                   for path in Path(root.path).iterdir())
    assert all("/Disable-Feature" not in command for command, _ in calls)
    if sys.platform == "win32":
        assert enabled  # Shared OS facilities are never implicitly disabled.


@pytest.mark.parametrize("boundary", ["category", "semantic"])
def test_public_platform_plan_needs_every_live_review_before_any_effect(
    tmp_path, policy, monkeypatch, boundary,
):
    service, scope, context, port, state, lock, ledger_id, root = platform_public_case(
        tmp_path, policy,
    )
    plan = service.plan(scope, context)
    assert not plan.blocked
    before = len(port.writes)

    def forbidden(*args, **kwargs):
        pytest.fail("A declined live category/scope reached an effect boundary.")

    monkeypatch.setattr(type(state.transport), "read", forbidden)
    monkeypatch.setattr(_NativePlatformIO, "run", forbidden)
    monkeypatch.setattr("netops.dependencies._installation_process._run", forbidden)
    if boundary == "category":
        reviewer = service.authorization._lifecycle_consent._reviewer
        assert plan.lifecycle.required_consequential
        for requirement in plan.lifecycle.required_consequential:
            reviewer.denied = requirement.category
            with pytest.raises(AuthorizationError):
                service.review(plan, 10.0, 20.0)
    else:
        for scope_name in next(release for release in lock.releases if release.scopes).scopes:
            reviewer = ScopeReview()
            reviewer.denied = scope_name
            state._family_reviews = _ScopeReviews(reviewer)
            consent = service.review(plan, 10.0, 20.0)
            with pytest.raises(AuthorizationError):
                service.provision(plan, consent, ProcessCancel())
    assert len(port.writes) == before
    assert port.read(ledger_id).payload["pending"] == ()
    assert port.read(ledger_id).payload["resources"] == ()
    assert tuple(Path(root.path).iterdir()) == ()
