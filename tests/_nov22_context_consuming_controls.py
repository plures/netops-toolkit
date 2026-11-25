"""Independent consuming SOURCE-port units; never installation qualification."""

import hashlib
import io
import json
import sys
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch
from uuid import uuid4


class MetadataAccepted(RuntimeError):
    """Stop a positive installer unit before any target effect."""


def wheel(root, name, requires=(), provides=()):
    """Create exact metadata bytes before any consumer or plan is constructed."""
    filename = name.replace("-", "_") + "-1.0-py3-none-any.whl"
    content = io.BytesIO()
    lines = ["Metadata-Version: 2.1", "Name: " + name, "Version: 1.0"]
    lines.extend("Requires-Dist: " + item for item in requires)
    lines.extend("Provides-Extra: " + item for item in provides)
    with zipfile.ZipFile(content, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            name.replace("-", "_") + "-1.0.dist-info/METADATA",
            "\n".join(lines) + "\n\n",
        )
    data = content.getvalue()
    with (root / filename).open("xb") as stream:
        stream.write(data)
    return filename, name, data


def case(api, root, *, declaration=True, alias=None, leaf=True):
    """Build valid real archive/member/spec inputs, not authentic actor proof."""
    c, installation, managed, assets = (
        api["contracts"], api["installation"], api["managed"], api["assets"],
    )
    requested = "Feature_Name" if alias == "transitive" else "feature"
    if alias == "root":
        toolkit_requires = ("leaf==1.0; extra == 'feature-name'",)
        toolkit_provides = ("FEATURE.NAME",)
        requested_extras = (("netops-toolkit", ("Feature_Name",)),)
        dependency_requires, dependency_provides = (), ()
    else:
        toolkit_requires = ("dependency[" + requested + "]==1.0",)
        toolkit_provides, requested_extras = (), ()
        spelling = "FEATURE.NAME" if alias == "transitive" else "feature"
        dependency_requires = (
            "leaf==1.0; extra == '" + (
                "feature-name" if alias == "transitive" else "feature"
            ) + "'",
        )
        dependency_provides = (spelling,) if declaration else ()
    written = [
        wheel(root, "netops-toolkit", toolkit_requires, toolkit_provides),
        wheel(root, "dependency", dependency_requires, dependency_provides),
    ]
    if leaf:
        written.append(wheel(root, "leaf"))
    members = tuple(
        managed.ManagedMember(name, hashlib.sha256(data).hexdigest(), len(data))
        for name, _, data in written
    )
    packed = io.BytesIO()
    with zipfile.ZipFile(packed, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, _, data in written:
            archive.writestr(name, data)
    data = packed.getvalue()
    archive_path = root / "selected.zip"
    with archive_path.open("xb") as stream:
        stream.write(data)
    asset = assets.LockedAsset(
        "tester-source-port", "native-python", "https://www.python.org/tester-unit.zip",
        hashlib.sha256(data).hexdigest(), len(data),
    )
    interpreter = api["guided"]._existing_python()
    spec = installation._InstallationSpec(
        interpreter, hashlib.sha256(Path(interpreter).read_bytes()).hexdigest(),
        ".".join(str(value) for value in sys.version_info[:3]), sys.platform,
        tuple(
            installation._Wheel(name, distribution, "1.0", member.digest)
            for (name, distribution, _), member in zip(written, members)
        ),
        requested_extras=requested_extras,
    )
    scope = c.InstallScope(("native.stdlib",), (), False, False)
    registry = api["service"].DependencyRegistry.load()
    generation = str(uuid4())
    context = api["setup"]._context(root, registry)
    contexts = api["setup"]._contexts(root, generation, False)
    archive = managed.ManagedArchive(asset, "zip", members)
    manifest = managed.ManagedGenerationManifest(
        generation, asset, "zip", members, scope, context,
        tuple(sorted(item.digest for item in contexts.values())),
        archives=(archive,), installation=spec,
    )
    document = {
        "archives": [{
            "asset": c.wire(asset), "archive": "zip", "members": c.wire(members),
            "cache_path": str(archive_path),
        }],
    }
    return manifest, document, registry, archive, archive_path


def verifier_port(api, records):
    """Execute unchanged production literal in the same guarded unit child."""
    program = api["installation"]._WHEEL_METADATA

    def run(command, cwd, clock, cancel, deadline, **kwargs):
        records.append({
            "kind": "source-port", "program_sha256": hashlib.sha256(program.encode()).hexdigest(),
            "cwd": str(cwd), "command_kind": (
                "metadata" if len(command) > 4 and command[4] == program else "other"
            ),
        })
        expected_interpreter = (
            sys.executable if len(command) == 7 else api["guided"]._existing_python()
        )
        assert command[0] == expected_interpreter
        assert command[1:4] == ("-I", "-B", "-c")
        assert command[4] == program, "Unexpected consuming command; venv/pip forbidden"
        assert len(command) in (6, 7)
        output, error = io.StringIO(), io.StringIO()
        old_argv = sys.argv
        try:
            sys.argv = ["-c", *command[5:]]
            with redirect_stdout(output), redirect_stderr(error):
                try:
                    exec(compile(program, "<actual-wheel-metadata>", "exec"), {})
                except AssertionError:
                    records[-1]["result"] = "rejected"
                    raise api["contracts"].ContractError() from None
        finally:
            sys.argv = old_argv
        assert output.getvalue().strip() == "verified-wheel-metadata-closure"
        assert error.getvalue() == ""
        records[-1]["result"] = "accepted"
        return output.getvalue().encode()

    return run


def cached(api, root, *, success, **kwargs):
    manifest, document, _, _, _ = case(api, root, **kwargs)
    records = []
    runner = verifier_port(api, records)
    with patch.object(api["process"], "_run", runner):
        try:
            api["setup"]._cached_closure(manifest, document)
        except api["contracts"].ContractError:
            assert not success, "Valid declared/alias closure unexpectedly rejected"
        else:
            assert success, "Undeclared extra or missing active leaf was accepted"
    assert len(records) == 1 and records[0]["command_kind"] == "metadata"
    assert records[0]["result"] == ("accepted" if success else "rejected")
    api["observations"].extend(records)


def test_cached_undeclared_transitive_before_checked_reuse(api, root):
    """LIFO revisits dependency after toolkit's active extra contribution."""
    cached(api, root, success=False, declaration=False)


def test_cached_declared_transitive_positive(api, root):
    cached(api, root, success=True)


def test_cached_transitive_alias_positive(api, root):
    cached(api, root, success=True, alias="transitive")


def test_cached_transitive_alias_missing_leaf_rejects(api, root):
    cached(api, root, success=False, alias="transitive", leaf=False)


def test_cached_root_alias_positive(api, root):
    cached(api, root, success=True, alias="root")


def test_cached_root_alias_missing_leaf_rejects(api, root):
    cached(api, root, success=False, alias="root", leaf=False)


def installer(api, root, *, success):
    """Actual install method, mocked SOURCE ports: explicitly not admission."""
    manifest, _, _, _, _ = case(api, root, declaration=success)
    installation, c = api["installation"], api["contracts"]
    guard = Mock()
    # The root object is unit input, not an authentic protected actor/grant.
    port = installation._OfflineInstallation(Mock(path=str(root)), _source_guard=guard)
    records = []
    metadata = verifier_port(api, records)
    target_boundary = Mock(side_effect=MetadataAccepted())

    def run(command, cwd, clock, cancel, deadline, **kwargs):
        if command[4] == "import platform; print(platform.python_version())":
            return (manifest.installation.python_version + "\n").encode()
        return metadata(command, cwd, clock, cancel, deadline, **kwargs)

    clock, cancel = api["setup"]._Clock(), api["setup"]._Cancel()
    with patch.object(port, "_run", run), patch.object(installation, "_root", target_boundary):
        try:
            port.install(manifest, root, clock, cancel, clock.monotonic() + 60.0)
        except MetadataAccepted:
            assert success
        except c.ContractError:
            assert not success
        else:
            raise AssertionError("Installer unit passed its zero-target-effect fence")
    assert len(records) == 1
    assert records[0]["result"] == ("accepted" if success else "rejected")
    assert target_boundary.call_count == (1 if success else 0)
    assert guard.call_count == 1
    assert not port.path(manifest).exists()
    api["observations"].extend(records)
    api["observations"].append({
        "scope": "installer-source-port-unit-not-authentic-admission",
        "target_boundary_calls": target_boundary.call_count,
        "target_effects": 0, "venv_effects": 0, "pip_effects": 0,
    })


def test_installer_unit_undeclared_extra_zero_target_effects(api, root):
    installer(api, root, success=False)


def test_installer_unit_declared_positive_stops_before_target(api, root):
    installer(api, root, success=True)


def guided(api, root, *, success):
    """Consume real cached verifier through actual resolve, using unit facts."""
    manifest, _, registry, archive, cache_path = case(api, root, declaration=success)
    g, service, metadata = api["guided"], api["service"], api["metadata"]
    entry = registry.entry("native-python")
    observed = service.ProbeResult(
        "native-python", "a" * 64, "available", "tester-source-port",
        manifest.installation.python_version, "b" * 64,
    )
    component = g._Component(
        entry.id, entry.kind, "native", entry.version, entry.platforms, entry.source,
        (), observed, ("reuse",), "reuse",
    )
    diagnosis = g._Diagnosis(None, None, (component,))
    selection = g._Selection((("native-python", "reuse"),))
    model = metadata._Metadata(
        manifest.installation, (metadata._CachedArchive(archive, cache_path),),
        generation_id=manifest.generation_id,
    )
    records = []
    with patch.object(api["process"], "_run", verifier_port(api, records)):
        candidate, needs = model.resolve(
            diagnosis, selection, manifest.scope, root, registry,
        )
    if success:
        assert candidate is not None and needs == ()
        assert candidate.owned_source is None, "Metadata never proves an authentic actor"
    else:
        assert candidate is None and len(needs) == 1
        assert needs[0].reason == "verified-offline-cache-required"
        assert needs[0].fields == ("verified-cache-member",)
    assert len(records) == 1
    assert records[0]["result"] == ("accepted" if success else "rejected")
    api["observations"].extend(records)


def test_guided_undeclared_extra_rejects_actual_cached_verifier(api, root):
    guided(api, root, success=False)


def test_guided_declared_positive_not_authentic_actor(api, root):
    guided(api, root, success=True)


def test_upstream_marker_default_environment_remains_baseline_blocked(api, root):
    """Actual public Marker evaluation must hit a rejection fence, not WMI."""
    from packaging.markers import Marker

    try:
        Marker("extra == 'feature'").evaluate({"extra": "feature"})
    except RuntimeError as error:
        assert str(error) == "Unauthorized implicit platform/process query blocked"
    else:
        raise AssertionError("Public default_environment escaped the baseline fence")
    api["observations"].append({
        "scope": "actual-upstream-marker-baseline-rejection",
        "actual_wmi_or_shell_queries": 0,
        "global_upstream_environment_mutation": False,
    })


def test_actual_factual_context_does_not_query_platform_shell(api, root):
    """No platform fixture; independent Windows native architecture observation."""
    import ctypes
    from ctypes import wintypes

    class SystemInfo(ctypes.Structure):
        _fields_ = [
            ("architecture", wintypes.WORD), ("reserved", wintypes.WORD),
            ("page_size", wintypes.DWORD), ("minimum", ctypes.c_void_p),
            ("maximum", ctypes.c_void_p), ("mask", ctypes.c_size_t),
            ("processors", wintypes.DWORD), ("processor_type", wintypes.DWORD),
            ("granularity", wintypes.DWORD), ("level", wintypes.WORD),
            ("revision", wintypes.WORD),
        ]

    function = ctypes.WinDLL("kernel32", use_last_error=True).GetNativeSystemInfo
    function.argtypes = [ctypes.POINTER(SystemInfo)]
    function.restype = None
    facts = SystemInfo()
    function(ctypes.byref(facts))
    expected = {0: "x86", 9: "AMD64", 12: "ARM64"}[facts.architecture]
    generation = str(uuid4())
    contexts = api["setup"]._contexts(root, generation, False)
    native = contexts["native"]
    assert tuple(contexts) == ("native",)
    assert native.platform == sys.platform == "win32"
    assert native.architecture.casefold() == expected.casefold()
    target = root / ("installation-" + api["contracts"].digest(generation))
    assert native.python == str(target / "Scripts/python.exe")
    assert native.path == __import__("os").pathsep.join((
        str(target / "Scripts"), str(target / "tools"),
    ))
    assert not target.exists()
    api["observations"].append({
        "scope": "actual-native-factual-context",
        "architecture_code": facts.architecture,
        "architecture": native.architecture,
        "platform": native.platform,
        "target_effects": 0,
    })


def publication(api, root, *, drift):
    """Original producer and stage; build/install ports remain explicit units."""
    from dataclasses import replace

    stack = api["patches"]()
    with stack as monkeypatch:
        host, source, manifest, builds = api["original_producer"](root, monkeypatch)
        original = api["storage"].rename
        installed, published = [], []

        def publish(*args, **kwargs):
            assert kwargs.get("replace", False) is False
            original(*args, **kwargs)
            published.append("published")
            if drift:
                host.spec = replace(host.spec, context_digest="f" * 64)

        monkeypatch.setattr(api["storage"], "rename", publish)
        monkeypatch.setattr(
            api["installation"]._OfflineInstallation, "install",
            lambda *args, **kwargs: installed.append("installation-entered"),
        )
        clock, cancel = api["source_clock"](), api["cancel"]()
        files = api["managed"].unpack(
            manifest, source._issued._result.content, clock, cancel, 100.0,
        )
        try:
            api["managed"].ProtectedGenerationFiles(host.consuming_root).stage(
                manifest, files, clock, cancel, 100.0,
                _source_guard=lambda: source.guard(manifest, clock, cancel, 100.0),
            )
        except (api["authorization"].AuthorizationError, OSError, api["contracts"].ContractError):
            assert drift, "Intact original guarded publication failed"
        else:
            assert not drift, "Postpublication producer drift was accepted"
        assert published == ["published"]
        assert installed == ([] if drift else ["installation-entered"])
        assert len(builds) == 1
        api["observations"].append({
            "scope": "actual-original-native-stage-with-synthetic-build-and-install-ports",
            "publication_count": len(published),
            "installer_port_entries": len(installed),
            "postpublication_producer_drift": drift,
            "real_venv_pip_effects": 0,
            "authentic_full_build_or_install_qualification": False,
        })


def test_original_guarded_intact_native_publication(api, root):
    publication(api, root, drift=False)


def test_original_guarded_postpublication_context_drift_before_installer(api, root):
    publication(api, root, drift=True)
