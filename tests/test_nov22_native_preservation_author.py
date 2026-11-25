"""Author native parity and ownership controls; not independent qualification."""

from __future__ import annotations

import ctypes
import hashlib
import io
import json
import os
from dataclasses import replace

import pytest

from netops.ansible import artifact_platform as platform
from netops.ansible import contracts as c
from netops.ansible import workflows as w
from netops.ansible._windows_job import _KernelError, _WindowsProcess
from netops.change.diff import diff_configs, format_json
from netops.core.bastion import ActiveBastion, _write_state
from tests.test_c01_independent_nov17 import (
    HydrationClock,
    hydrated,
    input_source,
    request,
)
from tests.test_c01_independent_nov17 import environment as environment


@pytest.mark.parametrize("namespace,revision", [("collector", 2), ("native-input", 17)])
@pytest.mark.parametrize("mode", [c.Mode.PREVIEW, c.Mode.CHECK])
@pytest.mark.parametrize("before,after", [
    (b"snmp-server enable traps snmp linkdown linkup\n",
     b"SNMP-SERVER ENABLE TRAPS SNMP AUTHENTICATION LINKDOWN LINKUP\r\n"),
    (b"hostname r1\ninterface Ethernet1\n description old\n",
     b"hostname r1\ninterface Ethernet1\n description new"),
    (b"set system host-name r1\n", b"set system host-name r2\n"),
])
def test_bound_versioned_provenance_keeps_native_bytes_and_semantics(
    environment, monkeypatch, namespace, revision, mode, before, after,
):
    service, context, _ = environment
    sources = tuple(replace(
        input_source(kind, content=data),
        parser_revision=f"{namespace}-parser-v{revision}",
        vendor_revision=f"{namespace}-vendor-v{revision}",
    ) for kind, data in (("before", before), ("after", after)))
    req, loaded = hydrated(replace(request(context, "compare.compare"), mode=mode), *sources)
    calls = []
    real_diff = w.diff_configs

    def native_diff(old, new, **kwargs):
        calls.append((old.encode(), new.encode()))
        return real_diff(old, new, **kwargs)

    monkeypatch.setattr(w, "diff_configs", native_diff)
    plan = service.preview(req, loaded)
    assert calls == [(before, after)]
    assert c.wire(plan.native_payload["native_payload"]) == json.loads(
        format_json(diff_configs(before.decode(), after.decode())),
    )
    assert tuple(item.content for item in loaded.contents) == (before, after)
    assert tuple(item.source.digest for item in loaded.contents) == tuple(
        hashlib.sha256(data).hexdigest() for data in (before, after)
    )
    assert plan.effects == ()
    assert plan.targets == req.scope.target_ids


@pytest.mark.parametrize("defect", ["namespace", "revision", "vendor", "parser"])
def test_provenance_pair_is_checked_before_native_parser(environment, monkeypatch, defect):
    service, context, _ = environment
    before = replace(input_source("before", content=b"hostname r1\n"),
                     parser_revision="collector-parser-v2", vendor_revision="collector-vendor-v2")
    after = replace(input_source("after", content=b"hostname r2\n"),
                    parser_revision=before.parser_revision, vendor_revision=before.vendor_revision)
    after = replace(after, **{
        "namespace": {"vendor_revision": "other-vendor-v2"},
        "revision": {"vendor_revision": "collector-vendor-v3"},
        "vendor": {"vendor_revision": "cisco_ios"},
        "parser": {"parser_revision": "collector-parser-v3"},
    }[defect])
    req, loaded = hydrated(request(context, "compare.compare"), before, after)
    monkeypatch.setattr(w, "diff_configs", lambda *a, **kw: pytest.fail("native parser entered"))
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(req, loaded)


@pytest.mark.parametrize("defect", ["digest", "controller", "missing"])
def test_native_provenance_does_not_replace_exact_input_binding(environment, defect):
    service, context, _ = environment
    req, loaded = hydrated(
        request(context, "compare.compare"),
        input_source("before", content=b"hostname r1\n"),
        input_source("after", content=b"hostname r2\n"),
    )
    if defect == "digest":
        loaded = replace(loaded, contents=(
            replace(loaded.contents[0], content=b"hostname r3\n"), loaded.contents[1],
        ))
    elif defect == "controller":
        req = replace(req, context=replace(context, controller_id="other-controller"))
    else:
        loaded = replace(loaded, contents=loaded.contents[:1])
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(req, loaded)


def test_digest_guard_rejects_nonsecret_changed_bytes_before_native_call():
    source = input_source("before", content=b"hostname r1\n")
    item = c.LoadedInput(source.source, "text", b"hostname r2\n",
                         source.parser_revision, source.vendor_revision)
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        w._content(item)


def test_required_after_input_guard_rejects_missing_snapshot(environment):
    _, context, _ = environment
    source = input_source("before", content=b"hostname r1\n")
    req = replace(request(context, "compare.compare"), inputs=(source.source,))
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        w._required_inputs(req)


def test_observation_controller_guard_rejects_foreign_native_owner(environment):
    _, context, _ = environment
    source = input_source("before", content=b"hostname r1\n")
    req = replace(request(context, "compare.compare"), inputs=(source.source,))
    item = c.LoadedInput(source.source, source.format, source.content,
                         source.parser_revision, source.vendor_revision)
    observation = c.Observation(
        "native-reading", req.scope.target_ids[0], c.digest(context), context.route_digest,
        "foreign-controller", source.source, source.source.digest, "2026-11-21T00:00:00Z", 0.0,
    )
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        w._observations(req, (item,), (observation,))


def test_notification_neighbor_secret_is_rejected_before_hash(environment, monkeypatch):
    _, context, _ = environment
    raw = (b"snmp-server enable traps snmp authentication linkdown linkup\n"
           b"snmp-server user observer group v3 auth sha NativePreservationPrivateSentinel "
           b"priv aes 128 NativePreservationPrivateSentinel\n")
    source = c.InputSource(c.InputRef("before", "selected-before", "0" * 64),
                           "text", raw, "collector-parser-v2", "collector-vendor-v2")
    req = replace(request(context, "compare.compare"), inputs=(
        source.source, c.InputRef("after", "selected-after", "1" * 64),
    ))
    after = replace(source, source=req.inputs[1], content=b"hostname r1\n")
    monkeypatch.setattr(w.hashlib, "sha256", lambda *a, **kw: pytest.fail("private bytes hashed"))
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        w.hydrate_inputs(req, (source, after), HydrationClock())


class _PartialKernel:
    def __init__(self, failed):
        self.failed, self.once, self.calls = failed, False, []

    def require(self, name, *args):
        self.calls.append((name, args))
        assert args[0] != 0
        if name == "CloseHandle" and args[0] == self.failed and not self.once:
            self.once = True
            raise _KernelError(name, 6)
        return 1

    def call(self, name, *args):
        self.calls.append((name, args))
        assert name == "WaitForSingleObject" and args[0] == 301
        return 0

    def active(self, handle):
        self.calls.append(("active", (handle,)))
        assert handle == 201
        return 0


@pytest.mark.parametrize("failed", [201, 301])
def test_joined_close_retry_keeps_only_failed_handle_and_never_reterminates(failed):
    kernel = _PartialKernel(failed)
    process = _WindowsProcess(kernel, 201, 301, 123, io.BytesIO(), io.BytesIO())
    process.returncode = 1
    with pytest.raises(_KernelError):
        process.close(0.1)
    assert process._joined and not process._closed
    assert process._job == (201 if failed == 201 else 0)
    assert process._process == (301 if failed == 301 else 0)
    boundary = len(kernel.calls)
    assert process.close(0.1)
    assert kernel.calls[boundary:] == [("CloseHandle", (failed,))]
    boundary = len(kernel.calls)
    assert process.close(0.1)
    process.terminate()
    assert len(kernel.calls) == boundary


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows protected native ABI only")
def test_windows_rename_uses_absolute_utf16_name_under_real_pinned_parent(tmp_path, monkeypatch):
    native = platform.WindowsHandles()
    root = tmp_path / "native-publication"
    with native._security() as security:
        assert native.kernel.CreateDirectoryW(str(root), ctypes.byref(security))
    recorded = []
    real_set = native.kernel.SetFileInformationByHandle

    def set_info(handle, kind, pointer, size):
        if kind == 3:
            value = pointer._obj
            name = ctypes.string_at(
                ctypes.addressof(value) + type(value).name.offset, value.length,
            ).decode("utf-16-le")
            recorded.append((handle, value.parent, name, value.replace))
        return real_set(handle, kind, pointer, size)

    monkeypatch.setattr(native.kernel, "SetFileInformationByHandle", set_info)
    try:
        with native.directory(str(root)) as parent:
            native.write(parent, "pending", b"exact-native-bytes")
            native.rename(parent, "pending", "publication-\N{GREEK SMALL LETTER OMEGA}.json", True)
            assert native.read(parent, "publication-\N{GREEK SMALL LETTER OMEGA}.json", 64) == b"exact-native-bytes"
            assert len(recorded) == 1
            assert recorded[0][0] != parent
            assert recorded[0][1:] == (
                None, str(root / "publication-\N{GREEK SMALL LETTER OMEGA}.json"), 1,
            )
            assert "pending" not in native.names(parent)
            native.remove(parent, "publication-\N{GREEK SMALL LETTER OMEGA}.json")
            assert native.names(parent) == []
            with pytest.raises(OSError, match="protected-storage-member"):
                native.rename(parent, "..\\escape", "publication.json", True)
    finally:
        with native.directory(str(root)) as parent:
            for member in ("pending", "publication-\N{GREEK SMALL LETTER OMEGA}.json"):
                if member in native.names(parent):
                    native.remove(parent, member)
        root.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows DACL only")
def test_bastion_token_state_is_created_with_protected_dacl_before_publication(tmp_path):
    native = platform.WindowsHandles()
    root = tmp_path / "native-bastion"
    with native._security() as security:
        assert native.kernel.CreateDirectoryW(str(root), ctypes.byref(security))
    state = ActiveBastion("bastion.example", 22, "netops", None,
                          "127.0.0.1", 1080, "127.0.0.1", 1081, "private-test-token", 123)
    path = root / "active-bastion.json"
    try:
        _write_state(state, path)
        with native.directory(str(root)) as parent:
            assert native.names(parent) == [path.name]
            # read opens/proves the actual file handle owner, protected DACL,
            # no-reparse and single-link identity before returning bytes.
            assert json.loads(native.read(parent, path.name, 4096))["token"] == state.token
            _write_state(replace(state, token="replacement-private-test-token"), path)
            assert json.loads(native.read(parent, path.name, 4096))["token"] == (
                "replacement-private-test-token"
            )
            assert native.names(parent) == [path.name]
            native.remove(parent, path.name)
    finally:
        # This exact test-created member may be unprotected in the deliberate
        # legacy-writer revert control; never broaden cleanup to other paths.
        path.unlink(missing_ok=True)
        root.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows DACL only")
def test_bastion_unsafe_parent_rejects_without_token_file_or_acl_repair(tmp_path):
    native = platform.WindowsHandles()
    state = ActiveBastion("bastion.example", 22, "netops", None,
                          "127.0.0.1", 1080, "127.0.0.1", 1081, "private-test-token", 123)
    path = tmp_path / "active-bastion.json"
    before = tuple(tmp_path.iterdir())
    with pytest.raises(OSError, match="protected-storage"):
        _write_state(state, path)
    assert not path.exists()
    assert tuple(tmp_path.iterdir()) == before
    # The original ordinary test parent is still unprotected, not silently
    # rewritten into a passing fixture or treated as POSIX mode 0600.
    with pytest.raises(OSError, match="protected-storage"):
        with native.directory(str(tmp_path)):
            pytest.fail("unprotected parent became private")
