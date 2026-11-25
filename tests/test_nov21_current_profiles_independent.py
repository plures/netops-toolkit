"""AC001/011/014: seven real metadata parsers with synthetic raw transport only."""

import hashlib
import io
import json
import tarfile
from dataclasses import replace
from unittest.mock import Mock

import pytest

from netops.ansible import contracts as c
from netops.dependencies import _official_profiles as p
from netops.dependencies._assets import AssetResponse, HttpsAssetTransport
from netops.dependencies._documentation import _Cancel, _Clock
from netops.dependencies._managed import ManagedMember

PROFILES = (
    ("ubuntu-packages", "os-package-manager", "executable", "linux", "host-package"),
    ("homebrew", "git-scm.com", "executable", "darwin", "tar.gz"),
    ("msys2", "os-package-manager", "executable", "win32", "host-package"),
    ("git-for-windows", "git-scm.com", "executable", "win32", "zip"),
    ("podman", "selected-runtime-vendor", "runtime", "linux", "tar.gz"),
    ("fedora-image", "selected-locked-image", "image", "linux", "oci-manifest"),
    ("ubuntu-cloud", "host-platform", "distribution", "linux", "vm-image"),
)


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _raw_case(case):
    profile, source, family, platform, format = case
    name, version = "independent-package", "2.3.4"
    target = p._Target("native", platform, "x86_64", "3.12.0", "cp312", (), _sha(b"context"))
    artifact = b"non-executable independent artifact"
    digest, size = _sha(artifact), len(artifact)
    meta = p._profile(profile).metadata[0] + "independent"
    url = p._profile(profile).artifacts[0] + "independent"
    selector, blobs, config = "", (), None
    if profile == "ubuntu-packages":
        url += "/file.deb"
        filename = "pool/independent/file.deb"
        raw = (f"Package: {name}\nVersion: {version}\nArchitecture: amd64\n"
               f"Filename: {filename}\nSize: {size}\nSHA256: {digest}\n").encode()
    elif profile == "msys2":
        meta += ".db"
        url += ".pkg.tar.zst"
        fields = {
            "NAME": name, "VERSION": version, "ARCH": "x86_64", "SHA256SUM": digest,
            "CSIZE": str(size), "FILENAME": url.rsplit("/", 1)[-1], "LICENSE": "MIT",
        }
        desc = "\n\n".join(f"%{key}%\n{value}" for key, value in fields.items()).encode()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            member = tarfile.TarInfo(f"{name}-{version}/desc")
            member.size = len(desc)
            archive.addfile(member, io.BytesIO(desc))
        raw = buffer.getvalue()
    elif profile in ("git-for-windows", "podman"):
        meta = p._profile(profile).metadata[0] + "321"
        url = p._profile(profile).artifacts[0] + f"v{version}/independent.zip"
        selector = "654"
        raw = json.dumps({
            "draft": False, "prerelease": False, "tag_name": f"v{version}",
            "assets": [{"id": 654, "name": "independent.zip", "size": size,
                        "digest": "sha256:" + digest, "browser_download_url": url}],
        }).encode()
    elif profile == "homebrew":
        meta = p._profile(profile).metadata[0] + name + ".json"
        selector = "ventura"
        raw = json.dumps({
            "name": name, "versions": {"stable": version}, "license": "MIT", "dependencies": [],
            "bottle": {"stable": {"files": {selector: {"url": url, "sha256": digest}}}},
        }).encode()
    elif profile == "ubuntu-cloud":
        selector = "independent.img"
        url = p._profile(profile).artifacts[0] + selector
        raw = (digest + " *" + selector + "\n").encode()
    else:
        config = b'{"architecture":"amd64","os":"linux"}'
        blobs = ((_sha(config), len(config)), (_sha(b"independent-layer"), 17))
        raw = json.dumps({
            "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + blobs[0][0], "size": blobs[0][1]},
            "layers": [{"digest": "sha256:" + blobs[1][0], "size": blobs[1][1]}],
        }).encode()
        digest, size = _sha(raw), len(raw)
        meta = url = p._profile(profile).metadata[0] + digest
    members = (ManagedMember("bin/independent", _sha(b"x"), 1),) if format in (
        "zip", "tar.gz",
    ) else ()
    pin = p._OfficialPin(
        profile, source, name, family, name, version,
        p._PublisherContext(platform, target, "native", "ventura"),
        meta, _sha(raw), url, digest, size, _sha(b"synthetic-not-qualification"),
        "MIT", _sha(b"synthetic-license-pin"), format, members=members,
        selector=selector, blob_pins=blobs,
        resource="independent-resource" if family in ("image", "runtime", "distribution") else None,
    )
    return pin, raw, config


@pytest.mark.parametrize("case", PROFILES, ids=[item[0] for item in PROFILES])
@pytest.mark.parametrize("fault", ["none", "raw-digest", "redirect", "target", "cancel", "deadline"])
def test_actual_official_client_rejects_unbound_raw_metadata_before_normalization(
    monkeypatch, case, fault,
):
    pin, raw, config = _raw_case(case)
    calls = []

    def read(_transport, url, timeout, limit, clock, cancel):
        calls.append((url, timeout, limit))
        content = config if "/blobs/" in url else raw
        return AssetResponse(url + "/redirect" if fault == "redirect" else url,
                             content + b"x" if fault == "raw-digest" else content)

    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", read)
    port = p._OfficialMetadata(pin.source, (pin,), HttpsAssetTransport())
    clock, cancel = _Clock(), _Cancel()
    target = pin.context.consuming
    if fault == "target":
        target = replace(target, context_digest=_sha(b"other-context"))
    if fault == "cancel":
        cancel = Mock(is_cancelled=Mock(return_value=True))
    deadline = clock.monotonic() + (60.0 if fault != "deadline" else -1.0)
    if fault == "none":
        snapshot = port.observe(pin.release().requirement, target, clock, cancel, deadline)
        assert snapshot.releases == (pin.release(),)
        assert snapshot.target_digest == c.digest(target)
        assert calls and all(0 < value[1] <= 60.0 for value in calls)
    else:
        error = {
            "raw-digest": p._SourceUnavailable, "redirect": p._SourceUnavailable,
            "target": p._CatalogueUnavailable, "cancel": InterruptedError,
            "deadline": TimeoutError,
        }[fault]
        with pytest.raises(error):
            port.observe(pin.release().requirement, target, clock, cancel, deadline)
        if fault in ("target", "cancel", "deadline"):
            assert not calls


@pytest.mark.parametrize("case", PROFILES, ids=[item[0] for item in PROFILES])
def test_empty_official_pins_never_acquire_or_claim_qualification(monkeypatch, case):
    pin, _, _ = _raw_case(case)
    forbidden = Mock(side_effect=AssertionError("must not acquire metadata"))
    monkeypatch.setattr(HttpsAssetTransport, "read_bounded", forbidden)
    port = p._OfficialMetadata(pin.source, (), HttpsAssetTransport())
    clock = _Clock()
    with pytest.raises(p._CatalogueUnavailable):
        port.observe(pin.release().requirement, pin.context.consuming,
                     clock, _Cancel(), clock.monotonic() + 60.0)
    forbidden.assert_not_called()


@pytest.mark.parametrize("layout", ["native", "direct-controller", "wsl2-guest", "vm-guest"])
def test_windows_controller_context_cannot_be_forged_as_native_fallback(layout):
    target = p._Target("controller", "win32", "x86_64", "3.12.0", "cp312", (), _sha(b"context"))
    with pytest.raises(c.ContractError):
        p._PublisherContext("win32", target, layout, "windows11")


@pytest.mark.parametrize("url", [
    "https://api.github.com/repos/unrelated/git/releases/321",
    "https://api.github.com/repos/git-for-windows/git/releases/%33%32%31",
    "https://api.github.com/repos/git-for-windows/git/releases/../321",
    "https://api.github.com/repos/git-for-windows/git/releases/321?token=secret",
])
def test_exact_origin_project_path_and_token_free_pin_is_closed(url):
    pin, _, _ = _raw_case(PROFILES[3])
    with pytest.raises(c.ContractError):
        replace(pin, metadata_url=url)
