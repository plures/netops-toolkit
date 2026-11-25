"""Closed official publisher metadata compilers, not acquisition or host grants.

Exact independently reviewed raw/artifact pins are constructor facts. Empty pins
produce precise inputs before HTTP. No generic publisher, CDN, signature callback,
native Windows controller or mutable image tag is admitted.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from netops.ansible import contracts as c

from ._assets import HttpsAssetTransport, LockedAsset, _origin
from ._family_lock import (
    _CatalogueUnavailable,
    _check,
    _name,
    _PublisherSnapshot,
    _RegisteredSource,
    _Release,
    _Requirement,
    _SourceUnavailable,
    _Target,
    _trace,
)
from ._managed import ManagedMember
from ._publisher_metadata import _object, _pairs

__all__: tuple[str, ...] = ()
_LIMIT = 1024 * 1024


@dataclass(frozen=True)
class _OfficialProfile:
    name: str
    sources: tuple[str, ...]
    platforms: tuple[str, ...]
    metadata: tuple[str, ...]
    artifacts: tuple[str, ...]
    integrity: str


_PROFILES = (
    _OfficialProfile(
        "ubuntu-packages", ("os-package-manager", "weasyprint-native-platform-packages",
                            "git-scm.com"), ("linux",),
        ("https://archive.ubuntu.com/ubuntu/dists/", "https://security.ubuntu.com/ubuntu/dists/"),
        ("https://archive.ubuntu.com/ubuntu/pool/", "https://security.ubuntu.com/ubuntu/pool/"),
        "reviewed-exact-package-and-raw-index-pin",
    ),
    _OfficialProfile(
        "homebrew", ("os-package-manager", "weasyprint-native-platform-packages",
                     "git-scm.com"), ("darwin",),
        ("https://formulae.brew.sh/api/formula/",),
        ("https://ghcr.io/v2/homebrew/core/",), "reviewed-exact-formula-and-bottle-pin",
    ),
    _OfficialProfile(
        "msys2", ("os-package-manager", "weasyprint-native-platform-packages"), ("win32",),
        ("https://repo.msys2.org/mingw/",), ("https://repo.msys2.org/mingw/",),
        "reviewed-exact-repository-and-package-pin",
    ),
    _OfficialProfile(
        "git-for-windows", ("git-scm.com",), ("win32",),
        ("https://api.github.com/repos/git-for-windows/git/releases/",),
        ("https://github.com/git-for-windows/git/releases/download/",),
        "reviewed-exact-project-release-and-asset-pin",
    ),
    _OfficialProfile(
        "podman", ("selected-runtime-vendor",), ("linux", "darwin", "win32"),
        ("https://api.github.com/repos/containers/podman/releases/",),
        ("https://github.com/containers/podman/releases/download/",),
        "reviewed-exact-project-release-and-asset-pin",
    ),
    _OfficialProfile(
        "fedora-image", ("selected-locked-image",), ("linux",),
        ("https://registry.fedoraproject.org/v2/fedora-minimal/manifests/sha256:",
         "https://registry.fedoraproject.org/v2/fedora-minimal/blobs/sha256:"),
        ("https://registry.fedoraproject.org/v2/fedora-minimal/manifests/sha256:",),
        "reviewed-exact-manifest-and-complete-blob-pin",
    ),
    _OfficialProfile(
        "ubuntu-cloud", ("host-platform",), ("linux",),
        ("https://cloud-images.ubuntu.com/releases/",),
        ("https://cloud-images.ubuntu.com/releases/",),
        "reviewed-exact-build-checksum-and-image-pin",
    ),
)


def _profile(name: str) -> _OfficialProfile:
    selected = tuple(value for value in _PROFILES if value.name == name)
    if len(selected) != 1:
        raise c.ContractError()
    return selected[0]


def _scoped(url: str, scopes: tuple[str, ...]) -> None:
    """Reject traversal, encoding aliases, query/token hops and unrelated projects."""
    _origin(url)
    parsed = urlsplit(url)
    if (
        unquote(parsed.path) != parsed.path
        or any(part in (".", "..") for part in parsed.path.split("/"))
        or "\\" in url or not any(url.startswith(scope) for scope in scopes)
    ):
        raise c.ContractError()


def _architecture(target: _Target, profile: str) -> str:
    architecture = {"AMD64": "x86_64", "ARM64": "aarch64"}.get(
        target.architecture, target.architecture,
    )
    if profile in ("ubuntu-packages", "fedora-image"):
        return {"x86_64": "amd64", "aarch64": "arm64"}.get(architecture, architecture)
    return architecture


def _json_constant(value: str) -> None:
    raise c.ContractError()


@dataclass(frozen=True)
class _PublisherContext:
    """Separate native host, controller and guest layout/version identities."""

    host_platform: str
    consuming: _Target
    layout: str
    platform_version: str

    def __post_init__(self) -> None:
        self.consuming.__post_init__()
        _name(self.platform_version)
        if self.host_platform not in ("win32", "linux", "darwin"):
            raise c.ContractError()
        if self.layout not in ("native", "direct-controller", "wsl2-guest", "vm-guest"):
            raise c.ContractError()
        if (
            (self.layout == "native") != (self.consuming.context == "native")
            or (self.consuming.context == "controller" and self.consuming.platform == "win32")
            or (self.layout == "wsl2-guest" and (
                self.host_platform != "win32" or self.consuming.platform != "linux"
            ))
            or (self.layout == "direct-controller" and
                self.host_platform != self.consuming.platform)
            or (self.layout == "native" and self.host_platform != self.consuming.platform)
        ):
            raise c.ContractError()


@dataclass(frozen=True)
class _OfficialPin:
    """Independent exact qualification reference, never a trust boolean or key.

    The exact-pin integrity branch is supported. OpenPGP/OCI signature enrolment
    remains a separate qualification input; no fake signature result substitutes.
    Native package formats remain ``host-package``, not relabelled TAR archives.
    """

    profile: str
    source: str
    name: str
    family: str
    publisher_name: str
    version: str
    context: _PublisherContext
    metadata_url: str
    metadata_digest: str
    artifact_url: str
    artifact_digest: str
    artifact_size: int
    qualification_ref: str
    license: str
    license_digest: str
    format: str
    members: tuple[ManagedMember, ...] = ()
    requires: tuple[_Requirement, ...] = ()
    resource: str | None = None
    selector: str = ""
    blob_pins: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        profile = _profile(self.profile)
        self.context.__post_init__()
        _Requirement(self.name, self.family, self.source, self.context.consuming.context,
                     "==" + self.version)
        _name(self.publisher_name)
        _name(self.version)
        if (
            self.source not in profile.sources
            or self.context.consuming.platform not in profile.platforms
            or type(self.license) is not str or not self.license or len(self.license) > 256
            or any(ord(value) < 32 for value in self.license)
            or type(self.selector) is not str or len(self.selector) > 256
        ):
            raise c.ContractError()
        for digest in (self.metadata_digest, self.artifact_digest,
                       self.qualification_ref, self.license_digest):
            c.sha256(digest)
        if c.counter(self.artifact_size, positive=True) > 128 * 1024 * 1024:
            raise c.ContractError()
        _scoped(self.metadata_url, profile.metadata)
        _scoped(self.artifact_url, profile.artifacts)
        if type(self.blob_pins) is not tuple or len(self.blob_pins) > 256:
            raise c.ContractError()
        c.unique(tuple(digest for digest, _ in self.blob_pins))
        for digest, size in self.blob_pins:
            c.sha256(digest)
            c.counter(size, positive=True)
        if self.profile == "fedora-image" and (
            self.format != "oci-manifest" or not self.blob_pins
            or self.metadata_url != self.artifact_url
            or not self.metadata_url.endswith("sha256:" + self.artifact_digest)
        ):
            raise c.ContractError()
        if self.profile in ("ubuntu-packages", "msys2") and self.format != "host-package":
            raise c.ContractError()
        if self.profile in ("git-for-windows", "podman"):
            suffix = self.metadata_url.rsplit("/", 1)[-1]
            if (
                not suffix.isascii() or not suffix.isdecimal() or int(suffix) <= 0
                or not self.selector.isascii() or not self.selector.isdecimal()
                or int(self.selector) <= 0
                or "/releases/download/v" + self.version + "/" not in self.artifact_url
            ):
                raise c.ContractError()
        if self.profile == "homebrew" and (
            self.metadata_url != profile.metadata[0] + self.publisher_name + ".json"
            or self.selector != (
                ("arm64_" if self.context.consuming.architecture in ("arm64", "aarch64") else "")
                + self.context.platform_version
            )
        ):
            raise c.ContractError()
        if self.profile == "msys2" and not self.metadata_url.endswith((".db", ".db.tar.gz")):
            raise c.ContractError()
        if self.profile == "ubuntu-cloud" and self.format not in ("vm-image", "wsl-rootfs"):
            raise c.ContractError()
        self.release().__post_init__()

    def release(self) -> _Release:
        """Compile only existing family formats, with exact target/context closure."""
        target = self.context.consuming
        artifact = None if self.format == "host-package" else LockedAsset(
            self.source, self.name, self.artifact_url, self.artifact_digest, self.artifact_size,
        )
        scopes: tuple[str, ...] = ()
        if self.format == "host-package":
            scopes = ("os",)
        elif self.family == "runtime":
            scopes = ("runtime",)
        elif self.family == "image":
            scopes = ("image",)
        elif self.family == "distribution":
            scopes = ("distribution", "wsl") if self.format == "wsl-rootfs" else (
                "distribution", "vm", "virtualization",
            )
        return _Release(
            _Requirement(self.name, self.family, self.source, target.context, "==" + self.version),
            self.version, self.format, (target.platform,), (target.architecture,),
            self.requires, self.metadata_digest, artifact, abis=(target.abi,),
            scopes=scopes, resource=self.resource, members=self.members,
        )


def _fields(content: bytes) -> tuple[dict[str, str], ...]:
    """Read bounded RFC822 package indexes or pacman percent-field records."""
    text = content.decode("utf-8")
    records = []
    for section in text.strip().split("\n\n"):
        record: dict[str, str] = {}
        key = ""
        for line in section.splitlines():
            if line.startswith((" ", "\t")) and key:
                record[key] += " " + line.strip()
                continue
            if ":" not in line:
                raise c.ContractError()
            key, value = line.split(":", 1)
            if key in record:
                raise c.ContractError()
            record[key] = value.strip()
        records.append(record)
    return tuple(records)


def _verify_document(pin: _OfficialPin, content: bytes, config_content: bytes | None = None) -> None:
    """Verify real publisher fields against independent pins, never normalize callbacks."""
    if pin.profile == "ubuntu-packages":
        records = tuple(item for item in _fields(content) if item.get("Package") == pin.publisher_name)
        if len(records) != 1:
            raise c.ContractError()
        item = records[0]
        if (
            item.get("Version") != pin.version
            or item.get("Architecture") != _architecture(pin.context.consuming, pin.profile)
            or item.get("SHA256") != pin.artifact_digest
            or item.get("Size") != str(pin.artifact_size)
            or not pin.artifact_url.endswith("/" + item.get("Filename", ""))
        ):
            raise c.ContractError()
        # Debian alternatives/ranges cannot become permissive PEP440 edges.
        dependencies = ", ".join(filter(None, (item.get("Pre-Depends"), item.get("Depends"))))
        expected_dependencies = ", ".join(
            edge.name + " (= " + edge.version.removeprefix("==") + ")" for edge in pin.requires
        )
        if dependencies != expected_dependencies:
            raise _CatalogueUnavailable(("exact-debian-dependency-closure",))
        return
    if pin.profile == "msys2":
        # The real pacman repository database is a TAR, not a fabricated JSON
        # response or an imaginary HTTP endpoint serving normalized desc fields.
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as database:
            entries = database.getmembers()
            if len(entries) > 8192 or sum(item.size for item in entries) > 64 * _LIMIT:
                raise c.ContractError()
            selected = tuple(item for item in entries if item.name == (
                pin.publisher_name + "-" + pin.version + "/desc"
            ))
            if (
                len(selected) != 1 or not selected[0].isfile()
                or selected[0].size > _LIMIT
                or any(item.issym() or item.islnk() or item.isdev() for item in entries)
            ):
                raise c.ContractError()
            stream = database.extractfile(selected[0])
            if stream is None:
                raise c.ContractError()
            description = stream.read(_LIMIT + 1)
            if len(description) != selected[0].size:
                raise c.ContractError()
        lines = description.decode("utf-8").strip().split("\n\n")
        fields = {}
        for section in lines:
            key, *values = section.splitlines()
            if not key.startswith("%") or not key.endswith("%") or key in fields:
                raise c.ContractError()
            fields[key] = values
        expected_fields = {
            "%NAME%": [pin.publisher_name], "%VERSION%": [pin.version],
            "%ARCH%": [_architecture(pin.context.consuming, pin.profile)],
            "%SHA256SUM%": [pin.artifact_digest], "%CSIZE%": [str(pin.artifact_size)],
            "%FILENAME%": [pin.artifact_url.rsplit("/", 1)[-1]],
            "%LICENSE%": pin.license.split(" AND "),
            "%DEPENDS%": [edge.name + "=" + edge.version.removeprefix("==") for edge in pin.requires],
        }
        if any(fields.get(key, []) != value for key, value in expected_fields.items()):
            raise c.ContractError()
        return
    if pin.profile == "ubuntu-cloud":
        checksum_matches = [line.split() for line in content.decode("ascii").splitlines()
                            if line.split() and line.split()[-1].lstrip("*") == pin.selector]
        if (
            len(checksum_matches) != 1 or len(checksum_matches[0]) != 2
            or checksum_matches[0][0] != pin.artifact_digest
            or pin.artifact_url.rsplit("/", 1)[-1] != pin.selector
            or (pin.format == "wsl-rootfs" and not pin.selector.endswith(".rootfs.tar.gz"))
        ):
            raise c.ContractError()
        return
    document = _object(json.loads(content, object_pairs_hook=_pairs, parse_constant=_json_constant))
    if pin.profile in ("git-for-windows", "podman"):
        assets = document.get("assets")
        if type(assets) is not list or len(assets) > 1024:
            raise c.ContractError()
        matches = [_object(item) for item in assets
                   if str(_object(item).get("id")) == pin.selector]
        if (
            len(matches) != 1 or document.get("draft") is not False
            or document.get("prerelease") is not False
            or document.get("tag_name") != "v" + pin.version
            or matches[0].get("browser_download_url") != pin.artifact_url
            or type(matches[0].get("size")) is not int
            or matches[0].get("size") != pin.artifact_size
            or matches[0].get("name") != pin.artifact_url.rsplit("/", 1)[-1]
        ):
            raise c.ContractError()
        published = matches[0].get("digest")
        if published is not None and published != "sha256:" + pin.artifact_digest:
            raise c.ContractError()
        return
    if pin.profile == "homebrew":
        stable = _object(_object(document.get("bottle")).get("stable"))
        bottle = _object(_object(stable.get("files")).get(pin.selector))
        if (
            document.get("name") != pin.publisher_name
            or _object(document.get("versions")).get("stable") != pin.version
            or document.get("license") != pin.license
            or bottle.get("url") != pin.artifact_url or bottle.get("sha256") != pin.artifact_digest
            or document.get("dependencies") != [edge.name for edge in pin.requires]
        ):
            raise c.ContractError()
        return
    if pin.profile == "fedora-image":
        layers = document.get("layers")
        config = _object(document.get("config"))
        if (
            type(document.get("schemaVersion")) is not int
            or document.get("schemaVersion") != 2 or type(layers) is not list
            or len(layers) > 255 or document.get("mediaType") not in (
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.v2+json",
            )
        ):
            raise c.ContractError()
        observed = []
        for item in (config, *layers):
            blob = _object(item)
            digest = blob.get("digest")
            if type(digest) is not str or not digest.startswith("sha256:"):
                raise c.ContractError()
            if type(blob.get("size")) is not int:
                raise c.ContractError()
            observed.append((digest[7:], blob.get("size")))
        if tuple(observed) != pin.blob_pins or len(content) != pin.artifact_size:
            raise c.ContractError()
        if config_content is None:
            raise c.ContractError()
        configuration = _object(json.loads(
            config_content, object_pairs_hook=_pairs, parse_constant=_json_constant,
        ))
        if (
            configuration.get("architecture") != _architecture(pin.context.consuming, pin.profile)
            or configuration.get("os") != pin.context.consuming.platform
        ):
            raise c.ContractError()
        return
    raise c.ContractError()


@dataclass(frozen=True)
class _OfficialMetadata:
    """Actual closed bounded external metadata adapter for every approved profile."""

    source: str
    pins: tuple[_OfficialPin, ...]
    transport: HttpsAssetTransport

    def __post_init__(self) -> None:
        if (
            self.source not in {source for profile in _PROFILES for source in profile.sources}
            or type(self.transport) is not HttpsAssetTransport or type(self.pins) is not tuple
            or len(self.pins) > 1024
        ):
            raise c.ContractError()
        for pin in self.pins:
            if type(pin) is not _OfficialPin or pin.source != self.source:
                raise c.ContractError()
            pin.__post_init__()
        c.unique(tuple(c.digest(pin) for pin in self.pins))

    @property
    def digest(self) -> str:
        return c.digest((self.source, self.pins))

    def observe(
        self, requirement: _Requirement, target: _Target,
        clock: c.ClockPort, cancel: c.CancelPort, deadline: float,
    ) -> _PublisherSnapshot:
        self.__post_init__()
        requirement.__post_init__()
        target.__post_init__()
        started = _check(clock, cancel, deadline)
        deadline = min(deadline, started + 60.0)
        if requirement.source != self.source:
            raise c.ContractError()
        pins = tuple(pin for pin in self.pins
                     if pin.name == requirement.name and pin.family == requirement.family
                     and pin.context.consuming == target)
        if not pins:
            raise _CatalogueUnavailable((
                "official-profile-exact-raw-and-artifact-pin", "independent-qualification-reference",
                "license-and-exact-platform-context-version", "complete-member-and-dependency-closure",
            ))
        releases = []
        for pin in pins:
            now = _check(clock, cancel, deadline)
            _trace("official-publisher-metadata", requirement.family, "attempt")
            try:
                response = self.transport.read_bounded(
                    pin.metadata_url, deadline - now, _LIMIT + 1, clock, cancel,
                )
                _check(clock, cancel, deadline)
                if (
                    response.url != pin.metadata_url or type(response.content) is not bytes
                    or len(response.content) > _LIMIT
                    or hashlib.sha256(response.content).hexdigest() != pin.metadata_digest
                ):
                    raise c.ContractError()
                config_content = None
                if pin.profile == "fedora-image":
                    config_digest, config_size = pin.blob_pins[0]
                    if config_size > _LIMIT:
                        raise c.ContractError()
                    config_url = (
                        "https://registry.fedoraproject.org/v2/fedora-minimal/blobs/sha256:"
                        + config_digest
                    )
                    remaining = deadline - _check(clock, cancel, deadline)
                    config = self.transport.read_bounded(
                        config_url, remaining, config_size + 1, clock, cancel,
                    )
                    _check(clock, cancel, deadline)
                    if (
                        config.url != config_url or type(config.content) is not bytes
                        or len(config.content) != config_size
                        or hashlib.sha256(config.content).hexdigest() != config_digest
                    ):
                        raise c.ContractError()
                    config_content = config.content
                _verify_document(pin, response.content, config_content)
                releases.append(pin.release())
            except (InterruptedError, TimeoutError):
                _trace("official-publisher-metadata", requirement.family, "interrupted")
                raise
            except _CatalogueUnavailable:
                _trace("official-publisher-metadata", requirement.family, "blocked")
                raise
            except (c.ContractError, OSError, ValueError, KeyError, TypeError, tarfile.TarError):
                _trace("official-publisher-metadata", requirement.family, "failed")
                raise _SourceUnavailable() from None
            _trace("official-publisher-metadata", requirement.family, "returned")
        now = _check(clock, cancel, deadline)
        return _PublisherSnapshot(
            self.source, c.digest(target), tuple(releases), self.digest,
            now, min(now + 300.0, deadline),
        )


def _official_sources(pins: tuple[_OfficialPin, ...]) -> tuple[_RegisteredSource, ...]:
    """Wire all official sources even with honest empty pins; no I/O during construction."""
    sources = sorted({source for profile in _PROFILES for source in profile.sources})
    result = []
    for source in sources:
        profiles = tuple(profile for profile in _PROFILES if source in profile.sources)
        selected = tuple(pin for pin in pins if pin.source == source)
        port = _OfficialMetadata(source, selected, HttpsAssetTransport())
        families = {
            "os-package-manager": ("executable", "library", "python"),
            "weasyprint-native-platform-packages": ("library",),
            "git-scm.com": ("executable",), "selected-runtime-vendor": ("runtime",),
            "selected-locked-image": ("image",), "host-platform": ("distribution", "os-feature"),
        }[source]
        origins = tuple(sorted({_origin(url) for profile in profiles for url in profile.artifacts}))
        result.append(_RegisteredSource(source, families, origins, port.digest, port))
    return tuple(result)


def _decode_pin(value: object) -> _OfficialPin:
    """Decode factual packaged inputs only; no port, key verification or grant."""
    from ._family_codec import _record, _requirement, _sequence, _target

    record = dict(_object(value))
    if set(record) != set(_OfficialPin.__dataclass_fields__):
        raise c.ContractError()
    context = _object(record["context"])
    if set(context) != set(_PublisherContext.__dataclass_fields__):
        raise c.ContractError()
    record["context"] = _PublisherContext(
        context["host_platform"], _target(context["consuming"]),
        context["layout"], context["platform_version"],
    )
    record["members"] = tuple(ManagedMember(**_record(ManagedMember, item))
                              for item in _sequence(record["members"], 4096))
    record["requires"] = tuple(_requirement(item) for item in _sequence(record["requires"], 256))
    record["blob_pins"] = tuple(tuple(_sequence(item, 2))
                                for item in _sequence(record["blob_pins"], 256))
    return _OfficialPin(**record)
