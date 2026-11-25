"""Versioned, immutable companion workflow values and effect-free wire validation.

These are toolkit contracts, not an upstream Praxis Python API. Authority-bearing
host values are deliberately excluded from the JSON boundary.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, BinaryIO, NoReturn, Protocol
from uuid import UUID

from .policy.contracts import (
    MAX_SAFE_INT,
    DecisionResult,
    FrozenObject,
    Json,
    PolicyIdentity,
    freeze,
)
from .policy.loader import validate_identity

MAX_CONTENT_BYTES = 1048576
MAX_STRING_BYTES = 4096
MAX_JSON_DEPTH = 32
DEFAULT_TARGET_LIMIT = 100
MAX_TARGET_LIMIT = 4096
SCHEMA_VERSION = "1.0"
INPUT_BINDING_INVALID = "input-binding-invalid"
INVALID_REQUEST = "invalid-request"

if TYPE_CHECKING:
    from .settings import SettingsSnapshot


class Mode(str, Enum):
    """Public modes; preview and check never imply execution approval."""

    PREVIEW = "preview"
    CHECK = "check"
    OBSERVE = "observe"
    OUTPUT = "output"
    APPLY = "apply"
    ROLLBACK = "rollback"


class OutcomeStatus(str, Enum):
    """Public aggregate statuses (partial is aggregate-only)."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"
    CANCELLED = "cancelled"
    NOT_REQUESTED = "not-requested"
    PARTIAL = "partial"


class ErrorCategory(str, Enum):
    """Stable safe error categories."""

    INVALID_INPUT = "invalid-input"
    DEPENDENCY = "dependency"
    PLATFORM = "platform"
    CREDENTIALS = "credentials"
    TRANSPORT = "transport"
    UNSUPPORTED = "unsupported-capability"
    PRECONDITION = "precondition"
    EXECUTION = "execution"
    POLICY = "policy"
    RENDERING = "rendering"
    CLEANUP = "cleanup"


class ReasonCode(str, Enum):
    """Stable v1 reasons; no supplied exception text crosses this boundary."""

    INVALID_REQUEST = "invalid-request"
    DEPENDENCY_NOT_READY = "dependency-not-ready"
    CONSENT_REQUIRED = "consent-required"
    REBOOT_PENDING = "reboot-pending"
    PROVISION_FAILED = "provision-failed"
    VAULT_LOCKED = "vault-locked"
    VAULT_MISSING = "vault-missing"
    VAULT_PASSWORD_INVALID = "vault-password-invalid"
    HANDOFF_INVALID = "handoff-invalid"
    CREDENTIAL_SCOPE_INVALID = "credential-scope-invalid"
    ROUTE_UNAVAILABLE = "route-unavailable"
    HOST_KEY_INVALID = "host-key-invalid"
    INVENTORY_INVALID = "inventory-invalid"
    LEGACY_CACHE_REJECTED = "legacy-cache-rejected"
    OBSERVATION_REQUIRED = "observation-required"
    CONSENT_STALE = "consent-stale"
    RESOURCE_BUSY = "resource-busy"
    OPERATION_UNSUPPORTED = "operation-unsupported"
    READING_UNAVAILABLE = "reading-unavailable"
    HEALTH_ALERT = "health-alert"
    APPLY_FAILED = "apply-failed"
    REMOTE_STATE_UNCERTAIN = "remote-state-uncertain"
    RENDER_FAILED = "render-failed"
    OUTPUT_REJECTED = "output-rejected"
    CANCELLED = "cancelled"
    DEADLINE_EXCEEDED = "deadline-exceeded"
    CLEANUP_FAILED = "cleanup-failed"
    OWNERSHIP_INVALID = "ownership-invalid"
    INPUT_BINDING_INVALID = "input-binding-invalid"
    CONTROL_LOST = "control-lost"
    RESTORE_CANDIDATE_INVALID = "restore-candidate-invalid"


class Stage(str, Enum):
    """Safe stages shared by Python and future surface adapters."""

    VALIDATE = "validate"
    READINESS = "readiness"
    PROVISION = "provision"
    CREDENTIALS = "credentials"
    CONTROLLER = "controller"
    CONNECT = "connect"
    INVENTORY = "inventory"
    AUTHORIZE = "authorize"
    EVALUATE = "evaluate"
    APPLY = "apply"
    RECOVER = "recover"
    RENDER = "render"
    PUBLISH = "publish"
    DISPATCH = "dispatch"
    FINALIZE = "finalize"
    ACTIVATE = "activate"


class ContractError(ValueError):
    """A closed safe validation failure, never a copy of the input."""

    def __init__(self, reason: str = INVALID_REQUEST) -> None:
        self.reason = reason if reason in (INVALID_REQUEST, INPUT_BINDING_INVALID) else INVALID_REQUEST
        self.error = SafeError(
            ErrorCategory.INVALID_INPUT, ReasonCode(self.reason), Stage.VALIDATE,
        )
        super().__init__(self.reason)


def text(value: object, *, empty: bool = False) -> str:
    """Validate bounded reference text without returning supplied diagnostics."""
    if type(value) is not str or not isinstance(value, str):
        raise ContractError()
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise ContractError() from None
    if size > MAX_STRING_BYTES or (not empty and size == 0):
        raise ContractError()
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ContractError()
    return value


def counter(value: object, *, positive: bool = False) -> int:
    """Require an exact int53 control counter, never bool or float."""
    if type(value) is not int or not isinstance(value, int):
        raise ContractError()
    if not (1 if positive else 0) <= value <= MAX_SAFE_INT:
        raise ContractError()
    return value


def finite(value: object) -> float:
    """Validate a nonnegative binary64 time without coercion or narrowing."""
    if type(value) is not float or not isinstance(value, float):
        raise ContractError()
    if not math.isfinite(value) or value < 0:
        raise ContractError()
    return value


def checked_deadline(now: float, duration: float) -> float:
    """Reject overflowing deadlines; caller obtains time outside pure preview."""
    return finite(finite(now) + finite(duration))


def sha256(value: object) -> str:
    """Validate an exact lower-case SHA256 identity."""
    result = text(value)
    if len(result) != 64 or any(c not in "0123456789abcdef" for c in result):
        raise ContractError()
    return result


def uuid_text(value: object) -> str:
    """Validate the canonical UUID string, not an opaque authorization token."""
    result = text(value)
    try:
        if str(UUID(result)) != result:
            raise ContractError()
    except ValueError:
        raise ContractError() from None
    return result


def unique(values: object) -> tuple[str, ...]:
    """Keep ordered unique references; never silently truncate selection."""
    if type(values) is not tuple or not isinstance(values, tuple):
        raise ContractError()
    for value in values:
        text(value)
    if len(set(values)) != len(values):
        raise ContractError()
    return values


_PRIVATE_KEYS = frozenset({
    "password", "passwd", "secret", "token", "authorization", "private_key",
    "master_password", "ansible_password", "ansible_ssh_pass", "ansible_become_password",
    "ntp_authentication_key", "ntp_auth_key", "credential", "credentials",
    "username", "ansible_user", "ansible_ssh_user", "jump_username",
})
_COMPACT_SECRET_KEYS = frozenset({
    "authkey", "privkey", "authenticationkey", "privacykey", "sharedkey", "sharedsecret",
    "authpassword", "privpassword", "authpassphrase", "privpassphrase",
    "community", "communitystring", "readcommunity", "writecommunity",
})
_CREDENTIAL_LINE = re.compile(
    r"(?im)(?:^.*\b(?:password|passwd|secret|community|authentication-key|"
    r"private-key|ansible_password)\s*[:= ]|-----BEGIN [^\n]*PRIVATE KEY-----)"
)


def nonsecret_text(value: str) -> None:
    """Reject supported credential-bearing CLI families, not redact secrets.

    SNMPv3 auth/priv and AAA block keys do not use the generic password syntax.
    Unknown secret encodings are not certified safe by this parser. Protected
    recovery configurations must never be supplied to this public boundary.
    """
    if _CREDENTIAL_LINE.search(value) is not None:
        raise ContractError()
    credential_block = False
    for line in value.splitlines():
        stripped = line.strip()
        words = tuple(part.strip("\"';{}").casefold() for part in stripped.split())
        if len(words) == 0:
            continue
        if words[0] == "no":
            words = words[1:]
            if not words:
                continue
        if stripped in ("!", "}", "exit", "end"):
            credential_block = False
            continue
        family = words[0].startswith(("snmp", "tacacs", "radius")) or words[:2] == ("set", "snmp")
        if not line[:1].isspace() and stripped not in ("{",):
            credential_block = family
        elif family:
            credential_block = True
        header = words[:2] in (("radius", "server"), ("tacacs", "server"))
        parameters = words[3:] if header else words[1:] if family else words
        user_credentials = words[:2] in (
            ("snmp-server", "user"), ("snmp", "user"), ("snmpv3", "user"),
            ("snmp-agent", "usm-user"),
        )
        if words[:2] == ("snmp-server", "user"):
            parameters = words[4:]
        elif words[:2] in (("snmp", "user"), ("snmpv3", "user")):
            parameters = words[3:]
        # Authentication/privacy are also nonsecret notification selectors and
        # security levels. Only credential productions give those words values.
        credential_parameters = (
            not words[0].startswith("snmp")
            or user_credentials
            or ("user" in words and ("v3" in words or "usm" in words))
            or not family
        )
        if (family or credential_block) and any(
            word in ("key", "key-string", "auth-key", "priv-key", "cipher", "encrypted-password")
            or (credential_parameters and (
                word in ("authentication", "privacy")
                or word.startswith(("authentication-", "privacy-"))
            ))
            or ((user_credentials or words[0] in ("auth", "priv")) and word in ("auth", "priv"))
            for word in parameters
        ):
            raise ContractError()


def _settings_default() -> SettingsSnapshot:
    # Deferred import keeps the strict settings decoder on the shared error type.
    from .settings import SettingsSnapshot

    return SettingsSnapshot()


def public_value(value: object, depth: int = 0) -> Json:
    """Detach credential-free JSON; public readings/totals retain integer range."""
    if depth > MAX_JSON_DEPTH:
        raise ContractError()
    if value is None or type(value) in (str, bool, int, float):
        if isinstance(value, str):
            # Payload text may contain newlines, unlike safe identifiers.
            if len(value.encode("utf-8")) > MAX_CONTENT_BYTES:
                raise ContractError()
            nonsecret_text(value)
        if type(value) is float and isinstance(value, float) and not math.isfinite(value):
            raise ContractError()
        return freeze(value)
    if isinstance(value, Mapping):
        pairs: list[tuple[str, Json]] = []
        for key, item in value.items():
            name = text(key)
            normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).casefold().replace("-", "_")
            compact = normalized.replace("_", "")
            # This exact non-authority settings record is not a private grant.
            if normalized == "authorization" and isinstance(item, Mapping):
                if set(item) == {"ttl_seconds"} and type(item["ttl_seconds"]) is int:
                    ttl = counter(item["ttl_seconds"], positive=True)
                    if ttl <= 300:
                        pairs.append((name, public_value(item, depth + 1)))
                        continue
            if normalized in _PRIVATE_KEYS or compact in _COMPACT_SECRET_KEYS or normalized.endswith((
                "_password", "_passphrase", "_secret", "_token", "_auth_key", "_priv_key",
                "_authentication_key", "_privacy_key", "_shared_key", "_community",
            )) or normalized in {
                "auth", "priv", "authentication", "privacy", "auth_key", "priv_key",
                "authentication_key", "privacy_key", "shared_key", "tacacs_key",
                "radius_key", "key_string", "cipher", "auth_pass", "priv_pass",
            } or (normalized.startswith(("snmp", "radius", "tacacs"))
                  and normalized.endswith(("_key", "_secret", "_password", "_passphrase"))):
                raise ContractError()
            if normalized in ("snmp", "snmpv3", "radius", "tacacs", "usm") and isinstance(item, Mapping):
                # This channel has no public structured credential-domain schema.
                # Protocol flags/scalars remain valid; private adapters own data.
                raise ContractError()
            pairs.append((name, public_value(item, depth + 1)))
        pairs.sort(key=lambda pair: pair[0])
        return FrozenObject(tuple(pairs))
    if type(value) in (list, tuple) and isinstance(value, (list, tuple)):
        return tuple(public_value(item, depth + 1) for item in value)
    raise ContractError()


def public_object(value: object) -> FrozenObject:
    """Require a credential-free immutable JSON object."""
    result = public_value(value)
    if type(result) is not FrozenObject or not isinstance(result, FrozenObject):
        raise ContractError()
    return result


def wire(value: object) -> object:
    """Encode public DTOs only; authority objects cannot be serialized."""
    if isinstance(value, _PrivateValue):
        raise ContractError()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, FrozenObject):
        return {key: wire(item) for key, item in value.items()}
    if type(value) is tuple:
        return [wire(item) for item in value]
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: wire(getattr(value, item.name)) for item in fields(value)}
    if value is None or type(value) in (str, bool, int, float):
        return value
    raise ContractError()


def canonical_bytes(value: object) -> bytes:
    """Canonical nonsecret JSON, retaining array order and exact integers."""
    try:
        return json.dumps(
            wire(public_value(wire(value))), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ContractError() from None


def digest(value: object) -> str:
    """Hash canonical nonsecret content only."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError()
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ContractError()


def decode_json(data: bytes) -> FrozenObject:
    """Reject duplicate keys, nonfinite numbers and unsafe input before dispatch."""
    if type(data) is not bytes or len(data) > MAX_CONTENT_BYTES:
        raise ContractError()
    try:
        parsed: object = json.loads(data, object_pairs_hook=_pairs, parse_constant=_constant)
        return public_object(parsed)
    except (ValueError, UnicodeError, RecursionError):
        raise ContractError() from None


@dataclass(frozen=True)
class Capability:
    """One declarative public operation; it is not runtime qualification."""

    area: str
    operation: str
    modes: tuple[Mode, ...]
    effects: tuple[str, ...]
    network: bool
    observation_required: bool = False
    required_inputs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate declaration values without dynamic executable registration."""
        text(self.area)
        text(self.operation)
        if type(self.modes) is not tuple or any(type(mode) is not Mode for mode in self.modes):
            raise ContractError()
        if len(set(self.modes)) != len(self.modes) or len(self.modes) == 0:
            raise ContractError()
        unique(self.effects)
        unique(self.required_inputs)
        if type(self.network) is not bool or type(self.observation_required) is not bool:
            raise ContractError()

    @property
    def id(self) -> str:
        """Return the unambiguous area-qualified operation identifier."""
        return self.area + "." + self.operation


_PURE = (Mode.PREVIEW, Mode.CHECK)
CAPABILITIES = (
    Capability("scan", "discover", _PURE + (Mode.OBSERVE,), ("scan",), True),
    Capability("scan", "inventory-preview", _PURE, (), False, required_inputs=("inventory", "fragment")),
    Capability("scan", "save", _PURE + (Mode.OUTPUT,), ("save",), False),
    Capability("inventory", "validate", _PURE, (), False, required_inputs=("inventory",)),
    Capability("inventory", "export", _PURE + (Mode.OUTPUT,), ("export",), False, required_inputs=("inventory",)),
    Capability("inventory", "refresh", _PURE + (Mode.OBSERVE,), ("refresh",), False, required_inputs=("inventory",)),
    Capability("vault", "preflight", _PURE, (), False),
    Capability("vault", "resolve-for-run", _PURE + (Mode.OBSERVE,), ("resolve-for-run",), False),
    Capability("config", "collect", _PURE + (Mode.OBSERVE,), ("collect",), True),
    Capability("config", "backup", _PURE + (Mode.OBSERVE, Mode.OUTPUT), ("collect", "backup"), True),
    Capability("config", "plan", _PURE, (), False, True, ("intent",)),
    Capability("config", "apply", _PURE + (Mode.APPLY,), ("apply",), True, True, ("intent",)),
    Capability("config", "rollback", _PURE + (Mode.ROLLBACK,), ("rollback",), True, True, ("intent",)),
    Capability("health", "gather", _PURE + (Mode.OBSERVE,), ("gather",), True),
    Capability("health", "evaluate", _PURE, (), False, True),
    Capability("compare", "compare", _PURE, (), False, required_inputs=("before", "after")),
    Capability("compare", "remediation-preview", _PURE, (), False, required_inputs=("findings",)),
    Capability("compare", "generate", _PURE + (Mode.OUTPUT,), ("save",), False, required_inputs=("findings",)),
    Capability("report", "aggregate", _PURE, (), False, required_inputs=("outcomes",)),
    Capability("report", "render", _PURE + (Mode.OUTPUT,), ("render",), False, required_inputs=("outcomes",)),
)


def capability(operation: str) -> Capability:
    """Resolve a fixed public identifier without callback/command dispatch."""
    text(operation)
    for item in CAPABILITIES:
        if item.id == operation:
            return item
    raise ContractError()


@dataclass(frozen=True)
class Scope:
    """Ordered selection and explicit network exclusions, never authentication."""

    target_ids: tuple[str, ...]
    exclusions: tuple[str, ...] = ()
    limit: int = DEFAULT_TARGET_LIMIT

    def __post_init__(self) -> None:
        """Validate complete selection and exclusions without clipping."""
        unique(self.target_ids)
        unique(self.exclusions)
        counter(self.limit, positive=True)
        if self.limit > MAX_TARGET_LIMIT or len(self.target_ids) > self.limit:
            raise ContractError()
        for exclusion in self.exclusions:
            try:
                ipaddress.ip_network(exclusion, strict=False)
            except ValueError:
                raise ContractError() from None


@dataclass(frozen=True)
class Context:
    """Selected context identities; no field asserts a qualified route."""

    controller_id: str
    route_digest: str
    source_id: str
    mapping_digest: str
    policy_identity: PolicyIdentity
    registry_digest: str
    assets_digest: str

    def __post_init__(self) -> None:
        """Validate all immutable selected context identities."""
        text(self.controller_id)
        text(self.source_id)
        for value in (self.route_digest, self.mapping_digest, self.registry_digest, self.assets_digest):
            sha256(value)
        try:
            validate_identity(self.policy_identity)
        except ValueError:
            raise ContractError() from None


@dataclass(frozen=True)
class InputRef:
    """An explicitly selected nonsecret source; ref is not a loader URL."""

    kind: str
    ref: str
    digest: str

    def __post_init__(self) -> None:
        """Reject unknown kinds, URL loaders and malformed content digests."""
        if self.kind not in (
            "inventory", "fragment", "before", "after", "findings", "outcomes",
            "observations", "intent", "readiness",
        ):
            raise ContractError()
        text(self.ref)
        if "://" in self.ref:
            raise ContractError()
        sha256(self.digest)


@dataclass(frozen=True)
class OutputIntent:
    """Planned destinations and explicit effects, not opened paths."""

    kinds: tuple[str, ...] = ()
    root_ref: str | None = None
    overwrite: str = "reject"
    retention: bool = False
    git: bool = False

    def __post_init__(self) -> None:
        """Validate output kinds and independently selected publication effects."""
        unique(self.kinds)
        if any(kind not in ("json", "yaml", "text", "html", "pdf") for kind in self.kinds):
            raise ContractError()
        if self.root_ref is not None:
            text(self.root_ref)
            if "://" in self.root_ref:
                raise ContractError()
        if self.overwrite not in ("reject", "replace"):
            raise ContractError()
        if type(self.retention) is not bool or type(self.git) is not bool:
            raise ContractError()
        if (len(self.kinds) != 0 or self.retention or self.git) and self.root_ref is None:
            raise ContractError()


@dataclass(frozen=True)
class OperationRequest:
    """Strict schema-1 request; no consent/secret/effect extension bag."""

    operation_id: str
    operation: str
    mode: Mode
    scope: Scope
    context: Context
    inputs: tuple[InputRef, ...] = ()
    plan_digest: str | None = None
    output_intent: OutputIntent = OutputIntent()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Validate the closed public request before any adapter is called."""
        uuid_text(self.operation_id)
        item = capability(self.operation)
        if type(self.mode) is not Mode or self.mode not in item.modes:
            raise ContractError()
        if self.schema_version != SCHEMA_VERSION:
            raise ContractError()
        if type(self.scope) is not Scope or type(self.context) is not Context:
            raise ContractError()
        if type(self.output_intent) is not OutputIntent:
            raise ContractError()
        if item.network and len(self.scope.target_ids) == 0:
            raise ContractError()
        if type(self.inputs) is not tuple or any(type(ref) is not InputRef for ref in self.inputs):
            raise ContractError()
        if len({(ref.kind, ref.ref) for ref in self.inputs}) != len(self.inputs):
            raise ContractError()
        if self.plan_digest is not None:
            sha256(self.plan_digest)

    @classmethod
    def from_json(cls, data: bytes) -> OperationRequest:
        """Decode a closed request before dispatch (including nested keys)."""
        value = decode_json(data)
        _closed(value, {item.name for item in fields(cls)})
        try:
            scope = _mapping(value["scope"])
            context = _mapping(value["context"])
            output = _mapping(value["output_intent"])
            _closed(scope, {"target_ids", "exclusions", "limit"})
            _closed(context, {item.name for item in fields(Context)})
            _closed(output, {item.name for item in fields(OutputIntent)})
            identity = _mapping(context["policy_identity"])
            _closed(identity, {item.name for item in fields(PolicyIdentity)})
            refs = value["inputs"]
            if type(refs) is not tuple or not isinstance(refs, tuple):
                raise ContractError()
            loaded_refs: list[InputRef] = []
            for ref in refs:
                fields_ref = _mapping(ref)
                _closed(fields_ref, {"kind", "ref", "digest"})
                loaded_refs.append(InputRef(
                    text(fields_ref["kind"]), text(fields_ref["ref"]), sha256(fields_ref["digest"]),
                ))
            manifest = unique(identity["rule_manifest"])
            parsed_identity = PolicyIdentity(
                canonical_revision=text(identity["canonical_revision"]),
                source_sha256=sha256(identity["source_sha256"]),
                contracts_sha256=sha256(identity["contracts_sha256"]),
                bundle_sha256=sha256(identity["bundle_sha256"]),
                rule_manifest=manifest,
                reducer_version=text(identity["reducer_version"]),
                profile=text(identity["profile"]),
                numeric_profile=text(identity["numeric_profile"]),
                schema=text(identity["schema"]),
            )
            root_ref = output["root_ref"]
            if type(output["retention"]) is not bool or type(output["git"]) is not bool:
                raise ContractError()
            retention = output["retention"]
            git = output["git"]
            assert isinstance(retention, bool) and isinstance(git, bool)
            return cls(
                operation_id=text(value["operation_id"]),
                operation=text(value["operation"]),
                mode=Mode(text(value["mode"])),
                scope=Scope(
                    unique(scope["target_ids"]), unique(scope["exclusions"]),
                    counter(scope["limit"], positive=True),
                ),
                context=Context(
                    controller_id=text(context["controller_id"]),
                    route_digest=sha256(context["route_digest"]),
                    source_id=text(context["source_id"]),
                    mapping_digest=sha256(context["mapping_digest"]),
                    policy_identity=parsed_identity,
                    registry_digest=sha256(context["registry_digest"]),
                    assets_digest=sha256(context["assets_digest"]),
                ),
                inputs=tuple(loaded_refs),
                plan_digest=None if value["plan_digest"] is None else sha256(value["plan_digest"]),
                output_intent=OutputIntent(
                    unique(output["kinds"]), None if root_ref is None else text(root_ref),
                    text(output["overwrite"]), retention, git,
                ),
                schema_version=text(value["schema_version"]),
            )
        except (ValueError, TypeError, KeyError):
            raise ContractError() from None


def _mapping(value: object) -> FrozenObject:
    if type(value) is not FrozenObject or not isinstance(value, FrozenObject):
        raise ContractError()
    return value


def _closed(value: FrozenObject, names: set[str]) -> None:
    if set(value) != names:
        raise ContractError()


@dataclass(frozen=True)
class Observation:
    """Nonsecret provenance supplied at hydration, not execution freshness."""

    observation_id: str
    target_id: str
    context_digest: str
    route_digest: str
    controller_id: str
    source: InputRef
    content_digest: str
    observed_at: str
    age_ms: float

    def __post_init__(self) -> None:
        """Validate provenance without establishing execution freshness."""
        text(self.observation_id)
        text(self.target_id)
        text(self.controller_id)
        for value in (self.context_digest, self.route_digest, self.content_digest):
            sha256(value)
        if type(self.source) is not InputRef:
            raise ContractError()
        try:
            timestamp = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
            offset = timestamp.utcoffset()
            if offset is None or offset.total_seconds() != 0:
                raise ContractError()
        except (ValueError, TypeError, AttributeError):
            raise ContractError() from None
        finite(self.age_ms)


@dataclass(frozen=True)
class LoadedInput:
    """Exact immutable bytes with parser identity, no implicit handle."""

    source: InputRef
    format: str
    content: bytes = field(repr=False)
    parser_revision: str
    vendor_revision: str

    def __post_init__(self) -> None:
        """Validate immutable byte ownership and explicit parser identities."""
        if type(self.source) is not InputRef or self.format not in ("json", "yaml", "text"):
            raise ContractError(INPUT_BINDING_INVALID)
        if type(self.content) is not bytes or len(self.content) > MAX_CONTENT_BYTES:
            raise ContractError(INPUT_BINDING_INVALID)
        if self.format == "text":
            try:
                nonsecret_text(self.content.decode("utf-8"))
            except (ValueError, UnicodeError):
                raise ContractError(INPUT_BINDING_INVALID) from None
        text(self.parser_revision)
        text(self.vendor_revision)


@dataclass(frozen=True)
class LoadedInputContext:
    """Frozen one-to-one hydration binding, never a persisted credential channel."""

    request_digest: str
    context_digest: str
    contents: tuple[LoadedInput, ...]
    observations: tuple[Observation, ...]
    binding_digest: str
    schema_version: str = SCHEMA_VERSION
    settings: SettingsSnapshot = field(default_factory=_settings_default)

    def __post_init__(self) -> None:
        """Validate immutable container shape; preview independently rebinds bytes."""
        for value in (self.request_digest, self.context_digest, self.binding_digest):
            sha256(value)
        from .settings import SettingsSnapshot

        if type(self.settings) is not SettingsSnapshot:
            raise ContractError(INPUT_BINDING_INVALID)
        self.settings.__post_init__()
        if self.schema_version != SCHEMA_VERSION:
            raise ContractError(INPUT_BINDING_INVALID)
        for items, expected in ((self.contents, LoadedInput), (self.observations, Observation)):
            if type(items) is not tuple or any(type(item) is not expected for item in items):
                raise ContractError(INPUT_BINDING_INVALID)


@dataclass(frozen=True)
class InputSource:
    """Explicit immutable bytes or a caller-checked read-only descriptor.

    The caller owns descriptor lifetime and performs path/ownership/no-follow
    checks. Hydration never opens a ref, takes a path, or closes the descriptor.
    """

    source: InputRef
    format: str
    content: bytes | BinaryIO = field(repr=False)
    parser_revision: str
    vendor_revision: str
    observations: tuple[Observation, ...] = ()


@dataclass(frozen=True)
class SafeError:
    """Structured safe failure with guidance and no raw external diagnostic."""

    category: ErrorCategory
    reason: ReasonCode
    stage: Stage
    target_id: str | None = None
    step_id: str | None = None
    retryable: bool = False
    detail: str = ""
    next_action: str = "Inspect the selected plan and correct the named precondition."

    def __post_init__(self) -> None:
        """Validate the safe error vocabulary and reference fields."""
        if (
            type(self.category) is not ErrorCategory or type(self.reason) is not ReasonCode
            or type(self.stage) is not Stage or type(self.retryable) is not bool
        ):
            raise ContractError()
        for value in (self.target_id, self.step_id):
            if value is not None:
                text(value)
        text(self.detail, empty=True)
        text(self.next_action)


@dataclass(frozen=True)
class Finding:
    """A policy reading independent from transport/connectivity success."""

    check: str
    category: str
    severity: str
    result: str
    reading: Json = None
    threshold: Json = None
    expected: Json = None
    vendor: str = "unknown"
    parser: str = "unknown"
    raw_source_ref: str | None = None

    def __post_init__(self) -> None:
        """Keep missing/error readings distinct from healthy zero."""
        for item in (self.check, self.category, self.vendor, self.parser):
            text(item)
        if self.severity not in ("info", "warning", "error", "critical"):
            raise ContractError()
        if self.result not in ("pass", "alert", "unknown", "error"):
            raise ContractError()
        for name in ("reading", "threshold", "expected"):
            object.__setattr__(self, name, public_value(getattr(self, name)))
        if self.raw_source_ref is not None:
            text(self.raw_source_ref)


@dataclass(frozen=True)
class CleanupOutcome:
    """Secondary teardown status; never erases primary or remote uncertainty."""

    status: str = "not-requested"
    remaining_refs: tuple[str, ...] = ()
    errors: tuple[SafeError, ...] = ()

    def __post_init__(self) -> None:
        """Reject cleanup success while resources or errors remain."""
        if self.status not in ("succeeded", "failed", "not-requested"):
            raise ContractError()
        unique(self.remaining_refs)
        if type(self.errors) is not tuple or any(type(error) is not SafeError for error in self.errors):
            raise ContractError()
        if self.status != "failed" and (len(self.remaining_refs) != 0 or len(self.errors) != 0):
            raise ContractError()


@dataclass(frozen=True)
class StepOutcome:
    """Complete selected-step coverage with compatible ordered native payload."""

    step_id: str
    status: OutcomeStatus
    attempted: bool
    unapplied_effects: tuple[str, ...] = ()
    native_payload: FrozenObject = FrozenObject()
    changed: bool = False
    remote_state: str = "unchanged"
    findings: tuple[Finding, ...] = ()
    errors: tuple[SafeError, ...] = ()
    selected: bool = True

    def __post_init__(self) -> None:
        """Validate complete selected work and detach native containers."""
        text(self.step_id)
        if type(self.status) is not OutcomeStatus or self.status == OutcomeStatus.PARTIAL:
            raise ContractError()
        if any(type(value) is not bool for value in (self.attempted, self.changed, self.selected)):
            raise ContractError()
        if self.remote_state not in (
            "unchanged", "committed", "confirmed", "rolled-back", "failed", "uncertain",
        ):
            raise ContractError()
        unique(self.unapplied_effects)
        if self.selected and self.status == OutcomeStatus.SUCCEEDED and (
            not self.attempted or len(self.unapplied_effects) != 0
        ):
            raise ContractError()
        object.__setattr__(self, "native_payload", public_object(self.native_payload))
        if type(self.findings) is not tuple or any(type(item) is not Finding for item in self.findings):
            raise ContractError()
        if type(self.errors) is not tuple or any(type(item) is not SafeError for item in self.errors):
            raise ContractError()


@dataclass(frozen=True)
class TargetOutcome:
    """Target disposition with the same lossless step/native result contract."""

    target_id: str
    status: OutcomeStatus
    attempted: bool
    unapplied_effects: tuple[str, ...] = ()
    native_payload: FrozenObject = FrozenObject()
    changed: bool = False
    remote_state: str = "unchanged"
    findings: tuple[Finding, ...] = ()
    errors: tuple[SafeError, ...] = ()
    selected: bool = True

    def __post_init__(self) -> None:
        """Apply the shared selected-work invariants to a target identity."""
        StepOutcome(
            self.target_id, self.status, self.attempted, self.unapplied_effects,
            self.native_payload, self.changed, self.remote_state, self.findings,
            self.errors, self.selected,
        )
        object.__setattr__(self, "native_payload", public_object(self.native_payload))


@dataclass(frozen=True)
class ReadinessProjection:
    """Independent tiers: absent consuming-context proof is blocked, not ready."""

    native: str = "blocked"
    companion: str = "blocked"
    enhanced: str = "not-requested"
    errors: tuple[SafeError, ...] = ()

    def __post_init__(self) -> None:
        """Validate independent readiness tiers without coercion."""
        for value in (self.native, self.companion, self.enhanced):
            if value not in ("ready", "blocked", "unsupported", "not-requested"):
                raise ContractError()
        if type(self.errors) is not tuple or any(type(item) is not SafeError for item in self.errors):
            raise ContractError()


@dataclass(frozen=True)
class PlannedEffect:
    """An ordered would-effect occurrence; never an executable or permit."""

    occurrence_id: str
    ordinal: int
    kind: str
    target_id: str
    step_id: str
    destination_ref: str | None = None

    def __post_init__(self) -> None:
        """Validate occurrence identity and exact ordinal."""
        counter(self.ordinal)
        if self.kind not in (
            "scan", "save", "export", "refresh", "resolve-for-run", "gather", "collect",
            "backup", "apply", "rollback", "render", "retention", "git",
        ):
            raise ContractError()
        for value in (self.occurrence_id, self.kind, self.target_id, self.step_id):
            text(value)
        if self.destination_ref is not None:
            text(self.destination_ref)


@dataclass(frozen=True)
class CapabilityCatalog:
    """Complete declarative catalog, explicitly distinct from dependency registry."""

    capabilities: tuple[Capability, ...] = CAPABILITIES
    schema_version: str = SCHEMA_VERSION
    qualification: str = "unqualified"
    next_action: str = "Obtain consuming-context dependency and controller qualification before execution."

    def __post_init__(self) -> None:
        """Keep declarations distinct from qualification and reject catalog drift."""
        if (
            self.schema_version != SCHEMA_VERSION or self.capabilities != CAPABILITIES
            or self.qualification != "unqualified"
        ):
            raise ContractError()
        text(self.next_action)


@dataclass(frozen=True)
class OperationPlan:
    """Pure bound plan with unmet conditions and inspectable nonsecret projections."""

    operation_id: str
    operation: str
    requested_mode: Mode
    targets: tuple[str, ...]
    routes: tuple[FrozenObject, ...]
    context: Context
    request_digest: str
    input_binding_digest: str
    policy_digest: str
    reducer_version: str
    effects: tuple[PlannedEffect, ...]
    observations: tuple[Observation, ...]
    preconditions: tuple[SafeError, ...]
    native_payload: FrozenObject
    output_intent: OutputIntent
    concurrency: int
    deadline_ms: int
    recovery_scope: tuple[str, ...]
    plan_digest: str
    schema_version: str = SCHEMA_VERSION
    settings: SettingsSnapshot = field(default_factory=_settings_default)

    def __post_init__(self) -> None:
        """Validate the immutable planning result, never grant executable authority."""
        uuid_text(self.operation_id)
        from .settings import SettingsSnapshot

        if type(self.settings) is not SettingsSnapshot:
            raise ContractError()
        self.settings.__post_init__()
        capability(self.operation)
        unique(self.targets)
        if (
            self.schema_version != SCHEMA_VERSION or type(self.requested_mode) is not Mode
            or type(self.context) is not Context or type(self.output_intent) is not OutputIntent
        ):
            raise ContractError()
        for value in (self.request_digest, self.input_binding_digest, self.policy_digest, self.plan_digest):
            sha256(value)
        if (
            self.policy_digest != self.context.policy_identity.bundle_sha256
            or self.reducer_version != self.context.policy_identity.reducer_version
        ):
            raise ContractError()
        counter(self.concurrency, positive=True)
        counter(self.deadline_ms, positive=True)
        unique(self.recovery_scope)
        for values, expected in (
            (self.effects, PlannedEffect), (self.observations, Observation),
            (self.preconditions, SafeError), (self.routes, FrozenObject),
        ):
            if type(values) is not tuple or any(type(value) is not expected for value in values):
                raise ContractError()
        if tuple(route.get("target_id") for route in self.routes) != self.targets:
            raise ContractError()
        unique(tuple(effect.occurrence_id for effect in self.effects))
        if tuple(effect.ordinal for effect in self.effects) != tuple(range(len(self.effects))):
            raise ContractError()
        object.__setattr__(self, "native_payload", public_object(self.native_payload))


@dataclass(frozen=True)
class OperationOutcome:
    """Versioned aggregate with every target, secondary error and safe provenance."""

    operation_id: str
    requested_mode: Mode
    executed_mode: Mode | None
    readiness: ReadinessProjection
    targets: tuple[TargetOutcome, ...]
    steps: tuple[StepOutcome, ...]
    status: OutcomeStatus
    changed: bool
    findings: tuple[Finding, ...]
    artifacts: tuple[FrozenObject, ...]
    errors: tuple[SafeError, ...]
    cleanup: CleanupOutcome
    provenance: FrozenObject
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Validate response DTOs, including direct Python construction."""
        uuid_text(self.operation_id)
        if (
            self.schema_version != SCHEMA_VERSION
            or type(self.requested_mode) is not Mode
            or (self.executed_mode is not None and type(self.executed_mode) is not Mode)
            or type(self.status) is not OutcomeStatus or type(self.changed) is not bool
            or type(self.readiness) is not ReadinessProjection
            or type(self.cleanup) is not CleanupOutcome
        ):
            raise ContractError()
        for values, expected in (
            (self.targets, TargetOutcome), (self.steps, StepOutcome), (self.findings, Finding),
            (self.errors, SafeError), (self.artifacts, FrozenObject),
        ):
            if type(values) is not tuple or any(type(value) is not expected for value in values):
                raise ContractError()
        unique(tuple(target.target_id for target in self.targets))
        unique(tuple(step.step_id for step in self.steps))
        object.__setattr__(self, "provenance", public_object(self.provenance))
        object.__setattr__(self, "artifacts", tuple(public_object(item) for item in self.artifacts))
        selected = tuple(item for item in self.targets + self.steps if item.selected)
        if self.status == OutcomeStatus.SUCCEEDED and (
            any(item.status != OutcomeStatus.SUCCEEDED or not item.attempted
                   or len(item.unapplied_effects) != 0
                   or item.remote_state in ("failed", "uncertain") for item in selected)
            or any(f.result != "pass" for f in self.findings
                   + tuple(f for item in selected for f in item.findings))
            or any(len(item.errors) != 0 for item in selected)
            or len(self.errors) != 0 or self.cleanup.status == "failed"
        ):
            raise ContractError()

    @property
    def exit_code(self) -> int:
        """Map exact public precedence; invalid input is not an execution failure."""
        if self.status == OutcomeStatus.PARTIAL:
            return 4
        if self.status == OutcomeStatus.FAILED:
            return 2 if any(e.category == ErrorCategory.INVALID_INPUT for e in self.errors) else 5
        return {
            OutcomeStatus.SUCCEEDED: 0, OutcomeStatus.NOT_REQUESTED: 0,
            OutcomeStatus.BLOCKED: 3, OutcomeStatus.UNSUPPORTED: 6, OutcomeStatus.CANCELLED: 130,
        }[self.status]

    @classmethod
    def from_json(cls, data: bytes) -> OperationOutcome:
        """Read a v1 response while ignoring optional additive response fields."""
        try:
            value = decode_json(data)
            readiness = _mapping(value["readiness"])
            cleanup = _mapping(value["cleanup"])
            executed_mode = value["executed_mode"]
            return cls(
                operation_id=uuid_text(value["operation_id"]),
                requested_mode=Mode(text(value["requested_mode"])),
                executed_mode=None if executed_mode is None else Mode(text(executed_mode)),
                readiness=ReadinessProjection(
                    text(readiness["native"]), text(readiness["companion"]),
                    text(readiness["enhanced"]),
                    tuple(_error_from_wire(item) for item in _sequence(readiness["errors"])),
                ),
                targets=tuple(_target_from_wire(item) for item in _sequence(value["targets"])),
                steps=tuple(_step_from_wire(item) for item in _sequence(value["steps"])),
                status=OutcomeStatus(text(value["status"])), changed=_boolean(value["changed"]),
                findings=tuple(_finding_from_wire(item) for item in _sequence(value["findings"])),
                artifacts=tuple(_mapping(item) for item in _sequence(value["artifacts"])),
                errors=tuple(_error_from_wire(item) for item in _sequence(value["errors"])),
                cleanup=CleanupOutcome(
                    text(cleanup["status"]), unique(cleanup["remaining_refs"]),
                    tuple(_error_from_wire(item) for item in _sequence(cleanup["errors"])),
                ),
                provenance=_mapping(value["provenance"]),
                schema_version=text(value["schema_version"]),
            )
        except (ValueError, KeyError, TypeError):
            raise ContractError() from None


def _sequence(value: Json) -> tuple[Json, ...]:
    if type(value) is not tuple or not isinstance(value, tuple):
        raise ContractError()
    return value


def _boolean(value: Json) -> bool:
    if type(value) is not bool or not isinstance(value, bool):
        raise ContractError()
    return value


def _nullable_text(value: Json) -> str | None:
    return None if value is None else text(value)


def _error_from_wire(value: Json) -> SafeError:
    item = _mapping(value)
    return SafeError(
        ErrorCategory(text(item["category"])), ReasonCode(text(item["reason"])),
        Stage(text(item["stage"])), _nullable_text(item["target_id"]),
        _nullable_text(item["step_id"]), _boolean(item["retryable"]),
        text(item["detail"], empty=True), text(item["next_action"]),
    )


def _finding_from_wire(value: Json) -> Finding:
    item = _mapping(value)
    return Finding(
        text(item["check"]), text(item["category"]), text(item["severity"]),
        text(item["result"]), item["reading"], item["threshold"], item["expected"],
        text(item["vendor"]), text(item["parser"]), _nullable_text(item["raw_source_ref"]),
    )


def _step_from_wire(value: Json) -> StepOutcome:
    item = _mapping(value)
    return StepOutcome(
        text(item["step_id"]), OutcomeStatus(text(item["status"])), _boolean(item["attempted"]),
        unique(item["unapplied_effects"]), _mapping(item["native_payload"]),
        _boolean(item["changed"]), text(item["remote_state"]),
        tuple(_finding_from_wire(finding) for finding in _sequence(item["findings"])),
        tuple(_error_from_wire(error) for error in _sequence(item["errors"])),
        _boolean(item["selected"]),
    )


def _target_from_wire(value: Json) -> TargetOutcome:
    item = _mapping(value)
    return TargetOutcome(
        text(item["target_id"]), OutcomeStatus(text(item["status"])), _boolean(item["attempted"]),
        unique(item["unapplied_effects"]), _mapping(item["native_payload"]),
        _boolean(item["changed"]), text(item["remote_state"]),
        tuple(_finding_from_wire(finding) for finding in _sequence(item["findings"])),
        tuple(_error_from_wire(error) for error in _sequence(item["errors"])),
        _boolean(item["selected"]),
    )


def aggregate_outcome(
    request: OperationRequest,
    targets: tuple[TargetOutcome, ...],
    steps: tuple[StepOutcome, ...] = (),
    *,
    executed_mode: Mode | None = None,
    readiness: ReadinessProjection = ReadinessProjection(),
    findings: tuple[Finding, ...] = (),
    errors: tuple[SafeError, ...] = (),
    cleanup: CleanupOutcome = CleanupOutcome(),
    artifacts: tuple[FrozenObject, ...] = (),
    provenance: FrozenObject = FrozenObject(),
) -> OperationOutcome:
    """Apply selected-work/health/cleanup precedence without dropping any target."""
    if type(request) is not OperationRequest:
        raise ContractError()
    if type(cleanup) is not CleanupOutcome or type(readiness) is not ReadinessProjection:
        raise ContractError()
    for values, expected in ((errors, SafeError), (findings, Finding), (artifacts, FrozenObject)):
        if type(values) is not tuple or any(type(value) is not expected for value in values):
            raise ContractError()
    if (
        type(targets) is not tuple or type(steps) is not tuple
        or any(type(target) is not TargetOutcome or not target.selected for target in targets)
        or any(type(step) is not StepOutcome for step in steps)
        or tuple(target.target_id for target in targets) != request.scope.target_ids
    ):
        raise ContractError()
    unique(tuple(step.step_id for step in steps))
    selected = tuple(item for item in targets + steps if item.selected)
    for item in selected:
        item.__post_init__()
    all_findings = findings + tuple(f for item in selected for f in item.findings)
    all_errors = errors + tuple(e for item in selected for e in item.errors)
    statuses = tuple(item.status for item in selected)
    health_failed = any(f.result != "pass" for f in all_findings)
    unsuccessful = any(s != OutcomeStatus.SUCCEEDED for s in statuses)
    failed = (
        OutcomeStatus.FAILED in statuses or health_failed or cleanup.status == "failed"
        or len(cleanup.errors) != 0 or any(e.category in (
            ErrorCategory.INVALID_INPUT, ErrorCategory.EXECUTION, ErrorCategory.POLICY,
            ErrorCategory.RENDERING, ErrorCategory.CLEANUP,
        ) for e in all_errors)
        or any(item.remote_state in ("failed", "uncertain") for item in selected)
        or (len(all_errors) != 0 and all(status == OutcomeStatus.SUCCEEDED for status in statuses))
    )
    if OutcomeStatus.SUCCEEDED in statuses and unsuccessful:
        status = OutcomeStatus.PARTIAL
    elif failed:
        status = OutcomeStatus.FAILED
    elif OutcomeStatus.CANCELLED in statuses:
        status = OutcomeStatus.CANCELLED
    elif OutcomeStatus.UNSUPPORTED in statuses:
        status = OutcomeStatus.UNSUPPORTED
    elif (
        OutcomeStatus.BLOCKED in statuses or OutcomeStatus.NOT_REQUESTED in statuses
        or len(selected) == 0
    ):
        status = OutcomeStatus.BLOCKED
    else:
        status = OutcomeStatus.SUCCEEDED
    return OperationOutcome(
        request.operation_id, request.mode, executed_mode, readiness, targets, steps, status,
        any(item.changed for item in selected), all_findings, artifacts, all_errors, cleanup,
        public_object(provenance),
    )


class _PrivateValue(ABC):
    """Nominal host-only seam; C01 does not issue authority-bearing values."""

    __slots__ = ()

    @property
    @abstractmethod
    def _host_owned(self) -> bool:
        """Concrete A01 broker values must be created only by the host."""
        ...

    def __repr__(self) -> str:
        return "<private>"

    def __reduce__(self) -> NoReturn:
        """Reject persistence of host-private values."""
        raise TypeError("private-value")


class Authorization(_PrivateValue):
    """Opaque one-use operational grant, implemented by the A01 host broker."""


class ConsentReceipt(_PrivateValue):
    """Opaque trusted adapter receipt, never an asserted public permission bit."""


class AdmissionSession(_PrivateValue):
    """Opaque consumed-grant session retaining the original deadline."""


class EffectPermit(_PrivateValue):
    """Opaque permit for exactly one bound effect occurrence."""


class ScopedCredentials(_PrivateValue):
    """Opaque private target/task credentials; resolved only under execution consent."""


@dataclass(frozen=True)
class PlanBinding:
    """Exact operational projection used by the later host admission boundary."""

    operation_id: str
    plan_digest: str
    policy_digest: str
    context_digest: str
    controller_digest: str
    route_digest: str
    input_digest: str
    observation_digest: str
    root_ref: str
    generation: int
    recovery_scope: tuple[str, ...]

    def __post_init__(self) -> None:
        """Revalidate all host-binding identities and exact generation."""
        uuid_text(self.operation_id)
        for value in (
            self.plan_digest, self.policy_digest, self.context_digest, self.controller_digest,
            self.route_digest, self.input_digest, self.observation_digest,
        ):
            sha256(value)
        text(self.root_ref)
        counter(self.generation)
        unique(self.recovery_scope)


@dataclass(frozen=True)
class EffectBinding:
    """Occurrence-specific binding; repeated action names are never authority."""

    plan: PlanBinding
    event_id: str
    expected_revision: int
    occurrence_id: str
    target_id: str
    step_id: str
    recovery_scope: tuple[str, ...]

    def __post_init__(self) -> None:
        """Reject malformed or widened effect binding before host admission."""
        if type(self.plan) is not PlanBinding:
            raise ContractError()
        self.plan.__post_init__()
        uuid_text(self.event_id)
        counter(self.expected_revision)
        for value in (self.occurrence_id, self.target_id, self.step_id):
            text(value)
        unique(self.recovery_scope)
        if any(value not in self.plan.recovery_scope for value in self.recovery_scope):
            raise ContractError()


@dataclass(frozen=True)
class CancelReceipt:
    """Safe cancellation acknowledgement, not a new effect or renewed grant."""

    accepted: bool
    reason: str
    received_at: float

    def __post_init__(self) -> None:
        """Validate a finite safe cancellation acknowledgement."""
        if type(self.accepted) is not bool:
            raise ContractError()
        text(self.reason)
        finite(self.received_at)


class AuthorizationBroker(Protocol):
    """Exact operational broker seam; no implementation or authorize alias."""

    def issue(
        self, plan: OperationPlan, consent: ConsentReceipt,
        decision: DecisionResult, now: float,
    ) -> Authorization:
        """Issue only against a fresh exact trusted consent decision."""
        ...

    def consume(self, authorization: Authorization, binding: PlanBinding, now: float) -> AdmissionSession:
        """Atomically consume exactly once."""
        ...

    def permit(self, session: AdmissionSession, binding: EffectBinding, now: float) -> EffectPermit:
        """Reserve one remaining occurrence under the host lock."""
        ...

    def revoke(self, operation_id: str) -> None:
        """Revoke without needing a new numeric revision."""
        ...


class ClockPort(Protocol):
    """Clock reads belong to explicit hydration/execution, never preview."""

    def monotonic(self) -> float:
        """Return finite nonnegative monotonic seconds."""
        ...

    def utc_now(self) -> datetime:
        """Return display/provenance time, never expiry authority."""
        ...


class CancelPort(Protocol):
    """Host cancellation independent of admission-revision exhaustion."""

    def is_cancelled(self) -> bool:
        """Return current cancellation state."""
        ...

    def wait(self, timeout: float) -> bool:
        """Wait within a finite caller-supplied bound."""
        ...


class DependencyPort(Protocol):
    """Consuming-context readiness probe seam, never invoked from pure planning."""

    def verify(self, scope: InstallScope, context: InstallContext) -> ReadinessReport:
        """Return actual verified consuming-context readiness."""
        ...


class ControllerPort(Protocol):
    """Effectful controller seam reserved for A02's admitted dispatch."""

    def verify(self, context: ControllerContext) -> ControllerReadiness:
        """Verify the exact consuming controller context."""
        ...

    def run(
        self, request: ControllerRequest, credentials: ScopedCredentials, cancel: CancelPort,
    ) -> OperationOutcome:
        """Run with private credentials and the host-authoritative dispatch bridge."""
        ...


class NativeWorkflowPort(Protocol):
    """Explicit native seam; companion planning never silently switches engines."""

    def preview(self, request: OperationRequest, loaded: LoadedInputContext) -> OperationPlan:
        """Reuse only supplied validated bytes; never reopen references."""
        ...

    def run(
        self, plan: OperationPlan, credentials: ScopedCredentials, cancel: CancelPort,
    ) -> OperationOutcome:
        """Preserve native result payloads under admitted execution."""
        ...


class ArtifactPort(Protocol):
    """Protected artifact publication seam, not a preview file writer."""

    def publish(
        self, intent: OutputIntent, content: bytes, binding: ArtifactBinding,
    ) -> ArtifactDescriptor:
        """Return a verified owned descriptor after admitted publication."""
        ...


class EventPort(Protocol):
    """Safe event sink; pure methods return diagnostics instead of emitting."""

    def emit(self, event: SafeEvent) -> None:
        """Emit an execution event without private values."""
        ...


@dataclass(frozen=True)
class ControllerContext:
    """Explicit selected context for later consuming-process qualification."""

    context: Context

    def __post_init__(self) -> None:
        """Validate context shape without probing a host."""
        if type(self.context) is not Context:
            raise ContractError()


@dataclass(frozen=True)
class InstallScope:
    """Selected prerequisite scope, not an installer or a readiness assertion."""

    native_capabilities: tuple[str, ...]
    companions: tuple[str, ...]
    enhanced: bool
    full_toolkit: bool = True

    def __post_init__(self) -> None:
        """Validate explicit capability selection without an invented registry."""
        unique(self.native_capabilities)
        unique(self.companions)
        if type(self.enhanced) is not bool or type(self.full_toolkit) is not bool:
            raise ContractError()


@dataclass(frozen=True)
class InstallContext:
    """Selected consuming context passed to the later dependency owner."""

    context: Context

    def __post_init__(self) -> None:
        """Validate selected identity without probing or provisioning."""
        if type(self.context) is not Context:
            raise ContractError()


@dataclass(frozen=True)
class ReadinessReport:
    """Explicit versioned consuming-context evidence from the dependency owner."""

    revision: str
    context: InstallContext
    capabilities: tuple[FrozenObject, ...]
    readiness: ReadinessProjection
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Require complete typed evidence containers, never imply ready by default."""
        text(self.revision)
        if (
            self.schema_version != SCHEMA_VERSION or type(self.context) is not InstallContext
            or type(self.readiness) is not ReadinessProjection or type(self.capabilities) is not tuple
        ):
            raise ContractError()
        object.__setattr__(self, "capabilities", tuple(public_object(item) for item in self.capabilities))


@dataclass(frozen=True)
class ControllerReadiness:
    """Consuming-context evidence, not a platform-range compatibility assertion."""

    context: ControllerContext
    readiness: ReadinessProjection
    evidence_digest: str

    def __post_init__(self) -> None:
        """Bind consuming-context evidence to its explicit projection."""
        if type(self.context) is not ControllerContext or type(self.readiness) is not ReadinessProjection:
            raise ContractError()
        sha256(self.evidence_digest)


@dataclass(frozen=True)
class ControllerRequest:
    """Bound nonsecret operation/plan crossing the controller port."""

    request: OperationRequest
    plan: OperationPlan

    def __post_init__(self) -> None:
        """Reject selected-target/context changes before controller dispatch."""
        if type(self.request) is not OperationRequest or type(self.plan) is not OperationPlan:
            raise ContractError()
        if (
            self.request.operation_id != self.plan.operation_id
            or self.request.operation != self.plan.operation
            or self.request.mode != self.plan.requested_mode
            or self.request.scope.target_ids != self.plan.targets
            or self.request.context != self.plan.context
        ):
            raise ContractError()


@dataclass(frozen=True)
class ArtifactBinding:
    """Publication must be bound to one exact admitted effect occurrence."""

    effect: EffectBinding
    classification: str

    def __post_init__(self) -> None:
        """Require one exact effect and explicit content classification."""
        if type(self.effect) is not EffectBinding or self.classification not in ("public", "sensitive"):
            raise ContractError()


@dataclass(frozen=True)
class ArtifactDescriptor:
    """An explicit protected output descriptor, never an unchecked path."""

    ref: str
    digest: str
    size: int
    media_type: str
    classification: str
    permissions_proof: str
    retention: str
    owning_resource: str
    input_binding: str

    def __post_init__(self) -> None:
        """Validate verified descriptor fields without opening a destination."""
        for value in (self.ref, self.media_type, self.permissions_proof, self.retention, self.owning_resource):
            text(value)
        sha256(self.digest)
        sha256(self.input_binding)
        if type(self.size) is not int or self.size < 0:
            raise ContractError()
        if self.classification not in ("public", "sensitive"):
            raise ContractError()


@dataclass(frozen=True)
class SafeEvent:
    """Safe execution-boundary dimensions; pure plans never emit events."""

    operation_id: str
    step_id: str
    target_id: str
    context_id: str
    mode: Mode
    status: OutcomeStatus
    error_category: ErrorCategory | None
    reason: ReasonCode | None
    retryable: bool
    duration: float

    def __post_init__(self) -> None:
        """Validate safe dimensions and duration before an execution sink sees them."""
        uuid_text(self.operation_id)
        for value in (self.step_id, self.target_id, self.context_id):
            text(value)
        if (
            type(self.mode) is not Mode or type(self.status) is not OutcomeStatus
            or (self.error_category is not None and type(self.error_category) is not ErrorCategory)
            or (self.reason is not None and type(self.reason) is not ReasonCode)
            or type(self.retryable) is not bool
        ):
            raise ContractError()
        finite(self.duration)
