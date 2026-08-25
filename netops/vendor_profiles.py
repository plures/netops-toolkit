"""Canonical vendor profiles for discovery, support reporting, and commands.

The registry keeps device fingerprints, deep-inventory commands, support
coverage, and command variants together.  Callers should use this module
instead of maintaining parallel vendor lists or ``if vendor`` command maps.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from enum import Enum

from netops.templates.arista_eos import EAPI as ARISTA_EAPI
from netops.templates.arista_eos import HEALTH as ARISTA_HEALTH
from netops.templates.arista_eos import SHOW as ARISTA_SHOW
from netops.templates.brocade import HEALTH as BROCADE_HEALTH
from netops.templates.brocade import SHOW as BROCADE_SHOW
from netops.templates.cisco_ios import HEALTH as CISCO_HEALTH
from netops.templates.cisco_ios import SHOW as CISCO_SHOW
from netops.templates.junos import HEALTH as JUNOS_HEALTH
from netops.templates.junos import SHOW as JUNOS_SHOW
from netops.templates.nokia_sros import HEALTH as SROS_HEALTH
from netops.templates.nokia_sros import MD_CLI as SROS_MD_CLI
from netops.templates.nokia_sros import SHOW as SROS_SHOW


class SupportLevel(str, Enum):
    """Declared maturity of a supported feature for one profile."""

    FULL = "full"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Fingerprint:
    """A case-insensitive sysDescr fingerprint with optional enterprise OIDs."""

    all_terms: tuple[str, ...] = ()
    any_terms: tuple[str, ...] = ()
    none_terms: tuple[str, ...] = ()
    oid_prefixes: tuple[str, ...] = ()
    generic: bool = False

    def matches_description(self, description: str) -> bool:
        """Return whether *description* satisfies this fingerprint's text terms."""
        normalized = description.lower()
        return bool(self.all_terms or self.any_terms) and (
            (not self.all_terms or all(term in normalized for term in self.all_terms))
            and (not self.any_terms or any(term in normalized for term in self.any_terms))
            and not any(term in normalized for term in self.none_terms)
        )

    def matches_oid(self, object_id: str) -> bool:
        """Return whether *object_id* belongs to one of this fingerprint's OIDs."""
        normalized = object_id.strip().lstrip(".")
        return any(
            normalized == prefix or normalized.startswith(f"{prefix}.")
            for prefix in self.oid_prefixes
        )


@dataclass(frozen=True)
class CommandVariant:
    """An explicitly gated alternate command dialect.

    A version is necessary but never sufficient for a variant that declares
    required capabilities.  This prevents a version string alone from causing
    a potentially destructive or unsupported CLI dialect change.
    """

    name: str
    collection: str
    commands: Mapping[str, str]
    minimum_version: tuple[int, ...] | None = None
    required_capabilities: frozenset[str] = frozenset()

    def applies_to(self, version: str | None, capabilities: AbstractSet[str]) -> bool:
        """Return whether the observation proves this variant may be selected."""
        if not self.required_capabilities.issubset(capabilities):
            return False
        if self.minimum_version is None:
            return True
        observed = parse_version(version)
        return observed is not None and observed >= self.minimum_version


@dataclass(frozen=True)
class VendorProfile:
    """One Netmiko device type and its maintained support contract."""

    id: str
    display_name: str
    family: str
    family_rank: int
    fingerprints: tuple[Fingerprint, ...]
    deep_commands: Mapping[str, str]
    command_collections: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    support: Mapping[str, SupportLevel] = field(default_factory=dict)
    variants: tuple[CommandVariant, ...] = ()

    def commands_for(
        self,
        collection: str,
        version: str | None = None,
        capabilities: AbstractSet[str] = frozenset(),
    ) -> dict[str, str]:
        """Return commands for a collection, applying only proven variants."""
        commands = self.deep_commands if collection == "deep" else self.command_collections.get(collection, {})
        selected = dict(commands)
        for variant in self.variants:
            if variant.collection == collection and variant.applies_to(version, capabilities):
                selected.update(variant.commands)
        return selected


def parse_version(version: str | None) -> tuple[int, ...] | None:
    """Extract a comparable numeric version without assuming vendor syntax."""
    if not version:
        return None
    numbers = re.findall(r"\d+", version)
    return tuple(int(number) for number in numbers) if numbers else None


_COMMON_DEEP = {"version": "show version", "inventory": "show inventory"}

_PROFILES: tuple[VendorProfile, ...] = (
    VendorProfile(
        id="cisco_ios",
        display_name="Cisco IOS",
        family="cisco",
        family_rank=0,
        fingerprints=(
            Fingerprint(
                all_terms=("cisco ios",),
                none_terms=("ios xe", "ios-xe", "ios xr", "nx-os", "nxos"),
            ),
            Fingerprint(any_terms=("cisco",), oid_prefixes=("1.3.6.1.4.1.9",), generic=True),
        ),
        deep_commands=_COMMON_DEEP,
        command_collections={"show": CISCO_SHOW, "health": CISCO_HEALTH},
        support={"identification": SupportLevel.FULL, "deep_inventory": SupportLevel.FULL},
    ),
    VendorProfile(
        id="cisco_xe",
        display_name="Cisco IOS-XE",
        family="cisco",
        family_rank=1,
        fingerprints=(Fingerprint(any_terms=("ios xe", "ios-xe")),),
        deep_commands=_COMMON_DEEP,
        command_collections={"show": CISCO_SHOW, "health": CISCO_HEALTH},
        support={"identification": SupportLevel.FULL, "deep_inventory": SupportLevel.FULL},
    ),
    VendorProfile(
        id="cisco_xr",
        display_name="Cisco IOS-XR",
        family="cisco",
        family_rank=2,
        fingerprints=(Fingerprint(any_terms=("ios xr",)),),
        deep_commands=_COMMON_DEEP,
        support={"identification": SupportLevel.FULL, "deep_inventory": SupportLevel.FULL},
    ),
    VendorProfile(
        id="cisco_nxos",
        display_name="Cisco NX-OS",
        family="cisco",
        family_rank=3,
        fingerprints=(Fingerprint(any_terms=("nx-os", "nxos")),),
        deep_commands=_COMMON_DEEP,
        support={"identification": SupportLevel.FULL, "deep_inventory": SupportLevel.FULL},
    ),
    VendorProfile(
        id="nokia_sros",
        display_name="Nokia SR-OS",
        family="nokia",
        family_rank=0,
        fingerprints=(
            Fingerprint(any_terms=("timos", "alcatel")),
            Fingerprint(any_terms=("nokia",), oid_prefixes=("1.3.6.1.4.1.6527",), generic=True),
        ),
        deep_commands={
            "version": SROS_SHOW["version"],
            "inventory": SROS_SHOW["chassis_detail"],
            "system_info": SROS_SHOW["system_info"],
            "card": SROS_SHOW["card"],
            "bof": SROS_SHOW["bof"],
        },
        command_collections={"show": SROS_SHOW, "health": SROS_HEALTH},
        support={"identification": SupportLevel.FULL, "deep_inventory": SupportLevel.FULL},
        variants=(
            CommandVariant(
                name="md-cli",
                collection="show",
                commands=SROS_MD_CLI,
                minimum_version=(19, 10),
                required_capabilities=frozenset({"md-cli"}),
            ),
        ),
    ),
    VendorProfile(
        id="nokia_srl",
        display_name="Nokia SR Linux",
        family="nokia",
        family_rank=1,
        fingerprints=(Fingerprint(all_terms=("nokia",), any_terms=("srl", "sr linux")),),
        deep_commands={
            "version": "info from state /system/information",
            "inventory": "info from state /platform/chassis",
        },
        support={"identification": SupportLevel.FULL, "deep_inventory": SupportLevel.FULL},
    ),
    VendorProfile(
        id="juniper_junos",
        display_name="Juniper Junos",
        family="juniper",
        family_rank=0,
        fingerprints=(
            Fingerprint(any_terms=("juniper", "junos"), oid_prefixes=("1.3.6.1.4.1.2636",)),
        ),
        deep_commands={"version": JUNOS_SHOW["version"], "inventory": JUNOS_SHOW["chassis_hardware"]},
        command_collections={"show": JUNOS_SHOW, "health": JUNOS_HEALTH},
        support={"identification": SupportLevel.FULL, "deep_inventory": SupportLevel.FULL},
    ),
    VendorProfile(
        id="arista_eos",
        display_name="Arista EOS",
        family="arista",
        family_rank=0,
        fingerprints=(Fingerprint(any_terms=("arista",), oid_prefixes=("1.3.6.1.4.1.30065",)),),
        deep_commands=_COMMON_DEEP,
        command_collections={"show": ARISTA_SHOW, "health": ARISTA_HEALTH, "eapi": ARISTA_EAPI},
        support={"identification": SupportLevel.FULL, "deep_inventory": SupportLevel.FULL},
    ),
    VendorProfile(
        id="brocade_fastiron",
        display_name="Brocade FastIron",
        family="brocade",
        family_rank=0,
        fingerprints=(
            Fingerprint(any_terms=("foundry", "fastiron", "icx", "ruckus", "commscope", "ironware", "extreme networks", "mlx")),
            Fingerprint(any_terms=("brocade",), oid_prefixes=("1.3.6.1.4.1.1991",), generic=True),
        ),
        deep_commands=_COMMON_DEEP,
        command_collections={"show": BROCADE_SHOW, "health": BROCADE_HEALTH},
        support={"identification": SupportLevel.FULL, "deep_inventory": SupportLevel.FULL},
    ),
    VendorProfile(
        id="brocade_nos",
        display_name="Brocade Network OS",
        family="brocade",
        family_rank=1,
        fingerprints=(
            Fingerprint(any_terms=("brocade network os", "network os"), oid_prefixes=("1.3.6.1.4.1.1588",)),
        ),
        deep_commands=_COMMON_DEEP,
        command_collections={"show": BROCADE_SHOW, "health": BROCADE_HEALTH},
        support={"identification": SupportLevel.FULL, "deep_inventory": SupportLevel.FULL},
    ),
)

PROFILES: Mapping[str, VendorProfile] = {profile.id: profile for profile in _PROFILES}
PROBE_ORDER: tuple[str, ...] = (
    "cisco_ios",
    "cisco_nxos",
    "nokia_sros",
    "juniper_junos",
    "arista_eos",
    "cisco_xe",
    "cisco_xr",
    "nokia_srl",
    "brocade_fastiron",
    "brocade_nos",
)


def identify_vendor(sys_descr: str, sys_obj_id: str = "") -> str:
    """Identify a profile from sysDescr first, then sysObjectID."""
    for profile in _PROFILES:
        if any(
            not fingerprint.generic and fingerprint.matches_description(sys_descr)
            for fingerprint in profile.fingerprints
        ):
            return profile.id
    for profile in _PROFILES:
        if any(
            fingerprint.generic and fingerprint.matches_description(sys_descr)
            for fingerprint in profile.fingerprints
        ):
            return profile.id
    for profile in _PROFILES:
        if any(fingerprint.matches_oid(sys_obj_id) for fingerprint in profile.fingerprints):
            return profile.id
    return "unknown"


def get_profile(vendor: str) -> VendorProfile | None:
    """Return the canonical profile for a Netmiko device type, if known."""
    return PROFILES.get(vendor)


def deep_commands_for(vendor: str) -> dict[str, str]:
    """Return deep-inventory commands, retaining Cisco IOS as the legacy fallback."""
    profile = get_profile(vendor) or PROFILES["cisco_ios"]
    return profile.commands_for("deep")


def family_members(vendor: str) -> list[str]:
    """Return the profile family with *vendor* first, or preserve unknown input."""
    profile = get_profile(vendor)
    if profile is None:
        return [vendor]
    siblings = sorted(
        (candidate for candidate in _PROFILES if candidate.family == profile.family),
        key=lambda candidate: candidate.family_rank,
    )
    return [vendor] + [candidate.id for candidate in siblings if candidate.id != vendor]


def probe_order() -> Sequence[str]:
    """Return the maintained auto-detection probe order."""
    return PROBE_ORDER


def friendly_name(vendor: str) -> str:
    """Return a profile display name without changing legacy unknown behavior."""
    profile = get_profile(vendor)
    return profile.display_name if profile else vendor
