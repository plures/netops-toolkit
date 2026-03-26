"""Vendor-specific remediation templates for playbook generation.

Each :class:`RemediationTemplate` encapsulates the commands needed to:

* **Pre-validate** the device state before remediation
* **Remediate** the failure condition
* **Post-validate** that the remediation succeeded
* **Rollback** (undo) the remediation when possible

Vendor command modules are mapped by the ``VENDOR_COMMAND_MODULE`` and
``VENDOR_CONFIG_MODULE`` dicts so that the generator can pick the correct
Ansible collection for each platform.

Public API::

    from netops.playbooks.templates.remediation import (
        RemediationTemplate,
        REMEDIATION_TEMPLATES,
        VENDOR_COMMAND_MODULE,
        VENDOR_CONFIG_MODULE,
        get_template,
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Vendor → Ansible module mappings
# ---------------------------------------------------------------------------

#: Maps device_type strings to Ansible *read-only* command modules.
VENDOR_COMMAND_MODULE: dict[str, str] = {
    "cisco_ios": "cisco.ios.ios_command",
    "cisco_ios_xe": "cisco.ios.ios_command",
    "cisco_ios_xr": "cisco.iosxr.iosxr_command",
    "cisco_nxos": "cisco.nxos.nxos_command",
    "arista_eos": "arista.eos.eos_command",
    "juniper_junos": "junipernetworks.junos.junos_command",
    "nokia_sros": "community.network.sros_command",
    "paloalto_panos": "paloaltonetworks.panos.panos_op",
    "brocade_fastiron": "community.network.ironware_command",
    "brocade_vdx": "community.network.nos_command",
    # Generic fallback (ansible.netcommon collection)
    "_default": "ansible.netcommon.cli_command",
}

#: Maps device_type strings to Ansible *configuration* modules.
VENDOR_CONFIG_MODULE: dict[str, str] = {
    "cisco_ios": "cisco.ios.ios_config",
    "cisco_ios_xe": "cisco.ios.ios_config",
    "cisco_ios_xr": "cisco.iosxr.iosxr_config",
    "cisco_nxos": "cisco.nxos.nxos_config",
    "arista_eos": "arista.eos.eos_config",
    "juniper_junos": "junipernetworks.junos.junos_config",
    "nokia_sros": "community.network.sros_command",
    "paloalto_panos": "paloaltonetworks.panos.panos_config",
    "brocade_fastiron": "community.network.ironware_config",
    "brocade_vdx": "community.network.nos_config",
    "_default": "ansible.netcommon.cli_config",
}


# ---------------------------------------------------------------------------
# Template dataclass
# ---------------------------------------------------------------------------


@dataclass
class RemediationTemplate:
    """Vendor-specific command sets for a single remediation action.

    Attributes
    ----------
    failure_type:
        The :class:`~netops.playbooks.generator.FailureType` string value this
        template targets.
    description:
        Human-readable description shown in generated playbook task names.
    pre_commands:
        Dict mapping vendor ``device_type`` strings (plus ``_default``) to a
        list of CLI commands to run *before* remediation for state capture.
    remediation_commands:
        Dict mapping vendor to remediation commands.  ``None`` or an empty
        dict means "no automated remediation available — human review only".
    post_commands:
        Dict mapping vendor to post-validation commands (same shape as pre).
    rollback_commands:
        Dict mapping vendor to rollback/undo commands.  Empty when the action
        cannot be rolled back (e.g. counter clearing).
    rollback_note:
        Human-readable note explaining rollback behaviour or limitations.

    """

    failure_type: str
    description: str
    pre_commands: dict[str, list[str]] = field(default_factory=dict)
    remediation_commands: dict[str, list[str]] = field(default_factory=dict)
    post_commands: dict[str, list[str]] = field(default_factory=dict)
    rollback_commands: dict[str, list[str]] = field(default_factory=dict)
    rollback_note: str = ""

    def commands_for(self, vendor: str, kind: str) -> list[str]:
        """Return the command list for *vendor* in *kind* (pre/remediation/post/rollback).

        Falls back to ``_default`` when the specific vendor is not listed.
        Returns an empty list when neither vendor nor default exists.
        """
        mapping: dict[str, list[str]] = getattr(self, f"{kind}_commands", {})
        return mapping.get(vendor, mapping.get("_default", []))


# ---------------------------------------------------------------------------
# Template definitions
# ---------------------------------------------------------------------------

_CPU_HIGH = RemediationTemplate(
    failure_type="cpu_high",
    description="Investigate high CPU utilisation",
    pre_commands={
        "cisco_ios": ["show processes cpu sorted", "show processes cpu history"],
        "cisco_ios_xe": ["show processes cpu sorted", "show processes cpu history"],
        "cisco_ios_xr": ["show processes cpu", "show processes memory"],
        "cisco_nxos": ["show processes cpu sort", "show system resources"],
        "arista_eos": ["show processes top once", "show version"],
        "juniper_junos": [
            "show system processes extensive | head 25",
            "show chassis routing-engine",
        ],
        "nokia_sros": ["show system cpu", "show system memory-pools"],
        "brocade_fastiron": ["show cpu", "show memory"],
        "_default": ["show processes cpu", "show version"],
    },
    remediation_commands={},  # No safe automated remediation for high CPU
    post_commands={
        "cisco_ios": ["show processes cpu sorted"],
        "cisco_ios_xe": ["show processes cpu sorted"],
        "cisco_ios_xr": ["show processes cpu"],
        "cisco_nxos": ["show processes cpu sort"],
        "arista_eos": ["show processes top once"],
        "juniper_junos": ["show system processes extensive | head 25"],
        "nokia_sros": ["show system cpu"],
        "brocade_fastiron": ["show cpu"],
        "_default": ["show processes cpu"],
    },
    rollback_commands={},
    rollback_note="High CPU has no automated remediation. Escalate to NOC for manual investigation.",
)

_MEMORY_HIGH = RemediationTemplate(
    failure_type="memory_high",
    description="Investigate high memory utilisation",
    pre_commands={
        "cisco_ios": ["show processes memory sorted", "show processes memory total"],
        "cisco_ios_xe": ["show processes memory sorted", "show processes memory total"],
        "cisco_ios_xr": ["show processes memory", "show memory summary"],
        "cisco_nxos": ["show system resources", "show processes memory"],
        "arista_eos": ["show version", "show processes top once"],
        "juniper_junos": ["show task memory detail", "show chassis routing-engine"],
        "nokia_sros": ["show system memory-pools", "show system cpu"],
        "brocade_fastiron": ["show memory", "show cpu"],
        "_default": ["show processes memory", "show version"],
    },
    remediation_commands={},  # No safe automated remediation for high memory
    post_commands={
        "cisco_ios": ["show processes memory sorted"],
        "cisco_ios_xe": ["show processes memory sorted"],
        "cisco_ios_xr": ["show processes memory"],
        "cisco_nxos": ["show system resources"],
        "arista_eos": ["show processes top once"],
        "juniper_junos": ["show task memory detail"],
        "nokia_sros": ["show system memory-pools"],
        "brocade_fastiron": ["show memory"],
        "_default": ["show processes memory"],
    },
    rollback_commands={},
    rollback_note=(
        "High memory has no automated remediation. "
        "Escalate to NOC for manual investigation or scheduled reload."
    ),
)

_INTERFACE_ERRORS = RemediationTemplate(
    failure_type="interface_errors",
    description="Clear interface error counters",
    pre_commands={
        "cisco_ios": [
            "show interfaces | include line|error|reset",
            "show interfaces counters errors",
        ],
        "cisco_ios_xe": [
            "show interfaces | include line|error|reset",
            "show interfaces counters errors",
        ],
        "cisco_ios_xr": ["show interfaces | include error|reset", "show interfaces detail"],
        "cisco_nxos": ["show interface status err-disabled", "show interfaces counters errors"],
        "arista_eos": ["show interfaces | grep -i error", "show interfaces status err-disabled"],
        "juniper_junos": [
            "show interfaces detail | match error",
            "show interfaces statistics | match error",
        ],
        "nokia_sros": ["show port detail | match error", "show port statistics"],
        "brocade_fastiron": ["show interfaces | include error", "show statistics"],
        "_default": ["show interfaces | include error"],
    },
    remediation_commands={
        "cisco_ios": ["clear counters"],
        "cisco_ios_xe": ["clear counters"],
        "cisco_ios_xr": ["clear counters all"],
        "cisco_nxos": ["clear counters"],
        "arista_eos": ["clear counters"],
        "juniper_junos": ["clear interfaces statistics all"],
        "nokia_sros": ["clear port statistics"],
        "brocade_fastiron": ["clear statistics"],
        "_default": ["clear counters"],
    },
    post_commands={
        "cisco_ios": ["show interfaces | include line|error|reset"],
        "cisco_ios_xe": ["show interfaces | include line|error|reset"],
        "cisco_ios_xr": ["show interfaces | include error|reset"],
        "cisco_nxos": ["show interfaces counters errors"],
        "arista_eos": ["show interfaces | grep -i error"],
        "juniper_junos": ["show interfaces detail | match error"],
        "nokia_sros": ["show port statistics"],
        "brocade_fastiron": ["show interfaces | include error"],
        "_default": ["show interfaces | include error"],
    },
    rollback_commands={},
    rollback_note=(
        "Counter clearing cannot be undone. "
        "Monitor interfaces for recurrence of errors after clearing."
    ),
)

_BGP_PEER_DOWN = RemediationTemplate(
    failure_type="bgp_peer_down",
    description="Soft-reset BGP peer sessions",
    pre_commands={
        "cisco_ios": ["show ip bgp summary", "show ip bgp neighbors | include BGP state"],
        "cisco_ios_xe": ["show ip bgp summary", "show ip bgp neighbors | include BGP state"],
        "cisco_ios_xr": ["show bgp summary", "show bgp neighbors brief"],
        "cisco_nxos": ["show bgp all summary", "show bgp sessions"],
        "arista_eos": ["show ip bgp summary", "show bgp neighbors | include BGP state"],
        "juniper_junos": ["show bgp summary", "show bgp neighbor | match State"],
        "nokia_sros": [
            "show router bgp summary",
            "show router bgp neighbor | match State",
        ],
        "brocade_vdx": ["show bgp neighbors summary", "show bgp neighbors"],
        "_default": ["show ip bgp summary"],
    },
    remediation_commands={
        "cisco_ios": ["clear ip bgp * soft"],
        "cisco_ios_xe": ["clear ip bgp * soft"],
        "cisco_ios_xr": ["clear bgp all * soft"],
        "cisco_nxos": ["clear ip bgp all soft"],
        "arista_eos": ["clear ip bgp * soft"],
        "juniper_junos": ["clear bgp neighbor all"],
        "nokia_sros": ["clear router bgp neighbor * soft"],
        "brocade_vdx": ["clear ip bgp all soft-out"],
        "_default": ["clear ip bgp * soft"],
    },
    post_commands={
        "cisco_ios": ["show ip bgp summary"],
        "cisco_ios_xe": ["show ip bgp summary"],
        "cisco_ios_xr": ["show bgp summary"],
        "cisco_nxos": ["show bgp all summary"],
        "arista_eos": ["show ip bgp summary"],
        "juniper_junos": ["show bgp summary"],
        "nokia_sros": ["show router bgp summary"],
        "brocade_vdx": ["show bgp neighbors summary"],
        "_default": ["show ip bgp summary"],
    },
    rollback_commands={
        "cisco_ios": ["clear ip bgp * soft"],
        "cisco_ios_xe": ["clear ip bgp * soft"],
        "cisco_ios_xr": ["clear bgp all * soft"],
        "cisco_nxos": ["clear ip bgp all soft"],
        "arista_eos": ["clear ip bgp * soft"],
        "juniper_junos": ["clear bgp neighbor all"],
        "nokia_sros": ["clear router bgp neighbor * soft"],
        "_default": ["clear ip bgp * soft"],
    },
    rollback_note=(
        "BGP soft-reset is non-disruptive and idempotent. "
        "Rollback repeats the soft-reset to re-trigger route advertisements."
    ),
)

_OSPF_NEIGHBOR_DOWN = RemediationTemplate(
    failure_type="ospf_neighbor_down",
    description="Verify OSPF neighbor adjacencies",
    pre_commands={
        "cisco_ios": [
            "show ip ospf neighbor",
            "show ip ospf neighbor detail | include State|Interface",
        ],
        "cisco_ios_xe": [
            "show ip ospf neighbor",
            "show ip ospf neighbor detail | include State|Interface",
        ],
        "cisco_ios_xr": ["show ospf neighbor", "show ospf neighbor detail"],
        "cisco_nxos": ["show ip ospf neighbors", "show ip ospf neighbors detail"],
        "arista_eos": ["show ip ospf neighbor", "show ip ospf neighbor detail"],
        "juniper_junos": ["show ospf neighbor", "show ospf neighbor detail"],
        "nokia_sros": [
            "show router ospf neighbor",
            "show router ospf neighbor detail",
        ],
        "_default": ["show ip ospf neighbor"],
    },
    # OSPF process restart is disruptive — no automated remediation
    remediation_commands={},
    post_commands={
        "cisco_ios": ["show ip ospf neighbor"],
        "cisco_ios_xe": ["show ip ospf neighbor"],
        "cisco_ios_xr": ["show ospf neighbor"],
        "cisco_nxos": ["show ip ospf neighbors"],
        "arista_eos": ["show ip ospf neighbor"],
        "juniper_junos": ["show ospf neighbor"],
        "nokia_sros": ["show router ospf neighbor"],
        "_default": ["show ip ospf neighbor"],
    },
    rollback_commands={},
    rollback_note=(
        "OSPF process restart is disruptive and requires manual approval. "
        "Escalate to NOC for investigation of neighbour adjacency failures."
    ),
)

_NTP_UNSYNC = RemediationTemplate(
    failure_type="ntp_unsync",
    description="Verify and re-apply NTP configuration",
    pre_commands={
        "cisco_ios": ["show ntp status", "show ntp associations"],
        "cisco_ios_xe": ["show ntp status", "show ntp associations"],
        "cisco_ios_xr": ["show ntp status", "show ntp associations"],
        "cisco_nxos": ["show ntp status", "show ntp peers"],
        "arista_eos": ["show ntp status", "show ntp associations"],
        "juniper_junos": ["show ntp status", "show ntp associations"],
        "nokia_sros": ["show system ntp", "show system time"],
        "brocade_fastiron": ["show ntp status", "show ntp associations"],
        "_default": ["show ntp status"],
    },
    remediation_commands={
        # Re-sync NTP — these commands re-trigger NTP synchronisation
        "cisco_ios": ["ntp update-calendar"],
        "cisco_ios_xe": ["ntp update-calendar"],
        "cisco_ios_xr": ["ntp update-calendar"],
        "cisco_nxos": ["ntp sync-retry"],
        "arista_eos": ["ntp resync"],
        "juniper_junos": ["set system ntp boot-server 127.0.0.1"],
        "nokia_sros": ["admin reboot ntp-resync"],
        "_default": ["ntp update-calendar"],
    },
    post_commands={
        "cisco_ios": ["show ntp status"],
        "cisco_ios_xe": ["show ntp status"],
        "cisco_ios_xr": ["show ntp status"],
        "cisco_nxos": ["show ntp status"],
        "arista_eos": ["show ntp status"],
        "juniper_junos": ["show ntp status"],
        "nokia_sros": ["show system ntp"],
        "brocade_fastiron": ["show ntp status"],
        "_default": ["show ntp status"],
    },
    rollback_commands={},
    rollback_note=(
        "NTP re-sync does not alter configuration — it only triggers a re-synchronisation attempt. "
        "No rollback is required. Verify NTP server reachability if the issue persists."
    ),
)

_ENVIRONMENT_ALERT = RemediationTemplate(
    failure_type="environment_alert",
    description="Check environmental health (temperature, fans, PSU)",
    pre_commands={
        "cisco_ios": ["show environment all", "show environment temperature"],
        "cisco_ios_xe": ["show environment all", "show environment temperature"],
        "cisco_ios_xr": ["show environment all", "show environment power-supply"],
        "cisco_nxos": ["show environment", "show environment power"],
        "arista_eos": [
            "show environment all",
            "show environment temperature",
            "show environment power",
        ],
        "juniper_junos": [
            "show chassis environment",
            "show chassis environment pem",
            "show chassis alarms",
        ],
        "nokia_sros": ["show chassis environment", "show card state"],
        "brocade_fastiron": ["show environment", "show chassis"],
        "brocade_vdx": ["show system environment fan", "show system environment power"],
        "_default": ["show environment all"],
    },
    remediation_commands={},  # Environmental issues require physical intervention
    post_commands={
        "cisco_ios": ["show environment all"],
        "cisco_ios_xe": ["show environment all"],
        "cisco_ios_xr": ["show environment all"],
        "cisco_nxos": ["show environment"],
        "arista_eos": ["show environment all"],
        "juniper_junos": ["show chassis environment"],
        "nokia_sros": ["show chassis environment"],
        "brocade_fastiron": ["show environment"],
        "_default": ["show environment all"],
    },
    rollback_commands={},
    rollback_note=(
        "Environmental alerts require physical inspection and intervention. "
        "Escalate immediately to a field engineer."
    ),
)

_LOG_ALERTS = RemediationTemplate(
    failure_type="log_alerts",
    description="Review and clear system log buffer",
    pre_commands={
        "cisco_ios": ["show logging | tail 50", "show logging count"],
        "cisco_ios_xe": ["show logging | tail 50", "show logging count"],
        "cisco_ios_xr": ["show logging last 50", "show logging"],
        "cisco_nxos": ["show logging last 50", "show logging logfile last 50"],
        "arista_eos": ["show logging last 50", "show logging"],
        "juniper_junos": ["show log messages | last 50", "show system alarms"],
        "nokia_sros": ["show log 99 | tail 50", "show log"],
        "brocade_fastiron": ["show logging last 50", "show logging"],
        "_default": ["show logging"],
    },
    remediation_commands={
        "cisco_ios": ["clear logging"],
        "cisco_ios_xe": ["clear logging"],
        "cisco_ios_xr": ["clear logging"],
        "cisco_nxos": ["clear logging logfile"],
        "arista_eos": ["clear logging"],
        "juniper_junos": ["clear log messages"],
        "nokia_sros": ["clear log"],
        "brocade_fastiron": ["clear logging"],
        "_default": ["clear logging"],
    },
    post_commands={
        "cisco_ios": ["show logging | tail 10"],
        "cisco_ios_xe": ["show logging | tail 10"],
        "cisco_ios_xr": ["show logging last 10"],
        "cisco_nxos": ["show logging last 10"],
        "arista_eos": ["show logging last 10"],
        "juniper_junos": ["show log messages | last 10"],
        "nokia_sros": ["show log 10"],
        "brocade_fastiron": ["show logging"],
        "_default": ["show logging"],
    },
    rollback_commands={},
    rollback_note=(
        "Log buffer clearing cannot be undone. "
        "Ensure critical events have been reviewed and acknowledged before clearing."
    ),
)

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

#: All remediation templates indexed by failure_type string.
REMEDIATION_TEMPLATES: dict[str, RemediationTemplate] = {
    t.failure_type: t
    for t in [
        _CPU_HIGH,
        _MEMORY_HIGH,
        _INTERFACE_ERRORS,
        _BGP_PEER_DOWN,
        _OSPF_NEIGHBOR_DOWN,
        _NTP_UNSYNC,
        _ENVIRONMENT_ALERT,
        _LOG_ALERTS,
    ]
}


def get_template(failure_type: str) -> RemediationTemplate | None:
    """Return the :class:`RemediationTemplate` for *failure_type*, or ``None``."""
    return REMEDIATION_TEMPLATES.get(failure_type)
