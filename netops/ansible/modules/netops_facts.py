#!/usr/bin/env python
"""Ansible module: netops_facts.

Collect structured device facts from a network device using netops utilities
and return them as Ansible facts (``ansible_facts``).

Options
-------
``host``
    IP address or FQDN of the target device.  Defaults to
    ``{{ inventory_hostname }}`` when omitted.
``vendor``
    Device vendor/OS type (e.g. ``cisco_ios``, ``nokia_sros``).  Maps to
    netmiko ``device_type``.
``username``
    SSH username.
``password``
    SSH password (mark ``no_log: true`` in your playbook).
``port``
    TCP port.  Default 22.
``transport``
    ``ssh`` (default) or ``telnet``.
``gather``
    List of fact categories to collect.  Supported values:
    ``health``, ``interfaces``, ``bgp``, ``vlans``, ``all``.
    Default is ``all``.
``inventory``
    Path to a netops inventory YAML/JSON file.  When provided, device
    connection details are read from it (``host`` must still name the
    inventory hostname).

Return values
-------------
``ansible_facts.netops``
    Dict with a key per gathered category, e.g.::

        ansible_facts:
          netops:
            health:
              cpu_percent: 12
              memory_percent: 45
            interfaces:
              - name: GigabitEthernet0/0
                status: up
                protocol: up

Examples
--------

.. code-block:: yaml

    - name: Collect device facts
      netops_facts:
        host: "{{ ansible_host }}"
        vendor: cisco_ios
        username: admin
        password: "{{ vault_password }}"
        gather:
          - health
          - interfaces

    - name: Show CPU usage
      debug:
        var: ansible_facts.netops.health.cpu_percent

"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netmiko.base_connection import BaseConnection

DOCUMENTATION = __doc__

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

# ---------------------------------------------------------------------------
# Ansible module execution guard
# ---------------------------------------------------------------------------
# This module is designed to run inside Ansible. The import of AnsibleModule
# is deferred so that the file can also be imported in unit-test contexts
# without Ansible installed.
# ---------------------------------------------------------------------------

_GATHER_ALL = {"health", "interfaces", "bgp", "vlans"}


def _gather_health(conn: BaseConnection) -> dict:
    """Collect observed CPU/memory facts without fabricating zero measurements.

    The evidence object reports observation coverage, *not* a healthy status.
    Health policy and thresholds belong to the downstream safety gate.
    """
    import math

    from netops.parsers.health import (
        parse_cpu_cisco,
        parse_cpu_nokia,
        parse_memory_cisco,
        parse_memory_nokia,
    )

    vendor = str(conn.device_type).lower()
    facts: dict = {"evidence": {"cpu": "UNKNOWN", "memory": "UNKNOWN"}}

    if "cisco" in vendor or "ios" in vendor:
        cpu_command = "show processes cpu | include utilization"
        memory_command = "show processes memory | include Processor"
        cpu_parser = parse_cpu_cisco
        memory_parser = parse_memory_cisco
        cpu_key = "five_seconds"
    elif "nokia" in vendor or "sros" in vendor:
        cpu_command = "show system cpu"
        memory_command = "show system memory-pools"
        cpu_parser = parse_cpu_nokia
        memory_parser = parse_memory_nokia
        cpu_key = "avg"
    else:
        facts["evidence"] = {"cpu": "UNSUPPORTED", "memory": "UNSUPPORTED"}
        facts["evidence_complete"] = False
        return facts

    def _valid_percent(value: object) -> bool:
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and 0 <= value <= 100
        )

    try:
        cpu = cpu_parser(conn.send_command(cpu_command))
        observed_cpu = cpu.get(cpu_key)
        if isinstance(observed_cpu, (int, float)) and _valid_percent(observed_cpu):
            facts["cpu_percent"] = float(observed_cpu)
            facts["evidence"]["cpu"] = "OBSERVED"
    except Exception:  # noqa: BLE001
        # Do not leak command output or credentials into Ansible facts.
        facts["evidence"]["cpu_reason"] = "collection_failed"

    try:
        memory = memory_parser(conn.send_command(memory_command))
        total = memory.get("total")
        used = memory.get("used")
        percent = memory.get("utilization")
        if (
            isinstance(total, int)
            and not isinstance(total, bool)
            and total > 0
            and isinstance(used, int)
            and not isinstance(used, bool)
            and 0 <= used <= total
            and isinstance(percent, (int, float))
            and _valid_percent(percent)
            and abs((used / total * 100) - percent) <= 0.05
        ):
            facts["memory_total_bytes"] = total
            facts["memory_used_bytes"] = used
            facts["memory_percent"] = float(percent)
            facts["evidence"]["memory"] = "OBSERVED"
    except Exception:  # noqa: BLE001
        facts["evidence"]["memory_reason"] = "collection_failed"

    facts["evidence_complete"] = (
        facts["evidence"]["cpu"] == "OBSERVED"
        and facts["evidence"]["memory"] == "OBSERVED"
    )
    return facts

def _gather_interfaces(conn: BaseConnection) -> list[dict]:
    """Collect interface status facts."""
    from netops.parsers.health import parse_interface_errors_cisco

    try:
        if "nokia" in conn.device_type or "sros" in conn.device_type:
            from netops.parsers.nokia_sros import parse_interfaces

            raw = conn.send_command("show port")
            return parse_interfaces(raw)
        else:
            raw = conn.send_command("show interfaces status")
            # Fall back to error parser which returns per-interface dicts
            ifaces = parse_interface_errors_cisco(raw)
            return ifaces if ifaces else []
    except Exception:  # noqa: BLE001
        return []


def _gather_bgp(conn: BaseConnection) -> list[dict]:
    """Collect BGP peer facts."""
    try:
        if "nokia" in conn.device_type or "sros" in conn.device_type:
            from netops.parsers.nokia_sros import parse_bgp_summary

            raw = conn.send_command("show router bgp summary")
            return parse_bgp_summary(raw)
        else:
            from netops.parsers.bgp import parse_bgp_summary_cisco

            raw = conn.send_command("show bgp summary")
            return parse_bgp_summary_cisco(raw)
    except Exception:  # noqa: BLE001
        return []


def _gather_vlans(conn: BaseConnection) -> list[dict]:
    """Collect VLAN facts (Cisco IOS / IOS-XE only)."""
    try:
        from netops.parsers.vlan import parse_vlan_brief

        raw = conn.send_command("show vlan brief")
        return parse_vlan_brief(raw)
    except Exception:  # noqa: BLE001
        return []


def _collect_facts(params: dict) -> dict:
    """Open a netmiko connection and gather requested fact categories."""
    from netmiko import ConnectHandler

    from netops.core.bastion import open_active_bastion_socket

    gather_set: set[str] = set(params["gather"])
    if "all" in gather_set:
        gather_set = _GATHER_ALL.copy()

    nm_params: dict = {
        "device_type": params["vendor"],
        "host": params["host"],
        "port": params["port"],
        "username": params["username"],
        "password": params["password"],
    }
    if params.get("key_file"):
        nm_params["key_file"] = params["key_file"]

    active_socket = open_active_bastion_socket(params["host"], params["port"], 30)
    if active_socket is not None:
        nm_params["sock"] = active_socket

    facts: dict = {}
    try:
        with ConnectHandler(**nm_params) as conn:
            if "health" in gather_set:
                facts["health"] = _gather_health(conn)
            if "interfaces" in gather_set:
                facts["interfaces"] = _gather_interfaces(conn)
            if "bgp" in gather_set:
                facts["bgp"] = _gather_bgp(conn)
            if "vlans" in gather_set:
                facts["vlans"] = _gather_vlans(conn)
    finally:
        if active_socket is not None:
            active_socket.close()

    return facts


def run_module() -> None:
    """Entry point called by Ansible."""
    from ansible.module_utils.basic import AnsibleModule

    module_args = {
        "host": {"type": "str", "required": False, "default": None},
        "vendor": {"type": "str", "required": True},
        "username": {"type": "str", "required": True},
        "password": {"type": "str", "required": True, "no_log": True},
        "port": {"type": "int", "default": 22},
        "transport": {"type": "str", "default": "ssh", "choices": ["ssh", "telnet"]},
        "key_file": {"type": "str", "required": False, "default": None},
        "gather": {
            "type": "list",
            "elements": "str",
            "default": ["all"],
            "choices": ["all", "health", "interfaces", "bgp", "vlans"],
        },
        "inventory": {"type": "str", "required": False, "default": None},
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    params = dict(module.params)

    # Resolve host from inventory file if provided
    if params.get("inventory") and not params.get("host"):
        module.fail_json(msg="'host' (inventory hostname) is required when 'inventory' is set")

    if params.get("inventory"):
        from netops.core.inventory import Inventory

        inv = Inventory.from_file(params["inventory"])
        device = inv.get(params["host"])
        if device is None:
            module.fail_json(msg=f"Host '{params['host']}' not found in inventory")
            return
        params.setdefault("username", device.username)
        params.setdefault("password", device.password)
        params["host"] = device.host
        params["vendor"] = device.vendor
        params["port"] = device.port or params["port"]

    if not params.get("host"):
        module.fail_json(msg="'host' parameter is required")

    if module.check_mode:
        module.exit_json(changed=False, ansible_facts={"netops": {}})
        return

    try:
        facts = _collect_facts(params)
    except Exception as exc:  # noqa: BLE001
        module.fail_json(msg=f"Failed to collect facts: {exc}")
        return

    module.exit_json(changed=False, ansible_facts={"netops": facts})


if __name__ == "__main__":
    run_module()
