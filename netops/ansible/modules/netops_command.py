#!/usr/bin/env python
"""Ansible module: netops_command.

Thin Ansible wrapper around netops utilities.  Sends one or more commands
to a network device using the netmiko connection backend and returns the
raw output.

Options
-------
``host``
    IP address or FQDN of the target device.
``vendor``
    Device vendor/OS type (netmiko ``device_type``).
``username``
    SSH username.
``password``
    SSH password.
``port``
    TCP port, default 22.
``commands``
    List of CLI commands to execute.
``wait_for``
    Optional list of output strings to wait for before returning
    (passed to netmiko ``expect_string``).

Return values
-------------
``output``
    List of raw command output strings, one per command.
``stdout``
    Concatenated output of all commands.

Examples
--------

.. code-block:: yaml

    - name: Run show commands
      netops_command:
        host: "{{ ansible_host }}"
        vendor: cisco_ios
        username: admin
        password: "{{ vault_password }}"
        commands:
          - show version
          - show interfaces status

    - name: Capture BGP summary
      netops_command:
        host: "{{ ansible_host }}"
        vendor: cisco_ios
        username: admin
        password: "{{ vault_password }}"
        commands:
          - show bgp summary
      register: bgp_raw

    - name: Parse BGP output
      set_fact:
        bgp_peers: "{{ bgp_raw.output[0] | netops_parse_bgp }}"

"""

from __future__ import annotations

DOCUMENTATION = __doc__

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


def _run_commands(params: dict) -> list[str]:
    """Open a netmiko session, run commands, return output list."""
    from netmiko import ConnectHandler

    nm_params: dict = {
        "device_type": params["vendor"],
        "host": params["host"],
        "port": params["port"],
        "username": params["username"],
        "password": params["password"],
    }
    if params.get("key_file"):
        nm_params["key_file"] = params["key_file"]

    outputs: list[str] = []
    with ConnectHandler(**nm_params) as conn:
        for cmd in params["commands"]:
            out = conn.send_command(cmd)
            outputs.append(out)
    return outputs


def run_module() -> None:
    """Entry point called by Ansible."""
    from ansible.module_utils.basic import AnsibleModule

    module_args = {
        "host": {"type": "str", "required": True},
        "vendor": {"type": "str", "required": True},
        "username": {"type": "str", "required": True},
        "password": {"type": "str", "required": True, "no_log": True},
        "port": {"type": "int", "default": 22},
        "key_file": {"type": "str", "required": False, "default": None},
        "commands": {"type": "list", "elements": "str", "required": True},
    }

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if module.check_mode:
        module.exit_json(changed=False, output=[], stdout="")
        return

    try:
        outputs = _run_commands(module.params)
    except Exception as exc:  # noqa: BLE001
        module.fail_json(msg=f"Command execution failed: {exc}")
        return

    module.exit_json(
        changed=False,
        output=outputs,
        stdout="\n".join(outputs),
    )


if __name__ == "__main__":
    run_module()
