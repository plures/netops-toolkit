"""Fixed installed play entry; private client is consumed before Ansible forks."""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from .action_runtime import _ActionClient, _install_client
from .controller_protocol import ProtocolError, _integer, _read_frame

_PLAY = {
    "name": "netops-owned-workflow-v1",
    "hosts": "all",
    "connection": "local",
    "gather_facts": False,
    "tasks": [{
        "name": "Execute the exact admitted local occurrence",
        "netops_workflow": {"handle": "{{ netops_handle }}"},
    }],
}


def _run(client: _ActionClient, concurrency: int) -> int:
    # Imports follow one-time auth consumption and descriptor close. Only this
    # separately owned runner's plugin paths/loggers are configured.
    from ansible import context
    from ansible.executor.task_queue_manager import TaskQueueManager
    from ansible.inventory.manager import InventoryManager
    from ansible.module_utils.common.collections import ImmutableDict
    from ansible.parsing.dataloader import DataLoader
    from ansible.playbook.play import Play
    from ansible.plugins.callback import CallbackBase
    from ansible.plugins.loader import action_loader
    from ansible.vars.manager import VariableManager

    if os.name != "posix":
        raise ProtocolError()
    _integer(concurrency, 1, 50)
    for name in ("netmiko", "paramiko", "ansible"):
        logger = logging.getLogger(name)
        logger.disabled = True
        logger.propagate = False
    action_loader.add_directory(str(Path(__file__).resolve().parent / "action_plugins"))
    context.CLIARGS = ImmutableDict(
        connection="local", forks=concurrency, check=False, diff=False,
        verbosity=0, start_at_task=None, syntax=False,
    )
    _install_client(client)
    status = 0
    handles = tuple(client._intents)
    try:
        # At most twice concurrency is presented to Ansible at a time; no
        # future per selected address and no unbounded inventory queue.
        for offset in range(0, len(handles), 2 * concurrency):
            loader = DataLoader()
            inventory = InventoryManager(loader=loader, sources=[])
            for index, handle in enumerate(handles[offset:offset + 2 * concurrency]):
                host = inventory.add_host(f"netops_{index}", group="all")
                if host is None:
                    raise ProtocolError()
                selected = inventory.get_host(host)
                if selected is None:
                    raise ProtocolError()
                selected.set_variable("netops_handle", handle)
                selected.set_variable("ansible_connection", "local")
            variables = VariableManager(loader=loader, inventory=inventory)
            play = Play().load(_PLAY, variable_manager=variables, loader=loader)
            queue = TaskQueueManager(
                inventory=inventory, variable_manager=variables, loader=loader,
                passwords={}, stdout_callback=CallbackBase(), forks=concurrency,
            )
            try:
                status = max(status, int(queue.run(play)))
            finally:
                queue.cleanup()
                loader.cleanup_all_tmp_files()
    finally:
        _install_client(None)
    # Safe failed/unsupported target facts are delivered through the private
    # broker, not callbacks/stdout. Ansible failure exit alone cannot erase them.
    return 0 if status in (0, 2) else 3


def _main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--auth-fd", type=int, required=True)
    parser.add_argument("--concurrency", type=int, required=True)
    args = parser.parse_args()
    if os.name != "posix" or args.auth_fd < 3:
        return 3
    try:
        with os.fdopen(args.auth_fd, "rb", closefd=True) as private:
            client = _ActionClient(_read_frame(private, eof=True))
        return _run(client, args.concurrency)
    except BaseException:
        return 3


if __name__ == "__main__":
    raise SystemExit(_main())
