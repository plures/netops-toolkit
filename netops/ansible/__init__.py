"""Ansible integration for netops-toolkit.

Provides:
- Dynamic inventory script compatible with Ansible's ``--inventory`` flag
- ``netops_facts`` Ansible module — collect structured device facts
- ``netops_command`` Ansible module — run netops utilities from playbooks
- ``netops.ansible.contracts`` — immutable version-1 companion contracts
- ``netops.ansible.workflows`` — explicit hydration and pure seven-area plans
- ``netops.ansible.settings`` — immutable settings and pure tuning resolution

Import companion surfaces explicitly from their modules. This package does not
eagerly bootstrap a policy, dependency registry, controller, vault or logger.
"""
