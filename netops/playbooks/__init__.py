"""
Ansible playbook generation from health check results.

Provides auto-generation of vendor-specific Ansible remediation playbooks
from health check failures:

* :mod:`netops.playbooks.generator`             — extract failures and generate playbooks
* :mod:`netops.playbooks.templates.remediation` — vendor-specific remediation templates
"""
