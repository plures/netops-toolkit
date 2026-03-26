"""Playbook template library for remediation actions.

Each template describes a specific remediation action with vendor-specific
commands for pre-validation, remediation, post-validation, and rollback.

Public API::

    from netops.playbooks.templates import REMEDIATION_TEMPLATES, get_template
    from netops.playbooks.templates.remediation import (
        RemediationTemplate,
        VENDOR_COMMAND_MODULE,
        VENDOR_CONFIG_MODULE,
    )
"""

from netops.playbooks.templates.remediation import (
    REMEDIATION_TEMPLATES,
    VENDOR_COMMAND_MODULE,
    VENDOR_CONFIG_MODULE,
    RemediationTemplate,
    get_template,
)

__all__ = [
    "RemediationTemplate",
    "REMEDIATION_TEMPLATES",
    "VENDOR_COMMAND_MODULE",
    "VENDOR_CONFIG_MODULE",
    "get_template",
]
