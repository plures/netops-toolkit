"""Fixed host-owned probe symbols shared by registry validation and dispatch."""

import sys

MODULES = {
    "netmiko": ("netmiko", "netmiko"), "paramiko": ("paramiko", "paramiko"),
    "cryptography": ("cryptography", "cryptography"), "pyyaml": ("yaml", "PyYAML"),
    "textual": ("textual", "textual"), "pysnmp": ("pysnmp", "pysnmp"),
    "jinja2": ("jinja2", "Jinja2"), "weasyprint": ("weasyprint", "weasyprint"),
    "ansible-core": ("ansible.release", "ansible-core"), "molecule": ("molecule", "molecule"),
    "molecule-plugins": ("molecule_plugins", "molecule-plugins"),
    "mkdocs": ("mkdocs", "mkdocs"),
    "mkdocs-material": ("material", "mkdocs-material"),
    "mkdocstrings": ("mkdocstrings", "mkdocstrings"),
    "mkdocs-autorefs": ("mkdocs_autorefs", "mkdocs-autorefs"),
}
TOOLS = {
    "ping": ("ping", "-?") if sys.platform == "win32" else ("ping", "-V"),
    "git": ("git", "--version"), "bash": ("bash", "--version"),
    "date": ("date", "--version"), "ls": ("ls", "--version"),
    "tail": ("tail", "--version"), "xargs": ("xargs", "--version"),
    # BSD rm has no help/version switch: no operands requests usage without a file effect.
    "rm": ("rm",) if sys.platform == "darwin" else ("rm", "--help"),
}
CONTROLLER_TOOLS = {
    "ansible-playbook": "ansible.cli.playbook",
    "ansible-inventory": "ansible.cli.inventory",
    "ansible-vault": "ansible.cli.vault",
    "molecule-cli": "molecule",
}
PROBE_SYMBOLS = {
    "python": frozenset({"python"}),
    "module": frozenset(MODULES),
    "executable": frozenset(TOOLS) | frozenset(CONTROLLER_TOOLS),
    "collection": frozenset({
        "ansible.netcommon", "ansible.utils", "cisco.ios", "arista.eos",
        "junipernetworks.junos", "paloaltonetworks.panos", "community.network",
    }),
    "pdf": frozenset({"render-pdf"}),
    "runtime": frozenset({"container-runtime"}),
    "asset": frozenset({"selected-image"}),
    "grant": frozenset({"platform-receipt"}),
}
