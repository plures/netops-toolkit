"""Command templates for Arista EOS devices (switches and routers).

eAPI JSON commands are the primary interface; CLI text fallbacks are also
provided for environments where eAPI is unavailable.
"""

# eAPI JSON commands (passed to ``enable`` then JSON-decoded)
EAPI = {
    "version": "show version",
    "agents": "show agent logs",
    "cpu": "show processes top once",
    "memory": "show version",
    "interfaces": "show interfaces",
    "interface_counters": "show interfaces counters errors",
    "transceivers": "show interfaces transceiver",
    "bgp_summary": "show bgp summary",
    "bgp_evpn": "show bgp evpn summary",
    "ospf_neighbors": "show ip ospf neighbor",
    "mlag": "show mlag",
    "mlag_config_sanity": "show mlag config-sanity",
    "environment": "show environment all",
    "environment_temp": "show environment temperature",
    "environment_cooling": "show environment cooling",
    "environment_power": "show environment power",
}

# CLI text commands (fallback, parsed with regex)
SHOW = {
    "version": "show version",
    "interfaces": "show interfaces status",
    "bgp_summary": "show bgp summary",
    "ospf_neighbors": "show ip ospf neighbor",
    "mlag": "show mlag",
    "environment": "show environment all",
}

HEALTH = {
    "cpu_memory": "show version",
    "interfaces": "show interfaces",
    "interface_counters": "show interfaces counters errors",
    "bgp_summary": "show bgp summary",
    "bgp_evpn": "show bgp evpn summary",
    "ospf_neighbors": "show ip ospf neighbor",
    "mlag": "show mlag",
    "mlag_config_sanity": "show mlag config-sanity",
    "environment": "show environment all",
}
