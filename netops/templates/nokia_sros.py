"""Command templates for Nokia SR OS devices.

Covers classic CLI (TiMOS) for 7750 SR, 7450 ESS, 7210 SAS, 7705 SAR,
7250 IXR, and 7730 SXR platforms.

Note: MD-CLI (model-driven CLI) uses a different command syntax. These
templates target classic CLI which is the default on most deployed SR OS
nodes. MD-CLI equivalents are noted in comments where applicable.
"""

SHOW = {
    # System
    "version": "show version",
    "system_info": "show system information",
    "config": "admin display-config",
    "bof": "show bof",
    "users": "show users",
    "uptime": "show system information | match uptime",
    "ntp": "show system ntp all",
    "logging": "show log log-id 99",
    "dns": "show system dns",
    # Chassis & Hardware
    "chassis": "show chassis",
    "chassis_detail": "show chassis detail",
    "inventory": "show chassis",
    "card": "show card",
    "card_detail": "show card detail",
    "mda": "show mda",
    "mda_detail": "show mda detail",
    "flash": "file dir cf3:",
    "environment": "show chassis environment",
    "power": "show chassis power-supply",
    "fan": "show chassis fan",
    # Interfaces
    "interfaces": "show port",
    "interfaces_detail": "show port detail",
    "router_interface": "show router interface",
    "router_interface_detail": "show router interface detail",
    "sap": "show service sap-using",
    "lag": "show lag",
    "lag_detail": "show lag detail",
    # Routing
    "routes": "show router route-table",
    "route_summary": "show router route-table summary",
    "bgp_summary": "show router bgp summary",
    "bgp_neighbor": "show router bgp neighbor",
    "ospf_neighbors": "show router ospf neighbor",
    "ospf_database": "show router ospf database",
    "isis_adjacency": "show router isis adjacency",
    "static_routes": "show router static-route",
    "arp": "show router arp",
    "ldp_session": "show router ldp session",
    "rsvp_session": "show router rsvp session",
    "mpls_path": "show router mpls path",
    "mpls_lsp": "show router mpls lsp",
    # Services
    "service_using": "show service service-using",
    "service_sdp": "show service sdp-using",
    "vpls_all": "show service id <id> all",
    "vprn_all": "show service id <id> all",
    # L2
    "mac_table": "show service fdb-mac",
    "lldp_neighbors": "show system lldp neighbor",
    "spanning_tree": "show eth-ring",
}

HEALTH = {
    "cpu": "show system cpu",
    "memory": "show system memory-pools",
    "environment": "show chassis environment",
    "card_state": "show card",
    "interface_errors": "show port detail | match errors",
    "log_errors": "show log log-id 99 | match MINOR|MAJOR|CRITICAL",
    "bgp_health": "show router bgp summary",
    "fan_status": "show chassis fan",
    "power_status": "show chassis power-supply",
    "temperature": "show chassis environment | match Temperature",
    "flash_usage": "file dir cf3:",
}

# MD-CLI equivalents for modern deployments (SR OS 19.10+)
# Uncomment and use when targeting MD-CLI enabled nodes.
MD_CLI = {
    "system_info": "/show system information",
    "chassis": "/show chassis",
    "card": "/show card",
    "version": "/show version",
    "interfaces": "/show port",
    "router_interface": "/show router interface",
    "bgp_summary": "/show router bgp neighbor",
    "service_using": "/show service",
}
