"""Command templates for Nokia SR OS devices."""

SHOW = {
    "version": "show version",
    "config": "admin display-config",
    "interfaces": "show port",
    "interfaces_detail": "show port detail",
    "routes": "show router route-table",
    "bgp_summary": "show router bgp summary",
    "ospf_neighbors": "show router ospf neighbor",
    "arp": "show router arp",
    "mac_table": "show service fdb-mac",
    "lldp_neighbors": "show system lldp neighbor",
    "inventory": "show chassis",
    "environment": "show chassis environment",
    "logging": "show log log-id 99",
    "ntp": "show system ntp all",
    "users": "show users",
    "uptime": "show system information | match uptime",
}

HEALTH = {
    "cpu": "show system cpu",
    "memory": "show system memory-pools",
    "interface_errors": "show port detail | match errors",
    "log_errors": "show log log-id 99 | match MINOR|MAJOR|CRITICAL",
}
