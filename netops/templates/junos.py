"""Command templates for Juniper JunOS devices (MX, QFX, EX, SRX)."""

SHOW = {
    "version": "show version",
    "config": "show configuration",
    "interfaces": "show interfaces terse",
    "interfaces_detail": "show interfaces detail",
    "routes": "show route summary",
    "bgp_summary": "show bgp summary",
    "ospf_neighbors": "show ospf neighbor",
    "arp": "show arp",
    "chassis_hardware": "show chassis hardware",
    "chassis_alarms": "show chassis alarms",
    "chassis_environment": "show chassis environment",
    "chassis_fpc": "show chassis fpc",
    "re_status": "show chassis routing-engine",
    "system_users": "show system users",
    "system_uptime": "show system uptime",
    "ntp": "show ntp associations",
}

HEALTH = {
    "re_cpu_memory": "show chassis routing-engine",
    "fpc_status": "show chassis fpc",
    "interface_errors": 'show interfaces extensive | match "error|drop"',
    "bgp_summary": "show bgp summary",
    "ospf_neighbors": "show ospf neighbor",
    "chassis_alarms": "show chassis alarms",
    "chassis_environment": "show chassis environment",
    "route_summary": "show route summary",
}

# XML RPC equivalents (for Netmiko send_command with use_textfsm=False)
XML_RPC = {
    "re_status": "show chassis routing-engine",
    "fpc_status": "show chassis fpc",
    "bgp_summary": "show bgp summary",
    "ospf_neighbors": "show ospf neighbor",
    "chassis_alarms": "show chassis alarms",
    "chassis_environment": "show chassis environment",
    "route_summary": "show route summary",
}
