"""Command templates for Cisco IOS/IOS-XE devices."""

SHOW = {
    "version": "show version",
    "config": "show running-config",
    "interfaces": "show ip interface brief",
    "interfaces_detail": "show interfaces",
    "routes": "show ip route",
    "bgp_summary": "show ip bgp summary",
    "ospf_neighbors": "show ip ospf neighbor",
    "arp": "show ip arp",
    "mac_table": "show mac address-table",
    "cdp_neighbors": "show cdp neighbors detail",
    "lldp_neighbors": "show lldp neighbors detail",
    "inventory": "show inventory",
    "environment": "show environment all",
    "logging": "show logging",
    "ntp": "show ntp associations",
    "snmp": "show snmp community",
    "users": "show users",
    "uptime": "show version | include uptime",
}

HEALTH = {
    "cpu": "show processes cpu sorted | head 20",
    "memory": "show processes memory sorted | head 20",
    "interface_errors": "show interfaces | include errors|drops|CRC",
    "log_errors": "show logging | include %",
}
