"""Command templates for Brocade FastIron / Network OS / Fabric OS devices."""

SHOW = {
    "version": "show version",
    "config": "show running-config",
    "interfaces": "show interface brief",
    "interfaces_detail": "show interfaces",
    "routes": "show ip route",
    "bgp_summary": "show ip bgp summary",
    "ospf_neighbors": "show ip ospf neighbor",
    "arp": "show arp",
    "mac_table": "show mac-address",
    "lldp_neighbors": "show lldp neighbors detail",
    "inventory": "show chassis",
    "environment": "show environment",
    "logging": "show logging",
    "ntp": "show ntp associations",
    "users": "show users",
    "uptime": "show version | include uptime",
    # Brocade Fabric OS (SAN) — only applicable to FOS devices
    "fabric": "show fabric",
    "fabric_name": "fabricname --show",
    "zone_active": "zoneshow --active",
}

HEALTH = {
    "cpu": "show cpu",
    "memory": "show memory",
    "interface_errors": "show interfaces | include error|discard|drop",
    "log_errors": "show logging",
    # Fabric health (FOS)
    "fabric_state": "show fabric",
}
