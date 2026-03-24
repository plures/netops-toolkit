"""Command templates for Palo Alto Networks PAN-OS devices."""

SHOW = {
    "system_info": "show system info",
    "interfaces": "show interface all",
    "routes": "show routing route",
    "bgp_summary": "show routing protocol bgp summary",
    "arp": "show arp all",
    "sessions": "show session info",
    "security_policy": "show running security-policy",
    "nat_policy": "show running nat-policy",
    "logging": "show log system",
    "users": "show admins",
    "ha_state": "show high-availability state",
    "ha_path_monitoring": "show high-availability path-monitoring",
    "threat_status": "show wildfire status",
    "url_filtering": "show url-filtering status",
    "security_policy_stats": "show security policy statistics",
}

HEALTH = {
    # PAN-OS exposes a Linux-style ``top`` snapshot via this command;
    # CPU and memory are both extracted from the same output.
    "resources": "show system resources follow duration 1",
    "session_info": "show session info",
    "ha_state": "show high-availability state",
    "threat_status": "show wildfire status",
    "url_filtering": "show url-filtering status",
    "log_errors": "show log system severity equal critical",
}
