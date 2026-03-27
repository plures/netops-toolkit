# `netops.check` — Health & Compliance Checks

Composable health, BGP, interface, VLAN, and vendor-specific checks.

---

## `netops.check.health`

Composable health checks for network devices.

Runs CPU, memory, interface-error, and log checks across vendors and reports
results as structured JSON for monitoring integration.

**CLI usage:**
```
python -m netops.check.health --inventory inv.yaml --group core \
    --threshold cpu=80,mem=85
python -m netops.check.health --host 10.0.0.1 --vendor cisco_ios \
    --threshold cpu=80,mem=85 --json
```

::: netops.check.health

---

## `netops.check.bgp`

BGP peer monitoring — peer state, prefix counts, and flap detection.

**CLI usage:**
```
python -m netops.check.bgp --inventory inv.yaml
python -m netops.check.bgp --inventory inv.yaml --expected-prefixes 10.0.0.2=100 --fail-on-alert
```

::: netops.check.bgp

---

## `netops.check.interfaces`

Interface status and error checking.

**CLI usage:**
```
python -m netops.check.interfaces --inventory inv.yaml --down-only
python -m netops.check.interfaces --host 10.0.0.1 --vendor cisco_ios --json
```

::: netops.check.interfaces

---

## `netops.check.vlan`

VLAN consistency audit across switching infrastructure.

**CLI usage:**
```
python -m netops.check.vlan --inventory inv.yaml --orphans
python -m netops.check.vlan --inventory inv.yaml --json
```

::: netops.check.vlan

---

## `netops.check.arista`

Arista EOS health checks — uses eAPI JSON as the primary transport with
CLI text fallback.

::: netops.check.arista

---

## `netops.check.cisco`

Cisco IOS/IOS-XE/IOS-XR/NX-OS health checks.

::: netops.check.cisco

---

## `netops.check.juniper`

Juniper JunOS health checks — Routing Engine status, FPC, BGP, OSPF,
chassis alarms, environment, and route summary.

::: netops.check.juniper

---

## `netops.check.paloalto`

Palo Alto PAN-OS health checks and security policy audit.

::: netops.check.paloalto
