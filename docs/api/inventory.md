# `netops.inventory` — Device Discovery

Subnet scanning and automatic device discovery.

---

## `netops.inventory.scan`

Scan subnets for network devices using ping sweep and SNMP fingerprinting.

Produces `ScanResult` objects that can be merged into an existing inventory
or exported as a new YAML/JSON inventory file.

**CLI usage:**
```
python -m netops.inventory.scan --subnet 10.0.0.0/24
python -m netops.inventory.scan --subnet 10.0.0.0/24 --community public
python -m netops.inventory.scan --subnet 10.0.0.0/24 --output inventory.yaml
python -m netops.inventory.scan --subnet 10.0.0.0/24 --json
python -m netops.inventory.scan --subnet 10.0.0.0/24 --deep-enrich
```

::: netops.inventory.scan
