# Vendor Support Profiles

`netops.vendor_profiles` is the canonical catalog for device identification,
deep-inventory commands, supported command collections, and declared feature
coverage. It prevents discovery, logging, and SSH enrichment from maintaining
different lists of supported devices.

## Current discovery profiles

| Family | Profiles |
| --- | --- |
| Cisco | IOS, IOS-XE, IOS-XR, NX-OS |
| Nokia | SR OS, SR Linux |
| Juniper | Junos |
| Arista | EOS |
| Brocade | FastIron, Network OS |

Each current profile has `full` coverage for SNMP identification and SSH
deep-inventory collection. Other feature areas remain explicitly owned by
their check and parser modules until they are migrated into the profile
contract; a registry entry does not imply that every command or parser is
available for every platform.

## Command variants and versions

Profiles can define version-aware command variants. A version alone does not
activate a variant when it requires a device capability. For example, Nokia
SR OS MD-CLI commands require both SR OS 19.10 or later *and* an explicit
`md-cli` capability. This avoids silently changing CLI syntax simply because a
version string looks recent.

```python
from netops.vendor_profiles import PROFILES

profile = PROFILES["nokia_sros"]
classic = profile.commands_for("show", version="24.10.R1")
md_cli = profile.commands_for(
    "show", version="24.10.R1", capabilities={"md-cli"}
)
```

## Adding or changing a vendor

1. Add or update the profile in `netops.vendor_profiles`.
2. Keep the fingerprint order intentional; the first matching `sysDescr`
   wins, then enterprise OID matching is used as a fallback.
3. Define `version` and `inventory` deep commands for every probeable profile.
4. Reference maintained command-template dictionaries where they exist rather
   than copying their commands into callers.
5. Add representative sysDescr/OID fixtures and a command-variant test in
   `tests/test_vendor_profiles.py`.
6. State the feature support level honestly and add parser/check fixtures
   before changing it to `full`.
