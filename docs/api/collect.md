# `netops.collect` — Configuration Collection

Bulk configuration backup with diff tracking and git integration.

---

## `netops.collect.config`

Single-device configuration collection.

**CLI usage:**
```
python -m netops.collect.config --host 10.0.0.1 --vendor cisco_ios \
    --user admin --password secret
```

::: netops.collect.config

---

## `netops.collect.backup`

Bulk configuration backup from an inventory file, with timestamped snapshots,
diff tracking, and optional git commit.

**CLI usage:**
```
python -m netops.collect.backup --inventory inventory.yaml --output-dir ./backups
python -m netops.collect.backup --inventory inventory.yaml --output-dir ./backups --git
python -m netops.collect.backup --inventory inventory.yaml --output-dir ./backups \
    --workers 10 --alert-on-change
```

::: netops.collect.backup
