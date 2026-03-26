# `netops.collect` — Configuration Collection

Collect and back up device configurations.

---

## `netops.collect.config`

Collect device configurations.

**CLI usage:**
```
python -m netops.collect.config --inventory inventory.yaml --group core
python -m netops.collect.config --host 10.0.0.1 --vendor cisco_ios --user admin
```

### Functions

#### `collect_config(params: ConnectionParams) -> dict`
Collect running config from a device. Returns structured result.

Uses the vendor-appropriate show command: `admin display-config` for Nokia
SR-OS; `show running-config` for all other vendors.

Returns a dict with keys:
- `host` — device IP/hostname
- `device_type` — device vendor/type string
- `collected_at` — ISO-8601 UTC collection timestamp
- `success` — `True` when collection succeeded
- `config` — raw configuration text (`None` on failure)
- `lines` — number of config lines (`None` on failure)
- `error` — error message on failure (`None` on success)

#### `main() -> None`
CLI entry point for device configuration collection.

**CLI options:**
- `--inventory` / `-i` — inventory file (YAML/JSON)
- `--group` / `-g` — inventory group to target
- `--host` — single host to connect to
- `--vendor` — device type (default: `cisco_ios`)
- `--user` / `-u` — username
- `--password` / `-p` — password (or set `NETOPS_PASSWORD`)
- `--transport` — `ssh` or `telnet` (default: `ssh`)
- `--output` / `-o` — output directory for collected configs
- `--json` — write JSON summary to stdout

---

## `netops.collect.backup`

Bulk configuration backup with diff tracking.

Collects running configs from all inventory devices, saves them with
timestamps to a per-device directory tree, and generates unified diffs
against the previous backup so unexpected changes are immediately visible.

Optional git integration commits every changed file to a local repository
so the full history is preserved.

**CLI usage:**
```
python -m netops.collect.backup --inventory inv.yaml --output /var/backups/network/
python -m netops.collect.backup --inventory inv.yaml --output /var/backups/network/ --git
python -m netops.collect.backup --inventory inv.yaml --output /var/backups/network/ --workers 10
```

**Directory layout:**
```
<output_dir>/
  <host>/
    20240101-120000.cfg
    20240102-130000.cfg
    ...
```

### Functions

#### `generate_diff(old_path: Path, new_config: str) -> str`
Return a unified diff between *old_path* on disk and *new_config* text.
Returns an empty string when the configs are identical.

#### `save_backup(result: dict, output_dir: Path, timestamp: str) -> dict`
Save one device's collected config to *output_dir* and compute a diff.

Returns a summary dict with keys:
- `host` — device hostname/IP
- `success` — `True` when the config was saved
- `saved_path` — path to the saved file (`None` on failure)
- `diff` — unified diff text (`None` when unchanged or on failure)
- `changed` — `True` when the config changed since the previous backup
- `error` — error message on failure

#### `git_init(output_dir: Path) -> bool`
Initialise a git repository in *output_dir* if one does not exist yet.
Returns `True` on success.

#### `git_commit(output_dir: Path, message: str) -> bool`
Stage all changes in *output_dir* and create a git commit.
Returns `True` on success (including the *nothing to commit* case).

#### `run_backup(params_list: list[ConnectionParams], output_dir: Path, *, workers: int = 5, git: bool = False, alert_on_change: bool = True, _timestamp: Optional[str] = None) -> list[dict]`
Collect configs from all devices and save them with diff tracking.

**Parameters:**
- `params_list` — connection parameters for each target device
- `output_dir` — root directory for the backup archive
- `workers` — maximum number of concurrent collection threads (default: `5`)
- `git` — when `True`, commit every changed file to a local git repository
- `alert_on_change` — when `True`, write change alerts to stderr
- `_timestamp` — override the timestamp string (intended for tests only)

Returns a list of per-device summary dicts (see `save_backup`).

Raises `ValueError` if `workers` is less than 1. Raises `RuntimeError` if
`git` is `True` and git initialisation or commit fails.

#### `main() -> None`
CLI entry point for bulk configuration backup.

**CLI options:**
- `--inventory` / `-i` — inventory file (required)
- `--output` / `-o` — output directory for backups (required)
- `--group` / `-g` — inventory group to target
- `--user` / `-u` — username override
- `--password` / `-p` — password (or set `NETOPS_PASSWORD`)
- `--workers` / `-w` — concurrent workers (default: `5`)
- `--git` — commit backups to a local git repository
- `--no-alert` — suppress change alerts on stderr
- `--json` — output summary as JSON to stdout
