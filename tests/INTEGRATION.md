# Integration Tests

End-to-end tests that exercise the **real scan pipeline** and **TUI** against self-contained mock SSH servers. No external services, Docker, or network access required.

## Quick Start

```bash
# Install with dev + tui extras
pip install -e ".[dev,tui]"

# Run integration tests
./scripts/run-integration-tests.sh
```

## What's Tested

### Scan Pipeline (`test_integration_scan.py`)

Starts real TCP servers (via paramiko) that speak SSH and respond to CLI commands like actual network devices:

| Personality | Commands Supported |
|---|---|
| `cisco_ios` | `show version`, `show inventory`, `show running-config \| include snmp-server community` |
| `brocade_fastiron` | `show version`, `show inventory`, `show running-config \| include snmp-server community` |
| `juniper_junos` | `show version`, `show chassis hardware`, `show configuration snmp \| display set \| match community` |

Tests verify:
- Netmiko connects and authenticates to mock servers
- Vendor identification from sysDescr strings
- Deep scan extracts version, model, serial from CLI output
- `deep_enrich()` pipeline processes inventory fragments end-to-end
- Auth failures are handled gracefully (no crashes)
- Multiple concurrent device types are discovered correctly

### TUI (`test_integration_tui.py`)

Uses Textual's `run_test()` harness to exercise the full app:

- App starts and renders device table from inventory JSON
- Refresh action reloads data from disk
- Scan modal opens and contains expected input fields
- Health modal opens and renders correctly
- Escape dismisses modals

## Architecture

```
tests/
├── mock_ssh_server.py          # Paramiko-based mock SSH server
├── fixtures/                   # Device command output fixtures
│   ├── brocade_fastiron_*.txt
│   ├── cisco_ios_*.txt
│   └── juniper_*.txt
├── test_integration_scan.py    # Scan pipeline integration tests
└── test_integration_tui.py     # TUI integration tests
```

### Mock SSH Server

`mock_ssh_server.py` provides:
- `MockSSHServerInstance` — start/stop a mock device on any port
- `mock_ssh_server()` — context manager for test fixtures
- Device "personalities" that respond to commands with fixture data
- Proper Netmiko compatibility (command echo, prompt patterns, session prep commands)

### Adding a New Device Personality

1. Add fixture files in `tests/fixtures/<vendor>_<command>.txt`
2. Add personality entry in `mock_ssh_server.py` `PERSONALITIES` dict
3. Include any session-prep commands Netmiko sends (e.g., `terminal length 0`, `set cli screen-width`)

## CI

These tests run in CI with no special setup:

```yaml
- run: pip install -e ".[dev,tui]"
- run: python -m pytest tests/test_integration_scan.py tests/test_integration_tui.py --no-cov
```

Port range 22220–22235 is used for mock servers (no root required, all > 1024).
