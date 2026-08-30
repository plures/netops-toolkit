# Terminal UI Screen Reference

This gallery shows every user-facing TUI screen. The images are generated from
the running application at a fixed terminal size, with no inventory entries,
credentials, or live device configuration. Regenerate them after a UI change:

```bash
python scripts/capture_tui_docs.py
```

## Workspace

![The netops-toolkit workspace with inventory table, detail pane, and footer shortcuts.](../images/tui-workspace.svg)

## Manual inventory editor

![The full-width manual inventory editor, with one labelled field per line.](../images/tui-inventory-editor.svg)

## Inventory scan

![The inventory scan form with labelled SNMP and SSH controls.](../images/tui-scan-form.svg)

## Health check

![The health-check form.](../images/tui-health-check.svg)

## Configuration push

![The configuration-push form.](../images/tui-config-push.svg)

## Configuration backup

![The configuration-backup form.](../images/tui-config-backup.svg)

## Configuration diff

![The configuration-diff form.](../images/tui-config-diff.svg)

## Active bastion

![The active-bastion connection and status form.](../images/tui-active-bastion.svg)

## Settings

![The non-secret settings form.](../images/tui-settings.svg)

## Credential vault

![The credential-vault screen with unlock and saved-credential controls.](../images/tui-credential-vault.svg)

## Running configuration

![The running-configuration reader without device output.](../images/tui-running-config.svg)

## Help

![The TUI keyboard-help notification.](../images/tui-help.svg)
