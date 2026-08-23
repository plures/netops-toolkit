"""netops CLI — unified command-line interface for netops-toolkit.

Works on Python 3.9+ with no TUI dependencies. Dispatches to subcommands:
  netops scan    — Discover devices (ping + SNMP + SSH autodetect)
  netops health  — Run health checks on devices
  netops backup  — Collect device configs
  netops push    — Push config changes
  netops diff    — Show config diffs
  netops report  — Generate reports
"""

from __future__ import annotations

import sys

COMMANDS = {
    "scan": "Discover & inventory devices (ping + SNMP + SSH)",
    "health": "Run health checks on devices",
    "backup": "Collect device configurations",
    "push": "Push config changes to devices",
    "diff": "Show config differences",
    "report": "Generate network reports",
    "tui": "Launch interactive TUI (requires Python 3.10+)",
    "bastion": "Connect or disconnect the workstation-wide SSH bastion",
}


def _print_help() -> None:
    from netops import __version__
    print(f"netops-toolkit v{__version__} — network automation without the GUI\n")
    print("Usage: netops <command> [options]\n")
    print("Commands:")
    for cmd, desc in COMMANDS.items():
        print(f"  {cmd:<10} {desc}")
    print("\nRun 'netops <command> --help' for command-specific options.")


def main() -> int:
    """Dispatch the requested netops subcommand."""
    from netops import __version__

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        _print_help()
        return 0

    if sys.argv[1] in ("-V", "--version", "version"):
        print(f"netops-toolkit v{__version__}")
        return 0

    command = sys.argv[1]

    if command not in COMMANDS:
        print(f"Unknown command: {command}\n", file=sys.stderr)
        _print_help()
        return 1

    # Rewrite sys.argv so the delegate module sees itself as the entry point
    sys.argv = [f"netops {command}"] + sys.argv[2:]

    if command == "scan":
        from netops.inventory import scan
        scan.main()
    elif command == "health":
        from netops.check import health
        health.main()
    elif command == "backup":
        from netops.collect import backup
        backup.main()
    elif command == "push":
        from netops.change import push
        push.main()
    elif command == "diff":
        from netops.change import diff
        diff.main()
    elif command == "report":
        from netops.report import generator
        generator.main()
    elif command == "tui":
        try:
            from netops.tui.__main__ import main as tui_main
            tui_main()
        except ImportError:
            print(
                "Error: TUI requires Python 3.10+ and textual.\n"
                "Install with: pip install 'netops-toolkit[tui]'\n"
                "Or use CLI commands directly: netops scan, netops health, etc.",
                file=sys.stderr,
            )
            return 1

    elif command == "bastion":
        from netops.core.bastion import main as bastion_main

        return bastion_main(sys.argv[1:])

    return 0


if __name__ == "__main__":
    sys.exit(main())
