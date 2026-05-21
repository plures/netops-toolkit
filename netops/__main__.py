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

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="netops",
        description="netops-toolkit CLI — network automation without the GUI",
    )
    sub = parser.add_subparsers(dest="command")

    # scan — delegates to netops.inventory.scan
    sub.add_parser("scan", help="Discover & inventory devices (ping + SNMP + SSH)")

    # health — delegates to netops.check.health
    sub.add_parser("health", help="Run health checks on devices")

    # backup — delegates to netops.collect.backup
    sub.add_parser("backup", help="Collect device configurations")

    # push — delegates to netops.change.push
    sub.add_parser("push", help="Push config changes to devices")

    # diff — delegates to netops.change.diff
    sub.add_parser("diff", help="Show config differences")

    # report — delegates to netops.report.generator
    sub.add_parser("report", help="Generate network reports")

    # tui — launch TUI if available
    sub.add_parser("tui", help="Launch interactive TUI (requires Python 3.10+)")

    args, remaining = parser.parse_known_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        from netops.inventory import scan
        sys.argv = ["netops scan"] + remaining
        scan.main()
    elif args.command == "health":
        from netops.check import health
        sys.argv = ["netops health"] + remaining
        health.main()
    elif args.command == "backup":
        from netops.collect import backup
        sys.argv = ["netops backup"] + remaining
        backup.main()
    elif args.command == "push":
        from netops.change import push
        sys.argv = ["netops push"] + remaining
        push.main()
    elif args.command == "diff":
        from netops.change import diff
        sys.argv = ["netops diff"] + remaining
        diff.main()
    elif args.command == "report":
        from netops.report import generator
        sys.argv = ["netops report"] + remaining
        generator.main()
    elif args.command == "tui":
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

    return 0


if __name__ == "__main__":
    sys.exit(main())
