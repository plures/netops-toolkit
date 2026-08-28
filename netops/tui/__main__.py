"""Entry point for ``python -m netops.tui``."""

from __future__ import annotations

import argparse
import logging
import os

from netops.terminal import configure_terminal_environment


def _arguments() -> argparse.Namespace:
    """Parse launcher-only arguments before importing Textual."""
    parser = argparse.ArgumentParser(description="Launch the netops-toolkit terminal UI")
    parser.add_argument(
        "--compat",
        action="store_true",
        help="use ASCII selection markers and a conservative terminal colour palette",
    )
    return parser.parse_args()


def main() -> int:
    """Launch the TUI with compatibility chosen before Textual loads."""
    args = _arguments()
    if args.compat:
        os.environ["NETOPS_TUI_COMPAT"] = "1"
    configure_terminal_environment(os.environ)

    from netops.tui import NetopsTUI

    try:
        app = NetopsTUI()
        app.run()
        return app.return_code or 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        logging.getLogger("netops.tui").exception("TUI launcher failed")
        print("netops-tui stopped unexpectedly; details were written to the netops log.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
