"""Entry point for `python -m netops.tui`."""

from netops.tui import NetopsTUI


def main() -> None:
    """Launch the netops TUI."""
    app = NetopsTUI()
    app.run()


if __name__ == "__main__":
    main()
