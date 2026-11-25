"""One packaged factual prelude for the fixed isolated consuming programs."""

from pathlib import Path

_CONTEXT_PROGRAM = Path(__file__).with_name("_context_facts.py").read_text(encoding="utf-8")
