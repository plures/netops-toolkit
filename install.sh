#!/usr/bin/env bash
# Guided protected source setup. No curl-to-shell, global install or rc changes.
set -euo pipefail
umask 077
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NETOPS_DOCS_DIR="${NETOPS_DOCS_DIR:-${HOME}/.netops-docs}"
PYTHON="${NETOPS_PYTHON:-}"
if [ -z "$PYTHON" ]; then
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      PYTHON="$(command -v "$candidate")"
      break
    fi
  done
fi
if [ -z "$PYTHON" ]; then
  echo "Existing Python unavailable. No runtime was acquired; setup review requires a compatible interpreter." >&2
  exit 3
fi
"$PYTHON" -I -B -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 3)'
if [ ! -f "$ROOT_DIR/netops/setup.py" ]; then
  echo "Select a reviewed local source containing netops/setup.py." >&2
  exit 3
fi
# Preserve the [tui,snmp,report,docs] contract through registry selection, not pip.
# The owned bridge executes Python -m mkdocs build --strict --config-file
# <reviewed-source>/mkdocs.yml --site-dir <new-owned-output>/site.
if [ "${1:-}" = "--docs-only" ]; then
  exec "$PYTHON" -I -B -c \
    'import sys,site; sys.path.insert(0,sys.argv.pop(1)); p=site.getusersitepackages(); sys.path.extend([p] if isinstance(p,str) else p); from netops.dependencies._documentation import _main; raise SystemExit(_main())' \
    "$ROOT_DIR" --source "$ROOT_DIR" --output "$NETOPS_DOCS_DIR"
fi
# Pass action, --root, --checkpoint and explicit capability/companion selections to the
# same registered source entry point. Its default selected scope is full toolkit.
"$PYTHON" -I -B -c \
  'import sys; sys.path.insert(0,sys.argv.pop(1)); from netops.setup import main; raise SystemExit(main())' \
  "$ROOT_DIR" "$@"
case "${1:-install}" in
  install|update)
    exec "$PYTHON" -I -B -c \
      'import sys,site; sys.path.insert(0,sys.argv.pop(1)); p=site.getusersitepackages(); sys.path.extend([p] if isinstance(p,str) else p); from netops.dependencies._documentation import _main; raise SystemExit(_main())' \
      "$ROOT_DIR" --source "$ROOT_DIR" --output "$NETOPS_DOCS_DIR"
    ;;
esac
