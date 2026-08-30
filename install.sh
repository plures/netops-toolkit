#!/usr/bin/env bash
# install.sh — one-command install for netops-toolkit + TUI
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/plures/netops-toolkit/main/install.sh | bash
#   # or from the extracted tarball:
#   ./install.sh
#
# Installs into ~/.venv/netops (user-local, no sudo needed).
# After install: source ~/.venv/netops/bin/activate && netops-tui

set -euo pipefail

VENV_DIR="${NETOPS_VENV_DIR:-$HOME/.venv/netops}"
DOCS_DIR="${NETOPS_DOCS_DIR:-$HOME/.local/share/netops-toolkit/docs}"
REPO="https://github.com/plures/netops-toolkit"
SOURCE_DIR=""
SOURCE_PATH=""

cleanup_source() {
  if [ -n "$SOURCE_DIR" ] && [ -d "$SOURCE_DIR" ]; then
    rm -rf "$SOURCE_DIR"
  fi
}
trap cleanup_source EXIT

# Allow constrained jump boxes to place the virtual environment and uv cache
# on a filesystem with sufficient user quota without requiring sudo.
if [ -n "${NETOPS_UV_CACHE_DIR:-}" ]; then
  export UV_CACHE_DIR="$NETOPS_UV_CACHE_DIR"
fi

# Resolve version: env override, or fetch latest release tag from GitHub
if [ -n "${NETOPS_VERSION:-}" ]; then
  TAG="$NETOPS_VERSION"
else
  TAG=$(curl -sSL "https://api.github.com/repos/plures/netops-toolkit/releases/latest" 2>/dev/null | grep -oP '"tag_name":\s*"\K[^"]+' || echo "main")
fi

echo "╔══════════════════════════════════════╗"
echo "║  netops-toolkit installer            ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── Find or install uv (fast Python package manager) ──────────────────────────
install_uv() {
  if command -v uv &>/dev/null; then
    UV="uv"
  elif [ -x "$HOME/.local/bin/uv" ]; then
    UV="$HOME/.local/bin/uv"
  elif [ -x "$HOME/.cargo/bin/uv" ]; then
    UV="$HOME/.cargo/bin/uv"
  else
    echo "→ Installing uv (fast Python package manager)..."
    curl -LsSf https://astral.sh/uv/install.sh | sh 2>/dev/null
    UV="$HOME/.local/bin/uv"
  fi
  echo "  uv: $($UV --version)"
}

select_python() {
  local candidate candidate_major candidate_minor candidate_patch
  local python_major="" python_minor="" python_patch=""

  PYTHON=""
  while IFS= read -r candidate; do
    IFS=. read -r candidate_major candidate_minor candidate_patch <<EOF
$("$candidate" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))' 2>/dev/null || true)
EOF
    case "$candidate_major.$candidate_minor.$candidate_patch" in
      [0-9]*.[0-9]*.[0-9]*) ;;
      *) continue ;;
    esac
    if [ "$candidate_major" -lt 3 ] ||
       { [ "$candidate_major" -eq 3 ] && [ "$candidate_minor" -lt 9 ]; }; then
      continue
    fi
    if [ -z "$PYTHON" ] ||
       [ "$candidate_major" -gt "$python_major" ] ||
       { [ "$candidate_major" -eq "$python_major" ] &&
         [ "$candidate_minor" -gt "$python_minor" ]; } ||
       { [ "$candidate_major" -eq "$python_major" ] &&
         [ "$candidate_minor" -eq "$python_minor" ] &&
         [ "$candidate_patch" -gt "$python_patch" ]; }; then
      PYTHON="$candidate"
      python_major="$candidate_major"
      python_minor="$candidate_minor"
      python_patch="$candidate_patch"
    fi
  done <<EOF
$($UV python list --only-installed 2>/dev/null | awk 'NF { print $NF }')
EOF

  if [ -n "$PYTHON" ]; then
    echo "→ Using installed Python: $PYTHON"
  else
    echo "→ No compatible installed Python found; uv will provision one."
  fi
}

# ── Create venv ───────────────────────────────────────────────────────────────
create_venv() {
  if [ -d "$VENV_DIR" ]; then
    echo "→ Upgrading existing install at $VENV_DIR"
    if [ -n "$PYTHON" ]; then
      $UV venv "$VENV_DIR" --python "$PYTHON" --clear --quiet
    else
      $UV venv "$VENV_DIR" --clear --quiet
    fi
  else
    echo "→ Creating virtual environment at $VENV_DIR"
    if [ -n "$PYTHON" ]; then
      $UV venv "$VENV_DIR" --python "$PYTHON" --quiet
    else
      $UV venv "$VENV_DIR" --quiet
    fi
  fi
}

# ── Install netops-toolkit ────────────────────────────────────────────────────
install_package() {
  local package

  # An extracted release archive already contains the package source and docs.
  if [ -f "pyproject.toml" ] && grep -q "netops-toolkit" pyproject.toml 2>/dev/null; then
    echo "→ Installing from local source..."
    SOURCE_PATH="$(pwd)"
  else
    echo "→ Downloading netops-toolkit@${TAG} source and local documentation..."
    SOURCE_DIR="$(mktemp -d)"
    if ! curl -fsSL "${REPO}/archive/${TAG}.tar.gz" | tar -xz -C "$SOURCE_DIR"; then
      echo "Unable to download source documentation for ${TAG}." >&2
      return 1
    fi
    SOURCE_PATH="$(find "$SOURCE_DIR" -mindepth 1 -maxdepth 1 -type d -exec test -f '{}/pyproject.toml' \; -print -quit)"
    if [ -z "$SOURCE_PATH" ]; then
      echo "Downloaded source did not contain a netops-toolkit package." >&2
      return 1
    fi
  fi

  package="${SOURCE_PATH}[tui,snmp,report,docs]"

  if ! $UV pip install --python "$VENV_DIR/bin/python" "$package" --quiet; then
    cat >&2 <<EOF

netops-toolkit installation did not complete, so netops and netops-tui are
not available from this environment yet. A prior partial environment at:
  $VENV_DIR
will be rebuilt on the next installer run.

If uv reported disk quota or no-space errors, free cache space with:
  $UV cache clean
  (cache directory: ${UV_CACHE_DIR:-$HOME/.cache/uv})

Or choose paths on a filesystem with available quota, then retry:
  export NETOPS_VENV_DIR=/path/with/space/netops
  export NETOPS_UV_CACHE_DIR=/path/with/space/netops-uv-cache
  export UV_PYTHON_INSTALL_DIR=/path/with/space/netops-uv-python
  curl -sSL https://raw.githubusercontent.com/plures/netops-toolkit/main/install.sh | bash
EOF
    return 1
  fi
}

build_local_docs() {
  local docs_parent docs_staging
  case "$DOCS_DIR" in
    ""|/|"$HOME"|"$VENV_DIR")
      echo "NETOPS_DOCS_DIR must be a dedicated documentation directory, not $DOCS_DIR." >&2
      return 1
      ;;
  esac
  if [ ! -f "$SOURCE_PATH/mkdocs.yml" ]; then
    echo "Source documentation configuration was not found at $SOURCE_PATH/mkdocs.yml." >&2
    return 1
  fi

  docs_parent="$(dirname "$DOCS_DIR")"
  mkdir -p "$docs_parent"
  docs_staging="$(mktemp -d "$docs_parent/.netops-docs.XXXXXX")"

  echo "→ Building local documentation at $DOCS_DIR..."
  if ! "$VENV_DIR/bin/python" -m mkdocs build --strict --config-file "$SOURCE_PATH/mkdocs.yml" --site-dir "$docs_staging/site" --quiet; then
    rm -rf "$docs_staging"
    echo "Local documentation build failed; netops-toolkit was not installed completely." >&2
    return 1
  fi
  rm -rf "$DOCS_DIR"
  mv "$docs_staging/site" "$DOCS_DIR"
  rmdir "$docs_staging"
}

# ── Shell activation helper ───────────────────────────────────────────────────
setup_activation() {
  SHELL_NAME="$(basename "${SHELL:-/bin/bash}")"
  case "$SHELL_NAME" in
    zsh)  RC="$HOME/.zshrc" ;;
    fish) RC="$HOME/.config/fish/config.fish" ;;
    *)    RC="$HOME/.bashrc" ;;
  esac

  # Add or refresh the alias so it always targets the current, shell-escaped
  # venv path (relocating an existing install must not leave a stale alias).
  local escaped_venv_dir alias_line
  escaped_venv_dir=$(printf '%q' "$VENV_DIR")
  alias_line="alias netops-activate='source ${escaped_venv_dir}/bin/activate'"

  if [ -f "$RC" ] && grep -q "^alias netops-activate=" "$RC" 2>/dev/null; then
    if ! grep -qxF "$alias_line" "$RC" 2>/dev/null; then
      local tmp
      tmp="$(mktemp)"
      grep -v "^alias netops-activate=" "$RC" > "$tmp"
      mv "$tmp" "$RC"
      echo "$alias_line" >> "$RC"
      echo "  Updated 'netops-activate' alias in $RC"
    fi
  else
    echo "" >> "$RC"
    echo "# netops-toolkit" >> "$RC"
    echo "$alias_line" >> "$RC"
    echo "  Added 'netops-activate' alias to $RC"
  fi
}

# ── Run ───────────────────────────────────────────────────────────────────────
install_uv
select_python
create_venv
install_package
build_local_docs
setup_activation

echo ""
echo "✅ netops-toolkit installed successfully!"
echo ""
echo "   To use now:"
echo "     source $VENV_DIR/bin/activate"
echo "     netops-tui"
echo ""
echo "   Next time (shortcut):"
echo "     netops-activate"
echo "     netops-tui"
echo ""
echo "   Or run directly without activating:"
echo "     $VENV_DIR/bin/netops-tui"
echo ""
echo "   Local documentation:"
echo "     $DOCS_DIR/index.html"
echo "   Open it with your preferred browser, or serve it with:"
echo "     $VENV_DIR/bin/python -m http.server --directory $DOCS_DIR"
echo ""
