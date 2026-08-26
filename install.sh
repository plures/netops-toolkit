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

VENV_DIR="$HOME/.venv/netops"
REPO="https://github.com/plures/netops-toolkit"

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
  # If we're running from inside an extracted tarball, install local
  if [ -f "pyproject.toml" ] && grep -q "netops-toolkit" pyproject.toml 2>/dev/null; then
    echo "→ Installing from local source..."
    $UV pip install --python "$VENV_DIR/bin/python" ".[tui,snmp,report]" --quiet
  else
    echo "→ Installing netops-toolkit@${TAG} from GitHub..."
    $UV pip install --python "$VENV_DIR/bin/python" \
      "netops-toolkit[tui,snmp,report] @ git+${REPO}@${TAG}" --quiet
  fi
}

# ── Shell activation helper ───────────────────────────────────────────────────
setup_activation() {
  SHELL_NAME="$(basename "${SHELL:-/bin/bash}")"
  case "$SHELL_NAME" in
    zsh)  RC="$HOME/.zshrc" ;;
    fish) RC="$HOME/.config/fish/config.fish" ;;
    *)    RC="$HOME/.bashrc" ;;
  esac

  # Add alias if not already present
  if ! grep -q "netops-activate" "$RC" 2>/dev/null; then
    echo "" >> "$RC"
    echo "# netops-toolkit" >> "$RC"
    echo "alias netops-activate='source $VENV_DIR/bin/activate'" >> "$RC"
    echo "  Added 'netops-activate' alias to $RC"
  fi
}

# ── Run ───────────────────────────────────────────────────────────────────────
install_uv
select_python
create_venv
install_package
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
