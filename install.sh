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
  PYTHON="$($UV python find --no-project --no-python-downloads '>=3.9' 2>/dev/null || true)"
  if [ -n "$PYTHON" ]; then
    echo "→ Using installed Python: $PYTHON"
  else
    echo "→ No compatible installed Python found; uv will provision one."
  fi
}

# ── Create venv ───────────────────────────────────────────────────────────────
create_venv() {
  local python_args=()
  if [ -n "$PYTHON" ]; then
    python_args=(--python "$PYTHON")
  fi

  if [ -d "$VENV_DIR" ]; then
    echo "→ Upgrading existing install at $VENV_DIR"
    $UV venv "$VENV_DIR" "${python_args[@]}" --clear --quiet
  else
    echo "→ Creating virtual environment at $VENV_DIR"
    $UV venv "$VENV_DIR" "${python_args[@]}" --quiet
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
