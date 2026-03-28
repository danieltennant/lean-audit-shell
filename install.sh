#!/usr/bin/env bash
# install.sh — build and install leash on macOS
#
# Usage:
#   ./install.sh              # installs to ~/.local/bin
#   INSTALL_DIR=/usr/local/bin ./install.sh
#
# The script will:
#   1. Check prerequisites (Rust toolchain, zsh)
#   2. Build the release binary
#   3. Install to INSTALL_DIR (created if absent)
#   4. Create the default config directory
#   5. Print next-steps instructions

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/leash"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/leash"
BINARY_NAME="leash"

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[leash]${NC} $*"; }
warn()  { echo -e "${YELLOW}[leash]${NC} $*"; }
error() { echo -e "${RED}[leash] error:${NC} $*" >&2; exit 1; }

# ── Prerequisites ──────────────────────────────────────────────────────────────
info "Checking prerequisites..."

command -v cargo >/dev/null 2>&1 \
    || error "Rust toolchain not found. Install from https://rustup.rs and try again."

command -v zsh >/dev/null 2>&1 \
    || warn "zsh not found at default locations — leash will fall back to bash."

# ── Build ──────────────────────────────────────────────────────────────────────
info "Building release binary (cargo build --release)..."
cargo build --release

BUILT="$(pwd)/target/release/$BINARY_NAME"
[[ -f "$BUILT" ]] || error "Build succeeded but binary not found at $BUILT"

# ── Install binary ─────────────────────────────────────────────────────────────
info "Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp "$BUILT" "$INSTALL_DIR/$BINARY_NAME"
chmod +x "$INSTALL_DIR/$BINARY_NAME"

# ── Create config and data dirs ────────────────────────────────────────────────
info "Creating config directory: $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"

info "Creating data directory:   $DATA_DIR"
mkdir -p "$DATA_DIR"

# Write a starter config only if one doesn't already exist
CONFIG_FILE="$CONFIG_DIR/config.toml"
if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" <<'TOML'
# leash configuration — https://github.com/danieltennant/lean-audit-shell

[shell]
# "auto" detects zsh on macOS (fallback: bash)
underlying = "auto"

[audit.local]
enabled = true
# log_path = "~/.local/share/leash/audit.log"  # default

[audit.remote]
# Set enabled = true and rebuild with --features otel to export via OTLP
enabled = false

[filter]
enabled = true

# Example rules — uncomment and customise as needed:

# [[filter.rules]]
# id       = "no-curl-pipe-sh"
# pattern  = "curl .* \\| (bash|sh|zsh)"
# match    = "regex"
# severity = "block"
# reason   = "Piping curl output to a shell is a security risk."

# [[filter.rules]]
# id       = "warn-force-push"
# pattern  = "git push.*--force"
# match    = "regex"
# severity = "warn"
# reason   = "Force push detected — ensure this is intentional."
TOML
    info "Wrote starter config to $CONFIG_FILE"
else
    info "Config already exists at $CONFIG_FILE — leaving unchanged."
fi

# ── PATH check ────────────────────────────────────────────────────────────────
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    warn "$INSTALL_DIR is not in your PATH."
    warn "Add the following line to your shell profile (~/.zprofile or ~/.zshrc):"
    warn ""
    warn "    export PATH=\"$INSTALL_DIR:\$PATH\""
    warn ""
fi

# ── Done ──────────────────────────────────────────────────────────────────────
info "Installation complete."
info ""
info "  Binary : $INSTALL_DIR/$BINARY_NAME"
info "  Config : $CONFIG_FILE"
info "  Logs   : $DATA_DIR/audit.log"
info ""
info "Run 'leash --version' to verify, then 'leash' to start the interactive REPL."
