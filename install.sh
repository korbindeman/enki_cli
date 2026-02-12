#!/bin/bash
set -euo pipefail

REPO="korbindeman/enki_cli"
BINARY="enki"
INSTALL_DIR="${ENKI_INSTALL_DIR:-$HOME/.local/bin}"

info() { printf '\033[1;34m%s\033[0m\n' "$*"; }
error() { printf '\033[1;31merror: %s\033[0m\n' "$*" >&2; exit 1; }

# Detect OS
case "$(uname -s)" in
    Linux*)  OS="unknown-linux-gnu" ;;
    Darwin*) OS="apple-darwin" ;;
    *)       error "Unsupported OS: $(uname -s)" ;;
esac

# Detect architecture
case "$(uname -m)" in
    x86_64|amd64)  ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)             error "Unsupported architecture: $(uname -m)" ;;
esac

TARGET="${ARCH}-${OS}"
ASSET_NAME="${BINARY}-${TARGET}.tar.gz"

info "Installing ${BINARY} (${TARGET})..."

# Get latest release tag
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$LATEST" ]; then
    error "Could not determine latest release"
fi

info "Latest release: ${LATEST}"

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET_NAME}"

# Download and extract
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading ${DOWNLOAD_URL}..."
if ! curl -fsSL "$DOWNLOAD_URL" -o "${TMPDIR}/${ASSET_NAME}"; then
    error "Download failed. No release found for ${TARGET}."
fi

tar -xzf "${TMPDIR}/${ASSET_NAME}" -C "$TMPDIR"

# Install
mkdir -p "$INSTALL_DIR"
mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
chmod +x "${INSTALL_DIR}/${BINARY}"

info "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"

# Check if INSTALL_DIR is in PATH
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    echo ""
    info "Add ${INSTALL_DIR} to your PATH:"
    echo ""
    case "$SHELL" in
        */zsh)  echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.zshrc && source ~/.zshrc" ;;
        */bash) echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.bashrc && source ~/.bashrc" ;;
        */fish) echo "  fish_add_path ${INSTALL_DIR}" ;;
        *)      echo "  export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
    esac
    echo ""
fi

info "Done! Run 'enki login' to get started."
