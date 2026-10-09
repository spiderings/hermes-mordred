#!/usr/bin/env bash
# Build, ad-hoc codesign, and install the mordred-hermes-sekey helper.
#
# The CryptoKit file-store design (SecureEnclave.P256 + dataRepresentation)
# does not touch the Keychain, so it needs NO keychain-access-groups
# entitlement, NO provisioning profile, and NO Developer ID identity — an
# ad-hoc signature (`codesign -s -`) is enough for Secure Enclave access.
#
# Run on a Mac with the Xcode toolchain and a Secure Enclave (Apple Silicon
# or T2). Idempotent: re-running rebuilds and re-installs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTALL_DIR="${MORDRED_SEKEY_INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="mordred-hermes-sekey"
INSTALL_TARGET="$INSTALL_DIR/$BINARY_NAME"
INSTALL_TMP=""

cleanup_install_tmp() {
    if [[ -n "$INSTALL_TMP" && -e "$INSTALL_TMP" ]]; then
        rm -f "$INSTALL_TMP"
    fi
}

sync_path() {
    # GNU/Linux can flush the filesystem containing one path. BSD/macOS sync
    # accepts no path, so use its system-wide flush without masking real I/O
    # failures behind a second fallback attempt.
    if [[ "$(uname -s)" == "Darwin" ]]; then
        sync
    else
        sync -f "$1"
    fi
}

path_mode() {
    if [[ "$(uname -s)" == "Darwin" ]]; then
        stat -f '%Lp' "$1"
    else
        stat -c '%a' "$1"
    fi
}

trap cleanup_install_tmp EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Resolve output directory before building (--show-bin-path exits immediately).
BIN_DIR="$(swift build -c release --show-bin-path)"

# `-Xlinker -S` drops the linker's debug map (N_OSO stabs carrying absolute
# object-file paths and mtimes). Without it the binary -- and so its ad-hoc
# code hash -- changes with the checkout / site-packages path and the build
# time. The login-keychain item that stores the vault anchor trusts the helper
# by that code hash, so a hash that changes on every reinstall would bring the
# keychain password dialog back once per reinstall. With it, the same source and
# toolchain always produce the same binary.
echo "==> swift build -c release (reproducible: no debug map)"
swift build -c release -Xlinker -S

BUILT_BIN="$BIN_DIR/$BINARY_NAME"
if [[ ! -f "$BUILT_BIN" ]]; then
    echo "ERROR: built binary not found at $BUILT_BIN" >&2
    exit 1
fi

echo "==> codesign (ad-hoc)"
# Ad-hoc signature is sufficient: no entitlement, no profile, no .app needed
# because the helper persists keys as SecureEnclave dataRepresentation blobs
# in plain files rather than in the Keychain.
codesign --force --sign - "$BUILT_BIN"

echo "==> Installing to $INSTALL_TARGET"
mkdir -p "$INSTALL_DIR"
if [[ -L "$INSTALL_TARGET" || ( -e "$INSTALL_TARGET" && ! -f "$INSTALL_TARGET" ) ]]; then
    echo "ERROR: install target must be a regular file or absent: $INSTALL_TARGET" >&2
    exit 1
fi
INSTALL_TMP="$(mktemp "$INSTALL_DIR/.${BINARY_NAME}.tmp.XXXXXX")"
cp "$BUILT_BIN" "$INSTALL_TMP"
chmod 0755 "$INSTALL_TMP"
sync_path "$INSTALL_TMP"
echo "==> Verifying staged signature"
codesign -dvv "$INSTALL_TMP" 2>&1 | sed 's/^/    /'
# The temp lives in INSTALL_DIR, so mv is an atomic same-filesystem rename.
# A failed copy/sync never truncates the previously-working helper.
mv -f "$INSTALL_TMP" "$INSTALL_TARGET"
INSTALL_TMP=""
if [[ -L "$INSTALL_TARGET" || ! -f "$INSTALL_TARGET" ]]; then
    echo "ERROR: installed helper is not a regular file: $INSTALL_TARGET" >&2
    exit 1
fi
if [[ "$(path_mode "$INSTALL_TARGET")" != "755" ]]; then
    echo "ERROR: installed helper is not mode 0755: $INSTALL_TARGET" >&2
    exit 1
fi
# The rename is visible but not crash-durable until its parent directory is
# synced. Surface a failure instead of claiming the helper was installed
# durably; the complete visible binary is left for inspection/retry.
sync_path "$INSTALL_DIR"

echo
echo "Installed: $INSTALL_TARGET"
echo "Smoke test: echo '{\"cmd\":\"probe\"}' | \"$INSTALL_TARGET\""
echo "Point Python at it (if not on PATH): export MORDRED_SEKEY_HELPER=\"$INSTALL_TARGET\""
