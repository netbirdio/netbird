#!/usr/bin/env bash
set -euo pipefail

# Imports GPG signing keys for deb and rpm package signing.
# Expects env vars: GPG_DEB_PRIVATE_KEY, GPG_DEB_PASSPHRASE, GPG_RPM_PRIVATE_KEY, GPG_RPM_PASSPHRASE
# Outputs: GPG_DEB_KEY_FILE and GPG_RPM_KEY_FILE written to $GITHUB_ENV

import_key() {
    local name="$1"
    local b64_key="$2"
    local passphrase="$3"
    local out_file="$4"
    local tmp_file="/tmp/gpg-${name}-import.gpg"

    echo "=== Importing ${name} key ==="

    echo "--- base64 decode ---"
    echo "$b64_key" | base64 -d > "$tmp_file"
    echo "Decoded file size: $(wc -c < "$tmp_file") bytes"
    file "$tmp_file"

    echo "--- import ---"
    printf '%s' "$passphrase" | gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase-fd 0 --import "$tmp_file"

    # Extract the fingerprint of the imported key
    local fpr
    fpr=$(gpg --with-colons --show-keys "$tmp_file" 2>/dev/null | awk -F: '/^fpr:/ { print $10; exit }')
    echo "Key fingerprint: $fpr"

    echo "--- remove passphrase from key $fpr ---"
    printf '%s\n\n' "$passphrase" | gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase-fd 0 --passwd "$fpr"

    echo "--- export key $fpr ---"
    gpg --batch --yes --no-tty --pinentry-mode loopback --passphrase "" --export-secret-keys --armor "$fpr" > "$out_file"
    echo "Exported key size: $(wc -c < "$out_file") bytes"

    rm -f "$tmp_file"
    echo "=== ${name} key imported successfully ==="
    echo ""
}

import_key "deb" "$GPG_DEB_PRIVATE_KEY" "$GPG_DEB_PASSPHRASE" "/tmp/gpg-deb-signing-key.asc"

if [ -n "${GITHUB_ENV:-}" ]; then
    echo "GPG_DEB_KEY_FILE=/tmp/gpg-deb-signing-key.asc" >> "$GITHUB_ENV"
fi

import_key "rpm" "$GPG_RPM_PRIVATE_KEY" "$GPG_RPM_PASSPHRASE" "/tmp/gpg-rpm-signing-key.asc"

if [ -n "${GITHUB_ENV:-}" ]; then
    echo "GPG_RPM_KEY_FILE=/tmp/gpg-rpm-signing-key.asc" >> "$GITHUB_ENV"
fi
