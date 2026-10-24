#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${NETBIRD_OUTPUT:-$ROOT_DIR/netbird}"
VERSION="${NETBIRD_VERSION:-}"

lookup_dnf_version() {
    command -v dnf >/dev/null 2>&1 || return 0

    local arch
    arch="$(rpm -E '%{_arch}' 2>/dev/null || uname -m)"

    dnf -q repoquery \
        --available \
        --arch="$arch" \
        --qf '%{version}\n' \
        netbird </dev/null 2>/dev/null |
        sort -Vu |
        tail -n 1
}

lookup_rpm_version() {
    command -v rpm >/dev/null 2>&1 || return 0
    rpm -q --qf '%{VERSION}\n' netbird 2>/dev/null | head -n 1
}

if [[ -z "$VERSION" ]]; then
    VERSION="$(lookup_dnf_version)"
fi

if [[ -z "$VERSION" ]]; then
    VERSION="$(lookup_rpm_version)"
fi

if [[ -z "$VERSION" ]]; then
    VERSION="development"
fi

version_pattern='^(development|dev-[0-9A-Za-z.-]+|ci-[0-9A-Za-z.-]+|[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?)$'
if [[ ! "$VERSION" =~ $version_pattern ]]; then
    printf 'invalid NetBird version: %s\n' "$VERSION" >&2
    exit 1
fi

printf 'building NetBird version %s\n' "$VERSION"
printf 'output: %s\n' "$OUTPUT"

CGO_ENABLED="${CGO_ENABLED:-0}" go build \
    -buildvcs=false \
    -ldflags="-s -w -X github.com/netbirdio/netbird/version.version=$VERSION" \
    -o "$OUTPUT" \
    "$ROOT_DIR/client"
