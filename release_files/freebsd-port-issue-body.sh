#!/bin/bash
#
# FreeBSD Port Issue Body Generator for NetBird
#
# This script generates the issue body content for submitting a FreeBSD port update
# to the FreeBSD Bugzilla at https://bugs.freebsd.org/bugzilla/
#
# Usage: ./freebsd-port-issue-body.sh [old_version] [new_version]
# Example: ./freebsd-port-issue-body.sh 0.56.0 0.59.1
#
# If no versions are provided, the script will:
#   - Fetch OLD version from FreeBSD ports cgit (current version in ports tree)
#   - Fetch NEW version from latest NetBird GitHub release tag

set -e

GITHUB_REPO="netbirdio/netbird"
PORTS_CGIT_URL="https://cgit.freebsd.org/ports/plain/security/netbird/Makefile"

fetch_current_ports_version() {
    echo "Fetching current version from FreeBSD ports..." >&2
    local makefile_content
    makefile_content=$(curl -sL "$PORTS_CGIT_URL" 2>/dev/null)
    if [[ -z "$makefile_content" ]]; then
        echo "Error: Could not fetch Makefile from FreeBSD ports" >&2
        return 1
    fi
    echo "$makefile_content" | grep -E "^DISTVERSION=" | sed 's/DISTVERSION=[[:space:]]*//' | tr -d '\t '
    return 0
}

fetch_all_tags() {
    # Fetch tags from GitHub tags page (no rate limiting, no auth needed)
    curl -sL "https://github.com/${GITHUB_REPO}/tags" 2>/dev/null | \
        grep -oE '/releases/tag/v[0-9]+\.[0-9]+\.[0-9]+' | \
        sed 's/.*\/v//' | \
        sort -u -V
    return 0
}

fetch_latest_github_release() {
    echo "Fetching latest release from GitHub..." >&2
    local latest

    # Fetch from GitHub tags page
    latest=$(fetch_all_tags | tail -1)

    if [[ -z "$latest" ]]; then
        # Fallback to GitHub API
        latest=$(curl -sL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null | \
            grep '"tag_name"' | sed 's/.*"tag_name": *"v\([^"]*\)".*/\1/')
    fi

    if [[ -z "$latest" ]]; then
        echo "Error: Could not fetch latest release from GitHub" >&2
        return 1
    fi
    echo "$latest"
    return 0
}

OLD_VERSION="${1:-}"
NEW_VERSION="${2:-}"

if [[ -z "$OLD_VERSION" ]]; then
    OLD_VERSION=$(fetch_current_ports_version)
    if [[ -z "$OLD_VERSION" ]]; then
        echo "Error: Could not determine old version. Please provide it manually." >&2
        echo "Usage: $0 <old_version> <new_version>" >&2
        exit 1
    fi
    echo "Detected OLD version from FreeBSD ports: $OLD_VERSION" >&2
fi

if [[ -z "$NEW_VERSION" ]]; then
    NEW_VERSION=$(fetch_latest_github_release)
    if [[ -z "$NEW_VERSION" ]]; then
        echo "Error: Could not determine new version. Please provide it manually." >&2
        echo "Usage: $0 <old_version> <new_version>" >&2
        exit 1
    fi
    echo "Detected NEW version from GitHub: $NEW_VERSION" >&2
fi

if [[ "$OLD_VERSION" = "$NEW_VERSION" ]]; then
    echo "Warning: OLD and NEW versions are the same ($OLD_VERSION). Port may already be up to date." >&2
fi

echo "" >&2

OUTPUT_DIR="${OUTPUT_DIR:-.}"

fetch_releases_between_versions() {
    echo "Fetching release history from GitHub..." >&2

    # Fetch all tags and filter to those between OLD and NEW versions
    fetch_all_tags | \
        while read -r ver; do
            if [[ "$(printf '%s\n' "$OLD_VERSION" "$ver" | sort -V | head -n1)" = "$OLD_VERSION" ]] && \
               [[ "$(printf '%s\n' "$ver" "$NEW_VERSION" | sort -V | head -n1)" = "$ver" ]] && \
               [[ "$ver" != "$OLD_VERSION" ]]; then
                echo "$ver"
            fi
        done
    return 0
}

generate_changelog_section() {
    local releases
    releases=$(fetch_releases_between_versions)

    echo "Changelogs:"
    if [[ -n "$releases" ]]; then
        echo "$releases" | while read -r ver; do
            echo "https://github.com/${GITHUB_REPO}/releases/tag/v${ver}"
        done
    else
        echo "https://github.com/${GITHUB_REPO}/releases/tag/v${NEW_VERSION}"
    fi
    return 0
}

OUTPUT_FILE="${OUTPUT_DIR}/netbird-${NEW_VERSION}-issue.txt"

cat << EOF > "$OUTPUT_FILE"
BUGZILLA ISSUE DETAILS
======================

Severity: Affects Some People

Summary: security/netbird: Update to ${NEW_VERSION}

Description:
------------
security/netbird: Update ${OLD_VERSION} => ${NEW_VERSION}

$(generate_changelog_section)

Commit log:
https://github.com/${GITHUB_REPO}/compare/v${OLD_VERSION}...v${NEW_VERSION}
EOF

echo "========================================="
echo "Issue body saved to: ${OUTPUT_FILE}"
echo "========================================="
echo ""
cat "$OUTPUT_FILE"
echo ""
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Go to https://bugs.freebsd.org/bugzilla/ and login"
echo "2. Click 'Report an update or defect to a port'"
echo "3. Fill in:"
echo "   - Severity: Affects Some People"
echo "   - Summary: security/netbird: Update to ${NEW_VERSION}"
echo "   - Description: Copy content from ${OUTPUT_FILE}"
echo "4. Attach diff file: netbird-${NEW_VERSION}.diff"
echo "5. Submit the bug report"
