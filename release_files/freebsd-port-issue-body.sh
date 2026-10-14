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
#   - Fetch OLD version from the FreeBSD ports GitHub mirror (current version in ports tree)
#   - Fetch NEW version from the latest stable NetBird release tag on GitHub
#
# Prerelease versions (canary, rc, ...) are rejected: the port only tracks
# stable releases.

set -e

# shellcheck source=release_files/freebsd-port-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/freebsd-port-lib.sh"

OLD_VERSION="${1:-}"
NEW_VERSION="${2:-}"

if [[ -z "$OLD_VERSION" ]]; then
    OLD_VERSION=$(fetch_current_ports_version)
    echo "Detected OLD version from FreeBSD ports: $OLD_VERSION" >&2
fi

if [[ -z "$NEW_VERSION" ]]; then
    NEW_VERSION=$(resolve_target_version "")
    echo "Detected NEW version from GitHub: $NEW_VERSION" >&2
else
    NEW_VERSION=$(resolve_target_version "$NEW_VERSION")
fi

if [[ "$OLD_VERSION" = "$NEW_VERSION" ]]; then
    echo "Warning: OLD and NEW versions are the same ($OLD_VERSION). Port may already be up to date." >&2
fi

echo "" >&2

OUTPUT_DIR="${OUTPUT_DIR:-.}"

fetch_releases_between_versions() {
    echo "Fetching release history from GitHub..." >&2

    # List the stable releases after OLD up to and including NEW
    fetch_stable_tags | \
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

cat << EOT > "$OUTPUT_FILE"
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
EOT

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
