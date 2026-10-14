#!/bin/bash
#
# Shared helpers for the FreeBSD port scripts. Source this file, do not run it.
#
# The FreeBSD port tracks stable NetBird releases only, so every helper here
# works on plain MAJOR.MINOR.PATCH versions and ignores canary, release
# candidate and any other prerelease tag.

GITHUB_REPO="netbirdio/netbird"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"
PORTS_MIRROR_BASE="https://raw.githubusercontent.com/freebsd/freebsd-ports/main/security/netbird"
STABLE_VERSION_RE='^[0-9]+\.[0-9]+\.[0-9]+$'

# is_stable_version reports whether the version is a plain MAJOR.MINOR.PATCH release.
is_stable_version() {
    [[ "$1" =~ $STABLE_VERSION_RE ]]
}

# fetch_stable_tags prints the stable release versions known to GitHub, oldest
# first. GITHUB_TOKEN is used when set so CI runs are not rate limited.
fetch_stable_tags() {
    local -a auth=()
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    fi

    local tags
    if ! tags=$(curl -fsL --proto '=https' --proto-redir '=https' --retry 3 \
            -H "Accept: application/vnd.github+json" "${auth[@]}" \
            "${GITHUB_API}/tags?per_page=100" 2>/dev/null); then
        echo "Error: Could not fetch tags from GitHub" >&2
        return 1
    fi

    echo "$tags" | \
        grep -oE '"name": *"v[0-9]+\.[0-9]+\.[0-9]+"' | \
        sed -E 's/.*"v([0-9]+\.[0-9]+\.[0-9]+)".*/\1/' | \
        sort -u -V
    return 0
}

# resolve_target_version validates an explicitly requested version, or picks the
# latest stable release from GitHub when none was given. A leading "v" is
# accepted so a git tag name can be passed as is.
resolve_target_version() {
    local requested="${1#v}"

    if [[ -n "$requested" ]]; then
        if ! is_stable_version "$requested"; then
            echo "Error: ${requested} is not a stable release. The FreeBSD port only tracks MAJOR.MINOR.PATCH versions." >&2
            return 1
        fi
        echo "$requested"
        return 0
    fi

    echo "Fetching latest stable release from GitHub..." >&2
    local latest
    latest=$(fetch_stable_tags | tail -1)
    if [[ -z "$latest" ]]; then
        echo "Error: Could not determine the latest stable release from GitHub" >&2
        return 1
    fi
    echo "$latest"
    return 0
}

# fetch_ports_file prints a file from the security/netbird port on the FreeBSD
# ports GitHub mirror.
fetch_ports_file() {
    local filename="$1"
    local content
    if ! content=$(curl -fsL --proto '=https' --proto-redir '=https' --retry 3 "${PORTS_MIRROR_BASE}/${filename}" 2>/dev/null); then
        echo "Error: Could not fetch ${filename} from ${PORTS_MIRROR_BASE}" >&2
        return 1
    fi
    if [[ "$content" == \<* ]]; then
        echo "Error: Received HTML instead of ${filename} from ${PORTS_MIRROR_BASE}" >&2
        return 1
    fi
    printf '%s' "$content"
    return 0
}

# fetch_current_ports_version prints the DISTVERSION currently in the ports tree.
fetch_current_ports_version() {
    echo "Fetching current version from FreeBSD ports..." >&2
    local makefile version
    makefile=$(fetch_ports_file "Makefile") || return 1
    version=$(echo "$makefile" | \
        grep -E "^DISTVERSION=" | \
        sed 's/DISTVERSION=[[:space:]]*//' | \
        tr -d '\t ')
    if [[ -z "$version" ]]; then
        echo "Error: Could not extract DISTVERSION from ports Makefile" >&2
        return 1
    fi
    echo "$version"
    return 0
}
