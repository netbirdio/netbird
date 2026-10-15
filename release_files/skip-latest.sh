#!/usr/bin/env bash
# Decide whether a release tag should move the "latest" pointers: the Docker
# `latest` tags, the Homebrew formula, GitHub's "Latest release" (set by the
# signing pipeline, which also updates the cask and Chocolatey) and the
# FreeBSD port.
#
# Prints the value for SKIP_LATEST: "true" means leave them alone, "false"
# means this tag is the newest release line and may move them. The name
# matches the variable so nothing has to invert the answer at the call site.
#
# Usage: release_files/skip-latest.sh v0.81.0
#
# Candidate tags come from `git tag -l 'v*'` in the current repository, so the
# checkout needs the tags. Set SKIP_LATEST_TAGS to a newline-separated list to
# supply them directly -- which is what the tests do:
#
#   SKIP_LATEST_TAGS='v0.80.3
#   v0.81.0' release_files/skip-latest.sh v0.80.3
#
# It is the variable being *set* that switches the source, not it being
# non-empty, so an empty value is an empty list rather than "ask git".
#
# The tag itself must be in the list. If it isn't, the list is broken -- a
# checkout without tags, an empty ls-remote -- and the script exits 1 rather
# than guess, since every guess about an empty list would move latest.
#
# Two rules, in order:
#
#   1. A prerelease tag never moves latest.
#   2. Otherwise it moves latest only if its version is >= the newest release
#      already tagged, so a patch on an older line cannot drag it backwards.
#
# Prereleases are excluded from "newest release" deliberately. `sort -V`
# orders 0.81.0-rc.1 *after* 0.81.0 -- unlike semver it treats `-` as an
# ordinary separator, and only `~` sorts lower. Leaving release candidates in
# the comparison would make a release look older than its own RC, and latest
# would never move.
set -euo pipefail

tag=${1:-}
if [ -z "$tag" ]; then
  echo "usage: $0 <tag>" >&2
  exit 2
fi

version=${tag#v}

if [ -n "${SKIP_LATEST_TAGS+set}" ]; then
  candidates=$SKIP_LATEST_TAGS
else
  candidates=$(git tag -l 'v*')
fi

# A here-string, not printf piped into grep -q: grep exits at the first match,
# and under pipefail the SIGPIPE that leaves printf with would read as a miss.
if ! grep -Fxq -- "$tag" <<<"$candidates"; then
  echo "$0: $tag is not in the tag list -- refusing to decide on a broken list" >&2
  exit 1
fi

# Strip the v prefix, drop anything holding a hyphen (prereleases, canaries,
# the odd -hotfix-N), and take the highest. `sed` rather than `grep -v` so an
# empty result is not a pipeline failure.
newest=$(printf '%s\n' "$candidates" \
  | sed -E 's/^v//; /-/d; /^$/d' \
  | sort -uV \
  | tail -1)

skip=true
if [ "${version#*-}" != "$version" ]; then
  echo ":: $version is a prerelease -- latest never moves" >&2
elif [ "$(printf '%s\n%s\n' "$version" "$newest" | sort -V | tail -1)" = "$version" ]; then
  skip=false
  echo ":: $version is the newest release -- it moves latest" >&2
else
  echo ":: $version is older than $newest -- latest stays where it is" >&2
fi

printf '%s\n' "$skip"
