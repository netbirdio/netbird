#!/bin/sh
# Builds netbird.pp.bz2 from the policy sources next to this script.
# Needs selinux-policy-devel (Fedora, RHEL and derivatives).
#
# Usage: build.sh [output-dir]

set -eu

src="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$src}"
devel="${SELINUX_DEVEL:-/usr/share/selinux/devel}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cp "$src/netbird.te" "$src/netbird.fc" "$src/netbird.if" "$work/"
make -C "$work" -f "$devel/Makefile" netbird.pp

mkdir -p "$out"
bzip2 -9 -c "$work/netbird.pp" > "$out/netbird.pp.bz2"
