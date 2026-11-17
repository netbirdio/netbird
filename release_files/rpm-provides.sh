#!/bin/sh
#
# Write .goreleaser.generated.yaml with the @RPM_EVR@ placeholder filled in.
#
# Red Hat certification (RPM Version Handling) expects rpmbuild's ISA provide,
# netbird(x86-64) = <evr>. nfpm does not emit it and GoReleaser does not template
# the provides field, so the version is substituted before GoReleaser runs.
#
# The value has to match what nfpm derives from the same tag: a semver
# prerelease becomes a tilde suffix, and the release defaults to 1.

set -eu

OUT=.goreleaser.generated.yaml

TAG="${GITHUB_REF#refs/tags/}"
case "$TAG" in
v*) ;;
*) TAG=$(git describe --tags --abbrev=0) ;;
esac

EVR=$(python3 - "$TAG" <<'PYEOF'
import sys

version = sys.argv[1].lstrip("v")
version, _, metadata = version.partition("+")
core, _, prerelease = version.partition("-")
if prerelease:
    core += "~" + prerelease.replace("-", "_")
if metadata:
    core += "+" + metadata
print("{}-1".format(core))
PYEOF
)

# Written to a separate, ignored file: GoReleaser refuses to release from a
# dirty tree, so .goreleaser.yaml itself must stay untouched.
sed "s/@RPM_EVR@/${EVR}/g" .goreleaser.yaml > "$OUT"

# A surviving placeholder means the provides entries moved or were renamed.
if grep -n "@RPM_EVR@" "$OUT"; then
	echo "unsubstituted @RPM_EVR@ left in $OUT" >&2
	exit 1
fi

echo "rpm provides version: ${EVR} -> ${OUT}"
