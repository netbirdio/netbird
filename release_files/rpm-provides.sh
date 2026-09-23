#!/bin/sh
#
# Fill the @RPM_EVR@ placeholder in the nfpm provides entries.
#
# Red Hat certification (RPM Version Handling) expects rpmbuild's ISA provide,
# netbird(x86-64) = <evr>. nfpm does not emit it and GoReleaser does not template
# the provides field, so the version is substituted before GoReleaser runs.
#
# The value has to match what nfpm derives from the same tag: a semver
# prerelease becomes a tilde suffix, and the release defaults to 1.

set -eu

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

# Not sed -i: it takes an argument on BSD but not on GNU.
sed "s/@RPM_EVR@/${EVR}/g" .goreleaser.yaml > .goreleaser.yaml.tmp
mv .goreleaser.yaml.tmp .goreleaser.yaml

# A surviving placeholder means the provides entries moved or were renamed.
if grep -n "@RPM_EVR@" .goreleaser.yaml; then
	echo "unsubstituted @RPM_EVR@ left in .goreleaser.yaml" >&2
	exit 1
fi

echo "rpm provides version: ${EVR}"
