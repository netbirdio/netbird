#!/bin/sh
#
# Collect the license terms shipped in /licenses of the UBI images: NetBird's
# own licenses, the Go standard library terms, and the root license files of
# every module the Go package links on the given architectures.
#
#   -l FILE   component license, copied as AGPL-3.0.txt (path from repo root)
#   -t TAGS   build tags used for the dependency walk
#   -w        add the proxy web UI's third-party licenses (needs proxy/web/node_modules)
set -eu

usage() {
	printf '%s\n' "usage: $0 [-l LICENSE_FILE] [-t TAGS] [-w] OUTPUT_DIRECTORY PACKAGE GOARCH..." >&2
	exit 2
}

component_license=""
tags=""
web=false
while getopts l:t:w opt; do
	case "$opt" in
	l) component_license=$OPTARG ;;
	t) tags=$OPTARG ;;
	w) web=true ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))
[ "$#" -ge 3 ] || usage

repo_root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
output_name=$(basename "$1")
if [ -z "$output_name" ] || [ "$output_name" = . ] || [ "$output_name" = .. ] || [ "$output_name" = / ]; then
	printf '%s\n' "OUTPUT_DIRECTORY must name a directory" >&2
	exit 2
fi
output_parent=$(CDPATH='' cd -- "$(dirname "$1")" && pwd)
output="$output_parent/$output_name"
package=$2
shift 2

if [ -e "$output" ] || [ -L "$output" ]; then
	printf 'output directory already exists: %s\n' "$output" >&2
	exit 1
fi
modules=$(mktemp "${TMPDIR:-/tmp}/netbird-licenses.modules.XXXXXX")
sorted_modules=$(mktemp "${TMPDIR:-/tmp}/netbird-licenses.sorted.XXXXXX")
# Assemble beside the target and rename on success, so a failed run leaves
# nothing behind that would block the next attempt.
staging=$(mktemp -d "$output_parent/.$output_name.XXXXXX")
trap 'rm -f "$modules" "$sorted_modules"; rm -rf "$staging"' EXIT HUP INT TERM
mkdir "$staging/third_party"

if [ -n "$component_license" ]; then
	cp "$repo_root/$component_license" "$staging/AGPL-3.0.txt"
fi
cp "$repo_root/LICENSE" "$staging/BSD-3-Clause.txt"
if [ "$web" = true ]; then
	node "$repo_root/proxy/web/scripts/third-party-licenses.mjs" >"$staging/Web-THIRD-PARTY-LICENSES"
fi

cd "$repo_root"
for arch in "$@"; do
	GOOS=${GOOS:-linux} GOARCH="$arch" CGO_ENABLED=${CGO_ENABLED:-0} \
		go list -deps -tags "$tags" -f '{{with .Module}}{{if .Replace}}{{.Replace.Path}}{{"\t"}}{{.Replace.Version}}{{"\t"}}{{.Replace.Dir}}{{else}}{{.Path}}{{"\t"}}{{.Version}}{{"\t"}}{{.Dir}}{{end}}{{end}}' "$package" >>"$modules"
done
LC_ALL=C sort -u "$modules" >"$sorted_modules"

goroot=$(go env GOROOT)
for term in LICENSE PATENTS; do
	if [ ! -f "$goroot/$term" ]; then
		printf 'missing Go standard-library term: %s\n' "$goroot/$term" >&2
		exit 1
	fi
	cp "$goroot/$term" "$staging/Go-$term"
done

while IFS='	' read -r module version module_dir; do
	[ -n "$module" ] || continue
	[ "$module" = "github.com/netbirdio/netbird" ] && continue

	if [ -z "$version" ] || [ ! -d "$module_dir" ]; then
		printf 'cannot collect terms for module %s at version %s\n' "$module" "$version" >&2
		exit 1
	fi

	destination="$staging/third_party/$module/$version"
	mkdir -p "$destination"
	printf 'module: %s\nversion: %s\n' "$module" "$version" >"$destination/MODULE"

	found=false
	for term in \
		"$module_dir"/LICENSE* "$module_dir"/License* "$module_dir"/license* \
		"$module_dir"/LICENCE* "$module_dir"/Licence* "$module_dir"/licence* \
		"$module_dir"/COPYING* "$module_dir"/Copying* "$module_dir"/copying* \
		"$module_dir"/NOTICE* "$module_dir"/Notice* "$module_dir"/notice* \
		"$module_dir"/PATENTS* "$module_dir"/Patents* "$module_dir"/patents*; do
		[ -f "$term" ] || continue
		cp "$term" "$destination/"
		found=true
	done

	if [ "$found" = false ]; then
		printf 'no root license terms found for module %s at %s\n' "$module" "$module_dir" >&2
		exit 1
	fi
done <"$sorted_modules"

mv "$staging" "$output"
