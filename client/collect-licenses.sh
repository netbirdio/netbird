#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
	printf '%s\n' "usage: $0 OUTPUT_DIRECTORY" >&2
	exit 2
fi

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
output_name=$(basename "$1")
case "$output_name" in
	"" | . | .. | /)
		printf '%s\n' "OUTPUT_DIRECTORY must name a directory" >&2
		exit 2
		;;
esac
output_parent=$(CDPATH= cd -- "$(dirname "$1")" && pwd)
output="$output_parent/$output_name"
modules=$(mktemp "${TMPDIR:-/tmp}/netbird-client-licenses.modules.XXXXXX")
sorted_modules=$(mktemp "${TMPDIR:-/tmp}/netbird-client-licenses.sorted.XXXXXX")
trap 'rm -f "$modules" "$sorted_modules"' EXIT HUP INT TERM

if [ -e "$output" ] || [ -L "$output" ]; then
	printf 'output directory already exists: %s\n' "$output" >&2
	exit 1
fi
mkdir "$output"
mkdir "$output/third_party"

cp "$repo_root/LICENSE" "$output/BSD-3-Clause.txt"

cd "$repo_root"
GOOS=${GOOS:-linux} GOARCH=${GOARCH:-amd64} CGO_ENABLED=${CGO_ENABLED:-0} \
	go list -deps -f '{{with .Module}}{{if .Replace}}{{.Replace.Path}}{{"\t"}}{{.Replace.Version}}{{"\t"}}{{.Replace.Dir}}{{else}}{{.Path}}{{"\t"}}{{.Version}}{{"\t"}}{{.Dir}}{{end}}{{end}}' -tags load_wgnt_from_rsrc ./client >"$modules"
LC_ALL=C sort -u "$modules" >"$sorted_modules"

goroot=$(go env GOROOT)
for term in LICENSE PATENTS; do
	if [ ! -f "$goroot/$term" ]; then
		printf 'missing Go standard-library term: %s\n' "$goroot/$term" >&2
		exit 1
	fi
	cp "$goroot/$term" "$output/Go-$term"
done

while IFS='	' read -r module version module_dir; do
	[ -n "$module" ] || continue
	[ "$module" = "github.com/netbirdio/netbird" ] && continue

	if [ -z "$version" ] || [ ! -d "$module_dir" ]; then
		printf 'cannot collect terms for module %s at version %s\n' "$module" "$version" >&2
		exit 1
	fi

	destination="$output/third_party/$module/$version"
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
