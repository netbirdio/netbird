#!/bin/bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/../getting-started-enterprise.sh"

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
cases=0

assert_tag() {
  local expected_status="$1" expected_message="$2" actual_status=0
  shift 2
  local label="${1-<unset>}"

  # Each call needs its own process because die exits rather than returning.
  (
    unset NETBIRD_TRAEFIK_TAG
    if [[ $# -gt 0 ]]; then
      NETBIRD_TRAEFIK_TAG="$1"
    fi
    check_traefik_tag
  ) >"$test_dir/stdout" 2>"$test_dir/stderr" || actual_status=$?

  if [[ "$actual_status" != "$expected_status" ]]; then
    echo "Tag '$label': expected exit $expected_status, got $actual_status" >&2
    cat "$test_dir/stderr" >&2
    exit 1
  fi
  if [[ -s "$test_dir/stdout" ]]; then
    echo "Tag '$label': unexpected output on stdout" >&2
    cat "$test_dir/stdout" >&2
    exit 1
  fi
  if [[ -n "$expected_message" ]]; then
    if ! grep -Fq "$expected_message" "$test_dir/stderr"; then
      echo "Tag '$label': expected diagnostic '$expected_message'" >&2
      cat "$test_dir/stderr" >&2
      exit 1
    fi
  elif [[ -s "$test_dir/stderr" ]]; then
    echo "Tag '$label': unexpected output on stderr" >&2
    cat "$test_dir/stderr" >&2
    exit 1
  fi
  cases=$((cases + 1))
}

# Unset and empty overrides both select the installer's default image.
assert_tag 0 ""
assert_tag 0 "" ""

for tag in v3.7.13 3.7.13 v3.7.14 v3.8 3.8 v4.0 v4.0.0 \
  v03.07.013 v3.08.0 v3.7.019; do
  assert_tag 0 "" "$tag"
done

for tag in v2.11.0 v3.6.20 v3.7 3.7 v3.7.11 v3.7.12 3.7.12 \
  v03.07.012 v3.7.08; do
  assert_tag 1 "predates aliasHeadersStrategy" "$tag"
done

for tag in latest custom-build v2 v3 sha256:abcdef v3.7.11-alpine \
  v3.7.13-alpine v3.7.13-rc1 v3.7.14+custom v3.7.14@sha256:abcdef \
  3..14 v3.7.14.0 " 3.7.14" $'v3.7.14\n'; do
  assert_tag 1 "Cannot verify NETBIRD_TRAEFIK_TAG=" "$tag"
done

echo "Passed $cases Traefik tag validation cases."
