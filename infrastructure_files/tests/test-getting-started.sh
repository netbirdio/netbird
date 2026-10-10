#!/bin/bash

set -eo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/../getting-started.sh"

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
cases=0

assert_image() {
  local expected_status="$1" expected_message="$2" image="$3" actual_status=0
  local case_dir="$test_dir/$cases"
  mkdir "$case_dir"

  (
    cd "$case_dir"
    TRAEFIK_IMAGE="$image"
    NETBIRD_DOMAIN=netbird.test
    NETBIRD_AGENT_NETWORK=false
    initialize_default_values
    generate_configuration_files
  ) >"$case_dir/stdout" 2>"$case_dir/stderr" || actual_status=$?

  if [[ "$actual_status" != "$expected_status" ]]; then
    echo "Image '$image': expected exit $expected_status, got $actual_status" >&2
    cat "$case_dir/stderr" >&2
    exit 1
  fi
  if [[ "$expected_status" == 0 ]]; then
    if [[ -s "$case_dir/stderr" ]]; then
      cat "$case_dir/stderr" >&2
      exit 1
    fi
    for entrypoint in web websecure; do
      if ! grep -Fq -- "--entrypoints.$entrypoint.http.aliasHeadersStrategy=delete" "$case_dir/docker-compose.yml"; then
        echo "Image '$image': missing header protection for $entrypoint" >&2
        exit 1
      fi
    done
    if ! grep -Fq "image: ${image:-traefik:v3.7.14}" "$case_dir/docker-compose.yml"; then
      echo "Image '$image': unexpected rendered image" >&2
      exit 1
    fi
  else
    if ! grep -Fq "$expected_message" "$case_dir/stderr"; then
      echo "Image '$image': expected diagnostic '$expected_message'" >&2
      cat "$case_dir/stderr" >&2
      exit 1
    fi
    if [[ -e "$case_dir/docker-compose.yml" || -e "$case_dir/config.yaml" || -e "$case_dir/dashboard.env" ]]; then
      echo "Image '$image': generated configuration despite failed validation" >&2
      exit 1
    fi
  fi
  cases=$((cases + 1))
}

# An empty override selects the default image.
assert_image 0 "" ""
for image in traefik:v3.7.13 traefik:3.7.13 traefik:v3.7.14 traefik:v3.8 \
  traefik:v4 traefik:v4.0.0 traefik:v03.07.013 traefik:v3.08.0 \
  registry.example:5000/team/traefik:3.7.13; do
  assert_image 0 "" "$image"
done

for tag in v2 v2.11.0 v3 v3.6.20 v3.7 v3.7.11 v3.7.12 v03.07.012 v3.7.08; do
  assert_image 1 "incompatible with this configuration" "traefik:$tag"
done

digest="sha256:$(printf '%064d' 0)"
for image in traefik:latest traefik:custom-build traefik registry.example:5000/traefik \
  "traefik@$digest" "registry.example:5000/team/traefik@$digest" \
  "traefik:v3.7.13@$digest" "traefik:latest@$digest" \
  traefik:v3.7.13-rc1 traefik:v3.7.13-alpine traefik:v3.7.14+custom \
  traefik:3..14 traefik:v3.7.14.0 traefik:custom:v3.7.14 :v3.7.14 \
  "traefik: v3.7.14" $'traefik:v3.7.14\n'; do
  assert_image 1 "Cannot verify TRAEFIK_IMAGE=" "$image"
done

echo "Passed $cases Traefik image configuration cases."
