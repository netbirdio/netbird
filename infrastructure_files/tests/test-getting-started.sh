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
    if ! grep -Fxq "    image: ${image:-traefik:v3.7.14}" "$case_dir/docker-compose.yml"; then
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

file_mode() {
  local file="$1"
  stat -c '%a' "$file" 2>/dev/null || stat -f '%OLp' "$file"
}

service_block() {
  local name="$1"
  awk -v s="  ${name}:" '$0 == s { p = 1; print; next } p && (/^[^ ]/ || /^  [^ ]/) { exit } p'
}

render_proxy_stack() {
  local case_dir="$1"
  mkdir -p "$case_dir"
  (
    cd "$case_dir"
    initialize_default_values
    NETBIRD_DOMAIN=netbird.test
    NETBIRD_NON_INTERACTIVE=true
    NETBIRD_REVERSE_PROXY_TYPE=0
    NETBIRD_LETSENCRYPT_EMAIL=admin@example.com
    NETBIRD_ENABLE_PROXY=true
    NETBIRD_ENABLE_CROWDSEC="$2"
    unset NETBIRD_ENABLE_CROWDSEC_APPSEC
    if [[ -n "${3:-}" ]]; then
      NETBIRD_ENABLE_CROWDSEC_APPSEC="$3"
    fi
    configure_reverse_proxy
    generate_configuration_files
  )
}

assert_appsec_enabled() {
  local case_dir="$test_dir/appsec-on"
  render_proxy_stack "$case_dir" true true
  local compose="$case_dir/docker-compose.yml"
  local key
  key=$(sed -n 's/^CROWDSEC_DASHBOARD_BOUNCER_KEY=//p' "$case_dir/.env")
  if [[ ! "$key" =~ ^[0-9a-f]{64}$ ]]; then
    echo "AppSec: dashboard bouncer key was not written" >&2
    exit 1
  fi
  if [[ "$(file_mode "$case_dir/.env")" != "600" ]]; then
    echo "AppSec: .env mode is $(file_mode "$case_dir/.env"), expected 600" >&2
    exit 1
  fi
  if grep -Fq "$key" "$compose"; then
    echo "AppSec: dashboard bouncer key was written into docker-compose.yml" >&2
    exit 1
  fi
  for line in \
    'github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin' \
    'version=v1.7.1' \
    'crowdsecAppsecHost=crowdsec:7422' \
    'crowdsecAppsecFailureBlock=true' \
    'crowdsecAppsecUnreachableBlock=true' \
    'netbird-dashboard.middlewares=netbird-dashboard-crowdsec@docker' \
    'netbird-dashboard-api.middlewares=netbird-dashboard-crowdsec@docker' \
    'netbird-dashboard-api.priority=110' \
    'crowdsecurity/appsec-virtual-patching' \
    'crowdsecurity/appsec-generic-rules' \
    'start_period: 30s'; do
    if ! grep -Fq "$line" "$compose"; then
      echo "AppSec: missing '$line' in docker-compose.yml" >&2
      exit 1
    fi
  done
  for line in \
    'listen_addr: 0.0.0.0:7422' \
    'crowdsecurity/appsec-default' \
    'source: appsec'; do
    if ! grep -Fq "$line" "$case_dir/crowdsec/acquis.d/appsec.yaml"; then
      echo "AppSec: missing '$line' in appsec.yaml" >&2
      exit 1
    fi
  done
  local traefik dashboard server crowdsec
  traefik=$(service_block traefik < "$compose")
  dashboard=$(service_block dashboard < "$compose")
  server=$(service_block netbird-server < "$compose")
  crowdsec=$(service_block crowdsec < "$compose")
  if [[ "$traefik" != *$'depends_on:\n      crowdsec:\n        condition: service_healthy'* ]]; then
    echo "AppSec: Traefik does not wait for CrowdSec" >&2
    exit 1
  fi
  # Both sides must read the same key from .env. The middleware belongs on the
  # Traefik service: declared on the dashboard container, a restart would drop
  # it and the routers would fail open.
  if ! grep -Fq 'crowdsecLapiKey=${CROWDSEC_DASHBOARD_BOUNCER_KEY}' <<< "$traefik"; then
    echo "AppSec: Traefik service does not read the dashboard bouncer key" >&2
    exit 1
  fi
  if ! grep -Fq 'BOUNCER_KEY_netbird_dashboard: "${CROWDSEC_DASHBOARD_BOUNCER_KEY}"' <<< "$crowdsec"; then
    echo "AppSec: crowdsec service does not register the dashboard bouncer key" >&2
    exit 1
  fi
  if ! grep -Fq 'netbird-dashboard.middlewares=netbird-dashboard-crowdsec@docker' <<< "$dashboard"; then
    echo "AppSec: dashboard router is not protected" >&2
    exit 1
  fi
  if ! grep -Fq 'netbird-dashboard-api.middlewares=netbird-dashboard-crowdsec@docker' <<< "$server"; then
    echo "AppSec: API router is not protected" >&2
    exit 1
  fi
  # A path missing from this rule falls through to the uninspected backend
  # router at priority 100.
  local api_rule
  api_rule=$(grep -F 'netbird-dashboard-api.rule=' <<< "$server")
  for match in 'Host(`netbird.test`)' 'PathPrefix(`/api`)' 'PathPrefix(`/oauth2`)'; do
    if [[ "$api_rule" != *"$match"* ]]; then
      echo "AppSec: API router rule does not match $match" >&2
      exit 1
    fi
  done
  if ! grep -Fq 'netbird-dashboard-api.service=netbird-server' <<< "$server"; then
    echo "AppSec: API router does not target netbird-server" >&2
    exit 1
  fi
  if [[ "$server" == *'netbird-dashboard-api.rule='*'/relay'* ]]; then
    echo "AppSec: API router includes relay" >&2
    exit 1
  fi
  if grep -F 'netbird-grpc' <<< "$server" | grep -q 'crowdsec'; then
    echo "AppSec: gRPC router gained the AppSec middleware" >&2
    exit 1
  fi
  if grep -Fq 'netbird-backend.middlewares' "$compose" || grep -Fq 'proxy-passthrough.middlewares' "$compose"; then
    echo "AppSec: middleware attached outside the dashboard and API routers" >&2
    exit 1
  fi
  cases=$((cases + 1))
}

assert_appsec_disabled() {
  local case_dir="$test_dir/appsec-off"
  render_proxy_stack "$case_dir" true ""
  if [[ -e "$case_dir/.env" || -e "$case_dir/crowdsec/acquis.d/appsec.yaml" ]]; then
    echo "AppSec off: generated AppSec files" >&2
    exit 1
  fi
  if grep -Fq 'appsec' "$case_dir/docker-compose.yml" || grep -Fq '7422' "$case_dir/docker-compose.yml"; then
    echo "AppSec off: CrowdSec-only compose includes AppSec" >&2
    exit 1
  fi
  if ! grep -Fq 'COLLECTIONS: crowdsecurity/linux' "$case_dir/docker-compose.yml"; then
    echo "AppSec off: missing the base CrowdSec collection" >&2
    exit 1
  fi
  cases=$((cases + 1))
}

assert_appsec_requires_crowdsec() {
  local status=0
  (
    initialize_default_values
    NETBIRD_NON_INTERACTIVE=true
    NETBIRD_REVERSE_PROXY_TYPE=0
    NETBIRD_LETSENCRYPT_EMAIL=admin@example.com
    NETBIRD_ENABLE_PROXY=true
    NETBIRD_ENABLE_CROWDSEC=false
    NETBIRD_ENABLE_CROWDSEC_APPSEC=true
    configure_reverse_proxy
  ) >"$test_dir/appsec-requires.out" 2>"$test_dir/appsec-requires.err" || status=$?
  if [[ "$status" -eq 0 ]] || ! grep -Fq 'requires NETBIRD_ENABLE_CROWDSEC=true' "$test_dir/appsec-requires.err"; then
    echo "AppSec without CrowdSec: expected the install to stop" >&2
    cat "$test_dir/appsec-requires.err" >&2
    exit 1
  fi
  cases=$((cases + 1))
}

assert_appsec_enabled
assert_appsec_disabled
assert_appsec_requires_crowdsec

echo "Passed $cases configuration cases."
