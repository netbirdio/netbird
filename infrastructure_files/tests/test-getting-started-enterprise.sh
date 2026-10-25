#!/bin/bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/../getting-started-enterprise.sh"

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
cases=0

for errexit in +o -o; do
  for pipefail in +o -o; do
    bash -c '
      set "$1" errexit
      set "$2" pipefail
      before_options=$SHELLOPTS
      source "$3"
      if [[ "$SHELLOPTS" != "$before_options" ]]; then
        echo "Sourcing changed shell options: $before_options -> $SHELLOPTS" >&2
        exit 1
      fi
    ' bash "$errexit" "$pipefail" "$script_dir/../getting-started-enterprise.sh"
  done
done

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

# Re-rendering an install that has no header config must not add a blank line
# to the Traefik command list.
for header_config in "" "$TRAEFIK_HEADER_CONFIG"; do
  rendered=$(TRAEFIK_HEADER_CONFIG="$header_config" render_compose_common)
  if [[ "$(printf '%s\n' "$rendered" | service_block traefik)" == *$'\n\n'* ]]; then
    echo "Traefik command list has a blank line (header config: '${header_config:-<empty>}')" >&2
    exit 1
  fi
  cases=$((cases + 1))
done

echo "Passed $cases Traefik tag validation cases."

render_enterprise() {
  NETBIRD_TRAFFIC_FLOW=no
  NETBIRD_PROXY=yes
  NETBIRD_CROWDSEC=yes
  NETBIRD_CROWDSEC_APPSEC="$1"
  CUSTOM_TLS_CERTS=""
  render_docker_compose
}

assert_enterprise_appsec() {
  local rendered traefik server
  rendered=$(render_enterprise yes)
  traefik=$(printf '%s\n' "$rendered" | service_block traefik)
  server=$(printf '%s\n' "$rendered" | service_block netbird-server)
  if [[ "$traefik" == *$'\n\n'* ]]; then
    echo "AppSec: Traefik service contains a blank line" >&2
    exit 1
  fi
  for line in \
    'github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin' \
    'version=v1.7.1' \
    'condition: service_healthy' \
    'crowdsecAppsecHost=crowdsec:7422' \
    'middlewares=netbird-dashboard-crowdsec@docker,nb-security@docker' \
    'netbird-dashboard-api.priority=110' \
    'crowdsecurity/appsec-virtual-patching' \
    './crowdsec/acquis.d:/etc/crowdsec/acquis.d:ro' \
    'start_period: 30s'; do
    if ! grep -Fq "$line" <<< "$rendered"; then
      echo "AppSec: missing '$line'" >&2
      exit 1
    fi
  done
  if grep -F 'netbird-dashboard-api.rule' <<< "$server" | grep -q '/relay'; then
    echo "AppSec: API router includes relay" >&2
    exit 1
  fi
  if grep -F 'netbird-grpc' <<< "$server" | grep -q 'crowdsec'; then
    echo "AppSec: gRPC router gained the AppSec middleware" >&2
    exit 1
  fi
  if grep -F 'netbird-backend.middlewares' <<< "$server" | grep -q 'crowdsec'; then
    echo "AppSec: relay router gained the AppSec middleware" >&2
    exit 1
  fi
  if grep -Fq 'proxy-passthrough.middlewares' <<< "$rendered"; then
    echo "AppSec: proxy passthrough gained a middleware" >&2
    exit 1
  fi
  if ! grep -Fq 'netbird-grpc.middlewares=nb-security@docker' <<< "$server"; then
    echo "AppSec: gRPC router lost nb-security" >&2
    exit 1
  fi
  cases=$((cases + 1))
}

assert_enterprise_crowdsec_only() {
  local rendered
  rendered=$(render_enterprise no)
  if grep -Fq 'appsec' <<< "$rendered" || grep -Fq '7422' <<< "$rendered"; then
    echo "AppSec off: CrowdSec-only compose includes AppSec" >&2
    exit 1
  fi
  if ! grep -Fq 'COLLECTIONS=crowdsecurity/linux' <<< "$rendered"; then
    echo "AppSec off: missing the base CrowdSec collection" >&2
    exit 1
  fi
  if ! grep -Fq 'middlewares=nb-security@docker' <<< "$rendered"; then
    echo "AppSec off: dashboard lost nb-security" >&2
    exit 1
  fi
  cases=$((cases + 1))
}

assert_dashboard_key_preserved() {
  local case_dir="$test_dir/dashboard-key"
  mkdir -p "$case_dir"
  (
    cd "$case_dir"
    printf 'CROWDSEC_DASHBOARD_BOUNCER_KEY=existingkey\n' > .env
    NETBIRD_CROWDSEC_APPSEC=yes
    ensure_crowdsec_dashboard_key
    if [[ -n "${CROWDSEC_DASHBOARD_BOUNCER_KEY}" ]]; then
      echo "AppSec: existing dashboard bouncer key was replaced" >&2
      exit 1
    fi
    if [[ "$(env_get CROWDSEC_DASHBOARD_BOUNCER_KEY)" != "existingkey" ]]; then
      echo "AppSec: existing dashboard bouncer key changed" >&2
      exit 1
    fi
    rm -f .env
    NETBIRD_CROWDSEC_APPSEC=yes
    ensure_crowdsec_dashboard_key
    if [[ ! "$CROWDSEC_DASHBOARD_BOUNCER_KEY" =~ ^[0-9a-f]{64}$ ]]; then
      echo "AppSec: new dashboard bouncer key was not generated" >&2
      exit 1
    fi
    generated=$CROWDSEC_DASHBOARD_BOUNCER_KEY
    rendered=$(render_env_dashboard_bouncer_key)
    if [[ "$rendered" != "CROWDSEC_DASHBOARD_BOUNCER_KEY=${generated}" ]]; then
      echo "AppSec: dashboard bouncer key was not rendered into .env" >&2
      exit 1
    fi
    CROWDSEC_DASHBOARD_BOUNCER_KEY=""
    if [[ -n "$(render_env_dashboard_bouncer_key)" ]]; then
      echo "AppSec: empty dashboard bouncer key would overwrite .env" >&2
      exit 1
    fi
  )
  cases=$((cases + 1))
}

assert_enterprise_appsec
assert_enterprise_crowdsec_only
assert_dashboard_key_preserved

echo "Passed $cases enterprise configuration cases."
