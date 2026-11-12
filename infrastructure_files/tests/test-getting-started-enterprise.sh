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
  local rendered traefik dashboard server crowdsec
  rendered=$(render_enterprise yes)
  traefik=$(printf '%s\n' "$rendered" | service_block traefik)
  dashboard=$(printf '%s\n' "$rendered" | service_block dashboard)
  server=$(printf '%s\n' "$rendered" | service_block netbird-server)
  crowdsec=$(printf '%s\n' "$rendered" | service_block crowdsec)
  if [[ "$traefik" == *$'\n\n'* ]]; then
    echo "AppSec: Traefik service contains a blank line" >&2
    exit 1
  fi
  # netbird-server also waits on a healthy Postgres, so the dependency has to
  # be found inside the Traefik block and name crowdsec.
  if [[ "$traefik" != *$'depends_on:\n      crowdsec:\n        condition: service_healthy'* ]]; then
    echo "AppSec: Traefik does not wait for CrowdSec" >&2
    exit 1
  fi
  for line in \
    'github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin' \
    'version=v1.7.1' \
    'crowdsecLapiKey=${CROWDSEC_DASHBOARD_BOUNCER_KEY}' \
    'crowdsecAppsecHost=crowdsec:7422' \
    'crowdsecAppsecFailureBlock=true' \
    'crowdsecAppsecUnreachableBlock=true'; do
    if ! grep -Fq "$line" <<< "$traefik"; then
      echo "AppSec: Traefik service is missing '$line'" >&2
      exit 1
    fi
  done
  if ! grep -Fq 'netbird-dashboard.middlewares=netbird-dashboard-crowdsec@docker,nb-security@docker' <<< "$dashboard"; then
    echo "AppSec: dashboard router is not protected" >&2
    exit 1
  fi
  local api_rule backend_rule
  api_rule=$(sed -n 's/^ *- traefik\.http\.routers\.netbird-dashboard-api\.rule=//p' <<< "$server")
  if [[ "$api_rule" != 'Host(`${NETBIRD_DOMAIN}`) && (PathPrefix(`/api`) || PathPrefix(`/oauth2`))' ]]; then
    echo "AppSec: API router has an unexpected rule: $api_rule" >&2
    exit 1
  fi
  # A missing AppSec middleware disables the protected routers. The backend
  # must not match API or OAuth2 requests while those routers are unavailable.
  backend_rule=$(sed -n 's/^ *- traefik\.http\.routers\.netbird-backend\.rule=//p' <<< "$server")
  if [[ "$backend_rule" != 'Host(`${NETBIRD_DOMAIN}`) && (PathPrefix(`/relay`) || PathPrefix(`/ws-proxy/`))' ]]; then
    echo "AppSec: backend router has an unexpected rule: $backend_rule" >&2
    exit 1
  fi
  for line in \
    'netbird-dashboard-api.middlewares=netbird-dashboard-crowdsec@docker,nb-security@docker' \
    'netbird-dashboard-api.service=netbird-server' \
    'netbird-dashboard-api.priority=110'; do
    if ! grep -Fq "$line" <<< "$server"; then
      echo "AppSec: netbird-server is missing '$line'" >&2
      exit 1
    fi
  done
  for line in \
    'crowdsecurity/appsec-virtual-patching' \
    'crowdsecurity/appsec-generic-rules' \
    'BOUNCER_KEY_netbird_dashboard=${CROWDSEC_DASHBOARD_BOUNCER_KEY}' \
    './crowdsec/acquis.d:/etc/crowdsec/acquis.d:ro' \
    '/dev/tcp/127.0.0.1/7422' \
    'start_period: 30s'; do
    if ! grep -Fq "$line" <<< "$crowdsec"; then
      echo "AppSec: crowdsec service is missing '$line'" >&2
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
  local backend_rule
  backend_rule=$(sed -n 's/^ *- traefik\.http\.routers\.netbird-backend\.rule=//p' <<< "$rendered")
  if [[ "$backend_rule" != 'Host(`${NETBIRD_DOMAIN}`) && (PathPrefix(`/relay`) || PathPrefix(`/ws-proxy/`) || PathPrefix(`/api`) || PathPrefix(`/oauth2`))' ]]; then
    echo "AppSec off: backend router has an unexpected rule: $backend_rule" >&2
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

assert_appsec_acquisition() {
  local case_dir="$test_dir/appsec-acquis"
  mkdir -p "$case_dir"
  (
    cd "$case_dir"
    APPSEC_ACQUIS_CREATED=""
    write_crowdsec_appsec_acquisition
    if [[ "$APPSEC_ACQUIS_CREATED" != "crowdsec/acquis.d/appsec.yaml" ]]; then
      echo "AppSec: acquisition file was not recorded for rollback" >&2
      exit 1
    fi
    for line in \
      'listen_addr: 0.0.0.0:7422' \
      'crowdsecurity/appsec-default' \
      'type: appsec' \
      'source: appsec'; do
      if ! grep -Fq "$line" crowdsec/acquis.d/appsec.yaml; then
        echo "AppSec: acquisition file is missing '$line'" >&2
        exit 1
      fi
    done
    # A customized file from an earlier run must survive --enable-proxy.
    printf 'custom: true\n' > crowdsec/acquis.d/appsec.yaml
    APPSEC_ACQUIS_CREATED=""
    write_crowdsec_appsec_acquisition
    if [[ "$(cat crowdsec/acquis.d/appsec.yaml)" != "custom: true" ]]; then
      echo "AppSec: existing acquisition file was overwritten" >&2
      exit 1
    fi
    if [[ -n "$APPSEC_ACQUIS_CREATED" ]]; then
      echo "AppSec: existing acquisition file was marked for rollback" >&2
      exit 1
    fi
  )
  cases=$((cases + 1))
}

assert_enterprise_appsec
assert_enterprise_crowdsec_only
assert_dashboard_key_preserved
assert_appsec_acquisition

echo "Passed $cases enterprise configuration cases."
