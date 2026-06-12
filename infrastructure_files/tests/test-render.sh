#!/bin/bash
# Render-validation tests for getting-started.sh.
# Runs the script in --non-interactive --render-only mode for every supported
# architecture / IdP / reverse-proxy combination and validates the generated
# files. Requires jq; uses `docker compose config` when docker is available.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GETTING_STARTED="$SCRIPT_DIR/../getting-started.sh"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

FAILURES=0

compose_validate() {
  if docker compose version &>/dev/null; then
    docker compose -f "$1" config -q
    return $?
  fi
  if command -v docker-compose &>/dev/null; then
    docker-compose -f "$1" config -q
    return $?
  fi
  # Without docker fall back to a structural sanity check
  grep -q "^services:" "$1"
  return $?
}

write_oidc_fixture() {
  # A file:// OpenID discovery document stands in for a real IdP
  cat > "$1" <<EOF
{
  "issuer": "https://idp.example.org/realms/netbird",
  "authorization_endpoint": "https://idp.example.org/realms/netbird/protocol/openid-connect/auth",
  "token_endpoint": "https://idp.example.org/realms/netbird/protocol/openid-connect/token",
  "jwks_uri": "https://idp.example.org/realms/netbird/protocol/openid-connect/certs",
  "device_authorization_endpoint": "https://idp.example.org/realms/netbird/protocol/openid-connect/auth/device"
}
EOF
}

run_case() {
  local name="$1"
  shift
  local expected_files=("$@")
  local case_dir="$WORK_DIR/$name"
  mkdir -p "$case_dir"

  # setup.env content is provided on stdin
  cat > "$case_dir/setup.env"

  echo "--- case: $name"
  if ! (cd "$case_dir" && bash "$GETTING_STARTED" --non-interactive --render-only > render.log 2>&1); then
    echo "FAIL($name): render exited non-zero"
    tail -5 "$case_dir/render.log" | sed 's/^/    /'
    FAILURES=$((FAILURES + 1))
    return 0
  fi

  for f in "${expected_files[@]}"; do
    if [[ ! -f "$case_dir/$f" ]]; then
      echo "FAIL($name): expected file $f was not generated"
      FAILURES=$((FAILURES + 1))
    fi
  done

  if [[ -f "$case_dir/management.json" ]] && ! jq . "$case_dir/management.json" > /dev/null; then
    echo "FAIL($name): management.json is not valid JSON"
    FAILURES=$((FAILURES + 1))
  fi

  if [[ -f "$case_dir/docker-compose.yml" ]] && ! compose_validate "$case_dir/docker-compose.yml"; then
    echo "FAIL($name): docker-compose.yml failed validation"
    FAILURES=$((FAILURES + 1))
  fi

  # Re-rendering from the persisted setup.env must be byte-identical (idempotent)
  local checksums_before checksums_after
  checksums_before=$(cd "$case_dir" && sha256sum docker-compose.yml dashboard.env config.yaml management.json 2>/dev/null || true)
  if ! (cd "$case_dir" && bash "$GETTING_STARTED" --non-interactive --render-only > render2.log 2>&1); then
    echo "FAIL($name): re-render exited non-zero"
    FAILURES=$((FAILURES + 1))
    return 0
  fi
  checksums_after=$(cd "$case_dir" && sha256sum docker-compose.yml dashboard.env config.yaml management.json 2>/dev/null || true)
  if [[ "$checksums_before" != "$checksums_after" ]]; then
    echo "FAIL($name): re-render from setup.env is not idempotent"
    FAILURES=$((FAILURES + 1))
  fi
  return 0
}

OIDC_FIXTURE="$WORK_DIR/openid-configuration-fixture.json"
write_oidc_fixture "$OIDC_FIXTURE"

run_case combined-embedded-traefik docker-compose.yml config.yaml dashboard.env <<EOF
NETBIRD_DOMAIN="netbird.example.org"
NETBIRD_ARCHITECTURE="combined"
NETBIRD_IDP_MODE="embedded"
NETBIRD_REVERSE_PROXY_TYPE="0"
NETBIRD_TRAEFIK_ACME_EMAIL="admin@example.org"
EOF

run_case combined-embedded-nginx docker-compose.yml config.yaml dashboard.env nginx-netbird.conf <<EOF
NETBIRD_DOMAIN="netbird.example.org"
NETBIRD_ARCHITECTURE="combined"
NETBIRD_IDP_MODE="embedded"
NETBIRD_REVERSE_PROXY_TYPE="2"
EOF

run_case split-embedded-traefik docker-compose.yml management.json dashboard.env <<EOF
NETBIRD_DOMAIN="netbird.example.org"
NETBIRD_ARCHITECTURE="split"
NETBIRD_IDP_MODE="embedded"
NETBIRD_REVERSE_PROXY_TYPE="0"
NETBIRD_TRAEFIK_ACME_EMAIL="admin@example.org"
EOF

run_case split-embedded-external-traefik docker-compose.yml management.json dashboard.env <<EOF
NETBIRD_DOMAIN="netbird.example.org"
NETBIRD_ARCHITECTURE="split"
NETBIRD_IDP_MODE="embedded"
NETBIRD_REVERSE_PROXY_TYPE="1"
NETBIRD_TRAEFIK_ENTRYPOINT="websecure"
NETBIRD_TRAEFIK_CERTRESOLVER="letsencrypt"
EOF

run_case split-external-nginx-postgres docker-compose.yml management.json dashboard.env nginx-netbird.conf <<EOF
NETBIRD_DOMAIN="netbird.example.org"
NETBIRD_ARCHITECTURE="split"
NETBIRD_IDP_MODE="external"
NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT="file://$OIDC_FIXTURE"
NETBIRD_AUTH_CLIENT_ID="netbird"
NETBIRD_AUTH_CLIENT_SECRET="some-secret"
NETBIRD_REVERSE_PROXY_TYPE="2"
NETBIRD_STORE_CONFIG_ENGINE="postgres"
EOF

run_case split-external-manual docker-compose.yml management.json dashboard.env <<EOF
NETBIRD_DOMAIN="netbird.example.org"
NETBIRD_ARCHITECTURE="split"
NETBIRD_IDP_MODE="external"
NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT="file://$OIDC_FIXTURE"
NETBIRD_AUTH_CLIENT_ID="netbird"
NETBIRD_REVERSE_PROXY_TYPE="5"
NETBIRD_BIND_LOCALHOST_ONLY="false"
EOF

# Auto-forced split must be accepted when no architecture is given with external IdP
run_case split-external-defaulted docker-compose.yml management.json dashboard.env <<EOF
NETBIRD_DOMAIN="netbird.example.org"
NETBIRD_IDP_MODE="external"
NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT="file://$OIDC_FIXTURE"
NETBIRD_AUTH_CLIENT_ID="netbird"
NETBIRD_REVERSE_PROXY_TYPE="5"
EOF

run_case split-external-keycloak-extra-config docker-compose.yml management.json dashboard.env <<EOF
NETBIRD_DOMAIN="netbird.example.org"
NETBIRD_IDP_MODE="external"
NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT="file://$OIDC_FIXTURE"
NETBIRD_AUTH_CLIENT_ID="netbird"
NETBIRD_REVERSE_PROXY_TYPE="5"
NETBIRD_MGMT_IDP="keycloak"
NETBIRD_IDP_MGMT_CLIENT_ID="netbird-backend"
NETBIRD_IDP_MGMT_CLIENT_SECRET="backend-secret"
NETBIRD_IDP_MGMT_EXTRA_ADMIN_ENDPOINT="https://idp.example.org/admin/realms/netbird"
NETBIRD_MGMT_IDP_SIGNKEY_REFRESH="true"
EOF

run_case split-external-keycloak-no-extra-config docker-compose.yml management.json dashboard.env <<EOF
NETBIRD_DOMAIN="netbird.example.org"
NETBIRD_IDP_MODE="external"
NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT="file://$OIDC_FIXTURE"
NETBIRD_AUTH_CLIENT_ID="netbird"
NETBIRD_REVERSE_PROXY_TYPE="5"
NETBIRD_MGMT_IDP="keycloak"
NETBIRD_IDP_MGMT_CLIENT_ID="netbird-backend"
NETBIRD_IDP_MGMT_CLIENT_SECRET="backend-secret"
EOF

# Invalid combination must fail: combined + external IdP
echo "--- case: combined-external-rejected"
REJECT_DIR="$WORK_DIR/combined-external-rejected"
mkdir -p "$REJECT_DIR"
cat > "$REJECT_DIR/setup.env" <<EOF
NETBIRD_DOMAIN="netbird.example.org"
NETBIRD_ARCHITECTURE="combined"
NETBIRD_IDP_MODE="external"
NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT="file://$OIDC_FIXTURE"
NETBIRD_AUTH_CLIENT_ID="netbird"
NETBIRD_REVERSE_PROXY_TYPE="5"
EOF
if (cd "$REJECT_DIR" && bash "$GETTING_STARTED" --non-interactive --render-only > render.log 2>&1); then
  echo "FAIL(combined-external-rejected): combined + external IdP was not rejected"
  FAILURES=$((FAILURES + 1))
fi

# Spot-check rendered content
SPLIT_KEYCLOAK_EXTRA="$WORK_DIR/split-external-keycloak-extra-config"
if [[ -f "$SPLIT_KEYCLOAK_EXTRA/management.json" ]]; then
  [[ $(jq -r '.IdpManagerConfig.ManagerType' "$SPLIT_KEYCLOAK_EXTRA/management.json") == "keycloak" ]] || { echo "FAIL: IdP manager type mismatch"; FAILURES=$((FAILURES + 1)); }
  [[ $(jq -r '.IdpManagerConfig.ClientConfig.ClientID' "$SPLIT_KEYCLOAK_EXTRA/management.json") == "netbird-backend" ]] || { echo "FAIL: IdP manager client ID mismatch"; FAILURES=$((FAILURES + 1)); }
  [[ $(jq -r '.IdpManagerConfig.ExtraConfig.AdminEndpoint' "$SPLIT_KEYCLOAK_EXTRA/management.json") == "https://idp.example.org/admin/realms/netbird" ]] || { echo "FAIL: IdP manager ExtraConfig.AdminEndpoint missing"; FAILURES=$((FAILURES + 1)); }
  [[ $(jq -r '.HttpConfig.IdpSignKeyRefreshEnabled' "$SPLIT_KEYCLOAK_EXTRA/management.json") == "true" ]] || { echo "FAIL: IdP sign-key refresh env not honored"; FAILURES=$((FAILURES + 1)); }
fi

SPLIT_KEYCLOAK_NO_EXTRA="$WORK_DIR/split-external-keycloak-no-extra-config"
if [[ -f "$SPLIT_KEYCLOAK_NO_EXTRA/management.json" ]]; then
  [[ $(jq -c '.IdpManagerConfig.ExtraConfig // {}' "$SPLIT_KEYCLOAK_NO_EXTRA/management.json") == "{}" ]] || { echo "FAIL: IdP manager ExtraConfig should be empty without EXTRA vars"; FAILURES=$((FAILURES + 1)); }
fi

SPLIT_EXT="$WORK_DIR/split-external-nginx-postgres"
if [[ -f "$SPLIT_EXT/management.json" ]]; then
  [[ $(jq -r '.HttpConfig.AuthIssuer' "$SPLIT_EXT/management.json") == "https://idp.example.org/realms/netbird" ]] || { echo "FAIL: external AuthIssuer mismatch"; FAILURES=$((FAILURES + 1)); }
  [[ $(jq -r '.EmbeddedIdP' "$SPLIT_EXT/management.json") == "null" ]] || { echo "FAIL: external mode must not configure EmbeddedIdP"; FAILURES=$((FAILURES + 1)); }
  [[ $(jq -r '.StoreConfig.Engine' "$SPLIT_EXT/management.json") == "postgres" ]] || { echo "FAIL: postgres engine not set"; FAILURES=$((FAILURES + 1)); }
  grep -q "postgres:" "$SPLIT_EXT/docker-compose.yml" || { echo "FAIL: postgres container missing"; FAILURES=$((FAILURES + 1)); }
fi

SPLIT_EMB="$WORK_DIR/split-embedded-traefik"
if [[ -f "$SPLIT_EMB/management.json" ]]; then
  [[ $(jq -r '.EmbeddedIdP.Enabled' "$SPLIT_EMB/management.json") == "true" ]] || { echo "FAIL: embedded IdP not enabled in split mode"; FAILURES=$((FAILURES + 1)); }
  [[ $(jq -r '.Relay.Addresses[0]' "$SPLIT_EMB/management.json") == "rels://netbird.example.org:443" ]] || { echo "FAIL: relay address mismatch"; FAILURES=$((FAILURES + 1)); }
fi

echo ""
if [[ $FAILURES -gt 0 ]]; then
  echo "$FAILURES test(s) failed"
  exit 1
fi
echo "All render tests passed"
