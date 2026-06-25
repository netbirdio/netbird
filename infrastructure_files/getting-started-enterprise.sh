#!/bin/bash

set -e
set -o pipefail

# NetBird Enterprise — Getting Started
# Single-node bootstrap for a self-hosted NetBird Enterprise stack with the
# embedded identity provider. Owner is created via first-login flow.

SED_STRIP_PADDING='s/=//g'

NETBIRD_EULA_URL="https://trust.netbird.io/?tab=reports-and-documents"

check_docker_compose() {
  if command -v docker-compose &> /dev/null; then
    echo "docker-compose"
    return
  fi
  if docker compose --help &> /dev/null; then
    echo "docker compose"
    return
  fi
  echo "docker-compose is not installed or not in PATH. See https://docs.docker.com/engine/install/" > /dev/stderr
  exit 1
}

check_openssl() {
  if ! command -v openssl &> /dev/null; then
    echo "openssl is not installed or not in PATH." > /dev/stderr
    exit 1
  fi
}

rand_secret() {
  openssl rand -base64 32 | sed "$SED_STRIP_PADDING"
}

rand_b64_key() {
  openssl rand -base64 32
}

check_nb_domain() {
  local domain="$1"
  if [[ -z "$domain" ]]; then
    echo "The domain cannot be empty." > /dev/stderr
    return 1
  fi
  if [[ "$domain" == "netbird.example.com" ]]; then
    echo "The domain cannot be netbird.example.com" > /dev/stderr
    return 1
  fi
  if [[ "$domain" =~ ^[0-9.]+$ ]]; then
    echo "An IP address is not allowed. A real DNS-resolvable domain is required for TLS and the embedded IdP issuer." > /dev/stderr
    return 1
  fi
  if [[ ! "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]; then
    echo "The value '$domain' is not a valid FQDN. A real DNS-resolvable domain is required for TLS and the embedded IdP issuer." > /dev/stderr
    return 1
  fi
  return 0
}

check_domain_resolves() {
  local domain="$1"
  if command -v getent &> /dev/null && getent hosts "$domain" &> /dev/null; then return 0; fi
  if command -v host &> /dev/null && host "$domain" &> /dev/null; then return 0; fi
  if command -v dig &> /dev/null && [[ -n "$(dig +short "$domain" 2>/dev/null)" ]]; then return 0; fi
  if command -v nslookup &> /dev/null && nslookup "$domain" &> /dev/null; then return 0; fi
  return 1
}

read_nb_domain() {
  local value=""
  echo -n "Enter the FQDN for NetBird (must resolve via DNS, e.g. netbird.my-domain.com): " > /dev/stderr
  read -r value < /dev/tty
  if ! check_nb_domain "$value"; then
    read_nb_domain
    return
  fi
  if ! check_domain_resolves "$value"; then
    echo "" > /dev/stderr
    echo "Warning: '$value' does not resolve via DNS from this host." > /dev/stderr
    echo "Caddy will not be able to issue TLS certificates until it does." > /dev/stderr
    local confirm=""
    echo -n "Continue anyway? [y/N]: " > /dev/stderr
    read -r confirm < /dev/tty
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
      read_nb_domain
      return
    fi
  fi
  echo "$value"
}

read_required() {
  local prompt="$1"
  local value=""
  while [[ -z "$value" ]]; do
    echo -n "$prompt: " > /dev/stderr
    read -r value < /dev/tty
    if [[ -z "$value" ]]; then
      echo "Value cannot be empty." > /dev/stderr
    fi
  done
  echo "$value"
}

read_secret() {
  local prompt="$1"
  local value=""
  while [[ -z "$value" ]]; do
    echo -n "$prompt: " > /dev/stderr
    read -rs value < /dev/tty
    echo "" > /dev/stderr
    if [[ -z "$value" ]]; then
      echo "Value cannot be empty." > /dev/stderr
    fi
  done
  echo "$value"
}

# read_yes_no "<prompt>" [<default y|n>]
read_yes_no() {
  local prompt="$1"
  local default="${2:-n}"
  local hint
  if [[ "$default" == "y" ]]; then
    hint="[Y/n]"
  else
    hint="[y/N]"
  fi
  echo -n "${prompt} ${hint}: " > /dev/stderr
  local ans=""
  read -r ans < /dev/tty
  if [[ -z "$ans" ]]; then
    ans="$default"
  fi
  case "$ans" in
    [Yy] | [Yy][Ee][Ss]) echo "yes" ;;
    *) echo "no" ;;
  esac
}

# Gate the install on explicit acceptance of the NetBird On-Premise EULA.
require_eula_acceptance() {
  cat > /dev/stderr <<EOF

  ──────────────────────────────────────────────────────────────────────
   NetBird On-Premise End User License Agreement
  ──────────────────────────────────────────────────────────────────────
  NetBird's on-premise software is commercial software, licensed and not
  sold. Your installation, deployment and use are governed by the NetBird
  On-Premise End User License Agreement (the "EULA"). Please read it in
  full before continuing — open the "On-Premise EULA" document here:

      ${NETBIRD_EULA_URL}

  By typing "accept" and continuing the installation, you confirm that you
  have read and agree to the EULA, that you are authorized to accept it on
  behalf of your organization (the "Customer"), and that the Software is
  used for business purposes only.
  ──────────────────────────────────────────────────────────────────────
EOF

  if [[ "${NB_ACCEPT_EULA:-}" == "yes" ]]; then
    echo "EULA accepted via NB_ACCEPT_EULA=yes." > /dev/stderr
    return 0
  fi

  local ans=""
  echo -n 'Type "accept" to agree, or anything else to abort: ' > /dev/stderr
  read -r ans < /dev/tty
  if [[ "$ans" != "accept" ]]; then
    echo "" > /dev/stderr
    echo "EULA not accepted. Aborting installation." > /dev/stderr
    exit 1
  fi
  echo "" > /dev/stderr
}

wait_postgres() {
  set +e
  echo -n "Waiting for postgres to become ready"
  local counter=1
  while true; do
    if $DOCKER_COMPOSE_COMMAND exec -T postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" &> /dev/null; then
      break
    fi
    if [[ $counter -eq 60 ]]; then
      echo ""
      echo "Postgres is taking too long. Recent logs:"
      $DOCKER_COMPOSE_COMMAND logs --tail=20 postgres
      exit 1
    fi
    echo -n " ."
    sleep 2
    counter=$((counter + 1))
  done
  echo " done"
  set -e
}

init_environment() {
  check_openssl
  DOCKER_COMPOSE_COMMAND=$(check_docker_compose)

  if [[ -f .env ]] || [[ -f docker-compose.yml ]] || [[ -f config.yaml ]] || [[ -f Caddyfile ]]; then
    echo "Generated files already exist in $(pwd)."
    echo "If you want to reinitialize the environment, please remove them first:"
    echo "  $DOCKER_COMPOSE_COMMAND down --volumes # removes all containers and volumes"
    echo "  rm -f .env docker-compose.yml Caddyfile config.yaml"
    echo "Be aware this will remove all data from the database."
    exit 1
  fi

  require_eula_acceptance
  NETBIRD_EULA_ACCEPTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  echo "NetBird Enterprise bootstrap"
  echo ""
  echo "Traffic flow:"
  echo "  Enables traffic events logging on the management server."
  echo "  When enabled, the NetBird stack also runs NATS along with two"
  echo "  additional containers: netbird-receiver (the traffic log receiver"
  echo "  service) and netbird-enricher (the traffic log enricher service)."
  echo "  It still has to be turned on from the dashboard settings afterwards."
  echo "  See https://docs.netbird.io/manage/activity/traffic-events-logging"
  NETBIRD_TRAFFIC_FLOW=$(read_yes_no "Enable traffic flow" "n")

  echo ""
  NETBIRD_DOMAIN=$(read_nb_domain)

  echo ""

  NETBIRD_LICENSE_KEY=$(read_secret "Enter license key (input hidden)")

  GHCR_USERNAME="netbirdExtAccess1"
  GHCR_TOKEN=$(read_secret "Enter GHCR token (input hidden)")

  POSTGRES_USER="netbird"
  POSTGRES_DB="netbird"
  POSTGRES_PASSWORD=$(rand_secret)
  NETBIRD_ENCRYPTION_KEY=$(rand_b64_key)
  NETBIRD_RELAY_AUTH_SECRET=$(rand_secret)

  POSTGRES_DSN="host=postgres user=${POSTGRES_USER} password=${POSTGRES_PASSWORD} dbname=${POSTGRES_DB} port=5432 sslmode=disable TimeZone=UTC"
  NETBIRD_RELAY_ENDPOINT="rels://${NETBIRD_DOMAIN}:443"

  echo ""
  echo "Selected:"
  echo "  Traffic flow: ${NETBIRD_TRAFFIC_FLOW}"
  echo "  Domain:       ${NETBIRD_DOMAIN}"
  echo ""
  echo "Rendering files into $(pwd) ..."
  install -m 600 /dev/null .env
  render_env >> .env
  render_docker_compose > docker-compose.yml

  if [[ -z "${NETBIRD_LICENSE_SERVER_BASE_URL:-}" ]]; then
    sed -i.bak '/NETBIRD_LICENSE_SERVER_BASE_URL/d' docker-compose.yml && rm -f docker-compose.yml.bak
  fi
  render_caddyfile > Caddyfile
  install -m 600 /dev/null config.yaml
  render_config_yaml >> config.yaml

  echo "Logging in to ghcr.io ..."
  printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USERNAME" --password-stdin
  unset GHCR_TOKEN

  echo ""
  echo "Pulling images ..."
  $DOCKER_COMPOSE_COMMAND pull

  echo ""
  echo "Starting postgres ..."
  $DOCKER_COMPOSE_COMMAND up -d postgres
  sleep 2
  wait_postgres

  echo ""
  echo "Starting remaining services ..."
  $DOCKER_COMPOSE_COMMAND up -d

  echo ""
  echo "Done."
  echo ""
  echo "Dashboard: https://${NETBIRD_DOMAIN}"
  echo ""
  echo "Open the dashboard in a browser to complete the first-login owner setup."
  echo "All configuration and secrets are stored (mode 600) in $(pwd)/.env"
  echo ""
  echo "Tail logs:"
  echo "  cd $(pwd) && $DOCKER_COMPOSE_COMMAND logs -f netbird-server caddy"
}

# ------------------------------------------------------------------
# Renderers
# ------------------------------------------------------------------

render_env() {
  cat <<EOF
# Generated by getting-started-enterprise.sh
# Holds all configuration and secrets for the stack. Mode 600.

# NetBird On-Premise EULA acceptance
NETBIRD_EULA_ACCEPTED=yes
NETBIRD_EULA_ACCEPTED_AT=${NETBIRD_EULA_ACCEPTED_AT}
NETBIRD_EULA_URL=${NETBIRD_EULA_URL}

# Features (set by the script; don't edit without re-running)
NETBIRD_TRAFFIC_FLOW_ENABLED=${NETBIRD_TRAFFIC_FLOW}

# Domain
NETBIRD_DOMAIN=${NETBIRD_DOMAIN}

# Image tags. Default to "latest"
NETBIRD_DASHBOARD_TAG=${NETBIRD_DASHBOARD_TAG:-latest}
NETBIRD_SERVER_TAG=${NETBIRD_SERVER_TAG:-latest}
EOF

  if [[ "$NETBIRD_TRAFFIC_FLOW" == "yes" ]]; then
    cat <<EOF
NETBIRD_ENRICHER_TAG=${NETBIRD_ENRICHER_TAG:-latest}
NETBIRD_RECEIVER_TAG=${NETBIRD_RECEIVER_TAG:-latest}
EOF
  fi

  cat <<EOF

# License keys
EOF
  if [[ -n "${NETBIRD_LICENSE_SERVER_BASE_URL:-}" ]]; then
    cat <<EOF
NETBIRD_LICENSE_SERVER_BASE_URL=${NETBIRD_LICENSE_SERVER_BASE_URL}
EOF
  fi
  cat <<EOF
NETBIRD_LICENSE_KEY=${NETBIRD_LICENSE_KEY}
EOF

  cat <<EOF

# Postgres
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
NETBIRD_STORE_ENGINE_POSTGRES_DSN=${POSTGRES_DSN}

# Relay
NETBIRD_RELAY_ENDPOINT=${NETBIRD_RELAY_ENDPOINT}
NETBIRD_RELAY_AUTH_SECRET=${NETBIRD_RELAY_AUTH_SECRET}

# Datastore encryption
NETBIRD_ENCRYPTION_KEY=${NETBIRD_ENCRYPTION_KEY}

# Dashboard OIDC scopes
NETBIRD_AUTH_SUPPORTED_SCOPES=${NETBIRD_AUTH_SUPPORTED_SCOPES:-openid profile email groups}
EOF
}

render_docker_compose() {
  render_compose_header
  render_compose_common
  render_compose_server
  if [[ "$NETBIRD_TRAFFIC_FLOW" == "yes" ]]; then
    render_compose_flow
  fi
  render_compose_postgres
  render_compose_footer
}

render_compose_header() {
  cat <<'EOF'
x-default: &default
  restart: unless-stopped
  logging:
    driver: json-file
    options:
      max-size: '500m'
      max-file: '2'

services:
EOF
}

render_compose_common() {
  cat <<'EOF'
  caddy:
    <<: *default
    image: caddy:2
    container_name: netbird-caddy
    networks: [netbird]
    environment:
      - CADDY_SECURE_DOMAIN=${NETBIRD_DOMAIN}
    ports:
      - '443:443'
      - '443:443/udp'
      - '80:80'
    volumes:
      - netbird_caddy_data:/data
      - ./Caddyfile:/etc/caddy/Caddyfile

  dashboard:
    <<: *default
    image: ghcr.io/netbirdio/dashboard-cloud:${NETBIRD_DASHBOARD_TAG}
    container_name: netbird-dashboard
    networks: [netbird]
    environment:
      - NETBIRD_MGMT_API_ENDPOINT=https://${NETBIRD_DOMAIN}
      - NETBIRD_MGMT_GRPC_API_ENDPOINT=https://${NETBIRD_DOMAIN}
      - AUTH_AUDIENCE=netbird-dashboard
      - AUTH_CLIENT_ID=netbird-dashboard
      - AUTH_CLIENT_SECRET=
      - AUTH_AUTHORITY=https://${NETBIRD_DOMAIN}/oauth2
      - USE_AUTH0=false
      - AUTH_SUPPORTED_SCOPES=${NETBIRD_AUTH_SUPPORTED_SCOPES}
      - AUTH_REDIRECT_URI=/nb-auth
      - AUTH_SILENT_REDIRECT_URI=/nb-silent-auth
      - NETBIRD_TOKEN_SOURCE=accessToken
      - NGINX_SSL_PORT=443
      - LETSENCRYPT_DOMAIN=
      - LETSENCRYPT_EMAIL=

EOF
}

render_compose_server() {
  cat <<'EOF'
  netbird-server:
    <<: *default
    image: ghcr.io/netbirdio/netbird-server-cloud:${NETBIRD_SERVER_TAG}
    container_name: netbird-server
    networks: [netbird]
    depends_on:
      dashboard:
        condition: service_started
      postgres:
        condition: service_healthy
    ports:
      - '3478:3478/udp'
    volumes:
      - netbird_data:/var/lib/netbird
      - ./config.yaml:/etc/netbird/config.yaml
    command: ["--config", "/etc/netbird/config.yaml"]
    environment:
      - NB_LICENSE_KEY=${NETBIRD_LICENSE_KEY}
      - NETBIRD_LICENSE_SERVER_BASE_URL=${NETBIRD_LICENSE_SERVER_BASE_URL}

EOF
}

render_compose_flow() {
  cat <<'EOF'
  nats:
    <<: *default
    image: nats:2
    container_name: netbird-nats
    networks: [netbird]
    volumes:
      - netbird_nats_data:/data
    command: ["-m", "8222", "--jetstream", "--store_dir", "/data"]

  enricher:
    <<: *default
    image: ghcr.io/netbirdio/flow-enricher-cloud:${NETBIRD_ENRICHER_TAG}
    container_name: netbird-enricher
    networks: [netbird]
    depends_on:
      postgres:
        condition: service_healthy
      nats:
        condition: service_started
    volumes:
      - netbird_enricher:/var/lib/netbird
    environment:
      - NB_LICENSE_KEY=${NETBIRD_LICENSE_KEY}
      - NETBIRD_LICENSE_SERVER_BASE_URL=${NETBIRD_LICENSE_SERVER_BASE_URL}
      - NB_DATADIR=/var/lib/netbird
      - NB_MANAGEMENT_STORE_ENGINE=postgres
      - NB_MANAGEMENT_POSTGRES_DSN=${NETBIRD_STORE_ENGINE_POSTGRES_DSN}
      - NETBIRD_STORE_ENGINE_POSTGRES_DSN=${NETBIRD_STORE_ENGINE_POSTGRES_DSN}
      - NB_TRAFFIC_EVENT_POSTGRES_DSN=${NETBIRD_STORE_ENGINE_POSTGRES_DSN}
      - NB_TRAFFIC_EVENT_STORE_ENGINE=postgres
      - NB_MANAGEMENT_STORE_KEY=${NETBIRD_ENCRYPTION_KEY}
      - NB_FLOW_ADAPTER_TYPE=nats
      - NB_FLOW_NATS_ENDPOINTS=nats://nats:4222
      - NB_FLOW_NATS_STREAM=traffic-events
      - NB_METRICS_PORT=9091
      - NB_PERSISTENCE_RETENTION_PERIOD=168h

  receiver:
    <<: *default
    image: ghcr.io/netbirdio/flow-receiver-cloud:${NETBIRD_RECEIVER_TAG}
    container_name: netbird-receiver
    networks: [netbird]
    depends_on:
      nats:
        condition: service_started
    environment:
      - NB_LICENSE_KEY=${NETBIRD_LICENSE_KEY}
      - NETBIRD_LICENSE_SERVER_BASE_URL=${NETBIRD_LICENSE_SERVER_BASE_URL}
      - NB_FLOW_LISTEN_PORT=80
      - NB_FLOW_ADAPTER_TYPE=nats
      - NB_FLOW_NATS_ENDPOINTS=nats://nats:4222
      - NB_FLOW_NATS_STREAM=traffic-events
      - NB_FLOW_AUTH_SECRET=${NETBIRD_RELAY_AUTH_SECRET}

EOF
}

render_compose_postgres() {
  cat <<'EOF'
  postgres:
    <<: *default
    image: postgres:17
    container_name: netbird-postgres
    networks: [netbird]
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=${POSTGRES_DB}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 10
    volumes:
      - netbird_postgres:/var/lib/postgresql/data

EOF
}

render_compose_footer() {
  cat <<'EOF'
volumes:
  netbird_data:
EOF
  if [[ "$NETBIRD_TRAFFIC_FLOW" == "yes" ]]; then
    cat <<'EOF'
  netbird_nats_data:
  netbird_enricher:
EOF
  fi
  cat <<'EOF'
  netbird_postgres:
  netbird_caddy_data:

networks:
  netbird:
EOF
}

render_caddyfile() {
  cat <<'EOF'
{
  servers :80,:443 {
    protocols h1 h2c h2 h3
  }
}

(security_headers) {
    header * {
        Strict-Transport-Security "max-age=3600; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        X-XSS-Protection "1; mode=block"
        -Server
        Referrer-Policy strict-origin-when-cross-origin
    }
}

:80 {
    redir https://{$CADDY_SECURE_DOMAIN}{uri} permanent
}

{$CADDY_SECURE_DOMAIN}:443 {
    import security_headers
    # Signal (gRPC over h2c)
    reverse_proxy /signalexchange.SignalExchange/* h2c://netbird-server:80
    # Management (gRPC over h2c + HTTP)
    reverse_proxy /management.ManagementService/* h2c://netbird-server:80
    reverse_proxy /api/* netbird-server:80
    reverse_proxy /ws-proxy/* netbird-server:80
    # Embedded IdP (OAuth2 endpoints served by netbird server)
    reverse_proxy /oauth2/* netbird-server:80
    # Relay (WebSocket multiplexed on the same port)
    reverse_proxy /relay* netbird-server:80
EOF

  if [[ "$NETBIRD_TRAFFIC_FLOW" == "yes" ]]; then
    cat <<'EOF'
    # Flow receiver (gRPC over h2c)
    reverse_proxy /flow.FlowService/* h2c://receiver:80
EOF
  fi

  cat <<'EOF'
    # Dashboard
    reverse_proxy /* dashboard:80
}
EOF
}

render_config_yaml() {
  cat <<EOF
# NetBird Enterprise server configuration.
# Generated by getting-started-enterprise.sh. Mode 600.

server:
  listenAddress: ":80"
  exposedAddress: "https://${NETBIRD_DOMAIN}:443"

  metricsPort: 9090
  healthcheckAddress: ":9000"

  logLevel: "info"
  logFile: "console"

  # TLS is terminated by Caddy in front; leave this block empty.
  tls:
    certFile: ""
    keyFile: ""
    letsencrypt:
      enabled: false

  authSecret: "${NETBIRD_RELAY_AUTH_SECRET}"
  dataDir: "/var/lib/netbird/"

  disableAnonymousMetrics: false
  disableGeoliteUpdate: false

  auth:
    issuer: "https://${NETBIRD_DOMAIN}/oauth2"
    localAuthDisabled: false
    signKeyRefreshEnabled: false
    dashboardRedirectURIs:
      - "https://${NETBIRD_DOMAIN}/nb-auth"
      - "https://${NETBIRD_DOMAIN}/nb-silent-auth"
    cliRedirectURIs:
      - "http://localhost:53000/"

  store:
    engine: "postgres"
    dsn: "${POSTGRES_DSN}"
    encryptionKey: "${NETBIRD_ENCRYPTION_KEY}"

  activityStore:
    engine: "postgres"
    dsn: "${POSTGRES_DSN}"
EOF

  if [[ "$NETBIRD_TRAFFIC_FLOW" == "yes" ]]; then
    cat <<EOF

  trafficFlow:
    enabled: true
    address: "https://${NETBIRD_DOMAIN}:443"
    interval: "60s"
EOF
  fi
}

init_environment
