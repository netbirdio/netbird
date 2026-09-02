#!/bin/bash

set -e
set -o pipefail

# NetBird Enterprise — Getting Started
# Single-node bootstrap for a self-hosted NetBird Enterprise stack with the
# embedded identity provider. Owner is created via first-login flow.

SED_STRIP_PADDING='s/=//g'

NETBIRD_EULA_URL="https://netbird.io/self-hosted-EULA"

# Static IP for Traefik inside the compose bridge network. The management
# server trusts X-Forwarded-* headers from this address only.
TRAEFIK_IP="172.30.0.10"

LICENSE_VERDICT="unknown"
LICENSE_LOG_LINES=""

check_docker_compose() {
  if ! command -v docker &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo "Docker is not installed or not in PATH. Please follow the steps from the official guide: https://docs.docker.com/engine/install/" > /dev/stderr
    exit 1
  fi

  if docker compose version &> /dev/null; then
    echo "docker compose"
    return
  fi
  if command -v docker-compose &> /dev/null && docker-compose version &> /dev/null; then
    echo "docker-compose"
    return
  fi

  echo "Docker Compose is not installed or not in PATH. Please follow the steps from the official guide: https://docs.docker.com/compose/install/" > /dev/stderr
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
    echo "Traefik will not be able to issue TLS certificates until it does." > /dev/stderr
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

read_letsencrypt_email() {
  if [[ -n "${NETBIRD_LETSENCRYPT_EMAIL:-}" ]]; then
    echo "$NETBIRD_LETSENCRYPT_EMAIL"
    return
  fi
  local value=""
  echo "Enter your email for Let's Encrypt certificate notifications." > /dev/stderr
  echo -n "Email address: " > /dev/stderr
  read -r value < /dev/tty
  if [[ -z "$value" ]]; then
    echo "Email is required for Let's Encrypt." > /dev/stderr
    read_letsencrypt_email
    return
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
  On-Premise End User License Agreement (the "EULA"). Please read the EULA
  in full before continuing:

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

wait_for_license_verdict() {
  local counter=0
  local logs=""

  echo -n "Waiting for the server to validate the license"
  while [[ $counter -lt 60 ]]; do
    logs=$($DOCKER_COMPOSE_COMMAND logs --no-color --tail=all netbird-server 2>/dev/null || true)

    if grep -qi "license invalidated" <<< "$logs"; then
      echo " rejected"
      LICENSE_VERDICT="rejected"
      LICENSE_LOG_LINES=$(grep -i "license" <<< "$logs" | tail -n 5 || true)
      return 0
    fi

    if grep -qi "license validated" <<< "$logs"; then
      echo " ok"
      LICENSE_VERDICT="ok"
      return 0
    fi

    echo -n " ."
    sleep 2
    counter=$((counter + 1))
  done

  echo " no verdict in 120s"
  LICENSE_VERDICT="unknown"
  LICENSE_LOG_LINES=$(grep -iE "failed to validate license|error validating license" <<< "$logs" | tail -n 3 || true)
  return 0
}

report_license_verdict() {
  if [[ "$LICENSE_VERDICT" == "ok" ]]; then
    return 0
  fi

  if [[ "$LICENSE_VERDICT" == "unknown" ]]; then
    echo ""
    echo "  ⚠  The server logged no license verdict within 120s."
    if [[ -n "$LICENSE_LOG_LINES" ]]; then
      echo "     It was still reporting validation errors:"
      while IFS= read -r line; do
        [[ -n "$line" ]] && echo "     $line"
      done <<< "$LICENSE_LOG_LINES"
    fi
    echo ""
    echo "     Check the verdict with:"
    echo ""
    echo "       $DOCKER_COMPOSE_COMMAND logs netbird-server | grep -i license"
    return 0
  fi

  local unreachable="false"
  if grep -qi "couldn't be validated with the license server" <<< "$LICENSE_LOG_LINES"; then
    unreachable="true"
  fi

  echo ""
  if [[ "$unreachable" == "true" ]]; then
    echo "  ⚠  The server could not validate the license:"
  else
    echo "  ⚠  The server rejected the license key:"
  fi
  while IFS= read -r line; do
    [[ -n "$line" ]] && echo "     $line"
  done <<< "$LICENSE_LOG_LINES"
  echo ""
  echo "     The stack is up, and only the license check did not pass."
  echo ""
  if [[ "$unreachable" == "true" ]]; then
    echo "     The license server could not be reached, so the key itself was"
    echo "     never checked. Confirm this host has outbound access to the"
    echo "     license server, then restart:"
  else
    echo "     Check the reason the server gave above, verify that"
    echo "     NETBIRD_LICENSE_KEY in .env matches the key you were issued,"
    echo "     then restart:"
  fi
  echo ""
  echo "       $DOCKER_COMPOSE_COMMAND up -d"
  return 0
}

init_environment() {
  check_openssl
  DOCKER_COMPOSE_COMMAND=$(check_docker_compose)

  if [[ -f .env ]] || [[ -f docker-compose.yml ]] || [[ -f config.yaml ]]; then
    echo "Generated files already exist in $(pwd)."
    echo "If you want to reinitialize the environment, please remove them first:"
    echo "  $DOCKER_COMPOSE_COMMAND down --volumes # removes all containers and volumes"
    echo "  rm -f .env docker-compose.yml config.yaml"
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
  NETBIRD_LETSENCRYPT_EMAIL=$(read_letsencrypt_email)

  echo ""

  NETBIRD_LICENSE_KEY=$(read_secret "Enter license key (input hidden)")

  POSTGRES_USER="netbird"
  POSTGRES_DB="netbird"
  POSTGRES_PASSWORD=$(rand_secret)
  NETBIRD_ENCRYPTION_KEY=$(rand_b64_key)
  NETBIRD_SESSION_COOKIE_ENCRYPTION_KEY=$(rand_b64_key)
  NETBIRD_RELAY_AUTH_SECRET=$(rand_secret)

  POSTGRES_DSN="host=postgres user=${POSTGRES_USER} password=${POSTGRES_PASSWORD} dbname=${POSTGRES_DB} port=5432 sslmode=disable TimeZone=UTC"
  NETBIRD_RELAY_ENDPOINT="rels://${NETBIRD_DOMAIN}:443"

  echo ""
  echo "Selected:"
  echo "  Traffic flow: ${NETBIRD_TRAFFIC_FLOW}"
  echo "  Domain:       ${NETBIRD_DOMAIN}"
  echo "  ACME email:   ${NETBIRD_LETSENCRYPT_EMAIL}"
  echo ""
  echo "Rendering files into $(pwd) ..."
  install -m 600 /dev/null .env
  render_env >> .env
  render_docker_compose > docker-compose.yml

  if [[ -z "${NETBIRD_LICENSE_SERVER_BASE_URL:-}" ]]; then
    sed -i.bak '/NETBIRD_LICENSE_SERVER_BASE_URL/d' docker-compose.yml && rm -f docker-compose.yml.bak
  fi
  install -m 600 /dev/null config.yaml
  render_config_yaml >> config.yaml

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
  wait_for_license_verdict

  echo ""
  echo "Done."
  echo ""
  echo "Dashboard: https://${NETBIRD_DOMAIN}"
  echo ""
  echo "Open the dashboard in a browser to complete the first-login owner setup."
  echo "All configuration and secrets are stored (mode 600) in $(pwd)/.env"
  echo ""
  echo "Tail logs:"
  echo "  cd $(pwd) && $DOCKER_COMPOSE_COMMAND logs -f netbird-server traefik"

  report_license_verdict

  if [[ "$LICENSE_VERDICT" == "rejected" ]]; then
    exit 1
  fi
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

# Reverse proxy (Traefik)
NETBIRD_LETSENCRYPT_EMAIL=${NETBIRD_LETSENCRYPT_EMAIL}
NETBIRD_TRAEFIK_TAG=${NETBIRD_TRAEFIK_TAG:-v3.6}
NETBIRD_TRAEFIK_IP=${TRAEFIK_IP}

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
  # Reverse proxy with automatic TLS via Let's Encrypt. Routes are declared as
  # labels on the services below and picked up through the Docker provider.
  traefik:
    <<: *default
    image: traefik:${NETBIRD_TRAEFIK_TAG}
    container_name: netbird-traefik
    networks:
      netbird:
        ipv4_address: ${NETBIRD_TRAEFIK_IP}
    command:
      # Logging
      - "--log.level=INFO"
      - "--accesslog=true"
      # Docker provider
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--providers.docker.network=netbird"
      # Entrypoints
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.websecure.allowACMEByPass=true"
      # readTimeout bounds the whole request, and gRPC streams / relay WebSockets
      # never end one; idleTimeout would close the keep-alive connection they
      # are reused over. Entrypoint-wide is the only scope Traefik offers here.
      # writeTimeout is left alone: it already defaults to 0.
      - "--entrypoints.websecure.transport.respondingTimeouts.readTimeout=0"
      - "--entrypoints.websecure.transport.respondingTimeouts.idleTimeout=0"
      # HTTP to HTTPS redirect
      - "--entrypoints.web.http.redirections.entrypoint.to=websecure"
      - "--entrypoints.web.http.redirections.entrypoint.scheme=https"
      # Let's Encrypt ACME
      - "--certificatesresolvers.letsencrypt.acme.email=${NETBIRD_LETSENCRYPT_EMAIL}"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.letsencrypt.acme.tlschallenge=true"
    ports:
      - '443:443'
      - '80:80'
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - netbird_traefik_letsencrypt:/letsencrypt
    labels:
      - traefik.enable=true
      # Shared security headers, referenced by every NetBird router below. A
      # label-declared middleware only exists while its container runs, so this
      # lives on Traefik itself: declaring it on an app container would drop
      # every router referencing it whenever that container restarts.
      - traefik.http.middlewares.nb-security.headers.stsSeconds=3600
      - traefik.http.middlewares.nb-security.headers.stsIncludeSubdomains=true
      - traefik.http.middlewares.nb-security.headers.contentTypeNosniff=true
      - traefik.http.middlewares.nb-security.headers.browserXssFilter=true
      - traefik.http.middlewares.nb-security.headers.referrerPolicy=strict-origin-when-cross-origin
      - traefik.http.middlewares.nb-security.headers.customResponseHeaders.X-Frame-Options=SAMEORIGIN
      # Empty value strips the header. Only the dashboard's nginx sets one; the
      # server emits none. Do not quote it — "" would send a literal Server: "".
      - traefik.http.middlewares.nb-security.headers.customResponseHeaders.Server=

  dashboard:
    <<: *default
    image: ghcr.io/netbirdio/dashboard-cloud:${NETBIRD_DASHBOARD_TAG}
    container_name: netbird-dashboard
    networks: [netbird]
    labels:
      - traefik.enable=true
      # Dashboard catch-all: lowest priority so every route below wins
      - traefik.http.routers.netbird-dashboard.rule=Host(`${NETBIRD_DOMAIN}`)
      - traefik.http.routers.netbird-dashboard.entrypoints=websecure
      - traefik.http.routers.netbird-dashboard.tls=true
      - traefik.http.routers.netbird-dashboard.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-dashboard.middlewares=nb-security@docker
      - traefik.http.routers.netbird-dashboard.service=dashboard
      - traefik.http.routers.netbird-dashboard.priority=1
      - traefik.http.services.dashboard.loadbalancer.server.port=80
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
    labels:
      - traefik.enable=true
      # Signal + Management gRPC (needs an h2c backend for HTTP/2 cleartext)
      - traefik.http.routers.netbird-grpc.rule=Host(`${NETBIRD_DOMAIN}`) && (PathPrefix(`/signalexchange.SignalExchange/`) || PathPrefix(`/management.ManagementService/`) || PathPrefix(`/management.ProxyService/`))
      - traefik.http.routers.netbird-grpc.entrypoints=websecure
      - traefik.http.routers.netbird-grpc.tls=true
      - traefik.http.routers.netbird-grpc.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-grpc.middlewares=nb-security@docker
      - traefik.http.routers.netbird-grpc.service=netbird-server-h2c
      - traefik.http.routers.netbird-grpc.priority=100
      # Relay WebSocket, management API, and the embedded IdP
      - traefik.http.routers.netbird-backend.rule=Host(`${NETBIRD_DOMAIN}`) && (PathPrefix(`/relay`) || PathPrefix(`/ws-proxy/`) || PathPrefix(`/api`) || PathPrefix(`/oauth2`))
      - traefik.http.routers.netbird-backend.entrypoints=websecure
      - traefik.http.routers.netbird-backend.tls=true
      - traefik.http.routers.netbird-backend.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-backend.middlewares=nb-security@docker
      - traefik.http.routers.netbird-backend.service=netbird-server
      - traefik.http.routers.netbird-backend.priority=100
      # Services
      - traefik.http.services.netbird-server.loadbalancer.server.port=80
      - traefik.http.services.netbird-server-h2c.loadbalancer.server.port=80
      - traefik.http.services.netbird-server-h2c.loadbalancer.server.scheme=h2c
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
    labels:
      - traefik.enable=true
      # Flow receiver gRPC (h2c backend)
      - traefik.http.routers.netbird-flow.rule=Host(`${NETBIRD_DOMAIN}`) && PathPrefix(`/flow.FlowService/`)
      - traefik.http.routers.netbird-flow.entrypoints=websecure
      - traefik.http.routers.netbird-flow.tls=true
      - traefik.http.routers.netbird-flow.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-flow.middlewares=nb-security@docker
      - traefik.http.routers.netbird-flow.service=netbird-flow-h2c
      - traefik.http.routers.netbird-flow.priority=100
      - traefik.http.services.netbird-flow-h2c.loadbalancer.server.port=80
      - traefik.http.services.netbird-flow-h2c.loadbalancer.server.scheme=h2c

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
  netbird_traefik_letsencrypt:

networks:
  netbird:
    name: netbird
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
          gateway: 172.30.0.1
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

  # TLS is terminated by Traefik in front; leave this block empty.
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
    sessionCookieEncryptionKey: "${NETBIRD_SESSION_COOKIE_ENCRYPTION_KEY}"
    dashboardRedirectURIs:
      - "https://${NETBIRD_DOMAIN}/nb-auth"
      - "https://${NETBIRD_DOMAIN}/nb-silent-auth"
    cliRedirectURIs:
      - "http://localhost:53000/"

  # Trust X-Forwarded-* only from the Traefik container's static address. Both
  # keys must stay in step with the ipv4_address pinned in docker-compose.yml:
  # trustedPeers decides whether forwarded headers are read at all, and leaving
  # it unset falls back to 0.0.0.0/0.
  reverseProxy:
    trustedPeers:
      - "${TRAEFIK_IP}/32"
    trustedHTTPProxies:
      - "${TRAEFIK_IP}/32"

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
