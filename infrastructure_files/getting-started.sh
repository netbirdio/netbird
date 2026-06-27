#!/bin/bash

set -e

# NetBird Getting Started
# Sets up a self-hosted NetBird deployment. Two architectures are supported:
#   - combined: a single netbird-server container (management + signal + relay + STUN)
#     using the built-in identity provider
#   - split: separate management, signal and relay containers, using either the
#     built-in identity provider or your own OIDC provider
#
# All wizard answers are persisted to setup.env. Re-running with --non-interactive
# renders the same deployment from that file (suitable for IaC/automation).
#
# Usage: getting-started.sh [--non-interactive] [--render-only] [--setup-env=FILE]

# Sed pattern to strip base64 padding characters
SED_STRIP_PADDING='s/=//g'

# Constants for repeated string literals
readonly MSG_STARTING_SERVICES="\nStarting NetBird services\n"
readonly MSG_DONE="\nDone!\n"
readonly MSG_NEXT_STEPS="Next steps:"
readonly MSG_SEPARATOR="=========================================="

############################################
# Utility Functions
############################################

check_docker_sock_perms() {
  local sock="${DOCKER_HOST:-unix:///var/run/docker.sock}"
  sock="${sock#unix://}"

  if [[ ! -S "$sock" ]]; then
    return 0
  fi

  if [[ ! -r "$sock" ]] || [[ ! -w "$sock" ]]; then
    local group
    if [[ "${OSTYPE}" == "darwin"* ]]; then
      group="$(stat -f '%Sg' "$sock")"
    else
      group="$(stat -c '%G' "$sock")"
    fi

    echo "Cannot access Docker socket: $sock" > /dev/stderr
    echo "" > /dev/stderr
    echo "Socket permissions:" > /dev/stderr
    ls -l "$sock" > /dev/stderr
    echo "" > /dev/stderr

    if [[ "$group" == "docker" ]]; then
      echo "Your user may need to be added to the '$group' group:" > /dev/stderr
      echo "  sudo usermod -aG $group \"$USER\"" > /dev/stderr
      echo "Then log out and back in, or run this for the current shell:" > /dev/stderr
      echo "  newgrp $group" > /dev/stderr
      echo "Note: newgrp is temporary; usermod is the permanent group change." > /dev/stderr
    else
      echo "The Docker socket is owned by the '$group' group, which is not the standard 'docker' group." > /dev/stderr
      echo "For safety, this script will not suggest adding your user to '$group'." > /dev/stderr
      echo "Instead, either run this script with appropriate privileges (for example, via sudo) or follow Docker's post-install steps to configure access via the 'docker' group:" > /dev/stderr
      echo "  https://docs.docker.com/engine/install/linux-postinstall/" > /dev/stderr
    fi

    exit 1
  fi
  return 0
}

check_docker_compose() {
  if command -v docker-compose &> /dev/null
  then
      echo "docker-compose"
      return
  fi
  if docker compose --help &> /dev/null
  then
      echo "docker compose"
      return
  fi

  echo "docker-compose is not installed or not in PATH. Please follow the steps from the official guide: https://docs.docker.com/engine/install/" > /dev/stderr
  exit 1
}

check_jq() {
  if ! command -v jq &> /dev/null
  then
    echo "jq is not installed or not in PATH, please install with your package manager. e.g. sudo apt install jq" > /dev/stderr
    exit 1
  fi
  return 0
}

get_main_ip_address() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    interface=$(route -n get default | grep 'interface:' | awk '{print $2}')
    ip_address=$(ifconfig "$interface" | grep 'inet ' | awk '{print $2}')
  else
    interface=$(ip route | grep default | awk '{print $5}' | head -n 1)
    ip_address=$(ip addr show "$interface" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
  fi

  echo "$ip_address"
  return 0
}

check_nb_domain() {
  DOMAIN=$1
  if [[ "$DOMAIN-x" == "-x" ]]; then
    echo "The NETBIRD_DOMAIN variable cannot be empty." > /dev/stderr
    return 1
  fi

  if [[ "$DOMAIN" == "netbird.example.com" ]]; then
    echo "The NETBIRD_DOMAIN cannot be netbird.example.com" > /dev/stderr
    return 1
  fi
  return 0
}

read_nb_domain() {
  READ_NETBIRD_DOMAIN=""
  echo -n "Enter the domain you want to use for NetBird (e.g. netbird.my-domain.com): " > /dev/stderr
  read -r READ_NETBIRD_DOMAIN < /dev/tty
  if ! check_nb_domain "$READ_NETBIRD_DOMAIN"; then
    read_nb_domain
  fi
  echo "$READ_NETBIRD_DOMAIN"
  return 0
}

check_curl() {
  if ! command -v curl &> /dev/null
  then
    echo "curl is not installed or not in PATH, please install with your package manager. e.g. sudo apt install curl" > /dev/stderr
    exit 1
  fi
  return 0
}

require_interactive() {
  # Guards prompts so --non-interactive runs fail loudly instead of hanging on /dev/tty
  local var_hint="$1"
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    echo "Missing or invalid value for $var_hint in non-interactive mode. Set it in $SETUP_ENV_FILE or as an environment variable." > /dev/stderr
    exit 1
  fi
  return 0
}

read_idp_mode() {
  echo "" > /dev/stderr
  echo "Which identity provider (IdP) do you want to use?" > /dev/stderr
  echo "  [0] Built-in IdP (recommended - local users, external providers can be added for SSO later)" > /dev/stderr
  echo "  [1] Your own OIDC provider as the sole authentication path (Keycloak, Zitadel, Okta, ...)" > /dev/stderr
  echo "" > /dev/stderr
  echo "Note: the built-in IdP supports connecting external identity providers for SSO" > /dev/stderr
  echo "from the dashboard, but runs in single account mode. Choose [1] only if you" > /dev/stderr
  echo "need multiple accounts or want no local user management at all." > /dev/stderr
  echo "" > /dev/stderr
  echo -n "Enter choice [0-1] (default: 0): " > /dev/stderr
  read -r CHOICE < /dev/tty

  case "$CHOICE" in
    ""|0) echo "embedded" ;;
    1) echo "external" ;;
    *)
      echo "Invalid choice. Please enter 0 or 1." > /dev/stderr
      read_idp_mode
      ;;
  esac
  return 0
}

read_architecture() {
  echo "" > /dev/stderr
  echo "How do you want to run the NetBird server components?" > /dev/stderr
  echo "  [0] Single combined container (recommended - simplest to operate)" > /dev/stderr
  echo "  [1] Separate containers per service (management, signal, relay - for scale-out)" > /dev/stderr
  echo "" > /dev/stderr
  echo -n "Enter choice [0-1] (default: 0): " > /dev/stderr
  read -r CHOICE < /dev/tty

  case "$CHOICE" in
    ""|0) echo "combined" ;;
    1) echo "split" ;;
    *)
      echo "Invalid choice. Please enter 0 or 1." > /dev/stderr
      read_architecture
      ;;
  esac
  return 0
}

read_oidc_endpoint() {
  echo "" > /dev/stderr
  echo "Enter your IdP's OpenID configuration endpoint." > /dev/stderr
  echo "e.g. https://keycloak.example.com/realms/netbird/.well-known/openid-configuration" > /dev/stderr
  echo "See https://docs.netbird.io/selfhosted/identity-providers for per-provider instructions." > /dev/stderr
  echo -n "OIDC configuration endpoint: " > /dev/stderr
  read -r ENDPOINT < /dev/tty
  if [[ -z "$ENDPOINT" ]]; then
    echo "The OIDC configuration endpoint is required." > /dev/stderr
    read_oidc_endpoint
    return
  fi
  echo "$ENDPOINT"
  return 0
}

read_oidc_client_id() {
  echo "" > /dev/stderr
  echo "Enter the OAuth client ID you registered for NetBird in your IdP." > /dev/stderr
  echo -n "Client ID (e.g. netbird): " > /dev/stderr
  read -r CLIENT_ID < /dev/tty
  if [[ -z "$CLIENT_ID" ]]; then
    echo "The client ID is required." > /dev/stderr
    read_oidc_client_id
    return
  fi
  echo "$CLIENT_ID"
  return 0
}

read_oidc_audience() {
  local default_audience="$1"
  echo "" > /dev/stderr
  echo "Enter the JWT audience your IdP issues tokens with." > /dev/stderr
  echo -n "Audience (default: ${default_audience}): " > /dev/stderr
  read -r AUDIENCE < /dev/tty
  if [[ -z "$AUDIENCE" ]]; then
    AUDIENCE="$default_audience"
  fi
  echo "$AUDIENCE"
  return 0
}

read_oidc_client_secret() {
  echo "" > /dev/stderr
  echo "Enter the OAuth client secret, if your IdP requires one." > /dev/stderr
  echo -n "Client secret (leave empty for public clients/PKCE): " > /dev/stderr
  read -r SECRET < /dev/tty
  echo "$SECRET"
  return 0
}

read_store_engine() {
  echo "" > /dev/stderr
  echo "Which database engine should the management service use?" > /dev/stderr
  echo "  [0] SQLite (default - file-based, no extra container)" > /dev/stderr
  echo "  [1] PostgreSQL (recommended for larger deployments)" > /dev/stderr
  echo "" > /dev/stderr
  echo -n "Enter choice [0-1] (default: 0): " > /dev/stderr
  read -r CHOICE < /dev/tty

  case "$CHOICE" in
    ""|0) echo "sqlite" ;;
    1) echo "postgres" ;;
    *)
      echo "Invalid choice. Please enter 0 or 1." > /dev/stderr
      read_store_engine
      ;;
  esac
  return 0
}

read_postgres_dsn() {
  echo "" > /dev/stderr
  echo "Enter the DSN of an existing PostgreSQL server, or leave empty to add" > /dev/stderr
  echo "a PostgreSQL container to this deployment." > /dev/stderr
  echo -n "DSN (e.g. host=db.example.com user=netbird password=... dbname=netbird port=5432): " > /dev/stderr
  read -r DSN < /dev/tty
  echo "$DSN"
  return 0
}

read_reverse_proxy_type() {
  echo "" > /dev/stderr
  echo "Which reverse proxy will you use?" > /dev/stderr
  echo "  [0] Traefik (recommended - automatic TLS, included in Docker Compose)" > /dev/stderr
  echo "  [1] Existing Traefik (labels for external Traefik instance)" > /dev/stderr
  echo "  [2] Nginx (generates config template)" > /dev/stderr
  echo "  [3] Nginx Proxy Manager (generates config + instructions)" > /dev/stderr
  echo "  [4] External Caddy (generates Caddyfile snippet)" > /dev/stderr
  echo "  [5] Other/Manual (displays setup documentation)" > /dev/stderr
  echo "" > /dev/stderr
  echo -n "Enter choice [0-5] (default: 0): " > /dev/stderr
  read -r CHOICE < /dev/tty

  if [[ -z "$CHOICE" ]]; then
    CHOICE="0"
  fi

  if [[ ! "$CHOICE" =~ ^[0-5]$ ]]; then
    echo "Invalid choice. Please enter a number between 0 and 5." > /dev/stderr
    read_reverse_proxy_type
    return
  fi

  echo "$CHOICE"
  return 0
}

read_traefik_network() {
  echo "" > /dev/stderr
  echo "If you have an existing Traefik instance, enter its external network name." > /dev/stderr
  echo -n "External network (leave empty to create 'netbird' network): " > /dev/stderr
  read -r NETWORK < /dev/tty
  echo "$NETWORK"
  return 0
}

read_traefik_entrypoint() {
  echo "" > /dev/stderr
  echo "Enter the name of your Traefik HTTPS entrypoint." > /dev/stderr
  echo -n "HTTPS entrypoint name (default: websecure): " > /dev/stderr
  read -r ENTRYPOINT < /dev/tty
  if [[ -z "$ENTRYPOINT" ]]; then
    ENTRYPOINT="websecure"
  fi
  echo "$ENTRYPOINT"
  return 0
}

read_traefik_certresolver() {
  echo "" > /dev/stderr
  echo "Enter the name of your Traefik certificate resolver (for automatic TLS)." > /dev/stderr
  echo "Leave empty if you handle TLS termination elsewhere or use a wildcard cert." > /dev/stderr
  echo -n "Certificate resolver name (e.g., letsencrypt): " > /dev/stderr
  read -r RESOLVER < /dev/tty
  echo "$RESOLVER"
  return 0
}

read_port_binding_preference() {
  echo "" > /dev/stderr
  echo "Should container ports be bound to localhost only (127.0.0.1)?" > /dev/stderr
  echo "Choose 'yes' if your reverse proxy runs on the same host (more secure)." > /dev/stderr
  echo -n "Bind to localhost only? [Y/n]: " > /dev/stderr
  read -r CHOICE < /dev/tty

  if [[ "$CHOICE" =~ ^[Nn]$ ]]; then
    echo "false"
  else
    echo "true"
  fi
  return 0
}

read_proxy_docker_network() {
  local proxy_name="$1"
  echo "" > /dev/stderr
  echo "Is ${proxy_name} running in Docker?" > /dev/stderr
  echo "If yes, enter the Docker network ${proxy_name} is on (NetBird will join it)." > /dev/stderr
  echo -n "Docker network (leave empty if not in Docker): " > /dev/stderr
  read -r NETWORK < /dev/tty
  echo "$NETWORK"
  return 0
}

read_enable_proxy() {
  echo "" > /dev/stderr
  echo "Do you want to enable the NetBird Proxy service?" > /dev/stderr
  echo "The proxy allows you to selectively expose internal NetBird network resources" > /dev/stderr
  echo "to the internet. You control which resources are exposed through the dashboard." > /dev/stderr
  echo -n "Enable proxy? [y/N]: " > /dev/stderr
  read -r CHOICE < /dev/tty

  if [[ "$CHOICE" =~ ^[Yy]$ ]]; then
    echo "true"
  else
    echo "false"
  fi
  return 0
}

read_enable_crowdsec() {
  echo "" > /dev/stderr
  echo "Do you want to enable CrowdSec IP reputation blocking?" > /dev/stderr
  echo "CrowdSec checks client IPs against a community threat intelligence database" > /dev/stderr
  echo "and blocks known malicious sources before they reach your services." > /dev/stderr
  echo "A local CrowdSec LAPI container will be added to your deployment." > /dev/stderr
  echo -n "Enable CrowdSec? [y/N]: " > /dev/stderr
  read -r CHOICE < /dev/tty

  if [[ "$CHOICE" =~ ^[Yy]$ ]]; then
    echo "true"
  else
    echo "false"
  fi
  return 0
}

read_traefik_acme_email() {
  echo "" > /dev/stderr
  echo "Enter your email for Let's Encrypt certificate notifications." > /dev/stderr
  echo -n "Email address: " > /dev/stderr
  read -r EMAIL < /dev/tty
  if [[ -z "$EMAIL" ]]; then
    echo "Email is required for Let's Encrypt." > /dev/stderr
    read_traefik_acme_email
    return
  fi
  echo "$EMAIL"
  return 0
}

get_bind_address() {
  if [[ "$BIND_LOCALHOST_ONLY" == "true" ]]; then
    echo "127.0.0.1"
  else
    echo "0.0.0.0"
  fi
  return 0
}

get_upstream_host() {
  # Always return 127.0.0.1 for health checks and upstream targets
  # Cannot use 0.0.0.0 as a connection target
  echo "127.0.0.1"
  return 0
}

management_ready() {
  # With the built-in IdP we can poll its discovery document for a strict 200.
  # With an external IdP the management API is the only public endpoint; any
  # HTTP response that is not a gateway error means the backend is up.
  local base_url="$1"
  if [[ "$IDP_MODE" == "embedded" ]]; then
    curl -sk -f -o /dev/null "${base_url}/oauth2/.well-known/openid-configuration" 2>/dev/null
    return $?
  fi

  local code
  code=$(curl -sk -o /dev/null -w '%{http_code}' "${base_url}/api/accounts" 2>/dev/null)
  [[ "$code" != "000" && "$code" != "502" && "$code" != "503" && "$code" != "504" ]]
  return $?
}

wait_management_proxy() {
  local proxy_container="${1:-traefik}"
  local use_docker_logs=false
  set +e

  if [[ "$proxy_container" == "detect-traefik" ]]; then
    proxy_container=$(docker ps --format "{{.ID}}\t{{.Image}}\t{{.Ports}}" \
    | awk -F'\t' '$2 ~ /traefik/ && $3 ~ /:(80|443)->/ {print $1; exit}')

    if [[ -z "$proxy_container" ]]; then
      echo "Warning: could not auto-detect Traefik container, log output will be skipped on timeout." > /dev/stderr
    else
      use_docker_logs=true
    fi
  fi

  echo -n "Waiting for NetBird server to become ready"
  counter=1
  while true; do
    if management_ready "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"; then
      break
    fi
    if [[ $counter -eq 60 ]]; then
      echo ""
      echo "Taking too long. Checking logs..."
      if [[ -n "$proxy_container" ]]; then
        if [[ "$use_docker_logs" == "true" ]]; then
          docker logs --tail=20 "$proxy_container"
        else
          $DOCKER_COMPOSE_COMMAND logs --tail=20 "$proxy_container"
        fi
      fi
      $DOCKER_COMPOSE_COMMAND logs --tail=20 "$SERVER_SERVICE"
    fi
    echo -n " ."
    sleep 2
    counter=$((counter + 1))
  done
  echo " done"
  set -e
  return 0
}

wait_management_direct() {
  set +e
  local upstream_host=$(get_upstream_host)
  echo -n "Waiting for NetBird server to become ready"
  counter=1
  while true; do
    if management_ready "http://${upstream_host}:${MANAGEMENT_HOST_PORT}"; then
      break
    fi
    if [[ $counter -eq 60 ]]; then
      echo ""
      echo "Taking too long. Checking logs..."
      $DOCKER_COMPOSE_COMMAND logs --tail=20 "$SERVER_SERVICE"
    fi
    echo -n " ."
    sleep 2
    counter=$((counter + 1))
  done
  echo " done"
  set -e
  return 0
}

############################################
# Initialization and Configuration
############################################

initialize_default_values() {
  NETBIRD_PORT=80
  NETBIRD_HTTP_PROTOCOL="http"
  NETBIRD_RELAY_PROTO="rel"
  NETBIRD_STUN_PORT=3478

  # Deployment shape
  IDP_MODE="embedded"        # embedded | external
  ARCHITECTURE="combined"    # combined | split

  # External OIDC provider (IDP_MODE=external)
  AUTH_OIDC_ENDPOINT=""
  AUTH_CLIENT_ID=""
  AUTH_CLIENT_SECRET=""
  AUTH_AUDIENCE=""
  AUTH_SUPPORTED_SCOPES="openid profile email"
  USE_AUTH0="false"
  TOKEN_SOURCE="accessToken"
  AUTH_REDIRECT_URI="/nb-auth"
  AUTH_SILENT_REDIRECT_URI="/nb-silent-auth"

  # Datastore (split architecture prompts for this; combined defaults to sqlite)
  STORE_ENGINE="sqlite"      # sqlite | postgres
  POSTGRES_DSN=""
  POSTGRES_PASSWORD=""
  DEPLOY_POSTGRES="false"

  # Docker images
  DASHBOARD_IMAGE=${DASHBOARD_IMAGE:-"netbirdio/dashboard:latest"}
  # Combined server replaces separate signal, relay, and management containers
  NETBIRD_SERVER_IMAGE=${NETBIRD_SERVER_IMAGE:-"netbirdio/netbird-server:latest"}
  # Split architecture images
  MANAGEMENT_IMAGE=${MANAGEMENT_IMAGE:-"netbirdio/management:latest"}
  SIGNAL_IMAGE=${SIGNAL_IMAGE:-"netbirdio/signal:latest"}
  RELAY_IMAGE=${RELAY_IMAGE:-"netbirdio/relay:latest"}
  POSTGRES_IMAGE=${POSTGRES_IMAGE:-"postgres:16-alpine"}
  NETBIRD_PROXY_IMAGE=${NETBIRD_PROXY_IMAGE:-"netbirdio/reverse-proxy:latest"}
  TRAEFIK_IMAGE=${TRAEFIK_IMAGE:-"traefik:v3.6"}
  CROWDSEC_IMAGE=${CROWDSEC_IMAGE:-"crowdsecurity/crowdsec:v1.7.7"}
  # Reverse proxy configuration
  REVERSE_PROXY_TYPE="0"
  TRAEFIK_EXTERNAL_NETWORK=""
  TRAEFIK_ENTRYPOINT="websecure"
  TRAEFIK_CERTRESOLVER=""
  TRAEFIK_ACME_EMAIL=""
  DASHBOARD_HOST_PORT="8080"
  MANAGEMENT_HOST_PORT="8081"  # Combined server / split management host port
  SIGNAL_HOST_PORT="10000"     # Split architecture only
  RELAY_HOST_PORT="33080"      # Split architecture only
  BIND_LOCALHOST_ONLY="true"
  EXTERNAL_PROXY_NETWORK=""

  # Service name used in compose logs hints (combined: netbird-server, split: management)
  SERVER_SERVICE="netbird-server"

  # Traefik static IP within the internal bridge network
  TRAEFIK_IP="172.30.0.10"

  # NetBird Proxy configuration
  ENABLE_PROXY="false"
  PROXY_TOKEN=""

  # CrowdSec configuration
  ENABLE_CROWDSEC="false"
  CROWDSEC_BOUNCER_KEY=""
  return 0
}

ensure_secrets() {
  # Secrets are generated only when not provided (setup.env or environment),
  # so re-rendering an existing deployment keeps peers and data intact
  GENERATED_SECRETS=""
  if [[ -z "$NETBIRD_RELAY_AUTH_SECRET" ]]; then
    NETBIRD_RELAY_AUTH_SECRET=$(openssl rand -base64 32 | sed "$SED_STRIP_PADDING")
    GENERATED_SECRETS="$GENERATED_SECRETS NETBIRD_RELAY_AUTH_SECRET"
  fi
  # Note: DataStoreEncryptionKey must keep base64 padding (=) for Go's base64.StdEncoding
  if [[ -z "$DATASTORE_ENCRYPTION_KEY" ]]; then
    DATASTORE_ENCRYPTION_KEY=$(openssl rand -base64 32)
    GENERATED_SECRETS="$GENERATED_SECRETS NETBIRD_DATASTORE_ENC_KEY"
  fi
  if [[ "$DEPLOY_POSTGRES" == "true" && -z "$POSTGRES_PASSWORD" ]]; then
    POSTGRES_PASSWORD=$(openssl rand -base64 24 | sed "$SED_STRIP_PADDING")
    GENERATED_SECRETS="$GENERATED_SECRETS NETBIRD_POSTGRES_PASSWORD"
  fi
  return 0
}

load_setup_env() {
  if [[ -f "$SETUP_ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$SETUP_ENV_FILE"
    set +a
  elif [[ -z "$NETBIRD_DOMAIN" ]]; then
    echo "Non-interactive mode requires $SETUP_ENV_FILE or configuration via environment variables (at least NETBIRD_DOMAIN)." > /dev/stderr
    exit 1
  fi

  IDP_MODE=${NETBIRD_IDP_MODE:-$IDP_MODE}
  ARCHITECTURE=${NETBIRD_ARCHITECTURE:-$ARCHITECTURE}
  AUTH_OIDC_ENDPOINT=${NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT:-$AUTH_OIDC_ENDPOINT}
  AUTH_CLIENT_ID=${NETBIRD_AUTH_CLIENT_ID:-$AUTH_CLIENT_ID}
  AUTH_CLIENT_SECRET=${NETBIRD_AUTH_CLIENT_SECRET:-$AUTH_CLIENT_SECRET}
  AUTH_AUDIENCE=${NETBIRD_AUTH_AUDIENCE:-$AUTH_AUDIENCE}
  AUTH_SUPPORTED_SCOPES=${NETBIRD_AUTH_SUPPORTED_SCOPES:-$AUTH_SUPPORTED_SCOPES}
  USE_AUTH0=${NETBIRD_USE_AUTH0:-$USE_AUTH0}
  TOKEN_SOURCE=${NETBIRD_TOKEN_SOURCE:-$TOKEN_SOURCE}
  AUTH_REDIRECT_URI=${NETBIRD_AUTH_REDIRECT_URI:-$AUTH_REDIRECT_URI}
  AUTH_SILENT_REDIRECT_URI=${NETBIRD_AUTH_SILENT_REDIRECT_URI:-$AUTH_SILENT_REDIRECT_URI}
  STORE_ENGINE=${NETBIRD_STORE_CONFIG_ENGINE:-$STORE_ENGINE}
  POSTGRES_DSN=${NETBIRD_STORE_ENGINE_POSTGRES_DSN:-$POSTGRES_DSN}
  POSTGRES_PASSWORD=${NETBIRD_POSTGRES_PASSWORD:-$POSTGRES_PASSWORD}
  REVERSE_PROXY_TYPE=${NETBIRD_REVERSE_PROXY_TYPE:-$REVERSE_PROXY_TYPE}
  TRAEFIK_ACME_EMAIL=${NETBIRD_TRAEFIK_ACME_EMAIL:-$TRAEFIK_ACME_EMAIL}
  TRAEFIK_EXTERNAL_NETWORK=${NETBIRD_TRAEFIK_EXTERNAL_NETWORK:-$TRAEFIK_EXTERNAL_NETWORK}
  TRAEFIK_ENTRYPOINT=${NETBIRD_TRAEFIK_ENTRYPOINT:-$TRAEFIK_ENTRYPOINT}
  TRAEFIK_CERTRESOLVER=${NETBIRD_TRAEFIK_CERTRESOLVER:-$TRAEFIK_CERTRESOLVER}
  BIND_LOCALHOST_ONLY=${NETBIRD_BIND_LOCALHOST_ONLY:-$BIND_LOCALHOST_ONLY}
  EXTERNAL_PROXY_NETWORK=${NETBIRD_EXTERNAL_PROXY_NETWORK:-$EXTERNAL_PROXY_NETWORK}
  ENABLE_PROXY=${NETBIRD_ENABLE_PROXY:-$ENABLE_PROXY}
  ENABLE_CROWDSEC=${NETBIRD_ENABLE_CROWDSEC:-$ENABLE_CROWDSEC}
  DATASTORE_ENCRYPTION_KEY=${NETBIRD_DATASTORE_ENC_KEY:-$DATASTORE_ENCRYPTION_KEY}
  # NETBIRD_RELAY_AUTH_SECRET is used directly
  return 0
}

render_setup_env_idp_manager_vars() {
  local var

  [[ -n "${NETBIRD_MGMT_IDP:-}" ]] && printf '%s=%q\n' "NETBIRD_MGMT_IDP" "$NETBIRD_MGMT_IDP"
  [[ -n "${NETBIRD_MGMT_IDP_SIGNKEY_REFRESH:-}" ]] && printf '%s=%q\n' "NETBIRD_MGMT_IDP_SIGNKEY_REFRESH" "$NETBIRD_MGMT_IDP_SIGNKEY_REFRESH"
  [[ -n "${NETBIRD_IDP_MGMT_CLIENT_ID:-}" ]] && printf '%s=%q\n' "NETBIRD_IDP_MGMT_CLIENT_ID" "$NETBIRD_IDP_MGMT_CLIENT_ID"
  [[ -n "${NETBIRD_IDP_MGMT_CLIENT_SECRET:-}" ]] && printf '%s=%q\n' "NETBIRD_IDP_MGMT_CLIENT_SECRET" "$NETBIRD_IDP_MGMT_CLIENT_SECRET"
  for var in ${!NETBIRD_IDP_MGMT_EXTRA_*}; do
    printf '%s=%q\n' "$var" "${!var}"
  done
  return 0
}

write_setup_env() {
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    persist_generated_secrets
    return 0
  fi

  cat > "$SETUP_ENV_FILE" <<EOF
# NetBird deployment configuration
# Generated by getting-started.sh - edit and re-run with --non-interactive to apply changes:
#   ./getting-started.sh --non-interactive

NETBIRD_DOMAIN="$NETBIRD_DOMAIN"
# Deployment architecture: combined (single netbird-server container) or split
# (separate management, signal and relay containers)
NETBIRD_ARCHITECTURE="$ARCHITECTURE"
# Identity provider: embedded (built-in IdP) or external (your own OIDC provider).
# The external option requires the split architecture.
NETBIRD_IDP_MODE="$IDP_MODE"

# External OIDC provider settings (only used when NETBIRD_IDP_MODE=external)
NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT="$AUTH_OIDC_ENDPOINT"
NETBIRD_AUTH_CLIENT_ID="$AUTH_CLIENT_ID"
NETBIRD_AUTH_CLIENT_SECRET="$AUTH_CLIENT_SECRET"
NETBIRD_AUTH_AUDIENCE="$AUTH_AUDIENCE"
NETBIRD_AUTH_SUPPORTED_SCOPES="$AUTH_SUPPORTED_SCOPES"
# Set to true only for Auth0
NETBIRD_USE_AUTH0="$USE_AUTH0"
# Token the dashboard sends to the management API: accessToken or idToken
NETBIRD_TOKEN_SOURCE="$TOKEN_SOURCE"

# Reverse proxy: 0=built-in Traefik, 1=existing Traefik, 2=Nginx,
# 3=Nginx Proxy Manager, 4=external Caddy, 5=other/manual
NETBIRD_REVERSE_PROXY_TYPE="$REVERSE_PROXY_TYPE"
NETBIRD_TRAEFIK_ACME_EMAIL="$TRAEFIK_ACME_EMAIL"
NETBIRD_TRAEFIK_EXTERNAL_NETWORK="$TRAEFIK_EXTERNAL_NETWORK"
NETBIRD_TRAEFIK_ENTRYPOINT="$TRAEFIK_ENTRYPOINT"
NETBIRD_TRAEFIK_CERTRESOLVER="$TRAEFIK_CERTRESOLVER"
NETBIRD_BIND_LOCALHOST_ONLY="$BIND_LOCALHOST_ONLY"
NETBIRD_EXTERNAL_PROXY_NETWORK="$EXTERNAL_PROXY_NETWORK"

# NetBird Proxy and CrowdSec (combined architecture with built-in Traefik only)
NETBIRD_ENABLE_PROXY="$ENABLE_PROXY"
NETBIRD_ENABLE_CROWDSEC="$ENABLE_CROWDSEC"

# Datastore: sqlite or postgres. With postgres and an empty DSN a PostgreSQL
# container is added to the deployment.
NETBIRD_STORE_CONFIG_ENGINE="$STORE_ENGINE"
NETBIRD_STORE_ENGINE_POSTGRES_DSN="$POSTGRES_DSN"
NETBIRD_POSTGRES_PASSWORD="$POSTGRES_PASSWORD"

# Generated secrets - keep these stable across re-renders
NETBIRD_RELAY_AUTH_SECRET="$NETBIRD_RELAY_AUTH_SECRET"
NETBIRD_DATASTORE_ENC_KEY="$DATASTORE_ENCRYPTION_KEY"

# Optional advanced settings (uncomment to use, then re-run with --non-interactive)
# Device authorization flow for headless clients (external IdP only):
#NETBIRD_AUTH_DEVICE_AUTH_CLIENT_ID=""
# IdP management API for user/group sync (external IdP only), see
# https://docs.netbird.io/selfhosted/identity-providers:
#NETBIRD_MGMT_IDP=""
#NETBIRD_MGMT_IDP_SIGNKEY_REFRESH="false"
#NETBIRD_IDP_MGMT_CLIENT_ID=""
#NETBIRD_IDP_MGMT_CLIENT_SECRET=""
# Extra IdP-manager settings (provider-specific), for example:
#NETBIRD_IDP_MGMT_EXTRA_ADMIN_ENDPOINT=""
$(render_setup_env_idp_manager_vars)
# Docker image overrides:
#DASHBOARD_IMAGE=""
#NETBIRD_SERVER_IMAGE=""
#MANAGEMENT_IMAGE=""
#SIGNAL_IMAGE=""
#RELAY_IMAGE=""
EOF
  echo "Saved configuration to $SETUP_ENV_FILE"
  return 0
}

persist_generated_secrets() {
  # In non-interactive mode never rewrite the user's file, but secrets generated
  # this run must be persisted or the next render would rotate them
  [[ -z "$GENERATED_SECRETS" || ! -f "$SETUP_ENV_FILE" ]] && return 0

  echo "" >> "$SETUP_ENV_FILE"
  echo "# Secrets generated by getting-started.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$SETUP_ENV_FILE"
  for secret in $GENERATED_SECRETS; do
    case "$secret" in
      NETBIRD_RELAY_AUTH_SECRET) echo "NETBIRD_RELAY_AUTH_SECRET=\"$NETBIRD_RELAY_AUTH_SECRET\"" >> "$SETUP_ENV_FILE" ;;
      NETBIRD_DATASTORE_ENC_KEY) echo "NETBIRD_DATASTORE_ENC_KEY=\"$DATASTORE_ENCRYPTION_KEY\"" >> "$SETUP_ENV_FILE" ;;
      NETBIRD_POSTGRES_PASSWORD) echo "NETBIRD_POSTGRES_PASSWORD=\"$POSTGRES_PASSWORD\"" >> "$SETUP_ENV_FILE" ;;
    esac
    echo "Generated $secret and appended it to $SETUP_ENV_FILE"
  done
  return 0
}

fetch_oidc_configuration() {
  check_curl
  echo "Loading OpenID configuration from $AUTH_OIDC_ENDPOINT"
  if ! curl -fsSL "$AUTH_OIDC_ENDPOINT" -o openid-configuration.json; then
    echo "Failed to fetch the OpenID configuration from $AUTH_OIDC_ENDPOINT" > /dev/stderr
    echo "Check that the URL is reachable and points to a .well-known/openid-configuration document." > /dev/stderr
    exit 1
  fi

  NETBIRD_AUTH_AUTHORITY=$(jq -r '.issuer // empty' openid-configuration.json)
  NETBIRD_AUTH_JWT_CERTS=$(jq -r '.jwks_uri // empty' openid-configuration.json)
  NETBIRD_AUTH_TOKEN_ENDPOINT=$(jq -r '.token_endpoint // empty' openid-configuration.json)
  NETBIRD_AUTH_PKCE_AUTHORIZATION_ENDPOINT=$(jq -r '.authorization_endpoint // empty' openid-configuration.json)
  NETBIRD_AUTH_DEVICE_AUTH_ENDPOINT=$(jq -r '.device_authorization_endpoint // empty' openid-configuration.json)

  if [[ -z "$NETBIRD_AUTH_AUTHORITY" || -z "$NETBIRD_AUTH_JWT_CERTS" ]]; then
    echo "The OpenID configuration at $AUTH_OIDC_ENDPOINT is missing the issuer or jwks_uri field." > /dev/stderr
    exit 1
  fi
  return 0
}

configure_domain() {
  if ! check_nb_domain "$NETBIRD_DOMAIN"; then
    require_interactive "NETBIRD_DOMAIN"
    NETBIRD_DOMAIN=$(read_nb_domain)
  fi

  if [[ "$NETBIRD_DOMAIN" == "use-ip" ]]; then
    NETBIRD_DOMAIN=$(get_main_ip_address)
    BASE_DOMAIN=$NETBIRD_DOMAIN
  else
    NETBIRD_PORT=443
    NETBIRD_HTTP_PROTOCOL="https"
    NETBIRD_RELAY_PROTO="rels"
    BASE_DOMAIN=$(echo $NETBIRD_DOMAIN | sed -E 's/^[^.]+\.//')
  fi
  return 0
}

configure_idp() {
  if [[ "$NON_INTERACTIVE" != "true" ]]; then
    IDP_MODE=$(read_idp_mode)
    if [[ "$IDP_MODE" == "external" ]]; then
      AUTH_OIDC_ENDPOINT=$(read_oidc_endpoint)
      AUTH_CLIENT_ID=$(read_oidc_client_id)
      AUTH_AUDIENCE=$(read_oidc_audience "$AUTH_CLIENT_ID")
      AUTH_CLIENT_SECRET=$(read_oidc_client_secret)
    fi
  fi

  case "$IDP_MODE" in
    embedded) ;;
    external)
      if [[ -z "$AUTH_OIDC_ENDPOINT" ]]; then
        require_interactive "NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT"
      fi
      if [[ -z "$AUTH_CLIENT_ID" ]]; then
        require_interactive "NETBIRD_AUTH_CLIENT_ID"
      fi
      AUTH_AUDIENCE=${AUTH_AUDIENCE:-$AUTH_CLIENT_ID}
      ;;
    *)
      echo "Invalid NETBIRD_IDP_MODE: $IDP_MODE (expected embedded or external)" > /dev/stderr
      exit 1
      ;;
  esac
  return 0
}

configure_architecture() {
  if [[ "$IDP_MODE" == "external" ]]; then
    # The combined netbird-server only supports the built-in IdP, so an external
    # provider requires the split architecture
    if [[ "$NON_INTERACTIVE" == "true" && "$ARCHITECTURE" == "combined" && -n "$NETBIRD_ARCHITECTURE" ]]; then
      echo "NETBIRD_ARCHITECTURE=combined is not supported with NETBIRD_IDP_MODE=external." > /dev/stderr
      echo "The combined netbird-server only supports the built-in IdP; use NETBIRD_ARCHITECTURE=split." > /dev/stderr
      exit 1
    fi
    if [[ "$NON_INTERACTIVE" != "true" ]]; then
      echo "" > /dev/stderr
      echo "Using your own OIDC provider requires the split architecture" > /dev/stderr
      echo "(separate management, signal and relay containers)." > /dev/stderr
    fi
    ARCHITECTURE="split"
  elif [[ "$NON_INTERACTIVE" != "true" ]]; then
    ARCHITECTURE=$(read_architecture)
  fi

  case "$ARCHITECTURE" in
    combined)
      SERVER_SERVICE="netbird-server"
      ;;
    split)
      SERVER_SERVICE="management"
      ;;
    *)
      echo "Invalid NETBIRD_ARCHITECTURE: $ARCHITECTURE (expected combined or split)" > /dev/stderr
      exit 1
      ;;
  esac
  return 0
}

configure_datastore() {
  if [[ "$ARCHITECTURE" == "split" && "$NON_INTERACTIVE" != "true" ]]; then
    STORE_ENGINE=$(read_store_engine)
    if [[ "$STORE_ENGINE" == "postgres" ]]; then
      POSTGRES_DSN=$(read_postgres_dsn)
    fi
  fi

  case "$STORE_ENGINE" in
    sqlite) ;;
    postgres)
      if [[ -z "$POSTGRES_DSN" ]]; then
        if [[ "$ARCHITECTURE" == "combined" ]]; then
          echo "NETBIRD_STORE_CONFIG_ENGINE=postgres with the combined architecture requires NETBIRD_STORE_ENGINE_POSTGRES_DSN." > /dev/stderr
          exit 1
        fi
        DEPLOY_POSTGRES="true"
      fi
      ;;
    *)
      echo "Invalid NETBIRD_STORE_CONFIG_ENGINE: $STORE_ENGINE (expected sqlite or postgres)" > /dev/stderr
      exit 1
      ;;
  esac
  return 0
}

configure_reverse_proxy() {
  if [[ "$NON_INTERACTIVE" != "true" ]]; then
    REVERSE_PROXY_TYPE=$(read_reverse_proxy_type)

    # Handle built-in Traefik prompts (option 0)
    if [[ "$REVERSE_PROXY_TYPE" == "0" ]]; then
      TRAEFIK_ACME_EMAIL=$(read_traefik_acme_email)
      # NetBird Proxy and CrowdSec are only wired up for the combined server
      if [[ "$ARCHITECTURE" == "combined" ]]; then
        ENABLE_PROXY=$(read_enable_proxy)
        if [[ "$ENABLE_PROXY" == "true" ]]; then
          ENABLE_CROWDSEC=$(read_enable_crowdsec)
        fi
      fi
    fi

    # Handle external Traefik-specific prompts (option 1)
    if [[ "$REVERSE_PROXY_TYPE" == "1" ]]; then
      TRAEFIK_EXTERNAL_NETWORK=$(read_traefik_network)
      TRAEFIK_ENTRYPOINT=$(read_traefik_entrypoint)
      TRAEFIK_CERTRESOLVER=$(read_traefik_certresolver)
    fi

    # Handle port binding for external proxy options (2-5)
    if [[ "$REVERSE_PROXY_TYPE" -ge 2 ]]; then
      BIND_LOCALHOST_ONLY=$(read_port_binding_preference)
    fi

    # Handle Docker network prompts for external proxies (options 2-4)
    case "$REVERSE_PROXY_TYPE" in
      2) EXTERNAL_PROXY_NETWORK=$(read_proxy_docker_network "Nginx") ;;
      3) EXTERNAL_PROXY_NETWORK=$(read_proxy_docker_network "Nginx Proxy Manager") ;;
      4) EXTERNAL_PROXY_NETWORK=$(read_proxy_docker_network "Caddy") ;;
      *) ;; # No network prompt for other options
    esac
  fi

  if [[ ! "$REVERSE_PROXY_TYPE" =~ ^[0-5]$ ]]; then
    echo "Invalid NETBIRD_REVERSE_PROXY_TYPE: $REVERSE_PROXY_TYPE (expected 0-5)" > /dev/stderr
    exit 1
  fi
  if [[ "$REVERSE_PROXY_TYPE" == "0" && -z "$TRAEFIK_ACME_EMAIL" ]]; then
    require_interactive "NETBIRD_TRAEFIK_ACME_EMAIL"
  fi
  if [[ "$ARCHITECTURE" == "split" && "$ENABLE_PROXY" == "true" ]]; then
    echo "The NetBird Proxy service is currently only supported with the combined architecture; disabling it." > /dev/stderr
    ENABLE_PROXY="false"
    ENABLE_CROWDSEC="false"
  fi
  return 0
}

check_existing_installation() {
  if [[ -f config.yaml || -f management.json ]]; then
    echo "Generated files already exist, if you want to reinitialize the environment, please remove them first."
    echo "You can use the following commands:"
    echo "  $DOCKER_COMPOSE_COMMAND down --volumes # to remove all containers and volumes"
    echo "  rm -f docker-compose.yml dashboard.env config.yaml management.json openid-configuration.json proxy.env traefik-dynamic.yaml nginx-netbird.conf caddyfile-netbird.txt npm-advanced-config.txt && rm -rf crowdsec/"
    echo "Be aware that this will remove all data from the database, and you will have to reconfigure the dashboard."
    echo ""
    echo "To re-render configuration for an existing deployment instead, run:"
    echo "  ./getting-started.sh --non-interactive"
    exit 1
  fi
  return 0
}

generate_configuration_files() {
  echo Rendering initial files...

  # Render docker-compose and proxy config based on selection
  case "$REVERSE_PROXY_TYPE" in
    0)
      if [[ "$ARCHITECTURE" == "split" ]]; then
        render_docker_compose_split_traefik_builtin > docker-compose.yml
      else
        render_docker_compose_traefik_builtin > docker-compose.yml
      fi
      if [[ "$ENABLE_PROXY" == "true" ]]; then
        # Create placeholder proxy.env so docker-compose can validate
        # This will be overwritten with the actual token after netbird-server starts
        echo "# Placeholder - will be updated with token after netbird-server starts" > proxy.env
        echo "NB_PROXY_TOKEN=placeholder" >> proxy.env
        # TCP ServersTransport for PROXY protocol v2 to the proxy backend
        render_traefik_dynamic > traefik-dynamic.yaml
        if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
          mkdir -p crowdsec
        fi
      fi
      ;;
    1)
      if [[ "$ARCHITECTURE" == "split" ]]; then
        render_docker_compose_split_traefik > docker-compose.yml
      else
        render_docker_compose_traefik > docker-compose.yml
      fi
      ;;
    2|3|4|5)
      if [[ "$ARCHITECTURE" == "split" ]]; then
        render_docker_compose_split_exposed_ports > docker-compose.yml
      else
        render_docker_compose_exposed_ports > docker-compose.yml
      fi
      case "$REVERSE_PROXY_TYPE" in
        2) render_nginx_conf > nginx-netbird.conf ;;
        3) render_npm_advanced_config > npm-advanced-config.txt ;;
        4) render_external_caddyfile > caddyfile-netbird.txt ;;
      esac
      ;;
    *)
      echo "Invalid reverse proxy type: $REVERSE_PROXY_TYPE" > /dev/stderr
      exit 1
      ;;
  esac

  # Common files for all configurations
  render_dashboard_env > dashboard.env
  if [[ "$ARCHITECTURE" == "split" ]]; then
    render_management_json | jq . > management.json
  else
    render_combined_yaml > config.yaml
  fi
  return 0
}

print_render_only_summary() {
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  CONFIGURATION RENDERED"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "Generated files (services were NOT started):"
  for f in docker-compose.yml dashboard.env config.yaml management.json setup.env \
           nginx-netbird.conf npm-advanced-config.txt caddyfile-netbird.txt traefik-dynamic.yaml; do
    [[ -f "$f" ]] && echo "  - $f"
  done
  echo ""
  echo "Start the deployment with:"
  echo "  $DOCKER_COMPOSE_COMMAND up -d"
  print_post_setup_instructions
  return 0
}

start_services_and_show_instructions() {
  # For built-in Traefik, start containers immediately
  # For NPM, start containers first (NPM needs services running to create proxy)
  # For other external proxies, show instructions first and wait for user confirmation
  if [[ "$REVERSE_PROXY_TYPE" == "0" ]]; then
    # Built-in Traefik - two-phase startup if proxy is enabled
    echo -e "$MSG_STARTING_SERVICES"

    if [[ "$ENABLE_PROXY" == "true" ]]; then
      # Phase 1: Start core services (without proxy)
      local core_services="traefik dashboard netbird-server"
      if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
        core_services="$core_services crowdsec"
      fi
      echo "Starting core services..."
      $DOCKER_COMPOSE_COMMAND up -d $core_services

      sleep 3
      wait_management_proxy traefik

      # Phase 2: Create proxy token and start proxy
      echo ""
      echo "Creating proxy access token..."
      # Use docker exec with bash to run the token command directly
      PROXY_TOKEN=$($DOCKER_COMPOSE_COMMAND exec -T netbird-server \
        /go/bin/netbird-server token create --name "default-proxy" --config /etc/netbird/config.yaml 2>/dev/null | grep "^Token:" | awk '{print $2}')

      if [[ -z "$PROXY_TOKEN" ]]; then
        echo "ERROR: Failed to create proxy token. Check netbird-server logs." > /dev/stderr
        $DOCKER_COMPOSE_COMMAND logs --tail=20 netbird-server
        exit 1
      fi

      echo "Proxy token created successfully."

      if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
        echo "Registering CrowdSec bouncer..."
        local cs_retries=0
        while ! $DOCKER_COMPOSE_COMMAND exec -T crowdsec cscli lapi status >/dev/null 2>&1; do
          cs_retries=$((cs_retries + 1))
          if [[ $cs_retries -ge 30 ]]; then
            echo "WARNING: CrowdSec did not become ready. Skipping CrowdSec setup." > /dev/stderr
            echo "You can register a bouncer manually later with:" > /dev/stderr
            echo "  docker exec netbird-crowdsec cscli bouncers add netbird-proxy -o raw" > /dev/stderr
            ENABLE_CROWDSEC="false"
            break
          fi
          sleep 2
        done

        if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
          CROWDSEC_BOUNCER_KEY=$($DOCKER_COMPOSE_COMMAND exec -T crowdsec \
            cscli bouncers add netbird-proxy -o raw 2>/dev/null)
          if [[ -z "$CROWDSEC_BOUNCER_KEY" ]]; then
            echo "WARNING: Failed to create CrowdSec bouncer key. Skipping CrowdSec setup." > /dev/stderr
            ENABLE_CROWDSEC="false"
          else
            echo "CrowdSec bouncer registered."
          fi
        fi
      fi

      render_proxy_env > proxy.env

      # Start proxy service
      echo "Starting proxy service..."
      $DOCKER_COMPOSE_COMMAND up -d proxy
    else
      # No proxy - start all services at once
      $DOCKER_COMPOSE_COMMAND up -d

      sleep 3
      wait_management_proxy traefik
    fi

    echo -e "$MSG_DONE"
    print_post_setup_instructions
  elif [[ "$REVERSE_PROXY_TYPE" == "1" ]]; then
    # External Traefik - start containers, then show instructions
    # Traefik discovers services via Docker labels, so containers must be running
    echo -e "$MSG_STARTING_SERVICES"
    $DOCKER_COMPOSE_COMMAND up -d

    sleep 3
    wait_management_proxy detect-traefik

    echo -e "$MSG_DONE"
    print_post_setup_instructions
    echo ""
    echo "NetBird containers are running. Once Traefik is connected, access the dashboard at:"
    echo "  $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  elif [[ "$REVERSE_PROXY_TYPE" == "3" ]]; then
    # NPM - start containers first, then show instructions
    # NPM requires backend services to be running before creating proxy hosts
    echo -e "$MSG_STARTING_SERVICES"
    $DOCKER_COMPOSE_COMMAND up -d

    sleep 3
    wait_management_direct

    echo -e "$MSG_DONE"
    print_post_setup_instructions
    echo ""
    echo "NetBird containers are running. Configure NPM as shown above, then access:"
    echo "  $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  else
    # External proxies (nginx, external Caddy, other) - need manual config first
    print_post_setup_instructions

    if [[ "$NON_INTERACTIVE" != "true" ]]; then
      echo ""
      echo -n "Press Enter when your reverse proxy is configured (or Ctrl+C to exit)... "
      read -r < /dev/tty
    fi

    echo -e "$MSG_STARTING_SERVICES"
    $DOCKER_COMPOSE_COMMAND up -d

    sleep 3
    wait_management_direct

    echo -e "$MSG_DONE"
    echo "NetBird is now running. Access the dashboard at:"
    echo "  $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  fi
  return 0
}

init_environment() {
  if [[ "$RENDER_ONLY" == "true" ]]; then
    # Rendering does not need a working Docker daemon; fall back for hint text
    if command -v docker-compose &> /dev/null; then
      DOCKER_COMPOSE_COMMAND="docker-compose"
    else
      DOCKER_COMPOSE_COMMAND="docker compose"
    fi
  else
    DOCKER_COMPOSE_COMMAND=$(check_docker_compose)
    check_docker_sock_perms
  fi

  check_jq

  initialize_default_values
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    load_setup_env
  fi

  configure_domain
  configure_idp
  configure_architecture
  configure_datastore
  configure_reverse_proxy
  ensure_secrets

  if [[ "$NON_INTERACTIVE" != "true" ]]; then
    check_existing_installation
  fi

  if [[ "$IDP_MODE" == "external" ]]; then
    fetch_oidc_configuration
  fi

  write_setup_env
  generate_configuration_files

  if [[ "$RENDER_ONLY" == "true" ]]; then
    print_render_only_summary
    return 0
  fi

  start_services_and_show_instructions
  return 0
}

############################################
# Configuration File Renderers
############################################

render_docker_compose_traefik_builtin() {
  # Generate proxy service section and Traefik dynamic config if enabled
  local proxy_service=""
  local proxy_volumes=""
  local crowdsec_service=""
  local crowdsec_volumes=""
  local traefik_file_provider=""
  local traefik_dynamic_volume=""
  if [[ "$ENABLE_PROXY" == "true" ]]; then
    traefik_file_provider='      - "--providers.file.filename=/etc/traefik/dynamic.yaml"'
    traefik_dynamic_volume="      - ./traefik-dynamic.yaml:/etc/traefik/dynamic.yaml:ro"

    local proxy_depends="
      netbird-server:
        condition: service_started"
    if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
      proxy_depends="
      netbird-server:
        condition: service_started
      crowdsec:
        condition: service_healthy"
    fi

    proxy_service="
  # NetBird Proxy - exposes internal resources to the internet
  proxy:
    image: $NETBIRD_PROXY_IMAGE
    container_name: netbird-proxy
    ports:
    - 51820:51820/udp
    restart: unless-stopped
    networks: [netbird]
    depends_on:${proxy_depends}
    env_file:
      - ./proxy.env
    volumes:
      - netbird_proxy_certs:/certs
    labels:
      # TCP passthrough for any unmatched domain (proxy handles its own TLS)
      - traefik.enable=true
      - traefik.tcp.routers.proxy-passthrough.entrypoints=websecure
      - traefik.tcp.routers.proxy-passthrough.rule=HostSNI(\`*\`)
      - traefik.tcp.routers.proxy-passthrough.tls.passthrough=true
      - traefik.tcp.routers.proxy-passthrough.service=proxy-tls
      - traefik.tcp.routers.proxy-passthrough.priority=1
      - traefik.tcp.services.proxy-tls.loadbalancer.server.port=8443
      - traefik.tcp.services.proxy-tls.loadbalancer.serverstransport=pp-v2@file
    logging:
      driver: \"json-file\"
      options:
        max-size: \"500m\"
        max-file: \"2\"
"
    proxy_volumes="
  netbird_proxy_certs:"

    if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
      crowdsec_service="
  crowdsec:
    image: $CROWDSEC_IMAGE
    container_name: netbird-crowdsec
    restart: unless-stopped
    networks: [netbird]
    environment:
      COLLECTIONS: crowdsecurity/linux
    volumes:
      - ./crowdsec:/etc/crowdsec
      - crowdsec_db:/var/lib/crowdsec/data
    healthcheck:
      test: ["CMD", "cscli", "lapi", "status"]
      interval: 10s
      timeout: 5s
      retries: 15
    labels:
      - traefik.enable=false
    logging:
      driver: \"json-file\"
      options:
        max-size: \"500m\"
        max-file: \"2\"
"
      crowdsec_volumes="
  crowdsec_db:"
    fi
  fi

  cat <<EOF
services:
  # Traefik reverse proxy (automatic TLS via Let's Encrypt)
  traefik:
    image: $TRAEFIK_IMAGE
    container_name: netbird-traefik
    restart: unless-stopped
    networks:
      netbird:
        ipv4_address: $TRAEFIK_IP
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
      # Disable timeouts for long-lived gRPC streams
      - "--entrypoints.websecure.transport.respondingTimeouts.readTimeout=0"
      - "--entrypoints.websecure.transport.respondingTimeouts.writeTimeout=0"
      - "--entrypoints.websecure.transport.respondingTimeouts.idleTimeout=0"
      # HTTP to HTTPS redirect
      - "--entrypoints.web.http.redirections.entrypoint.to=websecure"
      - "--entrypoints.web.http.redirections.entrypoint.scheme=https"
      # Let's Encrypt ACME
      - "--certificatesresolvers.letsencrypt.acme.email=$TRAEFIK_ACME_EMAIL"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.letsencrypt.acme.tlschallenge=true"
      # gRPC transport settings
      - "--serverstransport.forwardingtimeouts.responseheadertimeout=0s"
      - "--serverstransport.forwardingtimeouts.idleconntimeout=0s"
$traefik_file_provider
    ports:
      - '443:443'
      - '80:80'
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - netbird_traefik_letsencrypt:/letsencrypt
$traefik_dynamic_volume
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # UI dashboard
  dashboard:
    image: $DASHBOARD_IMAGE
    container_name: netbird-dashboard
    restart: unless-stopped
    networks: [netbird]
    env_file:
      - ./dashboard.env
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-dashboard.rule=Host(\`$NETBIRD_DOMAIN\`)
      - traefik.http.routers.netbird-dashboard.entrypoints=websecure
      - traefik.http.routers.netbird-dashboard.tls=true
      - traefik.http.routers.netbird-dashboard.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-dashboard.service=dashboard
      - traefik.http.routers.netbird-dashboard.priority=1
      - traefik.http.services.dashboard.loadbalancer.server.port=80
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Combined server (Management + Signal + Relay + STUN)
  netbird-server:
    image: $NETBIRD_SERVER_IMAGE
    container_name: netbird-server
    restart: unless-stopped
    networks: [netbird]
    ports:
      - '$NETBIRD_STUN_PORT:$NETBIRD_STUN_PORT/udp'
    volumes:
      - netbird_data:/var/lib/netbird
      - ./config.yaml:/etc/netbird/config.yaml
    command: ["--config", "/etc/netbird/config.yaml"]
    labels:
      - traefik.enable=true
      # gRPC router (needs h2c backend for HTTP/2 cleartext)
      - traefik.http.routers.netbird-grpc.rule=Host(\`$NETBIRD_DOMAIN\`) && (PathPrefix(\`/signalexchange.SignalExchange/\`) || PathPrefix(\`/management.ManagementService/\`) || PathPrefix(\`/management.ProxyService/\`))
      - traefik.http.routers.netbird-grpc.entrypoints=websecure
      - traefik.http.routers.netbird-grpc.tls=true
      - traefik.http.routers.netbird-grpc.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-grpc.service=netbird-server-h2c
      - traefik.http.routers.netbird-grpc.priority=100
      # Backend router (relay, WebSocket, API, OAuth2)
      - traefik.http.routers.netbird-backend.rule=Host(\`$NETBIRD_DOMAIN\`) && (PathPrefix(\`/relay\`) || PathPrefix(\`/ws-proxy/\`) || PathPrefix(\`/api\`) || PathPrefix(\`/oauth2\`))
      - traefik.http.routers.netbird-backend.entrypoints=websecure
      - traefik.http.routers.netbird-backend.tls=true
      - traefik.http.routers.netbird-backend.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-backend.service=netbird-server
      - traefik.http.routers.netbird-backend.priority=100
      # Services
      - traefik.http.services.netbird-server.loadbalancer.server.port=80
      - traefik.http.services.netbird-server-h2c.loadbalancer.server.port=80
      - traefik.http.services.netbird-server-h2c.loadbalancer.server.scheme=h2c
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
${proxy_service}${crowdsec_service}
volumes:
  netbird_data:
  netbird_traefik_letsencrypt:${proxy_volumes}${crowdsec_volumes}

networks:
  netbird:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
          gateway: 172.30.0.1
EOF
  return 0
}

render_combined_yaml() {
  cat <<EOF
# Combined NetBird Server Configuration (Simplified)
# Generated by getting-started.sh

server:
  listenAddress: ":80"
  exposedAddress: "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN:$NETBIRD_PORT"
  stunPorts:
    - $NETBIRD_STUN_PORT
  metricsPort: 9090
  healthcheckAddress: ":9000"
  logLevel: "info"
  logFile: "console"

  authSecret: "$NETBIRD_RELAY_AUTH_SECRET"
  dataDir: "/var/lib/netbird"

  auth:
    issuer: "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/oauth2"
    signKeyRefreshEnabled: true
    dashboardRedirectURIs:
      - "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/nb-auth"
      - "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/nb-silent-auth"
    cliRedirectURIs:
      - "http://localhost:53000/"

  reverseProxy:
    trustedHTTPProxies:
      - "$TRAEFIK_IP/32"

  store:
    engine: "$STORE_ENGINE"
$(if [[ "$STORE_ENGINE" == "postgres" ]]; then echo "    dsn: \"$POSTGRES_DSN\""; fi)
    encryptionKey: "$DATASTORE_ENCRYPTION_KEY"
EOF
  return 0
}

render_management_json() {
  local mgmt_issuer mgmt_audience mgmt_keys_location mgmt_oidc_endpoint mgmt_signkey_refresh
  local signal_proto="http"
  if [[ "$NETBIRD_HTTP_PROTOCOL" == "https" ]]; then
    signal_proto="https"
  fi

  if [[ "$IDP_MODE" == "embedded" ]]; then
    mgmt_issuer="$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/oauth2"
    mgmt_audience="netbird-dashboard"
    mgmt_keys_location="${mgmt_issuer}/keys"
    mgmt_oidc_endpoint="${mgmt_issuer}/.well-known/openid-configuration"
    mgmt_signkey_refresh="true"
  else
    mgmt_issuer="$NETBIRD_AUTH_AUTHORITY"
    mgmt_audience="$AUTH_AUDIENCE"
    mgmt_keys_location="$NETBIRD_AUTH_JWT_CERTS"
    mgmt_oidc_endpoint="$AUTH_OIDC_ENDPOINT"
    mgmt_signkey_refresh="false"
  fi
  mgmt_signkey_refresh="${NETBIRD_MGMT_IDP_SIGNKEY_REFRESH:-$mgmt_signkey_refresh}"

  local trusted_proxies="[]"
  if [[ "$REVERSE_PROXY_TYPE" == "0" ]]; then
    trusted_proxies="[\"$TRAEFIK_IP/32\"]"
  fi

  cat <<EOF
{
    "Stuns": [
        {
            "Proto": "udp",
            "URI": "stun:$NETBIRD_DOMAIN:$NETBIRD_STUN_PORT",
            "Username": "",
            "Password": null
        }
    ],
    "Relay": {
        "Addresses": ["$NETBIRD_RELAY_PROTO://$NETBIRD_DOMAIN:$NETBIRD_PORT"],
        "CredentialsTTL": "24h",
        "Secret": "$NETBIRD_RELAY_AUTH_SECRET"
    },
    "Signal": {
        "Proto": "$signal_proto",
        "URI": "$NETBIRD_DOMAIN:$NETBIRD_PORT",
        "Username": "",
        "Password": null
    },
    "ReverseProxy": {
        "TrustedHTTPProxies": $trusted_proxies,
        "TrustedHTTPProxiesCount": 0,
        "TrustedPeers": ["0.0.0.0/0"]
    },
    "Datadir": "/var/lib/netbird",
    "DataStoreEncryptionKey": "$DATASTORE_ENCRYPTION_KEY",
    "StoreConfig": {
        "Engine": "$STORE_ENGINE"
    },
    "HttpConfig": {
        "Address": "0.0.0.0:80",
        "AuthIssuer": "$mgmt_issuer",
        "AuthAudience": "$mgmt_audience",
        "AuthKeysLocation": "$mgmt_keys_location",
        "OIDCConfigEndpoint": "$mgmt_oidc_endpoint",
        "IdpSignKeyRefreshEnabled": $mgmt_signkey_refresh
    }$(render_management_json_idp_section)
}
EOF
  return 0
}

render_idp_manager_extra_config() {
  local extra_config="{}"
  local var key value

  # Extract extra config from all env prefixed with NETBIRD_IDP_MGMT_EXTRA_.
  # Preserve configure.sh's snake-case to CamelCase conversion so existing setup.env files keep working.
  for var in ${!NETBIRD_IDP_MGMT_EXTRA_*}; do
    key=$(
      echo "${var#NETBIRD_IDP_MGMT_EXTRA_}" | awk -F "_" \
        '{for (i=1; i<=NF; i++) {output=output substr($i,1,1) tolower(substr($i,2))} print output}'
    )
    value="${!var}"
    extra_config=$(jq -c --arg k "$key" --arg v "$value" '.[$k] = $v' <<<"$extra_config")
  done

  printf '%s' "$extra_config"
  return 0
}

render_management_json_idp_section() {
  if [[ "$IDP_MODE" == "embedded" ]]; then
    cat <<EOF
,
    "EmbeddedIdP": {
        "Enabled": true,
        "Issuer": "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/oauth2",
        "LocalAddress": "localhost:80",
        "Storage": {
            "Type": "sqlite3",
            "Config": {
                "File": "/var/lib/netbird/idp.db"
            }
        },
        "DashboardRedirectURIs": [
            "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN$AUTH_REDIRECT_URI",
            "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN$AUTH_SILENT_REDIRECT_URI"
        ],
        "CLIRedirectURIs": ["http://localhost:53000/"],
        "SignKeyRefreshEnabled": true
    }
EOF
    return 0
  fi

  local use_id_token="false"
  if [[ "$TOKEN_SOURCE" == "idToken" ]]; then
    use_id_token="true"
  fi

  cat <<EOF
,
    "PKCEAuthorizationFlow": {
        "ProviderConfig": {
            "Audience": "$AUTH_AUDIENCE",
            "ClientID": "$AUTH_CLIENT_ID",
            "ClientSecret": "$AUTH_CLIENT_SECRET",
            "Domain": "",
            "AuthorizationEndpoint": "$NETBIRD_AUTH_PKCE_AUTHORIZATION_ENDPOINT",
            "TokenEndpoint": "$NETBIRD_AUTH_TOKEN_ENDPOINT",
            "Scope": "$AUTH_SUPPORTED_SCOPES",
            "RedirectURLs": ["http://localhost:53000"],
            "UseIDToken": $use_id_token
        }
    }
EOF

  if [[ -n "$NETBIRD_AUTH_DEVICE_AUTH_CLIENT_ID" && -n "$NETBIRD_AUTH_DEVICE_AUTH_ENDPOINT" ]]; then
    cat <<EOF
,
    "DeviceAuthorizationFlow": {
        "Provider": "hosted",
        "ProviderConfig": {
            "Audience": "$AUTH_AUDIENCE",
            "ClientID": "$NETBIRD_AUTH_DEVICE_AUTH_CLIENT_ID",
            "TokenEndpoint": "$NETBIRD_AUTH_TOKEN_ENDPOINT",
            "DeviceAuthEndpoint": "$NETBIRD_AUTH_DEVICE_AUTH_ENDPOINT",
            "Scope": "openid",
            "UseIDToken": $use_id_token
        }
    }
EOF
  fi

  if [[ -n "$NETBIRD_MGMT_IDP" ]]; then
    cat <<EOF
,
    "IdpManagerConfig": {
        "ManagerType": "$NETBIRD_MGMT_IDP",
        "ClientConfig": {
            "Issuer": "$NETBIRD_AUTH_AUTHORITY",
            "TokenEndpoint": "$NETBIRD_AUTH_TOKEN_ENDPOINT",
            "ClientID": "$NETBIRD_IDP_MGMT_CLIENT_ID",
            "ClientSecret": "$NETBIRD_IDP_MGMT_CLIENT_SECRET",
            "GrantType": "client_credentials"
        },
        "ExtraConfig": $(render_idp_manager_extra_config)
    }
EOF
  fi
  return 0
}

render_dashboard_env() {
  local auth_authority="$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/oauth2"
  local auth_audience="netbird-dashboard"
  local auth_client_id="netbird-dashboard"
  local auth_client_secret=""
  local auth_scopes="openid profile email groups"
  local use_auth0="false"
  local token_source="accessToken"
  local oidc_comment="using built-in IdP"

  if [[ "$IDP_MODE" == "external" ]]; then
    auth_authority="$NETBIRD_AUTH_AUTHORITY"
    auth_audience="$AUTH_AUDIENCE"
    auth_client_id="$AUTH_CLIENT_ID"
    auth_client_secret="$AUTH_CLIENT_SECRET"
    auth_scopes="$AUTH_SUPPORTED_SCOPES"
    use_auth0="$USE_AUTH0"
    token_source="$TOKEN_SOURCE"
    oidc_comment="using external OIDC provider"
  fi

  cat <<EOF
# Endpoints
NETBIRD_MGMT_API_ENDPOINT=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN
NETBIRD_MGMT_GRPC_API_ENDPOINT=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN
# OIDC - $oidc_comment
AUTH_AUDIENCE=$auth_audience
AUTH_CLIENT_ID=$auth_client_id
AUTH_CLIENT_SECRET=$auth_client_secret
AUTH_AUTHORITY=$auth_authority
USE_AUTH0=$use_auth0
AUTH_SUPPORTED_SCOPES=$auth_scopes
AUTH_REDIRECT_URI=$AUTH_REDIRECT_URI
AUTH_SILENT_REDIRECT_URI=$AUTH_SILENT_REDIRECT_URI
NETBIRD_TOKEN_SOURCE=$token_source
# SSL
NGINX_SSL_PORT=443
# Letsencrypt
LETSENCRYPT_DOMAIN=none
EOF
  return 0
}

render_traefik_dynamic() {
  cat <<'EOF'
tcp:
  serversTransports:
    pp-v2:
      proxyProtocol:
        version: 2
EOF
  return 0
}

render_proxy_env() {
  cat <<EOF
# NetBird Proxy Configuration
NB_PROXY_DEBUG_LOGS=false
# Use internal Docker network to connect to management (avoids hairpin NAT issues)
NB_PROXY_MANAGEMENT_ADDRESS=http://netbird-server:80
# Allow insecure gRPC connection to management (required for internal Docker network)
NB_PROXY_ALLOW_INSECURE=true
# Public URL where this proxy is reachable (used for cluster registration)
NB_PROXY_DOMAIN=$NETBIRD_DOMAIN
NB_PROXY_ADDRESS=:8443
NB_PROXY_TOKEN=$PROXY_TOKEN
NB_PROXY_CERTIFICATE_DIRECTORY=/certs
NB_PROXY_ACME_CERTIFICATES=true
NB_PROXY_ACME_CHALLENGE_TYPE=tls-alpn-01
NB_PROXY_FORWARDED_PROTO=https
# Enable PROXY protocol to preserve client IPs through L4 proxies (Traefik TCP passthrough)
NB_PROXY_PROXY_PROTOCOL=true
# Trust Traefik's IP for PROXY protocol headers
NB_PROXY_TRUSTED_PROXIES=$TRAEFIK_IP
EOF

  if [[ "$ENABLE_CROWDSEC" == "true" && -n "$CROWDSEC_BOUNCER_KEY" ]]; then
    cat <<EOF
NB_PROXY_CROWDSEC_API_URL=http://crowdsec:8080
NB_PROXY_CROWDSEC_API_KEY=$CROWDSEC_BOUNCER_KEY
EOF
  fi

  return 0
}

render_docker_compose_traefik() {
  local network_name="${TRAEFIK_EXTERNAL_NETWORK:-netbird}"
  local network_config=""
  if [[ -n "$TRAEFIK_EXTERNAL_NETWORK" ]]; then
    network_config="    external: true"
  fi

  # Build TLS labels - certresolver is optional
  local tls_labels=""
  if [[ -n "$TRAEFIK_CERTRESOLVER" ]]; then
    tls_labels="tls.certresolver=${TRAEFIK_CERTRESOLVER}"
  fi

  cat <<EOF
services:
  # UI dashboard
  dashboard:
    image: $DASHBOARD_IMAGE
    container_name: netbird-dashboard
    restart: unless-stopped
    networks: [$network_name]
    env_file:
      - ./dashboard.env
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-dashboard.rule=Host(\`$NETBIRD_DOMAIN\`)
      - traefik.http.routers.netbird-dashboard.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-dashboard.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-dashboard.${tls_labels}"; fi)
      - traefik.http.routers.netbird-dashboard.priority=1
      - traefik.http.services.netbird-dashboard.loadbalancer.server.port=80
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Combined server (Management + Signal + Relay + STUN)
  netbird-server:
    image: $NETBIRD_SERVER_IMAGE
    container_name: netbird-server
    restart: unless-stopped
    networks: [$network_name]
    ports:
      - '$NETBIRD_STUN_PORT:$NETBIRD_STUN_PORT/udp'
    volumes:
      - netbird_data:/var/lib/netbird
      - ./config.yaml:/etc/netbird/config.yaml
    command: ["--config", "/etc/netbird/config.yaml"]
    labels:
      - traefik.enable=true
      # gRPC router (needs h2c backend for HTTP/2 cleartext)
      - traefik.http.routers.netbird-grpc.rule=Host(\`$NETBIRD_DOMAIN\`) && (PathPrefix(\`/signalexchange.SignalExchange/\`) || PathPrefix(\`/management.ManagementService/\`))
      - traefik.http.routers.netbird-grpc.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-grpc.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-grpc.${tls_labels}"; fi)
      - traefik.http.routers.netbird-grpc.service=netbird-server-h2c
      # Backend router (relay, WebSocket, API, OAuth2)
      - traefik.http.routers.netbird-backend.rule=Host(\`$NETBIRD_DOMAIN\`) && (PathPrefix(\`/relay\`) || PathPrefix(\`/ws-proxy/\`) || PathPrefix(\`/api\`) || PathPrefix(\`/oauth2\`))
      - traefik.http.routers.netbird-backend.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-backend.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-backend.${tls_labels}"; fi)
      - traefik.http.routers.netbird-backend.service=netbird-server
      # Services
      - traefik.http.services.netbird-server.loadbalancer.server.port=80
      - traefik.http.services.netbird-server-h2c.loadbalancer.server.port=80
      - traefik.http.services.netbird-server-h2c.loadbalancer.server.scheme=h2c
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

volumes:
  netbird_data:

networks:
  $network_name:
$network_config
EOF
  return 0
}

render_docker_compose_exposed_ports() {
  local bind_addr=$(get_bind_address)
  local networks="[netbird]"
  local networks_config="networks:
  netbird:"

  # If an external network is specified, add it and include in service networks
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    networks="[netbird, $EXTERNAL_PROXY_NETWORK]"
    networks_config="networks:
  netbird:
  $EXTERNAL_PROXY_NETWORK:
    external: true"
  fi

  cat <<EOF
services:
  # UI dashboard
  dashboard:
    image: $DASHBOARD_IMAGE
    container_name: netbird-dashboard
    restart: unless-stopped
    networks: ${networks}
    ports:
      - '${bind_addr}:${DASHBOARD_HOST_PORT}:80'
    env_file:
      - ./dashboard.env
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Combined server (Management + Signal + Relay + STUN)
  netbird-server:
    image: $NETBIRD_SERVER_IMAGE
    container_name: netbird-server
    restart: unless-stopped
    networks: ${networks}
    ports:
      - '${bind_addr}:${MANAGEMENT_HOST_PORT}:80'
      - '$NETBIRD_STUN_PORT:$NETBIRD_STUN_PORT/udp'
    volumes:
      - netbird_data:/var/lib/netbird
      - ./config.yaml:/etc/netbird/config.yaml
    command: ["--config", "/etc/netbird/config.yaml"]
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

volumes:
  netbird_data:

${networks_config}
EOF
  return 0
}

get_postgres_dsn() {
  if [[ "$DEPLOY_POSTGRES" == "true" ]]; then
    echo "host=postgres user=netbird password=$POSTGRES_PASSWORD dbname=netbird port=5432 sslmode=disable"
  else
    echo "$POSTGRES_DSN"
  fi
  return 0
}

render_split_management_environment() {
  if [[ "$STORE_ENGINE" == "postgres" ]]; then
    cat <<EOF
    environment:
      - NETBIRD_STORE_ENGINE_POSTGRES_DSN=$(get_postgres_dsn)
EOF
  fi
  return 0
}

render_split_management_depends() {
  if [[ "$DEPLOY_POSTGRES" == "true" ]]; then
    cat <<EOF
    depends_on:
      postgres:
        condition: service_healthy
EOF
  fi
  return 0
}

render_split_postgres_service() {
  local networks="$1"
  if [[ "$DEPLOY_POSTGRES" != "true" ]]; then
    return 0
  fi
  cat <<EOF

  # PostgreSQL datastore for the management service
  postgres:
    image: $POSTGRES_IMAGE
    container_name: netbird-postgres
    restart: unless-stopped
    networks: $networks
    environment:
      POSTGRES_USER: netbird
      POSTGRES_PASSWORD: $POSTGRES_PASSWORD
      POSTGRES_DB: netbird
    volumes:
      - netbird_postgres:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U netbird -d netbird"]
      interval: 5s
      timeout: 5s
      retries: 12
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
EOF
  return 0
}

render_split_postgres_volume() {
  if [[ "$DEPLOY_POSTGRES" == "true" ]]; then
    echo "  netbird_postgres:"
  fi
  return 0
}

render_docker_compose_split_traefik_builtin() {
  cat <<EOF
services:
  # Traefik reverse proxy (automatic TLS via Let's Encrypt)
  traefik:
    image: $TRAEFIK_IMAGE
    container_name: netbird-traefik
    restart: unless-stopped
    networks:
      netbird:
        ipv4_address: $TRAEFIK_IP
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
      # Disable timeouts for long-lived gRPC streams
      - "--entrypoints.websecure.transport.respondingTimeouts.readTimeout=0"
      - "--entrypoints.websecure.transport.respondingTimeouts.writeTimeout=0"
      - "--entrypoints.websecure.transport.respondingTimeouts.idleTimeout=0"
      # HTTP to HTTPS redirect
      - "--entrypoints.web.http.redirections.entrypoint.to=websecure"
      - "--entrypoints.web.http.redirections.entrypoint.scheme=https"
      # Let's Encrypt ACME
      - "--certificatesresolvers.letsencrypt.acme.email=$TRAEFIK_ACME_EMAIL"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.letsencrypt.acme.tlschallenge=true"
      # gRPC transport settings
      - "--serverstransport.forwardingtimeouts.responseheadertimeout=0s"
      - "--serverstransport.forwardingtimeouts.idleconntimeout=0s"
    ports:
      - '443:443'
      - '80:80'
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - netbird_traefik_letsencrypt:/letsencrypt
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # UI dashboard
  dashboard:
    image: $DASHBOARD_IMAGE
    container_name: netbird-dashboard
    restart: unless-stopped
    networks: [netbird]
    env_file:
      - ./dashboard.env
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-dashboard.rule=Host(\`$NETBIRD_DOMAIN\`)
      - traefik.http.routers.netbird-dashboard.entrypoints=websecure
      - traefik.http.routers.netbird-dashboard.tls=true
      - traefik.http.routers.netbird-dashboard.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-dashboard.service=dashboard
      - traefik.http.routers.netbird-dashboard.priority=1
      - traefik.http.services.dashboard.loadbalancer.server.port=80
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Management service (API, gRPC$(if [[ "$IDP_MODE" == "embedded" ]]; then echo ", built-in IdP"; fi))
  management:
    image: $MANAGEMENT_IMAGE
    container_name: netbird-management
    restart: unless-stopped
    networks: [netbird]
$(render_split_management_depends)
    volumes:
      - netbird_mgmt:/var/lib/netbird
      - ./management.json:/etc/netbird/management.json
    command: [
      "--port", "80",
      "--log-file", "console",
      "--log-level", "info",
      "--dns-domain", "netbird.selfhosted"
    ]
$(render_split_management_environment)
    labels:
      - traefik.enable=true
      # gRPC router (needs h2c backend for HTTP/2 cleartext)
      - traefik.http.routers.netbird-mgmt-grpc.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/management.ManagementService/\`)
      - traefik.http.routers.netbird-mgmt-grpc.entrypoints=websecure
      - traefik.http.routers.netbird-mgmt-grpc.tls=true
      - traefik.http.routers.netbird-mgmt-grpc.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-mgmt-grpc.service=netbird-mgmt-h2c
      - traefik.http.routers.netbird-mgmt-grpc.priority=100
      # HTTP router (API, OAuth2, WebSocket gRPC fallback)
      - traefik.http.routers.netbird-mgmt-http.rule=Host(\`$NETBIRD_DOMAIN\`) && (PathPrefix(\`/api\`) || PathPrefix(\`/oauth2\`) || Path(\`/ws-proxy/management\`))
      - traefik.http.routers.netbird-mgmt-http.entrypoints=websecure
      - traefik.http.routers.netbird-mgmt-http.tls=true
      - traefik.http.routers.netbird-mgmt-http.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-mgmt-http.service=netbird-mgmt
      - traefik.http.routers.netbird-mgmt-http.priority=100
      # Services
      - traefik.http.services.netbird-mgmt.loadbalancer.server.port=80
      - traefik.http.services.netbird-mgmt-h2c.loadbalancer.server.port=80
      - traefik.http.services.netbird-mgmt-h2c.loadbalancer.server.scheme=h2c
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Signal service (peer signaling)
  signal:
    image: $SIGNAL_IMAGE
    container_name: netbird-signal
    restart: unless-stopped
    networks: [netbird]
    command: ["--log-file", "console", "--port", "80"]
    labels:
      - traefik.enable=true
      # gRPC router (needs h2c backend for HTTP/2 cleartext)
      - traefik.http.routers.netbird-signal-grpc.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/signalexchange.SignalExchange/\`)
      - traefik.http.routers.netbird-signal-grpc.entrypoints=websecure
      - traefik.http.routers.netbird-signal-grpc.tls=true
      - traefik.http.routers.netbird-signal-grpc.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-signal-grpc.service=netbird-signal-h2c
      - traefik.http.routers.netbird-signal-grpc.priority=100
      # WebSocket gRPC fallback
      - traefik.http.routers.netbird-signal-ws.rule=Host(\`$NETBIRD_DOMAIN\`) && Path(\`/ws-proxy/signal\`)
      - traefik.http.routers.netbird-signal-ws.entrypoints=websecure
      - traefik.http.routers.netbird-signal-ws.tls=true
      - traefik.http.routers.netbird-signal-ws.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-signal-ws.service=netbird-signal
      - traefik.http.routers.netbird-signal-ws.priority=100
      # Services
      - traefik.http.services.netbird-signal.loadbalancer.server.port=80
      - traefik.http.services.netbird-signal-h2c.loadbalancer.server.port=80
      - traefik.http.services.netbird-signal-h2c.loadbalancer.server.scheme=h2c
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Relay service (TURN replacement) with embedded STUN
  relay:
    image: $RELAY_IMAGE
    container_name: netbird-relay
    restart: unless-stopped
    networks: [netbird]
    ports:
      - '$NETBIRD_STUN_PORT:$NETBIRD_STUN_PORT/udp'
    environment:
      - NB_LOG_LEVEL=info
      - NB_LISTEN_ADDRESS=:$RELAY_HOST_PORT
      - NB_EXPOSED_ADDRESS=$NETBIRD_RELAY_PROTO://$NETBIRD_DOMAIN:$NETBIRD_PORT
      - NB_AUTH_SECRET=$NETBIRD_RELAY_AUTH_SECRET
      - NB_ENABLE_STUN=true
      - NB_STUN_PORTS=$NETBIRD_STUN_PORT
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-relay.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/relay\`)
      - traefik.http.routers.netbird-relay.entrypoints=websecure
      - traefik.http.routers.netbird-relay.tls=true
      - traefik.http.routers.netbird-relay.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-relay.service=netbird-relay
      - traefik.http.routers.netbird-relay.priority=100
      - traefik.http.services.netbird-relay.loadbalancer.server.port=$RELAY_HOST_PORT
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
$(render_split_postgres_service "[netbird]")
volumes:
  netbird_mgmt:
  netbird_traefik_letsencrypt:
$(render_split_postgres_volume)
networks:
  netbird:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
          gateway: 172.30.0.1
EOF
  return 0
}

render_docker_compose_split_traefik() {
  local network_name="${TRAEFIK_EXTERNAL_NETWORK:-netbird}"
  local network_config=""
  if [[ -n "$TRAEFIK_EXTERNAL_NETWORK" ]]; then
    network_config="    external: true"
  fi

  # Build TLS labels - certresolver is optional
  local tls_labels=""
  if [[ -n "$TRAEFIK_CERTRESOLVER" ]]; then
    tls_labels="tls.certresolver=${TRAEFIK_CERTRESOLVER}"
  fi

  cat <<EOF
services:
  # UI dashboard
  dashboard:
    image: $DASHBOARD_IMAGE
    container_name: netbird-dashboard
    restart: unless-stopped
    networks: [$network_name]
    env_file:
      - ./dashboard.env
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-dashboard.rule=Host(\`$NETBIRD_DOMAIN\`)
      - traefik.http.routers.netbird-dashboard.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-dashboard.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-dashboard.${tls_labels}"; fi)
      - traefik.http.routers.netbird-dashboard.priority=1
      - traefik.http.services.netbird-dashboard.loadbalancer.server.port=80
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Management service (API, gRPC$(if [[ "$IDP_MODE" == "embedded" ]]; then echo ", built-in IdP"; fi))
  management:
    image: $MANAGEMENT_IMAGE
    container_name: netbird-management
    restart: unless-stopped
    networks: [$network_name]
$(render_split_management_depends)
    volumes:
      - netbird_mgmt:/var/lib/netbird
      - ./management.json:/etc/netbird/management.json
    command: [
      "--port", "80",
      "--log-file", "console",
      "--log-level", "info",
      "--dns-domain", "netbird.selfhosted"
    ]
$(render_split_management_environment)
    labels:
      - traefik.enable=true
      # gRPC router (needs h2c backend for HTTP/2 cleartext)
      - traefik.http.routers.netbird-mgmt-grpc.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/management.ManagementService/\`)
      - traefik.http.routers.netbird-mgmt-grpc.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-mgmt-grpc.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-mgmt-grpc.${tls_labels}"; fi)
      - traefik.http.routers.netbird-mgmt-grpc.service=netbird-mgmt-h2c
      # HTTP router (API, OAuth2, WebSocket gRPC fallback)
      - traefik.http.routers.netbird-mgmt-http.rule=Host(\`$NETBIRD_DOMAIN\`) && (PathPrefix(\`/api\`) || PathPrefix(\`/oauth2\`) || Path(\`/ws-proxy/management\`))
      - traefik.http.routers.netbird-mgmt-http.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-mgmt-http.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-mgmt-http.${tls_labels}"; fi)
      - traefik.http.routers.netbird-mgmt-http.service=netbird-mgmt
      # Services
      - traefik.http.services.netbird-mgmt.loadbalancer.server.port=80
      - traefik.http.services.netbird-mgmt-h2c.loadbalancer.server.port=80
      - traefik.http.services.netbird-mgmt-h2c.loadbalancer.server.scheme=h2c
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Signal service (peer signaling)
  signal:
    image: $SIGNAL_IMAGE
    container_name: netbird-signal
    restart: unless-stopped
    networks: [$network_name]
    command: ["--log-file", "console", "--port", "80"]
    labels:
      - traefik.enable=true
      # gRPC router (needs h2c backend for HTTP/2 cleartext)
      - traefik.http.routers.netbird-signal-grpc.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/signalexchange.SignalExchange/\`)
      - traefik.http.routers.netbird-signal-grpc.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-signal-grpc.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-signal-grpc.${tls_labels}"; fi)
      - traefik.http.routers.netbird-signal-grpc.service=netbird-signal-h2c
      # WebSocket gRPC fallback
      - traefik.http.routers.netbird-signal-ws.rule=Host(\`$NETBIRD_DOMAIN\`) && Path(\`/ws-proxy/signal\`)
      - traefik.http.routers.netbird-signal-ws.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-signal-ws.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-signal-ws.${tls_labels}"; fi)
      - traefik.http.routers.netbird-signal-ws.service=netbird-signal
      # Services
      - traefik.http.services.netbird-signal.loadbalancer.server.port=80
      - traefik.http.services.netbird-signal-h2c.loadbalancer.server.port=80
      - traefik.http.services.netbird-signal-h2c.loadbalancer.server.scheme=h2c
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Relay service (TURN replacement) with embedded STUN
  relay:
    image: $RELAY_IMAGE
    container_name: netbird-relay
    restart: unless-stopped
    networks: [$network_name]
    ports:
      - '$NETBIRD_STUN_PORT:$NETBIRD_STUN_PORT/udp'
    environment:
      - NB_LOG_LEVEL=info
      - NB_LISTEN_ADDRESS=:$RELAY_HOST_PORT
      - NB_EXPOSED_ADDRESS=$NETBIRD_RELAY_PROTO://$NETBIRD_DOMAIN:$NETBIRD_PORT
      - NB_AUTH_SECRET=$NETBIRD_RELAY_AUTH_SECRET
      - NB_ENABLE_STUN=true
      - NB_STUN_PORTS=$NETBIRD_STUN_PORT
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-relay.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/relay\`)
      - traefik.http.routers.netbird-relay.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-relay.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-relay.${tls_labels}"; fi)
      - traefik.http.routers.netbird-relay.service=netbird-relay
      - traefik.http.services.netbird-relay.loadbalancer.server.port=$RELAY_HOST_PORT
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
$(render_split_postgres_service "[$network_name]")
volumes:
  netbird_mgmt:
$(render_split_postgres_volume)
networks:
  $network_name:
$network_config
EOF
  return 0
}

render_docker_compose_split_exposed_ports() {
  local bind_addr=$(get_bind_address)
  local networks="[netbird]"
  local networks_config="networks:
  netbird:"

  # If an external network is specified, add it and include in service networks
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    networks="[netbird, $EXTERNAL_PROXY_NETWORK]"
    networks_config="networks:
  netbird:
  $EXTERNAL_PROXY_NETWORK:
    external: true"
  fi

  cat <<EOF
services:
  # UI dashboard
  dashboard:
    image: $DASHBOARD_IMAGE
    container_name: netbird-dashboard
    restart: unless-stopped
    networks: ${networks}
    ports:
      - '${bind_addr}:${DASHBOARD_HOST_PORT}:80'
    env_file:
      - ./dashboard.env
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Management service (API, gRPC$(if [[ "$IDP_MODE" == "embedded" ]]; then echo ", built-in IdP"; fi))
  management:
    image: $MANAGEMENT_IMAGE
    container_name: netbird-management
    restart: unless-stopped
    networks: ${networks}
    ports:
      - '${bind_addr}:${MANAGEMENT_HOST_PORT}:80'
$(render_split_management_depends)
    volumes:
      - netbird_mgmt:/var/lib/netbird
      - ./management.json:/etc/netbird/management.json
    command: [
      "--port", "80",
      "--log-file", "console",
      "--log-level", "info",
      "--dns-domain", "netbird.selfhosted"
    ]
$(render_split_management_environment)
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Signal service (peer signaling)
  signal:
    image: $SIGNAL_IMAGE
    container_name: netbird-signal
    restart: unless-stopped
    networks: ${networks}
    ports:
      - '${bind_addr}:${SIGNAL_HOST_PORT}:80'
    command: ["--log-file", "console", "--port", "80"]
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Relay service (TURN replacement) with embedded STUN
  relay:
    image: $RELAY_IMAGE
    container_name: netbird-relay
    restart: unless-stopped
    networks: ${networks}
    ports:
      - '${bind_addr}:${RELAY_HOST_PORT}:${RELAY_HOST_PORT}'
      - '$NETBIRD_STUN_PORT:$NETBIRD_STUN_PORT/udp'
    environment:
      - NB_LOG_LEVEL=info
      - NB_LISTEN_ADDRESS=:$RELAY_HOST_PORT
      - NB_EXPOSED_ADDRESS=$NETBIRD_RELAY_PROTO://$NETBIRD_DOMAIN:$NETBIRD_PORT
      - NB_AUTH_SECRET=$NETBIRD_RELAY_AUTH_SECRET
      - NB_ENABLE_STUN=true
      - NB_STUN_PORTS=$NETBIRD_STUN_PORT
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
$(render_split_postgres_service "${networks}")
volumes:
  netbird_mgmt:
$(render_split_postgres_volume)
${networks_config}
EOF
  return 0
}

render_nginx_conf() {
  if [[ "$ARCHITECTURE" == "split" ]]; then
    render_nginx_conf_split
    return 0
  fi
  local upstream_host=$(get_upstream_host)
  local dashboard_addr="${upstream_host}:${DASHBOARD_HOST_PORT}"
  local server_addr="${upstream_host}:${MANAGEMENT_HOST_PORT}"
  local install_note="# 1. Update SSL certificate paths below
# 2. Copy to your nginx config directory:
#    Debian/Ubuntu: /etc/nginx/sites-available/netbird (then symlink to sites-enabled)
#    RHEL/CentOS:   /etc/nginx/conf.d/netbird.conf
# 3. Test and reload: nginx -t && systemctl reload nginx"

  # If running in Docker network, use container names
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    dashboard_addr="netbird-dashboard:80"
    server_addr="netbird-server:80"
    install_note="# This config uses container names since Nginx is on the same Docker network.
# Add this to your nginx.conf or include it from a separate file."
  fi

  cat <<EOF
# NetBird Nginx Configuration
# Generated by getting-started.sh
#
${install_note}

upstream netbird_dashboard {
    server ${dashboard_addr};
    keepalive 10;
}
upstream netbird_server {
    server ${server_addr};
}

server {
    listen 80;
    server_name $NETBIRD_DOMAIN;

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $NETBIRD_DOMAIN;

    # SSL/TLS Configuration
    # Update these paths based on your certificate source:
    #
    # Let's Encrypt (certbot):
    #   ssl_certificate /etc/letsencrypt/live/$NETBIRD_DOMAIN/fullchain.pem;
    #   ssl_certificate_key /etc/letsencrypt/live/$NETBIRD_DOMAIN/privkey.pem;
    #
    # Let's Encrypt (acme.sh):
    #   ssl_certificate /root/.acme.sh/$NETBIRD_DOMAIN/fullchain.cer;
    #   ssl_certificate_key /root/.acme.sh/$NETBIRD_DOMAIN/$NETBIRD_DOMAIN.key;
    #
    # Custom certificates:
    #   ssl_certificate /etc/ssl/certs/$NETBIRD_DOMAIN.crt;
    #   ssl_certificate_key /etc/ssl/private/$NETBIRD_DOMAIN.key;
    #
    ssl_certificate /path/to/your/fullchain.pem;
    ssl_certificate_key /path/to/your/privkey.pem;

    # Recommended SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    # Required for long-lived gRPC connections
    client_header_timeout 1d;
    client_body_timeout 1d;

    # Common proxy headers
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Scheme \$scheme;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host \$host;
    grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

    # WebSocket connections (relay, signal, management)
    location ~ ^/(relay|ws-proxy/) {
        proxy_pass http://netbird_server;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 1d;
    }

    # Native gRPC (signal + management)
    location ~ ^/(signalexchange\.SignalExchange|management\.ManagementService)/ {
        grpc_pass grpc://netbird_server;
        grpc_read_timeout 1d;
        grpc_send_timeout 1d;
        grpc_socket_keepalive on;
    }

    # HTTP routes (API + OAuth2)
    location ~ ^/(api|oauth2)/ {
        proxy_pass http://netbird_server;
        proxy_set_header Host \$host;
    }

    # Dashboard (catch-all)
    location / {
        proxy_pass http://netbird_dashboard;
    }
}
EOF
  return 0
}

render_nginx_conf_split() {
  local upstream_host=$(get_upstream_host)
  local dashboard_addr="${upstream_host}:${DASHBOARD_HOST_PORT}"
  local mgmt_addr="${upstream_host}:${MANAGEMENT_HOST_PORT}"
  local signal_addr="${upstream_host}:${SIGNAL_HOST_PORT}"
  local relay_addr="${upstream_host}:${RELAY_HOST_PORT}"
  local install_note="# 1. Update SSL certificate paths below
# 2. Copy to your nginx config directory:
#    Debian/Ubuntu: /etc/nginx/sites-available/netbird (then symlink to sites-enabled)
#    RHEL/CentOS:   /etc/nginx/conf.d/netbird.conf
# 3. Test and reload: nginx -t && systemctl reload nginx"

  # If running in Docker network, use container names
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    dashboard_addr="netbird-dashboard:80"
    mgmt_addr="netbird-management:80"
    signal_addr="netbird-signal:80"
    relay_addr="netbird-relay:${RELAY_HOST_PORT}"
    install_note="# This config uses container names since Nginx is on the same Docker network.
# Add this to your nginx.conf or include it from a separate file."
  fi

  cat <<EOF
# NetBird Nginx Configuration (split architecture)
# Generated by getting-started.sh
#
${install_note}

upstream netbird_dashboard {
    server ${dashboard_addr};
    keepalive 10;
}
upstream netbird_management {
    server ${mgmt_addr};
}
upstream netbird_signal {
    server ${signal_addr};
}
upstream netbird_relay {
    server ${relay_addr};
}

server {
    listen 80;
    server_name $NETBIRD_DOMAIN;

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $NETBIRD_DOMAIN;

    # SSL/TLS Configuration
    # Update these paths based on your certificate source:
    #
    # Let's Encrypt (certbot):
    #   ssl_certificate /etc/letsencrypt/live/$NETBIRD_DOMAIN/fullchain.pem;
    #   ssl_certificate_key /etc/letsencrypt/live/$NETBIRD_DOMAIN/privkey.pem;
    #
    # Let's Encrypt (acme.sh):
    #   ssl_certificate /root/.acme.sh/$NETBIRD_DOMAIN/fullchain.cer;
    #   ssl_certificate_key /root/.acme.sh/$NETBIRD_DOMAIN/$NETBIRD_DOMAIN.key;
    #
    # Custom certificates:
    #   ssl_certificate /etc/ssl/certs/$NETBIRD_DOMAIN.crt;
    #   ssl_certificate_key /etc/ssl/private/$NETBIRD_DOMAIN.key;
    #
    ssl_certificate /path/to/your/fullchain.pem;
    ssl_certificate_key /path/to/your/privkey.pem;

    # Recommended SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    # Required for long-lived gRPC connections
    client_header_timeout 1d;
    client_body_timeout 1d;

    # Common proxy headers
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Scheme \$scheme;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host \$host;
    grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

    # Relay WebSocket
    location /relay {
        proxy_pass http://netbird_relay;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 1d;
    }

    # Signal WebSocket gRPC fallback
    location /ws-proxy/signal {
        proxy_pass http://netbird_signal;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 1d;
    }

    # Management WebSocket gRPC fallback
    location /ws-proxy/management {
        proxy_pass http://netbird_management;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 1d;
    }

    # Native gRPC (signal)
    location /signalexchange.SignalExchange/ {
        grpc_pass grpc://netbird_signal;
        grpc_read_timeout 1d;
        grpc_send_timeout 1d;
        grpc_socket_keepalive on;
    }

    # Native gRPC (management)
    location /management.ManagementService/ {
        grpc_pass grpc://netbird_management;
        grpc_read_timeout 1d;
        grpc_send_timeout 1d;
        grpc_socket_keepalive on;
    }

    # HTTP routes (API + OAuth2)
    location ~ ^/(api|oauth2)/ {
        proxy_pass http://netbird_management;
        proxy_set_header Host \$host;
    }

    # Dashboard (catch-all)
    location / {
        proxy_pass http://netbird_dashboard;
    }
}
EOF
  return 0
}

render_external_caddyfile() {
  if [[ "$ARCHITECTURE" == "split" ]]; then
    render_external_caddyfile_split
    return 0
  fi
  local upstream_host=$(get_upstream_host)
  local dashboard_addr="${upstream_host}:${DASHBOARD_HOST_PORT}"
  local server_addr="${upstream_host}:${MANAGEMENT_HOST_PORT}"
  local install_note="# Add this block to your existing Caddyfile and reload Caddy"

  # If running in Docker network, use container names
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    dashboard_addr="netbird-dashboard:80"
    server_addr="netbird-server:80"
    install_note="# This config uses container names since Caddy is on the same Docker network.
# Add this block to your Caddyfile and reload Caddy."
  fi

  cat <<EOF
# NetBird Caddyfile Snippet
# Generated by getting-started.sh
#
${install_note}

$NETBIRD_DOMAIN {
    # Native gRPC (needs HTTP/2 cleartext to backend)
    @grpc header Content-Type application/grpc*
    reverse_proxy @grpc h2c://${server_addr}

    # Combined server paths (relay, signal, management, OAuth2)
    @backend path /relay* /ws-proxy/* /api/* /oauth2/*
    reverse_proxy @backend ${server_addr}

    # Dashboard (everything else)
    reverse_proxy /* ${dashboard_addr}
}
EOF
  return 0
}

render_external_caddyfile_split() {
  local upstream_host=$(get_upstream_host)
  local dashboard_addr="${upstream_host}:${DASHBOARD_HOST_PORT}"
  local mgmt_addr="${upstream_host}:${MANAGEMENT_HOST_PORT}"
  local signal_addr="${upstream_host}:${SIGNAL_HOST_PORT}"
  local relay_addr="${upstream_host}:${RELAY_HOST_PORT}"
  local install_note="# Add this block to your existing Caddyfile and reload Caddy"

  # If running in Docker network, use container names
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    dashboard_addr="netbird-dashboard:80"
    mgmt_addr="netbird-management:80"
    signal_addr="netbird-signal:80"
    relay_addr="netbird-relay:${RELAY_HOST_PORT}"
    install_note="# This config uses container names since Caddy is on the same Docker network.
# Add this block to your Caddyfile and reload Caddy."
  fi

  cat <<EOF
# NetBird Caddyfile Snippet (split architecture)
# Generated by getting-started.sh
#
${install_note}

$NETBIRD_DOMAIN {
    # Native gRPC (needs HTTP/2 cleartext to backend)
    @grpc-signal path /signalexchange.SignalExchange/*
    reverse_proxy @grpc-signal h2c://${signal_addr}

    @grpc-mgmt path /management.ManagementService/*
    reverse_proxy @grpc-mgmt h2c://${mgmt_addr}

    # Relay WebSocket
    @relay path /relay*
    reverse_proxy @relay ${relay_addr}

    # Signal WebSocket gRPC fallback
    @signal-ws path /ws-proxy/signal
    reverse_proxy @signal-ws ${signal_addr}

    # Management HTTP (API, OAuth2, WebSocket gRPC fallback)
    @mgmt path /ws-proxy/management /api/* /oauth2/*
    reverse_proxy @mgmt ${mgmt_addr}

    # Dashboard (everything else)
    reverse_proxy /* ${dashboard_addr}
}
EOF
  return 0
}

render_npm_advanced_config() {
  if [[ "$ARCHITECTURE" == "split" ]]; then
    render_npm_advanced_config_split
    return 0
  fi
  local upstream_host=$(get_upstream_host)
  local server_addr="${upstream_host}:${MANAGEMENT_HOST_PORT}"

  # If external network is specified, use container names instead of host addresses
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    server_addr="netbird-server:80"
  fi

  cat <<EOF
# Advanced Configuration for Nginx Proxy Manager
# Paste this into the "Advanced" tab of your Proxy Host configuration
#
# IMPORTANT: Enable "HTTP/2 Support" in the SSL tab for gRPC to work!

# Required for long-lived connections (gRPC and WebSocket)
client_header_timeout 1d;
client_body_timeout 1d;

# WebSocket connections (relay, signal, management)
location ~ ^/(relay|ws-proxy/) {
    proxy_pass http://${server_addr};
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 1d;
}

# Native gRPC (signal + management)
location ~ ^/(signalexchange\.SignalExchange|management\.ManagementService)/ {
    grpc_pass grpc://${server_addr};
    grpc_read_timeout 1d;
    grpc_send_timeout 1d;
    grpc_socket_keepalive on;
}

# HTTP routes (API + OAuth2)
location ~ ^/(api|oauth2)/ {
    proxy_pass http://${server_addr};
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
}
EOF
  return 0
}

render_npm_advanced_config_split() {
  local upstream_host=$(get_upstream_host)
  local mgmt_addr="${upstream_host}:${MANAGEMENT_HOST_PORT}"
  local signal_addr="${upstream_host}:${SIGNAL_HOST_PORT}"
  local relay_addr="${upstream_host}:${RELAY_HOST_PORT}"

  # If external network is specified, use container names instead of host addresses
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    mgmt_addr="netbird-management:80"
    signal_addr="netbird-signal:80"
    relay_addr="netbird-relay:${RELAY_HOST_PORT}"
  fi

  cat <<EOF
# Advanced Configuration for Nginx Proxy Manager (split architecture)
# Paste this into the "Advanced" tab of your Proxy Host configuration
#
# IMPORTANT: Enable "HTTP/2 Support" in the SSL tab for gRPC to work!

# Required for long-lived connections (gRPC and WebSocket)
client_header_timeout 1d;
client_body_timeout 1d;

# Relay WebSocket
location /relay {
    proxy_pass http://${relay_addr};
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 1d;
}

# Signal WebSocket gRPC fallback
location /ws-proxy/signal {
    proxy_pass http://${signal_addr};
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 1d;
}

# Management WebSocket gRPC fallback
location /ws-proxy/management {
    proxy_pass http://${mgmt_addr};
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 1d;
}

# Native gRPC (signal)
location /signalexchange.SignalExchange/ {
    grpc_pass grpc://${signal_addr};
    grpc_read_timeout 1d;
    grpc_send_timeout 1d;
    grpc_socket_keepalive on;
}

# Native gRPC (management)
location /management.ManagementService/ {
    grpc_pass grpc://${mgmt_addr};
    grpc_read_timeout 1d;
    grpc_send_timeout 1d;
    grpc_socket_keepalive on;
}

# HTTP routes (API + OAuth2)
location ~ ^/(api|oauth2)/ {
    proxy_pass http://${mgmt_addr};
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
}
EOF
  return 0
}

############################################
# Post-Setup Instructions per Proxy Type
############################################

print_container_ports() {
  local bind_addr="$1"
  echo "Container ports (bound to ${bind_addr}):"
  echo "  Dashboard:     ${DASHBOARD_HOST_PORT}"
  if [[ "$ARCHITECTURE" == "split" ]]; then
    echo "  Management:    ${MANAGEMENT_HOST_PORT} (API, gRPC, OAuth2)"
    echo "  Signal:        ${SIGNAL_HOST_PORT} (gRPC, WebSocket)"
    echo "  Relay:         ${RELAY_HOST_PORT} (WebSocket)"
  else
    echo "  NetBird Server: ${MANAGEMENT_HOST_PORT} (all services)"
  fi
  return 0
}

print_builtin_traefik_instructions() {
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  NETBIRD SETUP COMPLETE"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "You can access the NetBird dashboard at:"
  echo "  $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  echo ""
  echo "Follow the onboarding steps to set up your NetBird instance."
  echo ""
  echo "Traefik is handling TLS certificates automatically via Let's Encrypt."
  echo "If you see certificate warnings, wait a moment for certificate issuance to complete."
  echo ""
  echo "Open ports:"
  echo "  - 443/tcp   (HTTPS - all NetBird services)"
  echo "  - 80/tcp    (HTTP - redirects to HTTPS)"
  echo "  - $NETBIRD_STUN_PORT/udp   (STUN - required for NAT traversal)"
  if [[ "$ENABLE_PROXY" == "true" ]]; then
    echo "  - 51820/udp (WIREGUARD - (optional) for P2P proxy connections)"
  fi
  echo ""
  echo "This setup is ideal for homelabs and smaller organization deployments."
  echo "For enterprise environments requiring high availability and advanced integrations,"
  echo "consider a commercial on-prem license or scaling your open source deployment:"
  echo ""
  echo "  Commercial license: https://netbird.io/pricing#on-prem"
  echo "  Scaling guide:      https://docs.netbird.io/scaling-your-self-hosted-deployment"
  echo ""
  if [[ "$ENABLE_PROXY" == "true" ]]; then
    echo "NetBird Proxy:"
    echo "  The proxy service is enabled and running."
    echo "  Any domain NOT matching $NETBIRD_DOMAIN will be passed through to the proxy."
    echo "  The proxy handles its own TLS certificates via ACME TLS-ALPN-01 challenge."
    echo "  Point your proxy domain to this server's domain address like in the examples below:"
    echo ""
    echo "  *.$NETBIRD_DOMAIN    CNAME    $NETBIRD_DOMAIN"
    echo ""
    if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
      echo "CrowdSec IP Reputation:"
      echo "  CrowdSec LAPI is running and connected to the community blocklist."
      echo "  The proxy will automatically check client IPs against known threats."
      echo "  Enable CrowdSec per-service in the dashboard under Access Control."
      echo ""
      echo "  To enroll in CrowdSec Console (optional, for dashboard and premium blocklists):"
      echo "    docker exec netbird-crowdsec cscli console enroll <your-enrollment-key>"
      echo "  Get your enrollment key at: https://app.crowdsec.net"
      echo ""
    fi
  fi
  return 0
}

print_traefik_instructions() {
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  TRAEFIK SETUP"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "NetBird containers are configured with Traefik labels."
  echo ""
  echo "Configuration:"
  echo "  Entrypoint: $TRAEFIK_ENTRYPOINT"
  if [[ -n "$TRAEFIK_CERTRESOLVER" ]]; then
    echo "  Certificate resolver: $TRAEFIK_CERTRESOLVER"
  fi
  if [[ -n "$TRAEFIK_EXTERNAL_NETWORK" ]]; then
    echo "  Network: $TRAEFIK_EXTERNAL_NETWORK (external)"
  else
    echo "  Network: netbird"
  fi
  echo ""
  echo "$MSG_NEXT_STEPS"
  echo "  - Ensure Traefik is running and configured"
  if [[ -n "$TRAEFIK_EXTERNAL_NETWORK" ]]; then
    echo "  - Traefik must be on the '$TRAEFIK_EXTERNAL_NETWORK' network"
  fi
  echo "  - Entrypoint '$TRAEFIK_ENTRYPOINT' must be defined"
  if [[ -n "$TRAEFIK_CERTRESOLVER" ]]; then
    echo "  - Certificate resolver '$TRAEFIK_CERTRESOLVER' must be configured"
  fi
  echo "  - Disable read timeout on the entrypoint for gRPC streams:"
  echo "    --entrypoints.$TRAEFIK_ENTRYPOINT.transport.respondingTimeouts.readTimeout=0"
  echo "  - HTTP to HTTPS redirect (recommended)"
  return 0
}

print_nginx_instructions() {
  local bind_addr=$(get_bind_address)
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  NGINX SETUP"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "Generated: nginx-netbird.conf"
  echo ""
  echo "IMPORTANT: Nginx requires manual TLS certificate setup."
  echo "You'll need to obtain SSL/TLS certificates and configure the paths in the"
  echo "generated config file. The config includes examples for common certificate sources."
  echo ""
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    echo "NetBird containers have joined the '$EXTERNAL_PROXY_NETWORK' Docker network."
    echo "The config uses container names for upstream servers."
    echo ""
    echo "$MSG_NEXT_STEPS"
    echo "  1. Ensure your Nginx container has access to SSL certificates"
    echo "     (mount certificate directory as volume if needed)"
    echo "  2. Edit nginx-netbird.conf and update SSL certificate paths"
    echo "     The config includes examples for certbot, acme.sh, and custom certs"
    echo "  3. Include the config in your Nginx container's configuration"
    echo "  4. Reload Nginx"
  else
    echo "$MSG_NEXT_STEPS"
    echo "  1. Obtain SSL/TLS certificates (Let's Encrypt recommended)"
    echo "  2. Edit nginx-netbird.conf and update certificate paths"
    echo "  3. Install to /etc/nginx/sites-available/ (Debian) or /etc/nginx/conf.d/ (RHEL)"
    echo "  4. Test and reload: nginx -t && systemctl reload nginx"
    echo ""
    echo "For detailed TLS setup instructions, see:"
    echo "https://docs.netbird.io/selfhosted/reverse-proxy#tls-certificate-setup-for-nginx"
    echo ""
    print_container_ports "${bind_addr}"
  fi
  return 0
}

print_npm_instructions() {
  local bind_addr=$(get_bind_address)
  local upstream_host=$(get_upstream_host)
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  NGINX PROXY MANAGER SETUP"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "Generated: npm-advanced-config.txt"
  echo ""
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    echo "NetBird containers have joined the '$EXTERNAL_PROXY_NETWORK' Docker network."
    echo ""
    echo "In NPM, create a Proxy Host:"
    echo "  Domain: $NETBIRD_DOMAIN"
    echo "  Forward Hostname: netbird-dashboard"
    echo "  Forward Port: 80"
    echo "  Block Common Exploits: enabled"
    echo ""
    echo "  SSL tab:"
    echo "    - Request or select existing certificate"
    echo "    - Enable 'HTTP/2 Support' (REQUIRED for gRPC)"
    echo ""
    echo "  Advanced tab:"
    echo "    - Paste contents of npm-advanced-config.txt"
  else
    print_container_ports "${bind_addr}"
    echo ""
    echo "In NPM, create a Proxy Host:"
    echo "  Domain: $NETBIRD_DOMAIN"
    echo "  Forward Hostname/IP: ${upstream_host}"
    echo "  Forward Port: ${DASHBOARD_HOST_PORT}"
    echo "  Block Common Exploits: enabled"
    echo ""
    echo "  SSL tab:"
    echo "    - Request or select existing certificate"
    echo "    - Enable 'HTTP/2 Support' (REQUIRED for gRPC)"
    echo ""
    echo "  Advanced tab:"
    echo "    - Paste contents of npm-advanced-config.txt"
  fi
  return 0
}

print_external_caddy_instructions() {
  local bind_addr=$(get_bind_address)
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  EXTERNAL CADDY SETUP"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "Generated: caddyfile-netbird.txt"
  echo ""
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    echo "NetBird containers have joined the '$EXTERNAL_PROXY_NETWORK' Docker network."
    echo "The config uses container names for upstream servers."
    echo ""
    echo "$MSG_NEXT_STEPS"
    echo "  1. Add the contents of caddyfile-netbird.txt to your Caddyfile"
    echo "  2. Reload Caddy"
  else
    echo "$MSG_NEXT_STEPS"
    echo "  1. Add the contents of caddyfile-netbird.txt to your Caddyfile"
    echo "  2. Reload Caddy: caddy reload --config /path/to/Caddyfile"
    echo ""
    print_container_ports "${bind_addr}"
  fi
  return 0
}

print_manual_instructions() {
  local bind_addr=$(get_bind_address)
  local upstream_host=$(get_upstream_host)
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  MANUAL REVERSE PROXY SETUP"
  echo "$MSG_SEPARATOR"
  echo ""
  print_container_ports "${bind_addr}"
  echo ""
  if [[ "$ARCHITECTURE" == "split" ]]; then
    echo "Configure your reverse proxy with these routes:"
    echo ""
    echo "  WebSocket (relay + gRPC fallbacks):"
    echo "    /relay*                          -> ${upstream_host}:${RELAY_HOST_PORT}"
    echo "    /ws-proxy/signal                 -> ${upstream_host}:${SIGNAL_HOST_PORT}"
    echo "    /ws-proxy/management             -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
    echo "    (HTTP with WebSocket upgrade, extended timeout)"
    echo ""
    echo "  Native gRPC:"
    echo "    /signalexchange.SignalExchange/* -> ${upstream_host}:${SIGNAL_HOST_PORT}"
    echo "    /management.ManagementService/*  -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
    echo "    (gRPC/h2c - plaintext HTTP/2)"
    echo ""
    echo "  HTTP (API + IdP):"
    echo "    /api/*, /oauth2/*                -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
    echo ""
    echo "  Dashboard (catch-all):"
    echo "    /*                               -> ${upstream_host}:${DASHBOARD_HOST_PORT}"
  else
    echo "Configure your reverse proxy with these routes (all go to the same backend):"
    echo ""
    echo "  WebSocket (relay, signal, management WS proxy):"
    echo "    /relay*, /ws-proxy/*           -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
    echo "    (HTTP with WebSocket upgrade, extended timeout)"
    echo ""
    echo "  Native gRPC (signal + management):"
    echo "    /signalexchange.SignalExchange/* -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
    echo "    /management.ManagementService/* -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
    echo "    (gRPC/h2c - plaintext HTTP/2)"
    echo ""
    echo "  HTTP (API + embedded IdP):"
    echo "    /api/*, /oauth2/*              -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
    echo ""
    echo "  Dashboard (catch-all):"
    echo "    /*                             -> ${upstream_host}:${DASHBOARD_HOST_PORT}"
  fi
  echo ""
  echo "IMPORTANT: gRPC routes require HTTP/2 (h2c) upstream support."
  echo "WebSocket and gRPC connections need extended timeouts (recommend 1 day)."
  return 0
}

print_post_setup_instructions() {
  case "$REVERSE_PROXY_TYPE" in
    0)
      print_builtin_traefik_instructions
      ;;
    1)
      print_traefik_instructions
      ;;
    2)
      print_nginx_instructions
      ;;
    3)
      print_npm_instructions
      ;;
    4)
      print_external_caddy_instructions
      ;;
    5)
      print_manual_instructions
      ;;
    *)
      echo "Unknown reverse proxy type: $REVERSE_PROXY_TYPE" > /dev/stderr
      ;;
  esac
  return 0
}

print_usage() {
  cat <<EOF
Usage: getting-started.sh [OPTIONS]

Sets up a self-hosted NetBird deployment. Without options an interactive wizard
asks a few questions and saves the answers to setup.env.

Options:
  --non-interactive    Render and deploy from setup.env (or environment
                       variables) without prompting. Suitable for IaC.
  --render-only        Generate configuration files but do not start services.
  --setup-env=FILE     Read/write configuration from FILE (default: setup.env).
  -h, --help           Show this help.
EOF
  return 0
}

NON_INTERACTIVE="false"
RENDER_ONLY="false"
SETUP_ENV_FILE="setup.env"

for arg in "$@"; do
  case "$arg" in
    --non-interactive|-n) NON_INTERACTIVE="true" ;;
    --render-only) RENDER_ONLY="true" ;;
    --setup-env=*) SETUP_ENV_FILE="${arg#*=}" ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" > /dev/stderr
      print_usage > /dev/stderr
      exit 1
      ;;
  esac
done

init_environment
