#!/bin/bash

set -e

# NetBird Getting Started with Embedded IdP (Dex)
# This script sets up NetBird with the embedded Dex identity provider
# No separate Dex container or reverse proxy needed - IdP is built into management server

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

read_reverse_proxy_type() {
  echo "" > /dev/stderr
  echo "Which reverse proxy will you use?" > /dev/stderr
  echo "  [0] Built-in Caddy (recommended - automatic TLS)" > /dev/stderr
  echo "  [1] Traefik (labels added to containers)" > /dev/stderr
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

wait_management() {
  set +e
  echo -n "Waiting for Management server to become ready"
  counter=1
  while true; do
    # Check the embedded IdP endpoint
    if curl -sk -f -o /dev/null "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/oauth2/.well-known/openid-configuration" 2>/dev/null; then
      break
    fi
    if [[ $counter -eq 60 ]]; then
      echo ""
      echo "Taking too long. Checking logs..."
      $DOCKER_COMPOSE_COMMAND logs --tail=20 caddy
      $DOCKER_COMPOSE_COMMAND logs --tail=20 management
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
  echo -n "Waiting for Management server to become ready"
  counter=1
  while true; do
    # Check the embedded IdP endpoint directly (no reverse proxy)
    if curl -sk -f -o /dev/null "http://${upstream_host}:${MANAGEMENT_HOST_PORT}/oauth2/.well-known/openid-configuration" 2>/dev/null; then
      break
    fi
    if [[ $counter -eq 60 ]]; then
      echo ""
      echo "Taking too long. Checking logs..."
      $DOCKER_COMPOSE_COMMAND logs --tail=20 management
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
  CADDY_SECURE_DOMAIN=""
  NETBIRD_PORT=80
  NETBIRD_HTTP_PROTOCOL="http"
  NETBIRD_RELAY_PROTO="rel"
  NETBIRD_RELAY_AUTH_SECRET=$(openssl rand -base64 32 | sed "$SED_STRIP_PADDING")
  # Note: DataStoreEncryptionKey must keep base64 padding (=) for Go's base64.StdEncoding
  DATASTORE_ENCRYPTION_KEY=$(openssl rand -base64 32)
  NETBIRD_STUN_PORT=3478

  # Docker images
  CADDY_IMAGE="caddy"
  DASHBOARD_IMAGE="netbirdio/dashboard:latest"
  SIGNAL_IMAGE="netbirdio/signal:latest"
  RELAY_IMAGE="netbirdio/relay:latest"
  MANAGEMENT_IMAGE="netbirdio/management:latest"

  # Reverse proxy configuration
  REVERSE_PROXY_TYPE="0"
  TRAEFIK_EXTERNAL_NETWORK=""
  TRAEFIK_ENTRYPOINT="websecure"
  TRAEFIK_CERTRESOLVER=""
  DASHBOARD_HOST_PORT="8080"
  MANAGEMENT_HOST_PORT="8081"
  SIGNAL_HOST_PORT="8083"
  SIGNAL_GRPC_PORT="10000"
  RELAY_HOST_PORT="8084"
  BIND_LOCALHOST_ONLY="true"
  EXTERNAL_PROXY_NETWORK=""
  return 0
}

configure_domain() {
  if ! check_nb_domain "$NETBIRD_DOMAIN"; then
    NETBIRD_DOMAIN=$(read_nb_domain)
  fi

  if [[ "$NETBIRD_DOMAIN" == "use-ip" ]]; then
    NETBIRD_DOMAIN=$(get_main_ip_address)
  else
    NETBIRD_PORT=443
    CADDY_SECURE_DOMAIN=", $NETBIRD_DOMAIN:$NETBIRD_PORT"
    NETBIRD_HTTP_PROTOCOL="https"
    NETBIRD_RELAY_PROTO="rels"
  fi
  return 0
}

configure_reverse_proxy() {
  # Prompt for reverse proxy type
  REVERSE_PROXY_TYPE=$(read_reverse_proxy_type)

  # Handle Traefik-specific prompts
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
  return 0
}

check_existing_installation() {
  if [[ -f management.json ]]; then
    echo "Generated files already exist, if you want to reinitialize the environment, please remove them first."
    echo "You can use the following commands:"
    echo "  $DOCKER_COMPOSE_COMMAND down --volumes # to remove all containers and volumes"
    echo "  rm -f docker-compose.yml Caddyfile dashboard.env management.json relay.env nginx-netbird.conf caddyfile-netbird.txt npm-advanced-config.txt"
    echo "Be aware that this will remove all data from the database, and you will have to reconfigure the dashboard."
    exit 1
  fi
  return 0
}

generate_configuration_files() {
  echo Rendering initial files...

  # Render docker-compose and proxy config based on selection
  case "$REVERSE_PROXY_TYPE" in
    0)
      render_docker_compose > docker-compose.yml
      render_caddyfile > Caddyfile
      ;;
    1)
      render_docker_compose_traefik > docker-compose.yml
      ;;
    2)
      render_docker_compose_exposed_ports > docker-compose.yml
      render_nginx_conf > nginx-netbird.conf
      ;;
    3)
      render_docker_compose_exposed_ports > docker-compose.yml
      render_npm_advanced_config > npm-advanced-config.txt
      ;;
    4)
      render_docker_compose_exposed_ports > docker-compose.yml
      render_external_caddyfile > caddyfile-netbird.txt
      ;;
    5)
      render_docker_compose_exposed_ports > docker-compose.yml
      ;;
    *)
      echo "Invalid reverse proxy type: $REVERSE_PROXY_TYPE" > /dev/stderr
      exit 1
      ;;
  esac

  # Common files for all configurations
  render_dashboard_env > dashboard.env
  render_management_json > management.json
  render_relay_env > relay.env
  return 0
}

start_services_and_show_instructions() {
  # For built-in Caddy and Traefik, start containers immediately
  # For NPM, start containers first (NPM needs services running to create proxy)
  # For other external proxies, show instructions first and wait for user confirmation
  if [[ "$REVERSE_PROXY_TYPE" == "0" ]]; then
    # Built-in Caddy - handles everything automatically
    echo -e "$MSG_STARTING_SERVICES"
    $DOCKER_COMPOSE_COMMAND up -d

    sleep 3
    wait_management

    echo -e "$MSG_DONE"
    print_post_setup_instructions
  elif [[ "$REVERSE_PROXY_TYPE" == "1" ]]; then
    # Traefik - start containers first, then show instructions
    # Traefik discovers services via Docker labels, so containers must be running
    echo -e "$MSG_STARTING_SERVICES"
    $DOCKER_COMPOSE_COMMAND up -d

    sleep 3
    wait_management_direct

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

    echo ""
    echo -n "Press Enter when your reverse proxy is configured (or Ctrl+C to exit)... "
    read -r < /dev/tty

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
  initialize_default_values
  configure_domain
  configure_reverse_proxy

  check_jq
  DOCKER_COMPOSE_COMMAND=$(check_docker_compose)

  check_existing_installation
  generate_configuration_files
  start_services_and_show_instructions
  return 0
}

############################################
# Configuration File Renderers
############################################

render_caddyfile() {
  cat <<EOF
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

:80${CADDY_SECURE_DOMAIN} {
    import security_headers
    # relay
    reverse_proxy /relay* relay:80
    # Signal
    reverse_proxy /ws-proxy/signal* signal:80
    reverse_proxy /signalexchange.SignalExchange/* h2c://signal:10000
    # Management
    reverse_proxy /api/* management:80
    reverse_proxy /ws-proxy/management* management:80
    reverse_proxy /management.ManagementService/* h2c://management:80
    reverse_proxy /oauth2/* management:80
    # Dashboard
    reverse_proxy /* dashboard:80
}
EOF
  return 0
}

render_management_json() {
  cat <<EOF
{
    "Stuns": [
        {
            "Proto": "udp",
            "URI": "stun:$NETBIRD_DOMAIN:$NETBIRD_STUN_PORT"
        }
    ],
    "Relay": {
        "Addresses": ["$NETBIRD_RELAY_PROTO://$NETBIRD_DOMAIN:$NETBIRD_PORT"],
        "CredentialsTTL": "24h",
        "Secret": "$NETBIRD_RELAY_AUTH_SECRET"
    },
    "Signal": {
        "Proto": "$NETBIRD_HTTP_PROTOCOL",
        "URI": "$NETBIRD_DOMAIN:$NETBIRD_PORT"
    },
    "Datadir": "/var/lib/netbird",
    "DataStoreEncryptionKey": "$DATASTORE_ENCRYPTION_KEY",
    "EmbeddedIdP": {
        "Enabled": true,
        "Issuer": "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/oauth2",
        "DashboardRedirectURIs": [
            "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/nb-auth",
            "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/nb-silent-auth"
        ]
    }
}
EOF
  return 0
}

render_dashboard_env() {
  cat <<EOF
# Endpoints
NETBIRD_MGMT_API_ENDPOINT=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN
NETBIRD_MGMT_GRPC_API_ENDPOINT=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN
# OIDC - using embedded IdP
AUTH_AUDIENCE=netbird-dashboard
AUTH_CLIENT_ID=netbird-dashboard
AUTH_CLIENT_SECRET=
AUTH_AUTHORITY=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/oauth2
USE_AUTH0=false
AUTH_SUPPORTED_SCOPES=openid profile email groups
AUTH_REDIRECT_URI=/nb-auth
AUTH_SILENT_REDIRECT_URI=/nb-silent-auth
# SSL
NGINX_SSL_PORT=443
# Letsencrypt
LETSENCRYPT_DOMAIN=none
EOF
  return 0
}

render_relay_env() {
  cat <<EOF
NB_LOG_LEVEL=info
NB_LISTEN_ADDRESS=:80
NB_EXPOSED_ADDRESS=$NETBIRD_RELAY_PROTO://$NETBIRD_DOMAIN:$NETBIRD_PORT
NB_AUTH_SECRET=$NETBIRD_RELAY_AUTH_SECRET
NB_ENABLE_STUN=true
NB_STUN_LOG_LEVEL=info
NB_STUN_PORTS=$NETBIRD_STUN_PORT
EOF
  return 0
}

render_docker_compose() {
  cat <<EOF
services:
  # Caddy reverse proxy
  caddy:
    image: $CADDY_IMAGE
    container_name: netbird-caddy
    restart: unless-stopped
    networks: [netbird]
    ports:
      - '443:443'
      - '443:443/udp'
      - '80:80'
    volumes:
      - netbird_caddy_data:/data
      - ./Caddyfile:/etc/caddy/Caddyfile
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
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Signal
  signal:
    image: $SIGNAL_IMAGE
    container_name: netbird-signal
    restart: unless-stopped
    networks: [netbird]
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Relay (includes embedded STUN server)
  relay:
    image: $RELAY_IMAGE
    container_name: netbird-relay
    restart: unless-stopped
    networks: [netbird]
    ports:
      - '$NETBIRD_STUN_PORT:$NETBIRD_STUN_PORT/udp'
    env_file:
      - ./relay.env
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Management (includes embedded IdP)
  management:
    image: $MANAGEMENT_IMAGE
    container_name: netbird-management
    restart: unless-stopped
    networks: [netbird]
    volumes:
      - netbird_management:/var/lib/netbird
      - ./management.json:/etc/netbird/management.json
    command: [
      "--port", "80",
      "--log-file", "console",
      "--log-level", "info",
      "--disable-anonymous-metrics=false",
      "--single-account-mode-domain=netbird.selfhosted",
      "--dns-domain=netbird.selfhosted",
      "--idp-sign-key-refresh-enabled",
    ]
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

volumes:
  netbird_caddy_data:
  netbird_management:

networks:
  netbird:
EOF
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

  # Signal
  signal:
    image: $SIGNAL_IMAGE
    container_name: netbird-signal
    restart: unless-stopped
    networks: [$network_name]
    labels:
      - traefik.enable=true
      # WebSocket router
      - traefik.http.routers.netbird-signal-ws.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/ws-proxy/signal\`)
      - traefik.http.routers.netbird-signal-ws.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-signal-ws.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-signal-ws.${tls_labels}"; fi)
      - traefik.http.routers.netbird-signal-ws.service=netbird-signal-ws
      - traefik.http.services.netbird-signal-ws.loadbalancer.server.port=80
      # gRPC router
      - traefik.http.routers.netbird-signal-grpc.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/signalexchange.SignalExchange/\`)
      - traefik.http.routers.netbird-signal-grpc.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-signal-grpc.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-signal-grpc.${tls_labels}"; fi)
      - traefik.http.routers.netbird-signal-grpc.service=netbird-signal-grpc
      - traefik.http.services.netbird-signal-grpc.loadbalancer.server.port=10000
      - traefik.http.services.netbird-signal-grpc.loadbalancer.server.scheme=h2c
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Relay (includes embedded STUN server)
  relay:
    image: $RELAY_IMAGE
    container_name: netbird-relay
    restart: unless-stopped
    networks: [$network_name]
    ports:
      - '$NETBIRD_STUN_PORT:$NETBIRD_STUN_PORT/udp'
    env_file:
      - ./relay.env
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-relay.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/relay\`)
      - traefik.http.routers.netbird-relay.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-relay.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-relay.${tls_labels}"; fi)
      - traefik.http.services.netbird-relay.loadbalancer.server.port=80
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Management (includes embedded IdP)
  management:
    image: $MANAGEMENT_IMAGE
    container_name: netbird-management
    restart: unless-stopped
    networks: [$network_name]
    volumes:
      - netbird_management:/var/lib/netbird
      - ./management.json:/etc/netbird/management.json
    command: [
      "--port", "80",
      "--log-file", "console",
      "--log-level", "info",
      "--disable-anonymous-metrics=false",
      "--single-account-mode-domain=netbird.selfhosted",
      "--dns-domain=netbird.selfhosted",
      "--idp-sign-key-refresh-enabled",
    ]
    labels:
      - traefik.enable=true
      # API router
      - traefik.http.routers.netbird-api.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/api\`)
      - traefik.http.routers.netbird-api.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-api.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-api.${tls_labels}"; fi)
      - traefik.http.routers.netbird-api.service=netbird-api
      - traefik.http.services.netbird-api.loadbalancer.server.port=80
      # Management WebSocket router
      - traefik.http.routers.netbird-mgmt-ws.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/ws-proxy/management\`)
      - traefik.http.routers.netbird-mgmt-ws.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-mgmt-ws.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-mgmt-ws.${tls_labels}"; fi)
      - traefik.http.routers.netbird-mgmt-ws.service=netbird-mgmt-ws
      - traefik.http.services.netbird-mgmt-ws.loadbalancer.server.port=80
      # Management gRPC router
      - traefik.http.routers.netbird-mgmt-grpc.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/management.ManagementService/\`)
      - traefik.http.routers.netbird-mgmt-grpc.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-mgmt-grpc.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-mgmt-grpc.${tls_labels}"; fi)
      - traefik.http.routers.netbird-mgmt-grpc.service=netbird-mgmt-grpc
      - traefik.http.services.netbird-mgmt-grpc.loadbalancer.server.port=80
      - traefik.http.services.netbird-mgmt-grpc.loadbalancer.server.scheme=h2c
      # OAuth2 router (embedded IdP)
      - traefik.http.routers.netbird-oauth2.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/oauth2\`)
      - traefik.http.routers.netbird-oauth2.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-oauth2.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-oauth2.${tls_labels}"; fi)
      - traefik.http.routers.netbird-oauth2.service=netbird-oauth2
      - traefik.http.services.netbird-oauth2.loadbalancer.server.port=80
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

volumes:
  netbird_management:

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

  # Signal
  signal:
    image: $SIGNAL_IMAGE
    container_name: netbird-signal
    restart: unless-stopped
    networks: ${networks}
    ports:
      - '${bind_addr}:${SIGNAL_HOST_PORT}:80'
      - '${bind_addr}:${SIGNAL_GRPC_PORT}:10000'
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Relay (includes embedded STUN server)
  relay:
    image: $RELAY_IMAGE
    container_name: netbird-relay
    restart: unless-stopped
    networks: ${networks}
    ports:
      - '${bind_addr}:${RELAY_HOST_PORT}:80'
      - '$NETBIRD_STUN_PORT:$NETBIRD_STUN_PORT/udp'
    env_file:
      - ./relay.env
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Management (includes embedded IdP)
  management:
    image: $MANAGEMENT_IMAGE
    container_name: netbird-management
    restart: unless-stopped
    networks: ${networks}
    ports:
      - '${bind_addr}:${MANAGEMENT_HOST_PORT}:80'
    volumes:
      - netbird_management:/var/lib/netbird
      - ./management.json:/etc/netbird/management.json
    command: [
      "--port", "80",
      "--log-file", "console",
      "--log-level", "info",
      "--disable-anonymous-metrics=false",
      "--single-account-mode-domain=netbird.selfhosted",
      "--dns-domain=netbird.selfhosted",
      "--idp-sign-key-refresh-enabled",
    ]
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

volumes:
  netbird_management:

${networks_config}
EOF
  return 0
}

render_nginx_conf() {
  local upstream_host=$(get_upstream_host)
  local dashboard_addr="${upstream_host}:${DASHBOARD_HOST_PORT}"
  local signal_grpc_addr="${upstream_host}:${SIGNAL_GRPC_PORT}"
  local signal_ws_addr="${upstream_host}:${SIGNAL_HOST_PORT}"
  local mgmt_addr="${upstream_host}:${MANAGEMENT_HOST_PORT}"
  local relay_addr="${upstream_host}:${RELAY_HOST_PORT}"
  local install_note="# 1. Update SSL certificate paths below
# 2. Copy to your nginx config directory:
#    Debian/Ubuntu: /etc/nginx/sites-available/netbird (then symlink to sites-enabled)
#    RHEL/CentOS:   /etc/nginx/conf.d/netbird.conf
# 3. Test and reload: nginx -t && systemctl reload nginx"

  # If running in Docker network, use container names
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    dashboard_addr="netbird-dashboard:80"
    signal_grpc_addr="netbird-signal:10000"
    signal_ws_addr="netbird-signal:80"
    mgmt_addr="netbird-management:80"
    relay_addr="netbird-relay:80"
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
upstream netbird_signal {
    server ${signal_grpc_addr};
}
upstream netbird_signal_ws {
    server ${signal_ws_addr};
}
upstream netbird_management {
    server ${mgmt_addr};
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

    # Relay (WebSocket)
    location /relay {
        proxy_pass http://netbird_relay;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 1d;
    }

    # Signal WebSocket
    location /ws-proxy/signal {
        proxy_pass http://netbird_signal_ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 1d;
    }

    # Signal gRPC
    location /signalexchange.SignalExchange/ {
        grpc_pass grpc://netbird_signal;
        grpc_read_timeout 1d;
        grpc_send_timeout 1d;
        grpc_socket_keepalive on;
    }

    # Management API
    location /api/ {
        proxy_pass http://netbird_management;
        proxy_set_header Host \$host;
    }

    # Management WebSocket
    location /ws-proxy/management {
        proxy_pass http://netbird_management;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 1d;
    }

    # Management gRPC
    location /management.ManagementService/ {
        grpc_pass grpc://netbird_management;
        grpc_read_timeout 1d;
        grpc_send_timeout 1d;
        grpc_socket_keepalive on;
    }

    # Embedded IdP OAuth2
    location /oauth2/ {
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
  local upstream_host=$(get_upstream_host)
  local dashboard_addr="${upstream_host}:${DASHBOARD_HOST_PORT}"
  local signal_grpc_addr="${upstream_host}:${SIGNAL_GRPC_PORT}"
  local signal_ws_addr="${upstream_host}:${SIGNAL_HOST_PORT}"
  local mgmt_addr="${upstream_host}:${MANAGEMENT_HOST_PORT}"
  local relay_addr="${upstream_host}:${RELAY_HOST_PORT}"
  local install_note="# Add this block to your existing Caddyfile and reload Caddy"

  # If running in Docker network, use container names
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    dashboard_addr="netbird-dashboard:80"
    signal_grpc_addr="netbird-signal:10000"
    signal_ws_addr="netbird-signal:80"
    mgmt_addr="netbird-management:80"
    relay_addr="netbird-relay:80"
    install_note="# This config uses container names since Caddy is on the same Docker network.
# Add this block to your Caddyfile and reload Caddy."
  fi

  cat <<EOF
# NetBird Caddyfile Snippet
# Generated by getting-started.sh
#
${install_note}

$NETBIRD_DOMAIN {
    # Relay (WebSocket)
    reverse_proxy /relay* ${relay_addr}

    # Signal WebSocket
    reverse_proxy /ws-proxy/signal* ${signal_ws_addr}

    # Signal gRPC (h2c for plaintext HTTP/2)
    reverse_proxy /signalexchange.SignalExchange/* h2c://${signal_grpc_addr}

    # Management API
    reverse_proxy /api/* ${mgmt_addr}

    # Management WebSocket
    reverse_proxy /ws-proxy/management* ${mgmt_addr}

    # Management gRPC
    reverse_proxy /management.ManagementService/* h2c://${mgmt_addr}

    # Embedded IdP OAuth2
    reverse_proxy /oauth2/* ${mgmt_addr}

    # Dashboard (catch-all)
    reverse_proxy /* ${dashboard_addr}
}
EOF
  return 0
}

render_npm_advanced_config() {
  local upstream_host=$(get_upstream_host)
  local relay_addr="${upstream_host}:${RELAY_HOST_PORT}"
  local signal_addr="${upstream_host}:${SIGNAL_HOST_PORT}"
  local signal_grpc_addr="${upstream_host}:${SIGNAL_GRPC_PORT}"
  local mgmt_addr="${upstream_host}:${MANAGEMENT_HOST_PORT}"

  # If external network is specified, use container names instead of host addresses
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    relay_addr="netbird-relay:80"
    signal_addr="netbird-signal:80"
    signal_grpc_addr="netbird-signal:10000"
    mgmt_addr="netbird-management:80"
  fi

  cat <<EOF
# Advanced Configuration for Nginx Proxy Manager
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

# Signal WebSocket
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

# Management WebSocket
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

# API routes
location /api/ {
    proxy_pass http://${mgmt_addr};
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
}

# OAuth2/IdP routes
location /oauth2/ {
    proxy_pass http://${mgmt_addr};
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
}

# gRPC for Signal service
location /signalexchange.SignalExchange/ {
    grpc_pass grpc://${signal_grpc_addr};
    grpc_read_timeout 1d;
    grpc_send_timeout 1d;
    grpc_socket_keepalive on;
}

# gRPC for Management service
location /management.ManagementService/ {
    grpc_pass grpc://${mgmt_addr};
    grpc_read_timeout 1d;
    grpc_send_timeout 1d;
    grpc_socket_keepalive on;
}
EOF
  return 0
}

############################################
# Post-Setup Instructions per Proxy Type
############################################

print_caddy_instructions() {
  echo "You can access the NetBird dashboard at $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  echo "Follow the onboarding steps to set up your NetBird instance."
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
  echo "IMPORTANT: Unlike Caddy, Nginx requires manual TLS certificate setup."
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
    echo "Container ports (bound to ${bind_addr}):"
    echo "  Dashboard:  ${DASHBOARD_HOST_PORT}"
    echo "  Signal:     ${SIGNAL_HOST_PORT} (HTTP), ${SIGNAL_GRPC_PORT} (gRPC)"
    echo "  Management: ${MANAGEMENT_HOST_PORT}"
    echo "  Relay:      ${RELAY_HOST_PORT}"
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
    echo "Container ports (bound to ${bind_addr}):"
    echo "  Dashboard:  ${DASHBOARD_HOST_PORT}"
    echo "  Signal:     ${SIGNAL_HOST_PORT} (HTTP), ${SIGNAL_GRPC_PORT} (gRPC)"
    echo "  Management: ${MANAGEMENT_HOST_PORT}"
    echo "  Relay:      ${RELAY_HOST_PORT}"
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
    echo "Container ports (bound to ${bind_addr}):"
    echo "  Dashboard:  ${DASHBOARD_HOST_PORT}"
    echo "  Signal:     ${SIGNAL_HOST_PORT} (HTTP), ${SIGNAL_GRPC_PORT} (gRPC)"
    echo "  Management: ${MANAGEMENT_HOST_PORT}"
    echo "  Relay:      ${RELAY_HOST_PORT}"
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
  echo "Container ports (bound to ${bind_addr}):"
  echo "  Dashboard:  ${DASHBOARD_HOST_PORT}"
  echo "  Signal:     ${SIGNAL_HOST_PORT} (HTTP), ${SIGNAL_GRPC_PORT} (gRPC)"
  echo "  Management: ${MANAGEMENT_HOST_PORT}"
  echo "  Relay:      ${RELAY_HOST_PORT}"
  echo ""
  echo "Configure your reverse proxy with these routes:"
  echo ""
  echo "  /relay*                          -> ${upstream_host}:${RELAY_HOST_PORT}"
  echo "    (HTTP with WebSocket upgrade)"
  echo ""
  echo "  /ws-proxy/signal*                -> ${upstream_host}:${SIGNAL_HOST_PORT}"
  echo "    (HTTP with WebSocket upgrade)"
  echo ""
  echo "  /signalexchange.SignalExchange/* -> ${upstream_host}:${SIGNAL_GRPC_PORT}"
  echo "    (gRPC/h2c - plaintext HTTP/2)"
  echo ""
  echo "  /api/*                           -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
  echo "    (HTTP)"
  echo ""
  echo "  /ws-proxy/management*            -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
  echo "    (HTTP with WebSocket upgrade)"
  echo ""
  echo "  /management.ManagementService/*  -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
  echo "    (gRPC/h2c - plaintext HTTP/2)"
  echo ""
  echo "  /oauth2/*                        -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
  echo "    (HTTP - embedded IdP)"
  echo ""
  echo "  /*                               -> ${upstream_host}:${DASHBOARD_HOST_PORT}"
  echo "    (HTTP - catch-all for dashboard)"
  echo ""
  echo "IMPORTANT: gRPC routes require HTTP/2 (h2c) upstream support."
  echo "Long-running connections need extended timeouts (recommend 1 day)."
  return 0
}

print_post_setup_instructions() {
  case "$REVERSE_PROXY_TYPE" in
    0)
      print_caddy_instructions
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

init_environment
