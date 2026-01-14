#!/bin/bash

set -e

# NetBird Getting Started with Embedded IdP (Dex)
# This script sets up NetBird with the embedded Dex identity provider
# No separate Dex container or reverse proxy needed - IdP is built into management server

# Sed pattern to strip base64 padding characters
SED_STRIP_PADDING='s/=//g'

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

get_turn_external_ip() {
  TURN_EXTERNAL_IP_CONFIG="#external-ip="
  IP=$(curl -s -4 https://jsonip.com | jq -r '.ip')
  if [[ "x-$IP" != "x-" ]]; then
    TURN_EXTERNAL_IP_CONFIG="external-ip=$IP"
  fi
  echo "$TURN_EXTERNAL_IP_CONFIG"
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

read_npm_network() {
  echo "" > /dev/stderr
  echo "Is Nginx Proxy Manager running in Docker?" > /dev/stderr
  echo "If yes, enter the Docker network NPM is on (NetBird will join it)." > /dev/stderr
  echo -n "NPM Docker network (leave empty if NPM is not in Docker): " > /dev/stderr
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
  local BIND_ADDR=$(get_bind_address)
  echo -n "Waiting for Management server to become ready"
  counter=1
  while true; do
    # Check the embedded IdP endpoint directly (no reverse proxy)
    if curl -sk -f -o /dev/null "http://${BIND_ADDR}:${MANAGEMENT_HOST_PORT}/oauth2/.well-known/openid-configuration" 2>/dev/null; then
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

init_environment() {
  CADDY_SECURE_DOMAIN=""
  NETBIRD_PORT=80
  NETBIRD_HTTP_PROTOCOL="http"
  NETBIRD_RELAY_PROTO="rel"
  TURN_USER="self"
  TURN_PASSWORD=$(openssl rand -base64 32 | sed "$SED_STRIP_PADDING")
  NETBIRD_RELAY_AUTH_SECRET=$(openssl rand -base64 32 | sed "$SED_STRIP_PADDING")
  # Note: DataStoreEncryptionKey must keep base64 padding (=) for Go's base64.StdEncoding
  DATASTORE_ENCRYPTION_KEY=$(openssl rand -base64 32)
  TURN_MIN_PORT=49152
  TURN_MAX_PORT=65535
  TURN_EXTERNAL_IP_CONFIG=$(get_turn_external_ip)

  # Reverse proxy configuration
  REVERSE_PROXY_TYPE="0"
  TRAEFIK_EXTERNAL_NETWORK=""
  DASHBOARD_HOST_PORT="8080"
  MANAGEMENT_HOST_PORT="8081"
  SIGNAL_HOST_PORT="8083"
  SIGNAL_GRPC_PORT="10000"
  RELAY_HOST_PORT="8084"
  BIND_LOCALHOST_ONLY="true"
  NPM_NETWORK=""

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

  # Prompt for reverse proxy type
  REVERSE_PROXY_TYPE=$(read_reverse_proxy_type)

  # Handle Traefik-specific prompts
  if [[ "$REVERSE_PROXY_TYPE" == "1" ]]; then
    TRAEFIK_EXTERNAL_NETWORK=$(read_traefik_network)
  fi

  # Handle port binding for external proxy options (2-5)
  if [[ "$REVERSE_PROXY_TYPE" -ge 2 ]]; then
    BIND_LOCALHOST_ONLY=$(read_port_binding_preference)
  fi

  # Handle NPM-specific prompts (option 3)
  if [[ "$REVERSE_PROXY_TYPE" == "3" ]]; then
    NPM_NETWORK=$(read_npm_network)
  fi

  check_jq

  DOCKER_COMPOSE_COMMAND=$(check_docker_compose)

  if [[ -f management.json ]]; then
    echo "Generated files already exist, if you want to reinitialize the environment, please remove them first."
    echo "You can use the following commands:"
    echo "  $DOCKER_COMPOSE_COMMAND down --volumes # to remove all containers and volumes"
    echo "  rm -f docker-compose.yml Caddyfile dashboard.env turnserver.conf management.json relay.env nginx-netbird.conf caddyfile-netbird.txt npm-advanced-config.txt"
    echo "Be aware that this will remove all data from the database, and you will have to reconfigure the dashboard."
    exit 1
  fi

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
  esac

  # Common files for all configurations
  render_dashboard_env > dashboard.env
  render_management_json > management.json
  render_turn_server_conf > turnserver.conf
  render_relay_env > relay.env

  # For built-in Caddy and Traefik, start containers immediately
  # For NPM, start containers first (NPM needs services running to create proxy)
  # For other external proxies, show instructions first and wait for user confirmation
  if [[ "$REVERSE_PROXY_TYPE" == "0" ]]; then
    # Built-in Caddy - handles everything automatically
    echo -e "\nStarting NetBird services\n"
    $DOCKER_COMPOSE_COMMAND up -d

    sleep 3
    wait_management

    echo -e "\nDone!\n"
    print_post_setup_instructions
  elif [[ "$REVERSE_PROXY_TYPE" == "1" ]]; then
    # Traefik - start containers first, then show instructions
    # Traefik discovers services via Docker labels, so containers must be running
    echo -e "\nStarting NetBird services\n"
    $DOCKER_COMPOSE_COMMAND up -d

    sleep 3

    echo -e "\nDone!\n"
    print_post_setup_instructions
    echo ""
    echo "NetBird containers are running. Once Traefik is connected, access the dashboard at:"
    echo "  $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  elif [[ "$REVERSE_PROXY_TYPE" == "3" ]]; then
    # NPM - start containers first, then show instructions
    # NPM requires backend services to be running before creating proxy hosts
    echo -e "\nStarting NetBird services\n"
    $DOCKER_COMPOSE_COMMAND up -d

    sleep 3
    wait_management_direct

    echo -e "\nDone!\n"
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

    echo -e "\nStarting NetBird services\n"
    $DOCKER_COMPOSE_COMMAND up -d

    sleep 3
    wait_management_direct

    echo -e "\nDone!\n"
    echo "NetBird is now running. Access the dashboard at:"
    echo "  $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  fi

  return 0
}

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

render_turn_server_conf() {
  cat <<EOF
listening-port=3478
$TURN_EXTERNAL_IP_CONFIG
tls-listening-port=5349
min-port=$TURN_MIN_PORT
max-port=$TURN_MAX_PORT
fingerprint
lt-cred-mech
user=$TURN_USER:$TURN_PASSWORD
realm=wiretrustee.com
cert=/etc/coturn/certs/cert.pem
pkey=/etc/coturn/private/privkey.pem
log-file=stdout
no-software-attribute
pidfile="/var/tmp/turnserver.pid"
no-cli
EOF
  return 0
}

render_management_json() {
  cat <<EOF
{
    "Stuns": [
        {
            "Proto": "udp",
            "URI": "stun:$NETBIRD_DOMAIN:3478"
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
EOF
  return 0
}

render_docker_compose() {
  cat <<EOF
services:
  # Caddy reverse proxy
  caddy:
    image: caddy
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
    image: netbirdio/dashboard:latest
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
    image: netbirdio/signal:latest
    container_name: netbird-signal
    restart: unless-stopped
    networks: [netbird]
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Relay
  relay:
    image: netbirdio/relay:latest
    container_name: netbird-relay
    restart: unless-stopped
    networks: [netbird]
    env_file:
      - ./relay.env
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Management (includes embedded IdP)
  management:
    image: netbirdio/management:latest
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

  # Coturn, AKA TURN server
  coturn:
    image: coturn/coturn
    container_name: netbird-coturn
    restart: unless-stopped
    volumes:
      - ./turnserver.conf:/etc/turnserver.conf:ro
    network_mode: host
    command:
      - -c /etc/turnserver.conf
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
  local NETWORK_NAME="${TRAEFIK_EXTERNAL_NETWORK:-netbird}"
  local NETWORK_CONFIG=""
  if [[ -n "$TRAEFIK_EXTERNAL_NETWORK" ]]; then
    NETWORK_CONFIG="    external: true"
  fi

  cat <<EOF
services:
  # UI dashboard
  dashboard:
    image: netbirdio/dashboard:latest
    container_name: netbird-dashboard
    restart: unless-stopped
    networks: [$NETWORK_NAME]
    env_file:
      - ./dashboard.env
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-dashboard.rule=Host(\`$NETBIRD_DOMAIN\`)
      - traefik.http.routers.netbird-dashboard.priority=1
      - traefik.http.services.netbird-dashboard.loadbalancer.server.port=80
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Signal
  signal:
    image: netbirdio/signal:latest
    container_name: netbird-signal
    restart: unless-stopped
    networks: [$NETWORK_NAME]
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-signal-ws.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/ws-proxy/signal\`)
      - traefik.http.routers.netbird-signal-ws.service=netbird-signal-ws
      - traefik.http.services.netbird-signal-ws.loadbalancer.server.port=80
      - traefik.http.routers.netbird-signal-grpc.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/signalexchange.SignalExchange/\`)
      - traefik.http.routers.netbird-signal-grpc.service=netbird-signal-grpc
      - traefik.http.services.netbird-signal-grpc.loadbalancer.server.port=10000
      - traefik.http.services.netbird-signal-grpc.loadbalancer.server.scheme=h2c
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Relay
  relay:
    image: netbirdio/relay:latest
    container_name: netbird-relay
    restart: unless-stopped
    networks: [$NETWORK_NAME]
    env_file:
      - ./relay.env
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-relay.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/relay\`)
      - traefik.http.services.netbird-relay.loadbalancer.server.port=80
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Management (includes embedded IdP)
  management:
    image: netbirdio/management:latest
    container_name: netbird-management
    restart: unless-stopped
    networks: [$NETWORK_NAME]
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
      - traefik.http.routers.netbird-api.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/api\`)
      - traefik.http.routers.netbird-api.service=netbird-api
      - traefik.http.services.netbird-api.loadbalancer.server.port=80
      - traefik.http.routers.netbird-mgmt-ws.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/ws-proxy/management\`)
      - traefik.http.routers.netbird-mgmt-ws.service=netbird-mgmt-ws
      - traefik.http.services.netbird-mgmt-ws.loadbalancer.server.port=80
      - traefik.http.routers.netbird-mgmt-grpc.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/management.ManagementService/\`)
      - traefik.http.routers.netbird-mgmt-grpc.service=netbird-mgmt-grpc
      - traefik.http.services.netbird-mgmt-grpc.loadbalancer.server.port=80
      - traefik.http.services.netbird-mgmt-grpc.loadbalancer.server.scheme=h2c
      - traefik.http.routers.netbird-oauth2.rule=Host(\`$NETBIRD_DOMAIN\`) && PathPrefix(\`/oauth2\`)
      - traefik.http.routers.netbird-oauth2.service=netbird-oauth2
      - traefik.http.services.netbird-oauth2.loadbalancer.server.port=80
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Coturn, AKA TURN server
  coturn:
    image: coturn/coturn
    container_name: netbird-coturn
    restart: unless-stopped
    volumes:
      - ./turnserver.conf:/etc/turnserver.conf:ro
    network_mode: host
    command:
      - -c /etc/turnserver.conf
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

volumes:
  netbird_management:

networks:
  $NETWORK_NAME:
$NETWORK_CONFIG
EOF
  return 0
}

render_docker_compose_exposed_ports() {
  local BIND_ADDR=$(get_bind_address)
  local NETWORKS="[netbird]"
  local NETWORKS_CONFIG="networks:
  netbird:"

  # If NPM network is specified, add it as external and include in service networks
  if [[ -n "$NPM_NETWORK" ]]; then
    NETWORKS="[netbird, $NPM_NETWORK]"
    NETWORKS_CONFIG="networks:
  netbird:
  $NPM_NETWORK:
    external: true"
  fi

  cat <<EOF
services:
  # UI dashboard
  dashboard:
    image: netbirdio/dashboard:latest
    container_name: netbird-dashboard
    restart: unless-stopped
    networks: ${NETWORKS}
    ports:
      - '${BIND_ADDR}:${DASHBOARD_HOST_PORT}:80'
    env_file:
      - ./dashboard.env
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Signal
  signal:
    image: netbirdio/signal:latest
    container_name: netbird-signal
    restart: unless-stopped
    networks: ${NETWORKS}
    ports:
      - '${BIND_ADDR}:${SIGNAL_HOST_PORT}:80'
      - '${BIND_ADDR}:${SIGNAL_GRPC_PORT}:10000'
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Relay
  relay:
    image: netbirdio/relay:latest
    container_name: netbird-relay
    restart: unless-stopped
    networks: ${NETWORKS}
    ports:
      - '${BIND_ADDR}:${RELAY_HOST_PORT}:80'
    env_file:
      - ./relay.env
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Management (includes embedded IdP)
  management:
    image: netbirdio/management:latest
    container_name: netbird-management
    restart: unless-stopped
    networks: ${NETWORKS}
    ports:
      - '${BIND_ADDR}:${MANAGEMENT_HOST_PORT}:80'
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

  # Coturn, AKA TURN server
  coturn:
    image: coturn/coturn
    container_name: netbird-coturn
    restart: unless-stopped
    volumes:
      - ./turnserver.conf:/etc/turnserver.conf:ro
    network_mode: host
    command:
      - -c /etc/turnserver.conf
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

volumes:
  netbird_management:

${NETWORKS_CONFIG}
EOF
  return 0
}

render_nginx_conf() {
  local BIND_ADDR=$(get_bind_address)

  cat <<EOF
# NetBird Nginx Configuration
# Generated by getting-started.sh
#
# 1. Update SSL certificate paths below
# 2. Copy to your nginx config directory:
#    Debian/Ubuntu: /etc/nginx/sites-available/netbird (then symlink to sites-enabled)
#    RHEL/CentOS:   /etc/nginx/conf.d/netbird.conf
# 3. Test and reload: nginx -t && systemctl reload nginx

upstream netbird_dashboard {
    server ${BIND_ADDR}:${DASHBOARD_HOST_PORT};
    keepalive 10;
}
upstream netbird_signal {
    server ${BIND_ADDR}:${SIGNAL_GRPC_PORT};
}
upstream netbird_signal_ws {
    server ${BIND_ADDR}:${SIGNAL_HOST_PORT};
}
upstream netbird_management {
    server ${BIND_ADDR}:${MANAGEMENT_HOST_PORT};
}
upstream netbird_relay {
    server ${BIND_ADDR}:${RELAY_HOST_PORT};
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

    # TODO: Update with your SSL certificate paths
    ssl_certificate /path/to/your/fullchain.pem;
    ssl_certificate_key /path/to/your/privkey.pem;

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
    }

    # Signal WebSocket
    location /ws-proxy/signal {
        proxy_pass http://netbird_signal_ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }

    # Signal gRPC
    location /signalexchange.SignalExchange/ {
        grpc_pass grpc://netbird_signal;
        grpc_read_timeout 1d;
        grpc_send_timeout 1d;
        grpc_socket_keepalive on;
    }

    # Management API
    location /api {
        proxy_pass http://netbird_management;
    }

    # Management WebSocket
    location /ws-proxy/management {
        proxy_pass http://netbird_management;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
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
  local BIND_ADDR=$(get_bind_address)

  cat <<EOF
# NetBird Caddyfile Snippet
# Generated by getting-started.sh
#
# Add this block to your existing Caddyfile and reload Caddy

$NETBIRD_DOMAIN {
    # Relay (WebSocket)
    reverse_proxy /relay* ${BIND_ADDR}:${RELAY_HOST_PORT}

    # Signal WebSocket
    reverse_proxy /ws-proxy/signal* ${BIND_ADDR}:${SIGNAL_HOST_PORT}

    # Signal gRPC (h2c for plaintext HTTP/2)
    reverse_proxy /signalexchange.SignalExchange/* h2c://${BIND_ADDR}:${SIGNAL_GRPC_PORT}

    # Management API
    reverse_proxy /api/* ${BIND_ADDR}:${MANAGEMENT_HOST_PORT}

    # Management WebSocket
    reverse_proxy /ws-proxy/management* ${BIND_ADDR}:${MANAGEMENT_HOST_PORT}

    # Management gRPC
    reverse_proxy /management.ManagementService/* h2c://${BIND_ADDR}:${MANAGEMENT_HOST_PORT}

    # Embedded IdP OAuth2
    reverse_proxy /oauth2/* ${BIND_ADDR}:${MANAGEMENT_HOST_PORT}x

    # Dashboard (catch-all)
    reverse_proxy /* ${BIND_ADDR}:${DASHBOARD_HOST_PORT}
}
EOF
  return 0
}

render_npm_advanced_config() {
  local BIND_ADDR=$(get_bind_address)
  local RELAY_ADDR="${BIND_ADDR}:${RELAY_HOST_PORT}"
  local SIGNAL_ADDR="${BIND_ADDR}:${SIGNAL_HOST_PORT}"
  local SIGNAL_GRPC_ADDR="${BIND_ADDR}:${SIGNAL_GRPC_PORT}"
  local MGMT_ADDR="${BIND_ADDR}:${MANAGEMENT_HOST_PORT}"

  # If NPM network is specified, use container names instead of host addresses
  if [[ -n "$NPM_NETWORK" ]]; then
    RELAY_ADDR="netbird-relay:80"
    SIGNAL_ADDR="netbird-signal:80"
    SIGNAL_GRPC_ADDR="netbird-signal:10000"
    MGMT_ADDR="netbird-management:80"
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
    proxy_pass http://${RELAY_ADDR};
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
    proxy_pass http://${SIGNAL_ADDR};
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
    proxy_pass http://${MGMT_ADDR};
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
    proxy_pass http://${MGMT_ADDR};
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
}

# OAuth2/IdP routes
location /oauth2/ {
    proxy_pass http://${MGMT_ADDR};
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
}

# gRPC for Signal service
location /signalexchange.SignalExchange/ {
    grpc_pass grpc://${SIGNAL_GRPC_ADDR};
    grpc_read_timeout 1d;
    grpc_send_timeout 1d;
    grpc_socket_keepalive on;
}

# gRPC for Management service
location /management.ManagementService/ {
    grpc_pass grpc://${MGMT_ADDR};
    grpc_read_timeout 1d;
    grpc_send_timeout 1d;
    grpc_socket_keepalive on;
}
EOF
  return 0
}

print_post_setup_instructions() {
  local BIND_ADDR=$(get_bind_address)

  case "$REVERSE_PROXY_TYPE" in
    0)
      # Built-in Caddy
      echo "You can access the NetBird dashboard at $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
      echo "Follow the onboarding steps to set up your NetBird instance."
      ;;
    1)
      # Traefik
      echo ""
      echo "=========================================="
      echo "  TRAEFIK SETUP"
      echo "=========================================="
      echo ""
      echo "NetBird containers are configured with Traefik labels."
      echo ""
      if [[ -n "$TRAEFIK_EXTERNAL_NETWORK" ]]; then
        echo "Using external network: $TRAEFIK_EXTERNAL_NETWORK"
        echo "Ensure your Traefik container is connected to this network."
      else
        echo "A new 'netbird' network has been created."
        echo "Connect your Traefik container to it:"
        echo "  docker network connect netbird <traefik-container-name>"
      fi
      echo ""
      echo "Traefik requirements:"
      echo "  - providers.docker.exposedByDefault=false"
      echo "  - HTTP to HTTPS redirect (recommended)"
      ;;
    2)
      # Nginx
      echo ""
      echo "=========================================="
      echo "  NGINX SETUP"
      echo "=========================================="
      echo ""
      echo "Generated: nginx-netbird.conf"
      echo ""
      echo "Next steps:"
      echo "  1. Edit nginx-netbird.conf and update SSL certificate paths"
      echo "  2. Copy to your nginx config directory:"
      echo "     # Debian/Ubuntu:"
      echo "     sudo cp nginx-netbird.conf /etc/nginx/sites-available/netbird"
      echo "     sudo ln -s /etc/nginx/sites-available/netbird /etc/nginx/sites-enabled/"
      echo "     # RHEL/CentOS/Fedora:"
      echo "     sudo cp nginx-netbird.conf /etc/nginx/conf.d/netbird.conf"
      echo "  3. Test and reload:"
      echo "     sudo nginx -t && sudo systemctl reload nginx"
      echo ""
      echo "Container ports (bound to ${BIND_ADDR}):"
      echo "  Dashboard:  ${DASHBOARD_HOST_PORT}"
      echo "  Signal:     ${SIGNAL_HOST_PORT} (HTTP), ${SIGNAL_GRPC_PORT} (gRPC)"
      echo "  Management: ${MANAGEMENT_HOST_PORT}"
      echo "  Relay:      ${RELAY_HOST_PORT}"
      ;;
    3)
      # Nginx Proxy Manager
      echo ""
      echo "=========================================="
      echo "  NGINX PROXY MANAGER SETUP"
      echo "=========================================="
      echo ""
      echo "Generated: npm-advanced-config.txt"
      echo ""
      if [[ -n "$NPM_NETWORK" ]]; then
        echo "NetBird containers have joined the '$NPM_NETWORK' Docker network."
        echo ""
        echo "In NPM, create a Proxy Host:"
        echo "  Domain: $NETBIRD_DOMAIN"
        echo "  Forward Hostname/IP: netbird-dashboard"
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
        echo "Container ports (bound to ${BIND_ADDR}):"
        echo "  Dashboard:  ${DASHBOARD_HOST_PORT}"
        echo "  Signal:     ${SIGNAL_HOST_PORT} (HTTP), ${SIGNAL_GRPC_PORT} (gRPC)"
        echo "  Management: ${MANAGEMENT_HOST_PORT}"
        echo "  Relay:      ${RELAY_HOST_PORT}"
        echo ""
        echo "In NPM, create a Proxy Host:"
        echo "  Domain: $NETBIRD_DOMAIN"
        echo "  Forward Hostname/IP: ${BIND_ADDR}"
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
      ;;
    4)
      # External Caddy
      echo ""
      echo "=========================================="
      echo "  EXTERNAL CADDY SETUP"
      echo "=========================================="
      echo ""
      echo "Generated: caddyfile-netbird.txt"
      echo ""
      echo "Next steps:"
      echo "  1. Add the contents of caddyfile-netbird.txt to your Caddyfile"
      echo "  2. Reload Caddy: caddy reload --config /path/to/Caddyfile"
      echo ""
      echo "Container ports (bound to ${BIND_ADDR}):"
      echo "  Dashboard:  ${DASHBOARD_HOST_PORT}"
      echo "  Signal:     ${SIGNAL_HOST_PORT} (HTTP), ${SIGNAL_GRPC_PORT} (gRPC)"
      echo "  Management: ${MANAGEMENT_HOST_PORT}"
      echo "  Relay:      ${RELAY_HOST_PORT}"
      ;;
    5)
      # Other/Manual
      echo ""
      echo "=========================================="
      echo "  MANUAL REVERSE PROXY SETUP"
      echo "=========================================="
      echo ""
      echo "Container ports (bound to ${BIND_ADDR}):"
      echo "  Dashboard:  ${DASHBOARD_HOST_PORT}"
      echo "  Signal:     ${SIGNAL_HOST_PORT} (HTTP), ${SIGNAL_GRPC_PORT} (gRPC)"
      echo "  Management: ${MANAGEMENT_HOST_PORT}"
      echo "  Relay:      ${RELAY_HOST_PORT}"
      echo ""
      echo "Configure your reverse proxy with these routes:"
      echo ""
      echo "  /relay*                          -> ${BIND_ADDR}:${RELAY_HOST_PORT}"
      echo "    (HTTP with WebSocket upgrade)"
      echo ""
      echo "  /ws-proxy/signal*                -> ${BIND_ADDR}:${SIGNAL_HOST_PORT}"
      echo "    (HTTP with WebSocket upgrade)"
      echo ""
      echo "  /signalexchange.SignalExchange/* -> ${BIND_ADDR}:${SIGNAL_GRPC_PORT}"
      echo "    (gRPC/h2c - plaintext HTTP/2)"
      echo ""
      echo "  /api/*                           -> ${BIND_ADDR}:${MANAGEMENT_HOST_PORT}"
      echo "    (HTTP)"
      echo ""
      echo "  /ws-proxy/management*            -> ${BIND_ADDR}:${MANAGEMENT_HOST_PORT}"
      echo "    (HTTP with WebSocket upgrade)"
      echo ""
      echo "  /management.ManagementService/*  -> ${BIND_ADDR}:${MANAGEMENT_HOST_PORT}"
      echo "    (gRPC/h2c - plaintext HTTP/2)"
      echo ""
      echo "  /oauth2/*                        -> ${BIND_ADDR}:${MANAGEMENT_HOST_PORT}"
      echo "    (HTTP - embedded IdP)"
      echo ""
      echo "  /*                               -> ${BIND_ADDR}:${DASHBOARD_HOST_PORT}"
      echo "    (HTTP - catch-all for dashboard)"
      echo ""
      echo "IMPORTANT: gRPC routes require HTTP/2 (h2c) upstream support."
      echo "Long-running connections need extended timeouts (recommend 1 day)."
      ;;
  esac

  return 0
}

init_environment
