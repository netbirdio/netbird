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

read_proxy_domain() {
  local suggested_proxy="proxy.${NETBIRD_DOMAIN}"

  echo "" > /dev/stderr
  echo "NOTE: The proxy domain must be different from the management domain ($NETBIRD_DOMAIN)" > /dev/stderr
  echo "to avoid TLS certificate conflicts." > /dev/stderr
  echo "" > /dev/stderr
  echo "You also need to add a wildcard DNS record for the proxy domain," > /dev/stderr
  echo "e.g. *.${suggested_proxy} pointing to the same server IP as $NETBIRD_DOMAIN." > /dev/stderr
  echo "" > /dev/stderr
  echo -n "Enter the domain for the NetBird Proxy (e.g. ${suggested_proxy}): " > /dev/stderr
  read -r READ_PROXY_DOMAIN < /dev/tty

  if [[ -z "$READ_PROXY_DOMAIN" ]]; then
    echo "The proxy domain cannot be empty." > /dev/stderr
    read_proxy_domain
    return
  fi

  if [[ "$READ_PROXY_DOMAIN" == "$NETBIRD_DOMAIN" ]]; then
    echo "The proxy domain cannot be the same as the management domain ($NETBIRD_DOMAIN)." > /dev/stderr
    read_proxy_domain
    return
  fi

  if [[ "$READ_PROXY_DOMAIN" == *".${NETBIRD_DOMAIN}" ]]; then
    echo "The proxy domain cannot be a subdomain of the management domain ($NETBIRD_DOMAIN)." > /dev/stderr
    read_proxy_domain
    return
  fi

  echo "$READ_PROXY_DOMAIN"
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

wait_management_proxy() {
  local proxy_container="${1:-traefik}"
  set +e
  echo -n "Waiting for NetBird server to become ready"
  counter=1
  while true; do
    # Check the embedded IdP endpoint through the reverse proxy
    if curl -sk -f -o /dev/null "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/oauth2/.well-known/openid-configuration" 2>/dev/null; then
      break
    fi
    if [[ $counter -eq 60 ]]; then
      echo ""
      echo "Taking too long. Checking logs..."
      $DOCKER_COMPOSE_COMMAND logs --tail=20 "$proxy_container"
      $DOCKER_COMPOSE_COMMAND logs --tail=20 netbird-server
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
    # Check the embedded IdP endpoint directly (no reverse proxy)
    if curl -sk -f -o /dev/null "http://${upstream_host}:${MANAGEMENT_HOST_PORT}/oauth2/.well-known/openid-configuration" 2>/dev/null; then
      break
    fi
    if [[ $counter -eq 60 ]]; then
      echo ""
      echo "Taking too long. Checking logs..."
      $DOCKER_COMPOSE_COMMAND logs --tail=20 netbird-server
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
  NETBIRD_RELAY_AUTH_SECRET=$(openssl rand -base64 32 | sed "$SED_STRIP_PADDING")
  # Note: DataStoreEncryptionKey must keep base64 padding (=) for Go's base64.StdEncoding
  DATASTORE_ENCRYPTION_KEY=$(openssl rand -base64 32)
  NETBIRD_STUN_PORT=3478

  # Docker images
  DASHBOARD_IMAGE="netbirdio/dashboard:latest"
  # Combined server replaces separate signal, relay, and management containers
  NETBIRD_SERVER_IMAGE="netbirdio/netbird-server:latest"
  NETBIRD_PROXY_IMAGE="netbirdio/reverse-proxy:latest"

  # Reverse proxy configuration
  REVERSE_PROXY_TYPE="0"
  TRAEFIK_EXTERNAL_NETWORK=""
  TRAEFIK_ENTRYPOINT="websecure"
  TRAEFIK_CERTRESOLVER=""
  TRAEFIK_ACME_EMAIL=""
  DASHBOARD_HOST_PORT="8080"
  MANAGEMENT_HOST_PORT="8081"  # Combined server port (management + signal + relay)
  BIND_LOCALHOST_ONLY="true"
  EXTERNAL_PROXY_NETWORK=""

  # NetBird Proxy configuration
  ENABLE_PROXY="false"
  PROXY_DOMAIN=""
  PROXY_TOKEN=""
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
    NETBIRD_HTTP_PROTOCOL="https"
    NETBIRD_RELAY_PROTO="rels"
  fi
  return 0
}

configure_reverse_proxy() {
  # Prompt for reverse proxy type
  REVERSE_PROXY_TYPE=$(read_reverse_proxy_type)

  # Handle built-in Traefik prompts (option 0)
  if [[ "$REVERSE_PROXY_TYPE" == "0" ]]; then
    TRAEFIK_ACME_EMAIL=$(read_traefik_acme_email)
    ENABLE_PROXY=$(read_enable_proxy)
    if [[ "$ENABLE_PROXY" == "true" ]]; then
      PROXY_DOMAIN=$(read_proxy_domain)
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
  return 0
}

check_existing_installation() {
  if [[ -f config.yaml ]]; then
    echo "Generated files already exist, if you want to reinitialize the environment, please remove them first."
    echo "You can use the following commands:"
    echo "  $DOCKER_COMPOSE_COMMAND down --volumes # to remove all containers and volumes"
    echo "  rm -f docker-compose.yml dashboard.env config.yaml proxy.env nginx-netbird.conf caddyfile-netbird.txt npm-advanced-config.txt"
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
      render_docker_compose_traefik_builtin > docker-compose.yml
      if [[ "$ENABLE_PROXY" == "true" ]]; then
        # Create placeholder proxy.env so docker-compose can validate
        # This will be overwritten with the actual token after netbird-server starts
        echo "# Placeholder - will be updated with token after netbird-server starts" > proxy.env
        echo "NB_PROXY_TOKEN=placeholder" >> proxy.env
      fi
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
  render_combined_yaml > config.yaml
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
      echo "Starting core services..."
      $DOCKER_COMPOSE_COMMAND up -d traefik dashboard netbird-server

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

      # Generate proxy.env with the token
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

render_docker_compose_traefik_builtin() {
  # Generate proxy service section if enabled
  local proxy_service=""
  local proxy_volumes=""
  if [[ "$ENABLE_PROXY" == "true" ]]; then
    proxy_service="
  # NetBird Proxy - exposes internal resources to the internet
  proxy:
    image: $NETBIRD_PROXY_IMAGE
    container_name: netbird-proxy
    # Hairpin NAT fix: route domain back to traefik's static IP within Docker
    extra_hosts:
      - \"$NETBIRD_DOMAIN:172.30.0.10\"
    restart: unless-stopped
    networks: [netbird]
    depends_on:
      - netbird-server
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
    logging:
      driver: \"json-file\"
      options:
        max-size: \"500m\"
        max-file: \"2\"
"
    proxy_volumes="
  netbird_proxy_certs:"
  fi

  cat <<EOF
services:
  # Traefik reverse proxy (automatic TLS via Let's Encrypt)
  traefik:
    image: traefik:v3.6
    container_name: netbird-traefik
    restart: unless-stopped
    networks:
      netbird:
        ipv4_address: 172.30.0.10
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
      - traefik.http.routers.netbird-grpc.rule=Host(\`$NETBIRD_DOMAIN\`) && (PathPrefix(\`/signalexchange.SignalExchange/\`) || PathPrefix(\`/management.ManagementService/\`))
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
${proxy_service}
volumes:
  netbird_data:
  netbird_traefik_letsencrypt:${proxy_volumes}

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

  store:
    engine: "sqlite"
    encryptionKey: "$DATASTORE_ENCRYPTION_KEY"
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

render_proxy_env() {
  cat <<EOF
# NetBird Proxy Configuration
NB_PROXY_DEBUG_LOGS=false
# Use internal Docker network to connect to management (avoids hairpin NAT issues)
NB_PROXY_MANAGEMENT_ADDRESS=http://netbird-server:80
# Allow insecure gRPC connection to management (required for internal Docker network)
NB_PROXY_ALLOW_INSECURE=true
# Public URL where this proxy is reachable (used for cluster registration)
NB_PROXY_DOMAIN=$PROXY_DOMAIN
NB_PROXY_ADDRESS=:8443
NB_PROXY_TOKEN=$PROXY_TOKEN
NB_PROXY_CERTIFICATE_DIRECTORY=/certs
NB_PROXY_ACME_CERTIFICATES=true
NB_PROXY_ACME_CHALLENGE_TYPE=tls-alpn-01
NB_PROXY_OIDC_CLIENT_ID=netbird-proxy
NB_PROXY_OIDC_ENDPOINT=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/oauth2
NB_PROXY_OIDC_SCOPES=openid,profile,email
NB_PROXY_FORWARDED_PROTO=https
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

render_nginx_conf() {
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

render_external_caddyfile() {
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

render_npm_advanced_config() {
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

############################################
# Post-Setup Instructions per Proxy Type
############################################

print_builtin_traefik_instructions() {
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  NETBIRD SETUP COMPLETE"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "You can access the NetBird dashboard at $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  echo "Follow the onboarding steps to set up your NetBird instance."
  echo ""
  echo "Traefik is handling TLS certificates automatically via Let's Encrypt."
  echo "If you see certificate warnings, wait a moment for certificate issuance to complete."
  echo ""
  echo "Open ports:"
  echo "  - 443/tcp  (HTTPS - all NetBird services)"
  echo "  - 80/tcp   (HTTP - redirects to HTTPS)"
  echo "  - $NETBIRD_STUN_PORT/udp  (STUN - required for NAT traversal)"
  if [[ "$ENABLE_PROXY" == "true" ]]; then
    echo ""
    echo "NetBird Proxy:"
    echo "  The proxy service is enabled and running."
    echo "  Any domain NOT matching $NETBIRD_DOMAIN will be passed through to the proxy."
    echo "  The proxy handles its own TLS certificates via ACME TLS-ALPN-01 challenge."
    echo "  Point your proxy domains (CNAMEs) to this server's IP address."
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
    echo "Container ports (bound to ${bind_addr}):"
    echo "  Dashboard:     ${DASHBOARD_HOST_PORT}"
    echo "  NetBird Server: ${MANAGEMENT_HOST_PORT} (all services)"
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
    echo "  Dashboard:     ${DASHBOARD_HOST_PORT}"
    echo "  NetBird Server: ${MANAGEMENT_HOST_PORT} (all services)"
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
    echo "  Dashboard:     ${DASHBOARD_HOST_PORT}"
    echo "  NetBird Server: ${MANAGEMENT_HOST_PORT} (all services)"
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
  echo "  Dashboard:     ${DASHBOARD_HOST_PORT}"
  echo "  NetBird Server: ${MANAGEMENT_HOST_PORT} (all services: management, signal, relay)"
  echo ""
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

init_environment
