#!/bin/bash

set -e

# NetBird Getting Started with Dex IDP
# This script sets up NetBird with Dex as the identity provider

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

wait_dex() {
  set +e
  echo -n "Waiting for Dex to become ready (via $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN)"
  counter=1
  while true; do
    # Check Dex through Caddy proxy (also validates TLS is working)
    if curl -sk -f -o /dev/null "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/dex/.well-known/openid-configuration" 2>/dev/null; then
      break
    fi
    if [[ $counter -eq 60 ]]; then
      echo ""
      echo "Taking too long. Checking logs..."
      $DOCKER_COMPOSE_COMMAND logs --tail=20 caddy
      $DOCKER_COMPOSE_COMMAND logs --tail=20 dex
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
  TURN_MIN_PORT=49152
  TURN_MAX_PORT=65535
  TURN_EXTERNAL_IP_CONFIG=$(get_turn_external_ip)

  # Generate secrets for Dex
  DEX_DASHBOARD_CLIENT_SECRET=$(openssl rand -base64 32 | sed "$SED_STRIP_PADDING")

  # Generate admin password
  NETBIRD_ADMIN_PASSWORD=$(openssl rand -base64 16 | sed "$SED_STRIP_PADDING")

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

  check_jq

  DOCKER_COMPOSE_COMMAND=$(check_docker_compose)

  if [[ -f dex.yaml ]]; then
    echo "Generated files already exist, if you want to reinitialize the environment, please remove them first."
    echo "You can use the following commands:"
    echo "  $DOCKER_COMPOSE_COMMAND down --volumes # to remove all containers and volumes"
    echo "  rm -f docker-compose.yml Caddyfile dex.yaml dashboard.env turnserver.conf management.json relay.env"
    echo "Be aware that this will remove all data from the database, and you will have to reconfigure the dashboard."
    exit 1
  fi

  echo Rendering initial files...
  render_docker_compose > docker-compose.yml
  render_caddyfile > Caddyfile
  render_dex_config > dex.yaml
  render_dashboard_env > dashboard.env
  render_management_json > management.json
  render_turn_server_conf > turnserver.conf
  render_relay_env > relay.env

  echo -e "\nStarting Dex IDP\n"
  $DOCKER_COMPOSE_COMMAND up -d caddy dex

  # Wait for Dex to be ready (through caddy proxy)
  sleep 3
  wait_dex

  echo -e "\nStarting NetBird services\n"
  $DOCKER_COMPOSE_COMMAND up -d

  echo -e "\nDone!\n"
  echo "You can access the NetBird dashboard at $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  echo ""
  echo "Login with the following credentials:"
  echo "Email: admin@$NETBIRD_DOMAIN" | tee .env
  echo "Password: $NETBIRD_ADMIN_PASSWORD" | tee -a .env
  echo ""
  echo "Dex admin UI is not available (Dex has no built-in UI)."
  echo "To add more users, edit dex.yaml and restart: $DOCKER_COMPOSE_COMMAND restart dex"
  return 0
}

render_caddyfile() {
  cat <<EOF
{
  debug
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
    # Relay
    reverse_proxy /relay* relay:80
    # Signal
    reverse_proxy /signalexchange.SignalExchange/* h2c://signal:10000
    # Management
    reverse_proxy /api/* management:80
    reverse_proxy /management.ManagementService/* h2c://management:80
    # Dex
    reverse_proxy /dex/* dex:5556
    # Dashboard
    reverse_proxy /* dashboard:80
}
EOF
  return 0
}

render_dex_config() {
  # Generate bcrypt hash of the admin password
  # Using a simple approach - htpasswd or python if available
  ADMIN_PASSWORD_HASH=""
  if command -v htpasswd &> /dev/null; then
    ADMIN_PASSWORD_HASH=$(htpasswd -bnBC 10 "" "$NETBIRD_ADMIN_PASSWORD" | tr -d ':\n')
  elif command -v python3 &> /dev/null; then
    ADMIN_PASSWORD_HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw('$NETBIRD_ADMIN_PASSWORD'.encode(), bcrypt.gensalt(rounds=10)).decode())" 2>/dev/null || echo "")
  fi

  # Fallback to a known hash if we can't generate one
  if [[ -z "$ADMIN_PASSWORD_HASH" ]]; then
    # This is hash of "password" - user should change it
    ADMIN_PASSWORD_HASH='$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W'
    NETBIRD_ADMIN_PASSWORD="password"
    echo "Warning: Could not generate password hash. Using default password: password. Please change it in dex.yaml" > /dev/stderr
  fi

  cat <<EOF
# Dex configuration for NetBird
# Generated by getting-started-with-dex.sh

issuer: $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/dex

storage:
  type: sqlite3
  config:
    file: /var/dex/dex.db

web:
  http: 0.0.0.0:5556

# gRPC API for user management (used by NetBird IDP manager)
grpc:
  addr: 0.0.0.0:5557

oauth2:
  skipApprovalScreen: true

# Static OAuth2 clients for NetBird
staticClients:
  # Dashboard client
  - id: netbird-dashboard
    name: NetBird Dashboard
    secret: $DEX_DASHBOARD_CLIENT_SECRET
    redirectURIs:
      - $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/nb-auth
      - $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/nb-silent-auth

  # CLI client (public - uses PKCE)
  - id: netbird-cli
    name: NetBird CLI
    public: true
    redirectURIs:
      - http://localhost:53000/
      - http://localhost:54000/

# Enable password database for static users
enablePasswordDB: true

# Static users - add more users here as needed
staticPasswords:
  - email: "admin@$NETBIRD_DOMAIN"
    hash: "$ADMIN_PASSWORD_HASH"
    username: "admin"
    userID: "$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "admin-user-id-001")"

# Optional: Add external identity provider connectors
# connectors:
#   - type: github
#     id: github
#     name: GitHub
#     config:
#       clientID: \$GITHUB_CLIENT_ID
#       clientSecret: \$GITHUB_CLIENT_SECRET
#       redirectURI: $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/dex/callback
#
#   - type: ldap
#     id: ldap
#     name: LDAP
#     config:
#       host: ldap.example.com:636
#       insecureNoSSL: false
#       bindDN: cn=admin,dc=example,dc=com
#       bindPW: admin
#       userSearch:
#         baseDN: ou=users,dc=example,dc=com
#         filter: "(objectClass=person)"
#         username: uid
#         idAttr: uid
#         emailAttr: mail
#         nameAttr: cn
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
    "HttpConfig": {
        "AuthIssuer": "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/dex",
        "AuthAudience": "netbird-dashboard",
        "OIDCConfigEndpoint": "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/dex/.well-known/openid-configuration"
    },
    "IdpManagerConfig": {
        "ManagerType": "dex",
        "ClientConfig": {
            "Issuer": "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/dex"
        },
        "ExtraConfig": {
            "GRPCAddr": "dex:5557"
        }
    },
    "DeviceAuthorizationFlow": {
        "Provider": "hosted",
        "ProviderConfig": {
            "Audience": "netbird-cli",
            "ClientID": "netbird-cli",
            "Scope": "openid profile email offline_access",
            "DeviceAuthEndpoint": "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/dex/device/code",
            "TokenEndpoint": "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/dex/token"
        }
    },
    "PKCEAuthorizationFlow": {
        "ProviderConfig": {
            "Audience": "netbird-cli",
            "ClientID": "netbird-cli",
            "Scope": "openid profile email offline_access",
            "RedirectURLs": ["http://localhost:53000/", "http://localhost:54000/"]
        }
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
# OIDC
AUTH_AUDIENCE=netbird-dashboard
AUTH_CLIENT_ID=netbird-dashboard
AUTH_CLIENT_SECRET=$DEX_DASHBOARD_CLIENT_SECRET
AUTH_AUTHORITY=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/dex
USE_AUTH0=false
AUTH_SUPPORTED_SCOPES=openid profile email offline_access
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

  # Dex - identity provider
  dex:
    image: ghcr.io/dexidp/dex:v2.38.0
    container_name: netbird-dex
    restart: unless-stopped
    networks: [netbird]
    volumes:
      - ./dex.yaml:/etc/dex/config.docker.yaml:ro
      - netbird_dex_data:/var/dex
    command: ["dex", "serve", "/etc/dex/config.docker.yaml"]
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

  # Management
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
  netbird_dex_data:
  netbird_management:

networks:
  netbird:
EOF
  return 0
}

init_environment
