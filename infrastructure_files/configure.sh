#!/bin/bash
set -e

# Check required dependencies
for cmd in curl jq envsubst openssl; do
  if ! which $cmd >/dev/null 2>&1; then
    echo "This script requires $cmd. Please install it and re-run."
    exit 1
  fi
done

# Source configuration
source setup.env
source base.setup.env

# Validate required variables
if [[ -z "$NETBIRD_DOMAIN" ]]; then
  echo "NETBIRD_DOMAIN is not set, please update your setup.env file"
  exit 1
fi

# Check database configuration if using external database
if [[ "$NETBIRD_STORE_CONFIG_ENGINE" == "postgres" && -z "$NETBIRD_STORE_ENGINE_POSTGRES_DSN" ]]; then
  echo "Error: NETBIRD_STORE_CONFIG_ENGINE=postgres but NETBIRD_STORE_ENGINE_POSTGRES_DSN is not set."
  exit 1
fi

if [[ "$NETBIRD_STORE_CONFIG_ENGINE" == "mysql" && -z "$NETBIRD_STORE_ENGINE_MYSQL_DSN" ]]; then
  echo "Error: NETBIRD_STORE_CONFIG_ENGINE=mysql but NETBIRD_STORE_ENGINE_MYSQL_DSN is not set."
  exit 1
fi

# Configure for local development vs production
if [[ $NETBIRD_DOMAIN == "localhost" || $NETBIRD_DOMAIN == "127.0.0.1" ]]; then
  export NETBIRD_MGMT_SINGLE_ACCOUNT_MODE_DOMAIN="netbird.selfhosted"
  export NETBIRD_MGMT_API_ENDPOINT="http://$NETBIRD_DOMAIN"
  export NETBIRD_HTTP_PROTOCOL="http"
  export ZITADEL_EXTERNALSECURE="false"
  export ZITADEL_EXTERNALPORT="80"
  export ZITADEL_TLS_MODE="disabled"
  export NETBIRD_RELAY_PROTO="rel"
else
  export NETBIRD_HTTP_PROTOCOL="https"
  export ZITADEL_EXTERNALSECURE="true"
  export ZITADEL_EXTERNALPORT="443"
  export ZITADEL_TLS_MODE="external"
  export NETBIRD_RELAY_PROTO="rels"
  export CADDY_SECURE_DOMAIN=", $NETBIRD_DOMAIN:443"
fi

# Auto-generate secrets if not provided
[[ -z "$TURN_PASSWORD" ]] && export TURN_PASSWORD=$(openssl rand -base64 32 | sed 's/=//g')
[[ -z "$NETBIRD_RELAY_AUTH_SECRET" ]] && export NETBIRD_RELAY_AUTH_SECRET=$(openssl rand -base64 32 | sed 's/=//g')
[[ -z "$ZITADEL_MASTERKEY" ]] && export ZITADEL_MASTERKEY=$(openssl rand -base64 32 | head -c 32)

# Generate Zitadel admin credentials if not provided
if [[ -z "$ZITADEL_ADMIN_USERNAME" ]]; then
  export ZITADEL_ADMIN_USERNAME="admin@${NETBIRD_DOMAIN}"
fi
if [[ -z "$ZITADEL_ADMIN_PASSWORD" ]]; then
  export ZITADEL_ADMIN_PASSWORD="$(openssl rand -base64 32 | sed 's/=//g')!"
fi

# Set Zitadel PAT expiration (1 year from now)
if [[ "$OSTYPE" == "darwin"* ]]; then
  export ZITADEL_PAT_EXPIRATION=$(date -u -v+1y "+%Y-%m-%dT%H:%M:%SZ")
else
  export ZITADEL_PAT_EXPIRATION=$(date -u -d "+1 year" "+%Y-%m-%dT%H:%M:%SZ")
fi

# Discover external IP for TURN
TURN_EXTERNAL_IP_CONFIG="#"
if [[ -z "$NETBIRD_TURN_EXTERNAL_IP" ]]; then
  IP=$(curl -s -4 https://jsonip.com | jq -r '.ip' 2>/dev/null || echo "")
  [[ -n "$IP" ]] && TURN_EXTERNAL_IP_CONFIG="external-ip=$IP"
elif echo "$NETBIRD_TURN_EXTERNAL_IP" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
  TURN_EXTERNAL_IP_CONFIG="external-ip=$NETBIRD_TURN_EXTERNAL_IP"
fi
export TURN_EXTERNAL_IP_CONFIG

# Configure endpoints
export NETBIRD_AUTH_AUTHORITY="${NETBIRD_HTTP_PROTOCOL}://${NETBIRD_DOMAIN}"
export NETBIRD_AUTH_TOKEN_ENDPOINT="${NETBIRD_AUTH_AUTHORITY}/oauth/v2/token"
export NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT="${NETBIRD_AUTH_AUTHORITY}/.well-known/openid-configuration"
export NETBIRD_AUTH_JWT_CERTS="${NETBIRD_AUTH_AUTHORITY}/.well-known/jwks.json"
export NETBIRD_AUTH_PKCE_AUTHORIZATION_ENDPOINT="${NETBIRD_AUTH_AUTHORITY}/oauth/v2/authorize"
export NETBIRD_AUTH_DEVICE_AUTH_ENDPOINT="${NETBIRD_AUTH_AUTHORITY}/oauth/v2/device_authorization"
export ZITADEL_MANAGEMENT_ENDPOINT="${NETBIRD_AUTH_AUTHORITY}/management/v1"
export NETBIRD_RELAY_ENDPOINT="${NETBIRD_RELAY_PROTO}://${NETBIRD_DOMAIN}:${ZITADEL_EXTERNALPORT}"

# Volume names (with backwards compatibility)
MGMT_VOLUMENAME="${VOLUME_PREFIX}${MGMT_VOLUMESUFFIX}"
SIGNAL_VOLUMENAME="${VOLUME_PREFIX}${SIGNAL_VOLUMESUFFIX}"
OLD_PREFIX='wiretrustee-'
docker volume ls 2>/dev/null | grep -q "${OLD_PREFIX}${MGMT_VOLUMESUFFIX}" && MGMT_VOLUMENAME="${OLD_PREFIX}${MGMT_VOLUMESUFFIX}"
docker volume ls 2>/dev/null | grep -q "${OLD_PREFIX}${SIGNAL_VOLUMESUFFIX}" && SIGNAL_VOLUMENAME="${OLD_PREFIX}${SIGNAL_VOLUMESUFFIX}"
export MGMT_VOLUMENAME SIGNAL_VOLUMENAME

# Preserve existing encryption key
if test -f 'management.json'; then
  encKey=$(jq -r ".DataStoreEncryptionKey" management.json 2>/dev/null || echo "null")
  [[ "$encKey" != "null" && -n "$encKey" ]] && export NETBIRD_DATASTORE_ENC_KEY="$encKey"
fi

# Create artifacts directory and backup existing files
artifacts_path="./artifacts"
mkdir -p "$artifacts_path"
bkp_postfix="$(date +%s)"
for file in docker-compose.yml management.json turnserver.conf Caddyfile; do
  [[ -f "${artifacts_path}/${file}" ]] && cp "${artifacts_path}/${file}" "${artifacts_path}/${file}.bkp.${bkp_postfix}"
done

# Generate configuration files
envsubst < docker-compose.yml.tmpl > "$artifacts_path/docker-compose.yml"
envsubst < management.json.tmpl | jq . > "$artifacts_path/management.json"
envsubst < turnserver.conf.tmpl > "$artifacts_path/turnserver.conf"
envsubst < Caddyfile.tmpl > "$artifacts_path/Caddyfile"

# Print summary
echo ""
echo "=========================================="
echo "  NetBird Configuration Complete"
echo "=========================================="
echo "  Domain: $NETBIRD_DOMAIN"
echo "  Protocol: $NETBIRD_HTTP_PROTOCOL"
echo "  Zitadel: $ZITADEL_TAG (SQLite)"
echo "=========================================="
echo ""
echo "  ADMIN CREDENTIALS (save these!):"
echo "  Username: $ZITADEL_ADMIN_USERNAME"
echo "  Password: $ZITADEL_ADMIN_PASSWORD"
echo ""
echo "=========================================="
echo ""
echo "To start NetBird:"
echo "  cd $artifacts_path && docker compose up -d"
echo ""
