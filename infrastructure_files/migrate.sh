#!/bin/bash
#
# NetBird Migration Script: Pre-v0.65.0 → Combined Container Setup
#
# Migrates from the old 5-container deployment (dashboard, signal, relay, management, coturn)
# to the new 2-container setup (Traefik + combined netbird-server).
#
# Supported: Embedded IdP (Dex) setups with embedded Caddy or custom reverse proxy.
# Not supported: External IdP (Auth0, Keycloak, etc.) — use getting-started.sh for fresh setup.
#
# Usage:
#   ./migrate.sh [--install-dir /path/to/netbird] [--non-interactive]

set -euo pipefail

############################################
# Constants
############################################

readonly SCRIPT_VERSION="1.0.0"
readonly DASHBOARD_IMAGE="netbirdio/dashboard:latest"
readonly NETBIRD_SERVER_IMAGE="netbirdio/netbird-server:latest"
readonly SED_STRIP_PADDING='s/=//g'
readonly MSG_SEPARATOR="=========================================="
readonly PROXY_TYPE_CADDY="caddy_embedded"

# Colors (disabled if not a terminal)
if [[ -t 1 ]]; then
  readonly RED='\033[0;31m'
  readonly GREEN='\033[0;32m'
  readonly YELLOW='\033[1;33m'
  readonly BLUE='\033[0;34m'
  readonly NC='\033[0m'
else
  readonly RED=''
  readonly GREEN=''
  readonly YELLOW=''
  readonly BLUE=''
  readonly NC=''
fi

############################################
# Global Variables (set during detection)
############################################

INSTALL_DIR=""
NON_INTERACTIVE=false
DOCKER_COMPOSE_CMD=""

# Detection results
PROXY_TYPE=""          # caddy_embedded | traefik | external
IDP_TYPE=""            # embedded | external
MGMT_VOLUME=""         # detected management volume name
DOMAIN=""
LETSENCRYPT_EMAIL=""
STORE_ENGINE="sqlite"
STORE_DSN=""
ENCRYPTION_KEY=""
RELAY_SECRET=""
SIGNKEY_REFRESH="true"
TRUSTED_PROXIES=""
TRUSTED_PROXIES_COUNT=""
TRUSTED_PEERS=""
MANAGEMENT_JSON_PATH=""
BACKUP_DIR=""

############################################
# Utility Functions
############################################

log_info() {
  local msg="$1"
  echo -e "${BLUE}[INFO]${NC} ${msg}"
  return 0
}

log_warn() {
  local msg="$1"
  echo -e "${YELLOW}[WARN]${NC} ${msg}"
  return 0
}

log_error() {
  local msg="$1"
  echo -e "${RED}[ERROR]${NC} ${msg}" >&2
  return 0
}

log_success() {
  local msg="$1"
  echo -e "${GREEN}[OK]${NC} ${msg}"
  return 0
}

print_banner() {
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  NetBird Migration Tool v${SCRIPT_VERSION}"
  echo "  Pre-v0.65.0 → Combined Container Setup"
  echo "$MSG_SEPARATOR"
  echo ""
  return 0
}

confirm_action() {
  local prompt="$1"
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    return 0
  fi
  echo ""
  echo -n "$prompt [y/N]: "
  read -r response < /dev/tty
  if [[ ! "$response" =~ ^[Yy]$ ]]; then
    log_error "Aborted by user."
    exit 1
  fi
  return 0
}

############################################
# Phase 0: Preflight & Detection
############################################

check_dependencies() {
  log_info "Checking dependencies..."

  local missing=()

  if ! command -v docker &>/dev/null; then
    missing+=("docker")
  fi

  if command -v docker-compose &>/dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
  elif docker compose --help &>/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
  else
    missing+=("docker-compose")
  fi

  if ! command -v jq &>/dev/null; then
    missing+=("jq")
  fi

  if ! command -v openssl &>/dev/null; then
    missing+=("openssl")
  fi

  if ! command -v curl &>/dev/null; then
    missing+=("curl")
  fi

  if [[ ${#missing[@]} -gt 0 ]]; then
    log_error "Missing required dependencies: ${missing[*]}"
    echo "Please install them and re-run the script."
    exit 1
  fi

  log_success "All dependencies found (docker compose: '$DOCKER_COMPOSE_CMD')"
  return 0
}

detect_install_dir() {
  if [[ -n "$INSTALL_DIR" ]]; then
    if [[ ! -d "$INSTALL_DIR" ]]; then
      log_error "Specified install directory does not exist: $INSTALL_DIR"
      exit 1
    fi
    return 0
  fi

  log_info "Detecting installation directory..."

  local search_paths=("$PWD" "/opt/netbird" "/opt/wiretrustee")
  for dir in "${search_paths[@]}"; do
    if [[ -f "$dir/management.json" ]] || [[ -f "$dir/artifacts/management.json" ]]; then
      INSTALL_DIR="$dir"
      log_success "Found installation at: $INSTALL_DIR"
      return 0
    fi
  done

  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    log_error "Could not auto-detect installation directory. Use --install-dir to specify."
    exit 1
  fi

  echo ""
  echo -n "Enter the path to your NetBird installation directory: "
  read -r INSTALL_DIR < /dev/tty
  if [[ ! -d "$INSTALL_DIR" ]]; then
    log_error "Directory does not exist: $INSTALL_DIR"
    exit 1
  fi
  return 0
}

validate_old_setup() {
  log_info "Validating old setup..."

  # Find management.json — check both root and artifacts/
  if [[ -f "$INSTALL_DIR/management.json" ]]; then
    MANAGEMENT_JSON_PATH="$INSTALL_DIR/management.json"
  elif [[ -f "$INSTALL_DIR/artifacts/management.json" ]]; then
    MANAGEMENT_JSON_PATH="$INSTALL_DIR/artifacts/management.json"
  else
    log_error "Cannot find management.json in $INSTALL_DIR or $INSTALL_DIR/artifacts/"
    echo "This doesn't appear to be a valid NetBird installation."
    exit 1
  fi

  # Check for docker-compose.yml (in root or artifacts/)
  local compose_found=false
  if [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
    compose_found=true
  elif [[ -f "$INSTALL_DIR/artifacts/docker-compose.yml" ]]; then
    compose_found=true
  fi

  if [[ "$compose_found" != "true" ]]; then
    log_error "Cannot find docker-compose.yml in $INSTALL_DIR or $INSTALL_DIR/artifacts/"
    exit 1
  fi

  log_success "Found management.json at: $MANAGEMENT_JSON_PATH"
  return 0
}

check_already_migrated() {
  if [[ -f "$INSTALL_DIR/config.yaml" ]]; then
    log_warn "config.yaml already exists in $INSTALL_DIR"
    echo "It appears this installation has already been migrated."
    echo "If you want to re-run the migration, remove config.yaml first."
    exit 0
  fi
  return 0
}

detect_reverse_proxy() {
  log_info "Detecting reverse proxy type..."

  local compose_file=""
  if [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
    compose_file="$INSTALL_DIR/docker-compose.yml"
  elif [[ -f "$INSTALL_DIR/artifacts/docker-compose.yml" ]]; then
    compose_file="$INSTALL_DIR/artifacts/docker-compose.yml"
  fi

  # Check for Traefik service or labels
  if grep -q 'traefik' "$compose_file" 2>/dev/null; then
    PROXY_TYPE="traefik"
    log_info "Detected: Traefik reverse proxy"
    return 0
  fi

  # Check for embedded Caddy — two patterns:
  # 1. Old configure.sh: dashboard container with LETSENCRYPT_DOMAIN env var + ports 80/443
  # 2. v0.62+ getting-started.sh: Caddy service in compose or standalone Caddyfile
  if grep -q 'LETSENCRYPT_DOMAIN' "$compose_file" 2>/dev/null && { grep -q '443:443' "$compose_file" 2>/dev/null || grep -q '443:' "$compose_file" 2>/dev/null; }; then
    PROXY_TYPE="$PROXY_TYPE_CADDY"
    log_info "Detected: Embedded Caddy (dashboard container with Let's Encrypt)"
    return 0
  fi

  # Check for Caddy service in docker-compose.yml (v0.62+ pattern)
  if grep -qE '^\s+caddy:|^\s+image:.*caddy' "$compose_file" 2>/dev/null; then
    PROXY_TYPE="$PROXY_TYPE_CADDY"
    log_info "Detected: Caddy reverse proxy (in Docker Compose)"
    return 0
  fi

  # Check for standalone Caddyfile in install directory (v0.62+ getting-started.sh)
  if [[ -f "$INSTALL_DIR/Caddyfile" ]]; then
    # Verify Caddy is referenced in docker-compose.yml or running as a container
    if grep -q 'caddy' "$compose_file" 2>/dev/null || grep -q 'Caddyfile' "$compose_file" 2>/dev/null; then
      PROXY_TYPE="$PROXY_TYPE_CADDY"
      log_info "Detected: Caddy reverse proxy (Caddyfile + Docker Compose)"
      return 0
    fi
    # Caddyfile exists but not in compose — might be running on host
    PROXY_TYPE="$PROXY_TYPE_CADDY"
    log_info "Detected: Caddy reverse proxy (standalone Caddyfile)"
    return 0
  fi

  # Check for disabled Let's Encrypt (external proxy)
  if [[ -f "$INSTALL_DIR/setup.env" ]] && grep -q 'NETBIRD_DISABLE_LETSENCRYPT=true' "$INSTALL_DIR/setup.env" 2>/dev/null; then
    PROXY_TYPE="external"
    log_info "Detected: External reverse proxy (Let's Encrypt disabled)"
    return 0
  fi

  # Default to external
  PROXY_TYPE="external"
  log_info "Detected: External/custom reverse proxy"
  return 0
}

detect_idp_type() {
  log_info "Detecting identity provider type..."

  # Check for embedded IdP (v0.62.0+ getting-started.sh format)
  local embedded_enabled
  embedded_enabled=$(jq -r '.EmbeddedIdP.Enabled // false' "$MANAGEMENT_JSON_PATH" 2>/dev/null || echo "false")
  if [[ "$embedded_enabled" == "true" ]]; then
    IDP_TYPE="embedded"
    log_success "IdP type: embedded (suitable for migration)"
    return 0
  fi

  # Check IdpManagerConfig.ManagerType (old configure.sh format)
  local manager_type
  manager_type=$(jq -r '.IdpManagerConfig.ManagerType // ""' "$MANAGEMENT_JSON_PATH" 2>/dev/null || echo "")

  if [[ -n "$manager_type" && "$manager_type" != "null" && "$manager_type" != "none" && "$manager_type" != "" ]]; then
    IDP_TYPE="external"
    log_error "External IdP detected: $manager_type"
    echo ""
    echo "This migration script only supports embedded IdP setups."
    echo "External IdP providers (Auth0, Keycloak, Zitadel, etc.) require"
    echo "a fresh installation using getting-started.sh."
    echo ""
    echo "Please refer to the NetBird documentation for upgrade instructions:"
    echo "  https://docs.netbird.io/selfhosted/getting-started"
    exit 1
  fi

  # Check HttpConfig.AuthIssuer for well-known external providers
  local auth_issuer
  auth_issuer=$(jq -r '.HttpConfig.AuthIssuer // ""' "$MANAGEMENT_JSON_PATH" 2>/dev/null || echo "")

  if [[ -n "$auth_issuer" && "$auth_issuer" != "null" ]]; then
    for provider in "auth0.com" "accounts.google.com" "login.microsoftonline.com" "keycloak" "zitadel" "authentik"; do
      if echo "$auth_issuer" | grep -qi "$provider" 2>/dev/null; then
        log_error "External OIDC provider detected: $auth_issuer"
        echo ""
        echo "This migration script only supports embedded IdP setups."
        echo "Please use getting-started.sh for a fresh installation."
        exit 1
      fi
    done
  fi

  # No embedded IdP and no external IdP detected — assume old setup without IdP manager
  IDP_TYPE="embedded"
  log_success "IdP type: embedded (suitable for migration)"
  return 0
}

detect_volumes() {
  log_info "Detecting Docker volumes..."

  local volumes_list
  volumes_list=$(docker volume ls --format '{{.Name}}' 2>/dev/null || echo "")

  # Check for well-known volume name patterns (exact match)
  local volume_patterns=(
    "wiretrustee-mgmt"
    "netbird-mgmt"
  )
  for pattern in "${volume_patterns[@]}"; do
    if echo "$volumes_list" | grep -q "^${pattern}$"; then
      MGMT_VOLUME="$pattern"
      log_success "Found management volume: $MGMT_VOLUME"
      return 0
    fi
  done

  # Check compose-prefixed patterns (e.g., netbird_netbird-mgmt, infrastructure_files_netbird-mgmt)
  local compose_prefixed
  compose_prefixed=$(echo "$volumes_list" | grep -E '(netbird|wiretrustee).*mgmt' | head -n1 || echo "")
  if [[ -n "$compose_prefixed" ]]; then
    MGMT_VOLUME="$compose_prefixed"
    log_success "Found management volume (compose-prefixed): $MGMT_VOLUME"
    return 0
  fi

  # Try to extract volume name from old docker-compose.yml
  local compose_file=""
  if [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
    compose_file="$INSTALL_DIR/docker-compose.yml"
  elif [[ -f "$INSTALL_DIR/artifacts/docker-compose.yml" ]]; then
    compose_file="$INSTALL_DIR/artifacts/docker-compose.yml"
  fi
  if [[ -n "$compose_file" ]]; then
    # Look for volume mount on /var/lib/netbird in management or netbird-server service
    local vol_name
    vol_name=$(grep -E '^\s+-\s+\S+:/var/lib/netbird' "$compose_file" 2>/dev/null | head -1 | sed 's/.*- //' | sed 's/:.*//' | tr -d ' ' || echo "")
    if [[ -n "$vol_name" && "$vol_name" != "." && "$vol_name" != "/" ]]; then
      # Check if this volume exists in Docker
      local full_vol
      full_vol=$(echo "$volumes_list" | grep -F "$vol_name" | head -1 || echo "")
      if [[ -n "$full_vol" ]]; then
        MGMT_VOLUME="$full_vol"
        log_success "Found management volume (from compose): $MGMT_VOLUME"
        return 0
      fi
    fi
  fi

  log_warn "Could not detect management volume. A new volume will be created."
  MGMT_VOLUME=""
  return 0
}

detect_domain() {
  log_info "Detecting domain..."

  # Try setup.env first
  if [[ -z "$DOMAIN" && -f "$INSTALL_DIR/setup.env" ]]; then
    DOMAIN=$(grep '^NETBIRD_DOMAIN=' "$INSTALL_DIR/setup.env" 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  fi

  # Try EmbeddedIdP.Issuer (v0.62.0+ getting-started.sh format)
  if [[ -z "$DOMAIN" ]]; then
    local issuer
    issuer=$(jq -r '.EmbeddedIdP.Issuer // ""' "$MANAGEMENT_JSON_PATH" 2>/dev/null || echo "")
    if [[ -n "$issuer" && "$issuer" != "null" ]]; then
      DOMAIN=$(echo "$issuer" | sed 's|https\?://||' | sed 's|/.*||' | sed 's|:.*||')
    fi
  fi

  # Try HttpConfig.AuthIssuer (old configure.sh format)
  if [[ -z "$DOMAIN" ]]; then
    local issuer
    issuer=$(jq -r '.HttpConfig.AuthIssuer // ""' "$MANAGEMENT_JSON_PATH" 2>/dev/null || echo "")
    if [[ -n "$issuer" && "$issuer" != "null" ]]; then
      DOMAIN=$(echo "$issuer" | sed 's|https\?://||' | sed 's|/.*||' | sed 's|:.*||')
    fi
  fi

  # Try dashboard.env NETBIRD_MGMT_API_ENDPOINT
  if [[ -z "$DOMAIN" && -f "$INSTALL_DIR/dashboard.env" ]]; then
    local endpoint
    endpoint=$(grep '^NETBIRD_MGMT_API_ENDPOINT=' "$INSTALL_DIR/dashboard.env" 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
    if [[ -n "$endpoint" ]]; then
      DOMAIN=$(echo "$endpoint" | sed 's|https\?://||' | sed 's|/.*||' | sed 's|:.*||')
    fi
  fi

  if [[ -z "$DOMAIN" ]]; then
    log_error "Could not detect domain from management.json, setup.env, or dashboard.env."
    exit 1
  fi

  # Detect Let's Encrypt email from setup.env or dashboard.env LETSENCRYPT_DOMAIN
  if [[ -f "$INSTALL_DIR/setup.env" ]]; then
    LETSENCRYPT_EMAIL=$(grep '^NETBIRD_LETSENCRYPT_EMAIL=' "$INSTALL_DIR/setup.env" 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  fi

  log_success "Domain: $DOMAIN"
  if [[ -n "$LETSENCRYPT_EMAIL" ]]; then
    log_success "Let's Encrypt email: $LETSENCRYPT_EMAIL"
  fi
  return 0
}

detect_store_config() {
  log_info "Detecting store configuration..."

  # Engine from management.json
  local engine
  engine=$(jq -r '.StoreConfig.Engine // ""' "$MANAGEMENT_JSON_PATH" 2>/dev/null || echo "")
  if [[ -n "$engine" && "$engine" != "null" && "$engine" != "" ]]; then
    STORE_ENGINE="$engine"
  fi

  # DSN from environment files
  if [[ -f "$INSTALL_DIR/setup.env" ]]; then
    local pg_dsn
    pg_dsn=$(grep '^NETBIRD_STORE_ENGINE_POSTGRES_DSN=' "$INSTALL_DIR/setup.env" 2>/dev/null | sed 's/^NETBIRD_STORE_ENGINE_POSTGRES_DSN=//' | tr -d '"' || echo "")
    if [[ -n "$pg_dsn" ]]; then
      STORE_DSN="$pg_dsn"
    fi

    local mysql_dsn
    mysql_dsn=$(grep '^NETBIRD_STORE_ENGINE_MYSQL_DSN=' "$INSTALL_DIR/setup.env" 2>/dev/null | sed 's/^NETBIRD_STORE_ENGINE_MYSQL_DSN=//' | tr -d '"' || echo "")
    if [[ -n "$mysql_dsn" ]]; then
      STORE_DSN="$mysql_dsn"
    fi
  fi

  # Also check base.setup.env
  if [[ -z "$STORE_DSN" && -f "$INSTALL_DIR/base.setup.env" ]]; then
    local pg_dsn
    pg_dsn=$(grep '^NETBIRD_STORE_ENGINE_POSTGRES_DSN=' "$INSTALL_DIR/base.setup.env" 2>/dev/null | sed 's/^NETBIRD_STORE_ENGINE_POSTGRES_DSN=//' | tr -d '"' || echo "")
    if [[ -n "$pg_dsn" ]]; then
      STORE_DSN="$pg_dsn"
    fi

    local mysql_dsn
    mysql_dsn=$(grep '^NETBIRD_STORE_ENGINE_MYSQL_DSN=' "$INSTALL_DIR/base.setup.env" 2>/dev/null | sed 's/^NETBIRD_STORE_ENGINE_MYSQL_DSN=//' | tr -d '"' || echo "")
    if [[ -n "$mysql_dsn" ]]; then
      STORE_DSN="$mysql_dsn"
    fi
  fi

  log_success "Store engine: $STORE_ENGINE"
  if [[ -n "$STORE_DSN" ]]; then
    log_success "Store DSN: [detected]"
  fi
  return 0
}

extract_config_values() {
  log_info "Extracting configuration from management.json..."

  # DataStoreEncryptionKey
  ENCRYPTION_KEY=$(jq -r '.DataStoreEncryptionKey // ""' "$MANAGEMENT_JSON_PATH" 2>/dev/null || echo "")
  if [[ -z "$ENCRYPTION_KEY" || "$ENCRYPTION_KEY" == "null" ]]; then
    ENCRYPTION_KEY=$(openssl rand -base64 32)
    log_warn "No encryption key found in management.json — generated a new one."
    log_warn "IMPORTANT: Save this key! Without it, existing encrypted data cannot be read."
    echo "  Encryption key: $ENCRYPTION_KEY"
  fi

  # Relay secret from management.json
  RELAY_SECRET=$(jq -r '.Relay.Secret // ""' "$MANAGEMENT_JSON_PATH" 2>/dev/null || echo "")

  # Fallback: relay secret from setup.env
  if [[ (-z "$RELAY_SECRET" || "$RELAY_SECRET" == "null") && -f "$INSTALL_DIR/setup.env" ]]; then
    RELAY_SECRET=$(grep '^NETBIRD_RELAY_AUTH_SECRET=' "$INSTALL_DIR/setup.env" 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  fi

  # Fallback: relay secret from base.setup.env
  if [[ (-z "$RELAY_SECRET" || "$RELAY_SECRET" == "null") && -f "$INSTALL_DIR/base.setup.env" ]]; then
    RELAY_SECRET=$(grep '^NETBIRD_RELAY_AUTH_SECRET=' "$INSTALL_DIR/base.setup.env" 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
  fi

  # Generate if still empty
  if [[ -z "$RELAY_SECRET" || "$RELAY_SECRET" == "null" ]]; then
    RELAY_SECRET=$(openssl rand -base64 32 | sed "$SED_STRIP_PADDING")
    log_warn "No relay secret found — generated a new one."
  fi

  # IdpSignKeyRefreshEnabled — check both HttpConfig and EmbeddedIdP locations
  local signkey_raw
  signkey_raw=$(jq -r '(.HttpConfig.IdpSignKeyRefreshEnabled // .EmbeddedIdP.SignKeyRefreshEnabled) // "true"' "$MANAGEMENT_JSON_PATH" 2>/dev/null || echo "true")
  if [[ "$signkey_raw" == "false" ]]; then
    SIGNKEY_REFRESH="false"
  else
    SIGNKEY_REFRESH="true"
  fi

  # ReverseProxy settings (may not exist in v0.62+ getting-started.sh format)
  TRUSTED_PROXIES=$(jq -c '.ReverseProxy.TrustedHTTPProxies // []' "$MANAGEMENT_JSON_PATH" 2>/dev/null || echo "[]")
  TRUSTED_PROXIES_COUNT=$(jq -r '.ReverseProxy.TrustedHTTPProxiesCount // 0' "$MANAGEMENT_JSON_PATH" 2>/dev/null || echo "0")
  TRUSTED_PEERS=$(jq -c '.ReverseProxy.TrustedPeers // []' "$MANAGEMENT_JSON_PATH" 2>/dev/null || echo "[]")

  log_success "Configuration values extracted"
  return 0
}

print_detection_summary() {
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  Migration Summary"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "  Install directory:  $INSTALL_DIR"
  echo "  Domain:             $DOMAIN"
  echo "  Reverse proxy:      $PROXY_TYPE"
  echo "  Store engine:       $STORE_ENGINE"
  if [[ -n "$STORE_DSN" ]]; then
    echo "  Store DSN:          [configured]"
  fi
  if [[ -n "$MGMT_VOLUME" ]]; then
    echo "  Management volume:  $MGMT_VOLUME"
  else
    echo "  Management volume:  [new volume will be created]"
  fi
  echo "  Encryption key:     ${ENCRYPTION_KEY:0:8}..."
  echo "  Relay secret:       ${RELAY_SECRET:0:8}..."
  echo ""

  if [[ "$PROXY_TYPE" == "$PROXY_TYPE_CADDY" ]]; then
    echo "  Migration mode:     AUTOMATIC"
    echo "  A Traefik-based docker-compose.yml will be generated and services"
    echo "  will be stopped and restarted automatically."
  else
    echo "  Migration mode:     MANUAL"
    echo "  New config files will be generated. You will need to stop old"
    echo "  containers, replace docker-compose.yml, and restart manually."
  fi
  echo ""
  return 0
}

############################################
# Phase 1: Backup
############################################

create_backup() {
  BACKUP_DIR="$INSTALL_DIR/backup-$(date +%Y%m%d-%H%M%S)"
  log_info "Creating backup at: $BACKUP_DIR"
  mkdir -p "$BACKUP_DIR"

  # Copy config files
  local files_to_backup=(
    "docker-compose.yml"
    "management.json"
    "setup.env"
    "base.setup.env"
    "turnserver.conf"
    "dashboard.env"
  )

  for f in "${files_to_backup[@]}"; do
    if [[ -f "$INSTALL_DIR/$f" ]]; then
      cp "$INSTALL_DIR/$f" "$BACKUP_DIR/$f"
    fi
  done

  # Back up artifacts/ if it exists
  if [[ -d "$INSTALL_DIR/artifacts" ]]; then
    cp -r "$INSTALL_DIR/artifacts" "$BACKUP_DIR/artifacts"
  fi

  # Record state
  {
    echo "# NetBird migration backup state"
    echo "# Created: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""
    echo "## Docker volumes"
    docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E '(netbird|wiretrustee)' || echo "(none found)"
    echo ""
    echo "## Running containers"
    docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null | grep -E '(netbird|wiretrustee|dashboard|signal|relay|management|coturn)' || echo "(none running)"
  } > "$BACKUP_DIR/state.txt"

  # Generate rollback script
  generate_rollback_script

  log_success "Backup created at: $BACKUP_DIR"
  return 0
}

generate_rollback_script() {
  cat > "$BACKUP_DIR/rollback.sh" <<'ROLLBACK_HEADER'
#!/bin/bash
set -euo pipefail

# NetBird Migration Rollback Script
# Restores the pre-migration configuration and restarts old containers.

ROLLBACK_HEADER

  cat >> "$BACKUP_DIR/rollback.sh" <<ROLLBACK_BODY
INSTALL_DIR="$INSTALL_DIR"
BACKUP_DIR="$BACKUP_DIR"

echo "Restoring NetBird configuration from backup..."

# Stop new containers if running
cd "\$INSTALL_DIR"
if command -v docker-compose &>/dev/null; then
  COMPOSE_CMD="docker-compose"
elif docker compose --help &>/dev/null 2>&1; then
  COMPOSE_CMD="docker compose"
else
  echo "ERROR: docker compose not found" >&2
  exit 1
fi

echo "Stopping current containers..."
\$COMPOSE_CMD down 2>/dev/null || true

# Restore old config files
echo "Restoring configuration files..."
for f in docker-compose.yml management.json setup.env base.setup.env turnserver.conf dashboard.env; do
  if [[ -f "\$BACKUP_DIR/\$f" ]]; then
    cp "\$BACKUP_DIR/\$f" "\$INSTALL_DIR/\$f"
    echo "  Restored: \$f"
  fi
done

# Remove new config files
for f in config.yaml; do
  if [[ -f "\$INSTALL_DIR/\$f" ]]; then
    rm "\$INSTALL_DIR/\$f"
    echo "  Removed: \$f"
  fi
done

# Restart old containers
echo "Starting old containers..."
cd "\$INSTALL_DIR"
\$COMPOSE_CMD up -d

echo ""
echo "Rollback complete. Old containers are running."
echo "Verify with: \$COMPOSE_CMD ps"
ROLLBACK_BODY

  chmod +x "$BACKUP_DIR/rollback.sh"
  return 0
}

############################################
# Phase 3: Generate New Configuration Files
############################################

generate_config_yaml() {
  log_info "Generating config.yaml..."

  local dsn_line=""
  if [[ -n "$STORE_DSN" ]]; then
    dsn_line="    dsn: \"$STORE_DSN\""
  fi

  local reverse_proxy_section=""
  # Only add reverseProxy if there are non-default values
  local has_proxy_config=false
  if [[ "$TRUSTED_PROXIES" != "[]" && -n "$TRUSTED_PROXIES" ]]; then
    has_proxy_config=true
  fi
  if [[ "$TRUSTED_PROXIES_COUNT" != "0" && -n "$TRUSTED_PROXIES_COUNT" ]]; then
    has_proxy_config=true
  fi
  if [[ "$TRUSTED_PEERS" != "[]" && -n "$TRUSTED_PEERS" ]]; then
    # Check if it's only the default ["0.0.0.0/0"]
    local default_peers='["0.0.0.0/0"]'
    if [[ "$TRUSTED_PEERS" != "$default_peers" ]]; then
      has_proxy_config=true
    fi
  fi

  if [[ "$has_proxy_config" == "true" ]]; then
    reverse_proxy_section="
  reverseProxy:"
    if [[ "$TRUSTED_PROXIES" != "[]" && -n "$TRUSTED_PROXIES" ]]; then
      reverse_proxy_section+="
    trustedHTTPProxies:"
      for proxy in $(echo "$TRUSTED_PROXIES" | jq -r '.[]' 2>/dev/null); do
        reverse_proxy_section+="
      - \"$proxy\""
      done
    fi
    if [[ "$TRUSTED_PROXIES_COUNT" != "0" && -n "$TRUSTED_PROXIES_COUNT" ]]; then
      reverse_proxy_section+="
    trustedHTTPProxiesCount: $TRUSTED_PROXIES_COUNT"
    fi
    if [[ "$TRUSTED_PEERS" != "[]" && -n "$TRUSTED_PEERS" ]]; then
      reverse_proxy_section+="
    trustedPeers:"
      for peer in $(echo "$TRUSTED_PEERS" | jq -r '.[]' 2>/dev/null); do
        reverse_proxy_section+="
      - \"$peer\""
      done
    fi
  fi

  {
    cat <<EOF
# Combined NetBird Server Configuration (Simplified)
# Generated by migrate.sh on $(date -u '+%Y-%m-%d %H:%M:%S UTC')

server:
  listenAddress: ":80"
  exposedAddress: "https://${DOMAIN}:443"
  stunPorts:
    - 3478
  metricsPort: 9090
  healthcheckAddress: ":9000"
  logLevel: "info"
  logFile: "console"

  authSecret: "${RELAY_SECRET}"
  dataDir: "/var/lib/netbird"

  auth:
    issuer: "https://${DOMAIN}/oauth2"
    signKeyRefreshEnabled: ${SIGNKEY_REFRESH}
    dashboardRedirectURIs:
      - "https://${DOMAIN}/nb-auth"
      - "https://${DOMAIN}/nb-silent-auth"
    cliRedirectURIs:
      - "http://localhost:53000/"

  store:
    engine: "${STORE_ENGINE}"
    encryptionKey: "${ENCRYPTION_KEY}"
EOF
    if [[ -n "$dsn_line" ]]; then
      echo "$dsn_line"
    fi
    if [[ -n "$reverse_proxy_section" ]]; then
      echo "$reverse_proxy_section"
    fi
  } > "$INSTALL_DIR/config.yaml"

  log_success "Generated config.yaml"
  return 0
}

generate_dashboard_env() {
  log_info "Generating dashboard.env..."

  cat > "$INSTALL_DIR/dashboard.env" <<EOF
# Endpoints
NETBIRD_MGMT_API_ENDPOINT=https://${DOMAIN}
NETBIRD_MGMT_GRPC_API_ENDPOINT=https://${DOMAIN}
# OIDC - using embedded IdP
AUTH_AUDIENCE=netbird-dashboard
AUTH_CLIENT_ID=netbird-dashboard
AUTH_CLIENT_SECRET=
AUTH_AUTHORITY=https://${DOMAIN}/oauth2
USE_AUTH0=false
AUTH_SUPPORTED_SCOPES=openid profile email groups
AUTH_REDIRECT_URI=/nb-auth
AUTH_SILENT_REDIRECT_URI=/nb-silent-auth
# SSL
NGINX_SSL_PORT=443
# Letsencrypt
LETSENCRYPT_DOMAIN=none
EOF

  log_success "Generated dashboard.env"
  return 0
}

generate_docker_compose_traefik() {
  log_info "Generating docker-compose.yml (Traefik)..."

  local acme_email="${LETSENCRYPT_EMAIL:-admin@${DOMAIN}}"

  # Volume config: use old volume if detected
  local volume_config=""
  if [[ -n "$MGMT_VOLUME" ]]; then
    volume_config="  netbird_data:
    external: true
    name: ${MGMT_VOLUME}"
  else
    volume_config="  netbird_data:"
  fi

  cat > "$INSTALL_DIR/docker-compose.yml" <<EOF
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
      - "--certificatesresolvers.letsencrypt.acme.email=${acme_email}"
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
    image: ${DASHBOARD_IMAGE}
    container_name: netbird-dashboard
    restart: unless-stopped
    networks: [netbird]
    env_file:
      - ./dashboard.env
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-dashboard.rule=Host(\`${DOMAIN}\`)
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
    image: ${NETBIRD_SERVER_IMAGE}
    container_name: netbird-server
    restart: unless-stopped
    networks: [netbird]
    ports:
      - '3478:3478/udp'
    volumes:
      - netbird_data:/var/lib/netbird
      - ./config.yaml:/etc/netbird/config.yaml
    command: ["--config", "/etc/netbird/config.yaml"]
    labels:
      - traefik.enable=true
      # gRPC router (needs h2c backend for HTTP/2 cleartext)
      - traefik.http.routers.netbird-grpc.rule=Host(\`${DOMAIN}\`) && (PathPrefix(\`/signalexchange.SignalExchange/\`) || PathPrefix(\`/management.ManagementService/\`))
      - traefik.http.routers.netbird-grpc.entrypoints=websecure
      - traefik.http.routers.netbird-grpc.tls=true
      - traefik.http.routers.netbird-grpc.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-grpc.service=netbird-server-h2c
      - traefik.http.routers.netbird-grpc.priority=100
      # Backend router (relay, WebSocket, API, OAuth2)
      - traefik.http.routers.netbird-backend.rule=Host(\`${DOMAIN}\`) && (PathPrefix(\`/relay\`) || PathPrefix(\`/ws-proxy/\`) || PathPrefix(\`/api\`) || PathPrefix(\`/oauth2\`))
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

volumes:
${volume_config}
  netbird_traefik_letsencrypt:

networks:
  netbird:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
          gateway: 172.30.0.1
EOF

  log_success "Generated docker-compose.yml"
  return 0
}

generate_docker_compose_exposed_ports() {
  log_info "Generating docker-compose.yml (exposed ports for custom proxy)..."

  # Volume config: use old volume if detected
  local volume_config=""
  if [[ -n "$MGMT_VOLUME" ]]; then
    volume_config="  netbird_data:
    external: true
    name: ${MGMT_VOLUME}"
  else
    volume_config="  netbird_data:"
  fi

  cat > "$INSTALL_DIR/docker-compose.yml" <<EOF
services:
  # UI dashboard
  dashboard:
    image: ${DASHBOARD_IMAGE}
    container_name: netbird-dashboard
    restart: unless-stopped
    networks: [netbird]
    ports:
      - '127.0.0.1:8080:80'
    env_file:
      - ./dashboard.env
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Combined server (Management + Signal + Relay + STUN)
  netbird-server:
    image: ${NETBIRD_SERVER_IMAGE}
    container_name: netbird-server
    restart: unless-stopped
    networks: [netbird]
    ports:
      - '127.0.0.1:8081:80'
      - '3478:3478/udp'
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
${volume_config}

networks:
  netbird:
EOF

  log_success "Generated docker-compose.yml"
  return 0
}

generate_docker_compose() {
  if [[ "$PROXY_TYPE" == "$PROXY_TYPE_CADDY" ]]; then
    generate_docker_compose_traefik
  else
    generate_docker_compose_exposed_ports
  fi
  return 0
}

############################################
# Phase 4: Apply Migration
############################################

stop_old_services() {
  log_info "Stopping old containers..."

  # Try to find old compose file location
  local old_compose_dir="$INSTALL_DIR"
  if [[ -f "$INSTALL_DIR/artifacts/docker-compose.yml" && ! -f "$INSTALL_DIR/docker-compose.yml" ]]; then
    old_compose_dir="$INSTALL_DIR/artifacts"
  fi

  (cd "$old_compose_dir" && $DOCKER_COMPOSE_CMD down 2>/dev/null) || true

  log_success "Old containers stopped"
  return 0
}

start_new_services() {
  log_info "Starting new containers..."

  (cd "$INSTALL_DIR" && $DOCKER_COMPOSE_CMD up -d)

  log_success "New containers started"
  return 0
}

wait_for_health() {
  log_info "Waiting for services to become healthy..."

  local max_attempts=60
  local attempt=0

  set +e
  echo -n "  Checking"
  while [[ $attempt -lt $max_attempts ]]; do
    # Try OIDC endpoint through reverse proxy
    if curl -sk -f -o /dev/null "https://${DOMAIN}/oauth2/.well-known/openid-configuration" 2>/dev/null; then
      echo " done"
      set -e
      log_success "Services are healthy"
      return 0
    fi

    # Also try health check endpoint directly
    if curl -sk -f -o /dev/null "http://127.0.0.1:9000/" 2>/dev/null; then
      echo " done"
      set -e
      log_success "Services are healthy (via healthcheck)"
      return 0
    fi

    echo -n " ."
    sleep 2
    attempt=$((attempt + 1))

    if [[ $attempt -eq 30 ]]; then
      echo ""
      log_warn "Taking longer than expected. Checking container logs..."
      (cd "$INSTALL_DIR" && $DOCKER_COMPOSE_CMD logs --tail=10 netbird-server 2>/dev/null) || true
      echo -n "  Still checking"
    fi
  done
  echo ""
  set -e

  log_warn "Health check timed out after $((max_attempts * 2)) seconds."
  log_warn "Services may still be starting. Check with: cd $INSTALL_DIR && $DOCKER_COMPOSE_CMD logs"
  return 0
}

############################################
# Phase 5: Verification & Summary
############################################

verify_migration() {
  log_info "Running verification checks..."

  local checks_passed=0
  local checks_total=3

  # Check 1: Container health
  local running
  running=$(cd "$INSTALL_DIR" && $DOCKER_COMPOSE_CMD ps --format '{{.Name}}' 2>/dev/null | wc -l || echo "0")
  if [[ "$running" -ge 2 ]]; then
    log_success "Containers are running ($running services)"
    checks_passed=$((checks_passed + 1))
  else
    log_warn "Expected at least 2 running containers, found $running"
  fi

  # Check 2: OIDC endpoint
  local oidc_status
  oidc_status=$(curl -sk -o /dev/null -w '%{http_code}' "https://${DOMAIN}/oauth2/.well-known/openid-configuration" 2>/dev/null || echo "000")
  if [[ "$oidc_status" == "200" ]]; then
    log_success "OIDC endpoint responding (HTTP $oidc_status)"
    checks_passed=$((checks_passed + 1))
  else
    log_warn "OIDC endpoint returned HTTP $oidc_status (expected 200)"
  fi

  # Check 3: Management API (expect 401 = working but needs auth, not 502 = proxy error)
  local api_status
  api_status=$(curl -sk -o /dev/null -w '%{http_code}' "https://${DOMAIN}/api/accounts" 2>/dev/null || echo "000")
  if [[ "$api_status" == "401" || "$api_status" == "200" || "$api_status" == "403" ]]; then
    log_success "Management API responding (HTTP $api_status)"
    checks_passed=$((checks_passed + 1))
  else
    log_warn "Management API returned HTTP $api_status (expected 401/200/403)"
  fi

  echo ""
  echo "  Verification: $checks_passed/$checks_total checks passed"
  return 0
}

print_summary() {
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  Migration Complete"
  echo "$MSG_SEPARATOR"
  echo ""

  if [[ "$PROXY_TYPE" == "$PROXY_TYPE_CADDY" ]]; then
    echo "  What was done:"
    echo "    - Old 5-container setup stopped"
    echo "    - New config.yaml generated (combined server config)"
    echo "    - New dashboard.env generated (embedded IdP)"
    echo "    - New docker-compose.yml generated (Traefik + combined server)"
    echo "    - New containers started"
  else
    echo "  What was done:"
    echo "    - New config.yaml generated (combined server config)"
    echo "    - New dashboard.env generated (embedded IdP)"
    echo "    - New docker-compose.yml generated (exposed ports)"
    echo ""
    echo "  What you need to do:"
    echo "    1. Stop old containers:"
    echo "       cd $INSTALL_DIR && $DOCKER_COMPOSE_CMD down"
    echo ""
    echo "    2. Start new containers:"
    echo "       cd $INSTALL_DIR && $DOCKER_COMPOSE_CMD up -d"
    echo ""
    echo "    3. Update your reverse proxy to route:"
    echo "       - /signalexchange.SignalExchange/*  -> 127.0.0.1:8081 (gRPC/h2c)"
    echo "       - /management.ManagementService/*   -> 127.0.0.1:8081 (gRPC/h2c)"
    echo "       - /relay*, /ws-proxy/*              -> 127.0.0.1:8081 (WebSocket)"
    echo "       - /api/*, /oauth2/*                 -> 127.0.0.1:8081 (HTTP)"
    echo "       - /*                                -> 127.0.0.1:8080 (dashboard)"
  fi

  echo ""
  echo "  Backup location: $BACKUP_DIR"
  echo "  Rollback command: bash $BACKUP_DIR/rollback.sh"
  echo ""
  echo "  IMPORTANT:"
  echo "    - Existing peers, routes, and policies are preserved in the database."
  echo "    - The embedded IdP data is preserved in the management volume."
  echo "    - Clients should reconnect automatically; if not: netbird down && netbird up"
  echo ""
  echo "  Next steps:"
  echo "    - Access the dashboard: https://$DOMAIN"
  echo "    - Re-authenticate all clients: netbird down && netbird up"
  echo "    - Check logs: cd $INSTALL_DIR && $DOCKER_COMPOSE_CMD logs -f"
  echo ""
  return 0
}

############################################
# Main
############################################

main() {
  # Parse arguments
  while [[ $# -gt 0 ]]; do
    local arg="$1"
    case "$arg" in
      --install-dir)
        local dir_value="$2"
        INSTALL_DIR="$dir_value"
        shift 2
        ;;
      --non-interactive)
        NON_INTERACTIVE=true
        shift
        ;;
      --help|-h)
        echo "Usage: $0 [--install-dir /path/to/netbird] [--non-interactive]"
        echo ""
        echo "Migrates a pre-v0.65.0 NetBird deployment to the combined container setup."
        echo ""
        echo "Options:"
        echo "  --install-dir DIR    Path to existing NetBird installation"
        echo "  --non-interactive    Skip confirmation prompts (for automation)"
        echo "  -h, --help           Show this help message"
        exit 0
        ;;
      *)
        log_error "Unknown option: $arg"
        echo "Use --help for usage information."
        exit 1
        ;;
    esac
  done

  print_banner

  # Phase 0: Preflight & Detection
  check_dependencies
  detect_install_dir
  validate_old_setup
  check_already_migrated
  detect_reverse_proxy
  detect_idp_type
  detect_volumes
  detect_domain
  detect_store_config
  extract_config_values
  print_detection_summary

  confirm_action "Proceed with migration?"

  # Phase 1: Backup
  create_backup

  # Phase 4: Apply migration
  if [[ "$PROXY_TYPE" == "$PROXY_TYPE_CADDY" ]]; then
    # Stop old containers BEFORE overwriting docker-compose.yml
    stop_old_services

    # Phase 2 + 3: Generate new configuration files
    generate_config_yaml
    generate_dashboard_env
    generate_docker_compose

    start_new_services
    sleep 3
    wait_for_health

    # Phase 5: Verification
    verify_migration
  else
    # For manual proxy setups, just generate files (don't stop/start)
    generate_config_yaml
    generate_dashboard_env
    generate_docker_compose
  fi

  print_summary
  return 0
}

main "$@"
