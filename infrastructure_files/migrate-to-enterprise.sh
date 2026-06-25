#!/bin/bash

set -e
set -o pipefail

# NetBird — community combined → Enterprise combined migration
#
# Non-destructive migration: produces docker-compose.override.yml (auto-loaded
# by docker compose) and config.yaml.enterprise alongside the operator's
# existing files. Original docker-compose.yml and config.yaml are never
# modified.
#
# Steps (all optional, asked interactively):
#   1. Image swap         — replace community images with enterprise cloud images.
#   2. Postgres migration — add Postgres, migrate SQLite data via migrate-store.
#   3. Traffic flow       — add NATS + flow-enricher + flow-receiver.
#
# To revert:
#   docker compose down
#   rm -f docker-compose.override.yml config.yaml.enterprise
#   # If Postgres migration was done, also restore the SQLite backup printed
#   # at the end of this script's run.
#   docker compose up -d

OVERRIDE_FILE="docker-compose.override.yml"
ENTERPRISE_CONFIG_FILE="config.yaml.enterprise"

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
  echo "docker-compose is not installed or not in PATH." > /dev/stderr
  exit 1
}

check_yq() {
  if ! command -v yq &> /dev/null; then
    cat > /dev/stderr <<'EOF'
yq is required to parse and update YAML safely.

  macOS:   brew install yq
  Linux:   https://github.com/mikefarah/yq/releases (download binary into PATH)
  Debian:  apt-get install yq   (Note: must be the mikefarah Go yq, not the Python wrapper.)

EOF
    exit 1
  fi
  if ! yq --version 2>&1 | grep -q "mikefarah"; then
    echo "yq is present but appears to be the wrong implementation. The mikefarah Go-based yq is required (https://github.com/mikefarah/yq)." > /dev/stderr
    exit 1
  fi
}

check_openssl() {
  if ! command -v openssl &> /dev/null; then
    echo "openssl is not installed or not in PATH." > /dev/stderr
    exit 1
  fi
}

rand_password() {
  openssl rand -hex 32
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

# Gate the migration on explicit acceptance of the NetBird On-Premise EULA.
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
    echo "EULA not accepted. Aborting migration." > /dev/stderr
    exit 1
  fi
  echo "" > /dev/stderr
}

# ---------------------------------------------------------------------------
# Detection — read the operator's existing compose to find service names and
# paths we need to override. Bail loudly if shape isn't recognised.
# ---------------------------------------------------------------------------

detect_combined_service() {
  yq eval '.services | to_entries | map(select(.value.image | test("^netbirdio/netbird-server"))) | .[0].key // ""' "$COMPOSE_FILE"
}

detect_dashboard_service() {
  yq eval '.services | to_entries | map(select(.value.image | test("^netbirdio/dashboard"))) | .[0].key // ""' "$COMPOSE_FILE"
}

detect_config_yaml_host_path() {
  yq eval ".services[\"$COMBINED_SERVICE\"].volumes[] | select(. | test(\":/etc/netbird/config.yaml\")) | sub(\":/etc/netbird/config.yaml.*\"; \"\") // \"\"" "$COMPOSE_FILE" | head -1
}

detect_data_volume() {
  yq eval ".services[\"$COMBINED_SERVICE\"].volumes[] | select(. | test(\":/var/lib/netbird\")) | sub(\":/var/lib/netbird.*\"; \"\") // \"\"" "$COMPOSE_FILE" | head -1
}

detect_exposed_address() {
  yq eval '.server.exposedAddress // ""' "$CONFIG_YAML_HOST"
}

detect_compose_network() {
  local tag
  tag=$(yq eval ".services[\"$COMBINED_SERVICE\"].networks | tag" "$COMPOSE_FILE" 2>/dev/null)
  case "$tag" in
    "!!seq")
      yq eval ".services[\"$COMBINED_SERVICE\"].networks[0]" "$COMPOSE_FILE"
      ;;
    "!!map")
      yq eval ".services[\"$COMBINED_SERVICE\"].networks | keys | .[0]" "$COMPOSE_FILE"
      ;;
    *)
      echo "default"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

# Build docker-compose.override.yml from the steps the operator selected.
# Service names match what we detected on the operator's side.
render_override() {
  cat <<EOF
# Generated by migrate-to-enterprise.sh. Mode 644.
# Merged with docker-compose.yml automatically by Docker Compose.
# Remove this file (and config.yaml.enterprise if present) to revert.

services:
  ${DASHBOARD_SERVICE}:
    image: \${NETBIRD_DASHBOARD_IMAGE:-ghcr.io/netbirdio/dashboard-cloud:latest}

  ${COMBINED_SERVICE}:
    image: \${NETBIRD_SERVER_IMAGE:-ghcr.io/netbirdio/netbird-server-cloud:latest}
    environment:
      NB_LICENSE_KEY: \${NB_LICENSE_KEY}
      NETBIRD_LICENSE_SERVER_BASE_URL: \${NETBIRD_LICENSE_SERVER_BASE_URL}
EOF

  if [[ "$MIGRATE_POSTGRES" == "yes" ]]; then
    cat <<EOF
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./${ENTERPRISE_CONFIG_FILE}:/etc/netbird/config.yaml.enterprise:ro
    command: ["--config", "/etc/netbird/config.yaml.enterprise"]

  postgres:
    image: postgres:17
    container_name: netbird-postgres
    restart: unless-stopped
    networks: [${COMPOSE_NETWORK}]
    environment:
      POSTGRES_USER: netbird
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
      POSTGRES_DB: netbird
    volumes:
      - netbird_postgres:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U netbird -d netbird"]
      interval: 5s
      timeout: 5s
      retries: 20
EOF
  fi

  if [[ "$ENABLE_FLOW" == "yes" ]]; then
    cat <<EOF

  nats:
    image: nats:2
    container_name: netbird-nats
    restart: unless-stopped
    networks: [${COMPOSE_NETWORK}]
    command: ["-m", "8222", "--jetstream", "--store_dir", "/data"]
    volumes:
      - netbird_nats_data:/data

  flow-enricher:
    image: ghcr.io/netbirdio/flow-enricher-cloud:latest
    container_name: netbird-flow-enricher
    restart: unless-stopped
    networks: [${COMPOSE_NETWORK}]
    depends_on:
      postgres:
        condition: service_healthy
      nats:
        condition: service_started
    environment:
      NB_LICENSE_KEY: \${NB_LICENSE_KEY}
      NETBIRD_LICENSE_SERVER_BASE_URL: \${NETBIRD_LICENSE_SERVER_BASE_URL}
      NB_DATADIR: /var/lib/netbird
      NB_MANAGEMENT_STORE_ENGINE: postgres
      NB_MANAGEMENT_POSTGRES_DSN: "host=postgres user=netbird password=\${POSTGRES_PASSWORD} dbname=netbird port=5432 sslmode=disable"
      NB_STORE_ENGINE_POSTGRES_DSN: "host=postgres user=netbird password=\${POSTGRES_PASSWORD} dbname=netbird port=5432 sslmode=disable"
      NB_TRAFFIC_EVENT_STORE_ENGINE: postgres
      NB_TRAFFIC_EVENT_POSTGRES_DSN: "host=postgres user=netbird password=\${POSTGRES_PASSWORD} dbname=netbird port=5432 sslmode=disable"
      NB_MANAGEMENT_STORE_KEY: \${NETBIRD_ENCRYPTION_KEY}
      NB_FLOW_ADAPTER_TYPE: nats
      NB_FLOW_NATS_ENDPOINTS: nats://nats:4222
      NB_FLOW_NATS_STREAM: traffic-events
      NB_METRICS_PORT: 9091
      NB_PERSISTENCE_RETENTION_PERIOD: 168h

  flow-receiver:
    image: ghcr.io/netbirdio/flow-receiver-cloud:latest
    container_name: netbird-flow-receiver
    restart: unless-stopped
    networks: [${COMPOSE_NETWORK}]
    depends_on:
      nats:
        condition: service_started
    environment:
      NB_LICENSE_KEY: \${NB_LICENSE_KEY}
      NETBIRD_LICENSE_SERVER_BASE_URL: \${NETBIRD_LICENSE_SERVER_BASE_URL}
      NB_FLOW_LISTEN_PORT: 80
      NB_FLOW_ADAPTER_TYPE: nats
      NB_FLOW_NATS_ENDPOINTS: nats://nats:4222
      NB_FLOW_NATS_STREAM: traffic-events
      NB_FLOW_AUTH_SECRET: \${NB_FLOW_AUTH_SECRET}
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-flow.rule=Host(\`${NETBIRD_HOSTNAME}\`) && PathPrefix(\`/flow.FlowService/\`)
      - traefik.http.routers.netbird-flow.entrypoints=websecure
      - traefik.http.routers.netbird-flow.tls=true
      - traefik.http.routers.netbird-flow.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-flow.service=netbird-flow-h2c
      - traefik.http.routers.netbird-flow.priority=100
      - traefik.http.services.netbird-flow-h2c.loadbalancer.server.port=80
      - traefik.http.services.netbird-flow-h2c.loadbalancer.server.scheme=h2c
EOF
  fi

  # Volume declarations for anything new the override introduced
  local has_volumes="no"
  if [[ "$MIGRATE_POSTGRES" == "yes" ]] || [[ "$ENABLE_FLOW" == "yes" ]]; then
    has_volumes="yes"
  fi

  if [[ "$has_volumes" == "yes" ]]; then
    cat <<EOF

volumes:
EOF
    if [[ "$MIGRATE_POSTGRES" == "yes" ]]; then
      echo "  netbird_postgres:"
    fi
    if [[ "$ENABLE_FLOW" == "yes" ]]; then
      echo "  netbird_nats_data:"
    fi
  fi
}

# Build config.yaml.enterprise by yq-editing the operator's existing
# config.yaml. We don't touch the original file.
render_enterprise_config() {
  local pg_dsn="host=postgres user=netbird password=${POSTGRES_PASSWORD} dbname=netbird port=5432 sslmode=disable"

  yq eval "
    .server.store.engine = \"postgres\" |
    .server.store.dsn = \"$pg_dsn\" |
    .server.activityStore.engine = \"postgres\" |
    .server.activityStore.dsn = \"$pg_dsn\" |
    .server.authStore.engine = \"postgres\" |
    .server.authStore.dsn = \"$pg_dsn\"
  " "$CONFIG_YAML_HOST" > "$ENTERPRISE_CONFIG_FILE"

  if [[ "$ENABLE_FLOW" == "yes" ]]; then
    local flow_addr="${NETBIRD_DOMAIN}"
    yq eval -i "
      .server.trafficFlow.enabled = true |
      .server.trafficFlow.address = \"$flow_addr\" |
      .server.trafficFlow.interval = \"60s\"
    " "$ENTERPRISE_CONFIG_FILE"
  fi
}

# ---------------------------------------------------------------------------
# Execution steps
# ---------------------------------------------------------------------------

resolve_data_volume() {
  local short="$1"
  local actual
  # Resolve project-prefixed volume name from Docker Compose config first.
  actual=$($DOCKER_COMPOSE_COMMAND config 2>/dev/null | yq eval ".volumes.\"$short\".name" - 2>/dev/null)
  if [[ -n "$actual" && "$actual" != "null" ]]; then
    echo "$actual"
    return
  fi
  # Relative bind mount: docker-compose resolves it against the compose
  # file's directory, but `docker run -v` resolves it against the current
  # working directory. Normalize to an absolute path so both interpretations
  # agree (and the printed revert command works from any CWD).
  if [[ "$short" == ./* || "$short" == ../* ]]; then
    local compose_dir
    compose_dir="$(cd "$(dirname "$COMPOSE_FILE")" && pwd)"
    (
      cd "$compose_dir"
      cd "$(dirname "$short")"
      printf '%s/%s\n' "$(pwd)" "$(basename "$short")"
    )
    return
  fi
  # Not a named volume (e.g. an absolute bind-mount path) — use it as-is.
  echo "$short"
}

backup_sqlite() {
  BACKUP_DIR="$(pwd)/backups/sqlite-pre-enterprise-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$BACKUP_DIR"
  local data_volume_actual
  data_volume_actual=$(resolve_data_volume "$DATA_VOLUME")
  echo "Backing up SQLite store from volume '$data_volume_actual' to $BACKUP_DIR ..."
  docker run --rm \
    -v "${data_volume_actual}:/var/lib/netbird:ro" \
    -v "${BACKUP_DIR}:/backup" \
    busybox \
    sh -c 'cp -a /var/lib/netbird/. /backup/ 2>/dev/null || true'
  local copied
  copied=$(find "$BACKUP_DIR" -mindepth 1 | head -1)
  if [[ -z "$copied" ]]; then
    echo "  ⚠ Backup directory is empty — the volume '$data_volume_actual' didn't contain data. Aborting." > /dev/stderr
    exit 1
  fi
  echo "  done"
}

run_migrate_store() {
  echo "Running migrate-store (SQLite → Postgres) ..."
  $DOCKER_COMPOSE_COMMAND run --rm "$COMBINED_SERVICE" migrate-store --config /etc/netbird/config.yaml.enterprise --verify
  echo "  done"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

init_migration() {
  DOCKER_COMPOSE_COMMAND=$(check_docker_compose)
  check_yq
  check_openssl

  require_eula_acceptance
  NETBIRD_EULA_ACCEPTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"

  if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "$COMPOSE_FILE not found in $(pwd)." > /dev/stderr
    exit 1
  fi
  if [[ -f "$OVERRIDE_FILE" ]] || [[ -f "$ENTERPRISE_CONFIG_FILE" ]]; then
    echo "Migration artifacts already exist in $(pwd):"
    [[ -f "$OVERRIDE_FILE" ]] && echo "  $OVERRIDE_FILE"
    [[ -f "$ENTERPRISE_CONFIG_FILE" ]] && echo "  $ENTERPRISE_CONFIG_FILE"
    echo ""
    echo "Either you've already migrated, or a previous run was interrupted."
    echo "To re-run cleanly: rm -f $OVERRIDE_FILE $ENTERPRISE_CONFIG_FILE"
    exit 1
  fi

  COMBINED_SERVICE=$(detect_combined_service)
  DASHBOARD_SERVICE=$(detect_dashboard_service)
  CONFIG_YAML_HOST=$(detect_config_yaml_host_path)
  DATA_VOLUME=$(detect_data_volume)
  COMPOSE_NETWORK=$(detect_compose_network)

  if [[ -z "$COMBINED_SERVICE" ]]; then
    echo "Could not find a service running netbirdio/netbird-server* in $COMPOSE_FILE." > /dev/stderr
    echo "This script targets the community combined-server deployment." > /dev/stderr
    exit 1
  fi
  if [[ -z "$DASHBOARD_SERVICE" ]]; then
    echo "Could not find a service running netbirdio/dashboard* in $COMPOSE_FILE." > /dev/stderr
    exit 1
  fi
  if [[ -z "$CONFIG_YAML_HOST" ]]; then
    echo "Could not find a config.yaml mount on $COMBINED_SERVICE (expected to bind-mount to /etc/netbird/config.yaml)." > /dev/stderr
    exit 1
  fi
  if [[ ! -f "$CONFIG_YAML_HOST" ]]; then
    echo "config.yaml host file not found at $CONFIG_YAML_HOST." > /dev/stderr
    exit 1
  fi
  if [[ -z "$DATA_VOLUME" ]]; then
    echo "Could not find a volume mounted at /var/lib/netbird on $COMBINED_SERVICE." > /dev/stderr
    exit 1
  fi

  echo "Detected existing deployment:"
  echo "  Combined service: $COMBINED_SERVICE"
  echo "  Dashboard:        $DASHBOARD_SERVICE"
  echo "  config.yaml:      $CONFIG_YAML_HOST"
  echo "  Data volume:      $DATA_VOLUME"
  echo "  Network:          $COMPOSE_NETWORK"
  echo ""

  local proceed
  proceed=$(read_yes_no "Proceed with migration?" "y")
  if [[ "$proceed" != "yes" ]]; then
    echo "Aborted."
    exit 0
  fi

  # Step 1 — always (this is the point of the script)
  MIGRATE_IMAGES="yes"
  echo ""
  echo "Step 1: Image swap (community → Enterprise). License key required."
  NB_LICENSE_KEY=$(read_secret "  License key")
  GHCR_USERNAME="netbirdExtAccess1"
  GHCR_TOKEN=$(read_secret "  GHCR token (input hidden)")

  # Step 2 — optional
  echo ""
  MIGRATE_POSTGRES=$(read_yes_no "Step 2: Migrate storage from SQLite to Postgres? (recommended)" "n")
  if [[ "$MIGRATE_POSTGRES" == "yes" ]]; then
    echo ""
    echo "  ⚠  Data will be migrated from SQLite to Postgres. The SQLite store"
    echo "     will be backed up automatically. To fully revert later, restore"
    echo "     that backup and delete docker-compose.override.yml +"
    echo "     config.yaml.enterprise."
    local confirm
    confirm=$(read_yes_no "  Continue?" "y")
    if [[ "$confirm" != "yes" ]]; then
      MIGRATE_POSTGRES="no"
      echo "  Skipping Postgres migration."
    else
      POSTGRES_PASSWORD=$(rand_password)
    fi
  fi

  # Step 3 — optional, only if Postgres is on (flow requires Postgres)
  echo ""
  if [[ "$MIGRATE_POSTGRES" == "yes" ]]; then
    ENABLE_FLOW=$(read_yes_no "Step 3: Enable traffic flow? (requires Postgres)" "n")
    if [[ "$ENABLE_FLOW" == "yes" ]]; then
      # Auth secret MUST match server.authSecret from config.yaml
      NB_FLOW_AUTH_SECRET=$(yq eval '.server.authSecret // ""' "$CONFIG_YAML_HOST")
      if [[ -z "$NB_FLOW_AUTH_SECRET" ]] || [[ "$NB_FLOW_AUTH_SECRET" == "null" ]]; then
        echo "Could not read server.authSecret from $CONFIG_YAML_HOST." > /dev/stderr
        echo "Flow receiver auth must match the combined server's authSecret." > /dev/stderr
        exit 1
      fi

      NETBIRD_DOMAIN=$(detect_exposed_address)
      if [[ -z "$NETBIRD_DOMAIN" ]] || [[ "$NETBIRD_DOMAIN" == "null" ]]; then
        NETBIRD_DOMAIN=$(read_required "  Public NetBird URL (e.g. https://netbird.example.com)")
      fi
      # Strip protocol + port to leave just the hostname for the Traefik Host() rule.
      NETBIRD_HOSTNAME=$(echo "$NETBIRD_DOMAIN" | sed -E 's,^https?://,,' | sed 's,:.*,,' | sed 's,/.*,,')

      # We need the encryption key from the existing config.yaml for the enricher
      NETBIRD_ENCRYPTION_KEY=$(yq eval '.server.store.encryptionKey // ""' "$CONFIG_YAML_HOST")
      if [[ -z "$NETBIRD_ENCRYPTION_KEY" ]] || [[ "$NETBIRD_ENCRYPTION_KEY" == "null" ]]; then
        echo "Could not read server.store.encryptionKey from $CONFIG_YAML_HOST." > /dev/stderr
        exit 1
      fi
    fi
  else
    ENABLE_FLOW="no"
    echo "Step 3 (traffic flow) skipped — requires Postgres."
  fi
}

apply_changes() {
  echo ""
  echo "Writing $OVERRIDE_FILE ..."
  install -m 644 /dev/null "$OVERRIDE_FILE"
  render_override > "$OVERRIDE_FILE"

  if [[ -z "${NETBIRD_LICENSE_SERVER_BASE_URL:-}" ]]; then
    sed -i.bak '/NETBIRD_LICENSE_SERVER_BASE_URL/d' "$OVERRIDE_FILE" && rm -f "$OVERRIDE_FILE.bak"
  fi

  if [[ "$MIGRATE_POSTGRES" == "yes" ]]; then
    echo "Writing $ENTERPRISE_CONFIG_FILE ..."
    install -m 600 /dev/null "$ENTERPRISE_CONFIG_FILE"
    render_enterprise_config
  fi

  # Persist secrets that the override file references via env interpolation.
  # We write them to a .env file in the current directory; docker compose
  # picks it up automatically.
  echo "Writing .env additions (mode 600) ..."
  local ENV_FILE=".env"
  touch "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  {
    echo ""
    echo "# Added by migrate-to-enterprise.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# NetBird On-Premise EULA accepted at install time"
    echo "NETBIRD_EULA_ACCEPTED=yes"
    echo "NETBIRD_EULA_ACCEPTED_AT=${NETBIRD_EULA_ACCEPTED_AT}"
    echo "NETBIRD_EULA_URL=${NETBIRD_EULA_URL}"
    echo "NB_LICENSE_KEY=${NB_LICENSE_KEY}"
    if [[ -n "${NETBIRD_LICENSE_SERVER_BASE_URL:-}" ]]; then
      echo "NETBIRD_LICENSE_SERVER_BASE_URL=${NETBIRD_LICENSE_SERVER_BASE_URL}"
    fi
    if [[ "$MIGRATE_POSTGRES" == "yes" ]]; then
      echo "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}"
    fi
    if [[ "$ENABLE_FLOW" == "yes" ]]; then
      echo "NB_FLOW_AUTH_SECRET=${NB_FLOW_AUTH_SECRET}"
      echo "NETBIRD_ENCRYPTION_KEY=${NETBIRD_ENCRYPTION_KEY}"
    fi
  } >> "$ENV_FILE"

  echo ""
  echo "Logging in to ghcr.io ..."
  printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USERNAME" --password-stdin
  unset GHCR_TOKEN

  echo ""
  echo "Pulling enterprise images ..."
  $DOCKER_COMPOSE_COMMAND pull

  if [[ "$MIGRATE_POSTGRES" == "yes" ]]; then
    echo ""
    echo "Stopping existing services (volumes preserved) ..."
    $DOCKER_COMPOSE_COMMAND down

    backup_sqlite

    echo ""
    echo "Starting Postgres ..."
    $DOCKER_COMPOSE_COMMAND up -d postgres

    # Wait for healthy
    local counter=0
    echo -n "Waiting for Postgres to become ready"
    while ! $DOCKER_COMPOSE_COMMAND exec -T postgres pg_isready -U netbird -d netbird &> /dev/null; do
      echo -n " ."
      sleep 2
      counter=$((counter + 1))
      if [[ $counter -ge 60 ]]; then
        echo ""
        echo "Postgres did not become ready in 120s. Recent logs:"
        $DOCKER_COMPOSE_COMMAND logs --tail=20 postgres
        exit 1
      fi
    done
    echo " done"

    run_migrate_store
  fi

  echo ""
  echo "Bringing up all services ..."
  $DOCKER_COMPOSE_COMMAND up -d

  echo ""
  echo "Migration complete."
}

print_summary() {
  echo ""
  echo "──────────────────────────────────────────────────────────────────────"
  echo " Summary"
  echo "──────────────────────────────────────────────────────────────────────"
  echo "  Images:           swapped to enterprise"
  [[ "$MIGRATE_POSTGRES" == "yes" ]] && echo "  Storage:          Postgres (data migrated from SQLite)"
  [[ "$MIGRATE_POSTGRES" != "yes" ]] && echo "  Storage:          SQLite (unchanged)"
  [[ "$ENABLE_FLOW" == "yes" ]] && echo "  Traffic flow:     enabled"
  [[ "$ENABLE_FLOW" != "yes" ]] && echo "  Traffic flow:     disabled"
  echo ""
  echo "  Generated files (next to your docker-compose.yml):"
  echo "    $OVERRIDE_FILE"
  [[ "$MIGRATE_POSTGRES" == "yes" ]] && echo "    $ENTERPRISE_CONFIG_FILE"
  echo "    .env  (license key + secrets, mode 600)"
  [[ "$MIGRATE_POSTGRES" == "yes" ]] && echo "    backups/sqlite-pre-enterprise-*/  (SQLite backup)"
  echo ""
  echo " Tail logs:"
  echo "   $DOCKER_COMPOSE_COMMAND logs -f $COMBINED_SERVICE"
  echo ""
  echo "──────────────────────────────────────────────────────────────────────"
  echo " To revert"
  echo "──────────────────────────────────────────────────────────────────────"
  echo "  $DOCKER_COMPOSE_COMMAND down"
  if [[ "$MIGRATE_POSTGRES" == "yes" ]]; then
    # Resolve project-prefixed volume names now (before override is removed).
    local pg_volume data_volume_actual
    pg_volume=$(resolve_data_volume "netbird_postgres")
    data_volume_actual=$(resolve_data_volume "$DATA_VOLUME")
    echo "  # Remove the Postgres volume FIRST, before deleting the override file:"
    echo "  docker volume rm $pg_volume"
    echo "  # Restore SQLite from the backup created during this run:"
    echo "  docker run --rm -v ${data_volume_actual}:/var/lib/netbird -v ${BACKUP_DIR}:/backup busybox sh -c 'cp -a /backup/. /var/lib/netbird/'"
  fi
  echo "  rm -f $OVERRIDE_FILE $ENTERPRISE_CONFIG_FILE"
  echo "  # Remove migrate-to-enterprise.sh additions from .env (search for the timestamp marker)"
  echo "  $DOCKER_COMPOSE_COMMAND up -d"
  echo "──────────────────────────────────────────────────────────────────────"
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

init_migration
apply_changes
print_summary
