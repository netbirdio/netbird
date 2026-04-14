#!/usr/bin/env bash
# up-device-auth-stand.sh — Bring up a local NetBird test stand with device-auth enabled.
#
# This script:
#   1. Checks that required ports are free
#   2. Builds the management server Docker image from the feature/tpm-cert-auth branch
#   3. Spins up the full NetBird + Zitadel stack (using getting-started-with-zitadel.sh)
#   4. Overrides the management service with our dev image
#   5. Optionally includes our custom dashboard image
#
# Prerequisites:
#   - Docker + Docker Compose installed
#   - jq installed (brew install jq)
#   - Git clone of https://github.com/netbirdio/netbird on branch feature/tpm-cert-auth
#   - Run this script from the repo root:
#       bash infrastructure_files/scripts/up-device-auth-stand.sh
#
# Flags:
#   --rebuild   Force rebuild of the management image even if it already exists
#
# After startup:
#   - Dashboard:    http://localhost (Zitadel-managed auth)
#   - Management:   http://localhost/api
#   - Zitadel:      http://localhost:8080
#
# Dashboard dev mode (optional, to test our React changes):
#   - cd /path/to/netbird-dashboard
#   - Copy src/config/local.example.ts → src/config/local.ts  (edit domain/client_id)
#   - npm run dev   → opens http://localhost:3000

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INFRA_DIR="$REPO_ROOT/infrastructure_files"
STAND_DIR="$INFRA_DIR/stand"
MANAGEMENT_DEV_IMAGE="netbird/management:tpm-dev"
DASHBOARD_DEV_IMAGE="netbird/dashboard:tpm-dev"

FORCE_REBUILD=false

for arg in "$@"; do
  case "$arg" in
    --rebuild) FORCE_REBUILD=true ;;
    *) echo "[WARN] Unknown argument: $arg" ;;
  esac
done

# ─── Step 0: Check ports ──────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Step 0: Checking required ports                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

if lsof -iTCP:80 -sTCP:LISTEN -t &>/dev/null 2>&1; then
  echo "[ERROR] Port 80 is already in use. Please stop other services first."
  echo "        Check what is running: docker ps"
  echo "        Or stop all containers: docker compose -f $STAND_DIR/docker-compose.yml down"
  exit 1
fi

echo "[OK] Port 80 is free."

# ─── Step 1: Build management dev image ──────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Step 1: Building management server image from feature branch ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

if [[ "$FORCE_REBUILD" == "true" ]] && docker image inspect "$MANAGEMENT_DEV_IMAGE" &>/dev/null; then
  echo "[INFO] --rebuild flag set. Removing existing image: $MANAGEMENT_DEV_IMAGE"
  docker rmi "$MANAGEMENT_DEV_IMAGE"
fi

if ! docker image inspect "$MANAGEMENT_DEV_IMAGE" &>/dev/null; then
  echo "[INFO] Building $MANAGEMENT_DEV_IMAGE ..."
  docker build -f "$REPO_ROOT/management/Dockerfile.multistage" -t "$MANAGEMENT_DEV_IMAGE" "$REPO_ROOT"
  echo "[OK] Image built: $MANAGEMENT_DEV_IMAGE"
else
  echo "[INFO] Image already exists: $MANAGEMENT_DEV_IMAGE"
  echo "       To rebuild: run this script with --rebuild"
fi

# ─── Step 2: Run getting-started-with-zitadel in stand directory ─────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Step 2: Setting up NetBird + Zitadel stack                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

mkdir -p "$STAND_DIR"
cd "$STAND_DIR"

if [[ -f "$STAND_DIR/docker-compose.yml" ]]; then
  echo "[INFO] docker-compose.yml already exists in $STAND_DIR"
  echo "       Skipping getting-started step (stack already configured)"
else
  echo "[INFO] Running getting-started-with-zitadel.sh ..."
  echo ""
  NETBIRD_DOMAIN=localhost NETBIRD_HTTP_PROTOCOL=http \
    bash "$INFRA_DIR/getting-started-with-zitadel.sh" || true
fi

# ─── Step 3: Override management service with our dev image ──────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Step 3: Injecting dev management image                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Write the device-auth overlay that uses our dev management image
cat > "$STAND_DIR/docker-compose.device-auth.yml" << EOF
# Device-auth overlay: uses locally-built management image.
# Usage: docker compose -f docker-compose.yml -f docker-compose.device-auth.yml up -d
services:
  management:
    image: ${MANAGEMENT_DEV_IMAGE}
EOF

# Build compose file list
COMPOSE_FILES="-f $STAND_DIR/docker-compose.yml -f $STAND_DIR/docker-compose.device-auth.yml"

# Optionally include dashboard overlay if the dev image exists
if docker image inspect "$DASHBOARD_DEV_IMAGE" &>/dev/null; then
  echo "[INFO] Found dashboard dev image: $DASHBOARD_DEV_IMAGE"
  echo "       Including dashboard overlay..."

  cat > "$STAND_DIR/docker-compose.dashboard.yml" << EOFD
# Dashboard overlay: replaces netbirdio/dashboard:latest with locally-built image.
# Build with: docker build -f docker/Dockerfile -t netbird/dashboard:tpm-dev .
# (run from the netbird-dashboard repo root)
services:
  dashboard:
    image: ${DASHBOARD_DEV_IMAGE}
EOFD

  COMPOSE_FILES="$COMPOSE_FILES -f $STAND_DIR/docker-compose.dashboard.yml"
else
  echo "[INFO] No dashboard dev image found ($DASHBOARD_DEV_IMAGE)."
  echo "       Using default dashboard. To use our custom build:"
  echo "         cd /path/to/netbird-dashboard"
  echo "         docker build -f docker/Dockerfile -t $DASHBOARD_DEV_IMAGE ."
  echo "         Then re-run this script."
fi

echo "[INFO] Starting stack with dev overlays..."
docker compose \
  $COMPOSE_FILES \
  up -d --no-deps management

echo "[OK] Management service restarted with $MANAGEMENT_DEV_IMAGE"

# ─── Step 4: Wait for management server ──────────────────────────────────────

echo ""
echo "[INFO] Waiting for management server to be healthy..."
ATTEMPTS=0
MAX_ATTEMPTS=30
until curl -sf http://localhost/api/device-auth/settings &>/dev/null 2>&1 \
    || curl -sf http://localhost/api/peers &>/dev/null 2>&1; do
  ATTEMPTS=$((ATTEMPTS + 1))
  if [[ $ATTEMPTS -ge $MAX_ATTEMPTS ]]; then
    echo "[WARN] Management server did not respond after ${MAX_ATTEMPTS}s"
    echo "       Check logs: docker compose -f $STAND_DIR/docker-compose.yml logs management"
    break
  fi
  echo "  Waiting... ($ATTEMPTS/${MAX_ATTEMPTS})"
  sleep 2
done

# ─── Step 5: Enable device auth ──────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Step 5: Enabling device certificate authentication          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Done ────────────────────────────────────────────────────────────────────

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NetBird device-auth test stand is ready!                    ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
echo "║  Dashboard UI:  http://localhost                             ║"
echo "║  Management:    http://localhost/api                         ║"
echo "║  Zitadel:       http://localhost:8080                        ║"
echo "║                                                              ║"
echo "║  Management image: $MANAGEMENT_DEV_IMAGE                   ║"
echo "║                                                              ║"
echo "║  HOW TO GET A TOKEN:                                         ║"
echo "║  1. Open http://localhost and create an account              ║"
echo "║  2. Go to Account Settings → Personal Access Token           ║"
echo "║  3. Generate a new token and copy it                         ║"
echo "║                                                              ║"
echo "║  HOW TO CONFIGURE DEVICE AUTH:                               ║"
echo "║    NETBIRD_TOKEN=<your-token> MGMT_URL=http://localhost \\    ║"
echo "║      bash infrastructure_files/scripts/setup-device-auth.sh ║"
echo "║                                                              ║"
echo "║  HOW TO VIEW DEVICE SECURITY UI:                             ║"
echo "║    http://localhost/device-security                          ║"
echo "║                                                              ║"
echo "║  Dashboard dev mode (optional, with our React changes):      ║"
echo "║    cd /path/to/netbird-dashboard                             ║"
echo "║    npm install && npm run dev  →  http://localhost:3000      ║"
echo "║                                                              ║"
echo "║  To approve an enrollment:                                   ║"
echo "║    bash infrastructure_files/scripts/approve-enrollment.sh  ║"
echo "║                                                              ║"
echo "║  To stop the stand:                                          ║"
echo "║    docker compose -f $STAND_DIR/docker-compose.yml down     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
