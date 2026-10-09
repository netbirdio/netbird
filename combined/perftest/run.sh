#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/perftest"

# Defaults
MANAGEMENT_URL="${MANAGEMENT_URL:-}"
SETUP_KEY="${SETUP_KEY:-}"
PEERS="${PEERS:-5}"
DURATION="${DURATION:-30s}"
PACKET_SIZE="${PACKET_SIZE:-512}"
FORCE_RELAY="${FORCE_RELAY:-false}"
LOG_LEVEL="${LOG_LEVEL:-panic}"

usage() {
    cat <<EOF
Usage: MANAGEMENT_URL=... SETUP_KEY=... $0 [options]

Environment variables (or flags):
  MANAGEMENT_URL   Management server URL (required)
  SETUP_KEY        Reusable setup key (required). Use ephemeral.
  PEERS            Number of peers (default: 5)
  DURATION         Traffic test duration (default: 30s)
  PACKET_SIZE      UDP packet size in bytes (default: 512)
  FORCE_RELAY      Force relay mode (default: false)
  LOG_LEVEL        Client log level (default: panic)

All extra arguments are passed directly to the binary.
EOF
    exit 1
}

if [[ -z "$MANAGEMENT_URL" || -z "$SETUP_KEY" ]]; then
    echo "Error: MANAGEMENT_URL and SETUP_KEY must be set"
    echo
    usage
fi

# Build
echo "Building perftest..."
cd "$SCRIPT_DIR"
go build -o "$BINARY" .
echo "Build OK: $BINARY"
echo

# Run
ARGS=(
    --management-url "$MANAGEMENT_URL"
    --setup-key "$SETUP_KEY"
    --peers "$PEERS"
    --duration "$DURATION"
    --packet-size "$PACKET_SIZE"
    --log-level "$LOG_LEVEL"
)

if [[ "$FORCE_RELAY" == "true" ]]; then
    ARGS+=(--force-relay)
fi

exec "$BINARY" "${ARGS[@]}" "$@"
