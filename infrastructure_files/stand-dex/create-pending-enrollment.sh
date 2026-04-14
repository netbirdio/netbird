#!/usr/bin/env bash
# create-pending-enrollment.sh
#
# Seeds one pending enrollment request against the running dev stand.
# Run this after `make up && make wait` to get a visible pending record
# in the Device Security → Enrollments table.
#
# Usage:
#   ./create-pending-enrollment.sh
#
# Optional environment overrides:
#   GRPC_URL    gRPC endpoint  (default: https://localhost:8443)
#   SETUP_KEY   reusable setup key (auto-detected from management container if unset)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.device-auth.yml"

GRPC_URL="${GRPC_URL:-https://localhost:8443}"
DEV_TOKEN="nbp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd34KlM6"

# ── 1. Verify the stand is running ──────────────────────────────────────────
if ! (cd "${SCRIPT_DIR}" && ${COMPOSE} ps management 2>/dev/null | grep -q "running"); then
  echo "ERROR: management container is not running. Start the stand first:" >&2
  echo "  cd ${SCRIPT_DIR} && make up && make wait" >&2
  exit 1
fi

# ── 2. Obtain setup key ──────────────────────────────────────────────────────
if [ -z "${SETUP_KEY:-}" ]; then
  SETUP_KEY=$(
    cd "${SCRIPT_DIR}" && \
    ${COMPOSE} exec -T management \
      sh -c 'grep NETBIRD_SETUP_KEY /var/lib/netbird/init.env 2>/dev/null | cut -d= -f2' \
    2>/dev/null || true
  )
fi

if [ -z "${SETUP_KEY}" ]; then
  echo "ERROR: Could not retrieve setup key from management container." >&2
  echo "  Provide it manually: SETUP_KEY=<key> $0" >&2
  exit 1
fi

echo "Using setup key: ${SETUP_KEY:0:8}..."
echo "gRPC endpoint:   ${GRPC_URL}"
echo ""

# ── 3. Check enrollment mode — warn if not manual ────────────────────────────
ENROLL_MODE=$(
  curl -sk -H "Authorization: Bearer ${DEV_TOKEN}" \
    https://localhost/api/device-auth/settings 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('enrollment_mode',''))" \
  2>/dev/null || true
)

if [ "${ENROLL_MODE}" != "manual" ] && [ "${ENROLL_MODE}" != "both" ]; then
  echo "WARNING: enrollment_mode is '${ENROLL_MODE:-unknown}'."
  echo "  For a pending enrollment to appear, set it to 'manual' or 'both':"
  echo "  curl -sk -X PUT https://localhost/api/device-auth/settings \\"
  echo "    -H 'Authorization: Bearer ${DEV_TOKEN}' \\"
  echo "    -H 'Content-Type: application/json' \\"
  echo "    -d '{\"enrollment_mode\":\"manual\"}'"
  echo ""
fi

# ── 4. Submit enrollment via enroll-demo ─────────────────────────────────────
# Capture stdout (JSON) to a temp file; let stderr (progress logs) flow to terminal.
echo "Submitting enrollment..."
TMP_JSON="$(mktemp)"
trap 'rm -f "${TMP_JSON}"' EXIT

cd "${REPO_ROOT}"
go run ./management/cmd/enroll-demo \
  -management "${GRPC_URL}" \
  -tls \
  -insecure \
  -setup-key "${SETUP_KEY}" \
  > "${TMP_JSON}"

ENROLLMENT_ID=$(python3 -c \
  "import sys,json; d=json.load(open(sys.argv[1])); print(d.get('enrollment_id',''))" \
  "${TMP_JSON}" 2>/dev/null || true)

STATUS=$(python3 -c \
  "import sys,json; d=json.load(open(sys.argv[1])); print(d.get('status',''))" \
  "${TMP_JSON}" 2>/dev/null || true)

echo ""
echo "Response:"
cat "${TMP_JSON}"
echo ""

if [ -n "${ENROLLMENT_ID}" ]; then
  echo "✓ Enrollment created: ${ENROLLMENT_ID} (status: ${STATUS})"
  echo ""
  echo "  View in dashboard: https://localhost/device-security"
  echo ""
  if [ "${STATUS}" = "pending" ]; then
    echo "  Approve via API:"
    echo "    curl -sk -X POST https://localhost/api/device-auth/enrollments/${ENROLLMENT_ID}/approve \\"
    echo "      -H 'Authorization: Bearer ${DEV_TOKEN}'"
    echo ""
    echo "  Reject via API:"
    echo "    curl -sk -X POST https://localhost/api/device-auth/enrollments/${ENROLLMENT_ID}/reject \\"
    echo "      -H 'Authorization: Bearer ${DEV_TOKEN}'"
  fi
else
  echo "Enrollment submitted (check JSON above for enrollment_id)."
fi
