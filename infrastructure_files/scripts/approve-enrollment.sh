#!/usr/bin/env bash
# approve-enrollment.sh — Approve a pending device enrollment request via the Management API.
#
# Usage:
#   # List pending enrollments and print instructions:
#   NETBIRD_TOKEN=<bearer-token> bash approve-enrollment.sh
#
#   # Approve a specific enrollment directly:
#   NETBIRD_TOKEN=<bearer-token> ENROLLMENT_ID=<id> bash approve-enrollment.sh
#
# Environment variables:
#   MGMT_URL        Management API base URL (default: http://localhost:80)
#   NETBIRD_TOKEN   Bearer token for API authentication (required)
#   ENROLLMENT_ID   Enrollment request ID to approve (optional; lists pending if unset)

set -euo pipefail

MGMT_URL="${MGMT_URL:-http://localhost:80}"

# Validate required token
if [[ -z "${NETBIRD_TOKEN:-}" ]]; then
  echo "[ERROR] NETBIRD_TOKEN is required."
  echo "        Set it before running:"
  echo "          export NETBIRD_TOKEN=<your-bearer-token>"
  exit 1
fi

echo "[INFO] Management URL: $MGMT_URL"
echo ""

# --- 1. List pending enrollments ---
echo "[INFO] Fetching pending enrollment requests..."
PENDING_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
  "$MGMT_URL/api/device-auth/enrollments?status=pending" \
  -H "Authorization: Bearer $NETBIRD_TOKEN")

PENDING_BODY=$(echo "$PENDING_RESPONSE" | head -n -1)
PENDING_CODE=$(echo "$PENDING_RESPONSE" | tail -n 1)

if [[ "$PENDING_CODE" -ge 200 && "$PENDING_CODE" -lt 300 ]]; then
  echo "[OK] Pending enrollments (HTTP $PENDING_CODE):"
  echo "$PENDING_BODY"
else
  echo "[ERROR] Failed to fetch pending enrollments (HTTP $PENDING_CODE):"
  echo "$PENDING_BODY"
  exit 1
fi

echo ""

# --- 2. Approve or print instructions ---
if [[ -z "${ENROLLMENT_ID:-}" ]]; then
  echo "[INFO] To approve an enrollment, set ENROLLMENT_ID and re-run:"
  echo "         NETBIRD_TOKEN=\$NETBIRD_TOKEN ENROLLMENT_ID=<id> bash $0"
  exit 0
fi

if [[ ! "$ENROLLMENT_ID" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "[ERROR] ENROLLMENT_ID contains invalid characters: $ENROLLMENT_ID" >&2
  exit 1
fi

echo "[INFO] Approving enrollment ID: $ENROLLMENT_ID"
APPROVE_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  "$MGMT_URL/api/device-auth/enrollments/$ENROLLMENT_ID/approve" \
  -H "Authorization: Bearer $NETBIRD_TOKEN" \
  -H "Content-Type: application/json")

APPROVE_BODY=$(echo "$APPROVE_RESPONSE" | head -n -1)
APPROVE_CODE=$(echo "$APPROVE_RESPONSE" | tail -n 1)

if [[ "$APPROVE_CODE" -ge 200 && "$APPROVE_CODE" -lt 300 ]]; then
  echo "[OK] Enrollment approved (HTTP $APPROVE_CODE)."
  echo "     Issued certificate info:"
  echo "$APPROVE_BODY"
else
  echo "[ERROR] Failed to approve enrollment (HTTP $APPROVE_CODE):"
  echo "$APPROVE_BODY"
  exit 1
fi
