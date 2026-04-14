#!/usr/bin/env bash
# setup-device-auth.sh — Configure device certificate authentication via the Management API.
#
# Run this script after the NetBird stack is up to enable device auth
# with the built-in CA and manual enrollment mode.
#
# Usage:
#   NETBIRD_TOKEN=<bearer-token> bash setup-device-auth.sh
#   NETBIRD_TOKEN=<bearer-token> MGMT_URL=https://my-mgmt-host bash setup-device-auth.sh
#
# Environment variables:
#   MGMT_URL        Management API base URL (default: http://localhost:80)
#   NETBIRD_TOKEN   Bearer token for API authentication (required)

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

# --- 1. Configure device auth settings ---
echo "[INFO] Configuring device auth settings..."
SETTINGS_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "$MGMT_URL/api/device-auth/settings" \
  -H "Authorization: Bearer $NETBIRD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"optional","enrollment_mode":"manual","ca_type":"builtin","cert_validity_days":365}')

SETTINGS_BODY=$(echo "$SETTINGS_RESPONSE" | head -n -1)
SETTINGS_CODE=$(echo "$SETTINGS_RESPONSE" | tail -n 1)

if [[ "$SETTINGS_CODE" -ge 200 && "$SETTINGS_CODE" -lt 300 ]]; then
  echo "[OK] Device auth settings applied (HTTP $SETTINGS_CODE):"
  echo "$SETTINGS_BODY"
else
  echo "[ERROR] Failed to apply device auth settings (HTTP $SETTINGS_CODE):"
  echo "$SETTINGS_BODY"
  exit 1
fi

echo ""

# --- 2. List enrollment requests ---
echo "[INFO] Fetching current enrollment requests..."
ENROLLMENTS_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$MGMT_URL/api/device-auth/enrollments" \
  -H "Authorization: Bearer $NETBIRD_TOKEN")

ENROLLMENTS_BODY=$(echo "$ENROLLMENTS_RESPONSE" | head -n -1)
ENROLLMENTS_CODE=$(echo "$ENROLLMENTS_RESPONSE" | tail -n 1)

if [[ "$ENROLLMENTS_CODE" -ge 200 && "$ENROLLMENTS_CODE" -lt 300 ]]; then
  echo "[OK] Enrollment requests (HTTP $ENROLLMENTS_CODE):"
  echo "$ENROLLMENTS_BODY"
else
  echo "[ERROR] Failed to fetch enrollment requests (HTTP $ENROLLMENTS_CODE):"
  echo "$ENROLLMENTS_BODY"
  exit 1
fi

echo ""

# --- 3. List trusted CAs ---
echo "[INFO] Fetching trusted certificate authorities..."
CAS_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$MGMT_URL/api/device-auth/trusted-cas" \
  -H "Authorization: Bearer $NETBIRD_TOKEN")

CAS_BODY=$(echo "$CAS_RESPONSE" | head -n -1)
CAS_CODE=$(echo "$CAS_RESPONSE" | tail -n 1)

if [[ "$CAS_CODE" -ge 200 && "$CAS_CODE" -lt 300 ]]; then
  echo "[OK] Trusted CAs (HTTP $CAS_CODE):"
  echo "$CAS_BODY"
else
  echo "[ERROR] Failed to fetch trusted CAs (HTTP $CAS_CODE):"
  echo "$CAS_BODY"
  exit 1
fi

echo ""
echo "[OK] Device auth setup complete."
echo "     To approve pending enrollments, run:"
echo "       NETBIRD_TOKEN=\$NETBIRD_TOKEN bash infrastructure_files/scripts/approve-enrollment.sh"
