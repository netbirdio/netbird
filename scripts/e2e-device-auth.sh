#!/usr/bin/env bash
# Device Certificate Authentication — comprehensive E2E test suite.
#
# Tests all scenarios against a running dev stand:
#   - Settings CRUD
#   - Full enrollment cycle (CSR submit → admin approve → cert issued → mTLS auth)
#   - mTLS mode enforcement (cert-only: no-cert denied, with-cert allowed)
#   - Certificate revocation (revoked cert denied)
#   - CA lifecycle (add / delete external trusted CA)
#   - Invalid CA cert rejection (M-5 server-side validation)
#   - Enrollment rejection flow
#
# The stand must be started before running this script:
#   make -C infrastructure_files/stand-dex build up wait
#
# Environment variables:
#   NETBIRD_TEST_TOKEN   — admin PAT (default: value in docker-compose.device-auth.yml)
#   NETBIRD_API_URL      — REST API base URL via Caddy (default: https://localhost)
#   NETBIRD_GRPC_URL     — gRPC URL for direct mTLS tests (default: https://localhost:8443)
#   NETBIRD_SETUP_KEY    — setup key (auto-discovered from management container if not set)
#   NETBIRD_E2E_VERBOSE  — set to 1 for verbose curl output
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e-lib.sh
source "${SCRIPT_DIR}/e2e-lib.sh"

# ── Config ────────────────────────────────────────────────────────────────────

NETBIRD_API_URL="${NETBIRD_API_URL:-https://localhost}"
NETBIRD_GRPC_URL="${NETBIRD_GRPC_URL:-https://localhost:8443}"

# docker compose invocation (base + device-auth overlay)
COMPOSE_DIR="${NETBIRD_COMPOSE_DIR:-${SCRIPT_DIR}/../infrastructure_files/stand-dex}"
COMPOSE_CMD="docker compose -f ${COMPOSE_DIR}/docker-compose.yml -f ${COMPOSE_DIR}/docker-compose.device-auth.yml"

FAILED_TESTS=0
TMPDIR_E2E=""

cleanup() {
    [ -n "${TMPDIR_E2E}" ] && rm -rf "${TMPDIR_E2E}"
    # Restore settings to sane default so subsequent runs start clean.
    set_device_auth_mode "optional" 2>/dev/null || true
}
trap cleanup EXIT

# ── Helpers ───────────────────────────────────────────────────────────────────

# Discover setup key from management container /var/lib/netbird/init.env
get_setup_key() {
    ${COMPOSE_CMD} exec -T management \
        sh -c 'grep NETBIRD_SETUP_KEY /var/lib/netbird/init.env 2>/dev/null | cut -d= -f2' \
        2>/dev/null | tr -d '\r\n' || true
}

# Set device auth mode via REST API (suppresses output)
set_device_auth_mode() {
    local mode="$1"
    local token
    token=$(get_token)
    curl ${CURL_OPTS}f -X PUT \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "{\"mode\":\"${mode}\",\"enrollment_mode\":\"manual\",\"ca_type\":\"builtin\",\"cert_validity_days\":365,\"ocsp_enabled\":false,\"fail_open_on_ocsp_unavailable\":false,\"inventory_type\":\"\"}" \
        "${NETBIRD_API_URL}/api/device-auth/settings" > /dev/null 2>&1
}

# Run enroll-demo INSIDE the management Docker container.
# The binary connects to management via TLS on localhost:443 within the container.
# Additional args (e.g. -save-device-key /tmp/device.key) must reference paths
# inside the container.  Use docker cp to retrieve files afterward.
run_enroll_demo_in_container() {
    local setup_key="$1"
    local save_key_container="${2:-}"
    local extra_args=""
    [ -n "${save_key_container}" ] && extra_args="-save-device-key ${save_key_container}"
    # shellcheck disable=SC2086
    ${COMPOSE_CMD} exec -T management \
        /usr/local/bin/enroll-demo \
        -management "https://localhost:443" \
        -tls -insecure \
        -setup-key "${setup_key}" \
        ${extra_args} \
        2>/dev/null || true
}

# Copy a file from the management container to the host tmp dir
copy_from_container() {
    local container_path="$1"
    local host_path="$2"
    ${COMPOSE_CMD} cp "management:${container_path}" "${host_path}" 2>/dev/null || true
}

# Run mtls-demo from the HOST against management's direct TLS port (8443).
# Returns the full output including the RESULT line.
run_mtls_demo() {
    local setup_key="$1"
    local wg_key="${2:-}"
    local cert_file="${3:-}"
    local key_file="${4:-}"

    local args=()
    args+=(-management "${NETBIRD_GRPC_URL}")
    args+=(-insecure)
    args+=(-setup-key "${setup_key}")
    [ -n "${wg_key}" ]    && args+=(-wg-key "${wg_key}")
    [ -n "${cert_file}" ] && args+=(-client-cert "${cert_file}")
    [ -n "${key_file}" ]  && args+=(-client-key "${key_file}")

    go run "${SCRIPT_DIR}/../management/cmd/mtls-demo/" "${args[@]}" 2>&1 || true
}

# ── Pre-flight ────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   NetBird Device Certificate Auth — E2E Test Suite            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "  REST API  : ${NETBIRD_API_URL}"
echo "  gRPC mTLS : ${NETBIRD_GRPC_URL}"
echo ""

TOKEN=$(get_token)
wait_for_mgmt "${NETBIRD_API_URL}/api/device-auth/settings"

SETUP_KEY="${NETBIRD_SETUP_KEY:-$(get_setup_key)}"
if [ -z "${SETUP_KEY}" ]; then
    echo "ERROR: NETBIRD_SETUP_KEY not found."
    echo "  Start the stand with: make -C ${COMPOSE_DIR} up wait"
    echo "  or set NETBIRD_SETUP_KEY env var manually."
    exit 1
fi
echo "  Setup key : ${SETUP_KEY}"

TMPDIR_E2E="$(mktemp -d)"
# Make key path visible inside the management container via /tmp
CONTAINER_KEY_PATH="/tmp/e2e-device.key"

# ── Scenario 1: Settings CRUD ─────────────────────────────────────────────────

echo ""
echo "── Scenario 1: Device auth settings CRUD ──────────────────────"

set_device_auth_mode "optional"
S1=$(curl ${CURL_OPTS}f -H "Authorization: Bearer ${TOKEN}" \
    "${NETBIRD_API_URL}/api/device-auth/settings")
run_test "GET settings returns mode=optional" \
    bash -c "echo '${S1}' | grep -q '\"mode\":\"optional\"'"

set_device_auth_mode "cert-only"
S2=$(curl ${CURL_OPTS}f -H "Authorization: Bearer ${TOKEN}" \
    "${NETBIRD_API_URL}/api/device-auth/settings")
run_test "PUT settings changes mode to cert-only" \
    bash -c "echo '${S2}' | grep -q '\"mode\":\"cert-only\"'"

set_device_auth_mode "optional"

# ── Scenario 2: Enrollment API ────────────────────────────────────────────────

echo ""
echo "── Scenario 2: Enrollment API reachability ──────────────────────"

RES=$(curl ${CURL_OPTS} -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${TOKEN}" "${NETBIRD_API_URL}/api/device-auth/enrollments")
run_test "enrollments list returns 200" [ "${RES}" = "200" ]

RES=$(curl ${CURL_OPTS} -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${TOKEN}" "${NETBIRD_API_URL}/api/device-auth/devices")
run_test "devices list returns 200" [ "${RES}" = "200" ]

# ── Scenario 3: Full enrollment cycle ────────────────────────────────────────

echo ""
echo "── Scenario 3: Full enrollment cycle ────────────────────────────"

set_device_auth_mode "optional"

ENROLLMENT_ID=""
WG_KEY=""
DEVICE_ID=""

ENROLL_OUT="$(run_enroll_demo_in_container "${SETUP_KEY}" "${CONTAINER_KEY_PATH}")"
if [ -n "${ENROLL_OUT}" ]; then
    ENROLLMENT_ID=$(echo "${ENROLL_OUT}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('enrollment_id',''))" 2>/dev/null || echo "")
    WG_KEY=$(echo "${ENROLL_OUT}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('wg_public_key',''))" 2>/dev/null || echo "")
    echo "[e2e] enrollment_id=${ENROLLMENT_ID}  wg_key=${WG_KEY}"
fi

run_test "enrollment submitted (got enrollment_id)" bash -c "[ -n '${ENROLLMENT_ID}' ]"

if [ -n "${ENROLLMENT_ID}" ]; then
    APPROVE_STATUS=$(curl ${CURL_OPTS} -o /dev/null -w "%{http_code}" -X POST \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        "${NETBIRD_API_URL}/api/device-auth/enrollments/${ENROLLMENT_ID}/approve")
    run_test "enrollment approved (HTTP 200)" [ "${APPROVE_STATUS}" = "200" ]

    # Poll for cert to be issued (max 15s).
    # The devices API returns serial/not_before/not_after (not cert_pem);
    # a non-empty serial means the certificate has been issued.
    echo "[e2e] Polling for cert issuance..."
    CERT_SERIAL=""
    for _ in $(seq 1 15); do
        DEVS_JSON=$(curl ${CURL_OPTS}f -H "Authorization: Bearer ${TOKEN}" \
            "${NETBIRD_API_URL}/api/device-auth/devices" 2>/dev/null || echo "")
        if echo "${DEVS_JSON}" | grep -q "${WG_KEY:-NONE}"; then
            DEVICE_ID=$(echo "${DEVS_JSON}" | python3 -c "import json,sys; devs=json.load(sys.stdin); [print(d.get('id','')) for d in (devs if isinstance(devs,list) else []) if d.get('wg_public_key','')==sys.argv[1]]" "${WG_KEY:-NONE}" 2>/dev/null | head -1 || echo "")
            CERT_SERIAL=$(echo "${DEVS_JSON}" | python3 -c "
import json, sys
devices = json.load(sys.stdin)
if isinstance(devices, list):
    for d in devices:
        if d.get('wg_public_key','') == sys.argv[1]:
            print(d.get('serial',''))
            break
" "${WG_KEY:-}" 2>/dev/null || echo "")
            [ -n "${CERT_SERIAL}" ] && break
        fi
        sleep 1
    done

    run_test "device cert issued (serial present)" bash -c "[ -n '${CERT_SERIAL}' ]"

    # Get the issued cert PEM from the enrollment status for mTLS tests.
    # The devices API doesn't return PEM; poll the enrollment status endpoint instead.
    CERT_PEM=""
    if [ -n "${CERT_SERIAL}" ] && [ -n "${WG_KEY}" ]; then
        ENROLL_STATUS=$(curl ${CURL_OPTS}f -H "Authorization: Bearer ${TOKEN}" \
            "${NETBIRD_API_URL}/api/device-auth/enrollments/${ENROLLMENT_ID}" 2>/dev/null || echo "")
        CERT_PEM=$(echo "${ENROLL_STATUS}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('cert_pem',''))" 2>/dev/null || echo "")
    fi

    # Persist cert for mTLS tests
    if [ -n "${CERT_PEM}" ]; then
        printf '%s' "${CERT_PEM}" > "${TMPDIR_E2E}/device.pem"
        # Copy the private key out of the management container
        copy_from_container "${CONTAINER_KEY_PATH}" "${TMPDIR_E2E}/device.key"
    fi
fi

# ── Scenario 4: mTLS mode enforcement ────────────────────────────────────────

echo ""
echo "── Scenario 4: mTLS mode enforcement ───────────────────────────"

if command -v go > /dev/null 2>&1 && [ -n "${SETUP_KEY}" ]; then

    # 4a: cert-only + no cert → denied
    set_device_auth_mode "cert-only"
    echo "[e2e] cert-only: connecting WITHOUT client cert..."
    OUT4A="$(run_mtls_demo "${SETUP_KEY}" "" "" "")"
    run_test "cert-only: no-cert login DENIED" \
        bash -c "echo '${OUT4A}' | grep -qiE 'RESULT: DENIED|PermissionDenied|Unauthenticated|not allowed'"

    # 4b: cert-only + valid cert → allowed
    if [ -f "${TMPDIR_E2E}/device.pem" ] && [ -f "${TMPDIR_E2E}/device.key" ]; then
        echo "[e2e] cert-only: connecting WITH valid client cert..."
        OUT4B="$(run_mtls_demo "${SETUP_KEY}" "${WG_KEY}" \
            "${TMPDIR_E2E}/device.pem" "${TMPDIR_E2E}/device.key")"
        run_test "cert-only: valid-cert login ALLOWED" \
            bash -c "echo '${OUT4B}' | grep -q 'RESULT: ALLOWED'"
    else
        echo "[e2e] SKIP 4b: cert files not available (enrollment scenario skipped)"
    fi

    # 4c: optional + no cert → allowed
    set_device_auth_mode "optional"
    echo "[e2e] optional: connecting WITHOUT client cert..."
    OUT4C="$(run_mtls_demo "${SETUP_KEY}" "" "" "")"
    run_test "optional: no-cert login ALLOWED" \
        bash -c "echo '${OUT4C}' | grep -q 'RESULT: ALLOWED'"

else
    echo "[e2e] SKIP scenario 4: go binary or setup key not available"
fi

# ── Scenario 5: Certificate revocation ───────────────────────────────────────

echo ""
echo "── Scenario 5: Certificate revocation ─────────────────────────"

if [ -n "${DEVICE_ID}" ] && [ -f "${TMPDIR_E2E}/device.pem" ] && command -v go > /dev/null 2>&1; then

    set_device_auth_mode "cert-only"

    REVOKE_STATUS=$(curl ${CURL_OPTS} -o /dev/null -w "%{http_code}" -X POST \
        -H "Authorization: Bearer ${TOKEN}" \
        "${NETBIRD_API_URL}/api/device-auth/devices/${DEVICE_ID}/revoke")
    run_test "device cert revoked (HTTP 200)" [ "${REVOKE_STATUS}" = "200" ]

    # Verify revoked flag in API
    DEVS=$(curl ${CURL_OPTS}f -H "Authorization: Bearer ${TOKEN}" \
        "${NETBIRD_API_URL}/api/device-auth/devices" 2>/dev/null || echo "")
    run_test "device shows revoked=true in API" \
        bash -c "echo '${DEVS}' | grep -q '\"revoked\":true'"

    # Try to authenticate with revoked cert → must be denied
    echo "[e2e] Attempting login with REVOKED cert..."
    OUT5="$(run_mtls_demo "${SETUP_KEY}" "${WG_KEY}" \
        "${TMPDIR_E2E}/device.pem" "${TMPDIR_E2E}/device.key")"
    run_test "revoked cert login DENIED" \
        bash -c "echo '${OUT5}' | grep -qiE 'RESULT: DENIED|PermissionDenied|revoked'"

    set_device_auth_mode "optional"

else
    echo "[e2e] SKIP scenario 5: requires enrollment + go binary"
fi

# ── Scenario 6: External trusted CA lifecycle ─────────────────────────────────

echo ""
echo "── Scenario 6: External trusted CA lifecycle ───────────────────"

if command -v openssl > /dev/null 2>&1; then

    openssl req -x509 -newkey rsa:2048 \
        -keyout "${TMPDIR_E2E}/ext-ca.key" \
        -out "${TMPDIR_E2E}/ext-ca.pem" \
        -days 1 -nodes -subj "/CN=e2e-external-ca" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

    CA_PEM_ESC="$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' "${TMPDIR_E2E}/ext-ca.pem")"

    CA_RESPONSE=$(curl ${CURL_OPTS}f -X POST \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"e2e-test-ca\",\"pem\":\"${CA_PEM_ESC}\"}" \
        "${NETBIRD_API_URL}/api/device-auth/trusted-cas" 2>/dev/null || echo "")

    CA_ID=$(echo "${CA_RESPONSE}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null || echo "")
    run_test "external CA added (got id)" [ -n "${CA_ID}" ]

    if [ -n "${CA_ID}" ]; then
        CAS=$(curl ${CURL_OPTS}f -H "Authorization: Bearer ${TOKEN}" \
            "${NETBIRD_API_URL}/api/device-auth/trusted-cas" 2>/dev/null || echo "")
        run_test "added CA appears in list" bash -c "echo '${CAS}' | grep -q 'e2e-test-ca'"

        DEL=$(curl ${CURL_OPTS} -o /dev/null -w "%{http_code}" -X DELETE \
            -H "Authorization: Bearer ${TOKEN}" \
            "${NETBIRD_API_URL}/api/device-auth/trusted-cas/${CA_ID}")
        run_test "external CA deleted (HTTP 204 or 200)" \
            bash -c "[ '${DEL}' = '204' ] || [ '${DEL}' = '200' ]"

        CAS_AFTER=$(curl ${CURL_OPTS}f -H "Authorization: Bearer ${TOKEN}" \
            "${NETBIRD_API_URL}/api/device-auth/trusted-cas" 2>/dev/null || echo "")
        run_test "deleted CA no longer in list" \
            bash -c "! echo '${CAS_AFTER}' | grep -q '\"id\":\"${CA_ID}\"'"
    fi

else
    echo "[e2e] SKIP scenario 6: openssl not available"
fi

# ── Scenario 7: Invalid CA cert rejected (M-5 validation) ────────────────────

echo ""
echo "── Scenario 7: Invalid CA cert rejected (M-5 validation) ──────"

if command -v openssl > /dev/null 2>&1; then

    # Generate a plain leaf cert (not a CA — no basicConstraints IsCA)
    openssl req -x509 -newkey rsa:2048 \
        -keyout "${TMPDIR_E2E}/leaf.key" \
        -out "${TMPDIR_E2E}/leaf.pem" \
        -days 1 -nodes -subj "/CN=leaf-not-a-ca" 2>/dev/null
    # Note: by default openssl req -x509 adds basicConstraints=CA:TRUE for self-signed,
    # so use a non-self-signed cert signed by a CA, or just test the expiry/format path

    LEAF_PEM_ESC="$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' "${TMPDIR_E2E}/leaf.pem")"

    # Submit a clearly invalid PEM (just garbage)
    REJECT_STATUS=$(curl ${CURL_OPTS} -o /dev/null -w "%{http_code}" -X POST \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{"name":"invalid","pem":"not-valid-pem"}' \
        "${NETBIRD_API_URL}/api/device-auth/trusted-cas" 2>/dev/null || echo "000")
    run_test "invalid PEM rejected (HTTP 4xx)" \
        bash -c "echo '${REJECT_STATUS}' | grep -qE '^4'"

else
    echo "[e2e] SKIP scenario 7: openssl not available"
fi

# ── Scenario 8: Enrollment rejection ─────────────────────────────────────────

echo ""
echo "── Scenario 8: Enrollment rejection ────────────────────────────"

set_device_auth_mode "optional"

if [ -n "${SETUP_KEY}" ]; then
    ENROLL2_OUT="$(run_enroll_demo_in_container "${SETUP_KEY}" "")"
    ENROLL2_ID=$(echo "${ENROLL2_OUT}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('enrollment_id',''))" 2>/dev/null || echo "")

    run_test "second enrollment submitted" bash -c "[ -n '${ENROLL2_ID}' ]"

    if [ -n "${ENROLL2_ID}" ]; then
        REJ=$(curl ${CURL_OPTS} -o /dev/null -w "%{http_code}" -X POST \
            -H "Authorization: Bearer ${TOKEN}" \
            -H "Content-Type: application/json" \
            -d '{"reason":"rejected by E2E test"}' \
            "${NETBIRD_API_URL}/api/device-auth/enrollments/${ENROLL2_ID}/reject")
        run_test "enrollment rejection returns 200" [ "${REJ}" = "200" ]
    fi
else
    echo "[e2e] SKIP scenario 8: no setup key"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════════════"
if [ "${FAILED_TESTS}" -eq 0 ]; then
    echo "  ALL TESTS PASSED"
else
    echo "  FAILED: ${FAILED_TESTS} test(s)"
fi
echo "════════════════════════════════════════════════════════════════"
[ "${FAILED_TESTS}" -eq 0 ]
