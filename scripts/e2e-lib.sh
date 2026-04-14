#!/usr/bin/env bash
# E2E test helpers for device auth scenarios.
# This file is sourced, not executed directly. Safety flags applied by parent.
#
# Required environment variables:
#   NETBIRD_TEST_TOKEN  — admin PAT (set via NETBIRD_DEV_INIT_TOKEN in docker-compose)
#   NETBIRD_API_URL     — management API base URL (default: https://localhost)

FAILED_TESTS="${FAILED_TESTS:-0}"

# curl flags: skip TLS verification for local self-signed Caddy cert
CURL_OPTS="-sk"

# Wait for management server to be ready
wait_for_mgmt() {
    local url="${1:-${NETBIRD_API_URL:-https://localhost}/api/device-auth/settings}"
    local max_attempts="${2:-30}"
    local token
    token=$(get_token)
    local attempt=0

    echo "Waiting for management server at ${url}..."
    while [ "${attempt}" -lt "${max_attempts}" ]; do
        local http_code
        http_code=$(curl ${CURL_OPTS} -o /dev/null -w '%{http_code}' \
            -H "Authorization: Bearer ${token}" "${url}" 2>/dev/null || echo "000")
        if [ "${http_code}" = "200" ] || [ "${http_code}" = "401" ]; then
            echo "Management server ready (HTTP ${http_code})"
            return 0
        fi
        sleep 2
        attempt=$((attempt + 1))
    done
    echo "ERROR: Management server not ready after $((max_attempts * 2))s"
    return 1
}

# Get admin token.
# Set NETBIRD_TEST_TOKEN in the environment (see stand-dex/Makefile).
# In the stand-dex setup this is the NETBIRD_DEV_INIT_TOKEN value.
get_token() {
    if [ -z "${NETBIRD_TEST_TOKEN:-}" ]; then
        echo "ERROR: NETBIRD_TEST_TOKEN is not set" >&2
        echo "  Run the stand via: make -C infrastructure_files/stand-dex up" >&2
        echo "  Then export NETBIRD_TEST_TOKEN=<token from docker-compose.device-auth.yml>" >&2
        exit 1
    fi
    echo "${NETBIRD_TEST_TOKEN}"
}

# Approve an enrollment request by ID
approve_enrollment() {
    local enrollment_id="$1"
    local token
    token=$(get_token)

    curl ${CURL_OPTS}f -X POST \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        "${NETBIRD_API_URL:-https://localhost}/api/device-auth/enrollments/${enrollment_id}/approve"
}

# Reject an enrollment request by ID
reject_enrollment() {
    local enrollment_id="$1"
    local reason="${2:-rejected by E2E test}"
    local token
    local json_body
    token=$(get_token)
    json_body=$(printf '{"reason":"%s"}' "${reason}")

    curl ${CURL_OPTS}f -X POST \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "${json_body}" \
        "${NETBIRD_API_URL:-https://localhost}/api/device-auth/enrollments/${enrollment_id}/reject"
}

# Get cert for a peer by WG public key
get_device_cert() {
    local wg_key="$1"
    local token
    token=$(get_token)

    curl ${CURL_OPTS}f \
        -H "Authorization: Bearer ${token}" \
        "${NETBIRD_API_URL:-https://localhost}/api/device-auth/devices?wg_public_key=${wg_key}"
}

# Revoke a device cert by device ID
revoke_device() {
    local device_id="$1"
    local token
    token=$(get_token)

    curl ${CURL_OPTS}f -X POST \
        -H "Authorization: Bearer ${token}" \
        "${NETBIRD_API_URL:-https://localhost}/api/device-auth/devices/${device_id}/revoke"
}

# Add an external trusted CA
add_trusted_ca() {
    local name="$1"
    local pem="$2"
    local token
    local json_body
    token=$(get_token)
    json_body=$(printf '{"name":"%s","pem":"%s"}' "${name}" "${pem}")

    curl ${CURL_OPTS}f -X POST \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "${json_body}" \
        "${NETBIRD_API_URL:-https://localhost}/api/device-auth/trusted-cas"
}

# Delete a trusted CA by ID
delete_trusted_ca() {
    local ca_id="$1"
    local token
    token=$(get_token)

    curl ${CURL_OPTS}f -X DELETE \
        -H "Authorization: Bearer ${token}" \
        "${NETBIRD_API_URL:-https://localhost}/api/device-auth/trusted-cas/${ca_id}"
}

# Run a test and report result
run_test() {
    local test_name="$1"
    shift

    FAILED_TESTS="${FAILED_TESTS:-0}"
    echo ""
    echo "=== TEST: ${test_name} ==="
    if "$@"; then
        echo "PASS: ${test_name}"
        return 0
    else
        echo "FAIL: ${test_name}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}
