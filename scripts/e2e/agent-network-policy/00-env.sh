# shellcheck disable=SC2148
# Sourced helper for the agent-network-policy e2e suite.
# Verifies the agent-network surface: window_seconds (post-rename)
# through the API, /api/agent-network/consumption read endpoint, and
# the CheckLLMPolicyLimits + RecordLLMUsage gRPC RPCs.
#
# Do not run directly.

set -euo pipefail

: "${NB_API:=http://localhost:8080}"
: "${NB_PAT_FILE:=/Users/maycon/projects/local-dev/nb-pat}"
: "${NB_TIMEOUT_SECONDS:=60}"
: "${NB_POLICY_NAME:=e2e-anpol}"
: "${NB_PROVIDER_NAME:=e2e-anpol-provider}"
: "${NB_GROUP_NAME:=e2e-anpol-engineers}"
: "${NB_GRPC_ADDR:=localhost:8080}"
# Proxy token shared with the tilt setup. Keep in sync with the
# NB_PROXY_TOKEN literal in /Users/maycon/projects/local-dev/Tiltfile;
# the management server accepts it as a registered proxy credential
# so the e2e binary can reach the proxy_service gRPC surface.
: "${NB_PROXY_TOKEN:=nbx_MEF9OKRhlLrWkc5TJmM3Eu2rhqigaP2yulHy}"
: "${NB_STATE_DIR:=/tmp/nb-anpol-e2e-state}"

mkdir -p "$NB_STATE_DIR"

if [ ! -r "$NB_PAT_FILE" ]; then
    echo "FAIL: cannot read PAT at $NB_PAT_FILE" >&2
    exit 2
fi
NB_PAT=$(tr -d '\n\r ' <"$NB_PAT_FILE")
if [ ${#NB_PAT} -lt 16 ]; then
    echo "FAIL: PAT at $NB_PAT_FILE is suspiciously short (${#NB_PAT} chars)" >&2
    exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "FAIL: jq is required (brew install jq)" >&2
    exit 2
fi

# nb_api METHOD PATH [BODY] — wraps curl with PAT auth and JSON.
nb_api() {
    local method="$1" path="$2" body="${3-}"
    if [ -n "$body" ]; then
        curl -fsS -X "$method" \
            -H "Authorization: Token $NB_PAT" \
            -H "Content-Type: application/json" \
            --data "$body" \
            "$NB_API$path"
    else
        curl -fsS -X "$method" \
            -H "Authorization: Token $NB_PAT" \
            "$NB_API$path"
    fi
}

# nb_api_status METHOD PATH [BODY] — returns the HTTP status code
# rather than the body. Use for negative-path tests where a 4xx is
# the expected outcome and curl's default -f would mask the result.
nb_api_status() {
    local method="$1" path="$2" body="${3-}"
    if [ -n "$body" ]; then
        curl -sS -o /dev/null -w '%{http_code}' -X "$method" \
            -H "Authorization: Token $NB_PAT" \
            -H "Content-Type: application/json" \
            --data "$body" \
            "$NB_API$path"
    else
        curl -sS -o /dev/null -w '%{http_code}' -X "$method" \
            -H "Authorization: Token $NB_PAT" \
            "$NB_API$path"
    fi
}

# wait_for COND_CMD TIMEOUT_S — polls every 1s.
wait_for() {
    local cmd="$1" timeout="${2:-$NB_TIMEOUT_SECONDS}"
    local i=0
    while [ "$i" -lt "$timeout" ]; do
        if eval "$cmd" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# resolve the absolute path of the netbird repo root from the script
# location so the Go smoke binary can be invoked via `go run` against
# the right module regardless of the caller's cwd.
nb_repo_root() {
    cd "$(dirname "$0")/../../.." && pwd
}

pass() {
    printf 'PASS: %s\n' "$1"
    exit 0
}

fail() {
    printf 'FAIL: %s — %s\n' "$1" "${2:-}"
    exit 1
}
