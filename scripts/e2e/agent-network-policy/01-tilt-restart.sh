#!/usr/bin/env bash
# 01-tilt-restart: re-trigger management + dashboard before each run so
# we start from a clean process state. The on-disk store survives, so
# the PAT, account, and any residual config persist across restarts.

# shellcheck source=00-env.sh
source "$(dirname "$0")/00-env.sh"

command -v tilt >/dev/null 2>&1 || fail "tilt not on PATH" "brew install tilt-dev/tap/tilt"

if ! curl -fsS -o /dev/null --max-time 2 http://localhost:10350/ 2>/dev/null; then
    fail "Tilt API not reachable at http://localhost:10350" "is 'tilt up' running in /Users/maycon/projects/local-dev?"
fi

restart_one() {
    local name="$1"
    if ! tilt trigger "$name" >/dev/null 2>&1; then
        fail "tilt trigger $name failed" ""
    fi
    echo "triggered $name"
}

restart_one management
restart_one dashboard
# proxy3 needs to come back too because PR2 wired the new
# llm_limit_check / llm_limit_record middlewares into the proxy
# binary; without restarting it, e2e keeps exercising whatever
# image was last loaded and silently misses any boot-order or
# wiring regression in the chain. Cheap to restart, expensive to
# silently miss.
restart_one proxy3

echo "waiting for management to accept requests..."
if ! wait_for "curl -fsS -o /dev/null --max-time 2 $NB_API/oauth2/.well-known/openid-configuration" 60; then
    fail "management did not come back up within 60s" "check 'tilt logs management'"
fi
echo "management is up"

code=$(curl -fsS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Token $NB_PAT" \
    "$NB_API/api/users" 2>&1) || true
[ "$code" = "200" ] || fail "PAT auth check failed after restart (HTTP $code)" "the PAT may have been revoked"

pass "Tilt resources restarted: management, dashboard"
