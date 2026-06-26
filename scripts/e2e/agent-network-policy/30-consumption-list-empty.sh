#!/usr/bin/env bash
# 30-consumption-list-empty: GET /api/agent-network/consumption must
# return a JSON array (possibly empty) — never a 404 / 500. The
# endpoint is the read side that backs the dashboard's basic counter
# view and must always be reachable so the page can render an empty
# state.

# shellcheck source=00-env.sh
source "$(dirname "$0")/00-env.sh"

resp=$(nb_api GET /api/agent-network/consumption)

# Must be a JSON array.
if ! printf '%s' "$resp" | jq -e 'type == "array"' >/dev/null 2>&1; then
    fail "consumption endpoint did not return a JSON array" "$resp"
fi

count=$(printf '%s' "$resp" | jq 'length')
echo "consumption rows: $count"

# Stash the baseline count so 40-grpc-record-and-list can compare.
printf '%s' "$count" >"$NB_STATE_DIR/consumption-baseline"

pass "consumption read endpoint returns a JSON array (count=$count)"
