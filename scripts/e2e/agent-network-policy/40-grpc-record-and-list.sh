#!/usr/bin/env bash
# 40-grpc-record-and-list: drives the new RecordLLMUsage and
# CheckLLMPolicyLimits gRPC RPCs through the e2e usage_smoke helper.
#
# Asserts:
#   - CheckLLMPolicyLimits returns decision=allow, picks the lowest
#     group id by string sort as attribution, default window of 24h.
#   - RecordLLMUsage with both user_id and group_id ticks BOTH the
#     user counter and the group counter exactly once each.
#   - A second RecordLLMUsage on the same key sums the deltas server
#     side (database upsert-increment, no read-modify-write race).
#   - The HTTP /api/agent-network/consumption listing reflects the
#     post-flight state.

# shellcheck source=00-env.sh
source "$(dirname "$0")/00-env.sh"

[ -r "$NB_STATE_DIR/group-id" ] && [ -r "$NB_STATE_DIR/provider-id" ] \
    || fail "missing group-id / provider-id state" \
            "run 10-policy-create.sh first to bootstrap prerequisites"
group_id=$(cat "$NB_STATE_DIR/group-id")
provider_id=$(cat "$NB_STATE_DIR/provider-id")

# Resolve the calling account id. /api/accounts returns NetBird xids,
# which is what the gRPC service expects (NOT IDP user UUIDs).
account_id=$(nb_api GET /api/accounts 2>/dev/null | jq -r '.[0].id // empty')
[ -n "$account_id" ] || fail "could not resolve account id" "GET /api/accounts returned nothing"

# Pick a stable user id for the test. The dimension is per-user, so we
# can use any unique value — a synthetic "e2e-..." prefix avoids
# colliding with real user ids in the consumption listing.
user_id="e2e-anpol-user-$$"
window_seconds=86400
echo "account=$account_id user=$user_id group=$group_id window=${window_seconds}s"

# ─── 1. CheckLLMPolicyLimits ────────────────────────────────────────
# Pass 3 group ids out of order; lowest by string sort wins.
groups_csv="grp-zz,$group_id,grp-aa-z"
check_resp=$(cd "$(nb_repo_root)" && go run ./scripts/e2e/agent-network-policy/cmd/usage_smoke check \
    --account "$account_id" \
    --user "$user_id" \
    --groups "$groups_csv" \
    --provider "$provider_id" \
    --model "gpt-4o" \
    --token "$NB_PROXY_TOKEN" \
    --addr "$NB_GRPC_ADDR" 2>&1) \
    || fail "CheckLLMPolicyLimits gRPC failed" "$check_resp"

decision=$(printf '%s' "$check_resp" | jq -r '.decision // ""')
attribution=$(printf '%s' "$check_resp" | jq -r '.attribution_group_id // ""')
got_window=$(printf '%s' "$check_resp" | jq -r '.window_seconds // ""')

[ "$decision" = "allow" ] \
    || fail "Check decision must be allow under PR1 stub" "$check_resp"
# Lowest group id of {grp-zz, $group_id, grp-aa-z} by string sort. The
# group_id is an xid (lowercase alnum starting with a digit/letter), so
# the sort answer depends on group_id's prefix. Compute it locally.
expected_low=$(printf '%s\n%s\n%s' "grp-zz" "$group_id" "grp-aa-z" | sort | head -1)
[ "$attribution" = "$expected_low" ] \
    || fail "Check did not pick the lowest-by-sort group" \
            "expected=$expected_low got=$attribution"
[ "$got_window" = "86400" ] \
    || fail "Check window_seconds stub default mismatch" "expected=86400 got=$got_window"

echo "Check decision=$decision attribution=$attribution window=${got_window}s"

# ─── 2. RecordLLMUsage — first increment ────────────────────────────
(cd "$(nb_repo_root)" && go run ./scripts/e2e/agent-network-policy/cmd/usage_smoke record \
    --account "$account_id" \
    --user "$user_id" \
    --group "$group_id" \
    --window-seconds "$window_seconds" \
    --tokens-in 100 \
    --tokens-out 50 \
    --cost-usd 0.0125 \
    --token "$NB_PROXY_TOKEN" \
    --addr "$NB_GRPC_ADDR") >/dev/null \
    || fail "RecordLLMUsage (first increment) failed" ""

# ─── 3. RecordLLMUsage — second increment, same key ─────────────────
(cd "$(nb_repo_root)" && go run ./scripts/e2e/agent-network-policy/cmd/usage_smoke record \
    --account "$account_id" \
    --user "$user_id" \
    --group "$group_id" \
    --window-seconds "$window_seconds" \
    --tokens-in 50 \
    --tokens-out 25 \
    --cost-usd 0.0025 \
    --token "$NB_PROXY_TOKEN" \
    --addr "$NB_GRPC_ADDR") >/dev/null \
    || fail "RecordLLMUsage (second increment) failed" ""

# ─── 4. Read-back via HTTP — sums must converge ─────────────────────
listing=$(nb_api GET /api/agent-network/consumption)

user_row=$(printf '%s' "$listing" | jq --arg u "$user_id" \
    'map(select(.dimension_kind == "user" and .dimension_id == $u)) | .[0]')
[ "$(printf '%s' "$user_row" | jq -r '. // empty')" != "" ] \
    || fail "user consumption row missing after RecordLLMUsage" "$listing"

user_in=$(printf '%s' "$user_row" | jq '.tokens_input')
user_out=$(printf '%s' "$user_row" | jq '.tokens_output')
user_cost=$(printf '%s' "$user_row" | jq '.cost_usd')
user_window=$(printf '%s' "$user_row" | jq '.window_seconds')

[ "$user_in" = "150" ] && [ "$user_out" = "75" ] \
    || fail "user counter did not sum the two increments" \
            "expected tokens_in=150 tokens_out=75; got in=$user_in out=$user_out"

# Floating point compare with awk — drift > 1e-9 is a real bug.
cost_ok=$(awk -v got="$user_cost" 'BEGIN { print (got > 0.0149 && got < 0.0151) ? "y" : "n" }')
[ "$cost_ok" = "y" ] \
    || fail "user cost did not sum to 0.015" "got=$user_cost"

[ "$user_window" = "$window_seconds" ] \
    || fail "user counter window_seconds mismatch" \
            "expected=$window_seconds got=$user_window"

# Group row gets the same deltas because RecordLLMUsage ticks both
# dimensions on a single call.
group_row=$(printf '%s' "$listing" | jq --arg g "$group_id" \
    'map(select(.dimension_kind == "group" and .dimension_id == $g)) | .[0]')
group_in=$(printf '%s' "$group_row" | jq '.tokens_input')
group_out=$(printf '%s' "$group_row" | jq '.tokens_output')

[ "$group_in" = "150" ] && [ "$group_out" = "75" ] \
    || fail "group counter did not sum the two increments" \
            "expected tokens_in=150 tokens_out=75; got in=$group_in out=$group_out"

echo "user counter: $user_in input / $user_out output / \$$user_cost over ${user_window}s"
echo "group counter: $group_in input / $group_out output"

pass "gRPC Check + Record round-trip atomically increments user + group counters"
