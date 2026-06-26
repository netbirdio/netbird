#!/usr/bin/env bash
# 50-grpc-allow-record-deny: drives the full lifecycle of the real
# selection algorithm landed in PR2 — initial allow, partial fills
# below the cap, exact-at-cap, then deny once consumption reaches the
# group_cap. Validates that:
#
#   - CheckLLMPolicyLimits picks the test policy as the attribution
#     when it's the only one authorising the (group, provider) pair.
#   - The selected_policy_id + window_seconds round-trip on the wire.
#   - Counter-aware headroom math is wired end-to-end (RecordLLMUsage
#     ticks counters that the next CheckLLMPolicyLimits call reads).
#   - At-cap consumption flips decision from allow to deny with the
#     canonical llm_policy.token_cap_exceeded code.
#
# The setup creates a dedicated group + provider + policy with the
# "-tight" suffix so it's isolated from the e2e-anpol resources
# 10-policy-create.sh seeded. 99-cleanup's prefix sweep catches both.

# shellcheck source=00-env.sh
source "$(dirname "$0")/00-env.sh"

# Per-run suffix so the consumption counter starts at zero on every
# run. Without this, a successful prior run leaves 200 tokens on the
# (group, 24h) bucket and the next run's stage 1 check sees a deny
# from the start. Consumption rows have no delete endpoint today.
RUN_TAG="$(date +%s)-$$"
NB_TIGHT_GROUP_NAME="$NB_GROUP_NAME-tight-$RUN_TAG"
NB_TIGHT_PROVIDER_NAME="$NB_PROVIDER_NAME-tight-$RUN_TAG"
NB_TIGHT_POLICY_NAME="$NB_POLICY_NAME-tight-$RUN_TAG"
TIGHT_CAP=200
TIGHT_WINDOW_SECONDS=86400

# 1. Group — fresh per-run so the (group, window) consumption counter
# starts at zero. The 99-cleanup sweep catches it via the
# `e2e-anpol-engineers-tight-` prefix.
body=$(jq -n --arg name "$NB_TIGHT_GROUP_NAME" '{name:$name}')
tight_group_id=$(nb_api POST /api/groups "$body" | jq -r '.id // ""')
[ -n "$tight_group_id" ] && [ "$tight_group_id" != "null" ] \
    || fail "tight group create failed" ""
echo "created tight group $tight_group_id"
printf '%s' "$tight_group_id" >"$NB_STATE_DIR/tight-group-id"

# 2. Provider — fresh per-run too so the policy targets a provider
# only this run knows about. Eliminates cross-policy interference if
# a prior run's tight policy targeted the same provider id.
body=$(jq -n \
    --arg name "$NB_TIGHT_PROVIDER_NAME" \
    '{
        provider_id: "openai_api",
        name: $name,
        upstream_url: "https://api.openai.com",
        api_key: "sk-e2e-tight-placeholder",
        bootstrap_cluster: "proxy.netbird.local",
        models: []
    }')
tight_provider_id=$(nb_api POST /api/agent-network/providers "$body" | jq -r '.id // ""')
[ -n "$tight_provider_id" ] && [ "$tight_provider_id" != "null" ] \
    || fail "tight provider create failed" ""
echo "created tight provider $tight_provider_id"
printf '%s' "$tight_provider_id" >"$NB_STATE_DIR/tight-provider-id"

# 3. Policy with a tight token cap so the test can observe the deny
# transition without burning thousands of records.
existing_policy=$(nb_api GET /api/agent-network/policies 2>/dev/null \
    | jq -r --arg name "$NB_TIGHT_POLICY_NAME" '.[] | select(.name == $name) | .id // empty' \
    | head -1)
if [ -n "$existing_policy" ]; then
    echo "deleting existing tight policy $existing_policy so the run starts clean"
    nb_api DELETE "/api/agent-network/policies/$existing_policy" >/dev/null 2>&1 || true
fi

policy_body=$(jq -n \
    --arg name "$NB_TIGHT_POLICY_NAME" \
    --arg group "$tight_group_id" \
    --arg provider "$tight_provider_id" \
    --argjson cap "$TIGHT_CAP" \
    --argjson window "$TIGHT_WINDOW_SECONDS" \
    '{
        name: $name,
        description: "agent-network e2e: cap-exhaust deny test",
        enabled: true,
        source_groups: [$group],
        destination_provider_ids: [$provider],
        guardrail_ids: [],
        limits: {
            token_limit: {
                enabled: true,
                group_cap: $cap,
                user_cap: 0,
                window_seconds: $window
            },
            budget_limit: {
                enabled: false,
                group_cap_usd: 0,
                user_cap_usd: 0,
                window_seconds: $window
            }
        }
    }')
tight_policy_id=$(nb_api POST /api/agent-network/policies "$policy_body" | jq -r '.id // ""')
[ -n "$tight_policy_id" ] && [ "$tight_policy_id" != "null" ] \
    || fail "tight policy create failed" ""
printf '%s' "$tight_policy_id" >"$NB_STATE_DIR/tight-policy-id"
echo "created tight policy $tight_policy_id (group_cap=$TIGHT_CAP, window=${TIGHT_WINDOW_SECONDS}s)"

# 4. Resolve the calling account id; the smoke binary stamps it onto
# every gRPC request the way the real proxy does.
account_id=$(nb_api GET /api/accounts 2>/dev/null | jq -r '.[0].id // empty')
[ -n "$account_id" ] || fail "could not resolve account id" ""

# Test user — synthetic prefix avoids colliding with real users.
test_user="e2e-anpol-tight-user-$$"

# Pre-resolve the netbird repo root ONCE so the helpers below can
# pushd / popd into it without `cd "$(dirname "$0")/.."` re-resolving
# from a moved cwd between calls. nb_repo_root walks up from $0; if a
# prior helper left cwd elsewhere the relative walk breaks.
repo_root=$(nb_repo_root)
[ -d "$repo_root" ] || fail "could not resolve netbird repo root" "got=$repo_root"

# Run the smoke binary inside a subshell so its `cd` doesn't pollute
# the caller's cwd between stages.
do_check() {
    (
        cd "$repo_root" || exit 1
        go run ./scripts/e2e/agent-network-policy/cmd/usage_smoke check \
            --account "$account_id" \
            --user "$test_user" \
            --groups "$tight_group_id" \
            --provider "$tight_provider_id" \
            --model "gpt-4o" \
            --token "$NB_PROXY_TOKEN" \
            --addr "$NB_GRPC_ADDR"
    )
}

do_record() {
    local in="$1" out="$2" cost="$3"
    (
        cd "$repo_root" || exit 1
        go run ./scripts/e2e/agent-network-policy/cmd/usage_smoke record \
            --account "$account_id" \
            --user "$test_user" \
            --group "$tight_group_id" \
            --window-seconds "$TIGHT_WINDOW_SECONDS" \
            --tokens-in "$in" \
            --tokens-out "$out" \
            --cost-usd "$cost" \
            --token "$NB_PROXY_TOKEN" \
            --addr "$NB_GRPC_ADDR"
    )
}

# Stage 1 — fresh state. Selection must allow and pick our tight
# policy as attribution because it's the ONLY policy authorising the
# (tight_group, tight_provider) tuple. Also confirms the wire-level
# selected_policy_id round-trip from manager → grpc → smoke client.
echo "stage 1: initial check (consumption=0/$TIGHT_CAP)"
resp=$(do_check) || fail "initial check failed" "$resp"
decision=$(printf '%s' "$resp" | jq -r '.decision // ""')
selected=$(printf '%s' "$resp" | jq -r '.selected_policy_id // ""')
window=$(printf '%s' "$resp" | jq -r '.window_seconds // ""')
[ "$decision" = "allow" ] \
    || fail "expected allow on fresh state" "$resp"
[ "$selected" = "$tight_policy_id" ] \
    || fail "selection did not pick the tight policy" \
            "expected=$tight_policy_id got=$selected"
[ "$window" = "$TIGHT_WINDOW_SECONDS" ] \
    || fail "window_seconds mismatch on the wire" "expected=$TIGHT_WINDOW_SECONDS got=$window"
echo "  → allow / selected=$selected / window=${window}s"

# Stage 2 — book half the cap. The next check must still allow.
echo "stage 2: record 100 input tokens (consumption=100/$TIGHT_CAP)"
do_record 100 0 0 >/dev/null || fail "record (stage 2) failed" ""
resp=$(do_check)
decision=$(printf '%s' "$resp" | jq -r '.decision // ""')
[ "$decision" = "allow" ] \
    || fail "expected allow at half-cap" "$resp"
echo "  → allow"

# Stage 3 — push to one token below cap. Headroom shrinks but
# decision stays allow.
echo "stage 3: record 99 more input tokens (consumption=199/$TIGHT_CAP)"
do_record 99 0 0 >/dev/null || fail "record (stage 3) failed" ""
resp=$(do_check)
decision=$(printf '%s' "$resp" | jq -r '.decision // ""')
[ "$decision" = "allow" ] \
    || fail "expected allow at one-below-cap" "$resp"
echo "  → allow"

# Stage 4 — exactly at cap. Selector treats consumed >= cap as
# exhausted, so the next check must deny with the canonical token cap
# code. The deny reason names the policy id so operators can debug
# from the access log.
echo "stage 4: record 1 final token (consumption=$TIGHT_CAP/$TIGHT_CAP)"
do_record 1 0 0 >/dev/null || fail "record (stage 4) failed" ""
resp=$(do_check) || fail "check after cap-exhaust failed" "$resp"
decision=$(printf '%s' "$resp" | jq -r '.decision // ""')
deny_code=$(printf '%s' "$resp" | jq -r '.deny_code // ""')
deny_reason=$(printf '%s' "$resp" | jq -r '.deny_reason // ""')
[ "$decision" = "deny" ] \
    || fail "expected DENY at cap" "$resp"
[ "$deny_code" = "llm_policy.token_cap_exceeded" ] \
    || fail "deny_code mismatch" "expected=llm_policy.token_cap_exceeded got=$deny_code resp=$resp"
echo "  → DENY / deny_code=$deny_code"
echo "  → deny_reason: $deny_reason"
[[ "$deny_reason" == *"$tight_policy_id"* ]] \
    || fail "deny_reason must name the policy id for operator debugging" "$deny_reason"

pass "selection algorithm flips allow → deny at cap-exhaust through the gRPC wire"
