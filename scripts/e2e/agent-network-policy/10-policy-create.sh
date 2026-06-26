#!/usr/bin/env bash
# 10-policy-create: end-to-end round-trip on the new window_seconds
# field. Creates the prerequisites (group + provider with
# bootstrap_cluster), POSTs a policy whose Limits.token_limit and
# budget_limit both carry window_seconds, then re-fetches the policy
# and asserts the field comes back unchanged.

# shellcheck source=00-env.sh
source "$(dirname "$0")/00-env.sh"

# 1. Group — sweep first so re-runs are idempotent, then POST.
existing_group=$(nb_api GET /api/groups 2>/dev/null \
    | jq -r --arg name "$NB_GROUP_NAME" '.[] | select(.name == $name) | .id // empty' \
    | head -1)
if [ -n "$existing_group" ]; then
    echo "reusing existing group $existing_group"
    group_id="$existing_group"
else
    body=$(jq -n --arg name "$NB_GROUP_NAME" '{name:$name}')
    group_resp=$(nb_api POST /api/groups "$body")
    group_id=$(printf '%s' "$group_resp" | jq -r '.id // ""')
    [ -n "$group_id" ] && [ "$group_id" != "null" ] \
        || fail "group create did not return an id" "$group_resp"
    echo "created group $group_id"
fi
printf '%s' "$group_id" >"$NB_STATE_DIR/group-id"

# 2. Provider — also idempotent. Bootstrap cluster pinned to the local
#    proxy3 cluster so the management settings row resolves and the
#    create completes (subsequent provider creates in the same account
#    ignore bootstrap_cluster, but the FIRST one needs it).
existing_provider=$(nb_api GET /api/agent-network/providers 2>/dev/null \
    | jq -r --arg name "$NB_PROVIDER_NAME" '.[] | select(.name == $name) | .id // empty' \
    | head -1)
if [ -n "$existing_provider" ]; then
    echo "reusing existing provider $existing_provider"
    provider_id="$existing_provider"
else
    provider_body=$(jq -n \
        --arg name "$NB_PROVIDER_NAME" \
        '{
            provider_id: "openai_api",
            name: $name,
            upstream_url: "https://api.openai.com",
            api_key: "sk-e2e-placeholder",
            bootstrap_cluster: "proxy.netbird.local",
            models: []
        }')
    prov_resp=$(nb_api POST /api/agent-network/providers "$provider_body")
    provider_id=$(printf '%s' "$prov_resp" | jq -r '.id // ""')
    [ -n "$provider_id" ] && [ "$provider_id" != "null" ] \
        || fail "provider create did not return an id" "$prov_resp"
    echo "created provider $provider_id"
fi
printf '%s' "$provider_id" >"$NB_STATE_DIR/provider-id"

# 3. Policy — drop any prior with the same name, then create with the
#    NEW window_seconds field on both halves of Limits. 86400s = 24h
#    on token, 2_592_000s = 30d on budget so the round-trip is
#    unambiguous (no ambiguous unit-conversion artefact when we read
#    back).
existing_policy=$(nb_api GET /api/agent-network/policies 2>/dev/null \
    | jq -r --arg name "$NB_POLICY_NAME" '.[] | select(.name == $name) | .id // empty' \
    | head -1)
if [ -n "$existing_policy" ]; then
    echo "deleting existing policy $existing_policy"
    nb_api DELETE "/api/agent-network/policies/$existing_policy" >/dev/null 2>&1 || true
fi

policy_body=$(jq -n \
    --arg name "$NB_POLICY_NAME" \
    --arg group "$group_id" \
    --arg provider "$provider_id" \
    '{
        name: $name,
        description: "agent-network e2e: window_seconds round-trip",
        enabled: true,
        source_groups: [$group],
        destination_provider_ids: [$provider],
        guardrail_ids: [],
        limits: {
            token_limit: {
                enabled: true,
                group_cap: 10000,
                user_cap: 5000,
                window_seconds: 86400
            },
            budget_limit: {
                enabled: true,
                group_cap_usd: 10.0,
                user_cap_usd: 2.5,
                window_seconds: 2592000
            }
        }
    }')

resp=$(nb_api POST /api/agent-network/policies "$policy_body")
policy_id=$(printf '%s' "$resp" | jq -r '.id // ""')
[ -n "$policy_id" ] && [ "$policy_id" != "null" ] \
    || fail "policy create did not return an id" "$resp"
printf '%s' "$policy_id" >"$NB_STATE_DIR/policy-id"
echo "policy id: $policy_id"

# 4. Round-trip assertions: GET the policy back and verify the
#    window_seconds values land on both limit halves. The OLD
#    window_hours / window_days fields must be absent.
got=$(nb_api GET "/api/agent-network/policies/$policy_id")

token_window=$(printf '%s' "$got" | jq -r '.limits.token_limit.window_seconds // empty')
budget_window=$(printf '%s' "$got" | jq -r '.limits.budget_limit.window_seconds // empty')

[ "$token_window" = "86400" ] \
    || fail "token_limit.window_seconds did not round-trip" \
            "expected=86400 got=$token_window body=$got"
[ "$budget_window" = "2592000" ] \
    || fail "budget_limit.window_seconds did not round-trip" \
            "expected=2592000 got=$budget_window body=$got"

# Negative: window_hours / window_days are legacy field names and
# must not be present in the response at all — their presence would
# mean the management server is still emitting the legacy shape.
legacy_h=$(printf '%s' "$got" | jq -r '.limits.token_limit | has("window_hours")')
legacy_d=$(printf '%s' "$got" | jq -r '.limits.token_limit | has("window_days")')
[ "$legacy_h" = "false" ] \
    || fail "legacy window_hours field still present in token_limit response" "$got"
[ "$legacy_d" = "false" ] \
    || fail "legacy window_days field still present in token_limit response" "$got"

echo "token_limit.window_seconds = $token_window"
echo "budget_limit.window_seconds = $budget_window"

pass "policy persisted with window_seconds on both Limits halves"
