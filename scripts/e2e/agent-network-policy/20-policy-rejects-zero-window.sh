#!/usr/bin/env bash
# 20-policy-rejects-zero-window: management must reject a policy whose
# token_limit or budget_limit is enabled but carries window_seconds < 60.
# Anything below the one-minute floor would either be a zero / negative
# window with no reset boundary, or a sub-minute window that produces
# untenable consumption-row volume at scale. The handler's
# validatePolicyLimits guard owes us a 4xx with a useful message.

# shellcheck source=00-env.sh
source "$(dirname "$0")/00-env.sh"

[ -r "$NB_STATE_DIR/group-id" ] && [ -r "$NB_STATE_DIR/provider-id" ] \
    || fail "missing group-id / provider-id state" \
            "run 10-policy-create.sh first to bootstrap prerequisites"
group_id=$(cat "$NB_STATE_DIR/group-id")
provider_id=$(cat "$NB_STATE_DIR/provider-id")

# Build a payload that is well-formed except for window_seconds=30 on
# token_limit (under the 60s minimum). We mark the field enabled so
# the validation path actually runs — a disabled limit is allowed to
# carry zero.
payload=$(jq -n \
    --arg name "$NB_POLICY_NAME-sub-minute" \
    --arg group "$group_id" \
    --arg provider "$provider_id" \
    '{
        name: $name,
        enabled: true,
        source_groups: [$group],
        destination_provider_ids: [$provider],
        guardrail_ids: [],
        limits: {
            token_limit: {
                enabled: true,
                group_cap: 10000,
                user_cap: 5000,
                window_seconds: 30
            },
            budget_limit: {
                enabled: false,
                group_cap_usd: 0,
                user_cap_usd: 0,
                window_seconds: 0
            }
        }
    }')

code=$(nb_api_status POST /api/agent-network/policies "$payload")
[ "$code" = "400" ] || [ "$code" = "422" ] \
    || fail "expected 400/422 on enabled token_limit with window_seconds<60" \
            "got HTTP $code"

# Sweep any policy that may have been mistakenly persisted (defence
# against a future bug; today's handler doesn't get there).
orphan=$(nb_api GET /api/agent-network/policies 2>/dev/null \
    | jq -r --arg name "$NB_POLICY_NAME-sub-minute" '.[] | select(.name == $name) | .id // empty' \
    | head -1)
if [ -n "$orphan" ]; then
    nb_api DELETE "/api/agent-network/policies/$orphan" >/dev/null 2>&1 || true
    fail "policy was persisted despite sub-minute window_seconds" \
         "id=$orphan — handler validation regression"
fi

echo "POST with token_limit.window_seconds=30 rejected with HTTP $code"
pass "validation rejects sub-minute window_seconds when limit is enabled"
