#!/usr/bin/env bash
# 99-cleanup: idempotent teardown. Drops the policy, provider, group,
# and any consumption rows our test created so re-runs start fresh.

# shellcheck source=00-env.sh
source "$(dirname "$0")/00-env.sh"

# Policies first (FK / synth chain owns provider references). Sweep
# every policy whose name STARTS with the e2e prefix so per-run
# instances created by 50 (with $RUN_TAG suffixes) get cleaned up.
nb_api GET /api/agent-network/policies 2>/dev/null \
    | jq -r --arg pfx "$NB_POLICY_NAME" '.[] | select(.name | startswith($pfx)) | .id' \
    | while read -r orphan; do
        [ -n "$orphan" ] || continue
        code=$(curl -fsS -X DELETE -H "Authorization: Token $NB_PAT" \
            -o /dev/null -w '%{http_code}' \
            "$NB_API/api/agent-network/policies/$orphan" 2>&1) || true
        echo "DELETE policy/$orphan -> $code"
    done

# Providers — same prefix sweep. Both the 10-policy-create.sh's main
# provider AND every per-run tight provider 50 minted carry the
# NB_PROVIDER_NAME prefix.
nb_api GET /api/agent-network/providers 2>/dev/null \
    | jq -r --arg pfx "$NB_PROVIDER_NAME" '.[] | select(.name | startswith($pfx)) | .id' \
    | while read -r orphan; do
        [ -n "$orphan" ] || continue
        code=$(curl -fsS -X DELETE -H "Authorization: Token $NB_PAT" \
            -o /dev/null -w '%{http_code}' \
            "$NB_API/api/agent-network/providers/$orphan" 2>&1) || true
        echo "DELETE provider/$orphan -> $code"
    done

# Groups — prefix sweep. /api/groups doesn't error on a
# referenced-elsewhere group; if so, the delete is a no-op and we
# move on.
nb_api GET /api/groups 2>/dev/null \
    | jq -r --arg pfx "$NB_GROUP_NAME" '.[] | select(.name | startswith($pfx)) | .id' \
    | while read -r orphan; do
        [ -n "$orphan" ] || continue
        code=$(curl -fsS -X DELETE -H "Authorization: Token $NB_PAT" \
            -o /dev/null -w '%{http_code}' \
            "$NB_API/api/groups/$orphan" 2>&1) || true
        echo "DELETE group/$orphan -> $code"
    done

# We don't expose a consumption-delete endpoint — the rows survive
# until the management store is recycled. Document the residue here
# so anyone debugging "why are there old e2e rows" knows the source.
remaining=$(nb_api GET /api/agent-network/consumption 2>/dev/null \
    | jq --arg pfx "e2e-anpol-user-" 'map(select(.dimension_id | startswith($pfx))) | length' \
    || echo "0")
[ "$remaining" = "0" ] || \
    echo "(left $remaining e2e consumption rows in the store — there's no delete endpoint yet)"

rm -rf "$NB_STATE_DIR"

pass "tear-down complete (idempotent)"
