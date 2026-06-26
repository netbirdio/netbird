#!/usr/bin/env bash
# Agent-network full end-to-end driver.
#
# One script, many subcommands, so the operator authorizes a single
# `bash scripts/e2e/agent-network-full/e2e.sh <cmd>` invocation instead of a
# stream of ad-hoc docker/netbird/curl commands.
#
# It joins a Docker NetBird client to the local Tilt management, drives LLM
# chat-completions through the agent-network proxy over the tunnel, and asserts
# token/cost/session capture via the REST API and proxy logs.
#
# Secrets (PAT, provider keys, setup key) are read from files / a sourced
# key file and never echoed.
#
# Usage:
#   bash scripts/e2e/agent-network-full/e2e.sh <command>
#
# Commands:
#   key            mint a reusable setup key bound to the Admins group
#   up             run the Docker NetBird client and join management
#   status         show netbird status -d inside the client
#   wait           wait until the proxy peer is Connected (1/1)
#   diag           dump client + proxy3 + relay diagnostics
#   chat M P       chat-completion through the proxy: model M, provider-kind P
#   verify         consumption + recent access-log rows
#   snapshot       save current agent-network config to the scratch dir
#   clean          delete all policies, budget-rules, providers (API teardown)
#   providers      create the five providers from .llm-keys
#   policy         create one policy: Admins -> all five providers
#   down           remove the Docker client container
#   restart-proxy  tilt trigger proxy3 (re-establish its relay link)
#   all            clean -> providers -> policy -> up -> wait -> chat-all -> verify

set -uo pipefail

# --- config ------------------------------------------------------------------
NB_API="${NB_API:-http://localhost:8080}"
NB_PAT_FILE="${NB_PAT_FILE:-/Users/maycon/projects/local-dev/nb-pat}"
LLM_KEYS_FILE="${LLM_KEYS_FILE:-/Users/maycon/.llm-keys}"
CLIENT="${CLIENT:-nb-e2e-agent}"
IMAGE="${IMAGE:-netbird:tilt}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:latest}"
MGMT_URL="${MGMT_URL:-http://host.docker.internal:8080}"
PROXY_HOST="${PROXY_HOST:-mitten.proxy.netbird.local}"
ADMINS_GROUP_NAME="${ADMINS_GROUP_NAME:-Admins}"
DASH_DIR="${DASH_DIR:-/Users/maycon/projects/dashboard}"
DASH_URL="${DASH_URL:-http://localhost:3000}"
DASH_USER="${DASH_USER:-netbird@netbird.io}"
DASH_PASS="${DASH_PASS:-netbird@netbird.io}"
STATE_DIR="${STATE_DIR:-/private/tmp/claude-501/-Users-maycon-projects-netbird/a3fe30e4-5777-47d5-b110-ebc228716026/scratchpad/agentnet-snapshot}"

mkdir -p "$STATE_DIR"

[ -r "$NB_PAT_FILE" ] || { echo "FAIL: cannot read PAT at $NB_PAT_FILE" >&2; exit 2; }
PAT="$(tr -d '\n\r ' <"$NB_PAT_FILE")"
AUTH="Authorization: Token $PAT"
B="$NB_API/api/agent-network"

# --- small helpers -----------------------------------------------------------
log()  { printf '%s\n' "$*" >&2; }
die()  { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

api()  { # METHOD PATH [BODY]
  local m="$1" p="$2" body="${3-}"
  if [ -n "$body" ]; then
    curl -fsS -X "$m" -H "$AUTH" -H "Content-Type: application/json" --data "$body" "$NB_API$p"
  else
    curl -fsS -X "$m" -H "$AUTH" "$NB_API$p"
  fi
}

# proxy_ip resolves the proxy host to its NetBird IP from inside the client.
proxy_ip() {
  docker exec "$CLIENT" sh -c "getent hosts $PROXY_HOST" 2>/dev/null | awk '{print $1; exit}'
}

admins_group_id() {
  api GET /api/groups | jq -r --arg n "$ADMINS_GROUP_NAME" \
    '.[] | select((.name//"")|ascii_downcase==($n|ascii_downcase)) | .id' | head -n1
}

require_llm_keys() {
  [ -r "$LLM_KEYS_FILE" ] || die "cannot read $LLM_KEYS_FILE"
  # shellcheck disable=SC1090
  set -a; . "$LLM_KEYS_FILE"; set +a
}

# --- commands ----------------------------------------------------------------
cmd_snapshot() {
  api GET /settings_unused 2>/dev/null || true
  curl -fsS -H "$AUTH" "$B/settings"      >"$STATE_DIR/settings.json"
  curl -fsS -H "$AUTH" "$B/providers"     >"$STATE_DIR/providers.json"
  curl -fsS -H "$AUTH" "$B/policies"      >"$STATE_DIR/policies.json"
  curl -fsS -H "$AUTH" "$B/budget-rules"  >"$STATE_DIR/budget-rules.json"
  curl -fsS -H "$AUTH" "$NB_API/api/groups" >"$STATE_DIR/groups.json"
  log "snapshot written to $STATE_DIR"
  ls -l "$STATE_DIR" >&2
}

cmd_key() {
  local gid kjson
  gid="$(admins_group_id)"
  [ -n "$gid" ] || die "could not resolve Admins group id"
  kjson="$(api POST /api/setup-keys "{\"name\":\"e2e-agentnet-docker\",\"type\":\"reusable\",\"expires_in\":86400,\"usage_limit\":0,\"auto_groups\":[\"$gid\"],\"ephemeral\":false}")"
  echo "$kjson" | jq -r '.key' >"$STATE_DIR/setup-key.txt"
  chmod 600 "$STATE_DIR/setup-key.txt"
  echo "$kjson" | jq '{id,name,type,state,valid,auto_groups}' >&2
  log "setup key saved (value not printed) to $STATE_DIR/setup-key.txt"
}

cmd_up() {
  [ -r "$STATE_DIR/setup-key.txt" ] || cmd_key
  local key; key="$(cat "$STATE_DIR/setup-key.txt")"
  docker rm -f "$CLIENT" >/dev/null 2>&1 || true
  docker run -d --name "$CLIENT" \
    --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add SYS_RESOURCE \
    --add-host host.docker.internal:host-gateway \
    -e NB_MANAGEMENT_URL="$MGMT_URL" \
    -e NB_SETUP_KEY="$key" \
    -e NB_LOG_LEVEL=info \
    "$IMAGE" >/dev/null
  log "started $CLIENT"
  sleep 6
  docker exec "$CLIENT" netbird status 2>&1 | sed -n '1,14p' >&2
}

cmd_status() { docker exec "$CLIENT" netbird status -d 2>&1; }

cmd_wait() {
  local i=0 line
  while [ "$i" -lt 90 ]; do
    line="$(docker exec "$CLIENT" netbird status 2>/dev/null | grep '^Peers count' || true)"
    log "t=${i}s ${line:-<no status>}"
    case "$line" in *"1/1 Connected"*) log "proxy peer connected"; return 0;; esac
    sleep 5; i=$((i+5))
  done
  log "proxy peer did not connect within ${i}s"
  return 1
}

cmd_diag() {
  log "===== client: peers count ====="
  docker exec "$CLIENT" netbird status 2>&1 | grep -E '^(Management|Signal|Relays|Peers)' >&2 || true
  log "===== client: relay/handshake (last 15) ====="
  docker exec "$CLIENT" sh -c 'tail -n 400 /var/log/netbird/client.log' 2>/dev/null \
    | grep -iE 'relay|handshake|offer|answer|error' | tail -15 >&2 || true
  log "===== proxy3: relay (last 15) ====="
  docker logs local-dev-proxy3-1 2>&1 | grep -iE 'relay|signal|handshake|offer|answer' | tail -15 >&2 || true
  log "===== mgmt: proxy peer online ====="
  curl -fsS -H "$AUTH" "$NB_API/api/peers" \
    | jq -r '.[] | select((.name//"")|test("^proxy-")) | "\(.name) connected=\(.connected) last_seen=\(.last_seen)"' >&2 || true
}

cmd_restart_proxy() {
  command -v tilt >/dev/null 2>&1 || die "tilt not on PATH"
  tilt trigger proxy3 && log "triggered proxy3"
}

# cmd_chat MODEL KIND  — KIND in: chat (POST /v1/chat/completions),
# messages (POST /v1/messages, anthropic body).
CHAT_RESP="$STATE_DIR/last-chat.json"
CHAT_PROMPT_DEFAULT="Reply with exactly: pong"

# _chat MODEL [KIND] [PROMPT] — POST through the proxy from $CHAT_CLIENT
# (defaults to $CLIENT). Echoes the HTTP status code on stdout; writes the
# response body to $CHAT_RESP. Returns 000 if the proxy host won't resolve.
_chat() {
  local model="$1" kind="${2:-chat}" prompt="${3:-$CHAT_PROMPT_DEFAULT}"
  local client="${CHAT_CLIENT:-$CLIENT}" ip path body out code attempt
  local extra_hdr=()
  case "$kind" in
    messages)
      path="/v1/messages"; extra_hdr=(-H "anthropic-version: 2023-06-01")
      body="$(jq -n --arg m "$model" --arg p "$prompt" '{model:$m,max_tokens:64,messages:[{role:"user",content:$p}]}')" ;;
    *)
      path="/v1/chat/completions"
      body="$(jq -n --arg m "$model" --arg p "$prompt" '{model:$m,messages:[{role:"user",content:$p}]}')" ;;
  esac
  # Re-resolve the proxy IP and retry on connection failure (000): a config
  # change churns the proxy peer's NetBird IP, so a freshly-joined client may
  # need a few seconds for its tunnel + magic DNS to converge.
  code=000
  for attempt in $(seq 1 "${CHAT_RETRIES:-6}"); do
    ip="$(CLIENT="$client" proxy_ip)"
    if [ -n "$ip" ]; then
      out="$(docker run --rm --network "container:$client" "$CURL_IMAGE" \
        -sSk --connect-timeout 5 --max-time 90 --resolve "$PROXY_HOST:443:$ip" \
        -w $'\n%{http_code}' -X POST "https://$PROXY_HOST$path" \
        -H "Content-Type: application/json" ${extra_hdr[@]+"${extra_hdr[@]}"} --data "$body")"
      code="$(printf '%s' "$out" | tail -n1)"
      printf '%s' "$out" | sed '$d' >"$CHAT_RESP"
    fi
    [ "$code" != 000 ] && break
    sleep 4
  done
  echo "$code"
}

cmd_chat() {
  local code
  log "POST $PROXY_HOST (model=$1 kind=${2:-chat} client=${CHAT_CLIENT:-$CLIENT})"
  code="$(_chat "$@")"
  cat "$CHAT_RESP" 2>/dev/null
  printf '\n[http %s]\n' "$code"
}

cmd_verify() {
  log "===== consumption ====="
  api GET /api/agent-network/consumption | jq -r '.[] | "\(.dimension_kind)/\(.dimension_id) tokens_in=\(.tokens_input) tokens_out=\(.tokens_output) cost=\(.cost_usd // 0)"' >&2 || true
  log "===== last 10 access-log rows ====="
  api GET /api/agent-network/access-logs | jq -r '.data[0:10][] | "\(.timestamp) provider=\(.provider) model=\(.model) status=\(.status_code) decision=\(.decision) src=\(.source_ip) session=\(.session_id // "-") in=\(.input_tokens // 0) out=\(.output_tokens // 0) cost=\(.cost_usd // 0)"' >&2 || true
}

cmd_clean() {
  cmd_snapshot
  local id
  for id in $(api GET /api/agent-network/policies | jq -r '.[].id'); do
    api DELETE "/api/agent-network/policies/$id" >/dev/null && log "deleted policy $id"
  done
  for id in $(api GET /api/agent-network/budget-rules | jq -r '.[].id'); do
    api DELETE "/api/agent-network/budget-rules/$id" >/dev/null && log "deleted budget-rule $id"
  done
  for id in $(api GET /api/agent-network/providers | jq -r '.[].id'); do
    api DELETE "/api/agent-network/providers/$id" >/dev/null && log "deleted provider $id"
  done
  log "account cleaned"
}

# create_provider NAME PROVIDER_ID UPSTREAM_URL API_KEY
create_provider() {
  local name="$1" pid="$2" url="$3" key="$4" body resp
  [ -n "$key" ] || { log "skip $name: empty key"; return 0; }
  body="$(jq -n --arg n "$name" --arg p "$pid" --arg u "$url" --arg k "$key" \
    '{name:$n,provider_id:$p,upstream_url:$u,api_key:$k,enabled:true}')"
  resp="$(api POST /api/agent-network/providers "$body")" || { log "create $name FAILED"; return 1; }
  echo "$resp" | jq -r '"created provider \(.name) id=\(.id) provider_id=\(.provider_id)"' >&2
  echo "$resp" | jq -r '.id'
}

cmd_providers() {
  require_llm_keys
  : >"$STATE_DIR/provider-ids.txt"
  create_provider "OpenAI API"           openai_api            "https://api.openai.com"     "${OPENAI_TOKEN:-}"     >>"$STATE_DIR/provider-ids.txt"
  create_provider "Anthropic API"        anthropic_api         "https://api.anthropic.com"  "${ANTHROPIC_TOKEN:-}"  >>"$STATE_DIR/provider-ids.txt"
  create_provider "Vercel AI Gateway"    vercel_ai_gateway     "${VERCEL_URL:-}"            "${VERCEL_TOKEN:-}"     >>"$STATE_DIR/provider-ids.txt"
  create_provider "OpenRouter"           openrouter            "${OPENROUTER_URL:-}"        "${OPENROUTER_TOKEN:-}" >>"$STATE_DIR/provider-ids.txt"
  create_provider "Cloudflare AI Gateway" cloudflare_ai_gateway "${CLOUDFLARE_URL:-}"       "${CLOUDFLARE_TOKEN:-}" >>"$STATE_DIR/provider-ids.txt"
  log "provider ids:"; cat "$STATE_DIR/provider-ids.txt" >&2
}

cmd_policy() {
  local gid ids body
  gid="$(admins_group_id)"; [ -n "$gid" ] || die "no Admins group"
  ids="$(api GET /api/agent-network/providers | jq -c '[.[].id]')"
  body="$(jq -n --arg n "e2e-all-providers" --arg g "$gid" --argjson dst "$ids" '{
    name:$n, description:"e2e: Admins to all providers", enabled:true,
    source_groups:[$g], destination_provider_ids:$dst, guardrail_ids:[],
    limits:{ budget_limit:{enabled:true,group_cap_usd:1000000,user_cap_usd:1000000,window_seconds:2592000},
             token_limit:{enabled:false,group_cap:0,user_cap:0,window_seconds:60} }
  }')"
  api POST /api/agent-network/policies "$body" | jq -r '"created policy \(.name) id=\(.id) dst=\(.destination_provider_ids|length) providers"' >&2
}

# set_enabled PROVIDER_ID BOOL — PUT the provider back with enabled toggled,
# preserving its required fields and keeping the sealed key (api_key omitted).
set_enabled() {
  local pid="$1" en="$2" cur body
  cur="$(api GET /api/agent-network/providers | jq -c --arg id "$pid" '.[] | select(.id==$id)')"
  [ -n "$cur" ] || { log "no provider $pid"; return 1; }
  body="$(echo "$cur" | jq -c --argjson en "$en" '{name,provider_id,upstream_url,enabled:$en} + (if .extra_values then {extra_values} else {} end)')"
  api PUT "/api/agent-network/providers/$pid" "$body" >/dev/null
}

# cmd_isolate NAME — leave only the named provider enabled (sole catch-all),
# so a request routes to it without first-party-vendor or first-catch-all
# interference. Matches NAME case-insensitively against provider .name.
cmd_isolate() {
  local want="$1" id name en
  api GET /api/agent-network/providers | jq -r '.[] | "\(.id)\t\(.name)"' | while IFS=$'\t' read -r id name; do
    case "$(echo "$name" | tr '[:upper:]' '[:lower:]')" in
      *"$(echo "$want" | tr '[:upper:]' '[:lower:]')"*) en=true ;;
      *) en=false ;;
    esac
    set_enabled "$id" "$en" && log "$name enabled=$en"
  done
}

cmd_enable_all() {
  local id
  for id in $(api GET /api/agent-network/providers | jq -r '.[].id'); do
    set_enabled "$id" true && log "enabled $id"
  done
}

# cmd_dashboard — drive the live :3000 dashboard (../dashboard repo) with
# Playwright, asserting the API-created providers/policy render in the UI.
cmd_dashboard() {
  command -v node >/dev/null 2>&1 || die "node not on PATH"
  [ -f "$DASH_DIR/e2e/live-agent-network.mjs" ] || die "dashboard script missing in $DASH_DIR/e2e"
  ( cd "$DASH_DIR" && BASE_URL="$DASH_URL" DASH_USER="$DASH_USER" DASH_PASS="$DASH_PASS" node e2e/live-agent-network.mjs )
}

cmd_down() { docker rm -f "$CLIENT" >/dev/null 2>&1 && log "removed $CLIENT" || log "no container"; }

cmd_all() {
  cmd_clean
  cmd_providers
  cmd_policy
  cmd_up
  cmd_wait || { cmd_diag; die "tunnel to proxy not established"; }
  log "===== chat: OpenAI ====="            ; cmd_chat gpt-5.4 chat
  log "===== chat: Anthropic ====="          ; cmd_chat claude-haiku-4-5 messages
  log "===== chat: Vercel (openai/...) ====="; cmd_chat openai/gpt-4o-mini chat
  log "===== chat: OpenRouter (openai/...) =="; cmd_chat openai/gpt-4o-mini chat
  sleep 3
  cmd_verify
}

# --- scenario helpers --------------------------------------------------------
FAILS=0
ok()   { log "  PASS: $1"; }
bad()  { log "  FAIL: $1"; FAILS=$((FAILS+1)); }
expect_code() { # WANT GOT LABEL
  if [ "$2" = "$1" ]; then ok "$3 (http $2)"; else bad "$3 (want $1, got $2)"; fi
}

# wait_tunnel [CLIENT] — poll silently until the proxy peer is 1/1 Connected.
wait_tunnel() {
  local c="${1:-$CLIENT}" i=0
  while [ "$i" -lt 60 ]; do
    docker exec "$c" netbird status 2>/dev/null | grep -q '1/1 Connected' && return 0
    sleep 3; i=$((i+3))
  done
  return 1
}

# wait_chat_ready CLIENT KIND MODEL — poll a real request from CLIENT until it
# returns a non-000 status, i.e. the tunnel + magic DNS + WG handshake to the
# proxy peer have all converged. Single-attempt probes pace the outer loop.
# Note: a netbird down/up bounce does NOT help here and is actively harmful —
# the peer is already in the net-map (status shows 0/1, i.e. known-not-connected),
# so the blocker is the WG handshake to a freshly-churned proxy peer, and
# bouncing just resets an in-progress slow handshake. We only wait it out.
wait_chat_ready() {
  local c="$1" kind="${2:-chat}" model="${3:-gpt-5.4}" rc i=0
  while [ "$i" -lt 30 ]; do
    rc="$(CHAT_CLIENT="$c" CHAT_RETRIES=1 _chat "$model" "$kind")"
    [ "$rc" != 000 ] && { echo "$rc"; return 0; }
    i=$((i + 5))
    sleep 5
  done
  echo 000
  return 1
}

# wait_peer_connected CLIENT [TIMEOUT] — poll until the client reports the proxy
# peer as 1/1 Connected, i.e. the proxy peer has re-stabilised after a churn.
# Used to settle the peer before joining a fresh client into it.
wait_peer_connected() {
  local c="$1" timeout="${2:-180}" i=0
  while [ "$i" -lt "$timeout" ]; do
    docker exec "$c" netbird status 2>/dev/null | grep -q '1/1 Connected' && return 0
    sleep 5
    i=$((i + 5))
  done
  return 1
}

provider_id_by_name() { api GET /api/agent-network/providers | jq -r --arg n "$1" '.[] | select(.name==$n) | .id' | head -n1; }
access_log_total()    { api GET /api/agent-network/access-logs | jq -r '.total_records'; }
access_log_top()      { api GET /api/agent-network/access-logs | jq -r ".data[0].$1 // \"\""; }

# ensure_group NAME — return the id of group NAME, creating it if absent.
ensure_group() {
  local name="$1" id
  id="$(api GET /api/groups | jq -r --arg n "$name" '.[] | select(.name==$n) | .id' | head -n1)"
  if [ -z "$id" ] || [ "$id" = null ]; then
    id="$(api POST /api/groups "$(jq -n --arg n "$name" '{name:$n}')" | jq -r '.id')"
  fi
  echo "$id"
}

# policy_put_limits LIMITS_JSON — replace the e2e-all-providers policy limits.
policy_put_limits() {
  local pol id body
  pol="$(api GET /api/agent-network/policies | jq -c '.[] | select(.name=="e2e-all-providers")')"
  id="$(echo "$pol" | jq -r '.id')"
  [ -n "$id" ] && [ "$id" != null ] || die "e2e-all-providers policy missing (run 'policy' first)"
  body="$(echo "$pol" | jq -c --argjson L "$1" '{name,description,enabled,source_groups,destination_provider_ids,guardrail_ids,limits:$L}')"
  api PUT "/api/agent-network/policies/$id" "$body" >/dev/null
}

settings_put() { api PUT /api/agent-network/settings "$1" >/dev/null; }

# --- scenarios ---------------------------------------------------------------

# Scenario 1: policy token-cap enforcement. Seed usage under a high cap, drop
# the cap to 1 token so the next call is denied, then restore and confirm
# recovery. Deterministic regardless of prior window usage.
cmd_scenario_budget() {
  log "### scenario: policy token-cap enforcement (deny + recovery) ###"
  # Seed AND enforce in the same 3600s token window (counters are per-window).
  policy_put_limits '{"budget_limit":{"enabled":false,"group_cap_usd":0,"user_cap_usd":0,"window_seconds":3600},"token_limit":{"enabled":true,"group_cap":100000,"user_cap":100000,"window_seconds":3600}}'
  wait_tunnel; sleep 2
  expect_code 200 "$(_chat gpt-5.4 chat)" "seed call under high token cap (books usage into 3600s window)"
  # Drop the cap to 1 in the SAME window so the seeded usage exhausts it.
  policy_put_limits '{"budget_limit":{"enabled":false,"group_cap_usd":0,"user_cap_usd":0,"window_seconds":3600},"token_limit":{"enabled":true,"group_cap":1,"user_cap":1,"window_seconds":3600}}'
  wait_tunnel; sleep 2
  local code; code="$(_chat gpt-5.4 chat)"
  expect_code 403 "$code" "call denied once token cap (1) is exhausted"
  log "  deny envelope: $(cat "$CHAT_RESP")"
  policy_put_limits '{"budget_limit":{"enabled":true,"group_cap_usd":1000000,"user_cap_usd":1000000,"window_seconds":2592000},"token_limit":{"enabled":false,"group_cap":0,"user_cap":0,"window_seconds":3600}}'
  wait_tunnel; sleep 2
  expect_code 200 "$(_chat gpt-5.4 chat)" "call allowed again after cap restored"
}

# Scenario 2: account-level budget rule (separate from policy limits). A rule
# targeting Admins with a 1-token cap must deny via the same gRPC check loop;
# deleting it restores access.
cmd_scenario_budget_rule() {
  log "### scenario: account budget-rule enforcement ###"
  local gid rid
  gid="$(admins_group_id)"
  # High cap first so the seed call books usage into the rule's 3600s window.
  rid="$(api POST /api/agent-network/budget-rules "$(jq -n --arg g "$gid" '{name:"e2e-tight-rule",enabled:true,target_groups:[$g],target_users:[],limits:{budget_limit:{enabled:false,group_cap_usd:0,user_cap_usd:0,window_seconds:3600},token_limit:{enabled:true,group_cap:100000,user_cap:100000,window_seconds:3600}}}')" | jq -r '.id')"
  log "  created budget-rule $rid (group token cap=100000)"
  wait_tunnel; sleep 2
  expect_code 200 "$(_chat gpt-5.4 chat)" "seed call under high account cap"
  # Tighten the same rule/window to 1 so the seeded usage exhausts it.
  api PUT "/api/agent-network/budget-rules/$rid" "$(jq -n --arg g "$gid" '{name:"e2e-tight-rule",enabled:true,target_groups:[$g],target_users:[],limits:{budget_limit:{enabled:false,group_cap_usd:0,user_cap_usd:0,window_seconds:3600},token_limit:{enabled:true,group_cap:1,user_cap:1,window_seconds:3600}}}')" >/dev/null
  log "  tightened budget-rule $rid (group token cap=1)"
  wait_tunnel; sleep 2
  expect_code 403 "$(_chat gpt-5.4 chat)" "account budget-rule denies when cap exhausted"
  api DELETE "/api/agent-network/budget-rules/$rid" >/dev/null && log "  deleted budget-rule $rid"
  wait_tunnel; sleep 2
  expect_code 200 "$(_chat gpt-5.4 chat)" "allowed again after budget-rule removed"
}

# Scenario 3: multiple groups + policies + destination scoping. A 2nd Docker
# client joins a 2nd group; each group's policy authorises a different
# provider. Cross-provider requests must be denied.
cmd_scenario_multigroup() {
  log "### scenario: multi-group / multi-policy destination scoping ###"
  local gidA gidB oai ant keyB polAllId
  gidA="$(admins_group_id)"; gidB="$(ensure_group e2e-grp-b)"
  oai="$(provider_id_by_name 'OpenAI API')"; ant="$(provider_id_by_name 'Anthropic API')"
  log "  groups: Admins=$gidA grp-b=$gidB ; providers: openai=$oai anthropic=$ant"

  # Disable the broad e2e policy; add two narrow ones.
  polAllId="$(api GET /api/agent-network/policies | jq -r '.[] | select(.name=="e2e-all-providers") | .id')"
  [ -n "$polAllId" ] && api PUT "/api/agent-network/policies/$polAllId" \
    "$(api GET /api/agent-network/policies | jq -c --arg id "$polAllId" '.[] | select(.id==$id) | {name,description,enabled:false,source_groups,destination_provider_ids,guardrail_ids,limits}')" >/dev/null
  local hi='{"budget_limit":{"enabled":true,"group_cap_usd":1000000,"user_cap_usd":1000000,"window_seconds":2592000},"token_limit":{"enabled":false,"group_cap":0,"user_cap":0,"window_seconds":60}}'
  local polA polB
  polA="$(api POST /api/agent-network/policies "$(jq -n --arg g "$gidA" --arg p "$oai" --argjson L "$hi" '{name:"e2e-A-admins-openai",enabled:true,source_groups:[$g],destination_provider_ids:[$p],guardrail_ids:[],limits:$L}')" | jq -r '.id')"
  polB="$(api POST /api/agent-network/policies "$(jq -n --arg g "$gidB" --arg p "$ant" --argjson L "$hi" '{name:"e2e-B-grpb-anthropic",enabled:true,source_groups:[$g],destination_provider_ids:[$p],guardrail_ids:[],limits:$L}')" | jq -r '.id')"
  log "  policy A (Admins->OpenAI)=$polA ; policy B (grp-b->Anthropic)=$polB"

  # The policy swap above re-synthesises the agent-network service and adds a
  # new source group (grp-b), which churns the proxy peer and forces it to
  # absorb the new authorisation. Wait for the peer to re-stabilise (client A
  # reconnects to the new peer) before joining B, so B handshakes into a stable
  # peer instead of racing the churn — otherwise the proxy never answers B's
  # offers and it sits at 0/1 Connected.
  if ! wait_peer_connected "$CLIENT" 30; then
    log "  warning: proxy peer did not re-stabilise for client A within 30s"
  fi
  sleep 5

  # 2nd client bound to grp-b.
  keyB="$(api POST /api/setup-keys "$(jq -n --arg g "$gidB" '{name:"e2e-agentnet-docker-b",type:"reusable",expires_in:86400,usage_limit:0,auto_groups:[$g],ephemeral:false}')" | jq -r '.key')"
  docker rm -f "${CLIENT}-b" >/dev/null 2>&1 || true
  docker run -d --name "${CLIENT}-b" --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add SYS_RESOURCE \
    --add-host host.docker.internal:host-gateway -e NB_MANAGEMENT_URL="$MGMT_URL" -e NB_SETUP_KEY="$keyB" \
    -e NB_LOG_LEVEL=info "$IMAGE" >/dev/null
  log "  started ${CLIENT}-b (grp-b)"
  # Gate on real end-to-end connectivity: a freshly-authorised group's client
  # takes ~1-2 min for the proxy to absorb and answer its WG handshake.
  local ra rb
  ra="$(wait_chat_ready "$CLIENT" chat gpt-5.4)"
  rb="$(wait_chat_ready "${CLIENT}-b" messages claude-haiku-4-5)"
  log "  connectivity ready: A(probe=$ra) B(probe=$rb)"

  log "  -- client A (Admins) --"
  CHAT_CLIENT="$CLIENT"   expect_code 200 "$(CHAT_CLIENT="$CLIENT"   _chat gpt-5.4 chat)"          "A->OpenAI authorised"
  CHAT_CLIENT="$CLIENT"   expect_code 403 "$(CHAT_CLIENT="$CLIENT"   _chat claude-haiku-4-5 messages)" "A->Anthropic denied (not in policy A)"
  log "  -- client B (grp-b) --"
  CHAT_CLIENT="${CLIENT}-b" expect_code 200 "$(CHAT_CLIENT="${CLIENT}-b" _chat claude-haiku-4-5 messages)" "B->Anthropic authorised"
  CHAT_CLIENT="${CLIENT}-b" expect_code 403 "$(CHAT_CLIENT="${CLIENT}-b" _chat gpt-5.4 chat)"          "B->OpenAI denied (not in policy B)"

  # Restore: drop A/B, re-enable the broad policy.
  api DELETE "/api/agent-network/policies/$polA" >/dev/null 2>&1 || true
  api DELETE "/api/agent-network/policies/$polB" >/dev/null 2>&1 || true
  [ -n "$polAllId" ] && api PUT "/api/agent-network/policies/$polAllId" \
    "$(api GET /api/agent-network/policies | jq -c --arg id "$polAllId" '.[] | select(.id==$id) | {name,description,enabled:true,source_groups,destination_provider_ids,guardrail_ids,limits}')" >/dev/null
  docker rm -f "${CLIENT}-b" >/dev/null 2>&1 || true
  log "  restored broad policy, removed client B"
}

# Scenario 4: log-collection + prompt-collection + redaction settings.
cmd_scenario_logs() {
  log "### scenario: log/prompt-collection + redaction settings ###"
  settings_put '{"enable_log_collection":true,"enable_prompt_collection":true,"redact_pii":false}'
  wait_tunnel; sleep 3

  # (a) log collection OFF -> no new access-log row.
  local before after
  before="$(access_log_total)"
  settings_put '{"enable_log_collection":false,"enable_prompt_collection":true,"redact_pii":false}'
  wait_tunnel; sleep 3
  expect_code 200 "$(_chat gpt-5.4 chat)" "request still served with logging off"
  sleep 3; after="$(access_log_total)"
  if [ "$after" = "$before" ]; then ok "log collection OFF -> no new row ($before==$after)"; else bad "log collection OFF still wrote a row ($before->$after)"; fi

  # (b) log ON, prompt OFF -> row present but request_prompt empty.
  settings_put '{"enable_log_collection":true,"enable_prompt_collection":false,"redact_pii":false}'
  wait_tunnel; sleep 3
  expect_code 200 "$(_chat gpt-5.4 chat "this prompt text must NOT be stored")" "served with prompt collection off"
  sleep 3
  local p; p="$(access_log_top request_prompt)"
  if [ -z "$p" ]; then ok "prompt collection OFF -> request_prompt empty"; else bad "prompt stored despite collection off: [$p]"; fi

  # (c) prompt ON + redact ON -> PII scrubbed from stored prompt.
  settings_put '{"enable_log_collection":true,"enable_prompt_collection":true,"redact_pii":true}'
  wait_tunnel; sleep 3
  expect_code 200 "$(_chat gpt-5.4 chat "Contact john.doe@example.com, SSN 123-45-6789, phone 555-123-4567")" "served with redaction on"
  sleep 3
  local stored; stored="$(access_log_top request_prompt)"
  log "  stored prompt: [$stored]"
  case "$stored" in
    *john.doe@example.com*) bad "email leaked into stored prompt" ;;
    *) ok "email redacted from stored prompt" ;;
  esac
  case "$stored" in
    *123-45-6789*) bad "SSN leaked into stored prompt" ;;
    *) ok "SSN redacted from stored prompt" ;;
  esac

  settings_put '{"enable_log_collection":true,"enable_prompt_collection":true,"redact_pii":false}'
  log "  restored settings (log on, prompt on, redact off)"
}

# Scenario 5: per-user cap isolated from the group cap. Seed under a high cap,
# then keep the group cap high but drop the USER cap to 1 — the deny must come
# from the user dimension, proving per-user accounting is independent.
cmd_scenario_user_cap() {
  log "### scenario: per-user token cap (isolated from group cap) ###"
  policy_put_limits '{"budget_limit":{"enabled":false,"group_cap_usd":0,"user_cap_usd":0,"window_seconds":3600},"token_limit":{"enabled":true,"group_cap":100000,"user_cap":100000,"window_seconds":3600}}'
  wait_tunnel; sleep 2
  expect_code 200 "$(_chat gpt-5.4 chat)" "seed call (books user+group usage into 3600s window)"
  # Group cap stays huge; only the user cap is exhausted.
  policy_put_limits '{"budget_limit":{"enabled":false,"group_cap_usd":0,"user_cap_usd":0,"window_seconds":3600},"token_limit":{"enabled":true,"group_cap":100000,"user_cap":1,"window_seconds":3600}}'
  wait_tunnel; sleep 2
  expect_code 403 "$(_chat gpt-5.4 chat)" "denied by USER cap=1 while group cap=100000 has headroom"
  log "  deny: $(cat "$CHAT_RESP")"
  policy_put_limits '{"budget_limit":{"enabled":true,"group_cap_usd":1000000,"user_cap_usd":1000000,"window_seconds":2592000},"token_limit":{"enabled":false,"group_cap":0,"user_cap":0,"window_seconds":3600}}'
  wait_tunnel; sleep 2
  expect_code 200 "$(_chat gpt-5.4 chat)" "allowed again after user cap lifted"
}

# Scenario 6: guardrail model-allowlist blocking. Attach a guardrail allowing
# only gpt-5.4; a request for any other model must be denied (model_blocked),
# while the allowed model passes.
cmd_scenario_guardrail() {
  log "### scenario: guardrail model-allowlist blocking ###"
  local gid polId
  gid="$(api POST /api/agent-network/guardrails "$(jq -n '{name:"e2e-allowlist",description:"e2e: only gpt-5.4",checks:{model_allowlist:{enabled:true,models:["gpt-5.4"]},prompt_capture:{enabled:true,redact_pii:false}}}')" | jq -r '.id')"
  log "  created guardrail $gid (allow only gpt-5.4)"
  local pol; pol="$(api GET /api/agent-network/policies | jq -c '.[] | select(.name=="e2e-all-providers")')"
  polId="$(echo "$pol" | jq -r '.id')"
  api PUT "/api/agent-network/policies/$polId" "$(echo "$pol" | jq -c --arg g "$gid" '{name,description,enabled,source_groups,destination_provider_ids,guardrail_ids:[$g],limits}')" >/dev/null
  wait_tunnel; sleep 2
  expect_code 403 "$(_chat gpt-4o-mini chat)" "model not in allowlist is blocked"
  log "  deny: $(cat "$CHAT_RESP")"
  expect_code 200 "$(_chat gpt-5.4 chat)" "allowlisted model passes"
  # Detach + delete.
  api PUT "/api/agent-network/policies/$polId" "$(echo "$pol" | jq -c '{name,description,enabled,source_groups,destination_provider_ids,guardrail_ids:[],limits}')" >/dev/null
  api DELETE "/api/agent-network/guardrails/$gid" >/dev/null && log "  detached + deleted guardrail $gid"
}

# _chat_stream MODEL — streaming chat completion (SSE) with usage included.
# Echoes the HTTP status; writes the raw SSE stream to $CHAT_RESP.
_chat_stream() {
  local model="$1" client="${CHAT_CLIENT:-$CLIENT}" ip body out code
  ip="$(CLIENT="$client" proxy_ip)"; [ -n "$ip" ] || { echo 000; return; }
  body="$(jq -n --arg m "$model" '{model:$m,stream:true,stream_options:{include_usage:true},messages:[{role:"user",content:"Reply with exactly: pong"}]}')"
  out="$(docker run --rm --network "container:$client" "$CURL_IMAGE" \
    -sSkN --connect-timeout 5 --max-time 90 --resolve "$PROXY_HOST:443:$ip" \
    -w $'\n%{http_code}' -X POST "https://$PROXY_HOST/v1/chat/completions" \
    -H "Content-Type: application/json" --data "$body")"
  code="$(printf '%s' "$out" | tail -n1)"
  printf '%s' "$out" | sed '$d' >"$CHAT_RESP"
  echo "$code"
}

# Scenario 7: streaming (SSE) token capture. The proxy must accumulate token
# usage from the streamed deltas and persist it on the access-log row.
cmd_scenario_streaming() {
  log "### scenario: streaming (SSE) token capture ###"
  policy_put_limits '{"budget_limit":{"enabled":true,"group_cap_usd":1000000,"user_cap_usd":1000000,"window_seconds":2592000},"token_limit":{"enabled":false,"group_cap":0,"user_cap":0,"window_seconds":3600}}'
  wait_tunnel; sleep 2
  expect_code 200 "$(_chat_stream gpt-5.4)" "streaming request served"
  if grep -q 'data: \[DONE\]' "$CHAT_RESP"; then ok "SSE stream terminated with [DONE]"; else bad "no [DONE] terminator in SSE stream"; fi
  if grep -q '"delta"' "$CHAT_RESP"; then ok "SSE carried incremental deltas"; else bad "no delta chunks in SSE stream"; fi
  sleep 3
  local st in out
  st="$(access_log_top stream)"; in="$(access_log_top input_tokens)"; out="$(access_log_top output_tokens)"
  log "  access-log: stream=$st input_tokens=$in output_tokens=$out"
  if [ "$st" = true ]; then ok "access-log row flagged stream=true"; else bad "stream flag not set (got $st)"; fi
  if [ "${in:-0}" -gt 0 ] 2>/dev/null && [ "${out:-0}" -gt 0 ] 2>/dev/null; then ok "streamed token usage captured (in=$in out=$out)"; else bad "streamed token usage not captured (in=$in out=$out)"; fi
}

# wait_for_mgmt — poll the management API until it accepts authed requests.
wait_for_mgmt() {
  local i=0
  while [ "$i" -lt 90 ]; do
    curl -fsS -o /dev/null --max-time 2 -H "$AUTH" "$NB_API/api/users" 2>/dev/null && return 0
    sleep 2; i=$((i+2))
  done
  return 1
}

# Scenario 8: access-log retention pruning. The sweep deletes rows older than
# now - retention_days and runs on management startup. We clone an existing row
# to a synthetic 2020-dated id, set retention to 365d (so only that far-past
# row is eligible — real 2026 rows are safe), restart management to trigger the
# sweep, and assert the synthetic row is gone while real rows survive.
cmd_scenario_retention() {
  log "### scenario: access-log retention pruning ###"
  local DB="/Users/maycon/projects/wt_testing_data/store.db" acct="d68ag3p31576fp2gmnag" sid="e2e-retention-2020"
  command -v sqlite3 >/dev/null 2>&1 || { bad "sqlite3 not on PATH"; return; }
  [ -w "$DB" ] || { bad "store.db not writable at $DB"; return; }
  local before mid after syn
  before="$(sqlite3 "$DB" "SELECT count(*) FROM agent_network_access_log WHERE account_id='$acct'")"
  sqlite3 "$DB" "PRAGMA busy_timeout=8000;
    DELETE FROM agent_network_access_log WHERE id='$sid';
    CREATE TEMP TABLE _t AS SELECT * FROM agent_network_access_log WHERE account_id='$acct' LIMIT 1;
    UPDATE _t SET id='$sid', timestamp='2020-01-01 00:00:00.000000000+00:00';
    INSERT INTO agent_network_access_log SELECT * FROM _t;" 2>&1 | sed 's/^/  sqlite: /' >&2 || true
  mid="$(sqlite3 "$DB" "SELECT count(*) FROM agent_network_access_log WHERE account_id='$acct'")"
  if [ "$mid" = "$((before+1))" ]; then ok "synthetic 2020 row inserted ($before -> $mid)"; else bad "insert failed ($before -> $mid)"; return; fi

  settings_put '{"enable_log_collection":true,"enable_prompt_collection":true,"redact_pii":false,"access_log_retention_days":365}'
  log "  retention=365d; restarting management to trigger the startup sweep..."
  tilt trigger management >/dev/null 2>&1 || bad "tilt trigger management failed"
  wait_for_mgmt || bad "management did not come back up"
  sleep 4

  syn="$(sqlite3 "$DB" "SELECT count(*) FROM agent_network_access_log WHERE id='$sid'")"
  after="$(sqlite3 "$DB" "SELECT count(*) FROM agent_network_access_log WHERE account_id='$acct'")"
  if [ "$syn" = 0 ]; then ok "synthetic 2020 row pruned by retention sweep"; else bad "synthetic row survived (sweep didn't prune)"; fi
  if [ "$after" = "$before" ]; then ok "real rows preserved (count back to $before)"; else bad "real row count changed ($before -> $after)"; fi

  settings_put '{"enable_log_collection":true,"enable_prompt_collection":true,"redact_pii":false,"access_log_retention_days":0}'
  sqlite3 "$DB" "DELETE FROM agent_network_access_log WHERE id='$sid'" 2>/dev/null || true
  log "  restored retention=0 (keep forever); re-establishing tunnel"
  wait_tunnel >/dev/null 2>&1 || true
}

# vertex_request IP PATH BODY — POST a Vertex rawPredict through the client
# sidecar; echo the HTTP status and stash the response body in VTX_RESP. Shared
# by the Vertex scenario's initial probe and its live-update propagation checks.
VTX_RESP=""
vertex_request() {
  local ip="$1" path="$2" body="$3" out
  out="$(docker run --rm --network "container:$CLIENT" "$CURL_IMAGE" \
    -sSk --connect-timeout 5 --max-time 90 --resolve "$PROXY_HOST:443:$ip" \
    -w $'\n%{http_code}' -X POST "https://$PROXY_HOST$path" \
    -H "Content-Type: application/json" --data "$body")"
  VTX_RESP="$(printf '%s' "$out" | sed '$d')"
  printf '%s' "$out" | tail -n1
}

# bedrock_probe LABEL PATH BODY IP — POST a Bedrock request via the client
# sidecar and assert the pipeline. 200 -> full pass (+ token metering); a
# Bedrock-origin 404 (account use-case gate / model access) -> pipeline OK
# (routing + bearer auth reached the model); 401/403 -> fail.
bedrock_probe() {
  local label="$1" path="$2" body="$3" ip="$4" out code resp
  out="$(docker run --rm --network "container:$CLIENT" "$CURL_IMAGE" \
    -sSk --connect-timeout 5 --max-time 90 --resolve "$PROXY_HOST:443:$ip" \
    -w $'\n%{http_code}' -X POST "https://$PROXY_HOST$path" \
    -H "Content-Type: application/json" --data "$body")"
  code="$(printf '%s' "$out" | tail -n1)"
  resp="$(printf '%s' "$out" | sed '$d')"
  log "  bedrock $label -> http=$code"
  case "$code" in
    200)
      ok "Bedrock $label 200 (path->model parse, routed, bearer accepted)"
      sleep 3
      local vin vout
      vin="$(access_log_top input_tokens)"; vout="$(access_log_top output_tokens)"
      if [ "${vin:-0}" -gt 0 ] 2>/dev/null && [ "${vout:-0}" -gt 0 ] 2>/dev/null; then ok "Bedrock $label usage metered (in=$vin out=$vout)"; else bad "Bedrock $label usage not metered (in=$vin out=$vout)"; fi
      ;;
    404)
      case "$resp" in
        *"use case"*|*NOT_FOUND*|*bedrock*|*"don't have access"*|*"inference profile"*)
          ok "reached Bedrock ($label, provider+bearer OK); 404 = account use-case gate / model access" ;;
        *) bad "Bedrock $label 404 but not a Bedrock response: $(printf '%s' "$resp" | head -c 160)" ;;
      esac ;;
    401) bad "Bedrock $label rejected the bearer token (401): $(printf '%s' "$resp" | head -c 160)" ;;
    403) bad "Bedrock $label denied before upstream (routing regression): $(printf '%s' "$resp" | head -c 160)" ;;
    000) bad "Bedrock $label no connectivity (tunnel not converged)" ;;
    *)   bad "Bedrock $label unexpected status $code: $(printf '%s' "$resp" | head -c 160)" ;;
  esac
}

# Scenario 9: Google Vertex AI (path-routed model + service-account OAuth minting).
# Vertex carries the model in the URL path and authenticates with a short-lived
# OAuth2 access token, not an API key. The operator stores a durable GCP
# service-account key as the provider api_key behind a "keyfile::" prefix; the
# synthesiser ships the base64 SA JSON to the router, which mints + caches a
# Bearer token per request. We assert the whole pipeline: path->model parse,
# route-to-Vertex, token mint + inject, upstream forward. A 200 is a complete
# pass; a 404 whose body is Vertex's own "Publisher model not found / no access"
# also passes the pipeline (the token was accepted) and only signals that the
# test project lacks model access in that region.
cmd_scenario_vertex() {
  log "### scenario: Google Vertex AI (path-routed + service-account OAuth minting) ###"
  require_llm_keys
  if [ -z "${GOOGLE_VERTEX_SA_BASE64:-}" ] || [ -z "${GOOGLE_VERTEXT_PROJECT:-}" ]; then
    log "  SKIP: GOOGLE_VERTEX_SA_BASE64 / GOOGLE_VERTEXT_PROJECT not set in $LLM_KEYS_FILE"
    return 0
  fi
  local vid pol pid old oldvids region vhost
  # The regional endpoint host is "<region>-aiplatform.googleapis.com"; the
  # "global" location uses the bare "aiplatform.googleapis.com" host.
  region="${GOOGLE_VERTEXT_REGION:-global}"
  if [ "$region" = global ]; then vhost="aiplatform.googleapis.com"; else vhost="${region}-aiplatform.googleapis.com"; fi
  # Remove any pre-existing Vertex providers, de-referencing them from the broad
  # policy first — a provider that is still a policy destination can't be deleted
  # (422), and a survivor leaves a duplicate (possibly stale-host) Vertex route.
  oldvids="$(api GET /api/agent-network/providers | jq -c '[.[]|select(.provider_id=="vertex_ai_api")|.id]')"
  if [ "$oldvids" != "[]" ]; then
    pol="$(api GET /api/agent-network/policies | jq -c '.[]|select(.name=="e2e-all-providers")')"
    pid="$(echo "$pol" | jq -r '.id')"
    api PUT "/api/agent-network/policies/$pid" \
      "$(echo "$pol" | jq -c --argjson rm "$oldvids" '{name,description,enabled,source_groups,destination_provider_ids:(.destination_provider_ids-$rm),guardrail_ids,limits}')" >/dev/null 2>&1 || true
    for old in $(echo "$oldvids" | jq -r '.[]'); do
      api DELETE "/api/agent-network/providers/$old" >/dev/null 2>&1 || true
    done
  fi
  vid="$(api POST /api/agent-network/providers "$(jq -n --arg k "keyfile::${GOOGLE_VERTEX_SA_BASE64}" --arg u "https://${vhost}" \
    '{name:"Vertex e2e",provider_id:"vertex_ai_api",upstream_url:$u,api_key:$k,enabled:true}')" \
    | jq -r '.id')"
  [ -n "$vid" ] && [ "$vid" != null ] || { bad "create Vertex provider failed"; return; }
  log "  created Vertex provider $vid (keyfile:: service-account, $vhost)"

  pol="$(api GET /api/agent-network/policies | jq -c '.[]|select(.name=="e2e-all-providers")')"
  pid="$(echo "$pol" | jq -r '.id')"
  [ -n "$pid" ] && [ "$pid" != null ] || { bad "e2e-all-providers policy missing (run 'policy' first)"; return; }
  api PUT "/api/agent-network/policies/$pid" \
    "$(echo "$pol" | jq -c --arg v "$vid" '{name,description,enabled,source_groups,destination_provider_ids:((.destination_provider_ids+[$v])|unique),guardrail_ids,limits}')" >/dev/null
  policy_put_limits '{"budget_limit":{"enabled":true,"group_cap_usd":1000000,"user_cap_usd":1000000,"window_seconds":2592000},"token_limit":{"enabled":false,"group_cap":0,"user_cap":0,"window_seconds":3600}}'
  # Provider create/update propagates to the proxy live via reconcile (the synth
  # config is re-pushed and the middleware chain rebuilt on receipt), so just let
  # the tunnel settle before probing — no restart needed.
  wait_tunnel; sleep 5

  local ip path body code resp
  ip="$(proxy_ip)"; [ -n "$ip" ] || { bad "could not resolve proxy IP"; return; }
  path="/v1/projects/${GOOGLE_VERTEXT_PROJECT}/locations/${region}/publishers/anthropic/models/claude-sonnet-4-5@20250929:rawPredict"
  body="$(jq -n '{anthropic_version:"vertex-2023-10-16",max_tokens:64,messages:[{role:"user",content:"Reply with exactly: pong"}]}')"
  code="$(vertex_request "$ip" "$path" "$body")"; resp="$VTX_RESP"
  log "  vertex rawPredict -> http=$code"
  case "$code" in
    200)
      ok "Vertex 200 (path->model parse, routed, token minted + accepted, model available)"
      sleep 3
      local vin vout
      vin="$(access_log_top input_tokens)"; vout="$(access_log_top output_tokens)"
      log "  access-log: model=$(access_log_top model) input_tokens=$vin output_tokens=$vout"
      if [ "${vin:-0}" -gt 0 ] 2>/dev/null && [ "${vout:-0}" -gt 0 ] 2>/dev/null; then ok "Vertex usage metered (in=$vin out=$vout)"; else bad "Vertex usage not metered (in=$vin out=$vout)"; fi
      ;;
    404)
      case "$resp" in
        *"Publisher model"*|*aiplatform*|*NOT_FOUND*)
          ok "reached Vertex with a minted token (pipeline OK); 404 = test project lacks model access" ;;
        *) bad "404 but not a Vertex response body: $(printf '%s' "$resp" | head -c 160)" ;;
      esac ;;
    401) bad "Vertex rejected the minted credential (401) — check the SA key/roles: $(printf '%s' "$resp" | head -c 160)" ;;
    403) bad "proxy denied before reaching Vertex (path parse / routing regression): $(printf '%s' "$resp" | head -c 160)" ;;
    000) bad "no connectivity to proxy (tunnel not converged)" ;;
    *)   bad "unexpected status $code: $(printf '%s' "$resp" | head -c 160)" ;;
  esac

  # Live provider-update propagation: a provider change must reach the proxy node
  # without a restart. Disable the provider -> its route disappears and the request
  # is denied (403); re-enable -> served again at the baseline status. Proves
  # reconcile re-pushes the synth config and the proxy rebuilds its chain live.
  case "$code" in
    200|404)
      log "  testing live provider-update propagation (disable/enable, no restart)..."
      local dcode ecode
      set_enabled "$vid" false; sleep 5
      dcode="$(vertex_request "$ip" "$path" "$body")"
      if [ "$dcode" = 403 ]; then ok "provider disable reflected on proxy live (route removed, http 403)"; else bad "provider disable not reflected on proxy (want 403, got $dcode)"; fi
      set_enabled "$vid" true; sleep 5
      ecode="$(vertex_request "$ip" "$path" "$body")"
      if [ "$ecode" = "$code" ]; then ok "provider re-enable reflected on proxy live (served again, http $ecode)"; else bad "provider re-enable not reflected on proxy (want $code, got $ecode)"; fi
      ;;
  esac

  pol="$(api GET /api/agent-network/policies | jq -c '.[]|select(.name=="e2e-all-providers")')"
  api PUT "/api/agent-network/policies/$pid" \
    "$(echo "$pol" | jq -c --arg v "$vid" '{name,description,enabled,source_groups,destination_provider_ids:(.destination_provider_ids-[$v]),guardrail_ids,limits}')" >/dev/null 2>&1 || true
  api DELETE "/api/agent-network/providers/$vid" >/dev/null 2>&1 || true
}

# Scenario 10: real-traffic coverage for the OpenAI-compatible gateway providers
# (Vercel, OpenRouter, Cloudflare). Each is isolated as the sole enabled provider
# so its model routes to it unambiguously, sent a real chat request, and asserted
# to return 200 with metered token usage. A gateway without a configured provider
# is skipped. Restores all providers at the end.
cmd_scenario_providers() {
  log "### scenario: gateway providers real-traffic (Vercel / OpenRouter / Cloudflare) ###"
  policy_put_limits '{"budget_limit":{"enabled":true,"group_cap_usd":1000000,"user_cap_usd":1000000,"window_seconds":2592000},"token_limit":{"enabled":false,"group_cap":0,"user_cap":0,"window_seconds":3600}}'
  local spec iso full model kind r pid code vin vout
  for spec in \
    "vercel|Vercel AI Gateway|openai/gpt-4o-mini|chat" \
    "openrouter|OpenRouter|openai/gpt-4o-mini|chat" \
    "cloudflare|Cloudflare AI Gateway|gpt-4o-mini|chat"; do
    iso="${spec%%|*}"; r="${spec#*|}"; full="${r%%|*}"; r="${r#*|}"; model="${r%%|*}"; kind="${r##*|}"
    pid="$(provider_id_by_name "$full")"
    if [ -z "$pid" ] || [ "$pid" = null ]; then log "  SKIP $full: not configured"; continue; fi
    cmd_isolate "$iso" >/dev/null 2>&1
    wait_tunnel; sleep 4
    code="$(_chat "$model" "$kind")"
    if [ "$code" = 200 ]; then ok "$full served real request ($model, http 200)"; else bad "$full request failed ($model, http $code)"; continue; fi
    sleep 3
    vin="$(access_log_top input_tokens)"; vout="$(access_log_top output_tokens)"
    if [ "${vin:-0}" -gt 0 ] 2>/dev/null && [ "${vout:-0}" -gt 0 ] 2>/dev/null; then ok "$full usage metered (in=$vin out=$vout)"; else bad "$full usage not metered (in=$vin out=$vout)"; fi
  done
  cmd_enable_all >/dev/null 2>&1
  log "  re-enabled all providers"
  wait_tunnel >/dev/null 2>&1 || true
}

# Scenario 11: AWS Bedrock (path-routed model + bearer auth) across invoke,
# converse, and invoke-with-response-stream. Bedrock carries the model in the URL
# path and authenticates with a static bearer token (Bedrock API key). Asserts
# the pipeline per endpoint: path->model parse + normalize, route-to-Bedrock,
# bearer inject, upstream forward (+ token metering on 200). A Bedrock-origin 404
# (account use-case gate / model access) passes the pipeline; see bedrock_probe.
cmd_scenario_bedrock() {
  log "### scenario: AWS Bedrock (path-routed + bearer; invoke/converse/stream) ###"
  require_llm_keys
  if [ -z "${AWS_BEARER_TOKEN_BEDROCK:-}" ]; then
    log "  SKIP: AWS_BEARER_TOKEN_BEDROCK not set in $LLM_KEYS_FILE"
    return 0
  fi
  local region model vid pol pid old oldvids
  region="${AWS_BEDROCK_REGION:-eu-central-1}"
  model="${BEDROCK_MODEL:-eu.anthropic.claude-sonnet-4-5-20250929-v1:0}"
  oldvids="$(api GET /api/agent-network/providers | jq -c '[.[]|select(.provider_id=="bedrock_api")|.id]')"
  if [ "$oldvids" != "[]" ]; then
    pol="$(api GET /api/agent-network/policies | jq -c '.[]|select(.name=="e2e-all-providers")')"
    pid="$(echo "$pol" | jq -r '.id')"
    api PUT "/api/agent-network/policies/$pid" \
      "$(echo "$pol" | jq -c --argjson rm "$oldvids" '{name,description,enabled,source_groups,destination_provider_ids:(.destination_provider_ids-$rm),guardrail_ids,limits}')" >/dev/null 2>&1 || true
    for old in $(echo "$oldvids" | jq -r '.[]'); do
      api DELETE "/api/agent-network/providers/$old" >/dev/null 2>&1 || true
    done
  fi
  vid="$(api POST /api/agent-network/providers "$(jq -n --arg k "$AWS_BEARER_TOKEN_BEDROCK" --arg u "https://bedrock-runtime.${region}.amazonaws.com" \
    '{name:"Bedrock e2e",provider_id:"bedrock_api",upstream_url:$u,api_key:$k,enabled:true}')" | jq -r '.id')"
  [ -n "$vid" ] && [ "$vid" != null ] || { bad "create Bedrock provider failed"; return; }
  log "  created Bedrock provider $vid (bearer, bedrock-runtime.${region})"

  pol="$(api GET /api/agent-network/policies | jq -c '.[]|select(.name=="e2e-all-providers")')"
  pid="$(echo "$pol" | jq -r '.id')"
  [ -n "$pid" ] && [ "$pid" != null ] || { bad "e2e-all-providers policy missing (run 'policy' first)"; return; }
  api PUT "/api/agent-network/policies/$pid" \
    "$(echo "$pol" | jq -c --arg v "$vid" '{name,description,enabled,source_groups,destination_provider_ids:((.destination_provider_ids+[$v])|unique),guardrail_ids,limits}')" >/dev/null
  policy_put_limits '{"budget_limit":{"enabled":true,"group_cap_usd":1000000,"user_cap_usd":1000000,"window_seconds":2592000},"token_limit":{"enabled":false,"group_cap":0,"user_cap":0,"window_seconds":3600}}'
  wait_tunnel; sleep 5

  local ip invokeBody converseBody
  ip="$(proxy_ip)"; [ -n "$ip" ] || { bad "could not resolve proxy IP"; return; }
  invokeBody='{"anthropic_version":"bedrock-2023-05-31","max_tokens":32,"messages":[{"role":"user","content":"Reply with exactly: pong"}]}'
  converseBody='{"messages":[{"role":"user","content":[{"text":"Reply with exactly: pong"}]}],"inferenceConfig":{"maxTokens":32}}'
  bedrock_probe "invoke" "/model/${model}/invoke" "$invokeBody" "$ip"
  bedrock_probe "converse" "/model/${model}/converse" "$converseBody" "$ip"
  bedrock_probe "invoke-stream" "/model/${model}/invoke-with-response-stream" "$invokeBody" "$ip"
  # Gateway-namespace prefix: /bedrock/... must route the same and be stripped
  # before the upstream call (AWS's native path has no /bedrock prefix).
  bedrock_probe "invoke (/bedrock prefix)" "/bedrock/model/${model}/invoke" "$invokeBody" "$ip"

  pol="$(api GET /api/agent-network/policies | jq -c '.[]|select(.name=="e2e-all-providers")')"
  api PUT "/api/agent-network/policies/$pid" \
    "$(echo "$pol" | jq -c --arg v "$vid" '{name,description,enabled,source_groups,destination_provider_ids:(.destination_provider_ids-[$v]),guardrail_ids,limits}')" >/dev/null 2>&1 || true
  api DELETE "/api/agent-network/providers/$vid" >/dev/null 2>&1 || true
}

cmd_scenarios() {
  FAILS=0
  cmd_scenario_budget
  cmd_scenario_budget_rule
  cmd_scenario_user_cap
  cmd_scenario_guardrail
  cmd_scenario_streaming
  cmd_scenario_multigroup
  cmd_scenario_logs
  cmd_scenario_retention
  cmd_scenario_providers
  cmd_scenario_vertex
  cmd_scenario_bedrock
  log "================================================"
  if [ "$FAILS" -eq 0 ]; then log "ALL SCENARIOS PASSED"; else log "SCENARIO FAILURES: $FAILS"; fi
  return "$FAILS"
}

# --- dispatch ----------------------------------------------------------------
cmd="${1:-}"; shift || true
case "$cmd" in
  snapshot)      cmd_snapshot ;;
  key)           cmd_key ;;
  up)            cmd_up ;;
  status)        cmd_status ;;
  wait)          cmd_wait ;;
  diag)          cmd_diag ;;
  restart-proxy) cmd_restart_proxy ;;
  chat)          cmd_chat "$@" ;;
  verify)        cmd_verify ;;
  clean)         cmd_clean ;;
  providers)     cmd_providers ;;
  policy)        cmd_policy ;;
  isolate)       cmd_isolate "$@" ;;
  enable-all)    cmd_enable_all ;;
  scenario-budget)      cmd_scenario_budget ;;
  scenario-budget-rule) cmd_scenario_budget_rule ;;
  scenario-user-cap)    cmd_scenario_user_cap ;;
  scenario-guardrail)   cmd_scenario_guardrail ;;
  scenario-streaming)   cmd_scenario_streaming ;;
  scenario-multigroup)  cmd_scenario_multigroup ;;
  scenario-logs)        cmd_scenario_logs ;;
  scenario-retention)   cmd_scenario_retention ;;
  scenario-providers)   cmd_scenario_providers ;;
  scenario-vertex)      cmd_scenario_vertex ;;
  scenario-bedrock)     cmd_scenario_bedrock ;;
  dashboard)            cmd_dashboard ;;
  scenarios)            cmd_scenarios ;;
  down)          cmd_down ;;
  all)           cmd_all ;;
  *) cat >&2 <<'USAGE'
usage: bash scripts/e2e/agent-network-full/e2e.sh <cmd>
  setup/flow : snapshot key up status wait diag restart-proxy clean providers policy isolate NAME enable-all down all
  traffic    : chat MODEL [chat|messages]   verify
  scenarios  : scenarios | scenario-budget | scenario-budget-rule | scenario-user-cap |
               scenario-guardrail | scenario-streaming | scenario-multigroup |
               scenario-logs | scenario-retention | scenario-providers | scenario-vertex |
               scenario-bedrock
  dashboard  : dashboard   (Playwright UI check against the live :3000 dashboard)
USAGE
     exit 2 ;;
esac
