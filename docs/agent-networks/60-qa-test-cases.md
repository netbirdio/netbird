# Agent Network — QA test cases

A manual/automatable test-case catalogue for the Agent Network feature,
covering the management API (`management/internals/modules/agentnetwork`),
the synthesised reverse-proxy runtime, and the dashboard surface
(`netbirdio/dashboard`, `src/modules/agent-network` + `src/app/(dashboard)/agent-network`).

Companion reading: [00-overview.md](00-overview.md) for the feature map,
[01-end-to-end-flows.md](01-end-to-end-flows.md) for the request lifecycle,
[modules/40-dashboard.md](modules/40-dashboard.md) for the UI.

---

## 1. Scope and conventions

**In scope:** providers, policies, guardrails, account budget rules,
agent-network settings, endpoint bootstrap, request authorisation and routing,
limit enforcement, cost/usage accounting, access logs and sessions, log/prompt
collection, RBAC, the dashboard surfaces and the Agent Network onboarding.

**Out of scope (covered elsewhere):** generic reverse-proxy cluster
provisioning, WireGuard connectivity, IdP/SSO login, billing.

**Priorities**

| Level | Meaning |
|---|---|
| **P0** | Blocks release. Core happy path, data isolation, security, money/limits correctness. |
| **P1** | Important. Validation, secondary flows, most negative cases. |
| **P2** | Nice to have. Cosmetic, rare edge cases, resilience. |

**HTTP status conventions used below** (from `shared/management/http/util/util.go`):

| Condition | Status |
|---|---|
| Validation failure (`status.InvalidArgument`) | **422** Unprocessable Entity |
| Malformed JSON body | **400** Bad Request |
| Missing/insufficient permission | **403** Forbidden |
| Unknown id / not bootstrapped | **404** Not Found |

All endpoints are under `/api/agent-network/...`.

---

## 2. Environment prerequisites

| # | Requirement |
|---|---|
| E1 | A management deployment with at least one **validated FREE reverse-proxy cluster/domain** (the provider wizard only offers `type=FREE && validated=true`). Without one, provider create is blocked in the UI. |
| E2 | At least one proxy instance connected and serving the cluster. |
| E3 | Two NetBird accounts (**Account A**, **Account B**) for isolation tests. |
| E4 | In Account A: users `owner@`, `admin@`, `user@`, plus an `auditor`-role user if available. |
| E5 | Groups: `g-eng`, `g-contractors`, `g-none` (a group with no policy). Peers enrolled and assigned so caller group membership is deterministic. |
| E6 | At least one client machine running the NetBird agent and connected to the tunnel (traffic reaches the endpoint **only** over the tunnel). |
| E7 | Real or mocked upstream credentials for: OpenAI (`openai_api`), Anthropic (`anthropic_api`), one gateway (`litellm_proxy` or `portkey`), and — if testing path-routed providers — Bedrock and/or Vertex (`keyfile::<base64 GCP SA JSON>`). |
| E8 | A tool to issue raw HTTP (curl / Postman) plus at least one real agent (Claude Code or Codex) for the connect-snippet checks. |

**Reference data**

- Catalog ids: `openai_api`, `anthropic_api`, `azure_openai_api`, `bedrock_api`,
  `vertex_ai_api`, `mistral_api`, `kimi_api` (kind=provider); `litellm_proxy`,
  `portkey`, `bifrost`, `cloudflare_ai_gateway`, `vercel_ai_gateway`,
  `openrouter` (kind=gateway); `vllm`, `custom` (kind=custom).
- Deny codes: `llm_policy.token_cap_exceeded`, `llm_policy.budget_cap_exceeded`,
  `llm_account.token_cap_exceeded`, `llm_account.budget_cap_exceeded`,
  `llm_policy.model_blocked`.
- Permission modules: `agent_network.providers|policies|guardrails|budgets|usage|logs|settings`,
  with the `agent_network` parent cascading to all of them.

---

## 3. Bootstrap and account settings

| ID | Title | P | Preconditions | Steps | Expected |
|---|---|---|---|---|---|
| **AN-BS-01** | Settings read before bootstrap returns defaults | P0 | Fresh account, no provider created | `GET /agent-network/settings` | 200. `cluster`, `subdomain`, `endpoint` all empty; `enable_log_collection=true`; `enable_prompt_collection=false`; `redact_pii=false`; `access_log_retention_days=30`; no `created_at`/`updated_at`. Nothing is persisted (repeat the GET — still no row). |
| **AN-BS-02** | First provider create bootstraps settings | P0 | AN-BS-01 | Create a provider with `bootstrap_cluster=<validated cluster>` | Provider created. `GET /agent-network/settings` now returns the pinned `cluster`, a generated word-based `subdomain`, and `endpoint = "<subdomain>.<cluster>"`. Timestamps present. |
| **AN-BS-03** | Subdomain is unique per cluster | P1 | Several accounts bootstrapped on the same cluster | Bootstrap 5+ accounts on one cluster; collect subdomains | All subdomains distinct; each is a readable word-label with a short account-id suffix. |
| **AN-BS-04** | Bootstrap hint ignored once settings exist | P1 | AN-BS-02 done | Create a second provider passing a *different* `bootstrap_cluster` | Provider created; settings `cluster`/`subdomain`/`endpoint` unchanged. |
| **AN-BS-05** | PUT settings bootstraps when a cluster is supplied | P1 | Fresh account | `PUT /agent-network/settings` with `cluster=<validated cluster>` and the toggles | 200; row created with that cluster and a generated subdomain; toggles applied. |
| **AN-BS-06** | PUT settings without cluster on un-bootstrapped account | P1 | Fresh account | `PUT /agent-network/settings` omitting `cluster` | 404, message names that settings have not been bootstrapped and that `cluster` (or a provider create with `bootstrap_cluster`) is required. |
| **AN-BS-07** | Cluster is immutable | P0 | Bootstrapped account | `PUT /agent-network/settings` with a *different* `cluster` | 422, message `cluster is immutable once assigned (current: <cluster>)`. Stored cluster unchanged. |
| **AN-BS-08** | PUT settings with the same cluster is accepted | P1 | Bootstrapped | `PUT` echoing the current cluster + changed toggles | 200; toggles updated; cluster/subdomain unchanged. |
| **AN-BS-09** | Subdomain can never be set by the client | P1 | Bootstrapped | `PUT` with a `subdomain` field in the body | Server value unchanged (field is server-assigned and ignored). |
| **AN-BS-10** | Collection toggles round-trip | P1 | Bootstrapped | Toggle `enable_log_collection`, `enable_prompt_collection`, `redact_pii`, and each retention option (7/14/30/60/90/0) | Each `PUT` returns the requested value; a subsequent `GET` matches; the dashboard **Configuration → Log Collection** tab reflects it after reload. |
| **AN-BS-11** | Settings change is audited | P2 | Bootstrapped | Change a toggle, then open **Activity/Events** | An `agent network settings updated` event exists with `log_collection`, `prompt_collection`, `redact_pii` in its metadata. |
| **AN-BS-12** | Concurrent settings PUTs don't interleave | P2 | Bootstrapped | Fire 10 concurrent `PUT`s with alternating toggle values | No 500s; final stored state equals one of the submitted payloads (no torn write); cluster unchanged. |

---

## 4. Providers — CRUD and validation

| ID | Title | P | Preconditions | Steps | Expected |
|---|---|---|---|---|---|
| **AN-PR-01** | Catalog listing | P0 | Authenticated | `GET /agent-network/catalog/providers` | 200 with all catalog entries; each has `id`, `name`, `kind` (`provider`/`gateway`/`custom`), `default_host`, and models with `input_per_1k`/`output_per_1k` (+ cache rates where applicable). Rates match the **live** default pricing table, not stale compiled rates. |
| **AN-PR-02** | Create OpenAI provider (happy path) | P0 | Cluster available | POST with `provider_id=openai_api`, name, `upstream_url=https://api.openai.com`, `api_key`, models, `enabled=true` | 201/200; response contains the provider with `id`; **`api_key` is absent from the response**. |
| **AN-PR-03** | Create Anthropic provider | P0 | — | Same with `provider_id=anthropic_api`, `https://api.anthropic.com` | Created. |
| **AN-PR-04** | Create gateway provider with extra headers | P1 | — | Create `portkey` and fill `extra_values["x-portkey-config"]` | Created; `extra_values` round-trips on GET. |
| **AN-PR-05** | Extra values are restricted to catalog-declared keys | P1 | AN-PR-04 | Send an `extra_values` key the catalog doesn't declare (e.g. `x-bogus`) | Undeclared key is not persisted/returned. Empty-string values are dropped rather than stored. |
| **AN-PR-06** | `provider_id` is required and must be a known catalog id | P0 | — | POST with `provider_id=""`, then `provider_id="not_a_provider"` | 422 `provider_id is required`; 422 `provider_id "not_a_provider" is not a known catalog provider`. |
| **AN-PR-07** | `name` required | P1 | — | POST with blank/whitespace name | 422 `name is required`. |
| **AN-PR-08** | `upstream_url` validation | P0 | — | POST with: empty; `not-a-url`; `ftp://x`; `https://` (no host) | 422 in every case (`upstream_url is required` / `must be a full http(s) URL`). |
| **AN-PR-09** | `api_key` required on create | P0 | — | POST omitting `api_key`, then with `"   "` | 422 `api_key is required`. No provider row is created. |
| **AN-PR-10** | Model rate validation | P0 | — | POST models with: empty `id`; `input_per_1k = -1`; `output_per_1k = NaN`; `cached_input_per_1k = Inf` | 422 each; message names the index, model id and offending field (`models[0] (gpt-4o): input_per_1k must be a finite, non-negative USD rate`). |
| **AN-PR-11** | Empty model list means "all catalog models at catalog prices" | P1 | — | Create with `models: []`, then route a request for any catalog model | Request routes and is billed at the default catalog rate for that model. |
| **AN-PR-12** | Update preserves API key when omitted | P0 | Provider exists | `PUT` the provider without `api_key`, changing only the name | 200; name changed; upstream calls still succeed (stored key intact). |
| **AN-PR-13** | Blank API key on update is rejected | P0 | Provider exists | `PUT` with `api_key: "   "` | 422 `api_key must be non-blank when rotating an agent network provider`. Stored key untouched. |
| **AN-PR-14** | API key rotation | P0 | Provider exists, requests succeeding | `PUT` with a new valid key | 200; subsequent agent requests use the new key (verify with a deliberately wrong key → upstream 401 surfaced; then restore). |
| **AN-PR-15** | Session keypair survives updates | P1 | Provider exists | Update the provider several times | No error; the synthesised service keeps working (existing agent sessions are not broken). |
| **AN-PR-16** | `created_at` is preserved on update | P2 | Provider exists | Update it | `created_at` unchanged; `updated_at` advanced. |
| **AN-PR-17** | Disable a provider | P0 | Provider + policy exist, traffic flowing | Set `enabled=false` | Requests targeting that provider stop being routed. If it was the only enabled provider, the whole endpoint stops serving (see AN-SY-01). |
| **AN-PR-18** | Delete blocked while referenced by a policy | P0 | Policy references the provider | `DELETE /agent-network/providers/{id}` | 422 `provider is in use by N policy/policies (<names>); detach it before deleting`. Provider still present. Message pluralises correctly for 1 vs many. |
| **AN-PR-19** | Delete after detaching | P0 | AN-PR-18, then remove it from the policy | `DELETE` again | 200; provider gone from `GET /agent-network/providers`; the synthesised routing table no longer offers its models. |
| **AN-PR-20** | Unknown provider id | P1 | — | `GET`/`PUT`/`DELETE` with a random id | 404. |
| **AN-PR-21** | `skip_tls_verification` | P1 | A self-hosted upstream with a self-signed cert (`vllm`/`custom`) | Create with the flag off → request; then on → request | Off: upstream dial fails on TLS. On: request succeeds. |
| **AN-PR-22** | `metadata_disabled` | P1 | Gateway provider that receives identity metadata | Create with `metadata_disabled=false`, inspect upstream request; then set `true` | False: user/group identity headers/metadata are stamped. True: they are absent. Catalog `extra_values` routing headers are still stamped in both cases. |
| **AN-PR-23** | Customisable identity header names (Bifrost) | P1 | — | Create `bifrost`, set `identity_header_user_id` / `identity_header_groups`; then clear one | Configured names are stamped upstream; a cleared name disables stamping for that dimension and round-trips as `""` (not omitted) in the API response. |
| **AN-PR-24** | Identity-header anti-spoofing | P0 | Gateway with identity injection | From the client, send a request that *already* sets the identity header with a fake user | The upstream receives NetBird's real caller identity — the client-supplied value is stripped, never forwarded. |
| **AN-PR-25** | Vertex `keyfile::` credential | P1 | GCP SA JSON | Create `vertex_ai_api` with `api_key = keyfile::<base64 SA JSON>` and a `<region>-aiplatform.googleapis.com` upstream | Requests succeed; upstream sees `Authorization: Bearer <short-lived OAuth token>`, never the key material. |
| **AN-PR-26** | Bedrock path-routed provider | P1 | Bedrock creds | Create `bedrock_api`; send a `/model/{modelId}/invoke` (and `/bedrock`-prefixed) request | Routed to the Bedrock provider by path, not by body model; the model recorded in the log is the path model with region/version stripped. |
| **AN-PR-27** | Secrets at rest | P0 | Provider created | Inspect the `agent_network_providers` table | `api_key` and `session_private_key` are ciphertext; `session_public_key` is plaintext. Neither key ever appears in an API response or in logs. |
| **AN-PR-28** | Malformed JSON | P2 | — | POST with a truncated JSON body | 400 `couldn't parse JSON request` (not 422/500). |

---

## 5. Policies — CRUD and validation

| ID | Title | P | Preconditions | Steps | Expected |
|---|---|---|---|---|---|
| **AN-PO-01** | Create policy (happy path) | P0 | 1 provider, 1 group | POST with name, `source_groups=[g-eng]`, `destination_provider_ids=[p1]`, no limits | Created with an `ainpol_`-prefixed id, `enabled=true` by default. |
| **AN-PO-02** | `name` required | P1 | — | POST with blank name | 422 `name is required`. |
| **AN-PO-03** | `source_groups` must be non-empty and non-blank | P0 | — | POST with `[]`, then `[""]` | 422 `source_groups must contain at least one group id` / `must not contain empty entries`. |
| **AN-PO-04** | `destination_provider_ids` must be non-empty and non-blank | P0 | — | POST with `[]`, then `[""]` | 422 with the matching messages. |
| **AN-PO-05** | Destination provider must exist in the account | P0 | — | POST referencing an id from Account B, and a random id | 422 `destination_provider_ids: provider <id> does not exist` for both. |
| **AN-PO-06** | `guardrail_ids` entries must be non-blank | P1 | — | POST with `guardrail_ids: [""]` | 422 `guardrail_ids must not contain empty entries`. |
| **AN-PO-07** | Token limit window floor | P0 | — | POST with `token_limit.enabled=true`, `window_seconds=59` (and `0`) | 422 `limits.token_limit.window_seconds must be at least 60 (one minute) when enabled`. |
| **AN-PO-08** | Token limit needs a positive cap | P0 | — | POST with `token_limit.enabled=true`, window 3600, both caps `0` | 422 `limits.token_limit requires group_cap or user_cap to be greater than zero when enabled`. |
| **AN-PO-09** | Negative caps rejected | P1 | — | `group_cap=-1`, then `user_cap=-1` | 422 `must not be negative`. |
| **AN-PO-10** | Budget limit mirrors the token rules | P0 | — | Repeat AN-PO-07..09 for `budget_limit` (`group_cap_usd`, `user_cap_usd`) | Same class of 422s with `budget_limit` wording. |
| **AN-PO-11** | Limits omitted → uncapped | P1 | — | POST with `limits` absent | Created; both halves disabled; policy behaves as catch-all-allow (see AN-LM-09). |
| **AN-PO-12** | Disabled limits skip validation | P2 | — | POST with `enabled=false` and `window_seconds=0`, caps 0 | Accepted (validation only applies when the half is enabled). |
| **AN-PO-13** | Update policy | P0 | Policy exists | `PUT` changing name, groups, providers, guardrails, limits | 200; all fields replaced; `created_at` preserved, `updated_at` advanced; changes take effect on the next request without a restart. |
| **AN-PO-14** | Disable a policy | P0 | Policy governs a caller | Set `enabled=false` | Caller loses access through that policy; if no other enabled policy exists, the account's endpoint stops serving (AN-SY-01). |
| **AN-PO-15** | Delete a policy | P0 | Policy exists | `DELETE` | 200; policy gone; a caller authorised only by it can no longer reach the endpoint. |
| **AN-PO-16** | Deleting a group referenced by a policy | P1 | Group used in `source_groups` | Try to delete the group in **Groups** | Deletion is refused with a message naming the agent-network policy (no dangling group reference is left behind). |
| **AN-PO-17** | Policy events are audited | P2 | — | Create/update/delete a policy | Three distinct activity events recorded with the policy name and enabled state. |
| **AN-PO-18** | Same group in two policies | P1 | — | Create two enabled policies with overlapping `source_groups` and the same provider | Both are valid; selection follows the ranking in §7. |

---

## 6. Guardrails

| ID | Title | P | Preconditions | Steps | Expected |
|---|---|---|---|---|---|
| **AN-GR-01** | Create guardrail with model allowlist | P0 | — | POST name + `checks.model_allowlist = {enabled:true, models:["gpt-4o","gpt-5.4-mini"]}` | Created with an `ainguard_`-prefixed id. |
| **AN-GR-02** | Create guardrail with prompt capture | P0 | — | POST with `checks.prompt_capture = {enabled:true, redact_pii:true}` | Created; both flags round-trip. |
| **AN-GR-03** | Empty allowlist arrays normalise | P2 | — | POST with `models` omitted / `null` | Response returns `models: []`, never `null`. |
| **AN-GR-04** | Update / delete guardrail | P1 | Guardrail exists | `PUT` then `DELETE` | 200 each; `created_at` preserved on update; deletion removes it from the attach picker. |
| **AN-GR-05** | Deleting an attached guardrail | P1 | Guardrail attached to a policy | Delete it | Observe and record the behaviour: either the delete is refused, or the policy's `guardrail_ids` no longer resolves. Follow-up requests must **not** 500, and a stale id must not silently turn a restricted policy into an unrestricted one — verify the effective model gate after deletion. |
| **AN-GR-06** | Model allowlist enforcement — allowed | P0 | Policy → guardrail with `models:["gpt-4o"]` | Agent requests `gpt-4o` | 200; served. |
| **AN-GR-07** | Model allowlist enforcement — blocked | P0 | Same | Agent requests `gpt-4.1` | Denied with `llm_policy.model_blocked`; reason reads `model "gpt-4.1" is not permitted by any applicable policy allowlist`. Access log shows decision `deny` and that reason. |
| **AN-GR-08** | Allowlist matching is case/whitespace tolerant | P1 | Allowlist `["GPT-4o"]` | Request `  gpt-4o ` | Allowed (comparison lowercases and trims on both sides). |
| **AN-GR-09** | Undetermined model fails closed | P0 | Restricted policy | Send a request whose body has no resolvable model | Denied with `llm_policy.model_blocked`; reason `request model could not be determined for the policy allowlist`. |
| **AN-GR-10** | Undetermined model is allowed when unrestricted | P1 | Policy with no allowlist-enabled guardrail | Same request | Not blocked by the allowlist gate. |
| **AN-GR-11** | Union across multiple guardrails on one policy | P1 | Policy with guardrail A (`gpt-4o`) and B (`gpt-4.1`) | Request each model | Both allowed — a policy permits the **union** of its enabled allowlists. |
| **AN-GR-12** | Union across multiple policies | P0 | Policy 1 allows `gpt-4o`, Policy 2 (same caller + provider) allows `gpt-4.1` | Request each | Both allowed; the blocked case only fires when **no** applicable policy permits the model. |
| **AN-GR-13** | Guardrail with allowlist disabled is not restrictive | P1 | Guardrail with `model_allowlist.enabled=false` but a populated `models` array | Request a model not in the array | Allowed. |
| **AN-GR-14** | Prompt capture requires both gates | P0 | Account `enable_prompt_collection=false`, policy guardrail `prompt_capture.enabled=true` | Send a request, then open the access-log row | **No** prompt/completion body captured. Flip the account toggle on → new requests capture bodies. Neither gate alone is sufficient. |
| **AN-GR-15** | PII redaction is account **OR** policy | P0 | Account `redact_pii=false`, policy guardrail `redact_pii=true`; prompt capture on both gates | Send a prompt containing an email/phone/credit-card-shaped string | Captured prompt is redacted. Repeat with the account flag on and the policy flag off → still redacted. |
| **AN-GR-16** | Browse-and-attach modal | P2 | ≥2 guardrails exist, 1 already attached | Open policy → Guardrails tab → **Browse** | Already-attached guardrails are not listed; multi-select works; the Attach button is disabled with nothing selected and shows a correct singular/plural count; when everything is attached, the empty-state copy is shown. |

---

## 7. Policy selection and limit enforcement

These are the money-correctness cases. Use short windows (60–300 s) so caps
can actually be exhausted inside a test run, and record the exact request/response
pairs.

| ID | Title | P | Preconditions | Steps | Expected |
|---|---|---|---|---|---|
| **AN-LM-01** | Caller with no matching policy | P0 | Caller in `g-none`; no policy names that group | Send a request | Denied — the router is the authorisation gate; no upstream call is made and no upstream cost is incurred. |
| **AN-LM-02** | Policy targets a different provider | P0 | Policy allows provider P1 only | Request a model served by P2 | Not authorised through that policy. |
| **AN-LM-03** | Per-user token cap | P0 | Policy: token limit on, `user_cap=1000`, window 300 s | Drive user U past 1000 total tokens (in+out) in the window, then send one more | The over-cap request is denied with `llm_policy.token_cap_exceeded`; reason reads `user token cap exhausted on policy <id> (used N of 1000)`. |
| **AN-LM-04** | Per-group token cap is shared | P0 | Policy: `group_cap=1000`, window 300 s; users U1 and U2 both in `g-eng` | U1 consumes ~700 tokens; U2 then sends requests | U2 is denied once the **combined** group total reaches 1000 (`group token cap exhausted…`). |
| **AN-LM-05** | Per-user budget cap | P0 | `budget_limit.user_cap_usd=0.01`, window 300 s | Spend past $0.01 | Denied with `llm_policy.budget_cap_exceeded`; reason shows used vs cap to 4 decimals. |
| **AN-LM-06** | Per-group budget cap | P0 | `group_cap_usd` set | Two users in the group spend past it | Denied for whoever crosses the shared total. |
| **AN-LM-07** | Window rollover restores headroom | P0 | AN-LM-03 exhausted | Wait for the aligned window to roll over, then retry | Request is served again; counters restart from zero in the new window. Windows are **aligned** (not sliding) — confirm the reset happens at the window boundary, not exactly N seconds after the first request. |
| **AN-LM-08** | Cap of zero means uncapped | P1 | `token_limit.enabled=true`, `user_cap=0`, `group_cap=5000` | Drive one user past 5000 tokens alone | The user cap never binds; only the group cap does. |
| **AN-LM-09** | Uncapped policy wins over capped | P0 | Policy A (no caps) and Policy B (`group_cap=100`), both matching the caller and provider | Send requests past 100 tokens | All requests are attributed to A and keep succeeding; B's cap never blocks the caller. |
| **AN-LM-10** | Bigger pool drains first | P0 | Policy A `group_cap=10000`, Policy B `group_cap=1000`, both matching | Send requests | A is selected while it has headroom; only after A is exhausted does B pay; when both are exhausted the request is denied. |
| **AN-LM-11** | Ranking tiebreaks | P1 | Two policies with equal group token caps but different group budget caps; then equal on both but different user caps | Send requests | Order: group token cap → group budget cap → user token cap → user budget cap → **older `created_at`**. Repeat the run: the winner is stable and deterministic. |
| **AN-LM-12** | Multi-group attribution is deterministic | P0 | Caller in `g-alpha` and `g-beta`, both in the policy's `source_groups` | Send several requests | Every request attributes to the **lowest by string sort** intersecting group id. Verify the group column in the access log is identical across requests and across management replicas. |
| **AN-LM-13** | Effective window when both halves are enabled | P1 | Policy with token window 300 s and budget window 3600 s, both enabled | Send a request and inspect the recorded consumption window | The **token** window (300 s) is used for the policy-window booking. |
| **AN-LM-14** | Account budget rule — account-wide | P0 | Budget rule with **no** target groups/users, `user_cap_usd` small | Any caller spends past it | Denied with `llm_account.budget_cap_exceeded`, even for a caller on an uncapped policy. |
| **AN-LM-15** | Account rule binds with no matching policy | P0 | Account rule exists; caller matches **no** agent-network policy | Send a request | Ceiling is still evaluated (and denies once exhausted) — account rules are independent of policy selection. |
| **AN-LM-16** | Account rule targeting by user | P0 | Rule with `target_users=[U1]` | U1 and U2 both send traffic past the cap | U1 is denied; U2 is unaffected. |
| **AN-LM-17** | Account rule targeting by group | P0 | Rule with `target_groups=[g-eng]` | Member and non-member both send traffic | Only the member is bound. |
| **AN-LM-18** | Min-wins across rules | P0 | Rule A `user_cap_usd=$10`, Rule B `user_cap_usd=$1`, both applying | Spend past $1 | Denied at $1 — every applicable rule must pass; a looser rule cannot raise the ceiling. |
| **AN-LM-19** | Disabled rule doesn't bind | P1 | Rule set to `enabled=false` | Spend past its cap | Not enforced. |
| **AN-LM-20** | Account and policy caps coexist | P0 | Policy cap 1000 tokens/5 min; account rule 100000 tokens/month | Exhaust the policy cap | `llm_policy.*` deny code (not the account one); the account counter keeps accruing in its own monthly window. |
| **AN-LM-21** | One request never double-counts a cap | P0 | Policy window == an account rule window, same dimension | Send one request and read the consumption rows | The (dimension, window) counter is incremented **once**, not twice. |
| **AN-LM-22** | Deny does not consume upstream quota | P0 | Any exhausted cap | Send the denied request | No upstream call is made; no cost is added for the denied request; the access log records it with decision `deny` and zero/absent tokens. |
| **AN-LM-23** | Concurrency under a near-exhausted cap | P1 | Cap with ~1 request of headroom | Fire 20 concurrent requests | No 500s; counters stay consistent (no negative/duplicated totals); over-cap requests are denied. Record whether any overshoot occurs and by how much — the check is pre-flight, so a small overshoot may be by design; it must be bounded and must not corrupt totals. |
| **AN-LM-24** | Usage deltas are validated | P1 | — | Exercise the usage-recording path with a negative or non-finite delta (unit/API level) | Rejected with `usage deltas must be non-negative and finite`; totals are never decremented. |
| **AN-LM-25** | Deny surfaces usefully to the agent | P1 | Any deny case | Observe the client-side response in Claude Code / curl | A well-formed, upstream-shaped error the SDK can render — not a raw proxy 500 or a hung connection. |

---

## 8. Runtime routing and the tunnel

| ID | Title | P | Preconditions | Steps | Expected |
|---|---|---|---|---|---|
| **AN-SY-01** | Endpoint requires settings + enabled provider + enabled policy | P0 | Bootstrapped account | Test all four states: (a) all three present; (b) no enabled provider; (c) no enabled policy; (d) no settings row | Only (a) serves. (b)/(c)/(d) produce no synthesised service and the endpoint does not serve LLM traffic. Re-enabling restores service without a restart. |
| **AN-SY-02** | Tunnel-only access | P0 | Endpoint serving | Call `https://<endpoint>/v1/chat/completions` from a machine **not** connected to the NetBird tunnel | Rejected — the synthesised service is private and gated by tunnel-peer access. |
| **AN-SY-03** | Access groups follow policy source groups | P0 | Endpoint serving; policies target `g-eng` only | Connect a peer whose user is only in `g-contractors` and call the endpoint | Rejected at the tunnel-peer gate. Add the user to `g-eng` → allowed (no restart). |
| **AN-SY-04** | No client API key needed | P0 | Endpoint serving | Call with `api_key=none` / no upstream credential | Succeeds; NetBird injects the real key server-side. Also confirm the caller's own bogus `Authorization` header is stripped and replaced. |
| **AN-SY-05** | Model → provider routing | P0 | Two providers with disjoint model lists | Request a model from each | Each routes to the correct upstream; the resolved provider is recorded in the access log. |
| **AN-SY-06** | Streaming (SSE) requests | P0 | — | Send a streaming chat completion (`stream: true`) | Stream is relayed correctly to the client; token usage from the trailing chunk is recorded; cost is non-zero. |
| **AN-SY-07** | Non-streaming requests | P0 | — | Same with `stream: false` | Usage and cost recorded. |
| **AN-SY-08** | Large request body | P1 | — | Send a request whose body exceeds the ~1 MiB capture cap (long context) | Request still routes and succeeds; routing fields (model) are still resolved; capture is truncated, not fatal. |
| **AN-SY-09** | Large / long streaming response | P1 | — | Generate a very long response | Usage is still recorded (the trailing usage event is within the 8 MiB response capture cap). |
| **AN-SY-10** | Config change propagation | P0 | Traffic flowing | Change a policy cap, add a provider, toggle a guardrail | New behaviour is observed on subsequent requests within seconds, with no manual proxy restart. |
| **AN-SY-11** | Upstream failure passthrough | P1 | Provider with a deliberately invalid key | Send a request | The upstream's 401/429/5xx is surfaced to the client intelligibly; the access log records the real status code; NetBird does not mask it as a generic 500. |
| **AN-SY-12** | Unreachable upstream | P1 | Provider pointing at a dead host | Send a request | Clean error to the client within a reasonable timeout; no hang; logged. |
| **AN-SY-13** | Non-LLM path on the endpoint | P2 | — | `GET https://<endpoint>/` and a random path | A sane response/404 — no panic, no stack trace, no credential leakage. |
| **AN-SY-14** | Multiple accounts on one cluster | P0 | Accounts A and B bootstrapped on the same cluster | Call A's endpoint with B's peer, and vice versa | Cross-account calls are rejected; each endpoint only serves its own account's providers and policies. |

---

## 9. Usage, cost and consumption accounting

| ID | Title | P | Preconditions | Steps | Expected |
|---|---|---|---|---|---|
| **AN-US-01** | Cost matches configured rates | P0 | Provider with known `input_per_1k`/`output_per_1k` | Send a request with known token counts | Recorded `cost_usd` == `(in/1000 × input_rate) + (out/1000 × output_rate)` within rounding. |
| **AN-US-02** | Operator override beats catalog default | P0 | Provider model row priced deliberately differently from the catalog | Send a request | The operator's rate is used. |
| **AN-US-03** | OpenAI-shape cached input tokens | P0 | OpenAI model with `cached_input_per_1k` set; a prompt that hits the cache | Send two identical large prompts | Second call reports cached input tokens; they are billed at the cached rate, and cached tokens are a **subset** of input tokens (not added on top). |
| **AN-US-04** | Anthropic-shape cache read / creation | P0 | Anthropic model with `cache_read_per_1k` and `cache_creation_per_1k` | Run a prompt-caching sequence | Cache-read and cache-creation tokens are billed at their own rates and are **additive** to input tokens. Total tokens in the UI include them; the hover breakdown splits input / output / cache read / cache write. |
| **AN-US-05** | `nil` vs explicit `0` cache rate | P1 | One model with the cache rate omitted, one with it explicitly `0` | Send cache-hitting requests to each | Omitted → NetBird's default rate for that model applies. Explicit `0` → that bucket bills at the **input** rate (no discount), not free. |
| **AN-US-06** | Usage is recorded even with log collection off | P0 | `enable_log_collection=false` | Send several requests | No access-log rows appear, but the **Usage** tab and cost/token totals still update. |
| **AN-US-07** | Usage is recorded with no caps configured | P1 | Policy with no limits | Send requests | Usage/cost rows exist (consumption counters may be skipped, but usage history is not). |
| **AN-US-08** | Usage overview default window | P1 | Usage across >90 days (or seeded data) | `GET /agent-network/usage/overview` with no dates | Defaults to the last 90 days; response doesn't attempt to aggregate all history. |
| **AN-US-09** | Usage overview range clamp | P1 | — | Request a range wider than 366 days | Clamped to 366 days back from the end date; no error, no timeout. |
| **AN-US-10** | Granularity bucketing | P1 | Usage over several days | Request each supported granularity | Buckets are correct and ordered oldest-first; sparse days are represented rather than collapsed. |
| **AN-US-11** | Usage chart vs table agreement | P1 | Any usage | Open **Usage & Logs → Usage** | The token/cost chart, the per-day table and the hover breakdowns agree with each other and with the access-log sum for the same window. |
| **AN-US-12** | Consumption listing | P2 | Caps configured and partly consumed | `GET /agent-network/consumption` | Rows ordered window-newest-first, with dimension kind (user/group), dimension id, window seconds, window start, tokens and cost. |
| **AN-US-13** | Empty state | P2 | Fresh account | Open the Usage tab | "No usage recorded yet" empty state, no chart errors, no NaN/`$NaN` values. |
| **AN-US-14** | Zero-cost models | P2 | Embeddings model with `output_per_1k = 0` | Send an embeddings request | Cost computed from input only; no divide-by-zero or NaN in the UI. |

---

## 10. Access logs and sessions

| ID | Title | P | Preconditions | Steps | Expected |
|---|---|---|---|---|---|
| **AN-AL-01** | Row content | P0 | Log collection on; a served request | Open **Usage & Logs → Access Logs** and expand the row | Timestamp, user (real identity, not the peer), authorising group, provider, model, path, tokens, cost, status code, duration, decision, session id. Values match the request. |
| **AN-AL-02** | Deny rows | P0 | A capped or model-blocked request | Inspect the row | Decision `deny`; the reason column carries the human-readable deny reason; the deny code is recoverable. |
| **AN-AL-03** | Log collection off suppresses rows | P0 | `enable_log_collection=false` | Send requests, then look | No new access-log rows (existing ones remain). Turn it back on → new requests appear. |
| **AN-AL-04** | Prompt capture content | P0 | Both prompt gates on | Send a request with a distinctive prompt | The expanded row shows the request prompt and the response completion. |
| **AN-AL-05** | Redaction of captured prompts | P0 | AN-GR-15 setup | Send a prompt containing an email address, phone number and card-shaped number | Stored/displayed prompt is redacted. Verify at the **database** level too, not just in the UI. |
| **AN-AL-06** | Pagination | P1 | >100 log rows | Page through; also call the API with `page_size=1000` | Default page size 50 (dashboard uses 25); `page_size` is clamped to 100; page navigation is consistent with no duplicate/missing rows. |
| **AN-AL-07** | Sorting | P1 | Mixed data | Sort by timestamp, model, provider, status_code, duration, cost_usd, total_tokens, user_id, decision, asc and desc | Each sort is correct; an unknown `sort_by` falls back to `timestamp desc` rather than erroring. |
| **AN-AL-08** | Filters | P0 | Mixed data | Filter by date range, user, group, provider (multi), model (multi), decision, path prefix, and free-text search | Each narrows correctly; multi-select is OR-within-field and AND-across-fields; combining filters with sorting and paging stays consistent. |
| **AN-AL-09** | Multi-value query forms | P1 | — | Call the API with `?provider_id=a&provider_id=b` and with `?provider_id=a,b` | Both forms behave identically. |
| **AN-AL-10** | Invalid date is rejected, not ignored | P1 | — | `?start_date=yesterday` and `?end_date=2026-13-45` | 422 `invalid start_date/end_date: …` — the filter must not silently broaden the query. |
| **AN-AL-11** | Default UI window | P2 | — | Open the Access Logs tab fresh | Defaults to the last 14 days; the reset-filters action returns to that window. |
| **AN-AL-12** | Session grouping | P0 | An agent session spanning many requests (e.g. a Claude Code task) | Toggle **group by session** | One row per session with request count, first/last activity, summed tokens, summed cost, and a max status; expanding shows the constituent requests. Toggling back to flat view shows the same data ungrouped. |
| **AN-AL-13** | Session sorting | P1 | — | Sort sessions by last activity, started_at, request_count, cost, tokens, duration, status, user, decision | Correct aggregate ordering; sorting by a flat-only field (model/provider) falls back to the default without error. |
| **AN-AL-14** | Session filter round-trip | P1 | — | From a flat row, filter by its `session_id` | Only that session's requests are listed. |
| **AN-AL-15** | Retention sweep deletes old rows | P0 | Retention set to 7 days; seeded rows older than that | Wait for/trigger the cleanup sweep (runs at startup and on the configured interval, default 24 h) | Rows older than the cutoff are deleted; newer rows and **all usage records** are untouched. |
| **AN-AL-16** | Indefinite retention | P1 | Retention set to `0` (Indefinite) | Run the sweep | No access-log rows are deleted for that account. |
| **AN-AL-17** | Per-account retention isolation | P1 | Account A retention 7 days, Account B indefinite | Run the sweep | Only A's old rows are removed. |
| **AN-AL-18** | Retention change takes effect | P1 | Retention 90 → 7 | Change it and run the sweep | Rows between 7 and 90 days old are removed on the next sweep. |
| **AN-AL-19** | Log volume under load | P2 | — | Drive sustained request volume | Ingest keeps up; no request failures caused by log writes; a log-write failure must not fail the user's LLM request. |

---

## 11. Permissions, roles and tenancy

| ID | Title | P | Preconditions | Steps | Expected |
|---|---|---|---|---|---|
| **AN-RB-01** | Owner/admin full access | P0 | Owner and admin users | Exercise create/read/update/delete on providers, policies, guardrails, budget rules, settings; read usage and logs | All succeed. |
| **AN-RB-02** | Regular user is denied writes | P0 | `user`-role account member | Attempt each mutating call | 403 on each; the dashboard shows the restricted-access state rather than a broken page. |
| **AN-RB-03** | Read-only role | P1 | Auditor/read-only role, if available | GET providers, policies, guardrails, budgets, usage, logs; then attempt a write | Reads succeed per the role's grants; writes 403. |
| **AN-RB-04** | Submodule grants are independent | P1 | A role granted only `agent_network.logs` read | Read logs; then read providers | Logs succeed; providers 403. |
| **AN-RB-05** | Parent grant cascades | P1 | A role granted `agent_network` | Access every submodule surface | All submodules resolve through the parent grant. |
| **AN-RB-06** | Bootstrap needs the settings permission too | P0 | A user with provider-create but **not** settings-create, on an un-bootstrapped account | Create a provider with `bootstrap_cluster` set | 403 — pinning the cluster/subdomain is a settings write. Without `bootstrap_cluster`, the provider create is allowed. |
| **AN-RB-07** | Cross-account read isolation | P0 | Accounts A and B each with providers/policies/logs | As an A user, `GET` B's provider/policy/guardrail/budget-rule ids directly | 404/403 — never B's data. |
| **AN-RB-08** | Cross-account write isolation | P0 | Same | As an A user, `PUT`/`DELETE` a B resource id | Rejected; B's data unchanged. |
| **AN-RB-09** | Cross-account log isolation | P0 | Both accounts have traffic | List A's access logs and usage | Only A's rows; no B user ids, models or costs. |
| **AN-RB-10** | Unauthenticated access | P0 | — | Call each agent-network endpoint with no token and with an invalid token | 401; no data leaked in the error body. |
| **AN-RB-11** | Service-user / PAT access | P2 | A PAT for an admin | Drive the full provider→policy→request flow via PAT | Works identically to session auth. |

---

## 12. Dashboard — providers page and the provider wizard

| ID | Title | P | Preconditions | Steps | Expected |
|---|---|---|---|---|---|
| **AN-UI-01** | Empty state before bootstrap | P0 | Fresh account | Open **Agent Network → Providers** | The API-Base-URL card shows the dashed "Connect your first provider to set up your agent network endpoint" prompt and opens the wizard on click. |
| **AN-UI-02** | Endpoint badge after bootstrap | P0 | Bootstrapped | Reload the page | Badge shows `https://<subdomain>.<cluster>`; the tooltip explains base-URL usage; **Copy** copies the full `https://` URL and confirms with a toast. |
| **AN-UI-03** | No validated cluster blocks create | P0 | Account with no validated FREE cluster | Open the wizard | The no-clusters state is shown and the operator cannot complete a first create. Add a validated cluster → the wizard proceeds. |
| **AN-UI-04** | Cluster auto-pick | P1 | ≥1 validated cluster, not bootstrapped | Open the wizard | The first validated cluster is preselected; the operator can change it before the first create. |
| **AN-UI-05** | Cluster picker hidden after bootstrap | P1 | Bootstrapped | Open the wizard for a second provider | No cluster choice is offered (the hint would be ignored anyway). |
| **AN-UI-06** | Provider type switching | P1 | — | Switch between OpenAI / Anthropic / Bedrock / Vertex / LiteLLM / Portkey / Bifrost / OpenRouter / vLLM / Custom | Name and upstream URL prefill from the catalog per type; Vertex shows the clean `https://aiplatform.googleapis.com` placeholder rather than a templated host; provider entries are grouped by kind (provider / gateway / custom). |
| **AN-UI-07** | Continue is gated | P0 | — | Leave name blank, then enter an invalid URL, then a 3-character API key | The Continue/Save action stays disabled until: a type is chosen, the name is non-blank, the URL matches `http(s)://…`, the key is ≥4 characters, and (first create) a cluster is picked. |
| **AN-UI-08** | Mappings tab visibility | P1 | — | Select `litellm_proxy`, `portkey`, `bifrost`, `cloudflare_ai_gateway`, `vercel_ai_gateway`, `openrouter`, `bedrock_api`; then switch to `openai_api` while on the Mappings tab | Mappings appear only for those types; switching to a type without mappings snaps the wizard back to the Provider tab (no blank tab). |
| **AN-UI-09** | Model rows | P1 | — | Add catalog models, add a custom model row, add an empty row, add two rows with the same id | Catalog picks prefill prices; a model already added can't be picked twice; empty rows are dropped on save; duplicate ids collapse to the first row (no ambiguous price is sent). |
| **AN-UI-10** | Price prefill matches live defaults | P1 | An operator pricing override is configured | Add a catalog model | The prefilled price matches what the proxy will actually bill (live default table), not the compiled catalog rate. |
| **AN-UI-11** | Edit shows a masked key | P0 | Provider exists | Open it for edit | The API key field shows a masked placeholder; saving without touching it preserves the stored key (verify a request still succeeds). |
| **AN-UI-12** | Stale extra values are dropped on type switch | P2 | — | Fill Portkey's config header, then switch the type to OpenAI and save | The Portkey-only key is not persisted. |
| **AN-UI-13** | Providers table | P1 | Several providers | Review the table | Name, logo, type, upstream, model count, enabled state; row actions (edit/delete/enable) behave; the delete-blocked error from AN-PR-18 is surfaced as a readable message, not a raw payload. |
| **AN-UI-14** | Agent Config modal — tabs | P0 | Bootstrapped, providers connected | Click **Agent Config** | Tabs: Claude Code, Codex, OpenAI SDK, cURL. Every snippet embeds the account's real endpoint (`https://<endpoint>`, `/v1` where appropriate) and copies to clipboard correctly. |
| **AN-UI-15** | Claude Code backend selector | P1 | — | Switch between Anthropic API / Vertex AI / Bedrock, and toggle JSON ↔ Shell | Each variant renders the right env vars (`ANTHROPIC_BASE_URL`, `ANTHROPIC_VERTEX_BASE_URL` with `/v1`, `ANTHROPIC_BEDROCK_BASE_URL` with `/bedrock`) and JSON/Shell forms are equivalent. |
| **AN-UI-16** | Kimi surfaces are gated on a Kimi provider | P1 | No `kimi_api` provider | Open the modal | No **Kimi CLI** tab and no Kimi option in the Claude Code selector. Add a `kimi_api` provider → both appear, and when Kimi is the only Anthropic-shaped provider the selector opens on Kimi. |
| **AN-UI-17** | Kimi snippets actually work | P1 | `kimi_api` provider with the default `https://api.moonshot.ai` upstream | Follow the Claude Code Kimi snippet (`ANTHROPIC_BASE_URL=<endpoint>/anthropic`) and the Kimi CLI snippet (bare endpoint, `type="anthropic"`) | Both drive real completions through NetBird; usage is logged against the Kimi provider. |
| **AN-UI-18** | cURL snippet is copy-paste runnable | P0 | Tunnel connected, OpenAI provider + policy | Copy the cURL snippet and run it | Returns a completion; the copied text is a single-line command even though it is displayed multi-line. |
| **AN-UI-19** | Codex snippet | P1 | — | Apply the `~/.codex/config.toml` snippet and run Codex | Requests route through NetBird. |
| **AN-UI-20** | OpenAI SDK snippet | P1 | — | Run the Python snippet with `api_key="not-needed"` | Returns a completion. |

---

## 13. Dashboard — policies, guardrails, limits, configuration

| ID | Title | P | Preconditions | Steps | Expected |
|---|---|---|---|---|---|
| **AN-UI-21** | Policies table | P1 | Several policies | Open **Agent Network → Policies** | Name, enabled toggle, source groups, destination providers, guardrail summary and limits render correctly; the enabled toggle persists. |
| **AN-UI-22** | Policy modal tabs | P1 | — | Walk the General / Guardrails / Limits tabs | Tab state is preserved while the modal is open; validation errors are shown next to the offending field, not only as a toast. |
| **AN-UI-23** | Limits tab window authoring | P1 | — | Author a window in minutes, hours, and days | The wire value is seconds; the default is 30 days (2,592,000 s); Save is disabled unless at least one cap is > 0 and the window is ≥ 60 s. |
| **AN-UI-24** | Limits display formatting | P2 | Policies with several window lengths | Review the limits column | Windows render as human units (e.g. "30 days", "1 hour"), and USD caps are formatted as currency. |
| **AN-UI-25** | Guardrail checks cell | P2 | Guardrails with different check combinations | Review the policy table | The cell summarises model allowlist and prompt capture accurately, including the "no checks" case. |
| **AN-UI-26** | Global Limits tab | P0 | — | **Configuration → Global Limits**: create, edit, disable and delete a budget rule; scope it to groups, to users, to both, and to neither | Each variant saves and reloads correctly; the "applies to everyone" (no targets) case is clearly communicated in the UI. |
| **AN-UI-27** | Budget rule save gating | P1 | — | Leave the name blank; then set a rule with no positive cap | Save stays disabled / the request is rejected with a readable message. |
| **AN-UI-28** | Log Collection tab | P0 | — | Toggle log collection, change retention, toggle prompt collection, click **Save Changes** | Save is disabled until something changes; the retention select is disabled (and visually dimmed) while log collection is off; a failed save keeps the unsaved-changes state; a successful save clears it. |
| **AN-UI-29** | Prompt-collection help copy is accurate | P2 | — | Read the helper text | It states that a policy guardrail must also be enabled (matching AN-GR-14). |
| **AN-UI-30** | Clusters tab | P1 | — | **Configuration → Clusters** | Lists clusters with validation state; the copy differs appropriately between focused (agent-network-only) mode and the full dashboard; the docs link opens. |
| **AN-UI-31** | Deep-linkable tabs | P2 | — | Open `/agent-network/configuration?tab=log-settings`, `?tab=clusters`, `/agent-network/usage?tab=access-logs`; use browser back/forward | The right tab opens; the active tab is reflected in the URL; back/forward restores the previous tab; an invalid `?tab=` value falls back to the default. |
| **AN-UI-32** | Restricted-access states | P1 | A user without `services.read` | Open each Agent Network page | The restricted-access component renders; no underlying data fetches are made (check the network tab); no console errors. |

---

## 14. Focused mode, navigation and onboarding

| ID | Title | P | Preconditions | Steps | Expected |
|---|---|---|---|---|---|
| **AN-NAV-01** | Menu hidden by default | P1 | Account with neither the feature flag nor the account setting | Open the dashboard | No Agent Network menu entry; direct navigation to `/agent-network/providers` behaves per the guard (redirect or restricted state), not a crash. |
| **AN-NAV-02** | Feature flag shows the menu | P0 | `dashboard_features.agent_network = true` | Reload | Agent Network appears in the nav with Providers, Policies, Usage & Logs, Configuration — **alongside** the rest of the dashboard. |
| **AN-NAV-03** | Account-level focused mode | P0 | `settings.agent_network_only = true` | Reload | The dashboard is focused on Agent Network; unrelated sections are hidden. Toggling it back off restores the full dashboard. |
| **AN-NAV-04** | Deployment-level focused mode is a floor | P0 | `NETBIRD_AGENT_NETWORK_ONLY` set on the deployment | Set the account setting to `false` and reload | Focused mode still applies — the env flag cannot be overridden by the per-account setting. |
| **AN-NAV-05** | Signup-source optimism | P1 | New account from the netbird.ai signup source, `signup_form_pending=true`, no explicit `agent_network_only` | Log in | Focused view applies immediately — the regular onboarding must not flash first. |
| **AN-NAV-06** | Explicit choice beats optimism | P1 | Same, but `agent_network_only = false` explicitly | Log in | The user's explicit choice is respected (no focused view). |
| **AN-NAV-07** | Loading guard | P2 | Slow `/accounts` response (throttle the network) | Load the dashboard | No premature redirect or flicker between modes while the account is still loading. |
| **AN-ONB-01** | Full onboarding walkthrough | P0 | Fresh focused-mode account, `signup_form_pending=true` | Walk Signup → Welcome → Device → Provider → Policy → Configure → End | Every step advances; the stepper reflects progress; the modal cannot be dismissed with Esc or an outside click. |
| **AN-ONB-02** | Signup step is skipped when already submitted | P1 | `signup_form_pending=false` | Enter onboarding | Opens on Welcome, never on Signup, and never returns to Signup. |
| **AN-ONB-03** | Device step detects a connection | P0 | No peers | Sit on the Device step and install/connect a client | The step detects the peer within ~5 s (it polls) without a manual refresh, and Continue unblocks. |
| **AN-ONB-04** | First-run seeding | P0 | Fresh account | Reach the Policy step | A "Users" source group exists containing the current user, and the permissive **Default** access-control policy has been removed. Verify both in Groups / Access Control. |
| **AN-ONB-05** | Provider step creates a working provider | P0 | — | Complete the Provider step | A provider is created and settings are bootstrapped (endpoint assigned). |
| **AN-ONB-06** | Policy step creates a working policy | P0 | — | Complete the Policy step | A policy exists linking the seeded group to the new provider. |
| **AN-ONB-07** | Configure step snippets work | P0 | — | Copy the inline snippet on the Configure step and run it from the connected device | A real completion is returned end to end. |
| **AN-ONB-08** | Resume after refresh | P1 | Mid-onboarding (e.g. step 5) | Hard-refresh the browser | Onboarding resumes on the same step, not from the beginning. |
| **AN-ONB-09** | Skip to dashboard | P1 | Any step except Signup and End | Click **Skip to Dashboard** | Onboarding closes and does not reappear on the next load. |
| **AN-ONB-10** | Finish | P1 | End step | Click Finish | Lands on the Agent Network dashboard with the created provider/policy visible and the endpoint badge populated. |
| **AN-ONB-11** | Onboarding is idempotent | P2 | Completed onboarding | Log out and back in; reload several times | Onboarding does not restart; the seeded group is not duplicated. |

---

## 15. Cross-cutting, resilience and security

| ID | Title | P | Steps | Expected |
|---|---|---|---|---|
| **AN-X-01** | Secrets never leak | P0 | Grep every provider/policy/settings API response, the dashboard network tab, and management/proxy logs at debug level for the upstream API key and the session private key | Neither value appears anywhere. |
| **AN-X-02** | Prompt content respects the gates in logs | P0 | With prompt capture **off**, send a distinctive prompt and grep management/proxy logs and the DB | The prompt body appears nowhere. |
| **AN-X-03** | Management restart | P0 | Restart management with traffic in flight | Service resumes; providers/policies/limits/counters survive; the endpoint serves again without reconfiguration. |
| **AN-X-04** | Proxy restart | P0 | Restart the proxy | Config is re-synthesised and pushed; requests resume without a management change. |
| **AN-X-05** | Migration of an existing account | P0 | Upgrade a deployment that already has agent-network rows from the previous release | Existing providers/policies/guardrails/budget rules/settings survive; providers missing a session keypair are backfilled automatically on the next synthesis (no dial failures). |
| **AN-X-06** | Fresh install | P1 | Deploy from scratch and run §3 → §8 | The full flow works with no manual DB steps. |
| **AN-X-07** | SQLite and PostgreSQL parity | P1 | Run §7, §9 and §10 against both store backends | Identical behaviour, especially access-log sorting/grouping and consumption aggregation. |
| **AN-X-08** | Injection safety on filters | P0 | Pass SQL/JS payloads into `search`, `path`, `model`, `user_id`, `session_id` and the group/provider multi-filters | Treated as literal text; no SQL error, no 500, no reflected script execution in the dashboard. |
| **AN-X-09** | Pagination overflow | P2 | Request `?page=99999999999&page_size=100` | No overflow, no 500 — an empty page is fine. |
| **AN-X-10** | Unicode and long strings | P2 | Create providers/policies/guardrails with emoji, RTL text and 500-character names | Stored and rendered correctly (or rejected with a clear length error) — never truncated silently mid-codepoint. |
| **AN-X-11** | Idempotent double-submit | P1 | Double-click Save on the provider, policy and budget-rule modals | Exactly one record is created. |
| **AN-X-12** | Concurrent edits | P2 | Two admins edit the same policy simultaneously | Last write wins without corruption; neither session gets a 500. |
| **AN-X-13** | Activity log coverage | P1 | Create/update/delete one of each entity (provider, policy, guardrail, budget rule) and change settings | Every mutation produces a distinct, correctly attributed activity event. |
| **AN-X-14** | Dark/light and responsive rendering | P2 | View every Agent Network page at 1280 px and 1440 px, and check wide tables | No horizontal page scroll; wide tables scroll within their own container; no clipped controls. |

---

## 16. Suggested execution order

1. **§3 Bootstrap → §4 Providers → §5 Policies** — nothing else can be tested until an endpoint serves.
2. **§8 Runtime routing** — prove one request works end to end over the tunnel.
3. **§7 Limits** and **§9 Usage/cost** — the highest-risk correctness areas; budget the most time here.
4. **§6 Guardrails** and **§10 Access logs** — depend on live traffic from step 2.
5. **§11 Permissions/tenancy** — run against the data created above.
6. **§12–§14 Dashboard, focused mode, onboarding** — needs a second fresh account for the onboarding cases.
7. **§15 Cross-cutting** — restart/migration cases last, since they disturb the environment.

## 17. Reporting template

For each failure, capture: test id, environment (deployment, cluster, account),
the request (method, path, body with secrets redacted), the actual response
(status + body), the access-log row id and session id if one exists, the
management and proxy log excerpts around the timestamp, and the deny code where
one was returned.
