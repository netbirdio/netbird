# MCP endpoint and OAuth broker

This package serves the management REST API as a
[Model Context Protocol](https://modelcontextprotocol.io) server at `/api/mcp`, and
runs an OAuth 2.1 authorization server (the broker) so MCP clients can sign users in
without a personal access token. Both are off unless `NB_MCP_ENABLED` is true.

## How tool calls work

- Every tool maps onto exactly one REST operation: `list_peers` is `GET /api/peers`,
  `update_peer` is `PUT /api/peers/{peer_id}`. The catalog is in `catalog.go`.
- A tool call is replayed in-process against the API router, so it runs the same
  handler and permission checks and returns the same JSON as the REST call. A non-2xx
  response becomes a tool error carrying the status and the API's error body, and a
  panic in a handler is recovered into a tool error.
- Input schemas are derived from the generated request types in
  `shared/management/http/api`, with path and query arguments added as top-level
  properties. Arguments are validated against the schema before the request is built,
  so a misspelled, missing or mistyped field fails the call instead of reaching an
  update as a zero value. A path argument containing `/` or `\`, or `.` or `..`, is
  refused.
- `account_id` is never taken from the client. Dispatch fills it from the caller's
  identity (`callerBound` in `catalog.go`), so `update_account` only acts on the
  account the request is authenticated for.
- `update_*` tools have PUT semantics: an omitted field resets. Their descriptions say
  so, and they are annotated destructive, like the delete tools.
- The catalog only holds operations the public OpenAPI spec
  (`shared/management/http/api/openapi.yml`) documents and does not mark
  `x-cloud-only`; `openapi_test.go` enforces it. Account deletion is left out: a
  deployment may guard it with middleware on the root router, as NetBird Cloud does
  for MSP tenants, and in-process dispatch does not pass through that router.

The transport is streamable HTTP in stateless mode with JSON responses. Every JSON-RPC
message is its own HTTP request, so each tool call is authenticated, rate limited and
metered like the REST call it stands for. JSON-RPC batches are refused with 400, so one
request carries at most one tool call. `GET` and `DELETE` answer 405.

`mcpapi_test.go` fails when a tool description or the server instructions name a tool
the catalog does not have.

## Enabling

| Variable | Meaning |
| --- | --- |
| `NB_MCP_ENABLED` | A true value (`strconv.ParseBool`) mounts `/api/mcp` and, when it can start, the broker. Unset, false or unparseable leaves both off; an unparseable value is logged. |
| `NB_MCP_TOOLS` | Optional comma-separated tool allowlist. Empty exposes the whole catalog. An unknown name stops management at boot. |
| `NB_MCP_OAUTH_KEY` | Optional secret of at least 32 bytes that seals the broker's codes and tokens. See [Keys](#keys). |
| `NB_CACHE_REDIS_ADDRESS` | Management's existing shared cache address. When set, broker grants live there. See [Grants](#grants). |

With `NB_API_RATE_LIMITING_ENABLED=true`, PAT calls are limited per token by the API
middleware and broker-token calls per user with the same limiter settings; over the
limit answers 429.

## Connecting a client

`<management>` below is the public scheme and host of management, the one the
dashboard calls the API on.

### With a personal access token

```bash
claude mcp add --transport http netbird https://<management>/api/mcp \
  --header "Authorization: Token nbp_..."
```

Any client that speaks streamable HTTP takes the same URL and header:

```json
{"mcpServers": {"netbird": {
  "type": "http",
  "url": "https://<management>/api/mcp",
  "headers": {"Authorization": "Token nbp_..."}
}}}
```

A smoke test that lists the tools:

```bash
curl -s https://<management>/api/mcp \
  -H "Authorization: Token nbp_..." \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### With OAuth

Give the client the URL only:

```bash
claude mcp add --transport http netbird https://<management>/api/mcp
```

In Claude Code, run `/mcp`, select `netbird` and authenticate. A browser opens the
consent page, then the identity provider's login. Other clients that implement MCP
authorization (RFC 9728 discovery, dynamic client registration, PKCE) work the same
way.

### Accepted credentials

| `Authorization` header | Accepted on |
| --- | --- |
| `Token nbp_...` (personal access token) | The whole API, `/api/mcp` included |
| `Bearer <JWT>` (dashboard login) | The whole API, `/api/mcp` included |
| `Bearer nbmcp_...` (broker access token) | Exactly `/api/mcp`; anywhere else the API authentication rejects it |

## OAuth broker

Identity providers rarely offer open dynamic client registration or tokens scoped to
one MCP server, so management runs its own authorization server under `/api/mcp/auth`.
It registers clients, renders consent, sends the user to the identity provider only to
log in, receives that login on its own callback, and issues its own tokens.

The broker starts when `NB_MCP_ENABLED` is true, a PKCE flow is available (see
[Identity provider setup](#identity-provider-setup)), the keys resolve and the grant
store is reachable. Otherwise management logs why, `/api/mcp` accepts PATs and JWTs
only, and its 401 carries no pointer to OAuth metadata.

### Endpoints

| Path | Method | Purpose |
| --- | --- | --- |
| `/api/mcp` | `POST` | The MCP endpoint. |
| `/api/mcp/.well-known/oauth-protected-resource` | `GET` | RFC 9728 protected resource metadata. The 401 challenge points here. |
| `/.well-known/oauth-protected-resource/api/mcp` | `GET` | The same document at its RFC 9728 root location. |
| `/.well-known/oauth-authorization-server/api/mcp/auth` | `GET` | RFC 8414 authorization server metadata. |
| `/.well-known/openid-configuration/api/mcp/auth`, `/api/mcp/auth/.well-known/openid-configuration` | `GET` | The same metadata, for clients that try OpenID discovery. |
| `/api/mcp/auth/register` | `POST` | RFC 7591 dynamic client registration. |
| `/api/mcp/auth/authorize` | `GET` | Validates the request and renders the consent page. |
| `/api/mcp/auth/authorize` | `POST` | The consent decision. |
| `/api/mcp/auth/callback` | `GET` | Where the identity provider returns the user. |
| `/api/mcp/auth/token` | `POST` | Redeems authorization codes and refresh tokens. |
| `/api/mcp/auth/revoke` | `POST` | RFC 7009 revocation: ends the session the token belongs to. |
| `/api/mcp/auth/jwks` | `GET` | An empty key set: the metadata names one for OpenID clients, and the broker signs nothing they verify. |

Everything but `/api/mcp` bypasses the API authentication and its rate limiter. The
issuer is `<base>/api/mcp/auth` and the resource `<base>/api/mcp`, where `<base>` comes
from the embedded IdP's issuer or else the request; see [Reverse proxy](#reverse-proxy).

### The flow

1. **Challenge.** A call to `/api/mcp` without a valid credential gets 401.
   `ChallengeMiddleware` adds `WWW-Authenticate: Bearer resource_metadata="<base>/api/mcp/.well-known/oauth-protected-resource"`
   and exposes `WWW-Authenticate`, `Mcp-Session-Id` and `Mcp-Protocol-Version` through
   CORS.
2. **Discovery.** The resource metadata names the broker as the only authorization
   server and the scopes `mcp:read` and `mcp:write`. The server metadata advertises
   response type `code`, grants `authorization_code` and `refresh_token`, PKCE `S256`
   only, token endpoint authentication `none` and RFC 9207 `iss`.
3. **Registration.** Only absolute `https` redirect URIs, or `http` on a loopback host
   (`localhost`, `127.0.0.0/8`, `::1`), with no fragment, no user info and an ASCII
   host are kept; others are dropped. None left answers 400 `invalid_redirect_uri`, a
   body that is not a JSON object 400 `invalid_client_metadata`. Success is 201 with
   no secret. The client ID (`nbmcpc_...`) seals the redirect URIs, the name (cut to
   100 bytes) and the issue time; nothing is stored and it never expires.
4. **Authorize.** Until the client ID opens and `redirect_uri` matches a registered
   one (exactly, or for loopback `http` on any port, RFC 8252 section 7.3), errors
   render a 400 page. After that, a malformed request is redirected as an OAuth error
   only to a loopback client; an `https` client gets the page, since open
   registration would otherwise make this an open redirector. Checked in order:
   `state` up to 1024 characters, `response_type=code`, S256 with a 43 to 128
   character challenge, and `resource` (RFC 8707), when sent, naming `<base>/api/mcp`.
5. **Consent.** The page names the client and the host the code goes to, and warns
   for a loopback redirect. Read access is always granted; write access is a ticked
   checkbox when the client asked for `mcp:write` or no scope. The request is sealed
   into the form and bound to the browser by a nonce cookie. The page is `no-store`,
   unframeable (`X-Frame-Options`, CSP `frame-ancestors 'none'`), and arms the
   approve button only after pointer or keyboard input.
6. **Decision.** A post whose `Sec-Fetch-Site` is present and not `same-origin` gets
   403. The sealed request must open and be unexpired and the cookie must match.
   Cancel redirects with `access_denied`. Approve fixes the scopes, generates the
   broker's own PKCE verifier and state, seals them into the login cookie and
   redirects to the identity provider with the PKCE flow's client ID, scope, audience
   when set, and `<base>/api/mcp/auth/callback`. The client's challenge, state and
   redirect URI never reach the identity provider, and no `prompt=login` is sent.
7. **Callback.** The login cookie must open, its state match and its first use be
   recorded (a replay gets an error page). The broker redeems the code and validates
   the token like a dashboard login: `ValidateAndParseToken`,
   `GetAccountIDFromUserAuth`, `EnsureUserAccessByJWTGroups`, `SyncUserJWTGroups`
   (failure only logged) and `GetUserFromUserAuth`; the user must not be blocked or
   pending approval and must belong to the account. The identity provider's token is
   then discarded. Failures redirect with `access_denied`, logged at debug.
8. **Token.** `authorization_code`: an unknown client is 401 `invalid_client`; the
   code must open, be unexpired, match the client ID, `redirect_uri` and PKCE
   verifier (else 400 `invalid_grant`) and `resource` (else 400 `invalid_target`). A
   second redemption answers `invalid_grant` and revokes the session the first one
   started (OAuth 2.1 section 4.1.3). `refresh_token`: every refusal answers 400
   `invalid_grant`, the only error on which the Go MCP SDK drops its tokens and signs
   in again. Other grant types are 400 `unsupported_grant_type`.
9. **Calling `/api/mcp`.** `AuthMiddleware` checks a `Bearer nbmcp_` token itself: it
   must open, be unexpired, name this `<base>/api/mcp` as resource, and its grant must
   exist. The user is reloaded and must still be active, in the same account, and not
   created after the session began. Failures answer 401 with the challenge. The call
   then runs as that user with the granted scopes; without `mcp:write`, tools that
   change data return a tool error.

### Sessions and refresh

A code redemption starts a session that ends 30 days later; refreshing never moves
that end. Access tokens last 1 hour and never outlive the session. Refresh tokens
rotate on each use (OAuth 2.1 section 4.3.1):

- For 10 seconds after a rotation, the replaced and the new token both get the
  current tokens without another rotation, so a refresh burst cannot chain rotations.
- Each refresh is one atomic step on the grant (a Lua script in Redis, a mutex in
  memory), so racing refreshes rotate once and a revocation cannot interleave.
- Any older refresh token is a replay: it is refused and the whole session is revoked.
- When the grant store cannot answer, token requests and MCP calls get 503, so
  clients retry instead of signing in again.

### Sealed values

Every value is JSON sealed with AES-256-GCM, with the purpose bound as associated data
so one kind cannot be replayed as another.

| Value | Prefix | Lifetime | Travels in |
| --- | --- | --- | --- |
| Client ID | `nbmcpc_` | Unlimited | Client storage |
| Consent request | none | 10 minutes | Hidden form field |
| Login state | none | 10 minutes | Login cookie |
| Authorization code | `nbmcpk_` | 2 minutes, one redemption | Redirect to the client |
| Access token | `nbmcp_` | 1 hour, capped at the session end, while the grant exists | `Authorization` header |
| Refresh token | `nbmcpr_` | Until rotated, revoked or the session ends | Client storage |

Tokens and codes carry the user ID, account ID, a SHA-256 fingerprint of the client ID,
the resource and the scopes, never the identity provider's token.

### Grants

A grant is the record of one login, created when its code is redeemed. Grants live in
Redis at `NB_CACHE_REDIS_ADDRESS` (or the legacy `NB_IDP_CACHE_REDIS_ADDRESS`) on a
connection of the broker's own, else in the management process. If Redis is
configured but unreachable at boot, the broker does not start.

| Key | Holds | Expires |
| --- | --- | --- |
| `mcp-oauth:session:<grant id>` | User, account, client fingerprint, current and previous refresh token IDs, last rotation, start | With the session |
| `mcp-oauth:used-code:<code id>` | The grant the code started | With the code |
| `mcp-oauth:used-login:<state>` | Marker that the callback ran | With the login state |

Management running as more than one instance needs Redis. The in-memory store suits a
single instance, and a restart signs every MCP client out. Losing the store never lets
a token through; while it is unavailable, PATs keep working.

### Keys

Sealing keys are derived with HKDF-SHA256:

| Seals | Secret, first one set wins |
| --- | --- |
| Codes, tokens, consent and login state | `NB_MCP_OAUTH_KEY`, the datastore encryption key |
| Client IDs | The datastore encryption key, `NB_MCP_OAUTH_KEY` |

Every instance serving the same host needs the same secrets. Changing
`NB_MCP_OAUTH_KEY` signs every MCP client out at once; client IDs survive, so clients
sign in again with the registration they have. Removing it falls back to the datastore
key, which revives unexpired tokens sealed with that key. A value shorter than 32 bytes
keeps the broker from starting rather than falling back. Generate one with
`openssl rand -base64 32`.

The `management` command saves a generated datastore key to its config; the combined
server generates one per start unless `server.store.encryptionKey` is set. Persist it.

### Cookies

| Cookie | Set by | SameSite | Lifetime |
| --- | --- | --- | --- |
| `__Host-nb_mcp_consent` | Consent page | `Strict` | 10 minutes |
| `__Host-nb_mcp_login` | Approve | `Lax` | 10 minutes |

Both are `HttpOnly` and cleared once used; the login cookie is `Lax` because the
identity provider returns the user with a cross-site navigation. Over https the
`__Host-` prefix, `Secure` and `Path=/` keep a sibling subdomain from planting either
cookie. Over plain http they carry neither, with path `/api/mcp/auth`. Names are fixed,
so a second connection started before the first finishes ends the first on an error
page.

### Revocation model

| To cut off | Do | Takes effect |
| --- | --- | --- |
| One connection | The client calls the revocation endpoint with either token; a `client_id`, when sent, must match | Next MCP call and refresh |
| One user on every client | Block or remove the user in NetBird, or move them to another account | Next MCP call and refresh |
| Every MCP client of every user | Change `NB_MCP_OAUTH_KEY` | Once every instance restarts with it |
| A user disabled at the identity provider or removed from JWT allow groups | Nothing, or block the user in NetBird for immediate effect | Next login, at most 30 days later |

A stolen access token gives the user's API access through `/api/mcp`, within its
scopes, for at most 1 hour. A stolen refresh token works until either party refreshes
again, which is a replay and revokes the session for both. A stolen code is useless
without the client's PKCE verifier.

### Security notes

- **Consent** is asked on every authorization. The client name is self-chosen and
  proves nothing; the redirect host tells the user where the code goes.
- **Unauthenticated endpoints** take no credential. A value the broker did not seal is
  refused when it fails to decrypt, before any store, database or identity provider
  call, and registration stores nothing. Anyone can mint the login cookie the callback
  takes, though, and each callback stores a marker and may call the identity provider,
  so the callback is limited to 30 per minute per client address. The address comes
  from `X-Forwarded-For` only when the request arrives from one of
  `ReverseProxy.TrustedHTTPProxies`; otherwise everyone behind the proxy shares one
  budget.
- **Forwarded headers** are trusted from any caller when the base URL comes from the
  request. See [Reverse proxy](#reverse-proxy).

## Identity provider setup

**Embedded IdP (Dex).** Nothing to configure. The broker logs users in with the
`netbird-cli` public client via PKCE. `EmbeddedIdPConfig.ToYAMLConfig`
(`management/server/idp/embedded.go`) adds `<base>/api/mcp/auth/callback`
(`MCPCallbackPath`) to the redirect URIs of Dex's dashboard and CLI clients, and
`BaseServer.mcpBaseURL` uses the same `<base>`: the issuer without its `/oauth2`
suffix. The issuer must have the form `<scheme>://<host>/oauth2` with no trailing slash,
as the getting-started setup writes it, or the broker does not start and logs why. MCP
clients must connect at that host, since the resource metadata and the accepted
`resource` name it.

**External IdP.** The broker uses the `PKCEAuthorizationFlow` block in
`management.json`, the one `netbird up` SSO login uses. It reads `ClientID`,
`AuthorizationEndpoint` and `TokenEndpoint` (all required), `Scope`, `Audience`,
`UseIDToken`, and `ClientSecret` when the client is confidential. `RedirectURLs` and
`LoginFlag` are not used. Add `https://<management>/api/mcp/auth/callback` to that
application's allowed redirect URIs, once for every host MCP clients use. The token is
validated with the same validator as an agent's SSO login, so a flow that works for
`netbird up` works here.

## Reverse proxy

- Only `/api` and `/oauth2` (the embedded IdP) need to reach management. The challenge
  points to the resource metadata under `/api`, and the server metadata is also
  served at `/api/mcp/auth/.well-known/openid-configuration`, the last form MCP
  clients try. Clients validate that form as OpenID provider metadata, so it also
  carries `jwks_uri` (an empty key set at `/api/mcp/auth/jwks`),
  `subject_types_supported` and `id_token_signing_alg_values_supported`.
- Clients try the root `/.well-known/...` forms first. The NetBird dashboard image
  answers unknown paths with 404, so clients move on to the `/api` form. A proxy or
  frontend that answers them with 200 and HTML stops some clients there: route the
  three root documents to management in that case.
- With the embedded IdP, `<base>` comes from its issuer and forwarding headers are
  ignored. Without it, `<base>` takes its scheme from TLS or `X-Forwarded-Proto` and
  its host from `X-Forwarded-Host` or `Host` (first list entry), and the issuer,
  resource, callback and cookie security follow. The proxy must set or overwrite both
  headers; omitting `X-Forwarded-Proto: https` yields an `http://` callback the
  identity provider rejects.
- A proxy on the same host may connect over `127.0.0.1` and forward the public `Host`.
  The MCP SDK's DNS rebinding check would refuse that with 403, so it is off: every
  call carries its credential in a header, which a rebound page cannot obtain.

## Tenant URLs

`/api/mcp?account=<account id>` is accepted; the challenge, the resource metadata and
the accepted `resource` values repeat the query (RFC 9728 section 3.3), while tokens
bind to host and path only, so one sign-in serves every account URL. A deployment can
add a middleware that switches the request to that account when the caller may manage
it. Either way `requireTenant` (`server.go`) answers 403 unless the request ended up on
that account, so tools never silently run against the caller's own account, and 400
for an unparseable query, an empty `account` or a key such as `Account`. This
repository has no switching middleware, so only the caller's own account ID passes.

## Self-hosted metrics

`mcpMetrics` (`management/internals/server/mcp.go`) adds these properties to the
anonymous self-hosted metrics, which `--disable-anonymous-metrics` (or
`disableAnonymousMetrics` in the combined server config) turns off:

| Property | Meaning |
| --- | --- |
| `mcp_enabled` | `NB_MCP_ENABLED` is true |
| `mcp_oauth_enabled` | The broker is running |
| `mcp_tool_calls_last_day` | Tool calls, those returning a tool error included, in the current hour and the 23 before |
| `mcp_active_users_last_day` | Distinct users who made those calls |

`Usage` (`usage.go`) counts in memory per process in hourly buckets, so a restart
resets it and each instance reports its own. User IDs are kept only to count them and
are never reported.

## Code map

| File | Contents |
| --- | --- |
| `mcpapi.go` | `NB_MCP_ENABLED` and the endpoint path |
| `server.go` | `NB_MCP_TOOLS`, `RegisterEndpoints`, the stateless handler, batch refusal, the account check, the allowlist, `Routes` |
| `catalog.go`, `schema.go` | The tool catalog, `callerBound`, input schemas and annotations |
| `dispatch.go` | Argument validation, building the in-process REST request, results |
| `tenant.go` | The `account` query and resource canonicalization |
| `usage.go` | The 24 hour usage counter |
| `broker.go` | The authorization server and its metadata |
| `tokenauth.go` | `AuthMiddleware` and the read-only scope check |
| `challenge.go` | The 401 pointer and exposed headers |
| `discovery.go` | Paths, `FlowFromConfig`, redirect URI rules, `externalBaseURL` |
| `seal.go` | Sealing, `ResolveSecrets`, `NB_MCP_OAUTH_KEY` |
| `grants.go`, `grants_memory.go`, `grants_redis.go` | The grant store and the rotation rule |
| `consent.go` | Consent and error pages |

Wiring lives in `management/internals/server/mcp.go` (`MCPBroker`, `mcpBaseURL`,
`registerMCPEndpoints`, `mcpMetrics`) and `boot.go`: `Router` installs
`ChallengeMiddleware` and wraps the auth middleware, the last element of
`BuildMiddleware`, with `AuthMiddleware`; `APIHandler` mounts everything in its
`http_mcp` block.

## Tests

```bash
go test ./management/internals/modules/mcpapi/...
go test -run MCP ./management/internals/server/
go test -tags integration -run MCP ./management/server/http/testing/integration/
go test -tags e2e -timeout 25m -v ./e2e/mcp/...
```

The server test boots `BaseServer` with the embedded IdP and signs in through Dex. The
integration test runs tool calls against the real handlers and store with two accounts
and checks that no tool reads or changes the other one.

The grant store tests use Redis from testcontainers or `NB_MCP_TEST_REDIS_URL`, and
skip the Redis case without Docker. The e2e suite (`e2e/mcp/README.md`, CI in
`.github/workflows/mcp-e2e.yml`) runs the combined server with only
`NB_MCP_ENABLED=true` and drives a PAT session and the full OAuth login through Dex.
