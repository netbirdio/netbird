# MCP OAuth broker

This package runs an OAuth 2.1 authorization server (the broker) so
[Model Context Protocol](https://modelcontextprotocol.io) clients can sign users in to
management's MCP endpoint at `/api/mcp` without a personal access token. It is off
unless `NB_MCP_ENABLED` is true. The package authenticates calls to `/api/mcp` but
mounts no handler there.

## Enabling

| Variable | Meaning |
| --- | --- |
| `NB_MCP_ENABLED` | A true value (`strconv.ParseBool`) starts the broker when it can. Unset, false or unparseable leaves it off; an unparseable value is logged. |
| `NB_MCP_OAUTH_KEY` | Optional secret of at least 32 bytes that seals the broker's codes and tokens. See [Keys](#keys). |
| `NB_CACHE_REDIS_ADDRESS` | Management's existing shared cache address. When set, broker grants live there. See [Grants](#grants). |

With `NB_API_RATE_LIMITING_ENABLED=true`, calls with a broker token are limited per
user with the API limiter's settings; over the limit answers 429.

## OAuth broker

Identity providers rarely offer open dynamic client registration or tokens scoped to
one MCP server, so management runs its own authorization server under `/api/mcp/auth`.
It registers clients, renders consent, sends the user to the identity provider only to
log in, receives that login on its own callback, and issues its own tokens.

The broker starts when `NB_MCP_ENABLED` is true, a PKCE flow is available (see
[Identity provider setup](#identity-provider-setup)), the keys resolve and the grant
store is reachable. Otherwise management logs why, serves none of the endpoints below,
and adds no pointer to OAuth metadata to the endpoint's 401.

### Endpoints

The authorization server's endpoints sit under `/api/mcp/auth`. Three discovery
documents are served at the root, where clients look first; [Reverse proxy](#reverse-proxy)
covers the forms under `/api`.

- `/.well-known/oauth-protected-resource/api/mcp` (RFC 9728)
- `/.well-known/oauth-authorization-server/api/mcp/auth` (RFC 8414)
- `/.well-known/openid-configuration/api/mcp/auth`

Everything but `/api/mcp` bypasses the API authentication and its rate limiter. The
issuer is `<base>/api/mcp/auth` and the resource `<base>/api/mcp`, where `<base>` comes
from the embedded IdP's issuer or else the request; see [Reverse proxy](#reverse-proxy).

### The flow

1. **Discovery and registration.** A call to `/api/mcp` without a valid credential gets
   401 with an RFC 9728 `resource_metadata` pointer. Registration is open and stores
   nothing: the client ID seals the redirect URIs and the name, and never expires. Only
   `https` redirect URIs, or `http` on a loopback host, are kept.
2. **Authorize.** `redirect_uri` must match a registered one exactly, or on any port for
   loopback `http` (RFC 8252 section 7.3), and PKCE `S256` is required. A malformed
   request is redirected as an OAuth error only to a loopback client; an `https` client
   gets an error page, since open registration would otherwise make this an open
   redirector.
3. **Consent.** The page names the client and the host the code goes to; write access is
   a ticked checkbox when the client asked for `mcp:write` or no scope. The request is
   sealed into the form and bound to the browser by the consent cookie, a post from
   another origin (by `Sec-Fetch-Site`) gets 403, and the page is unframeable and arms
   the approve button only after pointer or keyboard input.
4. **Login.** Approve sends the user to the identity provider with the broker's own PKCE
   verifier, state and callback; the client's challenge, state and redirect URI never
   reach it, and no `prompt=login` is sent. The callback validates the returned token
   like a dashboard login, JWT group restrictions included, requires a user of that
   account who is neither blocked nor pending approval, and discards the identity
   provider's token.
5. **Token.** A code lasts 2 minutes and redeems once, for the client ID, `redirect_uri`,
   PKCE verifier and `resource` it was issued to. A second redemption also revokes the
   session the first one started (OAuth 2.1 section 4.1.3).
6. **Calling `/api/mcp`.** `AuthMiddleware` checks a broker token itself: unexpired,
   issued for this `<base>/api/mcp`, and its grant still there. The user is reloaded on
   every call and must still exist, be neither blocked nor pending approval, belong to the
   same account, and not have been created more than a minute after the session began. A
   refused token answers 401 with the challenge; a grant or user store outage answers 503.

### Sessions and refresh

A code redemption starts a session that ends 30 days later; refreshing never moves
that end. Access tokens last 1 hour and never outlive the session. Refresh tokens
rotate on each use (OAuth 2.1 section 4.3.1):

- For 10 seconds after a rotation, the replaced and the new token both get the
  current tokens without another rotation, so a refresh burst cannot chain rotations.
- Each refresh is one atomic step on the grant (a Lua script in Redis, a mutex in
  memory), so racing refreshes rotate once and a revocation cannot interleave.
- Any older refresh token is a replay: it is refused and the whole session is revoked.
- When the grant store or the user store cannot answer, token requests and MCP calls
  get 503 instead of an error that makes the client sign in again. A rotation whose
  reply was lost may still have landed: a retry within 10 seconds gets its result, a
  later one presents the replaced token and is a replay.

### Sealed values

Client IDs, codes, tokens and the consent and login state are JSON sealed with
AES-256-GCM, with the purpose bound as associated data so one kind cannot be replayed as
another. Client IDs start with `nbmcpc_`, codes with `nbmcpk_`, access tokens with
`nbmcp_` and refresh tokens with `nbmcpr_`, which secret scanners can match. Codes and
tokens carry the user ID, account ID, a SHA-256 fingerprint of the client ID, the
resource and the scopes, never the identity provider's token.

### Grants

A grant is the record of one login, created when its code is redeemed. Grants live in
Redis at `NB_CACHE_REDIS_ADDRESS` (or the legacy `NB_IDP_CACHE_REDIS_ADDRESS`) on a
connection of the broker's own, else in the management process. If Redis is
configured but unreachable at boot, the broker does not start. Keys start with
`mcp-oauth:`, and deleting `mcp-oauth:session:*` ends every session.

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

The `management` command saves a generated datastore key to its config file as
`DataStoreEncryptionKey`; the combined server generates one per start unless
`server.store.encryptionKey` is set. Persist it.

### Cookies

The consent cookie (`SameSite=Strict`) ties the consent form to the browser, and the
login cookie (`Lax`, since the identity provider returns the user with a cross-site
navigation) carries the login state to the callback. Both are `HttpOnly`, last 10
minutes and are cleared once used. Over https they are `__Host-` cookies, which a sibling
subdomain cannot plant; over plain http they lack that protection. Names are fixed, so a
second connection started before the first finishes ends the first on an error page.

### Revocation model

| To cut off | Do | Takes effect |
| --- | --- | --- |
| One connection | The client calls the revocation endpoint with either token; a `client_id`, when sent, must match | Next MCP call and refresh |
| One user on every client | Block or remove the user in NetBird, or move them to another account | Next MCP call and refresh |
| Every MCP client of every user | Change `NB_MCP_OAUTH_KEY` | Once every instance restarts with it |
| A user disabled at the identity provider or removed from JWT allow groups | Nothing, or block the user in NetBird for immediate effect | Next login, at most 30 days later |

A stolen access token gives the user's API access through `/api/mcp`, within its
scopes, for at most 1 hour. A stolen refresh token works until the thief and the client
refresh more than 10 seconds apart: the later of the two presents a replaced token,
which is a replay and revokes the session for both. A stolen code is useless without
the client's PKCE verifier.

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
  budget. `TrustedHTTPProxiesCount` is not used: trusting the header by position lets a
  client that reaches management directly choose its own address. List the proxy in
  `TrustedHTTPProxies` for a budget per client.
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
application's allowed redirect URIs, once for every host MCP clients use. The code
exchange goes through `golang.org/x/oauth2` as in `netbird up`, so a secret is sent in
HTTP Basic or the form, whichever the provider takes, and the token is checked with the
validator an agent's SSO login goes through. A flow that works for `netbird up` works
here once the callback is allowed, unless the provider requires the client certificate
agents can present (`ClientCertPath`): the broker presents none.

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

## Tenant URLs

`/api/mcp?account=<account id>` is a valid resource. The challenge, the resource
metadata and the accepted `resource` values repeat the query (RFC 9728 section 3.3),
while tokens bind to host and path only, so one sign-in serves every account URL.

## Wiring

`management/internals/server/mcp.go` builds the broker (`MCPBroker`, `mcpBaseURL`,
`registerMCPEndpoints`). In `boot.go`, `Router` installs `ChallengeMiddleware` and wraps
the auth middleware, the last element of `BuildMiddleware`, with `AuthMiddleware`;
`APIHandler` mounts the broker's endpoints in its `http_mcp` block.

## Tests

```bash
go test ./management/internals/modules/mcpapi/...
go test -run MCP ./management/internals/server/
```
