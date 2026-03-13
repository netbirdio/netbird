# Migrating from External IdP to Embedded IdP

This guide walks through migrating a self-hosted NetBird deployment from an external identity provider (Auth0, Zitadel, Okta, Azure AD, Google, Keycloak, Authentik, PocketID) to the embedded Dex-based IdP introduced in v0.60.0.

## What the migration does

1. **Re-encodes user IDs** in the database so they include the external connector ID. This lets Dex route returning users back to the correct external provider.
2. **Generates a new management.json** that replaces `IdpManagerConfig` with `EmbeddedIdP` and updates the `HttpConfig` OAuth2 endpoints to point at the embedded Dex issuer.

Existing users keep logging in through the same external provider — Dex acts as a broker in front of it. No passwords or credentials change.

## Prerequisites

- NetBird **v0.60.0 or later** binaries (management server, or combined server).
- Access to the management server host and its `management.json`.
- The management server **must be stopped** while the migration runs (the tool writes directly to the database).
- A backup of your database and config (the tool creates `management.json.bak`, but you should have your own backup too).

## Supported identity providers

| Provider | Auto-detected | Notes |
|----------|:---:|-------|
| Auth0 | Yes | Maps to generic OIDC connector |
| Azure AD | Yes | Maps to Entra connector |
| Keycloak | Yes | |
| Okta | Yes | |
| Authentik | Yes | |
| PocketID | Yes | |
| Google | Yes | |
| Zitadel | No | Requires `--idp-seed-info` — see [Zitadel setup](#zitadel) below |
| JumpCloud | No | No Dex connector available — manual setup required |

Providers marked "No" for auto-detection require you to supply a connector via `--idp-seed-info`. The tool will print step-by-step instructions when it detects one of these providers.

## Step-by-step

### 1. Get the tool

**Option A: Download a pre-built binary** from the GitHub Releases page.

Each release includes `netbird-idp-migrate` archives for Linux (amd64, arm64, arm). Download the one matching your management server's architecture:

```bash
# Example for linux/amd64 — replace VERSION with the release tag
curl -L -o netbird-idp-migrate.tar.gz \
  https://github.com/netbirdio/netbird/releases/download/VERSION/netbird-idp-migrate_VERSION_linux_amd64.tar.gz
tar xzf netbird-idp-migrate.tar.gz
chmod +x netbird-idp-migrate
```

**Option B: Build from source** (requires Go 1.25+ and a C compiler for CGO/SQLite):

```bash
go build -o netbird-idp-migrate ./tools/idp-migrate/
```

Copy the binary to the management server host if building remotely.

### 2. Stop the management server

```bash
# systemd
sudo systemctl stop netbird-management

# docker compose
docker compose stop management
```

### 3. Back up your data

**Systemd / bare-metal** (database on the host filesystem):

```bash
cp /var/lib/netbird/store.db /var/lib/netbird/store.db.bak
cp /etc/netbird/management.json /etc/netbird/management.json.bak
```

**Docker Compose** (database inside a named volume):

The default `docker-compose.yml` stores the database in a Docker volume mounted at `/var/lib/netbird` inside the management container. The volume name varies by setup (e.g. `netbird_management`, `netbird_netbird_management`, `netbird_data`). To find it:

```bash
# Find the volume that holds store.db
docker volume ls --format '{{ .Name }}' | grep -i management
# Then inspect to get the host path
docker volume inspect <volume-name> --format '{{ .Mountpoint }}'
# e.g. /var/lib/docker/volumes/netbird_management/_data

# Verify store.db is there
sudo ls /var/lib/docker/volumes/<volume-name>/_data/

# Back up
sudo cp /var/lib/docker/volumes/<volume-name>/_data/store.db \
        /var/lib/docker/volumes/<volume-name>/_data/store.db.bak
cp ~/netbird/management.json ~/netbird/management.json.bak
```

**PostgreSQL**: use `pg_dump` instead of copying `store.db`.

### 4. Dry run

Always do a dry run first. This previews what would happen without writing anything:

```bash
./netbird-idp-migrate \
  --config /etc/netbird/management.json \
  --dry-run
```

You should see output like:

```
INFO resolved connector: type=zitadel, id=zitadel, name=zitadel
INFO found 12 total users: 12 pending migration, 0 already migrated
INFO [DRY RUN] migration dry-run mode enabled, no changes will be written
INFO [DRY RUN] would migrate user abc123 -> CgZhYmMxMjMSB3ppdGFkZWw (account: acct-1)
...
INFO [DRY RUN] migration summary: 12 users would be migrated, 0 already migrated
INFO derived domain for embedded IdP: mgmt.example.com
INFO [DRY RUN] new management.json would be:
{ ... }
```

Check that:
- The connector type and ID look correct for your provider.
- The user count matches what you expect.
- The generated config has the right domain and endpoints.

### 5. Run the migration

```bash
./netbird-idp-migrate \
  --config /etc/netbird/management.json
```

The tool will show a summary and ask for confirmation:

```
About to migrate 12 users. This cannot be easily undone. Continue? [y/N]
```

Type `y` and press Enter. You should see:

```
INFO DB migration completed successfully
INFO derived domain for embedded IdP: mgmt.example.com
INFO backed up original config to /etc/netbird/management.json.bak
INFO wrote new config to /etc/netbird/management.json
```

### 6. Review the new config

Open `/etc/netbird/management.json` and verify:

- `IdpManagerConfig` is gone.
- `EmbeddedIdP` is present with `"Enabled": true` and your connector in `StaticConnectors`.
- `HttpConfig.AuthIssuer` points to `https://<your-domain>/oauth2`.
- `HttpConfig.AuthClientID` is `"netbird-dashboard"`.

### 7. Update your reverse proxy

The embedded Dex IdP is served by the management server under the `/oauth2/` path. If your setup uses a reverse proxy (Caddy, nginx, Traefik, etc.) in front of the management server, you **must** add a route for `/oauth2/*` so that OIDC discovery and the login flow work.

**Caddy** (getting-started.sh setups use this):

Add the following to your `Caddyfile`, inside the site block for your management domain:

```
reverse_proxy /oauth2/* management:80
```

Place it alongside the existing `reverse_proxy /api/* management:80` and `reverse_proxy /management.ManagementService/* management:80` routes. Then reload Caddy:

```bash
docker compose restart caddy
# or
sudo systemctl reload caddy
```

**nginx:**

```nginx
location /oauth2/ {
    proxy_pass http://management:80;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

**Verify** the route is working before proceeding:

```bash
curl -s https://<your-domain>/oauth2/.well-known/openid-configuration | head -5
```

You should see a JSON response with `"issuer": "https://<your-domain>/oauth2"`.

### 8. Update dashboard.env

If your dashboard uses a separate `dashboard.env` or environment variables for authentication, update these to point to the embedded Dex IdP:

```bash
# Before (pointing to external IdP):
AUTH_AUTHORITY=https://external-idp.example.com
AUTH_CLIENT_ID=old-client-id
AUTH_AUDIENCE=old-audience

# After (pointing to embedded Dex):
AUTH_AUTHORITY=https://<your-domain>/oauth2
AUTH_CLIENT_ID=netbird-dashboard
AUTH_AUDIENCE=netbird-dashboard
```

Then restart the dashboard container or service.

### 9. Start the management server

```bash
sudo systemctl start netbird-management
# or
docker compose up -d management
```

### 10. Verify

- Open the OIDC discovery endpoint: `https://<your-domain>/oauth2/.well-known/openid-configuration` — it should return valid JSON.
- Log into the dashboard — you should be redirected through your external IdP as before.
- Check that peers are visible and policies are intact.
- **Important**: Use an incognito/private browser window or clear cookies for your first login. Stale tokens from the old IdP will fail validation.

## Command reference

```
Usage: netbird-idp-migrate [flags]

Flags:
  --config string        Path to management.json (required)
  --datadir string       Override data directory from config
  --idp-seed-info string Base64-encoded connector JSON (overrides auto-detection)
  --dry-run              Preview changes without writing
  --force                Skip confirmation prompt
  --skip-config          Skip config generation (DB migration only)
  --log-level string     Log level: debug, info, warn, error (default "info")
```

## Common scenarios

### DB-only migration (you'll edit config manually)

```bash
./netbird-idp-migrate \
  --config /etc/netbird/management.json \
  --skip-config
```

### Custom data directory

If your database lives somewhere other than what `Datadir` says in management.json (common with Docker volume mounts):

```bash
# Bare-metal with a non-default path
./netbird-idp-migrate \
  --config /etc/netbird/management.json \
  --datadir /custom/path/to/data

# Docker — point to the volume's host path (see step 3 to find it)
./netbird-idp-migrate \
  --config ~/netbird/management.json \
  --datadir /var/lib/docker/volumes/<volume-name>/_data
```

### Zitadel

Zitadel auto-detection is not supported because the management server uses service account credentials that cannot work as OAuth client credentials for the Dex OIDC connector. You need to create a new confidential OAuth application in Zitadel:

1. Open the Zitadel console at `https://<your-domain>/ui/console` (for getting-started.sh setups, Zitadel shares the same domain as NetBird).
2. Navigate to **Projects** → select the NetBird project → **Applications**.
3. Click **New** to create an application:
   - **Name**: `netbird-dex`
   - **Type**: Web
   - **Authentication Method**: POST (sends client_id + client_secret in request body)
4. Add redirect URI: `https://<your-management-domain>/oauth2/callback`
5. Save and copy the generated **Client ID** and **Client Secret**.
6. Create a `connector.json` file:

```json
{
  "type": "zitadel",
  "name": "zitadel",
  "id": "zitadel",
  "config": {
    "issuer": "https://<your-zitadel-domain>",
    "clientID": "<client-id-from-step-5>",
    "clientSecret": "<client-secret-from-step-5>",
    "redirectURI": "https://<your-management-domain>/oauth2/callback"
  }
}
```

7. Run the migration with `--idp-seed-info`:

```bash
./netbird-idp-migrate \
  --config /etc/netbird/management.json \
  --idp-seed-info "$(base64 < connector.json)"
```

### Explicit connector (skip auto-detection)

If auto-detection doesn't work or you want full control, provide the connector as base64-encoded JSON:

```bash
# Create the connector JSON
cat <<'EOF' > connector.json
{
  "type": "oidc",
  "name": "My Provider",
  "id": "my-provider",
  "config": {
    "issuer": "https://idp.example.com",
    "clientID": "my-client-id",
    "clientSecret": "my-client-secret",
    "redirectURI": "https://mgmt.example.com/oauth2/callback"
  }
}
EOF

# Base64-encode and pass to the tool
./netbird-idp-migrate \
  --config /etc/netbird/management.json \
  --idp-seed-info "$(base64 < connector.json)"
```

### Non-interactive (CI/scripts)

```bash
./netbird-idp-migrate \
  --config /etc/netbird/management.json \
  --force
```

## Troubleshooting

### "store does not support migration operations"

The store implementation doesn't have the required `ListUsers`/`UpdateUserID` methods. Make sure you're running v0.60.0+ binaries.

### "could not determine domain"

The tool couldn't infer your management server's domain. Set `HttpConfig.LetsEncryptDomain` in management.json before running, or run with `--skip-config` and configure the embedded IdP section manually.

### "could not open activity store"

This is a warning, not an error. If `events.db` doesn't exist (e.g., fresh install), activity event migration is skipped. User ID migration in the main database still proceeds.

### "no connector configuration found"

The tool couldn't find IdP configuration anywhere. Provide it explicitly with `--idp-seed-info`, set the `IDP_SEED_INFO` env var, or make sure `IdpManagerConfig` is present in management.json.

### "zitadel auto-detection is not supported"

Zitadel's management config uses service account credentials (e.g., `ClientID: "netbird-service-account"`) that aren't valid OAuth client credentials. See the [Zitadel setup](#zitadel) section above for step-by-step instructions.

### "no client secret found"

The Dex OIDC connector requires a confidential OAuth client with a client secret. If your `IdpManagerConfig.ClientConfig.ClientSecret` is empty, provide the connector credentials via `--idp-seed-info`.

### "Errors.App.NotFound" from Zitadel after migration

This usually means the connector's `clientID` is not a valid Zitadel OAuth application. The management server's `IdpManagerConfig.ClientConfig.ClientID` is typically a service account name (e.g., `netbird-service-account`), not an OAuth app ID. Create a Web application in Zitadel and re-run with `--idp-seed-info` — see the [Zitadel setup](#zitadel) section.

### OIDC discovery returns 404

The `/oauth2/` path is not being routed to the management server. See [step 7 (reverse proxy)](#7-update-your-reverse-proxy) — you need to add a route for `/oauth2/*` in your reverse proxy (Caddy, nginx, etc.).

### "jumpcloud does not have a supported Dex connector type"

JumpCloud isn't supported for auto-detection. You'll need to configure a generic OIDC connector manually using `--idp-seed-info`.

### Partial failure / re-running

The migration is idempotent. Already-migrated users are detected and skipped. If the tool fails partway through (e.g., database error), fix the issue and re-run — it will pick up where it left off.

## Rolling back

If something goes wrong after migration:

1. Stop the management server.
2. Restore your database backup (`store.db.bak` — or the volume-level copy for Docker, or `pg_dump` for PostgreSQL).
3. Restore `management.json.bak` (or your own backup).
4. Start the management server.
