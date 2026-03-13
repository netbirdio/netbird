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
| Zitadel | Yes | |
| Keycloak | Yes | |
| Okta | Yes | |
| Auth0 | Yes | Maps to generic OIDC connector |
| Azure AD | Yes | Maps to Entra connector |
| Google | Yes | |
| Authentik | Yes | |
| PocketID | Yes | |
| JumpCloud | No | No Dex connector available — manual setup required |

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

```bash
cp /var/lib/netbird/store.db /var/lib/netbird/store.db.bak
cp /etc/netbird/management.json /etc/netbird/management.json.bak
# If using PostgreSQL, use pg_dump instead
```

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

### 7. Start the management server

```bash
sudo systemctl start netbird-management
# or
docker compose up -d management
```

### 8. Verify

- Log into the dashboard — you should be redirected through your external IdP as before.
- Check that peers are visible and policies are intact.
- Check `https://<your-domain>/oauth2/.well-known/openid-configuration` returns valid OIDC discovery.

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

If your database lives somewhere other than what `Datadir` says in management.json:

```bash
./netbird-idp-migrate \
  --config /etc/netbird/management.json \
  --datadir /custom/path/to/data
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

### "jumpcloud does not have a supported Dex connector type"

JumpCloud isn't supported for auto-detection. You'll need to configure a generic OIDC connector manually using `--idp-seed-info`.

### Partial failure / re-running

The migration is idempotent. Already-migrated users are detected and skipped. If the tool fails partway through (e.g., database error), fix the issue and re-run — it will pick up where it left off.

## Rolling back

If something goes wrong after migration:

1. Stop the management server.
2. Restore your database backup (`store.db.bak`).
3. Restore `management.json.bak` (or your own backup).
4. Start the management server.
