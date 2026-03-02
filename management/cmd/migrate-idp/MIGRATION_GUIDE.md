# Migrating from an External IdP to NetBird's Embedded IdP

This guide walks you through migrating a self-hosted NetBird deployment from an external identity provider (Zitadel, Keycloak, Auth0, Okta, etc.) to NetBird's built-in embedded IdP (powered by DEX).

After this migration, NetBird manages authentication directly — no external IdP dependency required.

---

## Table of Contents

1. [What This Migration Does](#what-this-migration-does)
2. [Before You Start](#before-you-start)
3. [Step 1: Choose Your Connector ID](#step-1-choose-your-connector-id)
4. [Step 2: Stop the Management Server](#step-2-stop-the-management-server)
5. [Step 3: Run a Dry-Run](#step-3-run-a-dry-run)
6. [Step 4: Run the Migration](#step-4-run-the-migration)
7. [Step 5: Update management.json](#step-5-update-managementjson)
8. [Step 6: Start the Management Server](#step-6-start-the-management-server)
9. [Step 7: Verify Everything Works](#step-7-verify-everything-works)
10. [Rollback](#rollback)
11. [FAQ](#faq)

---

## What This Migration Does

NetBird's embedded IdP (DEX) uses a different format for user IDs than external providers do. When a user logs in through DEX, the user ID stored in the JWT `sub` claim looks like this:

```
CiQ3YWFkOGMwNS0zMjg3LTQ3M2YtYjQyYS0zNjU1MDRiZjI1ZTcSBG9pZGM
```

This is a base64-encoded blob that contains two pieces of information:

- The **original user ID** (e.g., `7aad8c05-3287-473f-b42a-365504bf25e7`)
- The **connector ID** (e.g., `oidc`)

The migration tool reads every user from your database, encodes their existing user ID into this DEX format, and updates all references across the database. After migration, when DEX issues tokens for your users, the `sub` claim will match what's in the database, and everything works seamlessly.

### What gets updated

The tool updates user ID references in **13 database columns** across two databases:

**Main database (store.db or PostgreSQL):**

| Table | Column | What it stores |
|-------|--------|----------------|
| `users` | `id` | The user's primary key |
| `personal_access_tokens` | `user_id` | Which user owns the token |
| `personal_access_tokens` | `created_by` | Who created the token |
| `peers` | `user_id` | Which user registered the peer |
| `user_invites` | `created_by` | Who sent the invitation |
| `accounts` | `created_by` | Who created the account |
| `proxy_access_tokens` | `created_by` | Who created the proxy token |
| `jobs` | `triggered_by` | Who triggered the job |
| `policy_rules` | `authorized_user` | SSH policy user authorization |
| `access_log_entries` | `user_id` | Reverse proxy access logs |

**Activity database (events.db or PostgreSQL):**

| Table | Column | What it stores |
|-------|--------|----------------|
| `events` | `initiator_id` | Who performed the action |
| `events` | `target_id` | Who was the target of the action |
| `deleted_users` | `id` | Archived deleted user records |

### What does NOT change

- Peer IDs, group IDs, network configurations, DNS settings, routes, and setup keys are **not affected**.
- Your WireGuard tunnels and peer connections continue working throughout.
- The migration only touches user identity references.

---

## Before You Start

### Requirements

- **Access to the management server machine** (SSH or direct).
- **The `migrate-idp` binary** — built from `management/cmd/migrate-idp/`.
- **Management server must be stopped** during migration. The tool works directly on the database files.
- **A backup strategy** — the tool creates automatic SQLite backups, but for PostgreSQL you should run `pg_dump` yourself.

### What you will need to know

Before starting, gather these pieces of information:

1. **Where your management.json lives** — typically `/etc/netbird/management.json`.
2. **Your connector ID** — see [Step 1](#step-1-choose-your-connector-id).
3. **Your public management URL** — the URL users and agents use to reach the management server (e.g., `https://netbird.example.com`).
4. **Your dashboard URL** — where the NetBird web dashboard is hosted (e.g., `https://app.netbird.example.com`).
5. **An admin email and password** — for the initial owner account in the embedded IdP.

### Build the migration tool

From the NetBird repository root:

```bash
cd management && go build -o migrate-idp ./cmd/migrate-idp/
```

This produces a `migrate-idp` binary. Copy it to your management server if building remotely.

---

## Step 1: Choose Your Connector ID

The connector ID is a short string that gets baked into every user's new ID. It tells DEX which authentication connector a user came from. You will use this same connector ID later when configuring the embedded IdP.

**For most migrations, use `oidc` as the connector ID.** This is the standard value for any OIDC-based external provider (Zitadel, Keycloak, Auth0, Okta, etc.).

Some specific cases:

| Previous IdP | Recommended connector ID |
|-------------|------------------------|
| Zitadel | `oidc` |
| Keycloak | `oidc` |
| Auth0 | `oidc` |
| Okta | `oidc` |
| Google Workspace | `google` |
| Microsoft Entra (Azure AD) | `microsoft` |
| Any generic OIDC provider | `oidc` |

The connector ID is arbitrary — it just needs to match between the migration and the DEX connector configuration you set up in Step 5. If you later add the old IdP as a DEX connector (to allow existing users to log in via their old provider through DEX), the connector's ID in the DEX config must match the value you use here.

---

## Step 2: Stop the Management Server

The migration modifies the database directly. The management server must not be running.

```bash
# systemd
sudo systemctl stop netbird-management

# Docker
docker compose stop management
# or
docker stop netbird-management
```

Verify it's stopped:

```bash
# systemd
sudo systemctl status netbird-management

# Docker
docker ps | grep management
```

---

## Step 3: Run a Dry-Run

A dry-run shows you exactly what the migration would do without writing any changes. Always do this first.

```bash
./migrate-idp \
  --config /etc/netbird/management.json \
  --connector-id oidc \
  --dry-run
```

You will see output like:

```
INFO loaded config from /etc/netbird/management.json (datadir: /var/lib/netbird, engine: sqlite)
INFO [DRY RUN] mode enabled — no changes will be written
INFO found 15 users to process
INFO [DRY RUN] would migrate user 7aad8c05-3287-... -> CiQ3YWFkOGMw... (account: abc123)
INFO [DRY RUN] would migrate user auth0|abc123... -> CgxhdXRoMHxh... (account: abc123)
...
INFO [DRY RUN] migration summary: 15 users would be migrated, 0 already migrated

Migration summary:
  Migrated: 15 users
  Skipped:  0 users (already migrated)

  [DRY RUN] No changes were written. Remove --dry-run to apply.
```

**Check the output carefully.** Every user should show their old ID transforming to a new base64-encoded ID. If anything looks wrong (unexpected user count, errors), stop and investigate before proceeding.

### Available flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--config` | Yes | `/etc/netbird/management.json` | Path to your management config file |
| `--connector-id` | Yes | — | The connector ID to encode into user IDs |
| `--dry-run` | No | `false` | Preview changes without writing |
| `--no-backup` | No | `false` | Skip automatic database backup |
| `--log-level` | No | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |

---

## Step 4: Run the Migration

Once you are satisfied with the dry-run output, run the actual migration:

```bash
./migrate-idp \
  --config /etc/netbird/management.json \
  --connector-id oidc
```

The tool will:

1. **Back up your databases** — for SQLite, it copies `store.db` and `events.db` to timestamped backups (e.g., `store.db.backup-20260302-140000`). For PostgreSQL, it prints a warning reminding you to use `pg_dump`.
2. **Migrate each user** — encodes their ID into DEX format and updates all 13 columns in a single database transaction per user.
3. **Print a summary** of how many users were migrated and how many were skipped.

Example output:

```
INFO loaded config from /etc/netbird/management.json (datadir: /var/lib/netbird, engine: sqlite)
INFO backed up /var/lib/netbird/store.db -> /var/lib/netbird/store.db.backup-20260302-140000
INFO backed up /var/lib/netbird/events.db -> /var/lib/netbird/events.db.backup-20260302-140000
INFO found 15 users to process
INFO migration complete: 15 users migrated, 0 already migrated

Migration summary:
  Migrated: 15 users
  Skipped:  0 users (already migrated)

  Next step: update management.json to enable EmbeddedIdP with connector ID "oidc"
```

### Idempotency

The migration is safe to run multiple times. If it's interrupted or you run it again, it detects already-migrated users (their IDs are already in DEX format) and skips them. A second run will report `0 users migrated, 15 already migrated`.

---

## Step 5: Update management.json

This is the manual configuration step. You need to add an `EmbeddedIdP` block to your `management.json` file so the management server starts with the built-in identity provider instead of your old external IdP.

### 5a: Gather the required information

You need these values:

| Value | Where to find it | Example |
|-------|------------------|---------|
| **Issuer URL** | Your public management server URL + `/oauth2`. This must be reachable by browsers and the NetBird client. | `https://netbird.example.com/oauth2` |
| **Local address** | The port the management server listens on locally. Check your current config's `HttpConfig` section. | `:443` or `:8080` or `:33073` |
| **Dashboard redirect URIs** | Your dashboard URL + `/nb-auth` and `/nb-silent-auth`. Check your current `HttpConfig.AuthAudience` or dashboard deployment for the base URL. | `https://app.netbird.example.com/nb-auth` |
| **CLI redirect URIs** | Standard localhost ports used by the NetBird CLI for OAuth callbacks. These are always the same. | `http://localhost:53000/` and `http://localhost:54000/` |
| **IdP storage path** | Where DEX should store its database. Use your existing data directory. | `/var/lib/netbird/idp.db` |
| **Owner email** | The email address of the initial admin user. This should be the email of the account owner who currently manages your NetBird deployment. | `admin@example.com` |
| **Owner password hash** | A bcrypt hash of the password for the initial admin. See section 5b below. | `$2a$10$N9qo8uLO...` |

**How to find your dashboard URL:** Look at the current `DeviceAuthorizationFlow` or `PKCEAuthorizationFlow` section in your `management.json`. The redirect URIs there point to your dashboard. You can also check what URL you use to access the NetBird web dashboard in your browser.

**How to find your local listen address:** Look at the current `HttpConfig` section in your `management.json` for the `ListenAddress` or check what port the management server binds to (default is `443` or `33073`).

### 5b: Generate a bcrypt password hash

The owner password must be stored as a bcrypt hash, not as plain text. Use any of these methods to generate one:

**Using htpasswd (most systems):**

```bash
htpasswd -nbBC 10 "" 'YourSecurePassword' | cut -d: -f2
```

**Using Python:**

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'YourSecurePassword', bcrypt.gensalt()).decode())"
```

If the `bcrypt` module is not installed: `pip3 install bcrypt`.

**Using Docker (no local dependencies):**

```bash
docker run --rm python:3-slim sh -c \
  "pip -q install bcrypt && python3 -c \"import bcrypt; print(bcrypt.hashpw(b'YourSecurePassword', bcrypt.gensalt()).decode())\""
```

The output will look like: `$2b$12$LJ3m4ys3Gl.2B1FlKNUyde8R7sCgSEO6k.gSCiBfQKOJDMBz.bXXi`

### 5c: Edit management.json

Open your `management.json` and make these changes:

**1. Add the `EmbeddedIdP` block.** Add it as a top-level key:

```json
{
  "Stuns": [...],
  "TURNConfig": {...},
  "Signal": {...},
  "Datadir": "/var/lib/netbird",
  "DataStoreEncryptionKey": "...",
  "HttpConfig": {...},

  "EmbeddedIdP": {
    "Enabled": true,
    "Issuer": "https://netbird.example.com/oauth2",
    "LocalAddress": ":443",
    "Storage": {
      "Type": "sqlite3",
      "Config": {
        "File": "/var/lib/netbird/idp.db"
      }
    },
    "DashboardRedirectURIs": [
      "https://app.netbird.example.com/nb-auth",
      "https://app.netbird.example.com/nb-silent-auth"
    ],
    "CLIRedirectURIs": [
      "http://localhost:53000/",
      "http://localhost:54000/"
    ],
    "Owner": {
      "Email": "admin@example.com",
      "Hash": "$2b$12$LJ3m4ys3Gl.2B1FlKNUyde8R7sCgSEO6k.gSCiBfQKOJDMBz.bXXi",
      "Username": "Admin"
    },
    "SignKeyRefreshEnabled": false,
    "LocalAuthDisabled": false
  },

  "StoreConfig": {...},
  ...
}
```

**2. Update `HttpConfig` to point at the embedded IdP:**

```json
"HttpConfig": {
  "AuthAudience": "netbird-dashboard",
  "AuthIssuer": "https://netbird.example.com/oauth2",
  "AuthUserIDClaim": "sub",
  "CLIAuthAudience": "netbird-cli",
  ...
}
```

- `AuthAudience` must be `"netbird-dashboard"` — this is the static client ID DEX uses for the dashboard.
- `CLIAuthAudience` must be `"netbird-cli"` — the static client ID DEX uses for the CLI.
- `AuthIssuer` must match the `Issuer` in your `EmbeddedIdP` block.

**3. Remove or leave the old `IdpManagerConfig` block.** When `EmbeddedIdP` is configured, the management server uses it instead of any external IdP config. You can either delete the old `IdpManagerConfig` block or leave it — it will be ignored.

### 5d: Explanation of each field

| Field | Required | Description |
|-------|----------|-------------|
| `Enabled` | Yes | Must be `true` to activate the embedded IdP. |
| `Issuer` | Yes | The public URL where DEX serves OIDC endpoints. Must be your management server's public URL with `/oauth2` appended. Browsers and clients will call this URL to authenticate. Must be HTTPS in production. |
| `LocalAddress` | Yes | The local listen address of the management server (e.g., `:443`). Used internally for JWT validation to avoid external network calls during token verification. |
| `Storage.Type` | Yes | `"sqlite3"` or `"postgres"`. This is the storage DEX uses for its own data (connectors, tokens, keys). Separate from NetBird's main store. |
| `Storage.Config.File` | For sqlite3 | Path where DEX creates its SQLite database. Use your data directory (e.g., `/var/lib/netbird/idp.db`). |
| `Storage.Config.DSN` | For postgres | PostgreSQL connection string for DEX storage (e.g., `host=localhost dbname=netbird_idp sslmode=disable`). |
| `DashboardRedirectURIs` | Yes | OAuth2 redirect URIs for the web dashboard. Must include `/nb-auth` and `/nb-silent-auth` paths on your dashboard URL. |
| `CLIRedirectURIs` | Yes | OAuth2 redirect URIs for the NetBird CLI. Always use `http://localhost:53000/` and `http://localhost:54000/`. |
| `Owner.Email` | Recommended | Email for the initial admin user. This user can log in immediately with email/password. |
| `Owner.Hash` | Recommended | Bcrypt hash of the admin password. See [5b](#5b-generate-a-bcrypt-password-hash). |
| `Owner.Username` | No | Display name for the admin user. Defaults to the email if not set. |
| `SignKeyRefreshEnabled` | No | Enables automatic rotation of JWT signing keys. Default `false`. |
| `LocalAuthDisabled` | No | Set to `true` to disable email/password login entirely (only allow login via external connectors configured in DEX). Default `false`. |

### 5e: If using PostgreSQL for DEX storage

If your main NetBird store uses PostgreSQL, you may want DEX to use PostgreSQL too. Create a separate database for DEX:

```sql
CREATE DATABASE netbird_idp;
```

Then configure:

```json
"Storage": {
  "Type": "postgres",
  "Config": {
    "DSN": "host=localhost port=5432 user=netbird password=secret dbname=netbird_idp sslmode=disable"
  }
}
```

---

## Step 6: Start the Management Server

```bash
# systemd
sudo systemctl start netbird-management

# Docker
docker compose start management
# or
docker start netbird-management
```

Check the logs for successful startup:

```bash
# systemd
sudo journalctl -u netbird-management -f

# Docker
docker logs -f netbird-management
```

Look for:

- `"embedded IdP started"` or similar DEX initialization messages.
- No errors about missing users, foreign key violations, or IdP configuration.
- The management server accepting connections on its listen port.

---

## Step 7: Verify Everything Works

### Test the dashboard

1. Open your NetBird dashboard in a browser.
2. You should see a DEX login page (NetBird-branded) instead of your old IdP's login page.
3. Log in with the **owner email and password** you configured in Step 5.
4. Verify you can see your account, peers, and policies.

### Test the CLI

```bash
netbird login --management-url https://netbird.example.com
```

This should open a browser for DEX authentication. Log in with the owner credentials.

### Test peer connectivity

Existing peers should continue to work. Their WireGuard tunnels are not affected by the IdP change. New peers can be registered by users who authenticate through the embedded IdP.

---

## Rollback

If something goes wrong, you can restore the database backups and revert `management.json`.

### SQLite

```bash
# Stop management
sudo systemctl stop netbird-management

# Restore backups (find the timestamp from migration output)
cp /var/lib/netbird/store.db.backup-20260302-140000 /var/lib/netbird/store.db
cp /var/lib/netbird/events.db.backup-20260302-140000 /var/lib/netbird/events.db

# Revert management.json (remove EmbeddedIdP block, restore old IdpManagerConfig)
# Then start management
sudo systemctl start netbird-management
```

### PostgreSQL

Restore from the `pg_dump` you took before migration:

```bash
# Stop management
sudo systemctl stop netbird-management

# Restore
pg_restore -d netbird /path/to/backup.dump
# or
psql netbird < /path/to/backup.sql

# Revert management.json and start
sudo systemctl start netbird-management
```

---

## FAQ

### Can I run the migration multiple times?

Yes. The migration is idempotent. It detects users whose IDs are already in DEX format and skips them. Running it twice will report `0 users migrated, N already migrated`.

### What happens if the migration is interrupted?

Each user is migrated in its own database transaction. If the process is killed mid-migration, some users will have new IDs and some will still have old IDs. Simply run the migration again — it will pick up where it left off and skip already-migrated users.

### Does this affect my WireGuard tunnels?

No. WireGuard tunnels are identified by peer keys, not user IDs. All existing tunnels continue working during and after migration. No client-side changes are needed.

### What about service users?

Service users (`IsServiceUser=true`) are migrated like all other users. Their IDs are re-encoded with the connector ID. This ensures consistency — all user IDs in the database follow the same format after migration.

### Can I keep my old IdP as a connector in DEX?

Yes. After migration, you can add your old IdP as an OIDC connector in DEX. This lets existing users log in via their old provider, but through DEX. The connector ID in DEX must match the `--connector-id` you used during migration (e.g., `oidc`).

To add a connector, create a connector via the DEX API or configure it as a static connector in the DEX config. The connector must have:
- `ID`: the same value you used for `--connector-id` (e.g., `oidc`)
- `Type`: `oidc` (or the specific provider type)
- `Issuer`, `ClientID`, `ClientSecret`: your old IdP's OAuth2 credentials

### What if I used the wrong connector ID?

Restore from backup and run the migration again with the correct connector ID. Already-migrated users cannot be re-migrated to a different connector ID without restoring the original data first.

### Does this work with the combined management container?

No. The combined container (`combined/cmd/`) only supports setups that already have the embedded IdP enabled. This migration tool is for standalone management server deployments (`management/cmd/`) that are switching from an external IdP.

### What database engines are supported?

SQLite, PostgreSQL, and MySQL are all supported. The tool reads the database engine from your `management.json` `StoreConfig` and connects accordingly. For SQLite, automatic backups are created. For PostgreSQL and MySQL, you must create your own backups before running the migration.
