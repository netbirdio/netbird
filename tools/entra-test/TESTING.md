# Entra Device Authentication — Test Harness

This directory contains everything needed to exercise the server-side Entra
device-auth feature end-to-end without yet needing the real NetBird Windows
client. Use it to verify the feature works against your own Entra tenant.

## What's here

```
tools/entra-test/
├── docker-compose.yml        # Postgres + management server built from the branch
├── config/management.json    # Minimal management-server config for local dev
├── enroll-tester/            # Go program that impersonates a NetBird device
│   └── main.go
└── TESTING.md                # This file
```

## Prerequisites

- Docker 24+ with `docker compose`.
- Go 1.25+ (only to build the synthetic test client).
- `curl` or similar for admin-API calls (or use Postman).

## Step 1 — Start the stack

From the repo root:

```bash path=null start=null
docker compose -f tools/entra-test/docker-compose.yml up --build
```

This will:

1. Start Postgres and wait for it to be healthy.
2. Build `netbird-mgmt` from the feature branch source (multi-stage Dockerfile
   at `management/Dockerfile.entra-test`).
3. Start the management server with gRPC **and** HTTP (admin API +
   `/join/entra/*`) cmux-multiplexed on `localhost:33073`.

On first boot the management server runs `AutoMigrate` for the two new
tables:

- `entra_device_auth`
- `entra_device_auth_mappings`

Look for them in the Postgres container if you want to confirm:

```bash path=null start=null
docker compose -f tools/entra-test/docker-compose.yml exec postgres \
  psql -U netbird -d netbird -c "\dt entra_device_auth*"
```

## Step 2 — Register an Entra application (Azure portal)

The server needs app-only credentials to query Microsoft Graph. In your Entra
tenant:

1. **Entra ID → App registrations → New registration.**
2. Name it something like `NetBird Device Auth Test`.
3. Under **Certificates & secrets → Client secrets → New client secret**, copy
   the value (you'll use it below as `client_secret`).
4. Under **API permissions → Microsoft Graph → Application permissions**, add:
   - `Device.Read.All`
   - `GroupMember.Read.All`
   - (Optional) `DeviceManagementManagedDevices.Read.All` if you want the
     `require_intune_compliant` gate.
5. Click **Grant admin consent** for your tenant.
6. Note the **Application (client) ID** and **Directory (tenant) ID** on the
   overview page.

## Step 3 — Create the integration via the admin API

The admin API is on the authenticated `/api/` surface. For local dev you can
either:

- Use a real JWT from your existing NetBird admin setup, **or**
- Temporarily loosen auth in the management config (not recommended for real
  tenants).

Once you can hit the admin API, create the integration:

```bash path=null start=null
curl -sS -X POST http://localhost:33073/api/integrations/entra-device-auth \
  -H "Authorization: Bearer $NB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id":                "YOUR-TENANT-GUID",
    "client_id":                "YOUR-APP-CLIENT-ID",
    "client_secret":            "YOUR-CLIENT-SECRET",
    "enabled":                  true,
    "require_intune_compliant": false,
    "mapping_resolution":       "strict_priority"
  }' | jq
```

Then create at least one mapping. You need an Entra group object ID and one
or more NetBird auto-group IDs (look them up via the Entra portal and the
NetBird `/api/groups` endpoint respectively):

```bash path=null start=null
curl -sS -X POST http://localhost:33073/api/integrations/entra-device-auth/mappings \
  -H "Authorization: Bearer $NB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name":                     "Corporate laptops",
    "entra_group_id":           "ENTRA-GROUP-OBJECT-ID",
    "auto_groups":              ["nb-group-id-1", "nb-group-id-2"],
    "ephemeral":                false,
    "allow_extra_dns_labels":   true,
    "priority":                 10
  }' | jq
```

If you just want to test the plumbing without wiring up a real Entra tenant,
use the wildcard mapping:

```json path=null start=null
{
  "name":           "Any device",
  "entra_group_id": "*",
  "auto_groups":    ["nb-group-id-1"],
  "priority":       100
}
```

## Step 4 — Run the synthetic test client

Build it once:

```bash path=null start=null
go build -o tools/entra-test/enroll-tester ./tools/entra-test/enroll-tester
```

Run an enrolment:

```bash path=null start=null
./tools/entra-test/enroll-tester \
  --url       http://localhost:33073 \
  --tenant    YOUR-TENANT-GUID \
  --device-id 11111111-2222-3333-4444-555555555555 \
  -v
```

The tool will:

1. Generate a fresh self-signed RSA cert with `CN = YOUR-DEVICE-ID`.
2. Generate a random WireGuard-style pubkey.
3. GET `/join/entra/challenge` → receive a nonce.
4. Sign the nonce with the RSA key (RSA-PSS SHA-256).
5. POST `/join/entra/enroll` with the cert + signed nonce + WG pubkey.
6. Print the result, including the resolved auto-groups and the one-shot
   bootstrap token.

On success you'll see:

```text path=null start=null
====================  ENROLMENT SUCCESS  ====================
  Peer ID               : csomething...
  Resolution mode       : strict_priority
  Matched mapping IDs   : [cmappingid...]
  Resolved auto-groups  : [nb-group-id-1]
  Bootstrap token       : a1b2...
  WG pubkey             : <32 random bytes b64>
```

And in the Postgres DB, the peer row will now exist in `peers`, joined to
the `groups` table via `group_peers`.

## Step 5 — Expected error scenarios

Exercising rejection paths is just as important. Try these:

| Scenario                              | Expected code                |
|---------------------------------------|------------------------------|
| Unknown tenant id                     | 404 `integration_not_found`  |
| Integration disabled                  | 403 `integration_disabled`   |
| Nonce replayed / unknown              | 401 `invalid_nonce`          |
| Cert expired / malformed              | 401 `invalid_cert_chain`     |
| Wrong signature                       | 401 `invalid_signature`      |
| Device not in Entra / disabled        | 403 `device_disabled`        |
| Device not in any mapped Entra group  | 403 `no_mapping_matched`     |
| All matching mappings revoked         | 403 `all_mappings_revoked`   |
| Graph API transient failure           | 503 `group_lookup_unavailable` |
| Compliance required but not compliant | 403 `device_not_compliant`   |

## Step 6 — What this does NOT test

The real NetBird Windows client is not yet wired to the `/join/entra/*`
path. That's **Phase 2** of the plan and has not been implemented. Once
Phase 2 lands, an enrolled device would:

- Use its `MS-Organization-Access` Entra device cert from
  `Cert:\LocalMachine\My` (not a synthetic one),
- Sign the nonce with the TPM-protected private key via CNG,
- Echo the bootstrap token into its first gRPC `LoginRequest`,
- Thereafter sync normally.

Until then, use this test harness for server-side verification.

## Troubleshooting

- **`go build` fails with `unknown field File in struct literal`**: you're on
  an older commit. This branch contains the dex CGO-shim fix
  (`idp/dex/sqlite_{cgo,nocgo}.go`). Make sure you're building from the tip of
  `feature/entra-device-auth`.
- **`docker compose build` takes forever**: the first build downloads the
  entire module graph (~1.2 GB). Subsequent builds are cached.
- **`connection refused` on port 33073**: the management server may still be
  waiting on Postgres. `docker compose logs management` to inspect.
- **`integration_not_found` despite having created the integration**: check
  that the `tenant_id` in the `EntraDeviceAuth` row exactly matches what you
  passed as `--tenant` to the test client. Case-sensitive.
