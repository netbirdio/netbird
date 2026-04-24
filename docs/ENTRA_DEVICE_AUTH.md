# Entra / Intune Device Authentication

**Status**: server-side complete, client integration pending (Phase 2).

## Overview

NetBird's Entra device authentication lets an Entra-joined / Intune-enrolled
machine register itself as a NetBird peer without any user interaction. The
device proves its identity using the Entra-issued device certificate
(`MS-Organization-Access`) and signs a server-supplied nonce. NetBird validates
the certificate, confirms the device is enabled in Entra (and optionally
compliant in Intune), looks up its Entra group memberships via Microsoft Graph,
then maps those Entra groups to NetBird auto-groups based on admin-defined
rules.

This is a third peer-registration method alongside:

- **Setup keys** — shared pre-auth secrets with auto-groups, usage limits, etc.
- **SSO** — user signs in via an IdP and obtains a JWT.
- **Entra device auth** (this feature) — the device is the credential.

The feature lives on a dedicated path on the management URL:
`https://your-mgmt/join/entra`. This path is reserved and never mixes with the
normal `/api` admin API or the gRPC `Login`/`Sync` surface.

## When to use it

- Corporate-managed Windows fleet where every device is already Entra-joined
  or hybrid-joined.
- Zero-touch onboarding: provision a device via Intune, include a scheduled
  task that runs `netbird up --management-url https://<your-mgmt>/join/entra`,
  and the device joins NetBird automatically on first boot.
- Device-centric access policies: a device not in the right Entra group, or
  marked as non-compliant by Intune, cannot join — regardless of which user
  is logged in.

## Concepts

### Integration (one per account)

An `EntraDeviceAuth` row carries the Azure tenant id + app registration
credentials NetBird uses to call Graph. Fields:

| Field                         | Purpose                                                          |
|-------------------------------|------------------------------------------------------------------|
| `tenant_id`                   | Azure tenant GUID.                                               |
| `client_id`                   | App registration's application (client) ID.                      |
| `client_secret`               | App registration's client secret. Write-only — masked on GET.    |
| `enabled`                     | Master kill switch.                                              |
| `require_intune_compliant`    | When true, devices must be `complianceState == compliant`.       |
| `allow_tenant_only_fallback`  | When true, devices with no group-scoped mapping match use the fallback. |
| `fallback_auto_groups`        | Auto-groups applied when tenant-only fallback kicks in.          |
| `mapping_resolution`          | `strict_priority` (default) or `union`. See below.               |
| `revalidation_interval`       | Reserved for Phase 5 (continuous revalidation). Currently unused. |

### Mappings (many per account)

An `EntraDeviceAuthMapping` row says "devices in this Entra group should end
up in these NetBird groups":

| Field                    | Purpose                                                               |
|--------------------------|-----------------------------------------------------------------------|
| `name`                   | Human-readable label.                                                 |
| `entra_group_id`         | Entra group object ID. Use `*` for wildcard (any device in tenant).  |
| `auto_groups`            | NetBird group IDs to assign to the peer.                              |
| `ephemeral`              | Same semantics as `SetupKey.Ephemeral` — peer auto-cleans on inactivity. |
| `allow_extra_dns_labels` | Whether peer may register extra DNS labels beyond its default.        |
| `expires_at`             | Mapping stops matching after this time (nullable).                    |
| `revoked`                | Admin can revoke without deleting for audit purposes.                 |
| `priority`               | Lower number = higher priority in `strict_priority` mode.             |

### Mapping resolution

When a device is a member of multiple Entra groups that each have a mapping,
the `mapping_resolution` field on the integration decides what happens.

**`strict_priority`** (default) — only the single mapping with the lowest
`priority` is applied. Ties broken by mapping ID for determinism. Mirrors the
"one setup key, one configuration" mental model.

**`union`** — every matched mapping contributes:

- `auto_groups` → set-union across matches.
- `ephemeral` → logical OR (most restrictive: any mapping ephemeral → peer ephemeral).
- `allow_extra_dns_labels` → logical AND (most restrictive: any mapping denies → denied).
- `expires_at` → min of non-nil values (earliest expiry wins).

Revoked and expired mappings never participate in either mode.

**Wildcard mappings** — a mapping with `entra_group_id = "*"` (or empty)
matches any authenticated device from the configured tenant. Useful as a
baseline "all corporate devices" tier in `union` mode.

**Tenant-only fallback** — if every group-scoped mapping misses, and
`allow_tenant_only_fallback` is true, devices get `fallback_auto_groups`. Off
by default; opt in deliberately.

### Error codes

All enrolment failures come back with a stable machine-readable code so
automation can branch on them:

| Code                         | HTTP | Meaning                                                         |
|------------------------------|------|-----------------------------------------------------------------|
| `integration_not_found`      | 404  | No integration configured for the claimed `tenant_id`.          |
| `integration_disabled`       | 403  | Integration exists but is disabled.                             |
| `invalid_nonce`              | 401  | Nonce is unknown, expired, or already consumed.                 |
| `invalid_cert_chain`         | 401  | Cert chain missing, malformed, expired, or fails trust-root verification. |
| `invalid_signature`          | 401  | Signature over the nonce did not verify against the leaf public key. |
| `device_disabled`            | 403  | Device is absent or `accountEnabled == false` in Entra.         |
| `device_not_compliant`       | 403  | `require_intune_compliant` is on and Intune says non-compliant. |
| `no_device_cert_for_tenant`  | 403  | Client-side: no matching cert for the configured tenant. (Phase 2) |
| `no_mapping_matched`         | 403  | Device is in no mapped Entra group and fallback is off.         |
| `all_mappings_revoked`       | 403  | Every mapping that matched the device's groups is revoked.      |
| `all_mappings_expired`       | 403  | Same but for expired mappings.                                  |
| `group_lookup_unavailable`   | 503  | Graph transient error — fail closed to avoid over-scoping.      |
| `already_enrolled`           | 409  | Peer with this WG pubkey already exists.                        |

## Setting up an Entra app registration

1. Azure portal → Entra ID → **App registrations → New registration**.
2. Name it (e.g. `NetBird Device Auth`).
3. **Certificates & secrets → Client secrets → New client secret**. Copy the value (you only see it once).
4. **API permissions → Microsoft Graph → Application permissions**, add:
   - `Device.Read.All`
   - `GroupMember.Read.All`
   - `DeviceManagementManagedDevices.Read.All` *(only if you plan to use `require_intune_compliant`)*
5. **Grant admin consent** for the tenant.
6. Record the **Application (client) ID** and **Directory (tenant) ID**.

## REST API

All admin endpoints sit under the standard authenticated `/api/` surface —
the existing NetBird JWT middleware applies, plus the new
`modules.EntraDeviceAuth` permission module (admin role only).

### Create / update the integration

```http path=null start=null
POST /api/integrations/entra-device-auth
PUT  /api/integrations/entra-device-auth
Content-Type: application/json

{
  "tenant_id":                 "00000000-0000-0000-0000-000000000000",
  "client_id":                 "11111111-1111-1111-1111-111111111111",
  "client_secret":             "…",
  "enabled":                   true,
  "require_intune_compliant":  false,
  "allow_tenant_only_fallback": false,
  "fallback_auto_groups":      [],
  "mapping_resolution":        "strict_priority"
}
```

### Retrieve

```http path=null start=null
GET /api/integrations/entra-device-auth
```

`client_secret` is masked (`********`) in the response. Omit it from a PUT
payload to keep the existing value unchanged.

### Delete

```http path=null start=null
DELETE /api/integrations/entra-device-auth
```

Cascades to the mapping table.

### Mapping CRUD

```http path=null start=null
GET    /api/integrations/entra-device-auth/mappings
POST   /api/integrations/entra-device-auth/mappings
GET    /api/integrations/entra-device-auth/mappings/{id}
PUT    /api/integrations/entra-device-auth/mappings/{id}
DELETE /api/integrations/entra-device-auth/mappings/{id}
```

Request body:

```json path=null start=null
{
  "name":                   "Corporate laptops",
  "entra_group_id":         "11111111-…-……",
  "auto_groups":            ["nb-group-id-1", "nb-group-id-2"],
  "ephemeral":              false,
  "allow_extra_dns_labels": true,
  "expires_at":             null,
  "revoked":                false,
  "priority":               10
}
```

## Device enrolment protocol (`/join/entra`)

Unauthenticated at the HTTP layer — the device certificate is the credential.

### Challenge

```http path=null start=null
GET /join/entra/challenge
```

Response:

```json path=null start=null
{
  "nonce":      "<base64url 32-byte random>",
  "expires_at": "2026-04-24T04:32:06Z"
}
```

Nonces are single-use and live for 60 seconds.

### Enrol

```http path=null start=null
POST /join/entra/enroll
Content-Type: application/json

{
  "tenant_id":        "00000000-0000-0000-0000-000000000000",
  "entra_device_id":  "22222222-2222-2222-2222-222222222222",
  "cert_chain":       ["<b64-DER leaf>", "<b64-DER intermediate>"],
  "nonce":            "<from /challenge>",
  "nonce_signature":  "<b64 RSA-PSS or ECDSA sig over raw nonce bytes>",
  "wg_pub_key":       "<b64 32-byte WG pubkey>",
  "ssh_pub_key":      "<b64 SSH pubkey>",
  "hostname":         "laptop-1",
  "dns_labels":       [],
  "extra_dns_labels": []
}
```

Signature format:

- RSA keys: RSA-PSS with SHA-256, or PKCS1v15 with SHA-256. Both are accepted.
- ECDSA keys: ASN.1-encoded `{R, S}` over SHA-256 digest.

The nonce is signed as its **raw (decoded) bytes**, not as the base64 string.

Success response (200 OK):

```json path=null start=null
{
  "peer_id":                     "c…",
  "enrollment_bootstrap_token":  "<64 hex chars>",
  "resolved_auto_groups":        ["nb-group-id-1"],
  "matched_mapping_ids":         ["m…"],
  "resolution_mode":             "strict_priority",
  "netbird_config":              { "dns_domain": "…" },
  "peer_config":                 { "address": "…", "dns_label": "…" },
  "checks":                      null
}
```

The peer is already created in the database. The bootstrap token is a
one-shot credential the client will pass on its first gRPC `Login` to close
the race window between enrolment and first Sync.

## Architecture

```
                      ┌─────────────────────────────────────┐
                      │  Device (Entra-joined)              │
                      │                                     │
                      │  Entra device cert (TPM-protected)  │
                      └──────────────┬──────────────────────┘
                                     │ 1. GET /challenge
                                     │ 2. POST /enroll
                                     ▼
 ┌────────────────────────────────────────────────────────────────────┐
 │  netbird-management                                                │
 │                                                                    │
 │   http/handlers/entra_join   ──►   integrations/entra_device       │
 │   (unauth'd /join/entra)             Manager.Enroll                │
 │                                        │                           │
 │                                        ├─► CertValidator           │
 │                                        ├─► NonceStore              │
 │                                        ├─► GraphClient ◄─── Entra ─┼──► login.microsoftonline.com
 │                                        │                           │    graph.microsoft.com
 │                                        ├─► ResolveMapping          │
 │                                        └─► PeerEnroller ──►        │
 │                                             DefaultAccountManager  │
 │                                               .EnrollEntraDevicePeer
 │                                               (creates peer,       │
 │                                                assigns auto-groups)│
 └────────────────────────────────────────────────────────────────────┘
```

Relevant Go packages:

- `management/server/types/entra_device_auth.go` — domain model
- `management/server/integrations/entra_device/` — validator, nonce store, Graph client, resolver, manager
- `management/server/http/handlers/entra_join/` — device-facing routes
- `management/server/http/handlers/entra_device_auth/` — admin CRUD
- `management/server/entra_device_enroll.go` — `DefaultAccountManager.EnrollEntraDevicePeer`

## Security notes

- The management HTTP surface for `/join/entra/*` bypasses the normal JWT
  middleware — that's intentional; the device certificate *is* the
  authentication.
- Graph failures are handled fail-closed (`group_lookup_unavailable`) so a
  transient 429 can never silently over-scope a device.
- Cert-vs-claimed-device-id mismatch is rejected *before* any Graph call, so
  spoofed device ids don't cost Graph quota.
- Bootstrap tokens are 32 random bytes (hex-encoded), valid for 5 minutes,
  single-use.
- Client secrets are stored plain-text in the current schema; that column
  should be rotated to the existing encrypted-column pattern before
  production. See the "Open design decisions" in the plan document.

## Live-tenant verification results
Run on `2026-04-24` against a real Entra tenant (`5a7a81b2-…-76c26`) using the
Docker test harness + the synthetic `enroll-tester` tool. The following
scenarios were all executed end-to-end through Microsoft Graph:
| Scenario                                     | Configuration                               | Input                       | Expected result          | Actual   |
|----------------------------------------------|---------------------------------------------|-----------------------------|--------------------------|----------|
| Happy path — wildcard mapping                | `mapping_resolution: strict_priority`       | real device, compliance off | success, peer created    | ✅       |
| Happy path — specific Entra group mapping     | mapping scoped to real Entra group id       | same real device            | success, peer created    | ✅       |
| Device not in mapped Entra group             | mapping scoped to non-matching group        | real device                 | `403 no_mapping_matched` | ✅       |
| Device absent from Entra                     | wildcard mapping                            | bogus device GUID           | `403 device_disabled`    | ✅       |
| Compliance on, compliant device              | `require_intune_compliant: true`            | compliant device id         | success, peer created    | ✅       |
| Compliance on, non-compliant device          | `require_intune_compliant: true`            | non-compliant device id     | `403 device_not_compliant` | ✅     |
Observations from the runs:
- Every reject path is atomic — zero rows written to `peers` / `group_peers`
  on any 4xx/5xx outcome.
- Graph OAuth2 client-credentials round-trip, device lookup, transitive group
  enumeration, and Intune compliance query all worked with a standard app
  registration granted `Device.Read.All`, `GroupMember.Read.All`, and
  `DeviceManagementManagedDevices.Read.All`.
- Compliance is checked *before* mapping resolution, so a non-compliant device
  is rejected even if it is a member of a mapped Entra group.
- The happy-path response includes the resolved auto-groups, matched mapping
  IDs, and a 64-hex bootstrap token valid for 5 minutes.
The server side is considered production-quality at this point; the remaining
work is all client-side (Phase 2) and dashboard (Phase 4).
## Current implementation status

| Area                           | Status                                                   |
|--------------------------------|----------------------------------------------------------|
| Domain model + storage         | ✅ Done (gorm auto-migrate)                              |
| Cert validator (RSA/ECDSA)     | ✅ Done                                                  |
| Graph client                   | ✅ Done (not yet run against a live tenant)              |
| Mapping resolution (both modes)| ✅ Done with unit tests                                  |
| HTTP endpoints `/join/entra`   | ✅ Done with integration tests                           |
| Admin CRUD                     | ✅ Done (wired but not yet OpenAPI-gen'd)                |
| AccountManager integration     | ✅ Done (`EnrollEntraDevicePeer`)                        |
| Activity codes / audit log     | ✅ Done                                                  |
| Permissions                    | ✅ `modules.EntraDeviceAuth` added                       |
| Proto `enrollmentBootstrapToken` | ❌ Not yet added (`Manager.ValidateBootstrapToken` ready) |
| NetBird Windows client (Phase 2) | ❌ Not started                                         |
| Dashboard UI (Phase 4)         | ❌ Not started                                           |
| Continuous revalidation        | ❌ Not started (Phase 5)                                 |

## Future work — Windows cert store + TPM-backed signing
The PFX path is the supported production mechanism today. It works with
Intune's PKCS Certificate profile (which can deploy PFX files to both
Windows and macOS), and the server accepts any RSA/ECDSA cert the client
presents.
A future enhancement will add a Windows-native cert store provider that:
- reads the device certificate from `Cert:\LocalMachine\My` (or `CurrentUser\My`)
- filters by Issuer CN substring (e.g. `MS-Organization-Access`)
- signs the server nonce via CNG / `NCryptSignHash` without ever extracting
  the private key (TPM-protected)
This was scoped for this branch but not landed. The two viable implementation
routes are:
1. **CGO + `github.com/github/smimesign/certstore`** (widely deployed).
   Requires mingw-w64 in the Windows build chain — substantial build-
   infrastructure change.
2. **Pure-Go syscalls via `golang.org/x/sys/windows` + a hand-rolled
   `ncrypt.dll` wrapper.** Keeps `CGO_ENABLED=0`, ~300-400 lines of careful
   Win32 code, needs testing against a real TPM-backed cert.
The `CertProvider` interface in `client/internal/enroll/entradevice/provider.go`
is deliberately shaped so either implementation drops in as a second
provider next to `PFXProvider` without touching the enroller. The PFX
path remains the default / fallback so cross-platform deployments keep
working.
## Further reading
- **Local testing walkthrough**: `tools/entra-test/TESTING.md`
- **In-process demo**:
  ```bash path=null start=null
  go run ./tools/entra-test/enroll-tester --demo -v
  ```
- **Full design plan**: see the original design doc artifact (`create_plan`).
