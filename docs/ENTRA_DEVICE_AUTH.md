# Entra / Intune Device Authentication
**Status**: Server + client (PFX provider) are complete, unit-tested, and
live-tested against a real Entra tenant (see [Live-tenant verification
results](#live-tenant-verification-results)). The PFX path is the supported
production client mechanism; Windows cert-store / TPM-backed CNG signing is a
planned follow-up ([Future work](#future-work--windows-cert-store--tpm-backed-signing)).
Three must-close gaps are tracked before exposing the feature to real
tenants: see [Known production gaps](#known-production-gaps) and the
[Production readiness checklist](#production-readiness-checklist).

**TL;DR** — deploy a cert via an Intune PKCS Certificate profile, run
`netbird entra-enroll --management-url https://.../join/entra --entra-tenant
YOUR-TENANT --entra-pfx <path> --entra-pfx-password-env NB_ENTRA_PFX_PASSWORD`,
and the device joins NetBird automatically based on its Entra group
membership.

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

## Deploying device certificates via Intune (PKCS Certificate profile)

The client needs a device certificate whose Subject CN is the Entra device ID.
The supported production mechanism is an Intune PKCS Certificate profile.

1. **Intune admin center → Devices → Configuration → Create → New policy**.
2. Platform: **Windows 10 and later** (or macOS). Profile type: **Templates →
   PKCS certificate**.
3. **Certificate type:** Device.
4. **Subject name format:** `CN={{AAD_Device_ID}}` — this is what ties the
   cert to a Graph-lookupable device id.
5. **Subject alternative name:** leave empty (not consulted by NetBird).
6. **Certificate validity period:** 1 year is a reasonable default; shorter
   values reduce the revocation window.
7. **Key storage provider (KSP):** *Enroll to Trusted Platform Module (TPM) KSP
   if present, otherwise fall back to Software KSP* — this keeps the private
   key TPM-protected on modern hardware.
8. **Key usage:** Digital signature (required for the nonce-signing flow).
9. **Extended key usage:** Client authentication.
10. **Certification authority + CA name + Root CA certificate:** point at your
    internal PKI (AD CS or equivalent) that the NetBird management server
    will later trust via `CertValidator.TrustRoots`.
11. **Assignments:** target the device group(s) that should be onboarded.
12. On target devices, Intune will enrol the cert into the user's / machine's
    `My` certificate store. For the current PFX-based client path, export it
    to a `.pfx` via `Export-PfxCertificate` (or use an Intune *SCEP profile*
    + `Export-PfxCertificate` script) and drop it somewhere readable by the
    `netbird` service account.

A future client release will remove the PFX step by reading the cert directly
from `Cert:\LocalMachine\My` via CNG — see [Future work](#future-work--windows-cert-store--tpm-backed-signing).

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

```text
                      ┌───────────────────────────────────┐
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
- OData `$filter` literals (`deviceId`, `azureADDeviceId`) are escaped
  per OData v4 (`''`) so a pathological CN can't alter filter semantics.
- Graph failures are handled fail-closed (`group_lookup_unavailable`) so a
  transient 429 can never silently over-scope a device.
- Graph pagination is fail-closed on unexpected `@odata.nextLink` hosts so
  a misconfigured base URL can't silently truncate the group enumeration.
- Cert-vs-claimed-device-id mismatch is rejected *before* any Graph call, so
  spoofed device ids don't cost Graph quota.
- Certs with an empty Subject CN are rejected at both the validator layer
  and in `Manager.validateCertAndDeviceID` (belt-and-braces).
- `X-Forwarded-For` / `X-Real-IP` are only honoured when the enrol handler's
  `TrustForwardedHeaders` flag is set (opt-in trusted-proxy policy).
- Enrolment request bodies are hard-capped at 512 KiB; oversized bodies
  return a real `413 payload_too_large`.
- Bootstrap tokens are 32 random bytes (hex-encoded), valid for 5 minutes,
  single-use; `ConsumeBootstrapToken` validates before deleting so a
  guess-the-peerID caller cannot DoS an in-flight enrolment.
- All rejection paths are atomic: zero rows are written to `peers` /
  `group_peers` on any `4xx` / `5xx` outcome.
- **Known production gaps** (see below) must be closed before exposing the
  integration to a real tenant.

## Live-tenant verification results

Run on `2026-04-24` against a real Entra tenant (`5a7a81b2-…-76c26`) using the
Docker test harness + the synthetic `enroll-tester` tool. The following
scenarios were all executed end-to-end through Microsoft Graph:

| Scenario                                 | Configuration                         | Input                       | Expected result            | Actual |
|------------------------------------------|---------------------------------------|-----------------------------|----------------------------|--------|
| Happy path — wildcard mapping            | `mapping_resolution: strict_priority` | real device, compliance off | success, peer created      | ✅     |
| Happy path — specific Entra group mapping | mapping scoped to real Entra group id | same real device            | success, peer created      | ✅     |
| Device not in mapped Entra group         | mapping scoped to non-matching group  | real device                 | `403 no_mapping_matched`   | ✅     |
| Device absent from Entra                 | wildcard mapping                      | bogus device GUID           | `403 device_disabled`      | ✅     |
| Compliance on, compliant device          | `require_intune_compliant: true`      | compliant device id         | success, peer created      | ✅     |
| Compliance on, non-compliant device      | `require_intune_compliant: true`      | non-compliant device id     | `403 device_not_compliant` | ✅     |

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
The server side is considered production-quality at this point modulo the
"Known production gaps" below; the remaining work is all client-side
(Phase 2) and dashboard (Phase 4).

## Known production gaps

These are tracked for follow-up and should be addressed before exposing the
integration to a real tenant:

- **`ClientSecret` is stored plaintext** in `entra_device_auth.client_secret`.
  Rotate the column to the existing encrypted-column pattern before shipping
  so a DB dump / backup / replica does not leak Graph app-only credentials
  (`Device.Read.All`, `GroupMember.Read.All`,
  `DeviceManagementManagedDevices.Read.All`).
- **Bootstrap tokens are in-memory only.** `SQLStore` keeps them in a
  process-local map, so (a) a restart between enrol and first gRPC Login
  invalidates the pending bootstrap, and (b) multi-instance HA management
  deployments will reject the Login if it lands on a different node than the
  one that handled /enroll. Persist (hashed) into the main DB with an
  `expires_at` column + periodic GC before multi-node use.
- **`CertValidator.TrustRoots` is nil by default**, which makes chain
  verification a no-op. Production wiring must set
  `manager.Cert.TrustRoots` to the Entra device auth CA set. This is
  currently the operator's responsibility and is NOT enforced at
  construction time.

## Current implementation status

| Area                             | Status                                                             |
|----------------------------------|--------------------------------------------------------------------|
| Domain model + storage           | ✅ Done (gorm auto-migrate)                                        |
| Cert validator (RSA/ECDSA)       | ✅ Done                                                            |
| Graph client                     | ✅ Done (live-tested; see verification matrix above)                |
| Mapping resolution (both modes)  | ✅ Done with unit tests                                            |
| HTTP endpoints `/join/entra`     | ✅ Done with integration tests                                     |
| Admin CRUD                       | ✅ Done (wired but not yet OpenAPI-gen'd)                          |
| AccountManager integration       | ✅ Done (`EnrollEntraDevicePeer` + orphan-peer compensation)        |
| Activity codes / audit log       | ✅ Done                                                            |
| Permissions                      | ✅ `modules.EntraDeviceAuth` added; fail-closed on nil manager      |
| Client PFX provider + CLI         | ✅ Done (`netbird entra-enroll`; PFX → sign → enroll → persist state) |
| Proto `enrollmentBootstrapToken` | ❌ Not yet added (`Manager.ValidateBootstrapToken` ready)           |
| Windows cert store / TPM signing | ❌ Planned — see [Future work](#future-work--windows-cert-store--tpm-backed-signing) |
| Dashboard UI                     | ❌ Not started (tracked in `netbirdio/dashboard`)                   |
| Continuous revalidation          | ❌ Not started (reserved `revalidation_interval` field on the integration) |
| Encrypt `client_secret` at rest  | ❌ Follow-up — see [Known production gaps](#known-production-gaps)  |
| Persist bootstrap tokens in DB   | ❌ Follow-up — required for HA / multi-instance deployments         |
| `CertValidator.TrustRoots` plumb | ❌ Follow-up — currently operator-set; must be configured for prod  |

## Troubleshooting

Enrolment failures return a stable `code` and a human-readable `message`.
Common failure modes and how to diagnose them:

| Code                        | Most likely cause                                                  | Where to look                                                            |
|-----------------------------|--------------------------------------------------------------------|--------------------------------------------------------------------------|
| `integration_not_found`     | `tenant_id` mismatch — client sent a different tenant than was seeded | `GET /api/integrations/entra-device-auth`; compare with `--entra-tenant` |
| `integration_disabled`      | `EntraDeviceAuth.enabled` is false                                 | Admin API; flip `enabled` back to `true`                                 |
| `invalid_nonce`             | Clock skew, TTL expiry, or replay                                  | Check management server clock + TTL (60 s); pipe a fresh `/challenge`    |
| `invalid_cert_chain`        | Cert expired, malformed, or (with `TrustRoots` set) does not chain to the configured root | `openssl x509 -in leaf.pem -noout -text`; verify the trust-root bundle   |
| `invalid_signature`         | Private key mismatch with leaf cert, or wrong digest alg           | Confirm RSA-PSS / PKCS1v15 / ECDSA-DER signing; server rejects anything else |
| `device_disabled`           | Device absent from Entra or `accountEnabled=false`                 | Entra admin center → Devices; confirm GUID matches cert CN               |
| `device_not_compliant`      | Intune reports `complianceState != compliant`                      | Intune admin center → Devices; fix compliance or toggle `require_intune_compliant` off |
| `no_mapping_matched`        | Device isn't in any mapped Entra group and fallback is off         | `GET /api/integrations/entra-device-auth/mappings`; add a mapping or enable tenant-only fallback |
| `all_mappings_revoked`      | All matching mappings have `revoked=true`                          | Admin API; un-revoke one, or add a new mapping                           |
| `all_mappings_expired`      | All matching mappings have passed their `expires_at`               | Admin API; extend or add a mapping                                       |
| `group_lookup_unavailable`  | Graph `5xx` / throttling / token endpoint failure                  | Management server logs; Entra service health dashboard                   |
| `already_enrolled`          | Peer with this WG pubkey already exists                            | Delete the stale peer, or regenerate the WG keypair on the client        |

Client-side diagnostics:

- `netbird entra-enroll` accepts the same `--log-level debug` flag as the rest of the CLI; enable it for full wire-level tracing of the challenge + enroll HTTP round-trip.
- The enroll-tester in `tools/entra-test/enroll-tester/` is useful for isolating whether a failure is server-side or client-side — point it at the same management URL with the same PFX (minus the `.pfx` — the tester generates its own self-signed cert for the given device ID).

Server-side diagnostics:

- Every enrolment emits a `PeerAddedWithEntraDevice` activity event when it succeeds, and a standard log line on every rejection with the stable error code. Grep the management log for the code to find the exact request.
- Graph calls are logged at `Debug`; switch the management server to `--log-level debug` to see the OAuth token + device lookup + transitive-group enumeration per enrolment.

## Production readiness checklist

Before exposing `/join/entra` to real devices, confirm all of the following:

- [ ] Entra app registration created with admin-consented `Device.Read.All`, `GroupMember.Read.All`, and (if using compliance) `DeviceManagementManagedDevices.Read.All`.
- [ ] Client secret rotated and stored via an encrypted-at-rest mechanism (see [Known production gaps](#known-production-gaps)). **Plaintext storage is the current default and MUST NOT be used for a production tenant.**
- [ ] Intune PKCS Certificate profile deployed with `CN={{AAD_Device_ID}}` and a TPM-preferred KSP.
- [ ] `CertValidator.TrustRoots` populated with the issuing CA(s) of the Intune certificate profile. With `TrustRoots == nil` the chain-verification step is skipped — acceptable only for dev / test.
- [ ] `EntraDeviceAuth.mapping_resolution` explicitly set (don't rely on the default if you have overlapping group memberships).
- [ ] At least one `EntraDeviceAuthMapping` row created — or `allow_tenant_only_fallback=true` with a meaningful `fallback_auto_groups` list.
- [ ] `require_intune_compliant` decision made (on for zero-touch device-centric security, off for BYOD-ish deployments that only care about Entra group scope).
- [ ] Management server is behind a reverse proxy that terminates TLS; if the proxy sets `X-Forwarded-For`, enable `Handler.TrustForwardedHeaders` in the wiring.
- [ ] If running multi-instance management (HA / load-balanced): bootstrap-token persistence in DB is still pending (see Known production gaps). Until that follow-up lands, pin device enrolment traffic to a single management node or accept that a node restart between `/enroll` and the first gRPC `Login` invalidates the bootstrap.
- [ ] Activity-log sink (Postgres table + any downstream SIEM) verified to capture `PeerAddedWithEntraDevice` events.
- [ ] Monitoring / alerting on `management_log` for the 4xx/5xx enrolment error codes (especially `group_lookup_unavailable` which signals a Graph outage or throttling).

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
- **Package-level notes for server maintainers**: `management/server/integrations/entra_device/README.md`
- **In-process demo** (zero dependencies; spins up the real handler):
  ```bash path=null start=null
  go run ./tools/entra-test/enroll-tester --demo -v
  ```
