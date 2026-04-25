# Entra / Intune device authentication

This package implements a third peer-registration method for NetBird alongside
setup keys and SSO.

A device proves its identity using the Entra-issued device certificate
(`MS-Organization-Access` issuer on Windows Entra-joined/hybrid-joined devices
or an Intune-provisioned cert on other platforms). The server validates the
certificate, confirms the device is enabled and compliant in Entra, looks up
its Entra group memberships via Microsoft Graph, then maps those Entra groups
to NetBird auto-groups based on admin-configured rules.

The feature lives behind the dedicated path `/join/entra` on the management URL
(e.g. `https://example.dk/join/entra`) so it never mixes with the normal gRPC
`Login`/`Sync` flow.

## Package layout

| File | Purpose |
|------|---------|
| `types.go`          | DTOs for the enrolment request/response + internal structs |
| `errors.go`         | Stable error codes returned to the client |
| `activity.go`       | Activity codes, registered lazily at process start |
| `nonce_store.go`    | Single-use challenge-nonce store with TTL |
| `cert_validator.go` | Entra device cert chain + proof-of-possession validation |
| `graph_client.go`   | Microsoft Graph calls (device, transitive groups, compliance) |
| `resolution.go`     | Mapping resolution (strict_priority / union) |
| `store.go`          | Storage interface for the integration's persistence |
| `manager.go`        | Glue: ties validator + graph + resolution + store together |

## Enrolment flow

1. `GET /join/entra/challenge` — server issues a single-use nonce.
2. Client finds its device cert, signs the nonce, collects its Entra device ID.
3. `POST /join/entra/enroll` — server:
   - validates cert chain + nonce signature,
   - calls Graph to confirm `accountEnabled` + (optionally) compliance,
   - enumerates transitive group membership,
   - resolves a mapping using `EntraDeviceAuth.MappingResolution`,
   - creates the NetBird peer with the resolved auto-groups,
   - returns a `LoginResponse` + a one-shot bootstrap token.
4. The client's next gRPC `Login` carries the bootstrap token to prove the
   enrolment was legitimate.

## Mapping resolution modes

- **`strict_priority`** (default) — only the lowest-`Priority` mapping applies.
  Ties broken by mapping `ID` ascending.
- **`union`** — every matched mapping's `AutoGroups` are merged by set-union;
  flags resolve most-restrictive (`Ephemeral` OR, `AllowExtraDNSLabels` AND,
  `ExpiresAt` min).

Revoked or expired mappings never participate. Distinct error codes signal
`no_mapping_matched`, `all_mappings_revoked`, `all_mappings_expired`,
`group_lookup_unavailable` so admins can diagnose.

## Status

See `docs/ENTRA_DEVICE_AUTH.md` ("Current implementation status") for the
canonical status table — this section previously drifted. At a glance,
server-side Phase 1 (types, resolution, nonce store, cert validator, Graph
client, enrolment endpoints, admin CRUD, AccountManager integration) is
shipped; proto `enrollmentBootstrapToken`, OpenAPI codegen, Phase 2 Windows
client cert-store provider, Phase 4 dashboard UI and Phase 5 continuous
revalidation remain follow-ups.

## Known production gaps (tracked for follow-up)

- **`ClientSecret` stored plaintext.** `types.EntraDeviceAuth.ClientSecret` is
  a plain gorm-mapped string. Rotating the column to the project's
  encrypted-column pattern is a follow-up; do not ship this integration to a
  tenant you cannot afford to have the app-only Graph credentials leak from.
- **Bootstrap tokens are in-memory.** `SQLStore.tokens` is process-local, so
  HA / multi-instance management deployments cannot use enrol-on-one-node /
  gRPC-login-on-another; and a process restart invalidates pending
  enrolments. Persisting tokens (hashed) into the existing DB is a follow-up.
- **`CertValidator.TrustRoots == nil` skips chain verification.** `NewManager`
  constructs a validator with no configured trust roots for the dev-harness
  path; production wiring MUST set `manager.Cert.TrustRoots` to the Entra
  device auth CAs before exposing `/join/entra`. This is currently not
  enforced at construction time — callers are on the honour system.
