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

## Status (Phase 1)

- [x] Domain types
- [x] Resolution logic + unit tests
- [x] Nonce store
- [x] Cert validator skeleton
- [x] Graph client skeleton
- [x] Enrolment HTTP handlers skeleton
- [ ] Wired into the main router (blocked on admin API routes — phase 1.5)
- [ ] Full integration with `AccountManager.AddPeer`
- [ ] Proto field `enrollmentBootstrapToken` (requires `protoc` regen)
- [ ] Admin CRUD handlers
- [ ] OpenAPI schemas
