# ADR-001: mTLS Port Strategy

**Status:** Accepted
**Date:** 2026-01-19
**Issue:** #14 (T-1.2: NetBird gRPC mTLS Interception)

## Context

The Machine Tunnel Fork adds mTLS (mutual TLS) authentication for machine peers using AD CS certificates. We need to decide how to expose the mTLS-authenticated gRPC endpoints.

**Options considered:**

### Option A: Single Port with Method-Based Routing
- Standard gRPC port (33073) handles both token-auth and mTLS
- TLS config uses `VerifyClientCertIfGiven` (not `RequireAndVerifyClientCert`)
- gRPC interceptors check if method requires mTLS
- Methods in `mTLSRequiredMethods` map reject requests without valid cert
- Other methods fall back to token authentication

### Option B: Dual Port
- Standard port (33073) for token authentication
- Separate port (33074) for mTLS-only authentication
- Each port has its own TLS config
- Simpler routing but more network config

## Decision

**We chose Option A: Single Port with Method-Based Routing**

## Rationale

1. **Simpler Deployment:** Only one port to configure in firewalls and load balancers
2. **Graceful Fallback:** Machines without certificates can still use Setup-Key auth for bootstrap
3. **Existing Infrastructure:** Works with existing NetBird deployments without port changes
4. **TLS Flexibility:** `VerifyClientCertIfGiven` allows:
   - Clients WITH certs: Verified against CA pool, mTLS identity extracted
   - Clients WITHOUT certs: TLS handshake succeeds, fall back to token auth

## Implementation

### TLS Configuration (boot.go)
```go
config := &tls.Config{
    ClientAuth: tls.VerifyClientCertIfGiven,  // NOT RequireAndVerifyClientCert
    ClientCAs:  caCertPool,
    // ...
}
```

### Method-Based Requirements (mtls_auth.go)
```go
var mTLSRequiredMethods = map[string]bool{
    "/management.ManagementService/RegisterMachinePeer": true,
    "/management.ManagementService/SyncMachinePeer":     true,
    "/management.ManagementService/GetMachineRoutes":    true,
    "/management.ManagementService/ReportMachineStatus": true,
}
```

### Interceptor Logic
```
Request arrives
  |
  +-> Extract mTLS identity from TLS state
  |     |
  |     +-> Success: Identity available
  |     |     |
  |     |     +-> Store in context, proceed
  |     |
  |     +-> Failure: No cert or invalid
  |           |
  |           +-> Method requires mTLS?
  |           |     |
  |           |     +-> YES: Return Unauthenticated error
  |           |     +-> NO:  Fall back to token auth
```

## Consequences

### Positive
- Bootstrap flow works: Machine can use Setup-Key initially, then mTLS after cert enrollment
- No network reconfiguration needed for existing deployments
- Single source of truth for mTLS-required methods

### Negative
- Slightly more complex interceptor logic
- All methods receive TLS handshake overhead (minimal)

### Risks
- **Misconfiguration:** If `mTLSRequiredMethods` is not kept in sync with proto definitions
  - Mitigation: Code review, integration tests
- **CA Pool exhaustion:** Large multi-tenant deployments with many CAs
  - Mitigation: MTLSCADir supports multiple CA files, can scale

## Related Decisions

- ADR-002 (pending): Machine Identity Extraction Strategy (SAN DNSName vs CN)
- ADR-003 (pending): Multi-Tenant CA Isolation

## Implementation Status

### Completed
- [x] `management/internals/server/mtls_auth.go` - gRPC interceptors
- [x] `management/internals/server/config/config.go` - mTLS config fields
- [x] `management/internals/server/boot.go` - TLS config + interceptor chain
- [x] `shared/management/proto/management.proto` - Machine RPC definitions

### TODO: Proto Code Generation
The proto file has been updated but **Go code needs to be regenerated**:

```bash
cd shared/management/proto
./generate.sh
```

**Prerequisites:**
- `protoc` (Protocol Buffers compiler)
- `protoc-gen-go` (installed by generate.sh)
- `protoc-gen-go-grpc` (installed by generate.sh)

**New Messages added:**
- `MachineIdentity` - Certificate identity info
- `MachineRegisterRequest/Response` - Registration with mTLS
- `MachineSyncRequest/Response` - Sync stream for machine peers
- `MachineRoutesRequest/Response` - Route retrieval
- `MachineStatusRequest/Response` - Health reporting
- `MachineUpdateType` - Enum for sync update types

**New RPCs added:**
- `RegisterMachinePeer` - mTLS-required
- `SyncMachinePeer` - mTLS-required
- `GetMachineRoutes` - mTLS-required
- `ReportMachineStatus` - mTLS-required

## References

- [Go TLS ClientAuthType](https://pkg.go.dev/crypto/tls#ClientAuthType)
- [gRPC Interceptors](https://grpc.io/docs/guides/interceptors/)
- [NetBird gRPC Server](management/internals/server/boot.go)
