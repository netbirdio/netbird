# Device Security — Technical Reference

**Branch:** `feature/tpm-cert-auth`  
**Last updated:** 2026-04-14

---

## Overview

Device Security adds PKI-based device certificate authentication to NetBird. Before a client can connect, it must hold a valid device certificate issued by the account's Certificate Authority. Certificates are issued through one of three enrollment flows and verified on every mTLS handshake against the account's CA pool.

---

## Architectural approach: gRPC channel, not WireGuard tunnels

Device certificates authenticate the **management plane** — the gRPC connection between the NetBird client and the Management server — not the WireGuard data plane tunnels between peers.

```
┌──────────────────────────────────────────────────────────────────────┐
│  NetBird client                                                      │
│                                                                      │
│  ┌─────────────────┐   mTLS (device cert)   ┌────────────────────┐   │
│  │  Enrollment /   │ ─────────────────────> │  Management gRPC   │   │
│  │  gRPC client    │ <───────────────────── │  Server            │   │
│  └─────────────────┘   TLS 1.3 + X.509      └────────────────────┘   │
│                                                                      │
│  ┌─────────────────┐   WireGuard (unchanged)  ┌───────────────────┐  │
│  │  WireGuard      │ ═══════════════════════> │  Peer / Relay     │  │
│  │  interface      │ <═══════════════════════ │                   │  │
│  └─────────────────┘   Noise_IKpsk2, no PKI   └───────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

**WireGuard is not touched.** WireGuard already provides strong cryptographic identity through its own key pair (Curve25519); adding a separate PKI layer on top of the WireGuard tunnel would be redundant. Instead, the device certificate extends the _management_ trust model:

| Layer            | Protocol                 | Authentication                  | What it proves                                                                |
| ---------------- | ------------------------ | ------------------------------- | ----------------------------------------------------------------------------- |
| Data plane       | WireGuard (Noise_IKpsk2) | Curve25519 key pair             | Peer identity within the overlay network                                      |
| Management plane | gRPC over TLS 1.3        | X.509 device certificate (mTLS) | That the connecting _device_ was explicitly enrolled and has not been revoked |

**Why this boundary makes sense:**

1. **Enrollment gate.** The Management server is the single point through which a client receives its WireGuard configuration, allowed peers, and ACL rules. Gating that channel with a device certificate means an un-enrolled or revoked device can never obtain routing information — it is blocked before it can participate in the overlay at all.

2. **No WireGuard protocol changes.** WireGuard has a deliberately minimal and stable protocol. Keeping PKI enforcement at the gRPC layer avoids any modification to the WireGuard handshake, stays compatible with all WireGuard implementations, and preserves the performance characteristics of the data plane.

3. **Revocation is meaningful.** Revoking a device certificate immediately prevents future Login and Sync RPCs from succeeding. The peer loses network map updates and is eventually disconnected from the overlay without the Management server needing to push an explicit "kick" to every other peer.

4. **Certificate CN binds to WireGuard identity.** The device certificate's Common Name is set to the peer's WireGuard public key. This ties the PKI identity to the WireGuard identity: even if a certificate were somehow stolen, it would only be usable by a client that also controls the corresponding WireGuard private key.

---

## Enrollment modes

Three enrollment paths exist. The client selects the path automatically based on available hardware security:

| Path                  | Hardware required    | Server flow                                             | Admin action required |
| --------------------- | -------------------- | ------------------------------------------------------- | --------------------- |
| **Mode A** — Manual   | None                 | CSR queued as pending; admin/cert_approver approves     | Yes                   |
| **Mode C / TPM**      | TPM 2.0 chip         | Two-round credential activation; cert issued on success | No                    |
| **Mode C / Apple SE** | Apple Secure Enclave | Single-round attestation; cert issued on success        | No                    |

---

## Mode A — Manual enrollment

```
Client                           Management gRPC                  Admin / cert_approver
──────                           ──────────────────────           ────────────────────
1. Register peer (setup key)
2. GenerateKey(TPM or software)
3. BuildCSR(wgPubKey)  →  CommonName = WireGuard public key
4. EnrollDevice(csr_pem, system_info) ─────────────────────────────────────────────────────>
                                     5. Validate CSR
                                     6. GetAccountIDForPeerKey(wgKey)
                                     7. Idempotency: GetEnrollmentRequestByWGKey
                                        → if Active, return existing enrollment_id
                                     8. AUTO-RENEWAL CHECK:
                                        GetDeviceCertificateByWGKey
                                        if valid cert exists AND not-revoked
                                        → SignCSR immediately → return cert (no admin)
                                     9. INVENTORY GATE (if RequireInventoryCheck=true):
                                        parse SystemSerialNumber from system_info
                                        check serial against MDM inventory
                                        if not found → PermissionDenied, no queue entry
                                     10. Save EnrollmentRequest{status:"pending"}
                                     ← return {enrollment_id, status:"pending"}

5. Poll GetEnrollmentStatus(enrollment_id)
   loop with backoff (5s → 5m)                                    POST /device-auth/enrollments/{id}/approve
                                                                  → SignCSR → SaveDeviceCertificate
                                                                  → EnrollmentRequest{status:"approved"}
                                     ← return {status:"approved", device_cert_pem:"..."}
6. StoreCert; reconnect with mTLS
```

**Key implementation details:**

- `EnrollDevice` gRPC method in `management/internals/shared/grpc/device_enrollment.go`
- CSR CommonName **must** equal the peer's WireGuard public key
- Idempotent: re-submitting the same WG key returns the existing enrollment ID
- Auto-renewal bypasses the approval queue — see [Auto-renewal](#auto-renewal)
- Polling interval: exponential backoff starting at `5s`, capped at `5m`

---

## Mode C / TPM — Credential activation

Two-round protocol. The server proves the client has a specific TPM chip by encrypting a secret that only that TPM can decrypt.

```
Client (TPM 2.0)                 Management gRPC
─────────────────                ──────────────────────────────────────────────────
1. Register peer (setup key)
2. TPM GenerateKey → EK key pair (hardware-bound, non-exportable)
3. AttestationProof() → EKCert, AKPub
4. BuildCSR(wgPubKey)

5. BeginTPMAttestation(ek_cert_pem, ak_pub_pem, csr_pem) ──────────────────────────>
                                 6. Parse and validate EK certificate PEM
                                 7. VerifyEKCertChain(ekCert):
                                    check against bundled TPM manufacturer CAs
                                    if no CAs bundled: skip (dev mode, warning logged)
                                 8. Parse AK public key; reject if not ECDSA P-256
                                 9. GetAccountIDForPeerKey(wgKey) — fail-fast before crypto
                                 10. Generate 32-byte random secret
                                 11. makeCredentialBlob(ekPub, akPub, secret):
                                     format: uint16BE(len(idObject)) | idObject |
                                             uint16BE(len(encSecret)) | encSecret
                                 12. generateSessionID() → 32 random bytes → 64 hex chars
                                 13. Store AttestationSession{
                                         ExpectedSecret, CSRPEM, WGKey, AccountID,
                                         ExpiresAt: now + 5min
                                     }
                                 ← return {session_id, credential_blob}

6. tpmProvider.ActivateCredential(blob):
   → TPM2_ActivateCredential decrypts blob using EK private key
   → returns 32-byte plaintext secret

7. CompleteTPMAttestation(session_id, activated_secret) ────────────────────────────>
                                 8. isValidSessionID(session_id) — must be 64 lowercase hex chars
                                 9. GetAndDelete(session_id) — atomic; prevents TOCTOU replay
                                 10. subtle.ConstantTimeCompare(expected, provided)
                                     if mismatch: session already deleted, return PermissionDenied
                                 11. issueDeviceCert(accountID, wgKey, csr_pem)
                                     → SignCSR → SaveDeviceCertificate → SaveEnrollmentRequest
                                 ← return {enrollment_id, status:"approved", device_cert_pem}

8. StoreCert; reconnect with mTLS
```

**Key implementation details:**

- `BeginTPMAttestation` / `CompleteTPMAttestation` in `management/internals/shared/grpc/attestation_handler.go`
- Session TTL: **5 minutes** (`attestationSessionTTL`)
- Session store capacity: **10,000** concurrent sessions (`maxAttestationSessions`)
- Session ID logged only as 8-char prefix; never echoed back to callers in errors
- `GetAndDelete` is atomic under a single write lock — prevents two concurrent `CompleteTPMAttestation` calls from both issuing a certificate for the same session
- AK must be ECDSA P-256 (RSA AK rejected)
- All PEM inputs capped at **16 KiB** (`maxPEMInputSize`)
- **Current limitation:** TPM manufacturer CA bundle not included in open-source build. Run `go run scripts/fetch-tpm-roots.go` before production deployment. Without CAs, EK chain verification is skipped with a WARNING log (see [Known limitations](#known-limitations))

---

## Mode C / Apple SE — Secure Enclave attestation

Single-round protocol. The client provides an Apple-signed attestation certificate chain proving the key was generated in the Secure Enclave.

```
Client (Apple Secure Enclave)    Management gRPC
─────────────────────────────    ──────────────────────────────────────────────────
1. Register peer (setup key)
2. SE GenerateKey → key pair (Secure Enclave-bound, non-exportable)
3. CreateSEAttestation() → leaf cert (signed by Apple intermediate CA)
4. BuildCSR(wgPubKey) using SE key

5. AttestAppleSE(csr_pem, attestation_pems, system_info) ──────────────────────────>
                                 6. Validate attestation_pems is non-empty (≤ 10 certs)
                                 7. ParseCSR; verify CommonName (wgKey) is non-empty
                                 8. GetAccountIDForPeerKey(wgKey) — fail-fast before chain crypto
                                 9. parseAttestationChain(attestation_pems):
                                    chain[0] = leaf, chain[1:] = client-provided intermediates
                                 10. BuildAppleSERootPool(config):
                                     load Apple Root CA G3 from config.CACertFile
                                 11. LoadIntermediateCerts(config):
                                     load Apple Secure Key Attestation CA from
                                     config.IntermediateCACertFile (if configured)
                                 12. verifyAppleAttestationChain(chain, roots, intermediates):
                                     Intermediates = chain[1:] + configured intermediates
                                     chain[0].Verify(opts) — fail-closed if intermediate missing
                                 13. matchCSRAndLeafKey(csr, chain[0]):
                                     compare PKIX DER public keys — prevents key substitution
                                 14. issueDeviceCert(accountID, wgKey, csr_pem)
                                 ← return {enrollment_id, status:"approved", device_cert_pem}

5. StoreCert; reconnect with mTLS
```

**Key implementation details:**

- `AttestAppleSE` in `management/internals/shared/grpc/attestation_handler.go`
- Apple's `SecKeyCreateAttestation` returns only the leaf cert. Client **must** either:
  - Include the intermediate CA in `attestation_pems[1]`, **or**
  - Operator configures `appleSEConfig.IntermediateCACertFile` (Apple Secure Key Attestation CA)
- CSR public key must cryptographically match the leaf attestation cert public key
- Chain verification **fails closed** — missing intermediate is never silently skipped

---

## Shared cert issuance (`issueDeviceCert`)

Called at the end of both Mode C paths after attestation passes:

```
issueDeviceCert(ctx, accountID, wgKey, csrPEM, systemInfo)
  1. if accountID == "": GetAccountIDForPeerKey(ctx, wgKey)
  2. GetAccountSettings(ctx, accountID) → DeviceAuthSettings + CertValidityDays
  3. NewCA(ctx, settings, accountID, store, managementURL)
     → for "builtin" type: newBuiltinCA — loads from TrustedCA store or generates fresh
     → loadRevokedFromStore — restores in-memory revocation list from DeviceCertificate records
  4. parseCSRPEM(csrPEM)
  5. ca.SignCSR(ctx, csr, wgKey, validityDays) → *x509.Certificate
     Certificate fields:
       CN = wgKey (WireGuard public key)
       NotBefore = now - 1 minute
       NotAfter = now + validityDays (default: 365 days)
       KeyUsage = DigitalSignature
       ExtKeyUsage = ClientAuth
       DNSNames = ["netbird-device-<SHA256(wgKey)[:8]hex>.internal"]
       CRLDistributionPoints = [managementURL/api/device-auth/crl/<crl-token>]  # if configured
       SerialNumber = 128-bit random big.Int
  6. GetPeerByPeerPubKey(ctx, wgKey) → peerID (may be empty for unregistered peers)
  7. SaveDeviceCertificate(ctx, DeviceCertificate{
       AccountID, PeerID, WGPublicKey: wgKey,
       Serial: cert.SerialNumber.String(),  // decimal string
       PEM: certPEM, NotBefore, NotAfter,
       Revoked: false
     })
  8. SaveEnrollmentRequest(ctx, EnrollmentRequest{
       AccountID, WGPublicKey: wgKey,
       Status: "approved",
       CSRPEM: csrPEM,
     })
  9. return AttestationResult{
       EnrollmentId: enrollmentRequest.ID,
       Status: "approved",
       DeviceCertPem: certPEM,
     }
```

---

## Authentication flow (after enrollment)

```
Client (mTLS)            Management gRPC Server
─────────────            ─────────────────────────────────────────────────────────
TLS ClientHello (cert)
                         VerifyPeerCert callback (tls.Config):
                           parse leaf cert from rawCerts[0]
                           leaf.Verify(VerifyOptions{Roots: accountCertPool})
                           if fail → TLS handshake rejected

                         Login / Sync RPC:
                           extract peer WG key from encrypted message
                           if clientCertPresent:
                             CheckDeviceAuth(mode, clientCert):
                               mode=disabled  → pass
                               mode=optional  → pass (cert verified if present)
                               mode=cert-only → cert required; pass
                               mode=cert+sso  → cert + valid SSO token required
                             checkCertRevocation(store, accountID, wgKey, cert):
                               see Revocation section below
Login/Sync proceeds normally
```

**CA pool loading:**

- `buildInitialCertPool()` runs at server startup (boot.go)
- Loads all `TrustedCA` records for all accounts via store
- Pool is updated in memory when CAs are added/removed via REST API
- `deviceauth.Handler` holds pool behind `sync.RWMutex`

**Known limitation:** Revocation is checked at **Login time only**. A peer with an active Sync stream is not disconnected when its cert is revoked — it remains connected until it reconnects and logs in again. Enforcing revocation on active streams requires injecting a disconnect signal into the peer's Sync context; tracked as a follow-up improvement.

---

## Revocation (`checkCertRevocation`)

`management/internals/shared/grpc/device_cert_revocation.go`

```
checkCertRevocation(ctx, store, accountID, wgKey, clientCert):

1. if clientCert == nil → pass (no cert presented)

2. GetDeviceCertificateByWGKey(ctx, accountID, wgKey):

   a. NotFound in store (external CA scenario):
      → verifyCertIssuedByAccountCA(ctx, store, accountID, clientCert):
           ListTrustedCAs(ctx, accountID) → build account CA pool
           clientCert.Verify(pool)
           if verified → pass
           if not verified → PermissionDenied "not issued by CA trusted in this account"
           if ListTrustedCAs fails → PermissionDenied (fail-closed)
           if no CAs in account → PermissionDenied

   b. DB error (non-NotFound) → PermissionDenied (fail-closed)

   c. Record found:
      serial mismatch (presentedSerial != dbRecord.Serial):
        → PermissionDenied "certificate serial mismatch"
        Rationale: peer must always present its current enrolled cert.
        Mismatch = old cert or cert from outside normal enrollment flow.
        Safe outcome: require re-enrollment.

      serial matches AND dbRecord.Revoked == true:
        → PermissionDenied "device certificate has been revoked"

      serial matches AND dbRecord.Revoked == false:
        → pass
```

**Security properties:**

- Fail-closed on any DB error
- External CA certs verified against account-scoped pool (prevents cross-account spoofing, H-5)
- Serial mismatch always denied even if cert is CA-signed (fail-safe)

---

## Auto-renewal

### Client-side renewal loop

`client/internal/enrollment/manager.go` — `StartRenewalLoop`

```
StartRenewalLoop(ctx, onRenewal func(*x509.Certificate)):
  Starts background goroutine with 6-hour wake interval.

  Each iteration:
    1. EnsureCertificate(ctx):
         if stored cert is valid (see certIsValid): return existing cert
         else: run full enrollment flow (Mode A/TPM/Apple SE)
    2. if cert.SerialNumber changed since last check:
         if not first iteration: call onRenewal(newCert)
         update lastSerial
    3. if first iteration: seed lastSerial, do NOT call onRenewal
       (prevents spurious reconnect on every client start)

certIsValid(cert):
  cert != nil
  AND now > cert.NotBefore
  AND now < cert.NotAfter
  AND cert.NotAfter - now > 7 days  ← renewal threshold
```

**In connect.go:** `onRenewal` calls `cancel()` on the engine context, triggering a full reconnect with the new certificate.

**Renewal is only started** when:

- `tpmProv.Available()` is true (not on iOS/Android/WASM/stub platforms)
- mTLS upgrade succeeded (cert was actually loaded and used)

### Server-side auto-renewal (Mode A)

When a client submits `EnrollDevice` and already has a valid, non-revoked cert:

1. `tryAutoRenew` fires before any approval queue
2. CA signs the new CSR immediately
3. New `DeviceCertificate` saved; previous cert left in place (not auto-revoked)
4. `EnrollmentRequest{status:"approved"}` saved as audit trail
5. Client receives cert immediately without admin action

Auto-renewal is **skipped** if the previous enrollment was `rejected` (prevents bypassing a rejection via renewal).

---

## Certificate Authority backends

### Builtin CA (default)

Self-signed ECDSA P-256 root per account. Created automatically on first use.

```
NewBuiltinCA(accountID) → certPEM, keyPEM:
  key = ECDSA P-256
  serial = 128-bit random
  CN = "NetBird Device CA — <accountID>"
  validity = 10 years
  IsCA = true, KeyUsage = CertSign | CRLSign
```

**Persistence:** CA cert + key stored in `TrustedCA` table. Key is AES-256-GCM encrypted if `SecretEncryption` is configured (see [Key encryption](#ca-key-encryption)).

**Revocation persistence:** On server startup, `loadRevokedFromStore` reads all `DeviceCertificate` records with `Revoked=true` and seeds the in-memory revocation list. CRL generation is correct after restart.

**CRL Distribution Point:** `https://<managementURL>/api/device-auth/crl/<crl-token>` — random token per CA prevents account ID enumeration.

### External CAs (interface defined, adapters implemented)

| CAType      | Backend              | Status                                       |
| ----------- | -------------------- | -------------------------------------------- |
| `builtin`   | In-process ECDSA     | ✅ Production-ready                          |
| `vault`     | HashiCorp Vault PKI  | ✅ Implemented (config: `VaultCAConfig`)     |
| `smallstep` | step-ca / Smallstep  | ✅ Implemented (config: `SmallstepCAConfig`) |
| `scep`      | SCEP protocol server | ✅ Implemented (config: `SCEPConfig`)        |

---

## CA key encryption

`management/server/secretenc/secretenc.go`

Builtin CA private keys are encrypted at rest with AES-256-GCM before being stored in the database.

**Algorithm:** AES-256-GCM  
**Wire format:** `[12-byte nonce][ciphertext + 16-byte auth tag]`  
**Storage prefix:** `enc:` — distinguishes encrypted from plaintext values for backward compatibility

**Key sources (configure one):**

| Provider                    | Config                                        | Notes                                                           |
| --------------------------- | --------------------------------------------- | --------------------------------------------------------------- |
| `NewEnvKeyProvider(envVar)` | `NB_SECRET_ENCRYPTION_KEY=base64(32bytes)`    | Recommended for production                                      |
| `NewFileKeyProvider(path)`  | 32 raw bytes; file must be `0600` or stricter | Fails (not warns) on permissive permissions                     |
| `NewNoOpKeyProvider()`      | No encryption — keys stored plaintext         | Requires `NB_SECRET_ENCRYPTION_NOOP_ALLOWED=yes`; dev/test only |

**If not configured:** CA keys are stored unencrypted in the database. A WARNING is logged at startup.

---

## MDM inventory integration

When `RequireInventoryCheck = true`, enrolling devices must have their serial number in the MDM inventory.

**Flow:**

1. Client includes `SystemSerialNumber` in `PeerSystemMeta` (JSON `system_info` field)
2. `checkInventoryForEnrollment` runs before creating any pending request
3. Serial not found → `PermissionDenied`; **no enrollment record created**
4. Serial found → enrollment proceeds

**Supported sources (combinable):**

| Source           | Type key | Description                               |
| ---------------- | -------- | ----------------------------------------- |
| Static list      | `static` | JSON array `{"serials": ["SN123", ...]}`  |
| Microsoft Intune | `intune` | Graph API; requires Azure app credentials |
| Jamf Pro         | `jamf`   | REST API; requires Jamf credentials       |

**Re-check on auto-renewal:**

- `InventoryRecheckIntervalHours`: how often to re-validate after initial enrollment (default `24h`)
- `0` = always re-check; negative = treat as `24h`
- `InventoryRecheckFailBehavior`: `"deny"` (default, fail-closed) or `"allow"` (fail-open)

**Skipped for:**

- Auto-renewal when `InventoryRecheckIntervalHours` not yet elapsed
- Attestation paths (use EK serial from TPM cert instead)

---

## REST API reference

All endpoints under `/api/v1/device-auth/`. Auth: Bearer token (Dex/OIDC).

### Enrollment management (admin OR cert_approver)

| Method | Path                                    | Description                                |
| ------ | --------------------------------------- | ------------------------------------------ |
| GET    | `/device-auth/enrollments`              | List all enrollment requests               |
| POST   | `/device-auth/enrollments/{id}/approve` | Approve → CA signs CSR → cert issued       |
| POST   | `/device-auth/enrollments/{id}/reject`  | Reject (optional body: `{"reason":"..."}`) |
| GET    | `/device-auth/devices`                  | List all issued device certificates        |

### Device certificate management (admin only)

| Method | Path                                   | Description                             |
| ------ | -------------------------------------- | --------------------------------------- |
| POST   | `/device-auth/devices/{id}/revoke`     | Revoke a device certificate             |
| POST   | `/device-auth/devices/{id}/cert/renew` | Force re-issue certificate for a device |

### Trusted CA management (admin only)

| Method | Path                            | Description                                 |
| ------ | ------------------------------- | ------------------------------------------- |
| GET    | `/device-auth/trusted-cas`      | List trusted CA certs (public PEM included) |
| POST   | `/device-auth/trusted-cas`      | Upload a trusted CA cert (PEM)              |
| DELETE | `/device-auth/trusted-cas/{id}` | Remove a trusted CA                         |

### Settings and CA config (admin only)

| Method | Path                            | Description                                   |
| ------ | ------------------------------- | --------------------------------------------- |
| GET    | `/device-auth/settings`         | Get current settings                          |
| PUT    | `/device-auth/settings`         | Update settings                               |
| GET    | `/device-auth/ca/config`        | Get CA config (credentials redacted)          |
| PUT    | `/device-auth/ca/config`        | Update CA config                              |
| POST   | `/device-auth/ca/test`          | Test CA connectivity                          |
| GET    | `/device-auth/inventory/config` | Get inventory config (credentials redacted)   |
| PUT    | `/device-auth/inventory/config` | Update inventory config                       |
| GET    | `/device-auth/crl`              | Download CRL (DER) — public, no auth required |

---

## gRPC messages

```proto
// Mode A — Manual enrollment
message DeviceEnrollRequest {
    string csr_pem     = 1;  // PEM-encoded PKCS#10 CSR
    string system_info = 2;  // JSON: {"SystemSerialNumber":"...", "hostname":"...", "wg_pub_key":"..."}
}
message DeviceEnrollResponse {
    string enrollment_id    = 1;
    string status           = 2;  // "pending" | "approved" | "rejected"
    string reason           = 3;  // set when rejected
    string device_cert_pem  = 4;  // set when approved
}
message GetEnrollmentStatusRequest  { string enrollment_id = 1; }
message GetEnrollmentStatusResponse {
    string status          = 1;
    string device_cert_pem = 2;
}

// Mode C — TPM credential activation
message BeginTPMAttestationRequest {
    string ek_cert_pem  = 1;  // DER-encoded EK certificate in PEM wrapper
    string ak_pub_pem   = 2;  // PKIX PEM, must be ECDSA P-256
    string csr_pem      = 3;  // PKCS#10 PEM; CN = WireGuard public key
}
message BeginTPMAttestationResponse {
    string session_id      = 1;  // 64 lowercase hex chars (32 random bytes)
    bytes  credential_blob = 2;  // uint16BE(len(id)) | id | uint16BE(len(enc)) | enc
}
message CompleteTPMAttestationRequest {
    string session_id       = 1;  // from BeginTPMAttestationResponse
    bytes  activated_secret = 2;  // 32-byte plaintext from TPM2_ActivateCredential
}

// Mode C — Apple Secure Enclave attestation
message AttestAppleSERequest {
    string   csr_pem          = 1;  // PKCS#10 PEM; CN = WireGuard public key
    repeated string attestation_pems = 2;  // [leaf, intermediate?, ...]; max 10
    string   system_info      = 3;  // JSON metadata
}

// Shared result for both Mode C paths
message AttestationResult {
    string enrollment_id   = 1;
    string status          = 2;  // "approved"
    string device_cert_pem = 3;  // PEM-encoded device certificate
}
```

---

## Configuration reference

### DeviceAuthSettings

```go
type DeviceAuthSettings struct {
    // Authentication mode
    Mode string  // "disabled" | "optional" | "cert-only" | "cert-and-sso"

    // Enrollment mode (controls which paths are offered to clients)
    EnrollmentMode string  // "manual" | "attestation" | "both"

    // CA backend
    CAType   string  // "builtin" | "vault" | "smallstep" | "scep"
    CAConfig string  // JSON (CA-specific; private fields redacted in GET)

    // Certificate validity
    CertValidityDays int  // default 365

    // OCSP (defined but not yet implemented — see Known limitations)
    OCSPEnabled               bool
    FailOpenOnOCSPUnavailable bool

    // MDM inventory
    InventoryType   string  // "intune" | "jamf" | "static" | ""
    InventoryConfig string  // JSON (credentials redacted in GET)
    RequireInventoryCheck       bool
    InventoryRecheckIntervalHours int  // 0 = always; default 24
    InventoryRecheckFailBehavior  string  // "deny" (default) | "allow"
}
```

### Apple SE config (`appleroots.Config`)

```go
type Config struct {
    CACertFile             string  // Path to Apple Root CA G3 PEM (required for Apple SE)
    IntermediateCACertFile string  // Path to Apple Secure Key Attestation CA PEM (recommended)
}
```

---

## RBAC roles

| Role            | List enrollments | Approve/Reject | List devices | Revoke devices | Change settings | Manage CAs |
| --------------- | :--------------: | :------------: | :----------: | :------------: | :-------------: | :--------: |
| `owner`         |        ✓         |       ✓        |      ✓       |       ✓        |        ✓        |     ✓      |
| `admin`         |        ✓         |       ✓        |      ✓       |       ✓        |        ✓        |     ✓      |
| `cert_approver` |        ✓         |       ✓        |      ✓       |       ✗        |        ✗        |     ✗      |
| `user`          |        ✗         |       ✗        |      ✗       |       ✗        |        ✗        |     ✗      |

`cert_approver` is for IT staff who prepare devices. They can approve/reject enrollments without full admin access.

---

## Known limitations (deferred to future phases)

### L-1: EK chain verification requires external CA bundle

**Status:** Not included in open-source build.  
**Impact:** TPM manufacturer identity is not verified. AK↔EK binding (the cryptographic proof of co-location) is still enforced by the `MakeCredential/ActivateCredential` protocol itself.  
**Mitigation:** Warning logged at startup and per-request. EK cert is still validated as a well-formed X.509 certificate.  
**Fix:** Run `go run scripts/fetch-tpm-roots.go` before production deployment to bundle manufacturer CA PEMs.

### L-2: Revocation not enforced on active Sync streams

**Status:** By design for initial release.  
**Impact:** A peer whose cert is revoked stays connected via Sync until it reconnects and logs in again. Revocation takes effect on next Login RPC (e.g., after client restart, network change, or reconnect).  
**Fix:** Requires injecting a disconnect signal into the peer's Sync context when a cert is revoked. Tracked as a follow-up feature.

### L-3: OCSP not implemented

**Status:** `OCSPEnabled` and `FailOpenOnOCSPUnavailable` fields exist in `DeviceAuthSettings` but OCSP validation is not performed.  
**Impact:** CRL-based revocation only. No real-time revocation checking.  
**Fix:** Implement OCSP stapling or responder integration in `checkCertRevocation`.

### L-4: Apple SE — intermediate CA not bundled

**Status:** Apple's intermediate CA (`Apple Secure Key Attestation CA`) is not bundled.  
**Impact:** Operator must download and configure `IntermediateCACertFile`, **or** clients must include the intermediate in `attestation_pems`. Without either, `AttestAppleSE` returns `Unauthenticated`.  
**Fix:** Download from Apple Certificate Authority page and configure before production use.

### L-5: Deprecated `AttestationProof` field in `DeviceEnrollRequest`

**Status:** Field exists in proto; `tryAttestationEnrollment` on the server always returns `codes.Unimplemented`.  
**Impact:** Old clients that send single-round attestation via `EnrollDevice` will get an error. They must upgrade to `BeginTPMAttestation` / `AttestAppleSE`.  
**Fix:** Remove the field in a future cleanup after all clients migrate.

### L-6: Session store not persistent across restarts

**Status:** Attestation sessions (`AttestationSessionStore`) are in-memory only.  
**Impact:** In-flight TPM credential activations are interrupted on server restart. Client must retry `BeginTPMAttestation`.  
**Fix:** Acceptable for the 5-minute TTL window; no action planned.

---

## Key components

### Backend (`netbirdio/netbird`)

| Package                                       | File                                   | Responsibility                                                                      |
| --------------------------------------------- | -------------------------------------- | ----------------------------------------------------------------------------------- |
| `management/internals/shared/grpc`            | `device_enrollment.go`                 | `EnrollDevice`, `GetEnrollmentStatus` — Mode A server handler                       |
| `management/internals/shared/grpc`            | `attestation_handler.go`               | `BeginTPMAttestation`, `CompleteTPMAttestation`, `AttestAppleSE`, `issueDeviceCert` |
| `management/internals/shared/grpc`            | `attestation_sessions.go`              | In-memory session store with TTL, capacity cap, atomic GetAndDelete                 |
| `management/internals/shared/grpc`            | `device_cert_revocation.go`            | `checkCertRevocation`, `verifyCertIssuedByAccountCA`                                |
| `management/internals/shared/grpc`            | `server.go`                            | mTLS enforcement; revocation check in Login; CA pool setup                          |
| `management/server/devicepki`                 | `builtin_ca.go`                        | Builtin ECDSA CA: sign, revoke, CRL generation                                      |
| `management/server/devicepki`                 | `factory.go`                           | `NewCA` dispatch + `newBuiltinCA` with revocation restore                           |
| `management/server/devicepki`                 | `attestation.go`                       | `VerifyEKCertChain` against bundled TPM manufacturer CAs                            |
| `management/server/devicepki/appleroots`      | `roots.go`                             | Apple Root CA G3 pool construction                                                  |
| `management/server/deviceauth`                | `handler.go`                           | `CheckDeviceAuth` policy; `VerifyPeerCert` TLS callback                             |
| `management/server/secretenc`                 | `secretenc.go`                         | AES-256-GCM CA key encryption                                                       |
| `management/server/deviceinventory`           | `inventory.go`, `intune.go`, `jamf.go` | Multi-source MDM inventory                                                          |
| `management/server/http/handlers/device_auth` | `handler.go`                           | REST admin API                                                                      |
| `management/server/store`                     | `sql_store.go`                         | `enrollment_requests`, `device_certificates`, `trusted_cas` tables                  |
| `client/internal/enrollment`                  | `manager.go`                           | `EnsureCertificate`, `StartRenewalLoop`, `BuildTLSCertificate`                      |
| `client/internal/tpm`                         | `provider.go`, `tpm_*.go`              | TPM/SE/CNG key providers per platform                                               |

### Frontend (`netbirdio/dashboard`)

| File                                                     | Responsibility                                     |
| -------------------------------------------------------- | -------------------------------------------------- |
| `src/modules/device-security/DeviceSecuritySettings.tsx` | Settings page (mode, CA, cert validity, inventory) |
| `src/modules/device-security/DeviceEnrollmentsPage.tsx`  | Enrollment queue with approve/reject               |
| `src/modules/device-security/DeviceInventoryPage.tsx`    | Inventory config (Intune, Jamf, static)            |
| `src/contexts/DeviceSecurityProvider.tsx`                | All device security API calls via SWR              |
| `src/interfaces/DeviceSecurity.ts`                       | TypeScript interfaces for all API types            |
| `src/modules/users/UserRoleSelector.tsx`                 | `cert_approver` role selection                     |

---

## Development

### Run tests

```bash
# Core attestation and session management
go test ./management/internals/shared/grpc/... -v

# CA backends
go test ./management/server/devicepki/... -v

# Secret encryption
go test ./management/server/secretenc/... -v

# HTTP admin handlers
go test ./management/server/http/handlers/device_auth/... -v

# MDM inventory
go test ./management/server/deviceinventory/... -v

# Client enrollment manager
go test ./client/internal/enrollment/... -v

# All feature packages with race detector
go test -race \
  ./management/internals/shared/grpc/... \
  ./management/server/devicepki/... \
  ./management/server/secretenc/... \
  ./client/internal/enrollment/...
```

### Demo tools

```bash
# Mode A enrollment demo (creates pending request)
go run ./management/cmd/enroll-demo \
  --management-url https://localhost \
  --setup-key <setup-key>

# mTLS connection test (requires issued cert)
go run ./management/cmd/mtls-demo \
  --management-url https://localhost \
  --cert /path/to/device.crt \
  --key /path/to/device.key
```

### Fetch TPM manufacturer CAs (required for production)

```bash
# Bundles manufacturer CAs into management/server/devicepki/tpmroots/
go run scripts/fetch-tpm-roots.go
```

### Dev stand with Docker

```bash
# See docs/superpowers/plans/ for full stand setup instructions
# management/stand-dex/docker-compose.device-auth.yml for docker-compose overlay
```
