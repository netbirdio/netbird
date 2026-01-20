# ADR-002: Windows CNG crypto.Signer Interface

**Status:** Pending (requires Windows environment)
**Date:** 2026-01-20
**Issue:** T-1.1 (Windows CNG crypto.Signer Spike)

## Context

Machine Tunnel needs to use Windows machine certificates stored in the Windows Certificate Store for mTLS authentication. Go's standard `crypto/tls` expects a `crypto.Signer` interface, but Windows certificates use CNG (Cryptography Next Generation) APIs where private keys are not exportable.

## Problem

1. Windows machine certificates are stored in `LocalMachine\My` certificate store
2. Private keys are managed by CNG (`ncrypt.dll`) and marked as non-exportable
3. Go's `tls.Certificate` expects either:
   - `PrivateKey` as `crypto.Signer` (preferred)
   - Or raw key bytes (not possible with non-exportable keys)

## Proposed Solution

Implement a `CNG crypto.Signer` wrapper that:
1. Opens the certificate from Windows Cert Store via `crypt32.dll`
2. Gets the private key handle via `ncrypt.dll`
3. Implements `crypto.Signer.Sign()` by calling `NCryptSignHash()`

### Interface Definition

```go
// cng_signer_windows.go

package auth

import (
    "crypto"
    "io"
)

// CNGSigner implements crypto.Signer using Windows CNG APIs.
// This allows using non-exportable machine certificates for mTLS.
type CNGSigner struct {
    keyHandle    uintptr  // NCRYPT_KEY_HANDLE
    publicKey    crypto.PublicKey
    certThumbprint string
}

// Public returns the public key.
func (s *CNGSigner) Public() crypto.PublicKey {
    return s.publicKey
}

// Sign signs digest with the private key via NCryptSignHash.
func (s *CNGSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    // TODO: Implement via NCryptSignHash
    // - Determine padding based on opts (PKCS1v15 vs PSS)
    // - Call NCryptSignHash with appropriate flags
    // - Return signature bytes
}

// NewCNGSignerFromThumbprint loads a certificate by thumbprint and returns a signer.
func NewCNGSignerFromThumbprint(thumbprint string) (*CNGSigner, *x509.Certificate, error) {
    // TODO: Implement
    // 1. CertOpenStore(CERT_STORE_PROV_SYSTEM, "MY", CERT_SYSTEM_STORE_LOCAL_MACHINE)
    // 2. CertFindCertificateInStore(thumbprint)
    // 3. CryptAcquireCertificatePrivateKey()
    // 4. Extract public key from certificate
    // 5. Return CNGSigner wrapping the key handle
}
```

### Required Windows APIs

| API | DLL | Purpose |
|-----|-----|---------|
| `CertOpenStore` | crypt32.dll | Open certificate store |
| `CertFindCertificateInStore` | crypt32.dll | Find cert by thumbprint |
| `CryptAcquireCertificatePrivateKey` | crypt32.dll | Get private key handle |
| `NCryptSignHash` | ncrypt.dll | Sign with CNG key |
| `NCryptFreeObject` | ncrypt.dll | Release key handle |

### Dependencies

```go
import "golang.org/x/sys/windows"
```

## Implementation Notes

### Build Constraints
```go
//go:build windows

package auth
```

### Stub for Non-Windows
```go
//go:build !windows

package auth

func NewCNGSignerFromThumbprint(thumbprint string) (*CNGSigner, *x509.Certificate, error) {
    return nil, nil, errors.New("CNG signer only available on Windows")
}
```

### Testing Requirements
- Requires Windows VM with:
  - AD CS enrolled machine certificate
  - Certificate in `LocalMachine\My` store
  - Non-exportable private key

## Status

**BLOCKED:** Implementation requires Windows development environment.

### Prerequisites
1. Windows 10/11 or Server 2019+ VM
2. Machine certificate enrolled via AD CS
3. Go 1.21+ with CGO enabled (for syscall)

### Next Steps (on Windows VM)
1. Create `client/internal/auth/cng_signer_windows.go`
2. Implement Windows API calls via `golang.org/x/sys/windows`
3. Test with real AD CS certificate
4. Add unit tests with mock certificate store

## References

- [NCryptSignHash](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsignhash)
- [CryptAcquireCertificatePrivateKey](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey)
- [golang.org/x/sys/windows](https://pkg.go.dev/golang.org/x/sys/windows)
- [Go crypto.Signer](https://pkg.go.dev/crypto#Signer)
