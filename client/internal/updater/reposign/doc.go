// Package reposign implements a cryptographic signing and verification system
// for NetBird software update artifacts. It provides a hierarchical key
// management system with support for key rotation, revocation, and secure
// artifact distribution.
//
// # Architecture
//
// The package uses a two-tier key hierarchy:
//
//   - Root Keys: Long-lived keys that sign artifact keys. These are embedded
//     in the client binary and establish the root of trust. Root keys should
//     be kept offline and highly secured.
//
//   - Artifact Keys: Short-lived keys that sign release artifacts (binaries,
//     packages, etc.). These are rotated regularly and can be revoked if
//     compromised. Artifact keys are signed by root keys and distributed via
//     a public repository.
//
// This separation allows for operational flexibility: artifact keys can be
// rotated frequently without requiring client updates, while root keys remain
// stable and embedded in the software.
//
// # Cryptographic Primitives
//
// The package uses strong, modern cryptographic algorithms:
//   - Ed25519: Fast, secure digital signatures (no timing attacks)
//   - BLAKE2s-256: Fast cryptographic hash for artifacts
//   - SHA-256: Key ID generation
//   - JSON: Structured key and signature serialization
//   - PEM: Standard key encoding format
//
// # Security Features
//
// Timestamp Binding:
//   - All signatures include cryptographically-bound timestamps
//   - Prevents replay attacks and enforces signature freshness
//   - Clock skew tolerance: 5 minutes
//
// Key Expiration:
//   - All keys have expiration times
//   - Expired keys are automatically rejected
//   - Signing with an expired key fails immediately
//
// Key Revocation:
//   - Compromised keys can be revoked via a signed revocation list
//   - Revocation list is checked during artifact validation
//   - Revoked keys are filtered out before artifact verification
//
// # File Structure
//
// The package expects the following file layout in the key repository:
//
//	signrepo/
//	  artifact-key-pub.pem      # Bundle of artifact public keys
//	  artifact-key-pub.pem.sig  # Root signature of the bundle
//	  revocation-list.json      # List of revoked key IDs
//	  revocation-list.json.sig  # Root signature of revocation list
//
// And in the artifacts repository:
//
//	releases/
//	  v0.28.0/
//	    netbird-linux-amd64
//	    netbird-linux-amd64.sig   # Artifact signature
//	    netbird-darwin-amd64
//	    netbird-darwin-amd64.sig
//	    ...
//
// # Embedded Root Keys
//
// Root public keys are embedded in the client binary at compile time:
//   - Production keys: certs/ directory
//   - Development keys: certsdev/ directory
//
// The build tag determines which keys are embedded:
//   - Production builds: //go:build !devartifactsign
//   - Development builds: //go:build devartifactsign
//
// This ensures that development artifacts cannot be verified using production
// keys and vice versa.
//
// # Key Rotation Strategies
//
// Root Key Rotation:
//
// Root keys can be rotated without breaking existing clients by leveraging
// the multi-key verification system. The loadEmbeddedPublicKeys function
// reads ALL files from the certs/ directory and accepts signatures from ANY
// of the embedded root keys.
//
// To rotate root keys:
//
//  1. Generate a new root key pair:
//     newRootKey, privPEM, pubPEM, err := GenerateRootKey(10 * 365 * 24 * time.Hour)
//
//  2. Add the new public key to the certs/ directory as a new file:
//     certs/
//     root-pub-2024.pem    # Old key (keep this!)
//     root-pub-2025.pem    # New key (add this)
//
//  3. Build new client versions with both keys embedded. The verification
//     will accept signatures from either key.
//
//  4. Start signing new artifact keys with the new root key. Old clients
//     with only the old root key will reject these, but new clients with
//     both keys will accept them.
//
// Each file in certs/ can contain a single key or a bundle of keys (multiple
// PEM blocks). The system will parse all keys from all files and use them
// for verification. This provides maximum flexibility for key management.
//
// Important: Never remove all old root keys at once. Always maintain at least
// one overlapping key between releases to ensure smooth transitions.
//
// Artifact Key Rotation:
//
// Artifact keys should be rotated regularly (e.g., every 90 days) using the
// bundling mechanism. The BundleArtifactKeys function allows multiple artifact
// keys to be bundled together in a single signed package, and ValidateArtifact
// will accept signatures from ANY key in the bundle.
//
// To rotate artifact keys smoothly:
//
//  1. Generate a new artifact key while keeping the old one:
//     newKey, newPrivPEM, newPubPEM, newSig, err := GenerateArtifactKey(rootKey, 90 * 24 * time.Hour)
//     // Keep oldPubPEM and oldKey available
//
//  2. Create a bundle containing both old and new public keys
//
//  3. Upload the bundle and its signature to the key repository:
//     signrepo/artifact-key-pub.pem      # Contains both keys
//     signrepo/artifact-key-pub.pem.sig  # Root signature
//
//  4. Start signing new releases with the NEW key, but keep the bundle
//     unchanged. Clients will download the bundle (containing both keys)
//     and accept signatures from either key.
//
// Key bundle validation workflow:
//  1. Client downloads artifact-key-pub.pem and artifact-key-pub.pem.sig
//  2. ValidateArtifactKeys verifies the bundle signature with ANY embedded root key
//  3. ValidateArtifactKeys parses all public keys from the bundle
//  4. ValidateArtifactKeys filters out expired or revoked keys
//  5. When verifying an artifact, ValidateArtifact tries each key until one succeeds
//
// This multi-key acceptance model enables overlapping validity periods and
// smooth transitions without client update requirements.
//
// # Best Practices
//
// Root Key Management:
//   - Generate root keys offline on an air-gapped machine
//   - Store root private keys in hardware security modules (HSM) if possible
//   - Use separate root keys for production and development
//   - Rotate root keys infrequently (e.g., every 5-10 years)
//   - Plan for root key rotation: embed multiple root public keys
//
// Artifact Key Management:
//   - Rotate artifact keys regularly (e.g., every 90 days)
//   - Use separate artifact keys for different release channels if needed
//   - Revoke keys immediately upon suspected compromise
//   - Bundle multiple artifact keys to enable smooth rotation
//
// Signing Process:
//   - Sign artifacts in a secure CI/CD environment
//   - Never commit private keys to version control
//   - Use environment variables or secret management for keys
//   - Verify signatures immediately after signing
//
// Distribution:
//   - Serve keys and revocation lists from a reliable CDN
//   - Use HTTPS for all key and artifact downloads
//   - Monitor download failures and signature verification failures
//   - Keep revocation list up to date
package reposign
