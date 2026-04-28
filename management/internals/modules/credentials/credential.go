// Package credentials defines the per-account encrypted credential records
// used by the management server. Credentials are opaque secrets (e.g.,
// DNS provider API tokens) referenced from other resources by an opaque
// ID; the secret itself is stored encrypted at rest and only ever
// decrypted on the management server, never on the wire to API clients.
package credentials

import "time"

// Credential is an account-scoped encrypted secret. Slice A scope: DNS
// provider tokens consumed by the proxy's Lego-based dns-01 path.
//
// Invariants:
//   - EncryptedSecret is always ciphertext on disk (AES-256-GCM via
//     util/crypt.FieldEncrypt).
//   - The plaintext secret is set only briefly during decryption inside
//     the management server's credential manager and never serialized
//     onto an HTTP response or stored anywhere else.
//   - ID is server-generated (UUIDv4) — clients never pick the ref.
type Credential struct {
	// ID is the opaque ref clients use to reference this credential.
	ID string `gorm:"primaryKey"`
	// AccountID scopes the credential to a single account; cross-account
	// access is never permitted.
	AccountID string `gorm:"index"`
	// ProviderType identifies the consumer (e.g., "cloudflare",
	// "route53"). Wave 4 introduces a registry; Slice A treats this as
	// an opaque non-empty string.
	ProviderType string `gorm:"index"`
	// Name is a user-friendly label.
	Name string
	// EncryptedSecret is the ciphertext (base64-encoded). Must be
	// decrypted via the credentials Manager; never read directly by
	// HTTP handlers or any code that returns it on the wire.
	EncryptedSecret string `gorm:"column:encrypted_secret"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

// TableName overrides the GORM-default plural table name to "credentials".
func (Credential) TableName() string {
	return "credentials"
}
