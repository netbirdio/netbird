package types

import (
	"time"

	"github.com/rs/xid"
)

// Enrollment request statuses.
const (
	EnrollmentStatusPending  = "pending"
	EnrollmentStatusApproved = "approved"
	EnrollmentStatusRejected = "rejected"
)

// DeviceCertificate records an issued device certificate.
// One record per (AccountID, WGPublicKey) pair; revoked certs stay in the table.
type DeviceCertificate struct {
	ID          string    `gorm:"primaryKey"`
	AccountID   string    `gorm:"index"`
	PeerID      string    `gorm:"index"`
	WGPublicKey string    `gorm:"index"`
	Serial      string    // big.Int serialised as decimal string
	PEM         string    `gorm:"type:text"`
	NotBefore   time.Time
	NotAfter    time.Time
	Revoked     bool
	RevokedAt   *time.Time
	// LastInventoryCheckAt is set to the current time whenever the device is
	// successfully confirmed in the configured MDM inventory during auto-renewal.
	// Nil means the device has never been checked. GORM AutoMigrate adds the
	// nullable column automatically.
	LastInventoryCheckAt *time.Time
	CreatedAt            time.Time
}

// NewDeviceCertificate returns a DeviceCertificate with a generated ID and CreatedAt.
func NewDeviceCertificate(accountID, peerID, wgPubKey, serial, pem string, notBefore, notAfter time.Time) *DeviceCertificate {
	return &DeviceCertificate{
		ID:          xid.New().String(),
		AccountID:   accountID,
		PeerID:      peerID,
		WGPublicKey: wgPubKey,
		Serial:      serial,
		PEM:         pem,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		CreatedAt:   time.Now().UTC(),
	}
}

// TrustedCA stores a CA certificate (PEM) trusted for device certificate verification.
// Accounts maintain their own CA pool; external CAs can be imported.
type TrustedCA struct {
	ID        string `gorm:"primaryKey"`
	AccountID string `gorm:"index"`
	Name      string
	PEM       string `gorm:"type:text"`
	// KeyPEM stores the CA private key PEM for builtin CAs.
	// Empty for externally-managed CAs where the private key is held by the CA server.
	KeyPEM string `gorm:"type:text"`
	// CRLToken is a 32-byte random hex token used as the path segment for the CRL
	// distribution endpoint: GET /api/device-auth/crl/{token}.
	// Using a random token instead of account ID prevents account enumeration.
	// Generated once when a builtin CA record is first created; never rotated.
	// Nil for externally-managed CAs (vault, smallstep, scep) that have no
	// CRL endpoint served by the management server.
	// Nullable so that multiple external-CA rows (nil token) never conflict in the
	// unique index — NULL values are not considered equal in SQL unique constraints.
	CRLToken *string `gorm:"type:varchar(64);uniqueIndex"`
	CreatedAt time.Time
}

// NewTrustedCA returns a TrustedCA with a generated ID and CreatedAt.
func NewTrustedCA(accountID, name, pem string) *TrustedCA {
	return &TrustedCA{
		ID:        xid.New().String(),
		AccountID: accountID,
		Name:      name,
		PEM:       pem,
		CreatedAt: time.Now().UTC(),
	}
}

// NewBuiltinTrustedCA returns a TrustedCA that includes the CA private key.
// Use this for builtin CAs whose key must be persisted for signing and CRL generation.
func NewBuiltinTrustedCA(accountID, name, certPEM, keyPEM string) *TrustedCA {
	return &TrustedCA{
		ID:        xid.New().String(),
		AccountID: accountID,
		Name:      name,
		PEM:       certPEM,
		KeyPEM:    keyPEM,
		CreatedAt: time.Now().UTC(),
	}
}

// EnrollmentRequest is a peer's request for a device certificate.
// The admin reviews and approves or rejects it.
type EnrollmentRequest struct {
	ID          string `gorm:"primaryKey"`
	AccountID   string `gorm:"index"`
	PeerID      string `gorm:"index"`
	WGPublicKey string `gorm:"index"`
	CSRPEM      string `gorm:"type:text"` // PEM-encoded PKCS#10 CSR
	SystemInfo  string `gorm:"type:text"` // JSON-encoded PeerSystemMeta
	Status      string `gorm:"default:pending"`
	Reason      string // populated on rejection
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NewEnrollmentRequest returns an EnrollmentRequest with a generated ID, status pending.
func NewEnrollmentRequest(accountID, peerID, wgPubKey, csrPEM, systemInfo string) *EnrollmentRequest {
	now := time.Now().UTC()
	return &EnrollmentRequest{
		ID:          xid.New().String(),
		AccountID:   accountID,
		PeerID:      peerID,
		WGPublicKey: wgPubKey,
		CSRPEM:      csrPEM,
		SystemInfo:  systemInfo,
		Status:      EnrollmentStatusPending,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// IsActive reports whether the enrollment request is in a terminal-pending state
// that should block a new submission (i.e. pending or approved).
func (e *EnrollmentRequest) IsActive() bool {
	return e.Status == EnrollmentStatusPending || e.Status == EnrollmentStatusApproved
}
