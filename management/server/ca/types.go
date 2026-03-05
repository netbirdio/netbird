package ca

import (
	"fmt"
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/util/crypt"
)

// CACertificate represents a Certificate Authority certificate stored in the database.
type CACertificate struct {
	ID             string    `gorm:"primaryKey"`
	AccountID      string    `gorm:"index"`
	CertificatePEM string    `gorm:"type:text"`
	PrivateKeyPEM  string    `gorm:"type:text"` // encrypted at rest via FieldEncrypt
	Fingerprint    string    `gorm:"index"`
	DisplayName    string    // CN used when generating the CA
	Organization   string    // O used when generating the CA
	NotBefore      time.Time
	NotAfter       time.Time
	IsActive       bool      `gorm:"index"`
	CreatedAt      time.Time
}

// NewCACertificate creates a new CACertificate with a generated ID and creation timestamp.
func NewCACertificate(accountID string, certPEM, keyPEM, fingerprint string, opts CAOptions, notBefore, notAfter time.Time) *CACertificate {
	return &CACertificate{
		ID:             xid.New().String(),
		AccountID:      accountID,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		Fingerprint:    fingerprint,
		DisplayName:    opts.DisplayName,
		Organization:   opts.Organization,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		IsActive:       true,
		CreatedAt:      time.Now().UTC(),
	}
}

// EncryptSensitiveData encrypts the CA private key in place.
func (c *CACertificate) EncryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return nil
	}

	if c.PrivateKeyPEM != "" {
		encrypted, err := enc.Encrypt(c.PrivateKeyPEM)
		if err != nil {
			return fmt.Errorf("encrypt ca private key: %w", err)
		}
		c.PrivateKeyPEM = encrypted
	}

	return nil
}

// DecryptSensitiveData decrypts the CA private key in place.
func (c *CACertificate) DecryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return nil
	}

	if c.PrivateKeyPEM != "" {
		decrypted, err := enc.Decrypt(c.PrivateKeyPEM)
		if err != nil {
			return fmt.Errorf("decrypt ca private key: %w", err)
		}
		c.PrivateKeyPEM = decrypted
	}

	return nil
}

// IssuedCertificate represents a certificate issued to a peer.
type IssuedCertificate struct {
	ID           string    `gorm:"primaryKey"`
	AccountID    string    `gorm:"index"`
	PeerID       string    `gorm:"index"`
	SerialNumber string    `gorm:"uniqueIndex"`
	DNSNames     []string  `gorm:"serializer:json"`
	HasWildcard  bool
	NotBefore    time.Time
	NotAfter     time.Time
	SigningType  string // "internal" or "acme"
	SignedByCAID string `gorm:"index"`
	Revoked      bool
	CreatedAt    time.Time
}

// IssuedCertParams holds the parameters for creating an IssuedCertificate.
type IssuedCertParams struct {
	AccountID    string
	PeerID       string
	SerialNumber string
	DNSNames     []string
	HasWildcard  bool
	NotBefore    time.Time
	NotAfter     time.Time
	SigningType   string
	SignedByCAID string
}

// NewIssuedCertificate creates a new IssuedCertificate with a generated ID and creation timestamp.
func NewIssuedCertificate(p IssuedCertParams) *IssuedCertificate {
	return &IssuedCertificate{
		ID:           xid.New().String(),
		AccountID:    p.AccountID,
		PeerID:       p.PeerID,
		SerialNumber: p.SerialNumber,
		DNSNames:     p.DNSNames,
		HasWildcard:  p.HasWildcard,
		NotBefore:    p.NotBefore,
		NotAfter:     p.NotAfter,
		SigningType:   p.SigningType,
		SignedByCAID: p.SignedByCAID,
		Revoked:      false,
		CreatedAt:    time.Now().UTC(),
	}
}

// CertIssuanceLog records each certificate issuance event for rate limiting.
type CertIssuanceLog struct {
	ID        string    `gorm:"primaryKey"`
	AccountID string    `gorm:"index"`
	PeerID    string    `gorm:"index"`
	IssuedAt  time.Time `gorm:"index"`
	Trigger   string    // "manual", "renewal", "domain_change"
}

// NewCertIssuanceLog creates a new CertIssuanceLog with a generated ID.
func NewCertIssuanceLog(accountID, peerID, trigger string) *CertIssuanceLog {
	return &CertIssuanceLog{
		ID:        xid.New().String(),
		AccountID: accountID,
		PeerID:    peerID,
		IssuedAt:  time.Now().UTC(),
		Trigger:   trigger,
	}
}
