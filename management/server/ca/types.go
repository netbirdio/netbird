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
	NotBefore      time.Time
	NotAfter       time.Time
	IsActive       bool      `gorm:"index"`
	CreatedAt      time.Time
}

// NewCACertificate creates a new CACertificate with a generated ID and creation timestamp.
func NewCACertificate(accountID, certPEM, keyPEM, fingerprint string, notBefore, notAfter time.Time) *CACertificate {
	return &CACertificate{
		ID:             xid.New().String(),
		AccountID:      accountID,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		Fingerprint:    fingerprint,
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

// NewIssuedCertificate creates a new IssuedCertificate with a generated ID and creation timestamp.
func NewIssuedCertificate(accountID, peerID, serialNumber string, dnsNames []string, hasWildcard bool, notBefore, notAfter time.Time, signingType, signedByCAID string) *IssuedCertificate {
	return &IssuedCertificate{
		ID:           xid.New().String(),
		AccountID:    accountID,
		PeerID:       peerID,
		SerialNumber: serialNumber,
		DNSNames:     dnsNames,
		HasWildcard:  hasWildcard,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SigningType:   signingType,
		SignedByCAID: signedByCAID,
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
