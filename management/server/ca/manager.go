package ca

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// DefaultRateLimitPerPeer is the default maximum certificate issuances per peer per day.
	DefaultRateLimitPerPeer = 10

	// TriggerManual indicates a manual certificate request by the user.
	TriggerManual = "manual"
	// TriggerRenewal indicates an automatic renewal before expiry.
	TriggerRenewal = "renewal"
	// TriggerDomainChange indicates re-issuance due to a peer FQDN change.
	TriggerDomainChange = "domain_change"
	// TriggerSessionRenewal indicates re-issuance after peer re-authentication.
	TriggerSessionRenewal = "session_renewal"
)

// CAStore defines the storage operations needed by the CA Manager.
type CAStore interface {
	CreateCACertificate(ctx context.Context, ca *CACertificate) error
	GetCACertificateByID(ctx context.Context, accountID, caID string) (*CACertificate, error)
	GetActiveCACertificates(ctx context.Context, accountID string) ([]*CACertificate, error)
	DeactivateCACertificate(ctx context.Context, accountID, caID string) error

	CreateIssuedCertificate(ctx context.Context, cert *IssuedCertificate) error
	GetIssuedCertificates(ctx context.Context, accountID string) ([]*IssuedCertificate, error)
	GetIssuedCertificatesByPeer(ctx context.Context, accountID, peerID string) ([]*IssuedCertificate, error)
	GetIssuedCertificateBySerial(ctx context.Context, accountID, serialNumber string) (*IssuedCertificate, error)
	RevokeCertificate(ctx context.Context, accountID, serialNumber string) error
	GetExpiringCertificates(ctx context.Context, accountID string, expiringBefore time.Time) ([]*IssuedCertificate, error)

	GetPeersWithActiveWildcardCerts(ctx context.Context, accountID string) (map[string]struct{}, error)

	CreateCertIssuanceLog(ctx context.Context, entry *CertIssuanceLog) error
	CountCertIssuancesInWindow(ctx context.Context, accountID, peerID string, since time.Time) (int64, error)
}

// Manager orchestrates certificate signing across multiple backends.
type Manager struct {
	store   CAStore
	signers map[string]CertSigner
}

// NewManager creates a new CA Manager.
func NewManager(store CAStore) *Manager {
	return &Manager{
		store:   store,
		signers: make(map[string]CertSigner),
	}
}

// RegisterSigner adds a signing backend to the manager.
func (m *Manager) RegisterSigner(signer CertSigner) {
	m.signers[signer.Type()] = signer
}

// InitForAccount generates a new internal root CA for the given account and stores it.
// The CA is constrained to the account's DNS domain via x509 NameConstraints.
// Encryption of sensitive fields is handled transparently by the store layer.
func (m *Manager) InitForAccount(ctx context.Context, accountID, dnsDomain string, opts CAOptions) (*CACertificate, error) {
	result, err := GenerateCA(dnsDomain, opts)
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}

	cert, err := parseCertificatePEM(result.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA cert: %w", err)
	}

	caCert := NewCACertificate(accountID, string(result.CertPEM), string(result.KeyPEM), result.Fingerprint, result.DisplayName, result.Organization, cert.NotBefore, cert.NotAfter)

	if err := m.store.CreateCACertificate(ctx, caCert); err != nil {
		return nil, fmt.Errorf("store CA certificate: %w", err)
	}

	log.WithContext(ctx).Infof("initialized internal CA for account %s (fingerprint: %s)", accountID, result.Fingerprint)

	return caCert, nil
}

// SignCertificate signs a CSR using the specified backend and records the issuance.
// Decryption of CA private keys is handled transparently by the store layer.
func (m *Manager) SignCertificate(ctx context.Context, accountID, peerID string, csr *x509.CertificateRequest, signingType string, wildcard bool, trigger string, validity time.Duration) (*SigningResult, *IssuedCertificate, error) {
	if csr == nil {
		return nil, nil, fmt.Errorf("csr is required")
	}

	if signingType == SigningTypeACME {
		signer, ok := m.signers[SigningTypeACME]
		if !ok {
			return nil, nil, fmt.Errorf("ACME signer not registered")
		}
		// ACME stub will return an error
		result, err := signer.Sign(ctx, csr, "", wildcard)
		return result, nil, err
	}

	if len(csr.DNSNames) == 0 {
		return nil, nil, fmt.Errorf("csr must include at least one DNS SAN")
	}
	peerFQDN := csr.DNSNames[0]

	activeCAs, err := m.store.GetActiveCACertificates(ctx, accountID)
	if err != nil {
		return nil, nil, fmt.Errorf("get active CAs: %w", err)
	}

	if len(activeCAs) == 0 {
		return nil, nil, fmt.Errorf("no active CA found for account %s", accountID)
	}

	// Use the most recently created active CA
	ca := activeCAs[0]

	certValidity := defaultCertValidity
	if validity > 0 {
		certValidity = validity
	}

	signer, err := NewInternalCASigner([]byte(ca.CertificatePEM), []byte(ca.PrivateKeyPEM), ca.ID, certValidity)
	if err != nil {
		return nil, nil, fmt.Errorf("create internal signer: %w", err)
	}

	result, err := signer.Sign(ctx, csr, peerFQDN, wildcard)
	if err != nil {
		return nil, nil, fmt.Errorf("sign certificate: %w", err)
	}

	serialNumber, err := SerialNumberFromResult(result.CertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("extract serial number: %w", err)
	}

	notAfter, err := NotAfterFromResult(result.CertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("extract not after: %w", err)
	}

	dnsNames := csr.DNSNames
	if wildcard && !containsName(dnsNames, "*."+peerFQDN) {
		dnsNames = append(dnsNames, "*."+peerFQDN)
	}

	issued := NewIssuedCertificate(
		accountID, peerID, serialNumber, dnsNames, wildcard,
		time.Now().UTC(), notAfter, SigningTypeInternal, ca.ID,
	)

	if err := m.store.CreateIssuedCertificate(ctx, issued); err != nil {
		return nil, nil, fmt.Errorf("store issued certificate: %w", err)
	}

	logEntry := NewCertIssuanceLog(accountID, peerID, trigger)
	if err := m.store.CreateCertIssuanceLog(ctx, logEntry); err != nil {
		log.WithContext(ctx).Warnf("failed to log certificate issuance: %v", err)
	}

	return result, issued, nil
}

// GetActiveCACertificates returns all active CA certificates for the given account.
func (m *Manager) GetActiveCACertificates(ctx context.Context, accountID string) ([]*CACertificate, error) {
	return m.store.GetActiveCACertificates(ctx, accountID)
}

// GetCACertificate returns a specific CA certificate by ID.
func (m *Manager) GetCACertificate(ctx context.Context, accountID, caID string) (*CACertificate, error) {
	return m.store.GetCACertificateByID(ctx, accountID, caID)
}

// GetIssuedCertificates returns all issued certificates for the given account.
func (m *Manager) GetIssuedCertificates(ctx context.Context, accountID string) ([]*IssuedCertificate, error) {
	return m.store.GetIssuedCertificates(ctx, accountID)
}

// RotateCA creates a new CA while keeping existing CAs active for trust continuity.
func (m *Manager) RotateCA(ctx context.Context, accountID, dnsDomain string, opts CAOptions) (*CACertificate, error) {
	return m.InitForAccount(ctx, accountID, dnsDomain, opts)
}

// DeactivateCA deactivates a specific CA certificate.
func (m *Manager) DeactivateCA(ctx context.Context, accountID, caID string) error {
	return m.store.DeactivateCACertificate(ctx, accountID, caID)
}

// CheckRateLimit checks if the peer has exceeded the rate limit for certificate issuance.
// domain_change triggers are exempt from rate limiting.
func (m *Manager) CheckRateLimit(ctx context.Context, accountID, peerID, trigger string, limit int) error {
	if trigger == TriggerDomainChange || trigger == TriggerSessionRenewal {
		return nil
	}

	if limit <= 0 {
		limit = DefaultRateLimitPerPeer
	}

	since := time.Now().UTC().Add(-24 * time.Hour)
	count, err := m.store.CountCertIssuancesInWindow(ctx, accountID, peerID, since)
	if err != nil {
		return fmt.Errorf("count issuances: %w", err)
	}

	if count >= int64(limit) {
		return fmt.Errorf("peer %s exceeded certificate rate limit (%d/%d in 24h)", peerID, count, limit)
	}

	return nil
}

// GetIssuedCertificatesByPeer returns all issued certificates for a peer.
func (m *Manager) GetIssuedCertificatesByPeer(ctx context.Context, accountID, peerID string) ([]*IssuedCertificate, error) {
	return m.store.GetIssuedCertificatesByPeer(ctx, accountID, peerID)
}

// RevokeCertificate revokes a certificate by its serial number.
func (m *Manager) RevokeCertificate(ctx context.Context, accountID, serialNumber string) error {
	return m.store.RevokeCertificate(ctx, accountID, serialNumber)
}

// GetExpiringCertificates returns certificates that expire before the given time.
func (m *Manager) GetExpiringCertificates(ctx context.Context, accountID string, expiringBefore time.Time) ([]*IssuedCertificate, error) {
	return m.store.GetExpiringCertificates(ctx, accountID, expiringBefore)
}
