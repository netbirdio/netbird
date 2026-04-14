package devicepki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// crlRefreshInterval controls how often Start re-generates and publishes the CRL.
// It matches the NextUpdate horizon set in GenerateCRL.
const crlRefreshInterval = 12 * time.Hour

// BuiltinCA is a self-signed root CA that signs device certificates in-process.
// It is safe for concurrent use. All state is in-memory; callers must persist
// CertPEM and KeyPEM via the TrustedCA store and reload with LoadBuiltinCA.
// revokedEntry records a certificate serial and the time it was revoked,
// as required by RFC 5280 for correct CRL RevocationTime values.
type revokedEntry struct {
	serial     *big.Int
	revokedAt  time.Time
}

type BuiltinCA struct {
	mu      sync.RWMutex
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	// cdpURL is the CRL Distribution Point URL embedded in issued certificates.
	// When empty, no CDP extension is added. Format:
	//   https://<management-host>/api/device-auth/crl/<crl-token>
	cdpURL string
	// revoked holds serials and revocation timestamps in-memory. The list is
	// seeded from persisted DeviceCertificate records on startup (see loadRevokedFromStore
	// in factory.go) and updated in-process by Revoke. Revocations survive restart.
	revoked []revokedEntry
}

// NewBuiltinCA generates a fresh ECDSA P-256 self-signed root CA for accountID.
// Returns the PEM-encoded certificate and private key.
func NewBuiltinCA(accountID string) (certPEM string, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("devicepki: generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("devicepki: generate CA serial: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "NetBird Device CA – " + accountID,
			Organization: []string{"NetBird"},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return "", "", fmt.Errorf("devicepki: create CA certificate: %w", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("devicepki: marshal CA key: %w", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	return certPEM, keyPEM, nil
}

// revokedEntrySlice is the type exposed for seeding revocations from the store.
// Defined here so factory.go can build it without importing internal types.
type revokedEntrySlice = []revokedEntry

// seedRevoked replaces the in-memory revocation list with the provided entries.
// Called once after LoadBuiltinCA to restore persisted revocations across restarts.
func (ca *BuiltinCA) seedRevoked(entries []revokedEntry) {
	ca.mu.Lock()
	ca.revoked = entries
	ca.mu.Unlock()
}

// LoadBuiltinCA reconstructs a BuiltinCA from persisted PEM strings.
// cdpURL is the CRL distribution point URL to embed in issued certificates.
// Pass "" to omit the CDP extension.
func LoadBuiltinCA(certPEM, keyPEM, cdpURL string) (*BuiltinCA, error) {
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, fmt.Errorf("devicepki: decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("devicepki: parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, fmt.Errorf("devicepki: decode CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("devicepki: parse CA private key: %w", err)
	}

	return &BuiltinCA{
		cert:    cert,
		key:     key,
		cdpURL:  cdpURL,
		revoked: nil,
	}, nil
}

// CACert returns the CA certificate.
func (ca *BuiltinCA) CACert(_ context.Context) *x509.Certificate {
	ca.mu.RLock()
	cert := ca.cert
	ca.mu.RUnlock()
	return cert
}

// GenerateCA implements CA. It generates a fresh root CA (wrapper around NewBuiltinCA).
// NOTE: this does NOT replace the active cert/key on the receiver. The returned PEMs
// must be persisted and the caller must reload via LoadBuiltinCA to activate the new CA.
func (ca *BuiltinCA) GenerateCA(_ context.Context, accountID string) (string, string, error) {
	return NewBuiltinCA(accountID)
}

// SignCSR validates csr, then issues and returns a signed *x509.Certificate.
// The certificate's CN is set to cn; a DNS SAN is derived from cn.
func (ca *BuiltinCA) SignCSR(_ context.Context, csr *x509.CertificateRequest, cn string, validityDays int) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("devicepki: generate certificate serial: %w", err)
	}

	ca.mu.RLock()
	cert := ca.cert
	key := ca.key
	cdpURL := ca.cdpURL
	ca.mu.RUnlock()

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{deviceSAN(cn)},
	}
	if cdpURL != "" {
		template.CRLDistributionPoints = []string{cdpURL}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, cert, csr.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("devicepki: sign certificate: %w", err)
	}

	return x509.ParseCertificate(der)
}

// RevokeCert adds the serial to the revocation list with the current timestamp. Idempotent.
func (ca *BuiltinCA) RevokeCert(_ context.Context, serial string) error {
	s, ok := new(big.Int).SetString(serial, 10)
	if !ok {
		return fmt.Errorf("devicepki: invalid serial number %q", serial)
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()

	for _, existing := range ca.revoked {
		if existing.serial.Cmp(s) == 0 {
			return nil // already revoked, idempotent
		}
	}
	ca.revoked = append(ca.revoked, revokedEntry{serial: s, revokedAt: time.Now().UTC()})
	return nil
}

// GenerateCRL builds and returns a fresh DER-encoded certificate revocation list.
func (ca *BuiltinCA) GenerateCRL(_ context.Context) ([]byte, error) {
	ca.mu.RLock()
	revokedCopy := make([]revokedEntry, len(ca.revoked))
	copy(revokedCopy, ca.revoked)
	cert := ca.cert
	key := ca.key
	ca.mu.RUnlock()

	now := time.Now().UTC()
	entries := make([]x509.RevocationListEntry, 0, len(revokedCopy))
	for _, e := range revokedCopy {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   e.serial,
			RevocationTime: e.revokedAt,
		})
	}

	template := &x509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now,
		NextUpdate:                now.Add(12 * time.Hour),
	}

	return x509.CreateRevocationList(rand.Reader, template, cert, key)
}

// Start spawns a background goroutine that regenerates the CRL every crlRefreshInterval
// (12 h) and calls onCRL with the fresh DER-encoded CRL bytes. It also calls onCRL
// immediately before entering the sleep loop so callers get an up-to-date CRL at startup.
//
// The goroutine exits when ctx is cancelled.
func (ca *BuiltinCA) Start(ctx context.Context, onCRL func([]byte)) {
	go func() {
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				crl, err := ca.GenerateCRL(ctx)
				if err != nil {
					log.Errorf("devicepki: CRL refresh failed: %v", err)
				} else if onCRL != nil {
					onCRL(crl)
				}
				timer.Reset(crlRefreshInterval)
			}
		}
	}()
}

// deviceSAN builds the DNS SAN for a device certificate.
// The WireGuard public key (base64) is hashed to SHA-256 and hex-encoded so that
// only [0-9a-f] characters appear in the DNS label, which is always DNS-safe.
// Format: netbird-device-<hex16>.internal
func deviceSAN(cn string) string {
	h := sha256.Sum256([]byte(cn))
	return "netbird-device-" + fmt.Sprintf("%x", h[:8]) + ".internal"
}
