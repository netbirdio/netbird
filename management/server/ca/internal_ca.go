package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// SigningTypeInternal is the identifier for the internal CA signer.
	SigningTypeInternal = "internal"

	// DefaultCAValidity is the default validity period for a root CA certificate.
	DefaultCAValidity = 10 * 365 * 24 * time.Hour

	// defaultCertValidity is the default validity for issued peer certificates.
	defaultCertValidity = 90 * 24 * time.Hour

	// defaultCAOrganization is the fallback organization when none is provided.
	defaultCAOrganization = "NetBird Self-Hosted"
)

// CAOptions configures the generated CA certificate's subject and validity.
type CAOptions struct {
	// DisplayName is used in the CA common name (e.g. "Zakhar" → "Zakhar Internal CA").
	// Falls back to the DNS domain if empty.
	DisplayName string

	// Organization is the x509 Organization field. Falls back to "NetBird Self-Hosted".
	Organization string

	// Validity overrides the CA certificate lifetime. Falls back to DefaultCAValidity (10 years).
	Validity time.Duration
}

// InternalCASigner signs CSRs using an internally managed root CA.
// The root CA is an ECDSA P-256 self-signed certificate with x509 NameConstraints
// limiting issuance to the account's DNS domain.
type InternalCASigner struct {
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	caID     string
	validity time.Duration
}

// NewInternalCASigner creates a signer from an existing CA certificate and private key in PEM format.
// validity controls how long issued peer certificates are valid.
func NewInternalCASigner(certPEM, keyPEM []byte, caID string, validity time.Duration) (*InternalCASigner, error) {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	key, err := parseECPrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA private key: %w", err)
	}

	if validity <= 0 {
		validity = defaultCertValidity
	}

	return &InternalCASigner{
		caCert:   cert,
		caKey:    key,
		caID:     caID,
		validity: validity,
	}, nil
}

// Sign signs the given CSR and returns the issued certificate and CA chain in PEM format.
// It validates that the CSR's DNS names match the expected peer FQDN and optionally adds
// a wildcard SAN.
func (s *InternalCASigner) Sign(ctx context.Context, csr *x509.CertificateRequest, peerFQDN string, wildcard bool) (*SigningResult, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	if err := s.validateCSRNames(csr, peerFQDN, wildcard); err != nil {
		return nil, err
	}

	dnsNames := []string{peerFQDN}
	if wildcard {
		dnsNames = append(dnsNames, "*."+peerFQDN)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: peerFQDN,
		},
		DNSNames:  dnsNames,
		NotBefore: now,
		NotAfter:  now.Add(s.validity),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw})

	log.WithContext(ctx).Debugf("signed certificate for %s (serial: %s, wildcard: %v)", peerFQDN, serialNumber.Text(16), wildcard)

	return &SigningResult{
		CertPEM:  certPEM,
		ChainPEM: chainPEM,
	}, nil
}

// Type returns the signer type identifier.
func (s *InternalCASigner) Type() string {
	return SigningTypeInternal
}

// CAID returns the CA certificate ID used by this signer.
func (s *InternalCASigner) CAID() string {
	return s.caID
}

// SerialNumberFromResult parses the serial number from a signed certificate PEM.
func SerialNumberFromResult(certPEM []byte) (string, error) {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return "", fmt.Errorf("parse issued certificate: %w", err)
	}
	return cert.SerialNumber.Text(16), nil
}

// NotAfterFromResult parses the NotAfter timestamp from a signed certificate PEM.
func NotAfterFromResult(certPEM []byte) (time.Time, error) {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse issued certificate: %w", err)
	}
	return cert.NotAfter, nil
}

// GenerateCA creates a new ECDSA P-256 self-signed root CA certificate with
// NameConstraints limiting issuance to the given DNS domain.
// Returns the certificate and key in PEM format, and the SHA-256 fingerprint.
func GenerateCA(dnsDomain string, opts CAOptions) (certPEM, keyPEM []byte, fingerprint string, err error) {
	if dnsDomain == "" {
		return nil, nil, "", fmt.Errorf("dnsDomain is required for CA generation")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate CA key: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate serial number: %w", err)
	}

	// Generate a short unique suffix from the serial number for default names.
	// This helps distinguish multiple CA instances on the same domain.
	suffix := fmt.Sprintf("%06x", serialNumber.Bytes()[:3])

	var cn string
	if opts.DisplayName != "" {
		cn = opts.DisplayName + " Internal CA"
	} else {
		cn = fmt.Sprintf("%s Internal CA (%s)", dnsDomain, suffix)
	}

	org := defaultCAOrganization
	if opts.Organization != "" {
		org = opts.Organization
	}

	validity := DefaultCAValidity
	if opts.Validity > 0 {
		validity = opts.Validity
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
		},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		PermittedDNSDomains:   []string{"." + dnsDomain, dnsDomain},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", fmt.Errorf("create CA certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, "", fmt.Errorf("marshal CA private key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	hash := sha256.Sum256(certDER)
	fingerprint = hex.EncodeToString(hash[:])

	return certPEM, keyPEM, fingerprint, nil
}

// Fingerprint computes the SHA-256 fingerprint of a PEM-encoded certificate.
func Fingerprint(certPEM []byte) (string, error) {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return "", fmt.Errorf("parse certificate for fingerprint: %w", err)
	}
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:]), nil
}

// validateCSRNames checks that the CSR DNS names match the expected FQDN.
func (s *InternalCASigner) validateCSRNames(csr *x509.CertificateRequest, peerFQDN string, wildcard bool) error {
	if len(csr.DNSNames) == 0 {
		return fmt.Errorf("CSR must contain at least one DNS name")
	}

	expectedNames := map[string]bool{peerFQDN: true}
	if wildcard {
		expectedNames["*."+peerFQDN] = true
	}

	for _, name := range csr.DNSNames {
		if !expectedNames[strings.ToLower(name)] {
			return fmt.Errorf("CSR contains unexpected DNS name %q, expected %v", name, peerFQDN)
		}
	}

	if !containsName(csr.DNSNames, peerFQDN) {
		return fmt.Errorf("CSR must contain the peer FQDN %q", peerFQDN)
	}

	return nil
}

func containsName(names []string, target string) bool {
	for _, n := range names {
		if strings.EqualFold(n, target) {
			return true
		}
	}
	return false
}

func generateSerialNumber() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("generate random serial: %w", err)
	}
	return serial, nil
}

func parseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM certificate block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseECPrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM EC private key block")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
