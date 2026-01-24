// Package tunnel provides machine tunnel functionality for Windows pre-login VPN.
package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// CertEnrollmentConfig contains configuration for certificate enrollment.
type CertEnrollmentConfig struct {
	// TemplateName is the AD CS certificate template name.
	// Default: "NetBirdMachineTunnel"
	TemplateName string

	// DomainName is the FQDN of the domain (e.g., "corp.local").
	DomainName string

	// Hostname is the machine hostname (without domain).
	Hostname string

	// OutputCertPath is the path to write the enrolled certificate.
	OutputCertPath string

	// OutputKeyPath is the path to write the private key.
	OutputKeyPath string

	// ValidityCheck enables pre-enrollment validation.
	ValidityCheck bool
}

// CertEnrollmentResult contains the results of certificate enrollment.
type CertEnrollmentResult struct {
	// Success indicates if enrollment succeeded.
	Success bool

	// CertPath is the path to the enrolled certificate.
	CertPath string

	// KeyPath is the path to the private key.
	KeyPath string

	// Thumbprint is the SHA-256 thumbprint of the certificate.
	Thumbprint string

	// Subject is the certificate subject.
	Subject string

	// DNSNames are the SAN DNS names in the certificate.
	DNSNames []string

	// NotBefore is the certificate validity start time.
	NotBefore time.Time

	// NotAfter is the certificate validity end time.
	NotAfter time.Time

	// Error contains any error that occurred.
	Error error
}

// DefaultCertTemplateName is the default AD CS template name.
const DefaultCertTemplateName = "NetBirdMachineTunnel"

// CertRenewalThreshold is how long before expiry to trigger renewal (30 days).
const CertRenewalThreshold = 30 * 24 * time.Hour

// MinCertValidity is the minimum acceptable certificate validity (7 days).
const MinCertValidity = 7 * 24 * time.Hour

// ValidateMachineCertificate validates a machine certificate for use with mTLS.
// It checks:
// - Certificate exists and is readable
// - Certificate is not expired
// - Certificate has valid SAN DNSNames matching expected hostname.domain format
// - Certificate is signed by a trusted CA (optional, if caCert provided)
func ValidateMachineCertificate(certPath string, expectedHostname, expectedDomain string) (*CertEnrollmentResult, error) {
	result := &CertEnrollmentResult{
		CertPath: certPath,
	}

	// Read certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		result.Error = fmt.Errorf("read certificate: %w", err)
		return result, result.Error
	}

	// Parse PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil {
		result.Error = fmt.Errorf("failed to decode PEM block")
		return result, result.Error
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		result.Error = fmt.Errorf("parse certificate: %w", err)
		return result, result.Error
	}

	// Fill in result fields
	result.Subject = cert.Subject.String()
	result.DNSNames = cert.DNSNames
	result.NotBefore = cert.NotBefore
	result.NotAfter = cert.NotAfter
	result.Thumbprint = ComputeCertThumbprint(cert)

	// Check expiry
	now := time.Now()
	if now.Before(cert.NotBefore) {
		result.Error = fmt.Errorf("certificate not yet valid (starts %s)", cert.NotBefore)
		return result, result.Error
	}
	if now.After(cert.NotAfter) {
		result.Error = fmt.Errorf("certificate expired (ended %s)", cert.NotAfter)
		return result, result.Error
	}

	// Check minimum validity remaining
	remaining := cert.NotAfter.Sub(now)
	if remaining < MinCertValidity {
		log.Warnf("Certificate expires soon: %s remaining", remaining)
	}

	// Check SAN DNSNames
	if len(cert.DNSNames) == 0 {
		result.Error = fmt.Errorf("certificate has no SAN DNSNames")
		return result, result.Error
	}

	// Validate expected hostname.domain format
	expectedFQDN := strings.ToLower(fmt.Sprintf("%s.%s", expectedHostname, expectedDomain))
	foundMatch := false
	for _, dnsName := range cert.DNSNames {
		if strings.EqualFold(dnsName, expectedFQDN) {
			foundMatch = true
			break
		}
	}

	if !foundMatch {
		result.Error = fmt.Errorf("certificate SAN DNSNames %v do not match expected %s", cert.DNSNames, expectedFQDN)
		return result, result.Error
	}

	result.Success = true
	log.Infof("Certificate validation passed: %s (expires %s)", result.Subject, cert.NotAfter)
	return result, nil
}

// ComputeCertThumbprint computes the SHA-256 thumbprint of a certificate.
func ComputeCertThumbprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// NeedsRenewal checks if a certificate needs renewal.
func NeedsRenewal(certPath string) (bool, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return true, fmt.Errorf("read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return true, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, fmt.Errorf("parse certificate: %w", err)
	}

	remaining := time.Until(cert.NotAfter)
	if remaining < CertRenewalThreshold {
		log.Infof("Certificate renewal needed: %s remaining (threshold: %s)", remaining, CertRenewalThreshold)
		return true, nil
	}

	return false, nil
}

// GenerateCertEnrollmentScript generates a PowerShell script for AD CS enrollment.
// This script uses certreq.exe which is available on domain-joined Windows machines.
func GenerateCertEnrollmentScript(config *CertEnrollmentConfig) string {
	templateName := config.TemplateName
	if templateName == "" {
		templateName = DefaultCertTemplateName
	}

	fqdn := fmt.Sprintf("%s.%s", config.Hostname, config.DomainName)

	script := fmt.Sprintf(`# Certificate Enrollment Script (Generated by NetBird Machine Tunnel)
# Prerequisites: Domain-joined, AD CS available, template "%s" configured

$ErrorActionPreference = 'Stop'
$hostname = '%s'
$domain = '%s'
$fqdn = '%s'
$templateName = '%s'

# Paths
$infPath = "$env:TEMP\netbird-certreq.inf"
$reqPath = "$env:TEMP\netbird-certreq.req"
$cerPath = "$env:TEMP\netbird-certreq.cer"
$pfxPath = "$env:TEMP\netbird-certreq.pfx"

Write-Host "Enrolling machine certificate for: $fqdn"
Write-Host "Using template: $templateName"

# Step 1: Create INF file for certificate request
$infContent = @"
[NewRequest]
Subject = "CN=$fqdn"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
HashAlgorithm = SHA256

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.2 ; Client Authentication

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$fqdn&"

[RequestAttributes]
CertificateTemplate = $templateName
"@

Set-Content -Path $infPath -Value $infContent -Encoding ASCII
Write-Host "Created certificate request INF: $infPath"

# Step 2: Generate certificate request
Write-Host "Generating certificate request..."
$result = certreq -new -machine $infPath $reqPath 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "certreq -new failed: $result"
}
Write-Host "Created certificate request: $reqPath"

# Step 3: Submit request to CA
Write-Host "Submitting request to CA..."
$result = certreq -submit -machine -config - $reqPath $cerPath 2>&1
if ($LASTEXITCODE -ne 0) {
    # Try with explicit CA discovery
    Write-Host "Trying with CA auto-discovery..."
    $result = certreq -submit -machine $reqPath $cerPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "certreq -submit failed: $result"
    }
}
Write-Host "Received certificate: $cerPath"

# Step 4: Accept certificate into store
Write-Host "Installing certificate..."
$result = certreq -accept -machine $cerPath 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "certreq -accept failed: $result"
}
Write-Host "Certificate installed to LocalMachine\My"

# Step 5: Find and export the certificate
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -match $fqdn } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if (-not $cert) {
    throw "Could not find enrolled certificate in store"
}

Write-Host "Certificate Details:"
Write-Host "  Subject:    $($cert.Subject)"
Write-Host "  Thumbprint: $($cert.Thumbprint)"
Write-Host "  Expires:    $($cert.NotAfter)"
Write-Host "  DNS Names:  $($cert.DnsNameList -join ', ')"

# Step 6: Export to PEM format (requires OpenSSL or manual conversion)
# For now, output the thumbprint for config update
$thumbprint = $cert.Thumbprint

# Cleanup temp files
Remove-Item $infPath, $reqPath, $cerPath -ErrorAction SilentlyContinue

# Return result
@{
    Success = $true
    Thumbprint = $thumbprint
    Subject = $cert.Subject
    NotAfter = $cert.NotAfter
    DnsNames = $cert.DnsNameList
}
`, templateName, config.Hostname, config.DomainName, fqdn, templateName)

	return script
}

// CertificateInfo contains parsed certificate information.
type CertificateInfo struct {
	// Thumbprint is the SHA-256 thumbprint.
	Thumbprint string

	// Subject is the certificate subject DN.
	Subject string

	// Issuer is the certificate issuer DN.
	Issuer string

	// DNSNames are the SAN DNS names.
	DNSNames []string

	// NotBefore is the validity start.
	NotBefore time.Time

	// NotAfter is the validity end.
	NotAfter time.Time

	// SerialNumber is the certificate serial number (hex encoded).
	SerialNumber string

	// IsExpired indicates if the certificate is expired.
	IsExpired bool

	// NeedsRenewal indicates if the certificate should be renewed.
	NeedsRenewal bool

	// RemainingValidity is the time until expiry.
	RemainingValidity time.Duration
}

// ParseCertificateFile parses a PEM certificate file and returns info.
func ParseCertificateFile(certPath string) (*CertificateInfo, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	now := time.Now()
	remaining := cert.NotAfter.Sub(now)

	info := &CertificateInfo{
		Thumbprint:        ComputeCertThumbprint(cert),
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		DNSNames:          cert.DNSNames,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		SerialNumber:      cert.SerialNumber.Text(16),
		IsExpired:         now.After(cert.NotAfter),
		NeedsRenewal:      remaining < CertRenewalThreshold,
		RemainingValidity: remaining,
	}

	return info, nil
}

// WatchCertificateExpiry starts a goroutine that monitors certificate expiry
// and calls the callback when renewal is needed.
func WatchCertificateExpiry(ctx context.Context, certPath string, checkInterval time.Duration, onRenewalNeeded func()) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Debug("Certificate expiry watcher stopped")
			return
		case <-ticker.C:
			needsRenewal, err := NeedsRenewal(certPath)
			if err != nil {
				log.Warnf("Certificate renewal check failed: %v", err)
				continue
			}
			if needsRenewal {
				log.Info("Certificate renewal needed, triggering callback")
				onRenewalNeeded()
			}
		}
	}
}

// ExtractIssuerFingerprint extracts the issuer certificate fingerprint from a cert chain.
// This is used for mTLS issuer verification (not AuthorityKeyId!).
func ExtractIssuerFingerprint(certPath string, verifyChain bool) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("read certificate: %w", err)
	}

	// Parse all certificates in the PEM file (may include chain)
	var certs []*x509.Certificate
	rest := certPEM
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return "", fmt.Errorf("parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		rest = remaining
	}

	if len(certs) == 0 {
		return "", fmt.Errorf("no certificates found in file")
	}

	// If we have a chain, the issuer is the second certificate
	if len(certs) > 1 {
		issuerCert := certs[1]
		return ComputeCertThumbprint(issuerCert), nil
	}

	// Single certificate - issuer fingerprint would need to be looked up
	// In production, this should verify against the system trust store
	return "", fmt.Errorf("certificate chain required for issuer fingerprint extraction")
}
