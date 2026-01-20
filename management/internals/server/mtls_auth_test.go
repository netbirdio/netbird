package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// TestExtractMTLSIdentity tests the identity extraction from a mocked TLS connection.
func TestExtractMTLSIdentity(t *testing.T) {
	// Find test certs relative to this file
	certDir := filepath.Join("..", "..", "..", "test", "certs")

	clientCertPEM, err := os.ReadFile(filepath.Join(certDir, "client.crt"))
	if err != nil {
		t.Skipf("Test certs not found (run from repo root): %v", err)
	}

	caCertPEM, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		t.Fatalf("Failed to read CA cert: %v", err)
	}

	// Parse client certificate
	clientCert, err := parseCertificatePEM(clientCertPEM)
	if err != nil {
		t.Fatalf("Failed to parse client cert: %v", err)
	}

	// Parse CA certificate
	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		t.Fatalf("Failed to parse CA cert: %v", err)
	}

	// Create a mock peer context with TLS info
	// VerifiedChains[0] = [clientCert, caCert]
	tlsState := tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{
			{clientCert, caCert},
		},
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	tlsInfo := credentials.TLSInfo{State: tlsState}
	peerInfo := &peer.Peer{
		Addr:     &net.IPAddr{IP: net.ParseIP("127.0.0.1")},
		AuthInfo: tlsInfo,
	}

	ctx := peer.NewContext(context.Background(), peerInfo)

	// Test extraction
	identity, err := extractMTLSIdentity(ctx)
	if err != nil {
		t.Fatalf("extractMTLSIdentity failed: %v", err)
	}

	// Verify expected values
	t.Logf("Extracted identity: %+v", identity)

	if identity.DNSName != "win10-pc.corp.local" {
		t.Errorf("Expected DNSName 'win10-pc.corp.local', got '%s'", identity.DNSName)
	}
	if identity.Hostname != "win10-pc" {
		t.Errorf("Expected Hostname 'win10-pc', got '%s'", identity.Hostname)
	}
	if identity.Domain != "corp.local" {
		t.Errorf("Expected Domain 'corp.local', got '%s'", identity.Domain)
	}
	if identity.SerialNumber == "" {
		t.Error("Expected SerialNumber to be set")
	}

	// Verify issuer fingerprint matches CA cert
	expectedFP := fmt.Sprintf("%x", sha256.Sum256(caCert.Raw))
	if identity.IssuerFingerprint != expectedFP {
		t.Errorf("IssuerFingerprint mismatch.\nExpected: %s\nGot: %s", expectedFP, identity.IssuerFingerprint)
	}

	t.Logf("✅ mTLS Identity extraction VERIFIED:")
	t.Logf("   DNSName: %s", identity.DNSName)
	t.Logf("   Hostname: %s", identity.Hostname)
	t.Logf("   Domain: %s", identity.Domain)
	t.Logf("   IssuerFP: %s...", identity.IssuerFingerprint[:16])
	t.Logf("   Serial: %s", identity.SerialNumber)
}

// TestExtractMTLSIdentityNoCert tests that missing cert returns error.
func TestExtractMTLSIdentityNoCert(t *testing.T) {
	// Empty TLS state (no client cert)
	tlsState := tls.ConnectionState{
		VerifiedChains: nil,
	}

	tlsInfo := credentials.TLSInfo{State: tlsState}
	peerInfo := &peer.Peer{
		Addr:     &net.IPAddr{IP: net.ParseIP("127.0.0.1")},
		AuthInfo: tlsInfo,
	}

	ctx := peer.NewContext(context.Background(), peerInfo)

	_, err := extractMTLSIdentity(ctx)
	if err == nil {
		t.Error("Expected error for missing certificate, got nil")
	}
	t.Logf("✅ Correctly rejected request without cert: %v", err)
}

// TestExtractMTLSIdentityNoSAN tests that cert without SAN DNSName is rejected.
func TestExtractMTLSIdentityNoSAN(t *testing.T) {
	// Create a minimal cert without SAN (CN only)
	cert := &x509.Certificate{
		DNSNames: []string{}, // Empty SAN
	}

	tlsState := tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{
			{cert},
		},
	}

	tlsInfo := credentials.TLSInfo{State: tlsState}
	peerInfo := &peer.Peer{
		Addr:     &net.IPAddr{IP: net.ParseIP("127.0.0.1")},
		AuthInfo: tlsInfo,
	}

	ctx := peer.NewContext(context.Background(), peerInfo)

	_, err := extractMTLSIdentity(ctx)
	if err == nil {
		t.Error("Expected error for cert without SAN DNSName")
	}
	t.Logf("✅ Correctly rejected cert without SAN: %v", err)
}

// TestSplitDNSName tests the FQDN splitting function.
func TestSplitDNSName(t *testing.T) {
	tests := []struct {
		input    string
		hostname string
		domain   string
		wantErr  bool
	}{
		{"win10-pc.corp.local", "win10-pc", "corp.local", false},
		{"server01.subdomain.example.com", "server01", "subdomain.example.com", false},
		{"host.a.b.c.d", "host", "a.b.c.d", false},
		{"nodotshere", "", "", true},
		{"", "", "", true},
	}

	for _, tt := range tests {
		hostname, domain, err := splitDNSName(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("splitDNSName(%q): expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitDNSName(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if hostname != tt.hostname || domain != tt.domain {
			t.Errorf("splitDNSName(%q) = (%q, %q), want (%q, %q)",
				tt.input, hostname, domain, tt.hostname, tt.domain)
		}
	}
}

// TestDecodeOID tests OID decoding.
func TestDecodeOID(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "Microsoft Template OID",
			input:    []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x02, 0x04, 0x05, 0x07}, // 2.16.840.1.101.2.4.5.7 (example)
			expected: "2.16.840.1.101.2.4.5.7",
		},
		{
			name:     "Simple OID",
			input:    []byte{0x55, 0x04, 0x03}, // 2.5.4.3 (CN)
			expected: "2.5.4.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodeOID(tt.input)
			if result != tt.expected {
				t.Errorf("decodeOID() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Helper to parse PEM certificate
func parseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// TestDecodeASN1String tests ASN.1 string decoding including BMPString.
func TestDecodeASN1String(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "UTF8String - Machine",
			input:    []byte{0x0C, 0x07, 'M', 'a', 'c', 'h', 'i', 'n', 'e'}, // tag=12, len=7
			expected: "Machine",
		},
		{
			name:     "PrintableString - Computer",
			input:    []byte{0x13, 0x08, 'C', 'o', 'm', 'p', 'u', 't', 'e', 'r'}, // tag=19, len=8
			expected: "Computer",
		},
		{
			name: "BMPString - Machine (UTF-16BE)",
			// BMPString tag=30, len=14 (7 chars * 2 bytes)
			// "Machine" in UTF-16BE: 0x004D 0x0061 0x0063 0x0068 0x0069 0x006E 0x0065
			input:    []byte{0x1E, 0x0E, 0x00, 'M', 0x00, 'a', 0x00, 'c', 0x00, 'h', 0x00, 'i', 0x00, 'n', 0x00, 'e'},
			expected: "Machine",
		},
		{
			name: "BMPString - NetBirdMachine",
			// "NetBirdMachine" = 14 chars * 2 bytes = 28 bytes (0x1C)
			input: []byte{
				0x1E, 0x1C, // BMPString, length=28
				0x00, 'N', 0x00, 'e', 0x00, 't', 0x00, 'B',
				0x00, 'i', 0x00, 'r', 0x00, 'd', 0x00, 'M',
				0x00, 'a', 0x00, 'c', 0x00, 'h', 0x00, 'i',
				0x00, 'n', 0x00, 'e',
			},
			expected: "NetBirdMachine",
		},
		{
			name:     "IA5String",
			input:    []byte{0x16, 0x04, 'T', 'e', 's', 't'}, // tag=22, len=4
			expected: "Test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodeASN1String(tt.input)
			if result != tt.expected {
				t.Errorf("decodeASN1String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestDecodeBMPString tests UTF-16BE decoding specifically.
func TestDecodeBMPString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "Simple ASCII in UTF-16BE",
			input:    []byte{0x00, 'H', 0x00, 'i'},
			expected: "Hi",
		},
		{
			name:     "Machine in UTF-16BE",
			input:    []byte{0x00, 'M', 0x00, 'a', 0x00, 'c', 0x00, 'h', 0x00, 'i', 0x00, 'n', 0x00, 'e'},
			expected: "Machine",
		},
		{
			name:     "Empty",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "With null terminators",
			input:    []byte{0x00, 'A', 0x00, 0x00, 0x00, 'B'}, // A, null, B
			expected: "AB",                                     // nulls stripped
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodeBMPString(tt.input)
			if result != tt.expected {
				t.Errorf("decodeBMPString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestDeterminePeerType tests peer type determination logic.
func TestDeterminePeerType(t *testing.T) {
	tests := []struct {
		name         string
		templateOID  string
		templateName string
		cert         *x509.Certificate
		expected     string
	}{
		{
			name:         "Machine template by name",
			templateOID:  "",
			templateName: "Machine",
			cert:         &x509.Certificate{},
			expected:     "machine",
		},
		{
			name:         "Machine template case insensitive",
			templateOID:  "",
			templateName: "MACHINE",
			cert:         &x509.Certificate{},
			expected:     "machine",
		},
		{
			name:         "Computer template",
			templateOID:  "",
			templateName: "Computer",
			cert:         &x509.Certificate{},
			expected:     "machine",
		},
		{
			name:         "NetBirdMachine custom template",
			templateOID:  "",
			templateName: "NetBirdMachine",
			cert:         &x509.Certificate{},
			expected:     "machine",
		},
		{
			name:         "User template by name",
			templateOID:  "",
			templateName: "User",
			cert:         &x509.Certificate{},
			expected:     "user",
		},
		{
			name:         "SmartCardLogon template",
			templateOID:  "",
			templateName: "SmartCardLogon",
			cert:         &x509.Certificate{},
			expected:     "user",
		},
		{
			name:         "Unknown template - has DNS but no email",
			templateOID:  "",
			templateName: "CustomTemplate",
			cert:         &x509.Certificate{DNSNames: []string{"host.domain.local"}},
			expected:     "machine",
		},
		{
			name:         "Unknown template - has email",
			templateOID:  "",
			templateName: "CustomTemplate",
			cert:         &x509.Certificate{EmailAddresses: []string{"user@domain.local"}},
			expected:     "user",
		},
		{
			name:         "No template - only ClientAuth EKU",
			templateOID:  "",
			templateName: "",
			cert:         &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
			expected:     "machine",
		},
		{
			name:         "No template - ClientAuth + Email",
			templateOID:  "",
			templateName: "",
			cert: &x509.Certificate{
				ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				EmailAddresses: []string{"user@example.com"},
			},
			expected: "user",
		},
		{
			name:         "Completely empty",
			templateOID:  "",
			templateName: "",
			cert:         &x509.Certificate{},
			expected:     "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determinePeerType(tt.templateOID, tt.templateName, tt.cert)
			if result != tt.expected {
				t.Errorf("determinePeerType() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestExtractTemplateNameV1 tests v1 template name extraction.
func TestExtractTemplateNameV1(t *testing.T) {
	// Create a certificate with v1 template extension (OID 1.3.6.1.4.1.311.20.2)
	// containing "Machine" as UTF8String
	cert := &x509.Certificate{
		Extensions: []pkix.Extension{
			{
				Id:       []int{1, 3, 6, 1, 4, 1, 311, 20, 2}, // szOID_ENROLL_CERTTYPE_EXTENSION
				Critical: false,
				Value:    []byte{0x0C, 0x07, 'M', 'a', 'c', 'h', 'i', 'n', 'e'}, // UTF8String "Machine"
			},
		},
	}

	result := extractTemplateNameV1(cert)
	if result != "Machine" {
		t.Errorf("extractTemplateNameV1() = %q, want %q", result, "Machine")
	}

	// Test with BMPString encoding
	certBMP := &x509.Certificate{
		Extensions: []pkix.Extension{
			{
				Id:       []int{1, 3, 6, 1, 4, 1, 311, 20, 2},
				Critical: false,
				Value:    []byte{0x1E, 0x0E, 0x00, 'M', 0x00, 'a', 0x00, 'c', 0x00, 'h', 0x00, 'i', 0x00, 'n', 0x00, 'e'},
			},
		},
	}

	resultBMP := extractTemplateNameV1(certBMP)
	if resultBMP != "Machine" {
		t.Errorf("extractTemplateNameV1() with BMPString = %q, want %q", resultBMP, "Machine")
	}

	// Test without v1 extension
	certNoExt := &x509.Certificate{}
	resultNoExt := extractTemplateNameV1(certNoExt)
	if resultNoExt != "" {
		t.Errorf("extractTemplateNameV1() without extension = %q, want empty", resultNoExt)
	}
}
