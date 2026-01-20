//go:build windows

// SAN/Template Parsing Spike - T-1.3
// Tests whether Go can parse SAN DNSName and Template OID/Name from AD CS certificates.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ASN.1 Tags for string types
const (
	tagUTF8String      = 12 // 0x0C
	tagPrintableString = 19 // 0x13
	tagIA5String       = 22 // 0x16
	tagBMPString       = 30 // 0x1E - UTF-16BE!
)

// Certificate Template OIDs (AD CS)
var (
	// szOID_CERTIFICATE_TEMPLATE (v2 Templates): contains OID + Version
	OIDCertificateTemplateV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 7}

	// szOID_ENROLL_CERTTYPE_EXTENSION (v1 Templates): contains Template NAME as String!
	OIDCertificateTemplateNameV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}

	// Known Machine Template Names (case-insensitive)
	DefaultMachineTemplateNames = []string{
		"Machine", "Computer", "Workstation",
		"NetBirdMachine", "DomainController",
	}
)

// TemplateInfo holds parsed template information
type TemplateInfo struct {
	OID     string // Template OID from v2 extension
	Name    string // Template Name from v1 extension
	Version int    // Template Version from v2 extension
}

// MTLSIdentity holds extracted certificate information
type MTLSIdentity struct {
	// Primary Identity: SAN DNSName (NOT CN!)
	DNSName  string // e.g. "win10-pc.corp.local"
	Hostname string // e.g. "win10-pc" (first part)
	Domain   string // e.g. "corp.local" (rest)

	// Validation
	IssuerDN     string // Issuer Distinguished Name
	IssuerFP     string // SHA-256 Fingerprint
	TemplateOID  string // Certificate Template OID
	TemplateName string // Template Name from extension
	CertSerial   string // For audit/logging

	PeerType string // "machine" | "user" | "unknown"
}

func main() {
	fmt.Println("=== SAN/Template Parsing Spike (T-1.3) ===")
	fmt.Println("Tests SAN DNSName + Template OID/Name extraction from AD CS certs")
	fmt.Println()

	// Search subject (default: DC01)
	searchSubject := "DC01"
	if len(os.Args) > 1 {
		searchSubject = os.Args[1]
	}

	// Test 1: Open LocalMachine Certificate Store
	fmt.Println("[1] Opening LocalMachine\\My certificate store...")
	store, err := openCertStore("MY", windows.CERT_SYSTEM_STORE_LOCAL_MACHINE)
	if err != nil {
		log.Fatalf("Failed to open cert store: %v", err)
	}
	defer windows.CertCloseStore(store, 0)
	fmt.Println("    Store opened successfully")
	fmt.Println()

	// Test 2: Find certificate
	fmt.Printf("[2] Searching for certificate containing '%s'...\n", searchSubject)
	cert, err := findCertBySubject(store, searchSubject)
	if err != nil {
		log.Fatalf("Failed to find certificate: %v", err)
	}
	fmt.Printf("    Found: CN=%s\n", cert.Subject.CommonName)
	fmt.Println()

	// Test 3: Extract SAN DNSNames
	fmt.Println("[3] Extracting SAN DNSNames...")
	if len(cert.DNSNames) == 0 {
		fmt.Println("    WARNING: No SAN DNSNames found!")
		fmt.Println("    This certificate cannot be used for mTLS (SAN required)")
	} else {
		for i, dns := range cert.DNSNames {
			fmt.Printf("    [%d] %s\n", i+1, dns)
		}
		fmt.Printf("    Total SAN DNSNames: %d\n", len(cert.DNSNames))
	}
	fmt.Println()

	// Test 4: Parse Template Extensions
	fmt.Println("[4] Parsing Certificate Template Extensions...")
	tmplInfo := extractTemplateInfo(cert)
	if tmplInfo.OID != "" {
		fmt.Printf("    Template OID (v2): %s\n", tmplInfo.OID)
		if tmplInfo.Version > 0 {
			fmt.Printf("    Template Version: %d\n", tmplInfo.Version)
		}
	} else {
		fmt.Println("    Template OID (v2): Not found")
	}
	if tmplInfo.Name != "" {
		fmt.Printf("    Template Name (v1): %s\n", tmplInfo.Name)
	} else {
		fmt.Println("    Template Name (v1): Not found")
	}
	fmt.Println()

	// Test 5: Determine Peer Type
	fmt.Println("[5] Determining Peer Type...")
	peerType := determinePeerType(cert, tmplInfo)
	fmt.Printf("    Peer Type: %s\n", peerType)
	fmt.Println()

	// Test 6: Build MTLSIdentity
	fmt.Println("[6] Building MTLSIdentity struct...")
	identity := buildMTLSIdentity(cert, tmplInfo)
	fmt.Printf("    DNSName:      %s\n", identity.DNSName)
	fmt.Printf("    Hostname:     %s\n", identity.Hostname)
	fmt.Printf("    Domain:       %s\n", identity.Domain)
	fmt.Printf("    IssuerDN:     %s\n", identity.IssuerDN)
	fmt.Printf("    IssuerFP:     %s\n", identity.IssuerFP)
	fmt.Printf("    TemplateOID:  %s\n", identity.TemplateOID)
	fmt.Printf("    TemplateName: %s\n", identity.TemplateName)
	fmt.Printf("    CertSerial:   %s\n", identity.CertSerial)
	fmt.Printf("    PeerType:     %s\n", identity.PeerType)
	fmt.Println()

	// Test 7: Verify all extensions are accessible
	fmt.Println("[7] Listing all certificate extensions...")
	for i, ext := range cert.Extensions {
		critical := ""
		if ext.Critical {
			critical = " [CRITICAL]"
		}
		fmt.Printf("    [%d] OID: %s%s\n", i+1, ext.Id.String(), critical)
	}
	fmt.Printf("    Total extensions: %d\n", len(cert.Extensions))
	fmt.Println()

	// Test 8: Test ASN.1 String Decoding (BMPString)
	fmt.Println("[8] Testing ASN.1 String Decoding...")

	// UTF8String test
	utf8Test := []byte{0x0C, 0x07, 'M', 'a', 'c', 'h', 'i', 'n', 'e'}
	utf8Result := decodeASN1String(utf8Test)
	fmt.Printf("    UTF8String test: 'Machine' -> '%s' %s\n", utf8Result, checkMark(utf8Result == "Machine"))

	// BMPString test (UTF-16BE: "Test")
	bmpTest := []byte{0x1E, 0x08, 0x00, 'T', 0x00, 'e', 0x00, 's', 0x00, 't'}
	bmpResult := decodeASN1String(bmpTest)
	fmt.Printf("    BMPString test:  'Test' -> '%s' %s\n", bmpResult, checkMark(bmpResult == "Test"))

	// PrintableString test
	printableTest := []byte{0x13, 0x05, 'H', 'e', 'l', 'l', 'o'}
	printableResult := decodeASN1String(printableTest)
	fmt.Printf("    PrintableString: 'Hello' -> '%s' %s\n", printableResult, checkMark(printableResult == "Hello"))
	fmt.Println()

	// Summary
	fmt.Println("=== SPIKE RESULT ===")
	fmt.Println()

	allPassed := true
	checks := []struct {
		name   string
		passed bool
	}{
		{"SAN DNSName extracted", len(cert.DNSNames) > 0},
		{"Template Info available", tmplInfo.OID != "" || tmplInfo.Name != ""},
		{"Peer Type determined", peerType != "unknown"},
		{"Identity built", identity.DNSName != ""},
		{"ASN.1 UTF8String", utf8Result == "Machine"},
		{"ASN.1 BMPString", bmpResult == "Test"},
	}

	for _, c := range checks {
		if c.passed {
			fmt.Printf("  [PASS] %s\n", c.name)
		} else {
			fmt.Printf("  [FAIL] %s\n", c.name)
			allPassed = false
		}
	}

	fmt.Println()
	if allPassed {
		fmt.Println("All checks passed! Go crypto/x509 can parse AD CS certificates.")
		fmt.Println()
		fmt.Println("Key findings:")
		fmt.Printf("  - SAN DNSName: %s\n", identity.DNSName)
		fmt.Printf("  - Template: %s (%s)\n", identity.TemplateName, identity.TemplateOID)
		fmt.Printf("  - Peer Type: %s\n", identity.PeerType)
		fmt.Println()
		fmt.Println("Recommendation: Proceed with mTLS implementation using SAN DNSName")
	} else {
		fmt.Println("Some checks failed. Review certificate configuration.")
	}
}

func checkMark(ok bool) string {
	if ok {
		return "[OK]"
	}
	return "[FAIL]"
}

func openCertStore(storeName string, storeLocation uint32) (windows.Handle, error) {
	storePtr, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return 0, err
	}
	return windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		uintptr(0),
		storeLocation,
		uintptr(unsafe.Pointer(storePtr)),
	)
}

func findCertBySubject(store windows.Handle, subject string) (*x509.Certificate, error) {
	var prevCtx *windows.CertContext

	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prevCtx)
		if err != nil {
			break
		}

		encodedCert := unsafe.Slice(ctx.EncodedCert, ctx.Length)
		buf := bytes.Clone(encodedCert)
		cert, err := x509.ParseCertificate(buf)
		if err != nil {
			prevCtx = ctx
			continue
		}

		if strings.Contains(cert.Subject.CommonName, subject) {
			// Found it - duplicate context to keep it valid
			_ = windows.CertDuplicateCertificateContext(ctx)
			return cert, nil
		}
		prevCtx = ctx
	}

	return nil, fmt.Errorf("certificate containing '%s' not found", subject)
}

// extractTemplateInfo extracts Template OID and Name from certificate extensions
func extractTemplateInfo(cert *x509.Certificate) TemplateInfo {
	var info TemplateInfo

	for _, ext := range cert.Extensions {
		// v2 Extension: contains Template OID + Version
		if ext.Id.Equal(OIDCertificateTemplateV2) {
			var templateData struct {
				TemplateID asn1.ObjectIdentifier
				Major      int `asn1:"optional"`
				Minor      int `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &templateData); err == nil {
				info.OID = templateData.TemplateID.String()
				info.Version = templateData.Major
			}
		}

		// v1 Extension: contains Template NAME as BMPString/UTF8String
		if ext.Id.Equal(OIDCertificateTemplateNameV1) {
			info.Name = decodeASN1String(ext.Value)
		}
	}
	return info
}

// decodeASN1String decodes ASN.1 encoded strings (UTF8, BMP, Printable, IA5)
func decodeASN1String(data []byte) string {
	if len(data) < 2 {
		return string(data)
	}

	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(data, &raw); err != nil {
		return string(data) // Fallback
	}

	switch raw.Tag {
	case tagUTF8String, tagPrintableString, tagIA5String:
		return string(raw.Bytes)
	case tagBMPString:
		return decodeBMPStringBytes(raw.Bytes) // UTF-16BE → UTF-8
	default:
		return string(raw.Bytes)
	}
}

// decodeBMPStringBytes decodes UTF-16BE bytes to Go string
func decodeBMPStringBytes(data []byte) string {
	runes := make([]rune, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		r := rune(data[i])<<8 | rune(data[i+1])
		if r != 0 {
			runes = append(runes, r)
		}
	}
	return string(runes)
}

// determinePeerType determines if cert is for machine or user
func determinePeerType(cert *x509.Certificate, tmplInfo TemplateInfo) string {
	// Priority 1: Template NAME (most reliable)
	if tmplInfo.Name != "" {
		nameLower := strings.ToLower(tmplInfo.Name)
		for _, mt := range DefaultMachineTemplateNames {
			if nameLower == strings.ToLower(mt) {
				return "machine"
			}
		}
		// Check for user templates
		if strings.Contains(nameLower, "user") || strings.Contains(nameLower, "smartcard") {
			return "user"
		}
	}

	// Priority 2: EKU Analysis
	for _, eku := range cert.ExtKeyUsage {
		// SmartCardLogon is typically user
		if eku == x509.ExtKeyUsageAny {
			continue
		}
	}
	// Check for SmartCardLogon OID (1.3.6.1.4.1.311.20.2.2)
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.String() == "1.3.6.1.4.1.311.20.2.2" {
			return "user" // SmartCardLogon
		}
	}

	// Priority 3: SAN Analysis (User certs often have UPN/Email)
	if len(cert.EmailAddresses) > 0 {
		return "user"
	}

	// Priority 4: Has DNSNames but no Email = likely machine
	if len(cert.DNSNames) > 0 && len(cert.EmailAddresses) == 0 {
		return "machine"
	}

	return "unknown"
}

// buildMTLSIdentity builds the full identity struct from certificate
func buildMTLSIdentity(cert *x509.Certificate, tmplInfo TemplateInfo) MTLSIdentity {
	identity := MTLSIdentity{
		IssuerDN:     cert.Issuer.String(),
		IssuerFP:     fmt.Sprintf("%X", sha256.Sum256(cert.RawIssuer)),
		TemplateOID:  tmplInfo.OID,
		TemplateName: tmplInfo.Name,
		CertSerial:   cert.SerialNumber.String(),
		PeerType:     determinePeerType(cert, tmplInfo),
	}

	// Extract primary SAN DNSName
	if len(cert.DNSNames) > 0 {
		identity.DNSName = strings.ToLower(cert.DNSNames[0])

		// Split into hostname and domain
		parts := strings.SplitN(identity.DNSName, ".", 2)
		identity.Hostname = parts[0]
		if len(parts) > 1 {
			identity.Domain = parts[1]
		}
	}

	return identity
}
