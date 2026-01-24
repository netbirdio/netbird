package server

// Machine Tunnel Fork - mTLS Authentication for Machine Peers
// This file implements gRPC interceptors for client certificate authentication.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/internals/shared/mtls"
)

// MTLSIdentity is an alias for the shared mtls.Identity type
// Kept for backwards compatibility within this package
type MTLSIdentity = mtls.Identity

// MTLSIdentityKey is an alias for the shared mtls.IdentityKey
// Kept for backwards compatibility
var MTLSIdentityKey = mtls.IdentityKey

// GetMTLSIdentity retrieves the mTLS identity from context.
// This is an alias for mtls.GetIdentity for backwards compatibility.
func GetMTLSIdentity(ctx context.Context) *MTLSIdentity {
	return mtls.GetIdentity(ctx)
}

// mTLSRequiredMethods defines which gRPC methods REQUIRE client certificate authentication.
// These methods will reject requests without a valid client certificate.
// Other methods will fall back to token-based authentication.
var mTLSRequiredMethods = map[string]bool{
	"/management.ManagementService/RegisterMachinePeer": true,
	"/management.ManagementService/SyncMachinePeer":     true,
	"/management.ManagementService/GetMachineRoutes":    true,
	"/management.ManagementService/ReportMachineStatus": true,
}

// MTLSConfig holds the mTLS configuration for domain-account mapping.
// This is set during server initialization from the config file.
type MTLSConfig struct {
	// DomainAccountMapping maps AD domains to NetBird account IDs
	DomainAccountMapping map[string]string
	// AccountAllowedDomains maps account IDs to their allowed domains
	AccountAllowedDomains map[string][]string
	// AccountAllowedIssuers maps account IDs to their allowed CA issuer fingerprints (SHA256)
	// CRITICAL: If set for an account, only certificates from these CAs are accepted
	// If empty for an account, issuer validation is SKIPPED (warned, NOT RECOMMENDED for production!)
	AccountAllowedIssuers map[string][]string
}

// globalMTLSConfig is the server-wide mTLS configuration.
// Set via SetMTLSConfig during server startup.
var globalMTLSConfig *MTLSConfig

// SetMTLSConfig sets the global mTLS configuration.
// Must be called during server initialization before handling requests.
func SetMTLSConfig(cfg *MTLSConfig) {
	globalMTLSConfig = cfg
	log.Infof("mTLS config loaded: %d domain mappings, %d account configs",
		len(cfg.DomainAccountMapping), len(cfg.AccountAllowedDomains))
}

// getAccountIDFromDomain maps a domain to its NetBird account ID.
// Returns error if domain is not mapped to any account.
// CRITICAL: This mapping prevents cross-tenant certificate acceptance!
func getAccountIDFromDomain(domain string) (string, error) {
	if globalMTLSConfig == nil {
		return "", fmt.Errorf("mTLS config not initialized")
	}

	// Normalize domain to lowercase for case-insensitive matching
	normalizedDomain := strings.ToLower(domain)

	accountID, ok := globalMTLSConfig.DomainAccountMapping[normalizedDomain]
	if !ok {
		return "", fmt.Errorf("domain %q not mapped to any account", domain)
	}

	return accountID, nil
}

// getAllowedDomainsForAccount returns the list of allowed domains for an account.
// Returns nil if no domains are configured (which means REJECT ALL - fail-safe!).
// CRITICAL: This is the security boundary for multi-tenant isolation!
func getAllowedDomainsForAccount(accountID string) []string {
	if globalMTLSConfig == nil {
		log.Warn("mTLS config not initialized, rejecting all domains")
		return nil
	}

	// First check explicit account configuration
	if domains, ok := globalMTLSConfig.AccountAllowedDomains[accountID]; ok {
		return domains
	}

	// Fallback: derive allowed domains from DomainAccountMapping
	// (all domains that map to this account are allowed)
	var domains []string
	for domain, accID := range globalMTLSConfig.DomainAccountMapping {
		if accID == accountID {
			domains = append(domains, domain)
		}
	}

	if len(domains) == 0 {
		log.Warnf("No allowed domains found for account %s", accountID)
	}

	return domains
}

// validateDomainForAccount checks if a domain is allowed for the given account.
// Returns the matched allowed domain pattern (for audit logging) or error.
func validateDomainForAccount(domain, accountID string) (string, error) {
	allowedDomains := getAllowedDomainsForAccount(accountID)
	if len(allowedDomains) == 0 {
		return "", fmt.Errorf("no allowed domains configured for account %s", accountID)
	}

	normalizedDomain := strings.ToLower(domain)
	for _, allowed := range allowedDomains {
		if strings.ToLower(allowed) == normalizedDomain {
			return allowed, nil
		}
	}

	return "", fmt.Errorf("domain %q not in allowed list for account %s: %v",
		domain, accountID, allowedDomains)
}

// ValidateIssuerCA validates that the certificate issuer is authorized for the given account.
// CRITICAL: This is a security boundary for multi-tenant isolation!
// Uses SHA256 fingerprint comparison (NOT string matching on DN which can be spoofed!)
//
// Returns nil if issuer is valid, error otherwise.
// Per Security Review: Empty allowlist = DENY (not any-CA!) for production safety.
func ValidateIssuerCA(accountID, issuerFingerprint string) error {
	if globalMTLSConfig == nil {
		return fmt.Errorf("mTLS config not initialized - cannot validate issuer")
	}

	// Get allowed issuers for this account
	allowedIssuers := globalMTLSConfig.AccountAllowedIssuers[accountID]

	// Security: Empty allowlist = DENY (fail-safe for production)
	// Per Security Review: Explicit configuration required, no "any CA" fallback
	if len(allowedIssuers) == 0 {
		log.Warnf("SECURITY: Account %s has no MTLSAccountAllowedIssuers configured - rejecting certificate (explicit config required)", accountID)
		return fmt.Errorf("no allowed CA issuers configured for account %s - explicit MTLSAccountAllowedIssuers configuration required", accountID)
	}

	// Normalize fingerprint for comparison (lowercase hex)
	normalizedFP := strings.ToLower(issuerFingerprint)

	// Check against allowed issuers
	for _, allowed := range allowedIssuers {
		if strings.ToLower(allowed) == normalizedFP {
			log.Debugf("Issuer CA validated for account %s (FP: %s...)", accountID, normalizedFP[:16])
			return nil
		}
	}

	// Log truncated fingerprint for security (don't expose full FP in logs)
	fpPreview := normalizedFP
	if len(fpPreview) > 16 {
		fpPreview = fpPreview[:16] + "..."
	}
	return fmt.Errorf("certificate issuer CA (FP: %s) not in allowed list for account %s", fpPreview, accountID)
}

// checkMultiAccountSpan detects if a certificate's SANs span multiple accounts.
// This is a security warning - certificates should belong to a single account.
func checkMultiAccountSpan(dnsNames []string) {
	seenAccounts := make(map[string]bool)
	for _, dnsName := range dnsNames {
		_, domain, err := splitDNSName(dnsName)
		if err != nil {
			continue
		}
		accountID, err := getAccountIDFromDomain(domain)
		if err == nil {
			seenAccounts[accountID] = true
		}
	}

	if len(seenAccounts) > 1 {
		accounts := make([]string, 0, len(seenAccounts))
		for acc := range seenAccounts {
			accounts = append(accounts, acc)
		}
		log.Warnf("SECURITY: Certificate spans multiple accounts: %v (SANs: %v). "+
			"Using first valid match only.", accounts, dnsNames)
	}
}

// MTLSUnaryInterceptor creates a gRPC unary interceptor for mTLS authentication.
// If strictMode is true, ALL requests require a client certificate.
// If strictMode is false, only methods in mTLSRequiredMethods require a certificate.
func MTLSUnaryInterceptor(strictMode bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{},
		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {

		identity, err := extractMTLSIdentity(ctx)
		methodRequiresMTLS := mTLSRequiredMethods[info.FullMethod]

		if err != nil {
			if methodRequiresMTLS {
				log.WithContext(ctx).Warnf("mTLS required for %s but no valid cert: %v", info.FullMethod, err)
				return nil, status.Errorf(codes.Unauthenticated,
					"method %s requires client certificate authentication", info.FullMethod)
			}
			if strictMode {
				log.WithContext(ctx).Warnf("mTLS strict mode: rejecting request without cert")
				return nil, status.Errorf(codes.Unauthenticated, "client certificate required")
			}
			// Non-strict + non-required: allow fallback to token auth
			log.WithContext(ctx).Tracef("No mTLS cert for %s, falling back to token auth", info.FullMethod)
			return handler(ctx, req)
		}

		log.WithContext(ctx).Debugf("mTLS authenticated: %s (issuer: %s...)",
			identity.DNSName, identity.IssuerFingerprint[:16])

		ctx = context.WithValue(ctx, MTLSIdentityKey, identity)
		return handler(ctx, req)
	}
}

// MTLSStreamInterceptor creates a gRPC stream interceptor for mTLS authentication.
func MTLSStreamInterceptor(strictMode bool) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {

		ctx := ss.Context()
		identity, err := extractMTLSIdentity(ctx)
		methodRequiresMTLS := mTLSRequiredMethods[info.FullMethod]

		if err != nil {
			if methodRequiresMTLS {
				log.WithContext(ctx).Warnf("mTLS required for %s but no valid cert: %v", info.FullMethod, err)
				return status.Errorf(codes.Unauthenticated,
					"method %s requires client certificate authentication", info.FullMethod)
			}
			if strictMode {
				return status.Errorf(codes.Unauthenticated, "client certificate required")
			}
			return handler(srv, ss)
		}

		log.WithContext(ctx).Debugf("mTLS stream authenticated: %s", identity.DNSName)

		// Wrap stream with identity context
		wrapped := &mtlsServerStream{
			ServerStream: ss,
			ctx:          context.WithValue(ctx, MTLSIdentityKey, identity),
		}
		return handler(srv, wrapped)
	}
}

// mtlsServerStream wraps a grpc.ServerStream to inject mTLS identity into context
type mtlsServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *mtlsServerStream) Context() context.Context {
	return s.ctx
}

// extractMTLSIdentity extracts the machine identity from a client certificate.
// It validates the certificate and extracts the SAN DNSName as the primary identity.
func extractMTLSIdentity(ctx context.Context) (*MTLSIdentity, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no peer info in context")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fmt.Errorf("no TLS info in peer")
	}

	// VerifiedChains is populated when ClientAuth >= VerifyClientCertIfGiven
	// and the client provided a certificate that passed verification
	if len(tlsInfo.State.VerifiedChains) == 0 {
		return nil, fmt.Errorf("no verified certificate chains")
	}

	// First chain, first cert is the client certificate
	chain := tlsInfo.State.VerifiedChains[0]
	if len(chain) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}

	clientCert := chain[0]

	// Extract SAN DNSName as primary identity (NOT CN!)
	// CN is deprecated and can be easily spoofed or left empty
	if len(clientCert.DNSNames) == 0 {
		return nil, fmt.Errorf("certificate has no SAN DNSName")
	}

	// Security: Check if certificate SANs span multiple accounts (logging only)
	checkMultiAccountSpan(clientCert.DNSNames)

	// Find first valid SAN that maps to an account and passes validation
	var validDNSName, validHostname, validDomain, accountID, matchedDomain string
	var validationErr error

	for _, dnsName := range clientCert.DNSNames {
		hostname, domain, err := splitDNSName(dnsName)
		if err != nil {
			log.Debugf("Skipping invalid SAN DNSName %q: %v", dnsName, err)
			continue
		}

		// Try to get account ID from domain
		accID, err := getAccountIDFromDomain(domain)
		if err != nil {
			log.Debugf("SAN %q: domain not mapped to account: %v", dnsName, err)
			validationErr = err
			continue
		}

		// Validate domain against account's allowed domains
		matched, err := validateDomainForAccount(domain, accID)
		if err != nil {
			log.Debugf("SAN %q: domain validation failed: %v", dnsName, err)
			validationErr = err
			continue
		}

		// Found valid SAN!
		validDNSName = dnsName
		validHostname = hostname
		validDomain = domain
		accountID = accID
		matchedDomain = matched
		log.Debugf("mTLS: Valid SAN found: %s (account: %s, matched: %s)",
			dnsName, accountID, matchedDomain)
		break
	}

	// If no valid SAN was found, return the last validation error
	// or a generic error if mTLS config is not set up
	if validDNSName == "" {
		switch {
		case globalMTLSConfig == nil:
			// mTLS config not set - fall back to simple validation (first valid FQDN)
			dnsName := clientCert.DNSNames[0]
			hostname, domain, err := splitDNSName(dnsName)
			if err != nil {
				return nil, fmt.Errorf("invalid SAN DNSName format: %w", err)
			}
			validDNSName = dnsName
			validHostname = hostname
			validDomain = domain
			log.Debugf("mTLS config not set, using first valid SAN: %s", dnsName)
		case validationErr != nil:
			return nil, fmt.Errorf("no valid SAN DNSName for configured accounts: %w", validationErr)
		default:
			return nil, fmt.Errorf("certificate has no SAN DNSName matching configured domains")
		}
	}

	// Compute issuer fingerprint from VerifiedChains (strong binding)
	// NOT from AuthorityKeyId which can be spoofed!
	issuerFP := ""
	if len(chain) > 1 {
		issuerCert := chain[1]
		hash := sha256.Sum256(issuerCert.Raw)
		issuerFP = fmt.Sprintf("%x", hash)
	}

	// Extract template info (OID from v2, Name from v1)
	templateOID := extractTemplateOID(clientCert)
	templateName := extractTemplateNameV1(clientCert)

	// Determine peer type from template
	peerType := determinePeerType(templateOID, templateName, clientCert)

	identity := &MTLSIdentity{
		DNSName:           validDNSName,
		Hostname:          validHostname,
		Domain:            validDomain,
		MatchedDomain:     matchedDomain,
		AccountID:         accountID,
		IssuerFingerprint: issuerFP,
		SerialNumber:      clientCert.SerialNumber.String(),
		TemplateOID:       templateOID,
		TemplateName:      templateName,
		PeerType:          peerType,
	}

	return identity, nil
}

// splitDNSName splits a FQDN into hostname and domain parts.
// Example: "win10-pc.corp.local" -> ("win10-pc", "corp.local")
func splitDNSName(dnsName string) (hostname, domain string, err error) {
	parts := strings.SplitN(dnsName, ".", 2)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("DNSName must be FQDN (hostname.domain): %s", dnsName)
	}
	return parts[0], parts[1], nil
}

// extractTemplateOID extracts the certificate template OID from extensions.
// AD CS certificates include the template OID in extension 1.3.6.1.4.1.311.21.7
// This can be used to validate the certificate was issued from the expected template.
//
// The extension value is ASN.1 encoded as:
// SEQUENCE {
//   OBJECT IDENTIFIER (template OID)
//   INTEGER (major version) OPTIONAL
//   INTEGER (minor version) OPTIONAL
// }
func extractTemplateOID(cert *x509.Certificate) string {
	// Microsoft Certificate Template OID (szOID_CERTIFICATE_TEMPLATE)
	const templateExtOID = "1.3.6.1.4.1.311.21.7"

	for _, ext := range cert.Extensions {
		if ext.Id.String() == templateExtOID {
			return parseTemplateExtension(ext.Value)
		}
	}
	return ""
}

// parseTemplateExtension parses the ASN.1 encoded certificate template extension.
// Returns the template OID string or empty string on parse error.
func parseTemplateExtension(data []byte) string {
	// Simple ASN.1 parsing for the template extension
	// Format: SEQUENCE { OID, [INTEGER], [INTEGER] }
	//
	// We only need the OID, which starts after the SEQUENCE header

	if len(data) < 4 {
		return ""
	}

	// Check for SEQUENCE tag (0x30)
	if data[0] != 0x30 {
		return ""
	}

	// Get sequence length (simplified - assumes short form)
	seqLen := int(data[1])
	if seqLen > len(data)-2 {
		return ""
	}

	// Move past SEQUENCE header
	pos := 2

	// Check for OID tag (0x06)
	if pos >= len(data) || data[pos] != 0x06 {
		return ""
	}
	pos++

	// Get OID length
	if pos >= len(data) {
		return ""
	}
	oidLen := int(data[pos])
	pos++

	if pos+oidLen > len(data) {
		return ""
	}

	// Parse the OID bytes
	oidBytes := data[pos : pos+oidLen]
	return decodeOID(oidBytes)
}

// decodeOID decodes ASN.1 DER encoded OID bytes to dotted string format.
func decodeOID(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// First byte encodes first two components: val = 40*c1 + c2
	// where c1 is 0, 1, or 2 and c2 < 40 (for c1 = 0 or 1) or any (for c1 = 2)
	var components []int

	first := int(data[0])
	switch {
	case first < 40:
		components = append(components, 0, first)
	case first < 80:
		components = append(components, 1, first-40)
	default:
		components = append(components, 2, first-80)
	}

	// Remaining bytes are variable-length encoded
	var val int
	for i := 1; i < len(data); i++ {
		val = val<<7 | int(data[i]&0x7f)
		if data[i]&0x80 == 0 {
			components = append(components, val)
			val = 0
		}
	}

	// Convert to dotted string
	result := ""
	for i, c := range components {
		if i > 0 {
			result += "."
		}
		result += fmt.Sprintf("%d", c)
	}
	return result
}

// extractTemplateNameV1 extracts the certificate template NAME from v1 extension.
// AD CS v1 templates use extension OID 1.3.6.1.4.1.311.20.2 (szOID_ENROLL_CERTTYPE_EXTENSION)
// The value is a string, usually encoded as BMPString (UTF-16BE) or UTF8String.
func extractTemplateNameV1(cert *x509.Certificate) string {
	// Microsoft Certificate Template Name OID (v1 templates)
	const templateNameExtOID = "1.3.6.1.4.1.311.20.2"

	for _, ext := range cert.Extensions {
		if ext.Id.String() == templateNameExtOID {
			return decodeASN1String(ext.Value)
		}
	}
	return ""
}

// ASN.1 tag constants for string types
const (
	tagUTF8String      = 12 // 0x0C
	tagPrintableString = 19 // 0x13
	tagIA5String       = 22 // 0x16
	tagBMPString       = 30 // 0x1E - UTF-16BE!
)

// decodeASN1String decodes an ASN.1 encoded string value.
// Handles UTF8String, PrintableString, IA5String, and BMPString (UTF-16BE).
func decodeASN1String(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// ASN.1 TLV: Tag, Length, Value
	tag := int(data[0])
	length := int(data[1])

	// Handle long form length (0x81 prefix for lengths 128-255)
	valueStart := 2
	if length == 0x81 && len(data) > 2 {
		length = int(data[2])
		valueStart = 3
	} else if length == 0x82 && len(data) > 3 {
		length = int(data[2])<<8 | int(data[3])
		valueStart = 4
	}

	if valueStart+length > len(data) {
		// Fallback: try to decode entire data as string
		return string(data)
	}

	value := data[valueStart : valueStart+length]

	switch tag {
	case tagUTF8String, tagPrintableString, tagIA5String:
		return string(value)
	case tagBMPString:
		return decodeBMPString(value)
	default:
		// Unknown tag, try as raw string
		return string(value)
	}
}

// decodeBMPString decodes UTF-16BE (BMPString) bytes to Go UTF-8 string.
// BMPString is commonly used in Microsoft certificate extensions.
func decodeBMPString(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	runes := make([]rune, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		// UTF-16BE: high byte first
		r := rune(data[i])<<8 | rune(data[i+1])
		if r != 0 { // Skip null characters
			runes = append(runes, r)
		}
	}
	return string(runes)
}

// DefaultMachineTemplateNames are template names that indicate a machine certificate.
// These are matched case-insensitively.
var DefaultMachineTemplateNames = []string{
	"Machine",
	"Computer",
	"Workstation",
	"NetBirdMachine",
	"DomainController",
	"WebServer",
	"IPSecIntermediateOffline",
}

// determinePeerType determines if the certificate belongs to a machine or user.
// Returns "machine", "user", or "unknown".
func determinePeerType(templateOID, templateName string, cert *x509.Certificate) string {
	// Priority 1: Check template NAME (v1 extension, most reliable for AD CS)
	if templateName != "" {
		nameLower := strings.ToLower(templateName)
		for _, mt := range DefaultMachineTemplateNames {
			if nameLower == strings.ToLower(mt) {
				return "machine"
			}
		}
		// Known user template names
		if nameLower == "user" || nameLower == "smartcardlogon" || nameLower == "smartcarduser" {
			return "user"
		}
	}

	// Priority 2: Check EKU (Extended Key Usage)
	// Machine certs typically have ClientAuth but NOT SmartCardLogon
	hasClientAuth := false
	hasSmartCardLogon := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	// SmartCardLogon OID: 1.3.6.1.4.1.311.20.2.2
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.String() == "1.3.6.1.4.1.311.20.2.2" {
			hasSmartCardLogon = true
		}
	}

	if hasClientAuth && !hasSmartCardLogon {
		// Check if SAN has email or UPN (user indicators)
		if len(cert.EmailAddresses) > 0 {
			return "user"
		}
		// No email, has ClientAuth, no SmartCardLogon = likely machine
		return "machine"
	}

	if hasSmartCardLogon {
		return "user"
	}

	// Priority 3: Check SAN types
	// User certs often have email addresses in SAN
	if len(cert.EmailAddresses) > 0 {
		return "user"
	}

	// DNS names without email usually indicate machine
	if len(cert.DNSNames) > 0 {
		return "machine"
	}

	return "unknown"
}
