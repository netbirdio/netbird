package mtls

// Machine Tunnel Fork - DNSLabel Generation for mTLS Peers
// Provides unique DNS label generation to prevent collisions across domains.

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
)

// dnsLabelRegex validates RFC 1123 compliant DNS labels
// Must start and end with alphanumeric, can contain hyphens in between
var dnsLabelRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// MaxDNSLabelLength is the maximum length for a DNS label per RFC 1123
const MaxDNSLabelLength = 63

// HashSuffixLength is the length of the FQDN hash suffix (8 hex chars = 32 bits)
const HashSuffixLength = 8

// GenerateUniqueDNSLabel creates a unique DNSLabel from hostname and domain.
//
// Problem (v3.5 - domain-only hash):
//   - Hash only over domain → all hosts of a domain get same hash suffix
//   - Hostname collision within domain would result in identical DNSLabel
//   - Example: Two "win10-pc.corp.local" (misconfiguration) → same DNSLabel!
//
// Solution (v3.6 - FQDN hash):
//   - FQDN = "hostname.domain" (case-insensitive)
//   - Each host gets guaranteed unique hash
//   - "win10-pc.customer-a.local" → "win10-pc-a1b2c3d4"
//   - "win10-pc.customer-b.local" → "win10-pc-5e6f7g8h"
//   - "win11-pc.customer-a.local" → "win11-pc-9x8y7z6w"
//
// Hash collision probability with 32 bits (8 hex chars) and 10,000 peers: ~0.001%
func GenerateUniqueDNSLabel(hostname, domain string) string {
	// Normalize: lowercase for case-insensitive matching
	hostname = strings.ToLower(hostname)
	domain = strings.ToLower(domain)

	// v3.6: Hash over FQDN (hostname.domain), not just domain!
	fqdn := fmt.Sprintf("%s.%s", hostname, domain)
	h := sha256.Sum256([]byte(fqdn))
	fqdnHash := fmt.Sprintf("%x", h[:4]) // 32 bit = 4 bytes = 8 hex chars

	// Sanitize hostname: replace invalid chars with hyphens
	sanitizedHostname := sanitizeForDNS(hostname)

	// Combine hostname with hash (Human-readable prefix + unique suffix)
	label := fmt.Sprintf("%s-%s", sanitizedHostname, fqdnHash)

	// DNS-Label max 63 chars (RFC 1123)
	if len(label) > MaxDNSLabelLength {
		// Truncate hostname to fit, keeping the hash suffix intact
		maxHostLen := MaxDNSLabelLength - HashSuffixLength - 1 // -1 for dash
		if maxHostLen < 1 {
			maxHostLen = 1
		}
		truncatedHostname := sanitizedHostname
		if len(sanitizedHostname) > maxHostLen {
			truncatedHostname = sanitizedHostname[:maxHostLen]
		}
		// Remove trailing hyphens after truncation
		truncatedHostname = strings.TrimRight(truncatedHostname, "-")
		label = fmt.Sprintf("%s-%s", truncatedHostname, fqdnHash)
		log.Debugf("DNSLabel truncated: %s (from hostname %s)", label, hostname)
	}

	return label
}

// ValidateDNSLabel checks if a label is RFC 1123 compliant.
// Returns nil if valid, error otherwise.
func ValidateDNSLabel(label string) error {
	if len(label) == 0 {
		return fmt.Errorf("DNS label cannot be empty")
	}
	if len(label) > MaxDNSLabelLength {
		return fmt.Errorf("DNS label must be 1-%d chars, got %d", MaxDNSLabelLength, len(label))
	}

	// RFC 1123: [a-z0-9]([-a-z0-9]*[a-z0-9])?
	// Must be lowercase, start/end with alphanumeric, can contain hyphens
	if !dnsLabelRegex.MatchString(label) {
		return fmt.Errorf("DNS label must match RFC 1123: start/end with alphanumeric, only lowercase letters, digits and hyphens allowed")
	}

	return nil
}

// sanitizeForDNS converts a hostname to a valid DNS label component.
// Replaces invalid characters with hyphens and ensures valid format.
func sanitizeForDNS(hostname string) string {
	// Replace underscores and other common invalid chars with hyphens
	result := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32 // lowercase
		case r == '_' || r == '.' || r == ' ':
			return '-'
		default:
			return -1 // drop other chars
		}
	}, hostname)

	// Remove leading/trailing hyphens
	result = strings.Trim(result, "-")

	// Collapse multiple consecutive hyphens
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}

	// If empty after sanitization, use a default
	if result == "" {
		result = "peer"
	}

	return result
}

// CheckDNSLabelCollision is a helper that logs a warning if a collision is detected.
// This should be called after DB check for existing label.
// Returns true if collision detected (existingLabel is not empty).
func CheckDNSLabelCollision(label, existingPeerID string) bool {
	if existingPeerID != "" {
		log.Warnf("RARE: DNSLabel collision detected for label %s (existing peer: %s)", label, existingPeerID)
		return true
	}
	return false
}
