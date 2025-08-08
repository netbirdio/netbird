package mgmt

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"

	dnsconfig "github.com/netbirdio/netbird/client/internal/dns/config"
	"github.com/netbirdio/netbird/client/internal/dns/test"
	"github.com/netbirdio/netbird/management/domain"
)

func TestResolver_NewResolver(t *testing.T) {
	resolver := NewResolver()

	assert.NotNil(t, resolver)
	assert.NotNil(t, resolver.records)
	assert.False(t, resolver.MatchSubdomains())
}

func TestResolver_ExtractDomainFromURL(t *testing.T) {
	tests := []struct {
		name        string
		urlStr      string
		expectedDom string
		expectError bool
	}{
		{
			name:        "HTTPS URL with port",
			urlStr:      "https://api.netbird.io:443",
			expectedDom: "api.netbird.io",
			expectError: false,
		},
		{
			name:        "HTTP URL without port",
			urlStr:      "http://signal.example.com",
			expectedDom: "signal.example.com",
			expectError: false,
		},
		{
			name:        "URL with path",
			urlStr:      "https://relay.netbird.io/status",
			expectedDom: "relay.netbird.io",
			expectError: false,
		},
		{
			name:        "Invalid URL",
			urlStr:      "not-a-valid-url",
			expectedDom: "not-a-valid-url",
			expectError: false,
		},
		{
			name:        "Empty URL",
			urlStr:      "",
			expectedDom: "",
			expectError: true,
		},
		{
			name:        "STUN URL",
			urlStr:      "stun:stun.example.com:3478",
			expectedDom: "stun.example.com",
			expectError: false,
		},
		{
			name:        "TURN URL",
			urlStr:      "turn:turn.example.com:3478",
			expectedDom: "turn.example.com",
			expectError: false,
		},
		{
			name:        "REL URL",
			urlStr:      "rel://relay.example.com:443",
			expectedDom: "relay.example.com",
			expectError: false,
		},
		{
			name:        "RELS URL",
			urlStr:      "rels://relay.example.com:443",
			expectedDom: "relay.example.com",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var parsedURL *url.URL
			var err error

			if tt.urlStr != "" {
				parsedURL, err = url.Parse(tt.urlStr)
				if err != nil && !tt.expectError {
					t.Fatalf("Failed to parse URL: %v", err)
				}
			}

			domain, err := extractDomainFromURL(parsedURL)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedDom, domain.SafeString())
			}
		})
	}
}

func TestResolver_PopulateFromConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := NewResolver()

	// Test with IP address - should return error since IP addresses are rejected
	mgmtURL, _ := url.Parse("https://127.0.0.1")

	err := resolver.PopulateFromConfig(ctx, mgmtURL)
	assert.Error(t, err)
	assert.ErrorIs(t, err, dnsconfig.ErrIPNotAllowed)

	// No domains should be cached when using IP addresses
	domains := resolver.GetCachedDomains()
	assert.Equal(t, 0, len(domains), "No domains should be cached when using IP addresses")
}

func TestResolver_ServeDNS(t *testing.T) {
	resolver := NewResolver()
	ctx := context.Background()

	// Add a test domain to the cache - use example.org which is reserved for testing
	testDomain, err := domain.FromString("example.org")
	if err != nil {
		t.Fatalf("Failed to create domain: %v", err)
	}
	err = resolver.AddDomain(ctx, testDomain)
	if err != nil {
		t.Skipf("Skipping test due to DNS resolution failure: %v", err)
	}

	// Test A record query for cached domain
	t.Run("Cached domain A record", func(t *testing.T) {
		var capturedMsg *dns.Msg
		mockWriter := &test.MockResponseWriter{
			WriteMsgFunc: func(m *dns.Msg) error {
				capturedMsg = m
				return nil
			},
		}

		req := new(dns.Msg)
		req.SetQuestion("example.org.", dns.TypeA)

		resolver.ServeDNS(mockWriter, req)

		assert.NotNil(t, capturedMsg)
		assert.Equal(t, dns.RcodeSuccess, capturedMsg.Rcode)
		assert.True(t, len(capturedMsg.Answer) > 0, "Should have at least one answer")
	})

	// Test uncached domain signals to continue to next handler
	t.Run("Uncached domain signals continue to next handler", func(t *testing.T) {
		var capturedMsg *dns.Msg
		mockWriter := &test.MockResponseWriter{
			WriteMsgFunc: func(m *dns.Msg) error {
				capturedMsg = m
				return nil
			},
		}

		req := new(dns.Msg)
		req.SetQuestion("unknown.example.com.", dns.TypeA)

		resolver.ServeDNS(mockWriter, req)

		assert.NotNil(t, capturedMsg)
		assert.Equal(t, dns.RcodeNameError, capturedMsg.Rcode)
		// Zero flag set to true signals the handler chain to continue to next handler
		assert.True(t, capturedMsg.MsgHdr.Zero, "Zero flag should be set to signal continuation to next handler")
		assert.Empty(t, capturedMsg.Answer, "Should have no answers for uncached domain")
	})

	// Test that subdomains of cached domains are NOT resolved
	t.Run("Subdomains of cached domains are not resolved", func(t *testing.T) {
		var capturedMsg *dns.Msg
		mockWriter := &test.MockResponseWriter{
			WriteMsgFunc: func(m *dns.Msg) error {
				capturedMsg = m
				return nil
			},
		}

		// Query for a subdomain of our cached domain
		req := new(dns.Msg)
		req.SetQuestion("sub.example.org.", dns.TypeA)

		resolver.ServeDNS(mockWriter, req)

		assert.NotNil(t, capturedMsg)
		assert.Equal(t, dns.RcodeNameError, capturedMsg.Rcode)
		assert.True(t, capturedMsg.MsgHdr.Zero, "Should signal continuation to next handler for subdomains")
		assert.Empty(t, capturedMsg.Answer, "Should have no answers for subdomains")
	})

	// Test case-insensitive matching
	t.Run("Case-insensitive domain matching", func(t *testing.T) {
		var capturedMsg *dns.Msg
		mockWriter := &test.MockResponseWriter{
			WriteMsgFunc: func(m *dns.Msg) error {
				capturedMsg = m
				return nil
			},
		}

		// Query with different casing
		req := new(dns.Msg)
		req.SetQuestion("EXAMPLE.ORG.", dns.TypeA)

		resolver.ServeDNS(mockWriter, req)

		assert.NotNil(t, capturedMsg)
		assert.Equal(t, dns.RcodeSuccess, capturedMsg.Rcode)
		assert.True(t, len(capturedMsg.Answer) > 0, "Should resolve regardless of case")
	})
}

func TestResolver_GetCachedDomains(t *testing.T) {
	resolver := NewResolver()
	ctx := context.Background()

	testDomain, err := domain.FromString("example.org")
	if err != nil {
		t.Fatalf("Failed to create domain: %v", err)
	}
	err = resolver.AddDomain(ctx, testDomain)
	if err != nil {
		t.Skipf("Skipping test due to DNS resolution failure: %v", err)
	}

	cachedDomains := resolver.GetCachedDomains()

	assert.Equal(t, 1, len(cachedDomains), "Should return exactly one domain for single added domain")
	assert.Equal(t, testDomain.SafeString(), cachedDomains[0].SafeString(), "Cached domain should match original")
	assert.False(t, strings.HasSuffix(cachedDomains[0].PunycodeString(), "."), "Domain should not have trailing dot")
}

func TestResolver_ManagementDomainProtection(t *testing.T) {
	resolver := NewResolver()
	ctx := context.Background()

	mgmtURL, _ := url.Parse("https://example.org")
	err := resolver.PopulateFromConfig(ctx, mgmtURL)
	if err != nil {
		t.Skipf("Skipping test due to DNS resolution failure: %v", err)
	}

	initialDomains := resolver.GetCachedDomains()
	if len(initialDomains) == 0 {
		t.Skip("Management domain failed to resolve, skipping test")
	}
	assert.Equal(t, 1, len(initialDomains), "Should have management domain cached")
	assert.Equal(t, "example.org", initialDomains[0].SafeString())

	serverDomains := dnsconfig.ServerDomains{
		Signal: "google.com",
		Relay:  []domain.Domain{"cloudflare.com"},
	}

	_, err = resolver.UpdateFromServerDomains(ctx, serverDomains)
	if err != nil {
		t.Logf("Server domains update failed: %v", err)
	}

	finalDomains := resolver.GetCachedDomains()

	managementStillCached := false
	for _, d := range finalDomains {
		if d.SafeString() == "example.org" {
			managementStillCached = true
			break
		}
	}
	assert.True(t, managementStillCached, "Management domain should never be removed")
}

// extractDomainFromURL extracts a domain from a URL - test helper function
func extractDomainFromURL(u *url.URL) (domain.Domain, error) {
	if u == nil {
		return "", fmt.Errorf("URL is nil")
	}
	return dnsconfig.ExtractValidDomain(u.String())
}

func TestResolver_EmptyUpdateDoesNotRemoveDomains(t *testing.T) {
	resolver := NewResolver()
	ctx := context.Background()

	// Set up initial domains using resolvable domains
	initialDomains := dnsconfig.ServerDomains{
		Signal: "example.org",
		Stuns:  []domain.Domain{"google.com"},
		Turns:  []domain.Domain{"cloudflare.com"},
	}

	// Add initial domains
	_, err := resolver.UpdateFromServerDomains(ctx, initialDomains)
	if err != nil {
		t.Skipf("Skipping test due to DNS resolution failure: %v", err)
	}

	// Verify domains were added
	cachedDomains := resolver.GetCachedDomains()
	assert.Len(t, cachedDomains, 3)

	// Update with empty ServerDomains (simulating partial network map update)
	emptyDomains := dnsconfig.ServerDomains{}
	removedDomains, err := resolver.UpdateFromServerDomains(ctx, emptyDomains)
	assert.NoError(t, err)

	// Verify no domains were removed
	assert.Len(t, removedDomains, 0, "No domains should be removed when update is empty")

	// Verify all original domains are still cached
	finalDomains := resolver.GetCachedDomains()
	assert.Len(t, finalDomains, 3, "All original domains should still be cached")
}

func TestResolver_PartialUpdateReplacesOnlyUpdatedTypes(t *testing.T) {
	resolver := NewResolver()
	ctx := context.Background()

	// Set up initial complete domains using resolvable domains
	initialDomains := dnsconfig.ServerDomains{
		Signal: "example.org",
		Stuns:  []domain.Domain{"google.com"},
		Turns:  []domain.Domain{"cloudflare.com"},
	}

	// Add initial domains
	_, err := resolver.UpdateFromServerDomains(ctx, initialDomains)
	if err != nil {
		t.Skipf("Skipping test due to DNS resolution failure: %v", err)
	}
	assert.Len(t, resolver.GetCachedDomains(), 3)

	// Update with partial ServerDomains (only signal domain - this should replace signal but preserve stun/turn)
	partialDomains := dnsconfig.ServerDomains{
		Signal: "github.com",
	}
	removedDomains, err := resolver.UpdateFromServerDomains(ctx, partialDomains)
	if err != nil {
		t.Skipf("Skipping test due to DNS resolution failure: %v", err)
	}

	// Should remove only the old signal domain
	assert.Len(t, removedDomains, 1, "Should remove only the old signal domain")
	assert.Equal(t, "example.org", removedDomains[0].SafeString())

	finalDomains := resolver.GetCachedDomains()
	assert.Len(t, finalDomains, 3, "Should have new signal plus preserved stun/turn domains")

	domainStrings := make([]string, len(finalDomains))
	for i, d := range finalDomains {
		domainStrings[i] = d.SafeString()
	}
	assert.Contains(t, domainStrings, "github.com")
	assert.Contains(t, domainStrings, "google.com")
	assert.Contains(t, domainStrings, "cloudflare.com")
	assert.NotContains(t, domainStrings, "example.org")
}

func TestResolver_PartialUpdateAddsNewTypePreservesExisting(t *testing.T) {
	resolver := NewResolver()
	ctx := context.Background()

	// Set up initial complete domains using resolvable domains
	initialDomains := dnsconfig.ServerDomains{
		Signal: "example.org",
		Stuns:  []domain.Domain{"google.com"},
		Turns:  []domain.Domain{"cloudflare.com"},
	}

	// Add initial domains
	_, err := resolver.UpdateFromServerDomains(ctx, initialDomains)
	if err != nil {
		t.Skipf("Skipping test due to DNS resolution failure: %v", err)
	}
	assert.Len(t, resolver.GetCachedDomains(), 3)

	// Update with partial ServerDomains (only flow domain - new type, should preserve all existing)
	partialDomains := dnsconfig.ServerDomains{
		Flow: "github.com",
	}
	removedDomains, err := resolver.UpdateFromServerDomains(ctx, partialDomains)
	if err != nil {
		t.Skipf("Skipping test due to DNS resolution failure: %v", err)
	}

	assert.Len(t, removedDomains, 0, "Should not remove any domains when adding new type")

	finalDomains := resolver.GetCachedDomains()
	assert.Len(t, finalDomains, 4, "Should have all original domains plus new flow domain")

	domainStrings := make([]string, len(finalDomains))
	for i, d := range finalDomains {
		domainStrings[i] = d.SafeString()
	}
	assert.Contains(t, domainStrings, "example.org")
	assert.Contains(t, domainStrings, "google.com")
	assert.Contains(t, domainStrings, "cloudflare.com")
	assert.Contains(t, domainStrings, "github.com")
}
