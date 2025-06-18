package dnsfwd

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/dns/test"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/route"
)

func Test_getMatchingEntries(t *testing.T) {
	testCases := []struct {
		name           string
		storedMappings map[string]route.ResID
		queryDomain    string
		expectedResId  route.ResID
	}{
		{
			name:           "Empty map returns empty string",
			storedMappings: map[string]route.ResID{},
			queryDomain:    "example.com",
			expectedResId:  "",
		},
		{
			name:           "Exact match returns stored resId",
			storedMappings: map[string]route.ResID{"example.com": "res1"},
			queryDomain:    "example.com",
			expectedResId:  "res1",
		},
		{
			name:           "Wildcard pattern matches base domain",
			storedMappings: map[string]route.ResID{"*.example.com": "res2"},
			queryDomain:    "example.com",
			expectedResId:  "res2",
		},
		{
			name:           "Wildcard pattern matches subdomain",
			storedMappings: map[string]route.ResID{"*.example.com": "res3"},
			queryDomain:    "foo.example.com",
			expectedResId:  "res3",
		},
		{
			name:           "Wildcard pattern does not match different domain",
			storedMappings: map[string]route.ResID{"*.example.com": "res4"},
			queryDomain:    "foo.example.org",
			expectedResId:  "",
		},
		{
			name:           "Non-wildcard pattern does not match subdomain",
			storedMappings: map[string]route.ResID{"example.com": "res5"},
			queryDomain:    "foo.example.com",
			expectedResId:  "",
		},
		{
			name: "Exact match over overlapping wildcard",
			storedMappings: map[string]route.ResID{
				"*.example.com":   "resWildcard",
				"foo.example.com": "resExact",
			},
			queryDomain:   "foo.example.com",
			expectedResId: "resExact",
		},
		{
			name: "Overlapping wildcards: Select more specific wildcard",
			storedMappings: map[string]route.ResID{
				"*.example.com":     "resA",
				"*.sub.example.com": "resB",
			},
			queryDomain:   "bar.sub.example.com",
			expectedResId: "resB",
		},
		{
			name: "Wildcard multi-level subdomain match",
			storedMappings: map[string]route.ResID{
				"*.example.com": "resMulti",
			},
			queryDomain:   "a.b.example.com",
			expectedResId: "resMulti",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fwd := &DNSForwarder{}

			var entries []*ForwarderEntry
			for domainPattern, resId := range tc.storedMappings {
				d, err := domain.FromString(domainPattern)
				require.NoError(t, err)
				entries = append(entries, &ForwarderEntry{
					Domain: d,
					ResID:  resId,
				})
			}
			fwd.UpdateDomains(entries)

			got, _ := fwd.getMatchingEntries(tc.queryDomain)
			assert.Equal(t, got, tc.expectedResId)
		})
	}
}

type MockFirewall struct {
	mock.Mock
}

func (m *MockFirewall) UpdateSet(set firewall.Set, prefixes []netip.Prefix) error {
	args := m.Called(set, prefixes)
	return args.Error(0)
}

type MockResolver struct {
	mock.Mock
}

func (m *MockResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	args := m.Called(ctx, network, host)
	return args.Get(0).([]netip.Addr), args.Error(1)
}

func TestDNSForwarder_SubdomainAccessLogic(t *testing.T) {
	tests := []struct {
		name             string
		configuredDomain string
		queryDomain      string
		shouldMatch      bool
		expectedResID    route.ResID
		description      string
	}{
		{
			name:             "exact domain match should be allowed",
			configuredDomain: "example.com",
			queryDomain:      "example.com",
			shouldMatch:      true,
			expectedResID:    "test-res-id",
			description:      "Direct match to configured domain should work",
		},
		{
			name:             "subdomain access should be restricted",
			configuredDomain: "example.com",
			queryDomain:      "mail.example.com",
			shouldMatch:      false,
			expectedResID:    "",
			description:      "Subdomain should not be accessible unless explicitly configured",
		},
		{
			name:             "wildcard should allow subdomains",
			configuredDomain: "*.example.com",
			queryDomain:      "mail.example.com",
			shouldMatch:      true,
			expectedResID:    "test-res-id",
			description:      "Wildcard domains should allow subdomain access",
		},
		{
			name:             "wildcard should allow base domain",
			configuredDomain: "*.example.com",
			queryDomain:      "example.com",
			shouldMatch:      true,
			expectedResID:    "test-res-id",
			description:      "Wildcard should also match the base domain",
		},
		{
			name:             "deep subdomain should be restricted",
			configuredDomain: "example.com",
			queryDomain:      "deep.mail.example.com",
			shouldMatch:      false,
			expectedResID:    "",
			description:      "Deep subdomains should not be accessible",
		},
		{
			name:             "wildcard allows deep subdomains",
			configuredDomain: "*.example.com",
			queryDomain:      "deep.mail.example.com",
			shouldMatch:      true,
			expectedResID:    "test-res-id",
			description:      "Wildcard should allow deep subdomains",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forwarder := &DNSForwarder{}

			d, err := domain.FromString(tt.configuredDomain)
			require.NoError(t, err)

			entries := []*ForwarderEntry{
				{
					Domain: d,
					ResID:  "test-res-id",
				},
			}

			forwarder.UpdateDomains(entries)

			resID, matchingEntries := forwarder.getMatchingEntries(tt.queryDomain)

			if tt.shouldMatch {
				assert.Equal(t, tt.expectedResID, resID, "Expected matching ResID")
				assert.NotEmpty(t, matchingEntries, "Expected matching entries")
				t.Logf("✓ Domain %s correctly matches pattern %s", tt.queryDomain, tt.configuredDomain)
			} else {
				assert.Equal(t, tt.expectedResID, resID, "Expected no ResID match")
				assert.Empty(t, matchingEntries, "Expected no matching entries")
				t.Logf("✓ Domain %s correctly does NOT match pattern %s", tt.queryDomain, tt.configuredDomain)
			}
		})
	}
}

func TestDNSForwarder_UnauthorizedDomainAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tests := []struct {
		name             string
		configuredDomain string
		queryDomain      string
		shouldResolve    bool
		description      string
	}{
		{
			name:             "configured exact domain resolves",
			configuredDomain: "example.com",
			queryDomain:      "example.com",
			shouldResolve:    true,
			description:      "Exact match should resolve",
		},
		{
			name:             "unauthorized subdomain blocked",
			configuredDomain: "example.com",
			queryDomain:      "mail.example.com",
			shouldResolve:    false,
			description:      "Subdomain should be blocked without wildcard",
		},
		{
			name:             "wildcard allows subdomain",
			configuredDomain: "*.example.com",
			queryDomain:      "mail.example.com",
			shouldResolve:    true,
			description:      "Wildcard should allow subdomain",
		},
		{
			name:             "wildcard allows base domain",
			configuredDomain: "*.example.com",
			queryDomain:      "example.com",
			shouldResolve:    true,
			description:      "Wildcard should allow base domain",
		},
		{
			name:             "unrelated domain blocked",
			configuredDomain: "example.com",
			queryDomain:      "example.org",
			shouldResolve:    false,
			description:      "Unrelated domain should be blocked",
		},
		{
			name:             "deep subdomain blocked",
			configuredDomain: "example.com",
			queryDomain:      "deep.mail.example.com",
			shouldResolve:    false,
			description:      "Deep subdomain should be blocked",
		},
		{
			name:             "wildcard allows deep subdomain",
			configuredDomain: "*.example.com",
			queryDomain:      "deep.mail.example.com",
			shouldResolve:    true,
			description:      "Wildcard should allow deep subdomain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFirewall := &MockFirewall{}
			mockResolver := &MockResolver{}

			if tt.shouldResolve {
				mockFirewall.On("UpdateSet", mock.AnythingOfType("manager.Set"), mock.AnythingOfType("[]netip.Prefix")).Return(nil)

				// Mock successful DNS resolution
				fakeIP := netip.MustParseAddr("1.2.3.4")
				mockResolver.On("LookupNetIP", mock.Anything, "ip4", dns.Fqdn(tt.queryDomain)).Return([]netip.Addr{fakeIP}, nil)
			}

			forwarder := NewDNSForwarder("127.0.0.1:0", 300, mockFirewall, &peer.Status{})
			forwarder.resolver = mockResolver

			d, err := domain.FromString(tt.configuredDomain)
			require.NoError(t, err)

			entries := []*ForwarderEntry{
				{
					Domain: d,
					ResID:  "test-res-id",
					Set:    firewall.NewDomainSet([]domain.Domain{d}),
				},
			}

			forwarder.UpdateDomains(entries)

			query := &dns.Msg{}
			query.SetQuestion(dns.Fqdn(tt.queryDomain), dns.TypeA)

			mockWriter := &test.MockResponseWriter{}
			resp := forwarder.handleDNSQuery(mockWriter, query)

			if tt.shouldResolve {
				require.NotNil(t, resp, "Expected response for authorized domain")
				require.Equal(t, dns.RcodeSuccess, resp.Rcode, "Expected successful response")
				assert.NotEmpty(t, resp.Answer, "Expected DNS answer records")

				time.Sleep(10 * time.Millisecond)
				mockFirewall.AssertExpectations(t)
				mockResolver.AssertExpectations(t)
			} else {
				if resp != nil {
					assert.True(t, len(resp.Answer) == 0 || resp.Rcode != dns.RcodeSuccess,
						"Unauthorized domain should not return successful answers")
				}
				mockFirewall.AssertNotCalled(t, "UpdateSet")
				mockResolver.AssertNotCalled(t, "LookupNetIP")
			}
		})
	}
}

func TestDNSForwarder_FirewallSetUpdates(t *testing.T) {
	tests := []struct {
		name              string
		configuredDomains []string
		query             string
		mockIP            string
		shouldResolve     bool
		expectedSetCount  int // How many sets should be updated
		description       string
	}{
		{
			name:              "exact domain gets firewall update",
			configuredDomains: []string{"example.com"},
			query:             "example.com",
			mockIP:            "1.1.1.1",
			shouldResolve:     true,
			expectedSetCount:  1,
			description:       "Single exact match updates one set",
		},
		{
			name:              "wildcard domain gets firewall update",
			configuredDomains: []string{"*.example.com"},
			query:             "mail.example.com",
			mockIP:            "1.1.1.2",
			shouldResolve:     true,
			expectedSetCount:  1,
			description:       "Wildcard match updates one set",
		},
		{
			name:              "overlapping exact and wildcard both get updates",
			configuredDomains: []string{"*.example.com", "mail.example.com"},
			query:             "mail.example.com",
			mockIP:            "1.1.1.3",
			shouldResolve:     true,
			expectedSetCount:  2,
			description:       "Both exact and wildcard sets should be updated",
		},
		{
			name:              "unauthorized domain gets no firewall update",
			configuredDomains: []string{"example.com"},
			query:             "mail.example.com",
			mockIP:            "1.1.1.4",
			shouldResolve:     false,
			expectedSetCount:  0,
			description:       "No firewall update for unauthorized domains",
		},
		{
			name:              "multiple wildcards matching get all updated",
			configuredDomains: []string{"*.example.com", "*.sub.example.com"},
			query:             "test.sub.example.com",
			mockIP:            "1.1.1.5",
			shouldResolve:     true,
			expectedSetCount:  2,
			description:       "All matching wildcard sets should be updated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFirewall := &MockFirewall{}
			mockResolver := &MockResolver{}

			// Set up forwarder
			forwarder := NewDNSForwarder("127.0.0.1:0", 300, mockFirewall, &peer.Status{})
			forwarder.resolver = mockResolver

			// Create entries and track sets
			var entries []*ForwarderEntry
			sets := make([]firewall.Set, 0)

			for i, configDomain := range tt.configuredDomains {
				d, err := domain.FromString(configDomain)
				require.NoError(t, err)

				set := firewall.NewDomainSet([]domain.Domain{d})
				sets = append(sets, set)

				entries = append(entries, &ForwarderEntry{
					Domain: d,
					ResID:  route.ResID(fmt.Sprintf("res-%d", i)),
					Set:    set,
				})
			}

			forwarder.UpdateDomains(entries)

			// Set up mocks
			if tt.shouldResolve {
				fakeIP := netip.MustParseAddr(tt.mockIP)
				mockResolver.On("LookupNetIP", mock.Anything, "ip4", dns.Fqdn(tt.query)).
					Return([]netip.Addr{fakeIP}, nil).Once()

				expectedPrefixes := []netip.Prefix{netip.PrefixFrom(fakeIP, 32)}

				// Count how many sets should actually match
				updateCount := 0
				for i, entry := range entries {
					domain := strings.ToLower(tt.query)
					pattern := entry.Domain.PunycodeString()

					matches := false
					if strings.HasPrefix(pattern, "*.") {
						baseDomain := strings.TrimPrefix(pattern, "*.")
						if domain == baseDomain || strings.HasSuffix(domain, "."+baseDomain) {
							matches = true
						}
					} else if domain == pattern {
						matches = true
					}

					if matches {
						mockFirewall.On("UpdateSet", sets[i], expectedPrefixes).Return(nil).Once()
						updateCount++
					}
				}

				assert.Equal(t, tt.expectedSetCount, updateCount,
					"Expected %d sets to be updated, but mock expects %d",
					tt.expectedSetCount, updateCount)
			}

			// Execute query
			dnsQuery := &dns.Msg{}
			dnsQuery.SetQuestion(dns.Fqdn(tt.query), dns.TypeA)

			mockWriter := &test.MockResponseWriter{}
			resp := forwarder.handleDNSQuery(mockWriter, dnsQuery)

			// Verify response
			if tt.shouldResolve {
				require.NotNil(t, resp, "Expected response for authorized domain")
				require.Equal(t, dns.RcodeSuccess, resp.Rcode)
				require.NotEmpty(t, resp.Answer)
			} else if resp != nil {
				assert.True(t, resp.Rcode == dns.RcodeRefused || len(resp.Answer) == 0,
					"Unauthorized domain should be refused or have no answers")
			}

			// Verify all mock expectations were met
			mockFirewall.AssertExpectations(t)
			mockResolver.AssertExpectations(t)
		})
	}
}

// Test to verify that multiple IPs for one domain result in all prefixes being sent together
func TestDNSForwarder_MultipleIPsInSingleUpdate(t *testing.T) {
	mockFirewall := &MockFirewall{}
	mockResolver := &MockResolver{}

	forwarder := NewDNSForwarder("127.0.0.1:0", 300, mockFirewall, &peer.Status{})
	forwarder.resolver = mockResolver

	// Configure a single domain
	d, err := domain.FromString("example.com")
	require.NoError(t, err)

	set := firewall.NewDomainSet([]domain.Domain{d})
	entries := []*ForwarderEntry{{
		Domain: d,
		ResID:  "test-res",
		Set:    set,
	}}

	forwarder.UpdateDomains(entries)

	// Mock resolver returns multiple IPs
	ips := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.1.1.2"),
		netip.MustParseAddr("1.1.1.3"),
	}
	mockResolver.On("LookupNetIP", mock.Anything, "ip4", "example.com.").
		Return(ips, nil).Once()

	// Expect ONE UpdateSet call with ALL prefixes
	expectedPrefixes := []netip.Prefix{
		netip.PrefixFrom(ips[0], 32),
		netip.PrefixFrom(ips[1], 32),
		netip.PrefixFrom(ips[2], 32),
	}
	mockFirewall.On("UpdateSet", set, expectedPrefixes).Return(nil).Once()

	// Execute query
	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeA)

	mockWriter := &test.MockResponseWriter{}
	resp := forwarder.handleDNSQuery(mockWriter, query)

	// Verify response contains all IPs
	require.NotNil(t, resp)
	require.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 3, "Should have 3 answer records")

	// Verify mocks
	mockFirewall.AssertExpectations(t)
	mockResolver.AssertExpectations(t)
}

func TestDNSForwarder_ResponseCodes(t *testing.T) {
	tests := []struct {
		name         string
		queryType    uint16
		queryDomain  string
		configured   string
		expectedCode int
		description  string
	}{
		{
			name:         "unauthorized domain returns REFUSED",
			queryType:    dns.TypeA,
			queryDomain:  "evil.com",
			configured:   "example.com",
			expectedCode: dns.RcodeRefused,
			description:  "RFC compliant REFUSED for unauthorized queries",
		},
		{
			name:         "unsupported query type returns NOTIMP",
			queryType:    dns.TypeMX,
			queryDomain:  "example.com",
			configured:   "example.com",
			expectedCode: dns.RcodeNotImplemented,
			description:  "RFC compliant NOTIMP for unsupported types",
		},
		{
			name:         "CNAME query returns NOTIMP",
			queryType:    dns.TypeCNAME,
			queryDomain:  "example.com",
			configured:   "example.com",
			expectedCode: dns.RcodeNotImplemented,
			description:  "CNAME queries not supported",
		},
		{
			name:         "TXT query returns NOTIMP",
			queryType:    dns.TypeTXT,
			queryDomain:  "example.com",
			configured:   "example.com",
			expectedCode: dns.RcodeNotImplemented,
			description:  "TXT queries not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forwarder := NewDNSForwarder("127.0.0.1:0", 300, nil, &peer.Status{})

			d, err := domain.FromString(tt.configured)
			require.NoError(t, err)

			entries := []*ForwarderEntry{{Domain: d, ResID: "test-res"}}
			forwarder.UpdateDomains(entries)

			query := &dns.Msg{}
			query.SetQuestion(dns.Fqdn(tt.queryDomain), tt.queryType)

			// Capture the written response
			var writtenResp *dns.Msg
			mockWriter := &test.MockResponseWriter{
				WriteMsgFunc: func(m *dns.Msg) error {
					writtenResp = m
					return nil
				},
			}

			_ = forwarder.handleDNSQuery(mockWriter, query)

			// Check the response written to the writer
			require.NotNil(t, writtenResp, "Expected response to be written")
			assert.Equal(t, tt.expectedCode, writtenResp.Rcode, tt.description)
		})
	}
}

func TestDNSForwarder_TCPTruncation(t *testing.T) {
	// Test that large UDP responses are truncated with TC bit set
	mockResolver := &MockResolver{}
	forwarder := NewDNSForwarder("127.0.0.1:0", 300, nil, &peer.Status{})
	forwarder.resolver = mockResolver

	d, _ := domain.FromString("example.com")
	entries := []*ForwarderEntry{{Domain: d, ResID: "test-res"}}
	forwarder.UpdateDomains(entries)

	// Mock many IPs to create a large response
	var manyIPs []netip.Addr
	for i := 0; i < 100; i++ {
		manyIPs = append(manyIPs, netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i%256)))
	}
	mockResolver.On("LookupNetIP", mock.Anything, "ip4", "example.com.").Return(manyIPs, nil)

	// Query without EDNS0
	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeA)

	var writtenResp *dns.Msg
	mockWriter := &test.MockResponseWriter{
		WriteMsgFunc: func(m *dns.Msg) error {
			writtenResp = m
			return nil
		},
	}
	forwarder.handleDNSQueryUDP(mockWriter, query)

	require.NotNil(t, writtenResp)
	assert.True(t, writtenResp.Truncated, "Large response should be truncated")
	assert.LessOrEqual(t, writtenResp.Len(), dns.MinMsgSize, "Response should fit in minimum UDP size")
}

func TestDNSForwarder_MultipleOverlappingPatterns(t *testing.T) {
	// Test complex overlapping pattern scenarios
	mockFirewall := &MockFirewall{}
	mockResolver := &MockResolver{}

	forwarder := NewDNSForwarder("127.0.0.1:0", 300, mockFirewall, &peer.Status{})
	forwarder.resolver = mockResolver

	// Set up complex overlapping patterns
	patterns := []string{
		"*.example.com",         // Matches all subdomains
		"*.mail.example.com",    // More specific wildcard
		"smtp.mail.example.com", // Exact match
		"example.com",           // Base domain
	}

	var entries []*ForwarderEntry
	sets := make(map[string]firewall.Set)

	for _, pattern := range patterns {
		d, _ := domain.FromString(pattern)
		set := firewall.NewDomainSet([]domain.Domain{d})
		sets[pattern] = set
		entries = append(entries, &ForwarderEntry{
			Domain: d,
			ResID:  route.ResID("res-" + pattern),
			Set:    set,
		})
	}

	forwarder.UpdateDomains(entries)

	// Test smtp.mail.example.com - should match 3 patterns
	fakeIP := netip.MustParseAddr("1.2.3.4")
	mockResolver.On("LookupNetIP", mock.Anything, "ip4", "smtp.mail.example.com.").Return([]netip.Addr{fakeIP}, nil)

	expectedPrefix := netip.PrefixFrom(fakeIP, 32)
	// All three matching patterns should get firewall updates
	mockFirewall.On("UpdateSet", sets["smtp.mail.example.com"], []netip.Prefix{expectedPrefix}).Return(nil)
	mockFirewall.On("UpdateSet", sets["*.mail.example.com"], []netip.Prefix{expectedPrefix}).Return(nil)
	mockFirewall.On("UpdateSet", sets["*.example.com"], []netip.Prefix{expectedPrefix}).Return(nil)

	query := &dns.Msg{}
	query.SetQuestion("smtp.mail.example.com.", dns.TypeA)

	mockWriter := &test.MockResponseWriter{}
	resp := forwarder.handleDNSQuery(mockWriter, query)

	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

	// Verify all three sets were updated
	mockFirewall.AssertExpectations(t)

	// Verify the most specific ResID was selected
	// (exact match should win over wildcards)
	resID, matches := forwarder.getMatchingEntries("smtp.mail.example.com")
	assert.Equal(t, route.ResID("res-smtp.mail.example.com"), resID)
	assert.Len(t, matches, 3, "Should match 3 patterns")
}

func TestDNSForwarder_EmptyQuery(t *testing.T) {
	// Test handling of malformed query with no questions
	forwarder := NewDNSForwarder("127.0.0.1:0", 300, nil, &peer.Status{})

	query := &dns.Msg{}
	// Don't set any question

	writeCalled := false
	mockWriter := &test.MockResponseWriter{
		WriteMsgFunc: func(m *dns.Msg) error {
			writeCalled = true
			return nil
		},
	}
	resp := forwarder.handleDNSQuery(mockWriter, query)

	assert.Nil(t, resp, "Should return nil for empty query")
	assert.False(t, writeCalled, "Should not write response for empty query")
}
