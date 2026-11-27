//go:build !ios

package dns

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateShortDomains generates domains like a.com, b.com, ..., aa.com, ab.com, etc.
func generateShortDomains(count int) []string {
	domains := make([]string, 0, count)
	for i := range count {
		label := ""
		n := i
		for {
			label = string(rune('a'+n%26)) + label
			n = n/26 - 1
			if n < 0 {
				break
			}
		}
		domains = append(domains, label+".com")
	}
	return domains
}

// generateLongDomains generates domains like subdomain-000.department.organization-name.example.com
func generateLongDomains(count int) []string {
	domains := make([]string, 0, count)
	for i := range count {
		domains = append(domains, fmt.Sprintf("subdomain-%03d.department.organization-name.example.com", i))
	}
	return domains
}

func TestSplitDomainsIntoBatches(t *testing.T) {
	tests := []struct {
		name            string
		domains         []string
		expectedCount   int
		checkAllPresent bool
	}{
		{
			name:          "empty",
			domains:       nil,
			expectedCount: 0,
		},
		{
			name:            "under_limit",
			domains:         generateShortDomains(10),
			expectedCount:   1,
			checkAllPresent: true,
		},
		{
			name:            "at_element_limit",
			domains:         generateShortDomains(50),
			expectedCount:   1,
			checkAllPresent: true,
		},
		{
			name:            "over_element_limit",
			domains:         generateShortDomains(51),
			expectedCount:   2,
			checkAllPresent: true,
		},
		{
			name:            "triple_element_limit",
			domains:         generateShortDomains(150),
			expectedCount:   3,
			checkAllPresent: true,
		},
		{
			name:            "long_domains_hit_byte_limit",
			domains:         generateLongDomains(50),
			checkAllPresent: true,
		},
		{
			name:            "500_short_domains",
			domains:         generateShortDomains(500),
			expectedCount:   10,
			checkAllPresent: true,
		},
		{
			name:            "500_long_domains",
			domains:         generateLongDomains(500),
			checkAllPresent: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			batches := splitDomainsIntoBatches(tc.domains)

			if tc.expectedCount > 0 {
				assert.Len(t, batches, tc.expectedCount, "expected %d batches", tc.expectedCount)
			}

			// Verify each batch respects limits
			for i, batch := range batches {
				assert.LessOrEqual(t, len(batch), maxDomainsPerResolverEntry,
					"batch %d exceeds element limit", i)

				totalBytes := 0
				for j, d := range batch {
					if j > 0 {
						totalBytes++
					}
					totalBytes += len(d)
				}
				assert.LessOrEqual(t, totalBytes, maxDomainBytesPerResolverEntry,
					"batch %d exceeds byte limit (%d bytes)", i, totalBytes)
			}

			if tc.checkAllPresent {
				var all []string
				for _, batch := range batches {
					all = append(all, batch...)
				}
				assert.Equal(t, tc.domains, all, "all domains should be present in order")
			}
		})
	}
}

func TestParseSystemDNSSettings(t *testing.T) {
	tests := []struct {
		name            string
		output          string
		expectedDomains []string
		expectedServers []netip.Addr
		expectedIP      netip.Addr
	}{
		{
			name: "well_formed",
			output: `<dictionary> {
  DomainName : example.com
  SearchDomains : <array> {
    0 : example.com
    1 : corp.example.com
  }
  ServerAddresses : <array> {
    0 : 192.168.1.1
    1 : fd00::53
  }
}
`,
			expectedDomains: []string{"example.com", "example.com", "corp.example.com"},
			expectedServers: []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fd00::53")},
			expectedIP:      netip.MustParseAddr("192.168.1.1"),
		},
		{
			// entries without a value after the separator used to panic with
			// "index out of range [1] with length 1"
			name: "malformed_array_entries_skipped",
			output: `<dictionary> {
  SearchDomains : <array> {
    0 :
    (null)

    1 : corp.example.com
  }
  ServerAddresses : <array> {
    0 :
    1 : 192.168.1.1
  }
}
`,
			expectedDomains: []string{"corp.example.com"},
			expectedServers: []netip.Addr{netip.MustParseAddr("192.168.1.1")},
			expectedIP:      netip.MustParseAddr("192.168.1.1"),
		},
		{
			name: "domain_name_without_value_skipped",
			output: `<dictionary> {
  DomainName :
  ServerAddresses : <array> {
    0 : 192.168.1.1
  }
}
`,
			expectedServers: []netip.Addr{netip.MustParseAddr("192.168.1.1")},
			expectedIP:      netip.MustParseAddr("192.168.1.1"),
		},
		{
			name: "ipv6_first_prefers_ipv4_server_ip",
			output: `<dictionary> {
  ServerAddresses : <array> {
    0 : fd00::53
    1 : 192.168.1.1
  }
}
`,
			expectedServers: []netip.Addr{netip.MustParseAddr("fd00::53"), netip.MustParseAddr("192.168.1.1")},
			expectedIP:      netip.MustParseAddr("192.168.1.1"),
		},
		{
			name: "invalid_and_unspecified_addresses_skipped",
			output: `<dictionary> {
  ServerAddresses : <array> {
    0 : (null)
    1 : 0.0.0.0
    2 : 192.168.1.1
  }
}
`,
			expectedServers: []netip.Addr{netip.MustParseAddr("192.168.1.1")},
			expectedIP:      netip.MustParseAddr("192.168.1.1"),
		},
		{
			name: "v4_mapped_address_unmapped",
			output: `<dictionary> {
  ServerAddresses : <array> {
    0 : ::ffff:192.168.1.1
  }
}
`,
			expectedServers: []netip.Addr{netip.MustParseAddr("192.168.1.1")},
			expectedIP:      netip.MustParseAddr("192.168.1.1"),
		},
		{
			name:   "empty_output",
			output: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			settings, servers, err := parseSystemDNSSettings([]byte(tc.output))
			require.NoError(t, err, "parsing should not fail")

			assert.Equal(t, tc.expectedDomains, settings.Domains, "domains should match")
			assert.Equal(t, tc.expectedServers, servers, "server addresses should match")
			assert.Equal(t, tc.expectedIP, settings.ServerIP, "server IP should match")
			assert.Equal(t, DefaultPort, settings.ServerPort, "server port should default to 53")
		})
	}
}

func TestGetOriginalNameservers(t *testing.T) {
	configurator := &systemConfigurator{
		createdKeys: make(map[string]struct{}),
		origNameservers: []netip.Addr{
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("1.1.1.1"),
		},
	}

	servers := configurator.getOriginalNameservers()
	assert.Len(t, servers, 2)
	assert.Equal(t, netip.MustParseAddr("8.8.8.8"), servers[0])
	assert.Equal(t, netip.MustParseAddr("1.1.1.1"), servers[1])
}
