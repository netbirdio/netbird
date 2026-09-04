package anonymize_test

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/anonymize"
)

func TestAnonymizeIP(t *testing.T) {
	startIPv4 := netip.MustParseAddr("198.51.100.0")
	startIPv6 := netip.MustParseAddr("2001:db8:ffff::")
	anonymizer := anonymize.NewAnonymizer(startIPv4, startIPv6)

	tests := []struct {
		name   string
		ip     string
		expect string
	}{
		{"Well known", "8.8.8.8", "8.8.8.8"},
		{"First Public IPv4", "1.2.3.4", "198.51.100.0"},
		{"Second Public IPv4", "4.3.2.1", "198.51.100.1"},
		{"Repeated IPv4", "1.2.3.4", "198.51.100.0"},
		{"Private IPv4", "192.168.1.1", "192.168.1.1"},
		{"First Public IPv6", "2607:f8b0:4005:805::200e", "2001:db8:ffff::"},
		{"Second Public IPv6", "a::b", "2001:db8:ffff::1"},
		{"Repeated IPv6", "2607:f8b0:4005:805::200e", "2001:db8:ffff::"},
		{"Private IPv6", "fe80::1", "fe80::1"},
		{"In Range IPv4", "198.51.100.2", "198.51.100.2"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := netip.MustParseAddr(tc.ip)
			anonymizedIP := anonymizer.AnonymizeIP(ip)
			if anonymizedIP.String() != tc.expect {
				t.Errorf("%s: expected %s, got %s", tc.name, tc.expect, anonymizedIP)
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input  string
		expect anonymize.Level
	}{
		{"", anonymize.LevelDefault},
		{"default", anonymize.LevelDefault},
		{"DEFAULT", anonymize.LevelDefault},
		{"strict", anonymize.LevelStrict},
		{"STRICT", anonymize.LevelStrict},
		// Unknown values must never yield less anonymization than requested.
		{"garbage", anonymize.LevelStrict},
	}

	for _, tc := range tests {
		t.Run("input="+tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expect, anonymize.ParseLevel(tc.input), "parsed level should match")
		})
	}
}

func TestAnonymizeIP_DefaultLevelInternalRanges(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())

	tests := []struct {
		name   string
		ip     string
		expect string
	}{
		{"RFC1918 10/8", "10.1.2.3", "10.1.2.3"},
		{"RFC1918 172.16/12", "172.16.5.5", "172.16.5.5"},
		{"RFC1918 192.168/16", "192.168.1.1", "192.168.1.1"},
		{"CGNAT", "100.64.0.5", "100.64.0.5"},
		{"IPv4 link-local", "169.254.1.1", "169.254.1.1"},
		{"IPv6 link-local", "fe80::1", "fe80::1"},
		// ULA is anonymized even at the default level: its random global ID
		// uniquely fingerprints the network, unlike shared RFC 1918 space.
		{"IPv6 ULA", "fd12:3456:789a::1", "2001:db8:ffff::"},
		// 4-in-6 addresses classify like their unmapped IPv4 form.
		{"4-in-6 RFC1918", "::ffff:192.168.1.1", "192.168.1.1"},
		{"4-in-6 CGNAT", "::ffff:100.64.0.5", "100.64.0.5"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := anonymizer.AnonymizeIP(netip.MustParseAddr(tc.ip))
			assert.Equal(t, tc.expect, result.String(), "default level should preserve internal ranges except ULA")
		})
	}
}

func TestAnonymizeIP_StrictLevel(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
	anonymizer.SetLevel(anonymize.LevelStrict)

	// Order matters: internal pool addresses are assigned sequentially.
	tests := []struct {
		name   string
		ip     string
		expect string
	}{
		{"RFC1918 192.168/16", "192.168.1.1", "198.18.0.0"},
		{"Second RFC1918", "192.168.1.2", "198.18.0.1"},
		{"Repeated RFC1918", "192.168.1.1", "198.18.0.0"},
		{"RFC1918 10/8", "10.1.2.3", "198.18.0.2"},
		{"RFC1918 172.16/12", "172.16.5.5", "198.18.0.3"},
		{"CGNAT", "100.64.0.5", "198.18.0.4"},
		{"IPv4 link-local", "169.254.1.1", "198.18.0.5"},
		{"Public IPv4 uses public pool", "1.2.3.4", "198.51.100.0"},
		{"IPv6 link-local", "fe80::1", "2001:db8:1::"},
		{"IPv6 ULA", "fd12:3456:789a::1", "2001:db8:1::1"},
		{"Public IPv6 uses public pool", "2607:f8b0:4005:805::200e", "2001:db8:ffff::"},
		{"Loopback IPv4", "127.0.0.1", "127.0.0.1"},
		{"Loopback IPv6", "::1", "::1"},
		{"Unspecified", "0.0.0.0", "0.0.0.0"},
		{"Multicast", "224.0.0.251", "224.0.0.251"},
		{"Well known resolver", "8.8.8.8", "8.8.8.8"},
		{"Well known split marker", "128.0.0.0", "128.0.0.0"},
		{"In internal pool range", "198.18.0.3", "198.18.0.3"},
		{"In public pool range", "198.51.100.0", "198.51.100.0"},
		{"4-in-6 repeated RFC1918", "::ffff:192.168.1.1", "198.18.0.0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := anonymizer.AnonymizeIP(netip.MustParseAddr(tc.ip))
			assert.Equal(t, tc.expect, result.String(), "strict level should replace internal ranges from the internal pools")
		})
	}
}

func TestAnonymizeString_StrictInternalIPs(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
	anonymizer.SetLevel(anonymize.LevelStrict)

	input := "route 10.20.30.0/24 via 192.168.1.1 dev eth0 src 100.64.0.7"
	firstPass := anonymizer.AnonymizeString(input)
	secondPass := anonymizer.AnonymizeString(firstPass)

	assert.NotContains(t, firstPass, "10.20.30.0", "private network address should be anonymized")
	assert.NotContains(t, firstPass, "192.168.1.1", "private gateway should be anonymized")
	assert.NotContains(t, firstPass, "100.64.0.7", "CGNAT address should be anonymized")
	assert.Contains(t, firstPass, "/24", "prefix length should be preserved")
	assert.Equal(t, firstPass, secondPass, "second pass should not further anonymize the string")
}

func TestAnonymizeMAC(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())

	first := anonymizer.AnonymizeMAC("aa:bb:cc:dd:ee:0f")
	assert.Equal(t, "02:00:00:00:00:01", first, "first MAC should get the first placeholder")
	assert.Equal(t, first, anonymizer.AnonymizeMAC("aa:bb:cc:dd:ee:0f"), "repeated MAC should map to the same placeholder")
	assert.Equal(t, first, anonymizer.AnonymizeMAC("AA:BB:CC:DD:EE:0F"), "case should not affect the mapping")
	assert.Equal(t, "02-00-00-00-00-01", anonymizer.AnonymizeMAC("AA-BB-CC-DD-EE-0F"), "dash form should keep its separator but share the mapping")

	second := anonymizer.AnonymizeMAC("10:22:33:44:55:66")
	assert.Equal(t, "02:00:00:00:00:02", second, "second distinct MAC should get the next placeholder")

	tests := []struct {
		name string
		mac  string
	}{
		{"Broadcast", "ff:ff:ff:ff:ff:ff"},
		{"IPv4 multicast", "01:00:5e:00:00:fb"},
		{"IPv6 multicast", "33:33:00:00:00:01"},
		{"All zero", "00:00:00:00:00:00"},
		{"Assigned placeholder", "02:00:00:00:00:01"},
		{"Invalid", "not-a-mac"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.mac, anonymizer.AnonymizeMAC(tc.mac), "should be preserved")
		})
	}
}

func TestAnonymizeString_MACAddresses(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())

	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "nftables ether rule",
			input:  "ether saddr aa:bb:cc:dd:ee:ff drop",
			expect: "ether saddr 02:00:00:00:00:01 drop",
		},
		{
			name:   "Windows dash form",
			input:  "Physical Address : AA-BB-CC-DD-EE-FF",
			expect: "Physical Address : 02-00-00-00-00-01",
		},
		{
			name:   "IPv6 address tail is not treated as MAC",
			input:  "addr fe80:0:11:22:33:44:55:66 scope link",
			expect: "addr fe80:0:11:22:33:44:55:66 scope link",
		},
		{
			name:   "broadcast MAC preserved",
			input:  "dst ff:ff:ff:ff:ff:ff type ARP",
			expect: "dst ff:ff:ff:ff:ff:ff type ARP",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := anonymizer.AnonymizeString(tc.input)
			assert.Equal(t, tc.expect, result, "MAC addresses should be anonymized at every level")
			assert.Equal(t, result, anonymizer.AnonymizeString(result), "second pass should not change the result")
		})
	}
}

func TestAnonymizeWGKey(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))

	t.Run("default level preserves keys", func(t *testing.T) {
		anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
		assert.Equal(t, key, anonymizer.AnonymizeWGKey(key), "default level should not touch WireGuard keys")
	})

	t.Run("strict level replaces keys", func(t *testing.T) {
		anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
		anonymizer.SetLevel(anonymize.LevelStrict)

		anon := anonymizer.AnonymizeWGKey(key)
		assert.NotEqual(t, key, anon, "strict level should replace the key")
		assert.Regexp(t, `^[A-Za-z0-9+/]{43}=$`, anon, "placeholder should keep the WireGuard key shape")
		assert.Equal(t, anon, anonymizer.AnonymizeWGKey(key), "repeated key should map to the same placeholder")
		assert.Equal(t, anon, anonymizer.AnonymizeWGKey(anon), "an assigned placeholder should pass through unchanged")

		assert.Equal(t, "not-a-key", anonymizer.AnonymizeWGKey("not-a-key"), "non-key values should be preserved")
	})
}

func TestAnonymizeString_WGKeys(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	input := "peer " + key + " handshake completed"

	t.Run("default level preserves keys", func(t *testing.T) {
		anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
		assert.Equal(t, input, anonymizer.AnonymizeString(input), "default level should not touch WireGuard keys in strings")
	})

	t.Run("strict level replaces keys", func(t *testing.T) {
		anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
		anonymizer.SetLevel(anonymize.LevelStrict)

		firstPass := anonymizer.AnonymizeString(input)
		assert.NotContains(t, firstPass, key, "the key should not survive strict anonymization")
		assert.Equal(t, anonymizer.AnonymizeWGKey(key), extractKey(t, firstPass), "string replacement should be consistent with AnonymizeWGKey")
		assert.Equal(t, firstPass, anonymizer.AnonymizeString(firstPass), "second pass should not change the result")
	})
}

func extractKey(t *testing.T, logLine string) string {
	t.Helper()
	fields := strings.Fields(logLine)
	require.Len(t, fields, 4, "log line should keep its structure")
	return fields[1]
}

func TestAnonymizeDomain_StrictLevel(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
	anonymizer.SetLevel(anonymize.LevelStrict)

	t.Run("netbird peer name", func(t *testing.T) {
		result := anonymizer.AnonymizeDomain("my-laptop.netbird.cloud")
		assert.Regexp(t, `^peer-\d+\.netbird\.cloud$`, result, "peer name should be anonymized, suffix kept")
		assert.NotContains(t, result, "my-laptop", "the peer name should not survive")
		assert.Equal(t, result, anonymizer.AnonymizeDomain("my-laptop.netbird.cloud"), "repeated domain should map consistently")
		assert.Equal(t, result, anonymizer.AnonymizeDomain(result), "an anonymized domain should pass through unchanged")
	})

	t.Run("bare netbird domain", func(t *testing.T) {
		assert.Equal(t, "netbird.cloud", anonymizer.AnonymizeDomain("netbird.cloud"), "the bare protected suffix should be preserved")
	})

	t.Run("netbird infrastructure preserved", func(t *testing.T) {
		assert.Equal(t, "api.netbird.io", anonymizer.AnonymizeDomain("api.netbird.io"),
			"netbird.io hosts infrastructure, not peer names, and should stay readable")
	})

	t.Run("leading labels of other domains", func(t *testing.T) {
		result := anonymizer.AnonymizeDomain("host1.corp.example.com")
		assert.Regexp(t, `^host-\d+\.host-\d+\.anon-[a-zA-Z0-9]+\.domain$`, result, "every label should be anonymized")
		for _, label := range []string{"host1", "corp", "example"} {
			assert.NotContains(t, result, label, "no original label should survive")
		}
		assert.Equal(t, result, anonymizer.AnonymizeDomain("host1.corp.example.com"), "repeated domain should map consistently")
	})

	t.Run("same label maps consistently across domains", func(t *testing.T) {
		first := anonymizer.AnonymizeDomain("shared.one.com")
		second := anonymizer.AnonymizeDomain("shared.two.com")
		assert.Equal(t, strings.Split(first, ".")[0], strings.Split(second, ".")[0], "the shared host label should get one placeholder")
	})

	t.Run("wildcard label preserved", func(t *testing.T) {
		result := anonymizer.AnonymizeDomain("*.example.com")
		assert.Regexp(t, `^\*\.anon-[a-zA-Z0-9]+\.domain$`, result, "the wildcard label should stay a wildcard")
	})
}

// TestAnonymizeDomain_WildcardSharesBase covers both orders because the base
// mapping is created by whichever form is seen first.
func TestAnonymizeDomain_WildcardSharesBase(t *testing.T) {
	for _, level := range []anonymize.Level{anonymize.LevelDefault, anonymize.LevelStrict} {
		t.Run(level.String(), func(t *testing.T) {
			t.Run("wildcard first", func(t *testing.T) {
				anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
				anonymizer.SetLevel(level)

				wildcard := anonymizer.AnonymizeDomain("*.example.org")
				bare := anonymizer.AnonymizeDomain("example.org")
				assert.Equal(t, "*."+bare, wildcard, "the wildcard form should be the bare anon domain behind a kept *.")
				assert.NotContains(t, wildcard, "example", "the original base should not survive")
			})

			t.Run("bare first", func(t *testing.T) {
				anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
				anonymizer.SetLevel(level)

				bare := anonymizer.AnonymizeDomain("example.org")
				wildcard := anonymizer.AnonymizeDomain("*.example.org")
				assert.Equal(t, "*."+bare, wildcard, "the wildcard form should be the bare anon domain behind a kept *.")
			})

			t.Run("in a log line", func(t *testing.T) {
				anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
				anonymizer.SetLevel(level)

				bare := anonymizer.AnonymizeDomain("example.org")
				line := `{"Domains": ["*.example.org", "example.org"]}`
				result := anonymizer.AnonymizeString(line)
				assert.Equal(t, `{"Domains": ["*.`+bare+`", "`+bare+`"]}`, result,
					"both forms in a log line should share one anon base and keep the wildcard prefix")
			})
		})
	}
}

// TestAnonymizeDomain_SingleLabelZone covers a custom zone whose name is a
// single label, as a bundle's DNS config can carry. Such a name has no
// two-label base to key on, so it used to pass through in the clear.
func TestAnonymizeDomain_SingleLabelZone(t *testing.T) {
	for _, level := range []anonymize.Level{anonymize.LevelDefault, anonymize.LevelStrict} {
		t.Run(level.String(), func(t *testing.T) {
			t.Run("zone name is anonymized", func(t *testing.T) {
				anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
				anonymizer.SetLevel(level)

				zone := anonymizer.AnonymizeDomainName("corp.")
				assert.Regexp(t, `^anon-[a-zA-Z0-9]+\.domain\.$`, zone, "a single-label zone should be anonymized and keep its trailing dot")
			})

			t.Run("names under the zone share its base", func(t *testing.T) {
				anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
				anonymizer.SetLevel(level)

				// The bundle generator anonymizes the zone before its records.
				zone := anonymizer.AnonymizeDomainName("corp")
				record := anonymizer.AnonymizeDomainName("host.corp")
				assert.True(t, strings.HasSuffix(record, "."+zone), "a record under the zone should keep the zone's anon base, got %q for zone %q", record, zone)
				assert.NotContains(t, record, "corp", "the original zone name should not survive")
			})

			t.Run("consistent regardless of order", func(t *testing.T) {
				anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
				anonymizer.SetLevel(level)

				first := anonymizer.AnonymizeDomainName("corp")
				second := anonymizer.AnonymizeDomainName("corp")
				assert.Equal(t, first, second, "the same zone should map consistently")
			})
		})
	}
}

// TestAnonymizeString_KnownZoneInLogLine covers the bundle order: the DNS
// config establishes the zone, then log lines naming it are anonymized through
// the domain= key even though the name carries no dot of its own.
func TestAnonymizeString_KnownZoneInLogLine(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())

	zone := anonymizer.AnonymizeDomainName("corp.")
	line := "adding handler pattern: domain=corp. original: domain=corp. priority=75"

	result := anonymizer.AnonymizeString(line)
	assert.Equal(t, "adding handler pattern: domain="+zone+" original: domain="+zone+" priority=75", result,
		"a log line naming a known zone should carry the zone's anon domain")
	assert.NotContains(t, result, "corp", "the original zone name should not survive")
}

// TestAnonymizeDomain_UnknownSingleLabelUntouched pins that free text reaching
// AnonymizeDomain is left alone. Values that are not domains at all (an address,
// an internal placeholder) arrive here, so a bare label is only anonymized once
// something that knows it is a DNS name has established it as a zone.
func TestAnonymizeDomain_UnknownSingleLabelUntouched(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())

	assert.Equal(t, "corp", anonymizer.AnonymizeDomain("corp"), "an unknown bare label should pass through")
	assert.Equal(t, "localhost", anonymizer.AnonymizeDomainName("localhost"), "localhost identifies nothing and should pass through")
	assert.Equal(t, "2001:db8:ffff::", anonymizer.AnonymizeDomain("2001:db8:ffff::"), "an address form should pass through")
}

// TestAnonymizeString_SingleLabelNotSubstringReplaced pins that a single-label
// mapping is never applied as a bare substring: it has no dot to anchor it, so
// doing so would corrupt any longer word containing it.
func TestAnonymizeString_SingleLabelNotSubstringReplaced(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())

	anonymizer.AnonymizeDomainName("corp")
	anonBase := anonymizer.AnonymizeDomainName("corpsite.example")

	result := anonymizer.AnonymizeString("reaching corpsite.example over corporation")
	assert.Equal(t, "reaching "+anonBase+" over corporation", result,
		"the single-label mapping should not rewrite longer words that contain it")
}

func TestAnonymizeDomain_DefaultLevelKeepsPeerNames(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())

	assert.Equal(t, "my-laptop.netbird.cloud", anonymizer.AnonymizeDomain("my-laptop.netbird.cloud"),
		"default level should preserve netbird FQDNs including the peer name")
	assert.Regexp(t, `^sub\.anon-[a-zA-Z0-9]+\.domain$`, anonymizer.AnonymizeDomain("sub.example.com"),
		"default level should keep subdomain labels")
}

func TestAnonymizeString_StrictPeerNames(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
	anonymizer.SetLevel(anonymize.LevelStrict)

	// Seed like the bundle generator does from the status: base first, then
	// the full FQDN, so replacement must prefer the longer mapping.
	anonBase := anonymizer.AnonymizeDomain("example.com")
	anonPeer := anonymizer.AnonymizeDomain("peer1.netbird.cloud")
	anonHost := anonymizer.AnonymizeDomain("host1.example.com")

	logLine := "connected to peer1.netbird.cloud via host1.example.com endpoint"
	firstPass := anonymizer.AnonymizeString(logLine)
	assert.NotContains(t, firstPass, "peer1", "the peer name should not survive in logs")
	assert.NotContains(t, firstPass, "host1", "the host label should not survive in logs")
	assert.Contains(t, firstPass, anonPeer, "the seeded peer mapping should be applied")
	assert.Contains(t, firstPass, anonHost, "the seeded host mapping should be applied, not just the base mapping")
	assert.NotContains(t, firstPass, "host1."+anonBase, "the base mapping must not preempt the longer FQDN mapping")
	assert.Equal(t, firstPass, anonymizer.AnonymizeString(firstPass), "second pass should not change the result")
}

func TestAnonymizeDNSLogLine(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(netip.Addr{}, netip.Addr{})
	tests := []struct {
		name     string
		input    string
		original string
		expect   string
	}{
		{
			name:     "Basic domain with trailing content",
			input:    "received DNS request for DNS forwarder: domain=example.com: something happened with code=123",
			original: "example.com",
			expect:   `received DNS request for DNS forwarder: domain=anon-[a-zA-Z0-9]+\.domain: something happened with code=123`,
		},
		{
			name:     "Domain with trailing dot",
			input:    "domain=example.com. processing request with status=pending",
			original: "example.com",
			expect:   `domain=anon-[a-zA-Z0-9]+\.domain\. processing request with status=pending`,
		},
		{
			name:     "Multiple domains in log",
			input:    "forward domain=first.com status=ok, redirect to domain=second.com port=443",
			original: "first.com", // testing just one is sufficient as AnonymizeDomain is tested separately
			expect:   `forward domain=anon-[a-zA-Z0-9]+\.domain status=ok, redirect to domain=anon-[a-zA-Z0-9]+\.domain port=443`,
		},
		{
			name:     "Already anonymized domain",
			input:    "got request domain=anon-xyz123.domain from=client1 to=server2",
			original: "", // nothing should be anonymized
			expect:   `got request domain=anon-xyz123\.domain from=client1 to=server2`,
		},
		{
			name:     "Subdomain with trailing dot",
			input:    "domain=sub.example.com. next_hop=10.0.0.1 proto=udp",
			original: "example.com",
			expect:   `domain=sub\.anon-[a-zA-Z0-9]+\.domain\. next_hop=10\.0\.0\.1 proto=udp`,
		},
		{
			name:     "Handler chain pattern log",
			input:    "pattern: domain=example.com. original: domain=*.example.com. wildcard=true priority=100",
			original: "example.com",
			expect:   `pattern: domain=anon-[a-zA-Z0-9]+\.domain\. original: domain=\*\.anon-[a-zA-Z0-9]+\.domain\. wildcard=true priority=100`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := anonymizer.AnonymizeDNSLogLine(tc.input)
			if tc.original != "" {
				assert.NotContains(t, result, tc.original)
			}
			assert.Regexp(t, tc.expect, result)
		})
	}
}

func TestAnonymizeDomain(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(netip.Addr{}, netip.Addr{})
	tests := []struct {
		name            string
		domain          string
		expectPattern   string
		shouldAnonymize bool
	}{
		{
			"General Domain",
			"example.com",
			`^anon-[a-zA-Z0-9]+\.domain$`,
			true,
		},
		{
			"Domain with Trailing Dot",
			"example.com.",
			`^anon-[a-zA-Z0-9]+\.domain.$`,
			true,
		},
		{
			"Subdomain",
			"sub.example.com",
			`^sub\.anon-[a-zA-Z0-9]+\.domain$`,
			true,
		},
		{
			"Subdomain with Trailing Dot",
			"sub.example.com.",
			`^sub\.anon-[a-zA-Z0-9]+\.domain.$`,
			true,
		},
		{
			"Protected Domain",
			"netbird.io",
			`^netbird\.io$`,
			false,
		},
		{
			"Protected Domain with Trailing Dot",
			"netbird.io.",
			`^netbird\.io.$`,
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := anonymizer.AnonymizeDomain(tc.domain)
			if tc.shouldAnonymize {
				assert.Regexp(t, tc.expectPattern, result, "The anonymized domain should match the expected pattern")
				assert.NotContains(t, result, tc.domain, "The original domain should not be present in the result")
			} else {
				assert.Equal(t, tc.domain, result, "Protected domains should not be anonymized")
			}
		})
	}
}

func TestAnonymizeURI(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(netip.Addr{}, netip.Addr{})
	tests := []struct {
		name  string
		uri   string
		regex string
	}{
		{
			"HTTP URI with Port",
			"http://example.com:80/path",
			`^http://anon-[a-zA-Z0-9]+\.domain:80/path$`,
		},
		{
			"HTTP URI without Port",
			"http://example.com/path",
			`^http://anon-[a-zA-Z0-9]+\.domain/path$`,
		},
		{
			"Opaque URI with Port",
			"stun:example.com:80?transport=udp",
			`^stun:anon-[a-zA-Z0-9]+\.domain:80\?transport=udp$`,
		},
		{
			"Opaque URI without Port",
			"stun:example.com?transport=udp",
			`^stun:anon-[a-zA-Z0-9]+\.domain\?transport=udp$`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := anonymizer.AnonymizeURI(tc.uri)
			assert.Regexp(t, regexp.MustCompile(tc.regex), result, "URI should match expected pattern")
			require.NotContains(t, result, "example.com", "Original domain should not be present")
		})
	}
}

func TestAnonymizeSchemeURI(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(netip.Addr{}, netip.Addr{})
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"STUN URI in text", "Connection made via stun:example.com", `Connection made via stun:anon-[a-zA-Z0-9]+\.domain`},
		{"STUNS URI in message", "Secure connection to stuns:example.com:443", `Secure connection to stuns:anon-[a-zA-Z0-9]+\.domain:443`},
		{"TURN URI in log", "Failed attempt turn:some.example.com:3478?transport=tcp: retrying", `Failed attempt turn:some.anon-[a-zA-Z0-9]+\.domain:3478\?transport=tcp: retrying`},
		{"TURNS URI in message", "Secure connection to turns:example.com:5349", `Secure connection to turns:anon-[a-zA-Z0-9]+\.domain:5349`},
		{"HTTP URI in text", "Visit http://example.com for more", `Visit http://anon-[a-zA-Z0-9]+\.domain for more`},
		{"HTTPS URI in CAPS", "Visit HTTPS://example.com for more", `Visit https://anon-[a-zA-Z0-9]+\.domain for more`},
		{"HTTPS URI in message", "Visit https://example.com for more", `Visit https://anon-[a-zA-Z0-9]+\.domain for more`},
		{"WS URI in log", "Connection established to ws://example.com:8080", `Connection established to ws://anon-[a-zA-Z0-9]+\.domain:8080`},
		{"WSS URI in message", "Secure connection to wss://example.com", `Secure connection to wss://anon-[a-zA-Z0-9]+\.domain`},
		{"Rel URI in text", "Relaying to rel://example.com", `Relaying to rel://anon-[a-zA-Z0-9]+\.domain`},
		{"Rels URI in message", "Relaying to rels://example.com", `Relaying to rels://anon-[a-zA-Z0-9]+\.domain`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := anonymizer.AnonymizeSchemeURI(tc.input)
			assert.Regexp(t, tc.expect, result, "The anonymized output should match expected pattern")
			require.NotContains(t, result, "example.com", "Original domain should not be present")
		})
	}
}

func TestAnonymizString_MemorizedDomain(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(netip.Addr{}, netip.Addr{})
	domain := "example.com"
	anonymizedDomain := anonymizer.AnonymizeDomain(domain)

	sampleString := "This is a test string including the domain example.com which should be anonymized."

	firstPassResult := anonymizer.AnonymizeString(sampleString)
	secondPassResult := anonymizer.AnonymizeString(firstPassResult)

	assert.Contains(t, firstPassResult, anonymizedDomain, "The domain should be anonymized in the first pass")
	assert.NotContains(t, firstPassResult, domain, "The original domain should not appear in the first pass output")

	assert.Equal(t, firstPassResult, secondPassResult, "The second pass should not further anonymize the string")
}

func TestAnonymizeString_DoubleURI(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(netip.Addr{}, netip.Addr{})
	domain := "example.com"
	anonymizedDomain := anonymizer.AnonymizeDomain(domain)

	sampleString := "Check out our site at https://example.com for more info."

	firstPassResult := anonymizer.AnonymizeString(sampleString)
	secondPassResult := anonymizer.AnonymizeString(firstPassResult)

	assert.Contains(t, firstPassResult, "https://"+anonymizedDomain, "The URI should be anonymized in the first pass")
	assert.NotContains(t, firstPassResult, "https://example.com", "The original URI should not appear in the first pass output")

	assert.Equal(t, firstPassResult, secondPassResult, "The second pass should not further anonymize the URI")
}

func TestAnonymizeString_IPAddresses(t *testing.T) {
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "IPv4 Address",
			input:  "Error occurred at IP 122.138.1.1",
			expect: "Error occurred at IP 198.51.100.0",
		},
		{
			name:   "IPv6 Address",
			input:  "Access attempted from 2001:db8::ff00:42",
			expect: "Access attempted from 2001:db8:ffff::",
		},
		{
			name:   "IPv6 Address with Port",
			input:  "Access attempted from [2001:db8::ff00:42]:8080",
			expect: "Access attempted from [2001:db8:ffff::]:8080",
		},
		{
			name:   "Both IPv4 and IPv6",
			input:  "IPv4: 142.108.0.1 and IPv6: 2001:db8::ff00:43",
			expect: "IPv4: 198.51.100.1 and IPv6: 2001:db8:ffff::1",
		},
		{
			name:   "STUN URI with IPv6",
			input:  "Connecting to stun:[2001:db8::ff00:42]:3478",
			expect: "Connecting to stun:[2001:db8:ffff::]:3478",
		},
		{
			name:   "HTTPS URI with IPv6",
			input:  "Visit https://[2001:db8::ff00:42]:443/path",
			expect: "Visit https://[2001:db8:ffff::]:443/path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := anonymizer.AnonymizeString(tc.input)
			assert.Equal(t, tc.expect, result, "IP addresses should be anonymized correctly")
		})
	}
}
