package anonymize_test

import (
	"net/netip"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/anonymize"
)

func TestAnonymizeIP(t *testing.T) {
	startIPv4 := netip.MustParseAddr("198.51.100.0")
	startIPv6 := netip.MustParseAddr("100::")
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
		{"First Public IPv6", "2607:f8b0:4005:805::200e", "100::"},
		{"Second Public IPv6", "a::b", "100::1"},
		{"Repeated IPv6", "2607:f8b0:4005:805::200e", "100::"},
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
			expect: "Access attempted from 100::",
		},
		{
			name:   "IPv6 Address with Port",
			input:  "Access attempted from [2001:db8::ff00:42]:8080",
			expect: "Access attempted from [100::]:8080",
		},
		{
			name:   "Both IPv4 and IPv6",
			input:  "IPv4: 142.108.0.1 and IPv6: 2001:db8::ff00:43",
			expect: "IPv4: 198.51.100.1 and IPv6: 100::1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := anonymizer.AnonymizeString(tc.input)
			assert.Equal(t, tc.expect, result, "IP addresses should be anonymized correctly")
		})
	}
}
