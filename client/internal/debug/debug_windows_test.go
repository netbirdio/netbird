//go:build windows

package debug

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/anonymize"
)

func newDNSValueGenerator(level anonymize.Level) *BundleGenerator {
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())
	anonymizer.SetLevel(level)

	return &BundleGenerator{
		anonymize:      true,
		anonymizeLevel: level,
		anonymizer:     anonymizer,
	}
}

// TestAnonymizeValueByName covers the value kinds of the DNS registry keys. The
// names decide the treatment, because the string pass alone replaces only
// domains another part of the bundle already seeded.
func TestAnonymizeValueByName(t *testing.T) {
	tests := []struct {
		name      string
		valueName string
		value     string
		assert    func(t *testing.T, got string)
	}{
		{
			name:      "NRPT match domains keep the leading dot",
			valueName: "Name",
			value:     ".internal.example.com, .corp.example.org",
			assert: func(t *testing.T, got string) {
				t.Helper()
				for _, entry := range strings.Split(got, ", ") {
					assert.True(t, strings.HasPrefix(entry, "."), "entry %q should keep its leading dot", entry)
					assert.NotContains(t, entry, "example", "entry %q should not keep the original domain", entry)
				}
			},
		},
		{
			name:      "any value name ending in Domain is treated as a domain",
			valueName: "ICSDomain",
			value:     "mshome.net",
			assert: func(t *testing.T, got string) {
				t.Helper()
				assert.NotContains(t, got, "mshome", "should anonymize a domain suffix value")
			},
		},
		{
			name:      "search list is a comma separated domain list",
			valueName: "SearchList",
			value:     "corp.example.com,branch.example.com",
			assert: func(t *testing.T, got string) {
				t.Helper()
				assert.NotContains(t, got, "example", "should anonymize every search domain")
				assert.Len(t, strings.Split(got, ", "), 2, "should keep both search domains")
			},
		},
		{
			name:      "name servers are anonymized as addresses",
			valueName: "DhcpNameServer",
			value:     "203.0.113.10 8.8.8.8",
			assert: func(t *testing.T, got string) {
				t.Helper()
				assert.NotContains(t, got, "203.0.113.10", "should anonymize a public resolver address")
				// well-known resolvers stay readable at every level
				assert.Contains(t, got, "8.8.8.8", "should keep a well-known resolver address")
			},
		},
		{
			name:      "opaque values are left to the string pass",
			valueName: "DataBasePath",
			value:     `%SystemRoot%\System32\drivers\etc`,
			assert: func(t *testing.T, got string) {
				t.Helper()
				assert.Equal(t, `%SystemRoot%\System32\drivers\etc`, got, "should not alter a path")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := newDNSValueGenerator(anonymize.LevelDefault)
			tc.assert(t, g.anonymizeValue(tc.valueName, tc.value))
		})
	}
}

// TestParseNRPTPolicyTable parses the MOF text of the policy table out
// parameters, as the provider on a client with one NRPT rule renders it.
func TestParseNRPTPolicyTable(t *testing.T) {
	const text = `[abstract]
class __PARAMETERS
{
	[Out, EmbeddedInstance("DnsClientPolicyConfiguration"): ToSubClass, ID(2): DisableOverride ToInstance] DnsClientPolicyConfiguration cmdletOutput[] = {
instance of DnsClientPolicyConfiguration
{
	DirectAccessProxyType = "NoProxy";
	DirectAccessQueryIPsecRequired = FALSE;
	NameEncoding = "Utf8WithoutMapping";
	Namespace = ".0.100.in-addr.arpa";
}, 
instance of DnsClientPolicyConfiguration
{
	DirectAccessProxyType = "NoProxy";
	NameEncoding = "Utf8WithoutMapping";
	NameServers = {"100.0.255.254", "100.0.255.253"};
	Namespace = ".nb.internal";
}};
	[in] boolean Effective;
	[out] uint32 ReturnValue = 0;
};
`

	entries := parseNRPTPolicyTable(text)
	require.Len(t, entries, 2, "should parse both embedded instances")

	assert.Equal(t, ".0.100.in-addr.arpa", entries[0].namespace, "should read the namespace of the first instance")
	assert.Equal(t, ".nb.internal", entries[1].namespace, "should read the namespace of the second instance")

	assert.Equal(t, []registryValue{
		{name: "DirectAccessProxyType", value: "NoProxy"},
		{name: "DirectAccessQueryIPsecRequired", value: "FALSE"},
		{name: "NameEncoding", value: "Utf8WithoutMapping"},
	}, entries[0].values, "should keep the remaining values in order")

	assert.Contains(t, entries[1].values, registryValue{name: "NameServers", value: "100.0.255.254, 100.0.255.253"},
		"should flatten a MOF array")

	for _, value := range entries[1].values {
		assert.NotContains(t, value.name, "ReturnValue", "should not read the class level parameters as values")
	}
}

func TestParseNRPTPolicyTableEmpty(t *testing.T) {
	assert.Empty(t, parseNRPTPolicyTable(""), "should parse no entries from empty text")
	assert.Empty(t, parseNRPTPolicyTable("class __PARAMETERS\n{\n};\n"), "should parse no entries from a table with no instances")
}
