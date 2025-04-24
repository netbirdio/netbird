package dnsfwd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/route"
)

func Test_getMatchingEntries(t *testing.T) {
	testCases := []struct {
		name           string
		storedMappings map[string]route.ResID // key: domain pattern, value: resId
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
			queryDomain:    "foo.notexample.com",
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
