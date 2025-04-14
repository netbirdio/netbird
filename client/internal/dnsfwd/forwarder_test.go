package dnsfwd

import (
	"sync"
	"testing"
)

func TestGetResIdForDomain(t *testing.T) {
	testCases := []struct {
		name           string
		storedMappings map[string]string // key: domain pattern, value: resId
		queryDomain    string
		expectedResId  string
	}{
		{
			name:           "Empty map returns empty string",
			storedMappings: map[string]string{},
			queryDomain:    "example.com",
			expectedResId:  "",
		},
		{
			name:           "Exact match returns stored resId",
			storedMappings: map[string]string{"example.com": "res1"},
			queryDomain:    "example.com",
			expectedResId:  "res1",
		},
		{
			name:           "Wildcard pattern matches base domain",
			storedMappings: map[string]string{"*.example.com": "res2"},
			queryDomain:    "example.com",
			expectedResId:  "res2",
		},
		{
			name:           "Wildcard pattern matches subdomain",
			storedMappings: map[string]string{"*.example.com": "res3"},
			queryDomain:    "foo.example.com",
			expectedResId:  "res3",
		},
		{
			name:           "Wildcard pattern does not match different domain",
			storedMappings: map[string]string{"*.example.com": "res4"},
			queryDomain:    "foo.notexample.com",
			expectedResId:  "",
		},
		{
			name:           "Non-wildcard pattern does not match subdomain",
			storedMappings: map[string]string{"example.com": "res5"},
			queryDomain:    "foo.example.com",
			expectedResId:  "",
		},
		{
			name: "Exact match over overlapping wildcard",
			storedMappings: map[string]string{
				"*.example.com":   "resWildcard",
				"foo.example.com": "resExact",
			},
			queryDomain:   "foo.example.com",
			expectedResId: "resExact",
		},
		{
			name: "Overlapping wildcards: Select more specific wildcard",
			storedMappings: map[string]string{
				"*.example.com":     "resA",
				"*.sub.example.com": "resB",
			},
			queryDomain:   "bar.sub.example.com",
			expectedResId: "resB",
		},
		{
			name: "Wildcard multi-level subdomain match",
			storedMappings: map[string]string{
				"*.example.com": "resMulti",
			},
			queryDomain:   "a.b.example.com",
			expectedResId: "resMulti",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fwd := &DNSForwarder{
				fwdEntries: sync.Map{},
			}

			for domainPattern, resId := range tc.storedMappings {
				fwd.fwdEntries.Store(domainPattern, resId)
			}

			got := fwd.getMatchingEntries(tc.queryDomain)
			if got != tc.expectedResId {
				t.Errorf("For query domain %q, expected resId %q, but got %q", tc.queryDomain, tc.expectedResId, got)
			}
		})
	}
}
