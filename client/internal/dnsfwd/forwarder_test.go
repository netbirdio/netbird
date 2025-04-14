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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new DNSForwarder with an initialized sync.Map.
			fwd := &DNSForwarder{
				resId: sync.Map{},
			}

			// Prepopulate the resId map with the test mappings.
			for domainPattern, resId := range tc.storedMappings {
				fwd.resId.Store(domainPattern, resId)
			}

			// Get the result using the query domain.
			got := fwd.getResIdForDomain(tc.queryDomain)
			if got != tc.expectedResId {
				t.Errorf("For query domain %q, expected resId %q, but got %q", tc.queryDomain, tc.expectedResId, got)
			}
		})
	}
}
