package manager

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
)

func TestExtractClusterFromFreeDomain(t *testing.T) {
	clusters := []string{"eu1.proxy.netbird.io", "us1.proxy.netbird.io"}

	tests := []struct {
		name    string
		domain  string
		wantOK  bool
		wantVal string
	}{
		{
			name:    "subdomain of cluster matches",
			domain:  "myapp.eu1.proxy.netbird.io",
			wantOK:  true,
			wantVal: "eu1.proxy.netbird.io",
		},
		{
			name:    "deep subdomain of cluster matches",
			domain:  "foo.bar.eu1.proxy.netbird.io",
			wantOK:  true,
			wantVal: "eu1.proxy.netbird.io",
		},
		{
			name:    "bare cluster domain matches",
			domain:  "eu1.proxy.netbird.io",
			wantOK:  true,
			wantVal: "eu1.proxy.netbird.io",
		},
		{
			name:   "unrelated domain does not match",
			domain: "example.com",
			wantOK: false,
		},
		{
			name:   "partial suffix does not match",
			domain: "fakeu1.proxy.netbird.io",
			wantOK: false,
		},
		{
			name:    "second cluster matches",
			domain:  "app.us1.proxy.netbird.io",
			wantOK:  true,
			wantVal: "us1.proxy.netbird.io",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cluster, ok := ExtractClusterFromFreeDomain(tc.domain, clusters)
			assert.Equal(t, tc.wantOK, ok)
			if ok {
				assert.Equal(t, tc.wantVal, cluster)
			}
		})
	}
}

func TestExtractClusterFromCustomDomains(t *testing.T) {
	customDomains := []*domain.Domain{
		{Domain: "example.com", TargetCluster: "eu1.proxy.netbird.io"},
		{Domain: "proxy.corp.io", TargetCluster: "us1.proxy.netbird.io"},
	}

	tests := []struct {
		name    string
		domain  string
		wantOK  bool
		wantVal string
	}{
		{
			name:    "subdomain of custom domain matches",
			domain:  "app.example.com",
			wantOK:  true,
			wantVal: "eu1.proxy.netbird.io",
		},
		{
			name:    "bare custom domain matches",
			domain:  "example.com",
			wantOK:  true,
			wantVal: "eu1.proxy.netbird.io",
		},
		{
			name:    "deep subdomain of custom domain matches",
			domain:  "a.b.example.com",
			wantOK:  true,
			wantVal: "eu1.proxy.netbird.io",
		},
		{
			name:    "subdomain of multi-level custom domain matches",
			domain:  "app.proxy.corp.io",
			wantOK:  true,
			wantVal: "us1.proxy.netbird.io",
		},
		{
			name:    "bare multi-level custom domain matches",
			domain:  "proxy.corp.io",
			wantOK:  true,
			wantVal: "us1.proxy.netbird.io",
		},
		{
			name:   "unrelated domain does not match",
			domain: "other.com",
			wantOK: false,
		},
		{
			name:   "partial suffix does not match custom domain",
			domain: "fakeexample.com",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cluster, ok := extractClusterFromCustomDomains(tc.domain, customDomains)
			assert.Equal(t, tc.wantOK, ok)
			if ok {
				assert.Equal(t, tc.wantVal, cluster)
			}
		})
	}
}
