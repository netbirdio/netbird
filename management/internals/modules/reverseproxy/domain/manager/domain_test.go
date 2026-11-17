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
		{Domain: "example.com", TargetCluster: "eu1.proxy.netbird.io", Validated: true},
		{Domain: "proxy.corp.io", TargetCluster: "us1.proxy.netbird.io", Validated: true},
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
			cluster, match := extractClusterFromCustomDomains(tc.domain, customDomains)
			if !tc.wantOK {
				assert.Equal(t, customDomainNoMatch, match, "unrelated domain should not match any custom domain")
				return
			}
			assert.Equal(t, customDomainValidated, match, "validated custom domain should resolve a cluster")
			assert.Equal(t, tc.wantVal, cluster)
		})
	}
}

// An unvalidated row must never yield a cluster: the account has not shown it
// controls the name, so no service may be bound to it.
func TestExtractClusterFromCustomDomains_UnvalidatedDomainRefused(t *testing.T) {
	customDomains := []*domain.Domain{
		{Domain: "example.com", TargetCluster: "eu1.proxy.netbird.io", Validated: false},
	}

	for _, serviceDomain := range []string{"example.com", "app.example.com"} {
		t.Run(serviceDomain, func(t *testing.T) {
			cluster, match := extractClusterFromCustomDomains(serviceDomain, customDomains)
			assert.Equal(t, customDomainUnvalidated, match, "unvalidated row must be reported as such")
			assert.Empty(t, cluster, "unvalidated row must not resolve a cluster")
		})
	}
}

// A more specific unvalidated row must not shadow a validated parent domain.
func TestExtractClusterFromCustomDomains_ValidatedParentWinsOverUnvalidatedChild(t *testing.T) {
	customDomains := []*domain.Domain{
		{Domain: "example.com", TargetCluster: "cluster-generic", Validated: true},
		{Domain: "app.example.com", TargetCluster: "cluster-app", Validated: false},
	}

	cluster, match := extractClusterFromCustomDomains("app.example.com", customDomains)
	assert.Equal(t, customDomainValidated, match)
	assert.Equal(t, "cluster-generic", cluster, "validated parent domain should provide the cluster")
}

func TestExtractClusterFromCustomDomains_OverlappingDomains(t *testing.T) {
	customDomains := []*domain.Domain{
		{Domain: "example.com", TargetCluster: "cluster-generic", Validated: true},
		{Domain: "app.example.com", TargetCluster: "cluster-app", Validated: true},
	}

	tests := []struct {
		name    string
		domain  string
		wantVal string
	}{
		{
			name:    "exact match on more specific domain",
			domain:  "app.example.com",
			wantVal: "cluster-app",
		},
		{
			name:    "subdomain of more specific domain",
			domain:  "api.app.example.com",
			wantVal: "cluster-app",
		},
		{
			name:    "subdomain of generic domain",
			domain:  "other.example.com",
			wantVal: "cluster-generic",
		},
		{
			name:    "bare generic domain",
			domain:  "example.com",
			wantVal: "cluster-generic",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cluster, match := extractClusterFromCustomDomains(tc.domain, customDomains)
			assert.Equal(t, customDomainValidated, match)
			assert.Equal(t, tc.wantVal, cluster)
		})
	}
}
