package manager

import (
	"testing"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
)

func TestExtractClusterFromCustomDomains(t *testing.T) {
	tests := map[string]struct {
		host          string
		customDomains []*domain.Domain
		wantCluster   string
		wantOK        bool
	}{
		"exact non-wildcard match": {
			host: "example.com",
			customDomains: []*domain.Domain{
				{Domain: "example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"wildcard matches subdomain": {
			host: "app.example.com",
			customDomains: []*domain.Domain{
				{Domain: "*.example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"wildcard matches apex": {
			host: "example.com",
			customDomains: []*domain.Domain{
				{Domain: "*.example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"non-wildcard matches subdomain": {
			host: "app.example.com",
			customDomains: []*domain.Domain{
				{Domain: "example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"exact non-wildcard beats wildcard": {
			host: "example.com",
			customDomains: []*domain.Domain{
				{Domain: "*.example.com", TargetCluster: "cluster-wild"},
				{Domain: "example.com", TargetCluster: "cluster-exact"},
			},
			wantCluster: "cluster-exact",
			wantOK:      true,
		},
		"longest wildcard suffix wins": {
			host: "app.sub.example.com",
			customDomains: []*domain.Domain{
				{Domain: "*.example.com", TargetCluster: "cluster-short"},
				{Domain: "*.sub.example.com", TargetCluster: "cluster-long"},
			},
			wantCluster: "cluster-long",
			wantOK:      true,
		},
		"longest non-wildcard suffix wins": {
			host: "app.sub.example.com",
			customDomains: []*domain.Domain{
				{Domain: "example.com", TargetCluster: "cluster-short"},
				{Domain: "sub.example.com", TargetCluster: "cluster-long"},
			},
			wantCluster: "cluster-long",
			wantOK:      true,
		},
		"trailing dot on host is normalized": {
			host: "example.com.",
			customDomains: []*domain.Domain{
				{Domain: "example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"trailing dot on custom domain is normalized": {
			host: "example.com",
			customDomains: []*domain.Domain{
				{Domain: "example.com.", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"case insensitive match": {
			host: "APP.Example.COM",
			customDomains: []*domain.Domain{
				{Domain: "*.example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"no match returns false": {
			host: "other.com",
			customDomains: []*domain.Domain{
				{Domain: "example.com", TargetCluster: "cluster-a"},
				{Domain: "*.example.com", TargetCluster: "cluster-b"},
			},
			wantCluster: "",
			wantOK:      false,
		},
		"empty custom domains returns false": {
			host:          "example.com",
			customDomains: nil,
			wantCluster:   "",
			wantOK:        false,
		},
		"partial suffix does not match": {
			host: "notexample.com",
			customDomains: []*domain.Domain{
				{Domain: "example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "",
			wantOK:      false,
		},
		"wildcard does not match partial suffix": {
			host: "notexample.com",
			customDomains: []*domain.Domain{
				{Domain: "*.example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "",
			wantOK:      false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cluster, ok := extractClusterFromCustomDomains(tc.host, tc.customDomains)
			if ok != tc.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tc.wantOK)
			}
			if cluster != tc.wantCluster {
				t.Errorf("cluster: got %q, want %q", cluster, tc.wantCluster)
			}
		})
	}
}
