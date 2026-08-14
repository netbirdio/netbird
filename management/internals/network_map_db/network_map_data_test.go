package networkmapdb

import (
	"database/sql"
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestDomainFromSuffix(t *testing.T) {
	assert.False(t, domainFromSuffix("test", ""))
	assert.False(t, domainFromSuffix("test", "suffix"))               // domain != suffix
	assert.True(t, domainFromSuffix("test", "test"))                  // domain == suffix
	assert.False(t, domainFromSuffix("test.anothersuffix", "suffix")) // domain doesn't contain suffix
	assert.True(t, domainFromSuffix("test.suffix", "suffix"))         // domain contains suffix
}

func TestServiceDomainZone(t *testing.T) {
	// shortcut -- service's domain is a subomain of proxy cluster
	assert.Equal(t, "cluster",
		serviceDomainZone(
			Service{
				Domain:       sql.NullString{Valid: true, String: "test.cluster"},
				ProxyCluster: sql.NullString{Valid: true, String: "cluster"}},
			[]Domain{}))
	assert.Equal(t, "a.b", serviceDomainZone(
		Service{
			Domain:       sql.NullString{Valid: true, String: "test.a.b"},
			ProxyCluster: sql.NullString{Valid: true, String: "cluster"}},
		[]Domain{
			{TargetCluster: sql.NullString{Valid: true, String: "a-cluster"}},
			{TargetCluster: sql.NullString{Valid: true, String: "cluster"},
				Domain: sql.NullString{Valid: true, String: "b"}},
			{TargetCluster: sql.NullString{Valid: true, String: "cluster"},
				Domain: sql.NullString{Valid: true, String: "a.b"}}, // should return this domain, as it's the longest match
			{TargetCluster: sql.NullString{Valid: true, String: "b-cluster"}},
		}))
	// service and domain clusters don't match
	assert.Empty(t, serviceDomainZone(
		Service{
			Domain:       sql.NullString{Valid: true, String: "test.a.b"},
			ProxyCluster: sql.NullString{Valid: true, String: "c-cluster"}},
		[]Domain{
			{TargetCluster: sql.NullString{Valid: true, String: "cluster"},
				Domain: sql.NullString{Valid: true, String: "a.b"}},
		}))
	// service domain is empty
	assert.Empty(t, serviceDomainZone(
		Service{
			Domain:       sql.NullString{Valid: false, String: ""},
			ProxyCluster: sql.NullString{Valid: true, String: "cluster"}},
		[]Domain{
			{TargetCluster: sql.NullString{Valid: true, String: "cluster"},
				Domain: sql.NullString{Valid: true, String: "a.b"}},
		}))
}

func TestRecordForProxyPeer(t *testing.T) {
	record, ok := recordForProxyPeer("test.cluster", netip.MustParseAddr("127.0.0.1"))
	assert.True(t, ok)
	assert.Equal(t, nmdata.SimpleRecord{
		Name:  "test.cluster.",
		Type:  1,
		Class: "IN",
		TTL:   5,
		RData: "127.0.0.1",
	}, record)

	// invalid address
	var addr netip.Addr
	record, ok = recordForProxyPeer("test.cluster", addr)
	assert.False(t, ok)

}

var empty []networkmap.PrivateServiceCandidate

// empty proxyPeersByCluster results in empty []PrivateServiceCandidates
func TestBuildPrivateServiceCandidates_EmptyProxyPeers(t *testing.T) {
	assert.Equal(t, empty, buildPrivateServiceCandidates([]Service{}, []Domain{}, nil))
}

// disabled service returns an empty result
func TestBuildPrivateServiceCandidates_DisabledService(t *testing.T) {
	assert.Equal(t, empty,
		buildPrivateServiceCandidates([]Service{
			{Enabled: sql.NullBool{Valid: true, Bool: false},
				Private:      sql.NullBool{Valid: true, Bool: true},
				AccessGroups: []string{"group-1", "group-2"},
				Domain:       sql.NullString{Valid: true, String: "test.a.b"},
				ProxyCluster: sql.NullString{Valid: true, String: "cluster"}},
		}, []Domain{
			{TargetCluster: sql.NullString{Valid: true, String: "cluster"},
				Domain: sql.NullString{Valid: true, String: "a.b"}},
		},
			map[string][]*nmdata.Peer{
				"cluster":   {&nmdata.Peer{IP: netip.MustParseAddr("127.0.0.1")}, &nmdata.Peer{IP: netip.MustParseAddr("127.0.0.2")}},
				"a-cluster": {&nmdata.Peer{IP: netip.MustParseAddr("127.0.0.3")}, &nmdata.Peer{IP: netip.MustParseAddr("127.0.0.4")}},
			}))
}

// non-private service results in empty []PrivateServiceCandidates
func TestBuildPrivateServiceCandidates_PublicService(t *testing.T) {
	assert.Equal(t, empty,
		buildPrivateServiceCandidates([]Service{
			{Enabled: sql.NullBool{Valid: true, Bool: true},
				Private:      sql.NullBool{Valid: true, Bool: false},
				AccessGroups: []string{"group-1", "group-2"},
				Domain:       sql.NullString{Valid: true, String: "test.a.b"},
				ProxyCluster: sql.NullString{Valid: true, String: "cluster"}},
		}, []Domain{
			{TargetCluster: sql.NullString{Valid: true, String: "cluster"},
				Domain: sql.NullString{Valid: true, String: "a.b"}},
		},
			map[string][]*nmdata.Peer{
				"cluster":   {&nmdata.Peer{IP: netip.MustParseAddr("127.0.0.1")}, &nmdata.Peer{IP: netip.MustParseAddr("127.0.0.2")}},
				"a-cluster": {&nmdata.Peer{IP: netip.MustParseAddr("127.0.0.3")}, &nmdata.Peer{IP: netip.MustParseAddr("127.0.0.4")}},
			}))
}

// empty AccessList results in empty []PrivateServiceCandidates
func TestBuildPrivateServiceCandidates_EmptyAccessList(t *testing.T) {
	assert.Equal(t, empty,
		buildPrivateServiceCandidates([]Service{
			{Enabled: sql.NullBool{Valid: true, Bool: true},
				Private:      sql.NullBool{Valid: true, Bool: true},
				Domain:       sql.NullString{Valid: true, String: "test.a.b"},
				ProxyCluster: sql.NullString{Valid: true, String: "cluster"}},
		}, []Domain{
			{TargetCluster: sql.NullString{Valid: true, String: "cluster"},
				Domain: sql.NullString{Valid: true, String: "a.b"}},
		},
			map[string][]*nmdata.Peer{
				"cluster":   {&nmdata.Peer{IP: netip.MustParseAddr("127.0.0.1")}, &nmdata.Peer{IP: netip.MustParseAddr("127.0.0.2")}},
				"a-cluster": {&nmdata.Peer{IP: netip.MustParseAddr("127.0.0.3")}, &nmdata.Peer{IP: netip.MustParseAddr("127.0.0.4")}},
			}))
}

// empty TragetCluster results in empty []PrivateServiceCandidates
func TestBuildPrivateServiceCandidates_EmptyTargetCluster(t *testing.T) {
	assert.Equal(t, empty,
		buildPrivateServiceCandidates([]Service{
			{Enabled: sql.NullBool{Valid: true, Bool: true},
				Private:      sql.NullBool{Valid: true, Bool: true},
				AccessGroups: []string{"group-1", "group-2"},
				Domain:       sql.NullString{Valid: true, String: "test.a.b"},
				ProxyCluster: sql.NullString{Valid: true, String: "cluster"}},
		}, []Domain{
			{TargetCluster: sql.NullString{Valid: true, String: ""},
				Domain: sql.NullString{Valid: true, String: "a.b"}},
		},
			map[string][]*nmdata.Peer{
				"cluster":   {&nmdata.Peer{IP: netip.MustParseAddr("127.0.0.1")}, &nmdata.Peer{IP: netip.MustParseAddr("127.0.0.2")}},
				"a-cluster": {&nmdata.Peer{IP: netip.MustParseAddr("127.0.0.3")}, &nmdata.Peer{IP: netip.MustParseAddr("127.0.0.4")}},
			}))
}

func TestBuildPrivateServiceCandidates_EmptyServiceDomain(t *testing.T) {
	assert.Equal(t, empty,
		buildPrivateServiceCandidates([]Service{
			{Enabled: sql.NullBool{Valid: true, Bool: true},
				Private:      sql.NullBool{Valid: true, Bool: true},
				Domain:       sql.NullString{Valid: true, String: ""},
				ProxyCluster: sql.NullString{Valid: true, String: "cluster"}},
		}, []Domain{
			{TargetCluster: sql.NullString{Valid: true, String: "cluster"},
				Domain: sql.NullString{Valid: true, String: "a.b"}},
		},
			map[string][]*nmdata.Peer{
				"cluster":   {&nmdata.Peer{IP: netip.MustParseAddr("127.0.0.1")}, &nmdata.Peer{IP: netip.MustParseAddr("127.0.0.2")}},
				"a-cluster": {&nmdata.Peer{IP: netip.MustParseAddr("127.0.0.3")}, &nmdata.Peer{IP: netip.MustParseAddr("127.0.0.4")}},
			}))
}

func TestBuildPrivateServiceCandidates_HappyPath(t *testing.T) {
	assert.Equal(t, []networkmap.PrivateServiceCandidate{
		{
			AccessGroups: []string{"group-1", "group-2"},
			Zone: nmdata.CustomZone{
				Domain:               "a.b.",
				SearchDomainDisabled: true,
				NonAuthoritative:     true,
				Records: []nmdata.SimpleRecord{
					{
						Name:  "test.a.b.",
						Type:  1,
						Class: "IN",
						TTL:   5,
						RData: "127.0.0.1",
					},
					{
						Name:  "test.a.b.",
						Type:  1,
						Class: "IN",
						TTL:   5,
						RData: "127.0.0.2",
					},
				},
			},
		},
		{
			AccessGroups: []string{"group-1", "group-2"},
			Zone: nmdata.CustomZone{
				Domain:               "c.d.",
				SearchDomainDisabled: true,
				NonAuthoritative:     true,
				Records: []nmdata.SimpleRecord{
					{
						Name:  "test.c.d.",
						Type:  1,
						Class: "IN",
						TTL:   5,
						RData: "127.0.0.3",
					},
					{
						Name:  "test.c.d.",
						Type:  1,
						Class: "IN",
						TTL:   5,
						RData: "127.0.0.4",
					},
				},
			},
		},
	},
		buildPrivateServiceCandidates([]Service{
			{Enabled: sql.NullBool{Valid: true, Bool: true},
				Private:      sql.NullBool{Valid: true, Bool: true},
				AccessGroups: []string{"group-1", "group-2"},
				Domain:       sql.NullString{Valid: true, String: "test.a.b"},
				ProxyCluster: sql.NullString{Valid: true, String: "cluster"}},
			{Enabled: sql.NullBool{Valid: true, Bool: true},
				Private:      sql.NullBool{Valid: true, Bool: true},
				AccessGroups: []string{"group-1", "group-2"},
				Domain:       sql.NullString{Valid: true, String: "test.c.d"},
				ProxyCluster: sql.NullString{Valid: true, String: "a-cluster"}},
		}, []Domain{
			{TargetCluster: sql.NullString{Valid: true, String: "cluster"},
				Domain: sql.NullString{Valid: true, String: "a.b"}},
			{TargetCluster: sql.NullString{Valid: true, String: "a-cluster"},
				Domain: sql.NullString{Valid: true, String: "c.d"}},
		},
			map[string][]*nmdata.Peer{
				"cluster":   {&nmdata.Peer{IP: netip.MustParseAddr("127.0.0.1")}, &nmdata.Peer{IP: netip.MustParseAddr("127.0.0.2")}},
				"a-cluster": {&nmdata.Peer{IP: netip.MustParseAddr("127.0.0.3")}, &nmdata.Peer{IP: netip.MustParseAddr("127.0.0.4")}},
			}))
}

// disabled network resource shouldn't be in the resulting map
func TestBuildResourcePolicies_DisabledNetworkResource(t *testing.T) {
	networkResources := []nmdata.NetworkResource{
		{ID: "net-res-1", Enabled: false},
	}
	policies := []nmdata.Policy{
		{ID: "policy-1", Enabled: true},
	}
	resourceToGroupIdx := map[string]map[string]any{}
	policyToDestinationResourceIdx := map[string]map[string]any{
		"policy-1": {
			"net-res-1": struct{}{},
			"net-res-3": struct{}{},
		},
	}
	policyToDestinationGroupIdx := map[string]map[string]any{}

	assert.Empty(t, buildResourcePolicies(
		networkResources, policies, resourceToGroupIdx, policyToDestinationResourceIdx, policyToDestinationGroupIdx))
}

// disabled policy shouldn't be in the resulting map
func TestBuildResourcePolicies_DisabledPolicy(t *testing.T) {
	networkResources := []nmdata.NetworkResource{
		{ID: "net-res-1", Enabled: true},
	}
	policies := []nmdata.Policy{
		{ID: "policy-1", Enabled: false},
	}
	resourceToGroupIdx := map[string]map[string]any{}
	policyToDestinationResourceIdx := map[string]map[string]any{
		"policy-1": {
			"net-res-1": struct{}{},
			"net-res-3": struct{}{},
		},
	}
	policyToDestinationGroupIdx := map[string]map[string]any{}

	assert.Empty(t, buildResourcePolicies(
		networkResources, policies, resourceToGroupIdx, policyToDestinationResourceIdx, policyToDestinationGroupIdx))
}

// build ResourcePolicies via PolicyToDestinationResourceIdx only
func TestBuildResourcePolicies_ViaPolicyToDestinationResourceIdx(t *testing.T) {
	networkResources := []nmdata.NetworkResource{
		{ID: "net-res-1", Enabled: true},
		{ID: "net-res-2", Enabled: true},
		{ID: "net-res-3", Enabled: true},
	}
	policies := []nmdata.Policy{
		{ID: "policy-1", Enabled: true},
		{ID: "policy-2", Enabled: true},
		{ID: "policy-3", Enabled: true},
	}
	resourceToGroupIdx := map[string]map[string]any{}
	policyToDestinationResourceIdx := map[string]map[string]any{
		"policy-1": {
			"net-res-1": struct{}{},
			"net-res-3": struct{}{},
		},
		"policy-2": {
			"net-res-2": struct{}{},
		},
		"policy-3": {
			"net-res-1": struct{}{},
			"net-res-2": struct{}{},
		},
	}
	policyToDestinationGroupIdx := map[string]map[string]any{}

	resourceToPolicies := buildResourcePolicies(
		networkResources, policies, resourceToGroupIdx, policyToDestinationResourceIdx, policyToDestinationGroupIdx)

	assert.Equal(t, map[string][]*nmdata.Policy{
		"net-res-1": {
			{ID: "policy-1", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
		"net-res-2": {
			{ID: "policy-2", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
		"net-res-3": {
			{ID: "policy-1", Enabled: true},
		},
	}, resourceToPolicies)
}

// build ResourcePolicies via PolicyToDestinationGroupIdx only
func TestBuildResourcePolicies_ViaPolicyToDestinationGroupIdx(t *testing.T) {
	networkResources := []nmdata.NetworkResource{
		{ID: "net-res-1", Enabled: true},
		{ID: "net-res-2", Enabled: true},
		{ID: "net-res-3", Enabled: true},
	}
	policies := []nmdata.Policy{
		{ID: "policy-1", Enabled: true},
		{ID: "policy-2", Enabled: true},
		{ID: "policy-3", Enabled: true},
	}
	resourceToGroupIdx := map[string]map[string]any{
		"net-res-1": {
			"group-1": struct{}{},
			"group-2": struct{}{},
		},
		"net-res-2": {
			"group-2": struct{}{},
			"group-3": struct{}{},
		},
		"net-res-3": {
			"group-3": struct{}{},
			"group-4": struct{}{},
		},
	}
	policyToDestinationResourceIdx := map[string]map[string]any{}
	policyToDestinationGroupIdx := map[string]map[string]any{
		"policy-1": {
			"group-1": struct{}{},
			"group-2": struct{}{},
		},
		"policy-2": {
			"group-1": struct{}{},
			"group-4": struct{}{},
		},
		"policy-3": {
			"group-1": struct{}{},
			"group-3": struct{}{},
		},
	}

	resourceToPolicies := buildResourcePolicies(
		networkResources, policies, resourceToGroupIdx, policyToDestinationResourceIdx, policyToDestinationGroupIdx)

	assert.Equal(t, map[string][]*nmdata.Policy{
		"net-res-1": {
			{ID: "policy-1", Enabled: true},
			{ID: "policy-2", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
		"net-res-2": {
			{ID: "policy-1", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
		"net-res-3": {
			{ID: "policy-2", Enabled: true},
			{ID: "policy-3", Enabled: true},
		},
	}, resourceToPolicies)
}
