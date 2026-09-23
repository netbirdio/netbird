package networkmap

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

func proxyPeer(id, ip, cluster string, connected bool) *nmdata.Peer {
	return &nmdata.Peer{
		ID: id, Key: id + "-key", IP: netip.MustParseAddr(ip), Connected: connected,
		ProxyMeta: nmdata.ProxyMeta{Embedded: true, Cluster: cluster},
	}
}

func privateService(id, domain, cluster string, groups ...string) *nmdata.Service {
	return &nmdata.Service{
		ID: id, Enabled: true, Private: true, Mode: "http",
		Domain: domain, ProxyCluster: cluster, AccessGroups: groups,
	}
}

func twinWithProxy(services ...*nmdata.Service) *NetworkMapData {
	return &NetworkMapData{
		Peers: map[string]*nmdata.Peer{
			"proxy-1": proxyPeer("proxy-1", "100.64.0.99", "eu.proxy.netbird.io", true),
		},
		Services: services,
	}
}

// An agent-network service is synthesised in memory and never persisted, so it
// only ever reaches the twin through nmd.Services. Deriving the zone from that
// same field is what stops it from arriving with an ACL and no name.
func TestBuildPrivateServiceCandidates_SynthesisedServiceGetsAZone(t *testing.T) {
	nmd := twinWithProxy(privateService(
		"agent-network-acct-1", "acct-1.agent.netbird.io", "eu.proxy.netbird.io", "grp-admins"))

	nmd.BuildPrivateServiceCandidates()

	require.Len(t, nmd.PrivateServiceCandidates, 0,
		"a service whose domain sits under no registered apex publishes nothing")

	nmd.Domains = []nmdata.ProxyDomain{
		{Domain: "agent.netbird.io", TargetCluster: "eu.proxy.netbird.io"},
	}
	nmd.BuildPrivateServiceCandidates()

	require.Len(t, nmd.PrivateServiceCandidates, 1)
	got := nmd.PrivateServiceCandidates[0]
	assert.Equal(t, []string{"grp-admins"}, got.AccessGroups)
	assert.Equal(t, "agent.netbird.io.", got.Zone.Domain, "apex is the registered domain, not the service FQDN")
	assert.True(t, got.Zone.NonAuthoritative, "zone stays match-only")
	assert.True(t, got.Zone.SearchDomainDisabled)
	require.Len(t, got.Zone.Records, 1)
	assert.Equal(t, nmdata.SimpleRecord{
		Name: "acct-1.agent.netbird.io.", Type: 1, Class: "IN", TTL: 5, RData: "100.64.0.99",
	}, got.Zone.Records[0])
}

func TestBuildPrivateServiceCandidates_ClusterApexNeedsNoRegisteredDomain(t *testing.T) {
	nmd := twinWithProxy(privateService("svc-1", "myapp.eu.proxy.netbird.io", "eu.proxy.netbird.io", "grp-admins"))

	nmd.BuildPrivateServiceCandidates()

	require.Len(t, nmd.PrivateServiceCandidates, 1)
	assert.Equal(t, "eu.proxy.netbird.io.", nmd.PrivateServiceCandidates[0].Zone.Domain)
}

func TestBuildPrivateServiceCandidates_LongestRegisteredApexWins(t *testing.T) {
	nmd := twinWithProxy(privateService("svc-1", "app.sub.example.com", "eu.proxy.netbird.io", "grp-admins"))
	nmd.Domains = []nmdata.ProxyDomain{
		{Domain: "example.com", TargetCluster: "eu.proxy.netbird.io"},
		{Domain: "sub.example.com", TargetCluster: "eu.proxy.netbird.io"},
		{Domain: "other.com", TargetCluster: "eu.proxy.netbird.io"},
	}

	nmd.BuildPrivateServiceCandidates()

	require.Len(t, nmd.PrivateServiceCandidates, 1)
	assert.Equal(t, "sub.example.com.", nmd.PrivateServiceCandidates[0].Zone.Domain)
}

func TestBuildPrivateServiceCandidates_RegisteredApexOfAnotherClusterIsIgnored(t *testing.T) {
	nmd := twinWithProxy(privateService("svc-1", "app.example.com", "eu.proxy.netbird.io", "grp-admins"))
	nmd.Domains = []nmdata.ProxyDomain{
		{Domain: "example.com", TargetCluster: "us.proxy.netbird.io"},
	}

	nmd.BuildPrivateServiceCandidates()

	assert.Empty(t, nmd.PrivateServiceCandidates)
}

// A disconnected proxy peer's tunnel IP does not answer, so publishing it
// black-holes the name for as long as a client caches the record.
func TestBuildPrivateServiceCandidates_OnlyConnectedProxyPeersSurface(t *testing.T) {
	nmd := twinWithProxy(privateService("svc-1", "myapp.eu.proxy.netbird.io", "eu.proxy.netbird.io", "grp-admins"))
	nmd.Peers["proxy-2"] = proxyPeer("proxy-2", "100.64.0.100", "eu.proxy.netbird.io", false)

	nmd.BuildPrivateServiceCandidates()

	require.Len(t, nmd.PrivateServiceCandidates, 1)
	require.Len(t, nmd.PrivateServiceCandidates[0].Zone.Records, 1)
	assert.Equal(t, "100.64.0.99", nmd.PrivateServiceCandidates[0].Zone.Records[0].RData)

	nmd.Peers["proxy-1"].Connected = false
	nmd.BuildPrivateServiceCandidates()
	assert.Empty(t, nmd.PrivateServiceCandidates, "no connected proxy peer means no zone at all")
}

func TestBuildPrivateServiceCandidates_SkipsServicesThatGrantNothing(t *testing.T) {
	cases := map[string]func(*nmdata.Service){
		"disabled":         func(s *nmdata.Service) { s.Enabled = false },
		"not private":      func(s *nmdata.Service) { s.Private = false },
		"no access groups": func(s *nmdata.Service) { s.AccessGroups = nil },
		"no domain":        func(s *nmdata.Service) { s.Domain = "" },
		"other cluster":    func(s *nmdata.Service) { s.ProxyCluster = "us.proxy.netbird.io" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			svc := privateService("svc-1", "myapp.eu.proxy.netbird.io", "eu.proxy.netbird.io", "grp-admins")
			mutate(svc)
			nmd := twinWithProxy(svc)

			nmd.BuildPrivateServiceCandidates()

			assert.Empty(t, nmd.PrivateServiceCandidates)
		})
	}
}

func TestBuildPrivateServiceCandidates_MultipleConnectedProxyPeersEachGetARecord(t *testing.T) {
	nmd := twinWithProxy(privateService("svc-1", "myapp.eu.proxy.netbird.io", "eu.proxy.netbird.io", "grp-admins"))
	nmd.Peers["proxy-2"] = proxyPeer("proxy-2", "100.64.0.100", "eu.proxy.netbird.io", true)

	nmd.BuildPrivateServiceCandidates()

	require.Len(t, nmd.PrivateServiceCandidates, 1)
	records := nmd.PrivateServiceCandidates[0].Zone.Records
	require.Len(t, records, 2)
	assert.Equal(t, "100.64.0.99", records[0].RData, "records are ordered by proxy peer id")
	assert.Equal(t, "100.64.0.100", records[1].RData)
}
