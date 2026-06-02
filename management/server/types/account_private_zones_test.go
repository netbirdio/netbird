package types

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func privateZoneTestAccount(t *testing.T) *Account {
	t.Helper()
	return &Account{
		Id:       "acct-1",
		Settings: &Settings{},
		Network: &Network{
			Identifier: "net-1",
			Net:        net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.CIDRMask(10, 32)},
		},
		Peers: map[string]*nbpeer.Peer{
			"user-peer": {
				ID:        "user-peer",
				AccountID: "acct-1",
				Key:       "user-peer-key",
				IP:        netip.MustParseAddr("100.64.0.10"),
				Status:    &nbpeer.PeerStatus{Connected: true},
			},
			"proxy-peer": {
				ID:        "proxy-peer",
				AccountID: "acct-1",
				Key:       "proxy-peer-key",
				IP:        netip.MustParseAddr("100.64.0.99"),
				Status:    &nbpeer.PeerStatus{Connected: true},
				ProxyMeta: nbpeer.ProxyMeta{
					Embedded: true,
					Cluster:  "eu.proxy.netbird.io",
				},
			},
		},
		Groups: map[string]*Group{
			"grp-admins": {
				ID:    "grp-admins",
				Name:  "admins",
				Peers: []string{"user-peer"},
			},
		},
		Services: []*service.Service{
			{
				ID:           "svc-1",
				AccountID:    "acct-1",
				Name:         "myapp",
				Domain:       "myapp.eu.proxy.netbird.io",
				ProxyCluster: "eu.proxy.netbird.io",
				Enabled:      true,
				Private:      true,
				Mode:         service.ModeHTTP,
				AccessGroups: []string{"grp-admins"},
			},
		},
	}
}

func TestSynthesizePrivateServiceZones_PeerInGroup_GetsRecord(t *testing.T) {
	account := privateZoneTestAccount(t)

	zones := account.SynthesizePrivateServiceZones("user-peer")
	require.Len(t, zones, 1, "one cluster should produce one zone")
	zone := zones[0]
	assert.Equal(t, "eu.proxy.netbird.io.", zone.Domain, "zone apex must be the cluster FQDN")
	assert.True(t, zone.NonAuthoritative, "synth zone must be match-only so unrelated sibling names fall through to the upstream resolver")
	require.Len(t, zone.Records, 1, "one private service yields one A record")
	rec := zone.Records[0]
	assert.Equal(t, "myapp.eu.proxy.netbird.io.", rec.Name, "record name is the service FQDN")
	assert.Equal(t, int(dns.TypeA), rec.Type, "record type must be A")
	assert.Equal(t, "100.64.0.99", rec.RData, "record points at the embedded proxy peer's tunnel IP")
	assert.Equal(t, privateServiceDNSRecordTTL, rec.TTL, "TTL must match the synth-records constant")
	assert.Equal(t, nbdns.DefaultClass, rec.Class, "record class must be the package default")
}

func TestSynthesizePrivateServiceZones_PeerNotInGroup_NoRecord(t *testing.T) {
	account := privateZoneTestAccount(t)
	account.Groups["grp-admins"].Peers = nil

	zones := account.SynthesizePrivateServiceZones("user-peer")
	assert.Empty(t, zones, "peer outside distribution_groups must not see private-service records")
}

func TestSynthesizePrivateServiceZones_NotPrivate_NoRecord(t *testing.T) {
	account := privateZoneTestAccount(t)
	account.Services[0].Private = false

	zones := account.SynthesizePrivateServiceZones("user-peer")
	assert.Empty(t, zones, "non-private service must not produce DNS records")
}

func TestSynthesizePrivateServiceZones_NoAccessGroups_NoRecord(t *testing.T) {
	account := privateZoneTestAccount(t)
	account.Services[0].AccessGroups = nil

	zones := account.SynthesizePrivateServiceZones("user-peer")
	assert.Empty(t, zones, "private service without bearer auth must not produce DNS records")
}

func TestSynthesizePrivateServiceZones_NoProxyPeers_NoRecord(t *testing.T) {
	account := privateZoneTestAccount(t)
	delete(account.Peers, "proxy-peer")

	zones := account.SynthesizePrivateServiceZones("user-peer")
	assert.Empty(t, zones, "no embedded proxy peer in cluster means no record to emit")
}

func TestSynthesizePrivateServiceZones_DisabledService_NoRecord(t *testing.T) {
	account := privateZoneTestAccount(t)
	account.Services[0].Enabled = false

	zones := account.SynthesizePrivateServiceZones("user-peer")
	assert.Empty(t, zones, "disabled service must not produce DNS records")
}

func TestSynthesizePrivateServiceZones_DisconnectedProxyPeer_NoRecord(t *testing.T) {
	account := privateZoneTestAccount(t)
	account.Peers["proxy-peer"].Status = &nbpeer.PeerStatus{Connected: false}

	zones := account.SynthesizePrivateServiceZones("user-peer")
	assert.Empty(t, zones, "disconnected proxy peer must not produce a DNS record (would be a black hole)")
}

func TestSynthesizePrivateServiceZones_PartiallyDisconnectedProxyPeers_OnlyConnectedSurface(t *testing.T) {
	account := privateZoneTestAccount(t)
	account.Peers["proxy-peer-2"] = &nbpeer.Peer{
		ID:        "proxy-peer-2",
		AccountID: "acct-1",
		Key:       "proxy-peer-2-key",
		IP:        netip.MustParseAddr("100.64.0.100"),
		Status:    &nbpeer.PeerStatus{Connected: false},
		ProxyMeta: nbpeer.ProxyMeta{Embedded: true, Cluster: "eu.proxy.netbird.io"},
	}

	zones := account.SynthesizePrivateServiceZones("user-peer")
	require.Len(t, zones, 1)
	require.Len(t, zones[0].Records, 1, "only the connected proxy peer must surface")
	assert.Equal(t, "100.64.0.99", zones[0].Records[0].RData)
}

func TestSynthesizePrivateServiceZones_MultipleProxyPeers_RoundRobin(t *testing.T) {
	account := privateZoneTestAccount(t)
	account.Peers["proxy-peer-2"] = &nbpeer.Peer{
		ID:        "proxy-peer-2",
		AccountID: "acct-1",
		Key:       "proxy-peer-2-key",
		IP:        netip.MustParseAddr("100.64.0.100"),
		Status:    &nbpeer.PeerStatus{Connected: true},
		ProxyMeta: nbpeer.ProxyMeta{Embedded: true, Cluster: "eu.proxy.netbird.io"},
	}

	zones := account.SynthesizePrivateServiceZones("user-peer")
	require.Len(t, zones, 1, "still one cluster yields one zone")
	require.Len(t, zones[0].Records, 2, "two proxy peers must produce two A records on the same name")
	rdata := []string{zones[0].Records[0].RData, zones[0].Records[1].RData}
	assert.ElementsMatch(t, []string{"100.64.0.99", "100.64.0.100"}, rdata, "both proxy peer IPs must surface")
}

// findCustomZone returns the CustomZone whose Domain equals the FQDN
// of want, or a zero value when not found. Tests use it to assert
// that the synth zone reaches dnsUpdate.CustomZones end-to-end.
func findCustomZone(zones []nbdns.CustomZone, want string) (nbdns.CustomZone, bool) {
	wantFqdn := dns.Fqdn(want)
	for _, z := range zones {
		if z.Domain == wantFqdn {
			return z, true
		}
	}
	return nbdns.CustomZone{}, false
}

// TestPrivateZone_GetPeerNetworkMapFromComponents_ShipsSynthZone
// covers the components-based builder path. The components builder
// appends SynthesizePrivateServiceZones to AccountZones; the
// CalculateNetworkMapFromComponents step then merges AccountZones
// into dnsUpdate.CustomZones.
func TestPrivateZone_GetPeerNetworkMapFromComponents_ShipsSynthZone(t *testing.T) {
	account := privateZoneTestAccount(t)
	ctx := context.Background()
	validated := map[string]struct{}{
		"user-peer":  {},
		"proxy-peer": {},
	}

	nm := account.GetPeerNetworkMapFromComponents(ctx, "user-peer", nbdns.CustomZone{}, nil, validated, nil, nil, nil, nil)
	require.NotNil(t, nm, "network map must be produced for an in-account peer")

	zone, ok := findCustomZone(nm.DNSConfig.CustomZones, "eu.proxy.netbird.io")
	require.True(t, ok, "shipped CustomZones must include the synth zone for the cluster")
	require.Len(t, zone.Records, 1, "exactly one record per private service per connected proxy peer")
	rec := zone.Records[0]
	assert.Equal(t, "myapp.eu.proxy.netbird.io.", rec.Name, "record name is the service FQDN")
	assert.Equal(t, "100.64.0.99", rec.RData, "record points at the embedded proxy peer's tunnel IP")
}

// TestPrivateZone_GetPeerNetworkMap_PeerOutsideGroups_OmitsSynthZone
// confirms the negative case the user encountered: a peer whose
// groups don't overlap the policy's distribution_groups gets a
// network map with no synth zone (and the wildcard / peer zones still
// flow through). This is the test mirror of the runtime confusion
// where the user looked at a non-distribution-group peer and assumed
// the synth path was broken.
func TestPrivateZone_GetPeerNetworkMap_PeerOutsideGroups_OmitsSynthZone(t *testing.T) {
	account := privateZoneTestAccount(t)
	account.Peers["outsider"] = &nbpeer.Peer{
		ID:        "outsider",
		AccountID: "acct-1",
		Key:       "outsider-key",
		IP:        netip.MustParseAddr("100.64.0.20"),
		Status:    &nbpeer.PeerStatus{Connected: true},
	}
	ctx := context.Background()
	validated := map[string]struct{}{
		"user-peer":  {},
		"proxy-peer": {},
		"outsider":   {},
	}

	nm := account.GetPeerNetworkMapFromComponents(ctx, "outsider", nbdns.CustomZone{}, nil, validated, nil, nil, nil, nil)
	require.NotNil(t, nm)

	_, ok := findCustomZone(nm.DNSConfig.CustomZones, "eu.proxy.netbird.io")
	assert.False(t, ok, "peer outside the distribution_groups must not see the synth zone")
}

func TestSynthesizePrivateServiceZones_TwoServicesSameCluster_OneZone(t *testing.T) {
	account := privateZoneTestAccount(t)
	account.Services = append(account.Services, &service.Service{
		ID:           "svc-2",
		AccountID:    "acct-1",
		Name:         "anotherapp",
		Domain:       "anotherapp.eu.proxy.netbird.io",
		ProxyCluster: "eu.proxy.netbird.io",
		Enabled:      true,
		Private:      true,
		Mode:         service.ModeHTTP,
		AccessGroups: []string{"grp-admins"},
	})

	zones := account.SynthesizePrivateServiceZones("user-peer")
	require.Len(t, zones, 1, "two services on the same cluster must collapse into one zone")
	require.Len(t, zones[0].Records, 2, "two services yield two A records")
	names := []string{zones[0].Records[0].Name, zones[0].Records[1].Name}
	assert.ElementsMatch(t, []string{"myapp.eu.proxy.netbird.io.", "anotherapp.eu.proxy.netbird.io."}, names, "both service domains must surface")
}
