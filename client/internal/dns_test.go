package internal

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	nbdns "github.com/netbirdio/netbird/dns"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestCreatePTRRecord_IPv4(t *testing.T) {
	record := nbdns.SimpleRecord{
		Name:  "peer1.netbird.cloud.",
		Type:  int(dns.TypeA),
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "100.64.0.5",
	}
	prefix := netip.MustParsePrefix("100.64.0.0/16")

	ptr, ok := createPTRRecord(record, prefix)
	require.True(t, ok)
	assert.Equal(t, "5.0.64.100.in-addr.arpa.", ptr.Name)
	assert.Equal(t, int(dns.TypePTR), ptr.Type)
	assert.Equal(t, "peer1.netbird.cloud.", ptr.RData)
}

func TestCreatePTRRecord_IPv6(t *testing.T) {
	record := nbdns.SimpleRecord{
		Name:  "peer1.netbird.cloud.",
		Type:  int(dns.TypeAAAA),
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "fd00:1234:5678::1",
	}
	prefix := netip.MustParsePrefix("fd00:1234:5678::/48")

	ptr, ok := createPTRRecord(record, prefix)
	require.True(t, ok)
	assert.Equal(t, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.7.6.5.4.3.2.1.0.0.d.f.ip6.arpa.", ptr.Name)
	assert.Equal(t, int(dns.TypePTR), ptr.Type)
	assert.Equal(t, "peer1.netbird.cloud.", ptr.RData)
}

func TestCreatePTRRecord_OutOfRange(t *testing.T) {
	record := nbdns.SimpleRecord{
		Name:  "peer1.netbird.cloud.",
		Type:  int(dns.TypeA),
		RData: "10.0.0.1",
	}
	prefix := netip.MustParsePrefix("100.64.0.0/16")

	_, ok := createPTRRecord(record, prefix)
	assert.False(t, ok)
}

func TestGenerateReverseZoneName_IPv4(t *testing.T) {
	tests := []struct {
		prefix   string
		expected string
	}{
		{"100.64.0.0/16", "64.100.in-addr.arpa."},
		{"10.0.0.0/8", "10.in-addr.arpa."},
		{"192.168.1.0/24", "1.168.192.in-addr.arpa."},
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			zone, err := generateReverseZoneName(netip.MustParsePrefix(tt.prefix))
			require.NoError(t, err)
			assert.Equal(t, tt.expected, zone)
		})
	}
}

func TestGenerateReverseZoneName_IPv6(t *testing.T) {
	tests := []struct {
		prefix   string
		expected string
	}{
		{"fd00:1234:5678::/48", "8.7.6.5.4.3.2.1.0.0.d.f.ip6.arpa."},
		{"fd00::/16", "0.0.d.f.ip6.arpa."},
		{"fd12:3456:789a:bcde::/64", "e.d.c.b.a.9.8.7.6.5.4.3.2.1.d.f.ip6.arpa."},
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			zone, err := generateReverseZoneName(netip.MustParsePrefix(tt.prefix))
			require.NoError(t, err)
			assert.Equal(t, tt.expected, zone)
		})
	}
}

func TestCollectPTRRecords_BothFamilies(t *testing.T) {
	config := &nbdns.Config{
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "netbird.cloud.",
				Records: []nbdns.SimpleRecord{
					{Name: "peer1.netbird.cloud.", Type: int(dns.TypeA), RData: "100.64.0.1"},
					{Name: "peer1.netbird.cloud.", Type: int(dns.TypeAAAA), RData: "fd00::1"},
					{Name: "peer2.netbird.cloud.", Type: int(dns.TypeA), RData: "100.64.0.2"},
				},
			},
		},
	}

	v4Records := collectPTRRecords(config, netip.MustParsePrefix("100.64.0.0/16"))
	assert.Len(t, v4Records, 2, "should collect 2 A record PTRs for the v4 prefix")

	v6Records := collectPTRRecords(config, netip.MustParsePrefix("fd00::/64"))
	assert.Len(t, v6Records, 1, "should collect 1 AAAA record PTR for the v6 prefix")
}

func TestAddReverseZone_IPv6(t *testing.T) {
	config := &nbdns.Config{
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "netbird.cloud.",
				Records: []nbdns.SimpleRecord{
					{Name: "peer1.netbird.cloud.", Type: int(dns.TypeAAAA), RData: "fd00:1234:5678::1"},
				},
			},
		},
	}

	addReverseZone(config, netip.MustParsePrefix("fd00:1234:5678::/48"))

	require.Len(t, config.CustomZones, 2)
	reverseZone := config.CustomZones[1]
	assert.Equal(t, "8.7.6.5.4.3.2.1.0.0.d.f.ip6.arpa.", reverseZone.Domain)
	assert.Len(t, reverseZone.Records, 1)
	assert.Equal(t, int(dns.TypePTR), reverseZone.Records[0].Type)
}

// TestToDNSConfig_ZoneFlagsPreserved pins the per-zone NonAuthoritative flag
// through the legacy DNSConfig path. A non-authoritative zone is match-only:
// the local resolver falls through to the upstream for an in-zone name it does
// not define. The built-in peer zone is the authoritative one and must stay
// that way, so the flag has to travel per zone rather than be derived.
func TestToDNSConfig_ZoneFlagsPreserved(t *testing.T) {
	config := toDNSConfig(&mgmProto.DNSConfig{
		ServiceEnable: true,
		CustomZones: []*mgmProto.CustomZone{
			{
				Domain: "netbird.cloud.",
				Records: []*mgmProto.SimpleRecord{
					{Name: "peer1.netbird.cloud.", Type: int64(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "100.64.0.1"},
				},
			},
			{
				Domain:               "corp.internal.",
				NonAuthoritative:     true,
				SearchDomainDisabled: true,
				Records: []*mgmProto.SimpleRecord{
					{Name: "db.corp.internal.", Type: int64(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.10.0.5"},
				},
			},
		},
	}, wgaddr.Address{
		IP:      netip.MustParseAddr("100.64.0.1"),
		Network: netip.MustParsePrefix("100.64.0.0/16"),
	})

	zones := make(map[string]nbdns.CustomZone, len(config.CustomZones))
	for _, zone := range config.CustomZones {
		zones[zone.Domain] = zone
	}

	peerZone, ok := zones["netbird.cloud."]
	require.True(t, ok, "peer zone must survive")
	assert.False(t, peerZone.NonAuthoritative, "the built-in peer zone owns the account domain and stays authoritative")

	accountZone, ok := zones["corp.internal."]
	require.True(t, ok, "account zone must survive")
	assert.True(t, accountZone.NonAuthoritative, "an account zone stays match-only, else undefined in-zone names get black-holed")
	assert.True(t, accountZone.SearchDomainDisabled)
}

// TestToDNSConfig_SingleZoneForcedAuthoritative pins the compatibility clause
// in toDNSConfig: a config carrying exactly one zone is treated as
// authoritative no matter what the server said, because servers that predate
// the NonAuthoritative field send only the peer FQDN zone.
//
// The clause can only ever downgrade an explicit true to false, so a server
// that legitimately sends a single non-authoritative zone — an account whose
// only zone is a custom one, with no peer records to build the built-in zone
// from — gets that zone's whole apex black-holed on the client. Real accounts
// always carry the peer zone alongside, which is why this is latent. Narrowing
// it needs a way to tell "unset" from "false" on the wire, or the account
// domain passed down here; until then this test states the contract so a
// change to it is deliberate.
func TestToDNSConfig_SingleZoneForcedAuthoritative(t *testing.T) {
	config := toDNSConfig(&mgmProto.DNSConfig{
		ServiceEnable: true,
		CustomZones: []*mgmProto.CustomZone{
			{
				Domain:           "corp.internal.",
				NonAuthoritative: true,
				Records: []*mgmProto.SimpleRecord{
					{Name: "db.corp.internal.", Type: int64(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.10.0.5"},
				},
			},
		},
	}, wgaddr.Address{
		IP:      netip.MustParseAddr("100.64.0.1"),
		Network: netip.MustParsePrefix("100.64.0.0/16"),
	})

	require.NotEmpty(t, config.CustomZones)
	assert.Equal(t, "corp.internal.", config.CustomZones[0].Domain)
	assert.False(t, config.CustomZones[0].NonAuthoritative,
		"a lone zone is forced authoritative for pre-NonAuthoritative servers")

	// The reverse zone the config gains afterwards must not feed back into the
	// decision: the compat gate counts the zones the server sent.
	require.Len(t, config.CustomZones, 2, "a reverse zone is appended for the overlay prefix")
	assert.Equal(t, "64.100.in-addr.arpa.", config.CustomZones[1].Domain)
}
