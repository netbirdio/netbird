package internal

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
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
