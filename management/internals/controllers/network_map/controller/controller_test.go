package controller

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestComputeForwarderPort(t *testing.T) {
	// Test with empty peers list
	peers := []*nbpeer.Peer{}
	result := computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for empty peers list, got %d", network_map.OldForwarderPort, result)
	}

	// Test with peers that have old versions
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.57.0",
			},
		},
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.26.0",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with old versions, got %d", network_map.OldForwarderPort, result)
	}

	// Test with peers that have new versions
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.59.0",
			},
		},
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.59.0",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.DnsForwarderPort) {
		t.Errorf("Expected %d for peers with new versions, got %d", network_map.DnsForwarderPort, result)
	}

	// Test with peers that have mixed versions
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.59.0",
			},
		},
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "0.57.0",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with mixed versions, got %d", network_map.OldForwarderPort, result)
	}

	// Test with peers that have empty version
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with empty version, got %d", network_map.OldForwarderPort, result)
	}

	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "development",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result == int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with dev version, got %d", network_map.DnsForwarderPort, result)
	}

	// Test with peers that have unknown version string
	peers = []*nbpeer.Peer{
		{
			Meta: nbpeer.PeerSystemMeta{
				WtVersion: "unknown",
			},
		},
	}
	result = computeForwarderPort(peers, "v0.59.0")
	if result != int64(network_map.OldForwarderPort) {
		t.Errorf("Expected %d for peers with unknown version, got %d", network_map.OldForwarderPort, result)
	}
}

func TestController_filterPeerAppliedZones(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		accountZones []*zones.Zone
		peerGroups   types.LookupMap
		expected     []nbdns.CustomZone
	}{
		{
			name:         "empty peer groups returns empty custom zones",
			accountZones: []*zones.Zone{},
			peerGroups:   types.LookupMap{},
			expected:     []nbdns.CustomZone{},
		},
		{
			name: "peer has access to zone with A record",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "example.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.example.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: types.LookupMap{"group1": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "example.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.example.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
		{
			name: "peer has access to zone with search domain enabled",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "internal.local",
					Enabled:            true,
					EnableSearchDomain: true,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "api.internal.local",
							Type:    records.RecordTypeA,
							Content: "10.0.0.1",
							TTL:     600,
						},
					},
				},
			},
			peerGroups: types.LookupMap{"group1": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "internal.local.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "api.internal.local.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   600,
							RData: "10.0.0.1",
						},
					},
					SearchDomainDisabled: false,
				},
			},
		},
		{
			name: "peer has no access to zone",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "private.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group2"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "secret.private.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: types.LookupMap{"group1": struct{}{}},
			expected:   []nbdns.CustomZone{},
		},
		{
			name: "disabled zone is filtered out",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "disabled.com",
					Enabled:            false,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.disabled.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: types.LookupMap{"group1": struct{}{}},
			expected:   []nbdns.CustomZone{},
		},
		{
			name: "zone with no records is filtered out",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "empty.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records:            []*records.Record{},
				},
			},
			peerGroups: types.LookupMap{"group1": struct{}{}},
			expected:   []nbdns.CustomZone{},
		},
		{
			name: "peer has access via multiple groups",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "multi.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1", "group2", "group3"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.multi.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: types.LookupMap{"group2": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "multi.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.multi.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
		{
			name: "multiple zones with mixed access",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "allowed.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.allowed.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
				{
					ID:                 "zone2",
					Domain:             "denied.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group2"},
					Records: []*records.Record{
						{
							ID:      "record2",
							Name:    "www.denied.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.2",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: types.LookupMap{"group1": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "allowed.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.allowed.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
		{
			name: "zone with multiple record types",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "mixed.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.mixed.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
						{
							ID:      "record2",
							Name:    "ipv6.mixed.com",
							Type:    records.RecordTypeAAAA,
							Content: "2001:db8::1",
							TTL:     600,
						},
						{
							ID:      "record3",
							Name:    "alias.mixed.com",
							Type:    records.RecordTypeCNAME,
							Content: "www.mixed.com",
							TTL:     900,
						},
					},
				},
			},
			peerGroups: types.LookupMap{"group1": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "mixed.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.mixed.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
						{
							Name:  "ipv6.mixed.com.",
							Type:  int(dns.TypeAAAA),
							Class: nbdns.DefaultClass,
							TTL:   600,
							RData: "2001:db8::1",
						},
						{
							Name:  "alias.mixed.com.",
							Type:  int(dns.TypeCNAME),
							Class: nbdns.DefaultClass,
							TTL:   900,
							RData: "www.mixed.com",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
		{
			name: "multiple zones both accessible",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "first.com",
					Enabled:            true,
					EnableSearchDomain: true,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.first.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
				{
					ID:                 "zone2",
					Domain:             "second.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record2",
							Name:    "www.second.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.2",
							TTL:     600,
						},
					},
				},
			},
			peerGroups: types.LookupMap{"group1": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "first.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.first.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
					},
					SearchDomainDisabled: false,
				},
				{
					Domain: "second.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.second.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   600,
							RData: "192.168.1.2",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
		{
			name: "zone with multiple records of same type",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "multi-a.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.multi-a.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
						{
							ID:      "record2",
							Name:    "www.multi-a.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.2",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: types.LookupMap{"group1": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "multi-a.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.multi-a.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
						{
							Name:  "www.multi-a.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.2",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
		{
			name: "peer in multiple groups accessing different zones",
			accountZones: []*zones.Zone{
				{
					ID:                 "zone1",
					Domain:             "zone1.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group1"},
					Records: []*records.Record{
						{
							ID:      "record1",
							Name:    "www.zone1.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.1",
							TTL:     300,
						},
					},
				},
				{
					ID:                 "zone2",
					Domain:             "zone2.com",
					Enabled:            true,
					EnableSearchDomain: false,
					DistributionGroups: []string{"group2"},
					Records: []*records.Record{
						{
							ID:      "record2",
							Name:    "www.zone2.com",
							Type:    records.RecordTypeA,
							Content: "192.168.1.2",
							TTL:     300,
						},
					},
				},
			},
			peerGroups: types.LookupMap{"group1": struct{}{}, "group2": struct{}{}},
			expected: []nbdns.CustomZone{
				{
					Domain: "zone1.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.zone1.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.1",
						},
					},
					SearchDomainDisabled: true,
				},
				{
					Domain: "zone2.com.",
					Records: []nbdns.SimpleRecord{
						{
							Name:  "www.zone2.com.",
							Type:  int(dns.TypeA),
							Class: nbdns.DefaultClass,
							TTL:   300,
							RData: "192.168.1.2",
						},
					},
					SearchDomainDisabled: true,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterPeerAppliedZones(ctx, tt.accountZones, tt.peerGroups)
			require.Equal(t, len(tt.expected), len(result), "number of custom zones should match")

			for i, expectedZone := range tt.expected {
				assert.Equal(t, expectedZone.Domain, result[i].Domain, "domain should match")
				assert.Equal(t, expectedZone.SearchDomainDisabled, result[i].SearchDomainDisabled, "search domain disabled flag should match")
				assert.Equal(t, len(expectedZone.Records), len(result[i].Records), "number of records should match")

				for j, expectedRecord := range expectedZone.Records {
					assert.Equal(t, expectedRecord.Name, result[i].Records[j].Name, "record name should match")
					assert.Equal(t, expectedRecord.Type, result[i].Records[j].Type, "record type should match")
					assert.Equal(t, expectedRecord.Class, result[i].Records[j].Class, "record class should match")
					assert.Equal(t, expectedRecord.TTL, result[i].Records[j].TTL, "record TTL should match")
					assert.Equal(t, expectedRecord.RData, result[i].Records[j].RData, "record RData should match")
				}
			}
		})
	}
}
