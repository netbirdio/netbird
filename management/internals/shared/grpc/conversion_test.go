package grpc

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
)

func TestToProtocolDNSConfigWithCache(t *testing.T) {
	var cache cache.DNSConfigCache

	// Create two different configs
	config1 := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "example.com",
				Records: []nbdns.SimpleRecord{
					{Name: "www", Type: 1, Class: "IN", TTL: 300, RData: "192.168.1.1"},
				},
			},
		},
		NameServerGroups: []*nbdns.NameServerGroup{
			{
				ID:   "group1",
				Name: "Group 1",
				NameServers: []nbdns.NameServer{
					{IP: netip.MustParseAddr("8.8.8.8"), Port: 53},
				},
			},
		},
	}

	config2 := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "example.org",
				Records: []nbdns.SimpleRecord{
					{Name: "mail", Type: 1, Class: "IN", TTL: 300, RData: "192.168.1.2"},
				},
			},
		},
		NameServerGroups: []*nbdns.NameServerGroup{
			{
				ID:   "group2",
				Name: "Group 2",
				NameServers: []nbdns.NameServer{
					{IP: netip.MustParseAddr("8.8.4.4"), Port: 53},
				},
			},
		},
	}

	// First run with config1
	result1 := toProtocolDNSConfig(config1, &cache, int64(network_map.DnsForwarderPort))

	// Second run with config2
	result2 := toProtocolDNSConfig(config2, &cache, int64(network_map.DnsForwarderPort))

	// Third run with config1 again
	result3 := toProtocolDNSConfig(config1, &cache, int64(network_map.DnsForwarderPort))

	// Verify that result1 and result3 are identical
	if !reflect.DeepEqual(result1, result3) {
		t.Errorf("Results are not identical when run with the same input. Expected %v, got %v", result1, result3)
	}

	// Verify that result2 is different from result1 and result3
	if reflect.DeepEqual(result1, result2) || reflect.DeepEqual(result2, result3) {
		t.Errorf("Results should be different for different inputs")
	}

	if _, exists := cache.GetNameServerGroup("group1"); !exists {
		t.Errorf("Cache should contain name server group 'group1'")
	}

	if _, exists := cache.GetNameServerGroup("group2"); !exists {
		t.Errorf("Cache should contain name server group 'group2'")
	}
}

func BenchmarkToProtocolDNSConfig(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		testData := generateTestData(size)

		b.Run(fmt.Sprintf("WithCache-Size%d", size), func(b *testing.B) {
			cache := &cache.DNSConfigCache{}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				toProtocolDNSConfig(testData, cache, int64(network_map.DnsForwarderPort))
			}
		})

		b.Run(fmt.Sprintf("WithoutCache-Size%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cache := &cache.DNSConfigCache{}
				toProtocolDNSConfig(testData, cache, int64(network_map.DnsForwarderPort))
			}
		})
	}
}

func generateTestData(size int) nbdns.Config {
	config := nbdns.Config{
		ServiceEnable:    true,
		CustomZones:      make([]nbdns.CustomZone, size),
		NameServerGroups: make([]*nbdns.NameServerGroup, size),
	}

	for i := 0; i < size; i++ {
		config.CustomZones[i] = nbdns.CustomZone{
			Domain: fmt.Sprintf("domain%d.com", i),
			Records: []nbdns.SimpleRecord{
				{
					Name:  fmt.Sprintf("record%d", i),
					Type:  1,
					Class: "IN",
					TTL:   3600,
					RData: "192.168.1.1",
				},
			},
		}

		config.NameServerGroups[i] = &nbdns.NameServerGroup{
			ID:                   fmt.Sprintf("group%d", i),
			Primary:              i == 0,
			Domains:              []string{fmt.Sprintf("domain%d.com", i)},
			SearchDomainsEnabled: true,
			NameServers: []nbdns.NameServer{
				{
					IP:     netip.MustParseAddr("8.8.8.8"),
					Port:   53,
					NSType: 1,
				},
			},
		}
	}

	return config
}
