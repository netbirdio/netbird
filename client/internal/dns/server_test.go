package dns

import (
	"context"
	"fmt"
	nbdns "github.com/netbirdio/netbird/dns"
	"net"
	"net/netip"
	"testing"
	"time"
)

var zoneRecords = []nbdns.SimpleRecord{
	{
		Name:  "peera.netbird.cloud",
		Type:  1,
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "1.2.3.4",
	},
}

func TestUpdateDNSServer(t *testing.T) {

	nameServers := []nbdns.NameServer{
		{
			IP:     netip.MustParseAddr("8.8.8.8"),
			NSType: nbdns.UDPNameServerType,
			Port:   53,
		},
		{
			IP:     netip.MustParseAddr("8.8.4.4"),
			NSType: nbdns.UDPNameServerType,
			Port:   53,
		},
	}

	testCases := []struct {
		name                string
		initUpstreamMap     registrationMap
		initLocalMap        registrationMap
		initSerial          uint64
		inputSerial         uint64
		inputUpdate         nbdns.Update
		shouldFail          bool
		expectedUpstreamMap registrationMap
		expectedLocalMap    registrationMap
	}{
		{
			name:            "Initial Update Should Succeed",
			initLocalMap:    make(registrationMap),
			initUpstreamMap: make(registrationMap),
			initSerial:      0,
			inputSerial:     1,
			inputUpdate: nbdns.Update{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{
						Domain:  "netbird.cloud",
						Records: zoneRecords,
					},
				},
				NameServerGroups: []nbdns.NameServerGroup{
					{
						Domains:     []string{"netbird.io"},
						NameServers: nameServers,
					},
					{
						NameServers: nameServers,
						Primary:     true,
					},
				},
			},
			expectedUpstreamMap: registrationMap{"netbird.io": struct{}{}, "netbird.cloud": struct{}{}, nbdns.RootZone: struct{}{}},
			expectedLocalMap:    registrationMap{zoneRecords[0].Name: struct{}{}},
		},
		{
			name:            "New Update Should Succeed",
			initLocalMap:    registrationMap{"netbird.cloud": struct{}{}},
			initUpstreamMap: registrationMap{zoneRecords[0].Name: struct{}{}},
			initSerial:      0,
			inputSerial:     1,
			inputUpdate: nbdns.Update{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{
						Domain:  "netbird.cloud",
						Records: zoneRecords,
					},
				},
				NameServerGroups: []nbdns.NameServerGroup{
					{
						Domains:     []string{"netbird.io"},
						NameServers: nameServers,
					},
				},
			},
			expectedUpstreamMap: registrationMap{"netbird.io": struct{}{}, "netbird.cloud": struct{}{}},
			expectedLocalMap:    registrationMap{zoneRecords[0].Name: struct{}{}},
		},
		{
			name:            "Smaller Update Serial Should Be Skipped",
			initLocalMap:    make(registrationMap),
			initUpstreamMap: make(registrationMap),
			initSerial:      2,
			inputSerial:     1,
			shouldFail:      true,
		},
		{
			name:            "Empty NS Group Domain Or Not Primary Element Should Fail",
			initLocalMap:    make(registrationMap),
			initUpstreamMap: make(registrationMap),
			initSerial:      0,
			inputSerial:     1,
			inputUpdate: nbdns.Update{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{
						Domain:  "netbird.cloud",
						Records: zoneRecords,
					},
				},
				NameServerGroups: []nbdns.NameServerGroup{
					{
						NameServers: nameServers,
					},
				},
			},
			shouldFail: true,
		},
		{
			name:            "Invalid NS Group Nameservers list Should Fail",
			initLocalMap:    make(registrationMap),
			initUpstreamMap: make(registrationMap),
			initSerial:      0,
			inputSerial:     1,
			inputUpdate: nbdns.Update{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{
						Domain:  "netbird.cloud",
						Records: zoneRecords,
					},
				},
				NameServerGroups: []nbdns.NameServerGroup{
					{
						NameServers: nameServers,
					},
				},
			},
			shouldFail: true,
		},
		{
			name:            "Invalid Custom Zone Records list Should Fail",
			initLocalMap:    make(registrationMap),
			initUpstreamMap: make(registrationMap),
			initSerial:      0,
			inputSerial:     1,
			inputUpdate: nbdns.Update{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{
						Domain: "netbird.cloud",
					},
				},
				NameServerGroups: []nbdns.NameServerGroup{
					{
						NameServers: nameServers,
						Primary:     true,
					},
				},
			},
			shouldFail: true,
		},
		{
			name:                "Empty Update Should Succeed and Clean Maps",
			initLocalMap:        registrationMap{"netbird.cloud": struct{}{}},
			initUpstreamMap:     registrationMap{zoneRecords[0].Name: struct{}{}},
			initSerial:          0,
			inputSerial:         1,
			inputUpdate:         nbdns.Update{ServiceEnable: true},
			expectedUpstreamMap: make(registrationMap),
			expectedLocalMap:    make(registrationMap),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			dnsServer := NewServer(ctx)

			dnsServer.dnsMuxMap = testCase.initUpstreamMap
			dnsServer.localResolver.registeredMap = testCase.initLocalMap
			dnsServer.updateSerial = testCase.initSerial
			dnsServer.listenerIsRunning = true

			err := dnsServer.UpdateDNSServer(testCase.inputSerial, testCase.inputUpdate)
			if err != nil {
				if testCase.shouldFail {
					return
				}
				t.Fatalf("update dns server should not fail, got error: %v", err)
			}

			if len(dnsServer.dnsMuxMap) != len(testCase.expectedUpstreamMap) {
				t.Fatalf("update upstream failed, map size is different than expected, want %d, got %d", len(testCase.expectedUpstreamMap), len(dnsServer.dnsMuxMap))
			}

			for key := range testCase.expectedUpstreamMap {
				_, found := dnsServer.dnsMuxMap[key]
				if !found {
					t.Fatalf("update upstream failed, key %s was not found in the dnsMuxMap: %#v", key, dnsServer.dnsMuxMap)
				}
			}

			if len(dnsServer.localResolver.registeredMap) != len(testCase.expectedLocalMap) {
				t.Fatalf("update local failed, registered map size is different than expected, want %d, got %d", len(testCase.expectedLocalMap), len(dnsServer.localResolver.registeredMap))
			}

			for key := range testCase.expectedLocalMap {
				_, found := dnsServer.localResolver.registeredMap[key]
				if !found {
					t.Fatalf("update local failed, key %s was not found in the localResolver.registeredMap: %#v", key, dnsServer.localResolver.registeredMap)
				}
			}
		})
	}
}

func TestDNSServerStartStop(t *testing.T) {
	ctx := context.Background()
	dnsServer := NewServer(ctx)
	dnsServer.Start()

	_ = dnsServer.localResolver.registerRecord(zoneRecords[0])
	dnsServer.dnsMux.Handle("netbird.cloud", dnsServer.localResolver)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 5,
			}
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				// retry test before exit, for slower systems
				return d.DialContext(ctx, network, addr)
			}

			return conn, nil
		},
	}

	ips, err := resolver.LookupHost(context.Background(), zoneRecords[0].Name)
	if err != nil {
		t.Fatalf("failed to connect to the server, error: %v", err)
	}

	if ips[0] != zoneRecords[0].RData {
		t.Fatalf("got a different IP from the server: want %s, got %s", zoneRecords[0].RData, ips[0])
	}

	dnsServer.Stop()
	ctx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	_, err = resolver.LookupHost(ctx, zoneRecords[0].Name)
	if err == nil {
		t.Fatalf("we should encounter an error when querying a stopped server")
	}
}
