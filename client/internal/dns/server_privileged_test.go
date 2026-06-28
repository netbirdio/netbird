//go:build privileged

package dns

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface"
	pfmock "github.com/netbirdio/netbird/client/iface/mocks"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/dns/local"
	"github.com/netbirdio/netbird/client/internal/dns/test"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	nbdns "github.com/netbirdio/netbird/dns"
)

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
		initUpstreamMap     []handlerWrapper
		initLocalZones      []nbdns.CustomZone
		initSerial          uint64
		inputSerial         uint64
		inputUpdate         nbdns.Config
		shouldFail          bool
		expectedUpstreamMap []handlerWrapper
		expectedLocalQs     []dns.Question
	}{
		{
			name:            "Initial Config Should Succeed",
			initUpstreamMap: nil,
			initSerial:      0,
			inputSerial:     1,
			inputUpdate: nbdns.Config{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{
						Domain:  "netbird.cloud",
						Records: zoneRecords,
					},
				},
				NameServerGroups: []*nbdns.NameServerGroup{
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
			expectedUpstreamMap: []handlerWrapper{
				{
					domain:   "netbird.io",
					priority: PriorityUpstream,
				},
				{
					domain:   "netbird.cloud",
					priority: PriorityLocal,
				},
				{
					domain:   nbdns.RootZone,
					priority: PriorityDefault,
				},
			},
			expectedLocalQs: []dns.Question{{Name: "peera.netbird.cloud.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		},
		{
			name:           "New Config Should Succeed",
			initLocalZones: []nbdns.CustomZone{{Domain: "netbird.cloud", Records: []nbdns.SimpleRecord{{Name: "netbird.cloud", Type: 1, Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"}}}},
			initUpstreamMap: []handlerWrapper{
				{
					domain:   "netbird.cloud",
					handler:  &mockHandler{},
					priority: PriorityUpstream,
				},
			},
			initSerial:  0,
			inputSerial: 1,
			inputUpdate: nbdns.Config{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{
						Domain:  "netbird.cloud",
						Records: zoneRecords,
					},
				},
				NameServerGroups: []*nbdns.NameServerGroup{
					{
						Domains:     []string{"netbird.io"},
						NameServers: nameServers,
					},
				},
			},
			expectedUpstreamMap: []handlerWrapper{
				{
					domain:   "netbird.io",
					priority: PriorityUpstream,
				},
				{
					domain:   "netbird.cloud",
					priority: PriorityLocal,
				},
			},
			expectedLocalQs: []dns.Question{{Name: zoneRecords[0].Name, Qtype: 1, Qclass: 1}},
		},
		{
			name:            "Smaller Config Serial Should Be Skipped",
			initLocalZones:  []nbdns.CustomZone{},
			initUpstreamMap: nil,
			initSerial:      2,
			inputSerial:     1,
			shouldFail:      true,
		},
		{
			name:            "Empty NS Group Domain Or Not Primary Element Should Fail",
			initLocalZones:  []nbdns.CustomZone{},
			initUpstreamMap: nil,
			initSerial:      0,
			inputSerial:     1,
			inputUpdate: nbdns.Config{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{
						Domain:  "netbird.cloud",
						Records: zoneRecords,
					},
				},
				NameServerGroups: []*nbdns.NameServerGroup{
					{
						NameServers: nameServers,
					},
				},
			},
			shouldFail: true,
		},
		{
			name:            "Invalid NS Group Nameservers list Should Fail",
			initLocalZones:  []nbdns.CustomZone{},
			initUpstreamMap: nil,
			initSerial:      0,
			inputSerial:     1,
			inputUpdate: nbdns.Config{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{
						Domain:  "netbird.cloud",
						Records: zoneRecords,
					},
				},
				NameServerGroups: []*nbdns.NameServerGroup{
					{
						NameServers: nameServers,
					},
				},
			},
			shouldFail: true,
		},
		{
			name:            "Invalid Custom Zone Records list Should Skip",
			initLocalZones:  []nbdns.CustomZone{},
			initUpstreamMap: nil,
			initSerial:      0,
			inputSerial:     1,
			inputUpdate: nbdns.Config{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{
						Domain: "netbird.cloud",
					},
				},
				NameServerGroups: []*nbdns.NameServerGroup{
					{
						NameServers: nameServers,
						Primary:     true,
					},
				},
			},
			expectedUpstreamMap: []handlerWrapper{{
				domain:   ".",
				priority: PriorityDefault,
			}},
		},
		{
			name:           "Empty Config Should Succeed and Clean Maps",
			initLocalZones: []nbdns.CustomZone{{Domain: "netbird.cloud", Records: []nbdns.SimpleRecord{{Name: "netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"}}}},
			initUpstreamMap: []handlerWrapper{
				{
					domain:   zoneRecords[0].Name,
					handler:  &mockHandler{},
					priority: PriorityUpstream,
				},
			},
			initSerial:          0,
			inputSerial:         1,
			inputUpdate:         nbdns.Config{ServiceEnable: true},
			expectedUpstreamMap: nil,
			expectedLocalQs:     []dns.Question{},
		},
		{
			name:           "Disabled Service Should clean map",
			initLocalZones: []nbdns.CustomZone{{Domain: "netbird.cloud", Records: []nbdns.SimpleRecord{{Name: "netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"}}}},
			initUpstreamMap: []handlerWrapper{
				{
					domain:   zoneRecords[0].Name,
					handler:  &mockHandler{},
					priority: PriorityUpstream,
				},
			},
			initSerial:          0,
			inputSerial:         1,
			inputUpdate:         nbdns.Config{ServiceEnable: false},
			expectedUpstreamMap: nil,
			expectedLocalQs:     []dns.Question{},
		},
	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			privKey, _ := wgtypes.GenerateKey()
			newNet, err := stdnet.NewNet(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}

			opts := iface.WGIFaceOpts{
				IFaceName:    fmt.Sprintf("utun230%d", n),
				Address:      wgaddr.MustParseWGAddress(fmt.Sprintf("100.66.100.%d/32", n+1)),
				WGPort:       33100,
				WGPrivKey:    privKey.String(),
				MTU:          iface.DefaultMTU,
				TransportNet: newNet,
			}

			wgIface, err := iface.NewWGIFace(opts)
			if err != nil {
				t.Fatal(err)
			}
			err = wgIface.Create()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				err = wgIface.Close()
				if err != nil {
					t.Log(err)
				}
			}()
			dnsServer, err := NewDefaultServer(context.Background(), DefaultServerConfig{
				WgInterface:    wgIface,
				CustomAddress:  "",
				StatusRecorder: peer.NewRecorder("mgm"),
				StateManager:   nil,
				DisableSys:     false,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = dnsServer.Initialize()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				err = dnsServer.hostManager.restoreHostDNS()
				if err != nil {
					t.Log(err)
				}
			}()

			dnsServer.dnsMuxHandlers = testCase.initUpstreamMap
			dnsServer.localResolver.Update(testCase.initLocalZones)
			dnsServer.updateSerial = testCase.initSerial

			err = dnsServer.UpdateDNSServer(testCase.inputSerial, testCase.inputUpdate)
			if err != nil {
				if testCase.shouldFail {
					return
				}
				t.Fatalf("update dns server should not fail, got error: %v", err)
			}

			if len(dnsServer.dnsMuxHandlers) != len(testCase.expectedUpstreamMap) {
				t.Fatalf("update upstream failed, map size is different than expected, want %d, got %d", len(testCase.expectedUpstreamMap), len(dnsServer.dnsMuxHandlers))
			}

			for _, expected := range testCase.expectedUpstreamMap {
				found := false
				for _, got := range dnsServer.dnsMuxHandlers {
					if got.domain == expected.domain && got.priority == expected.priority {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("update upstream failed, handler for domain=%s priority=%d not found in dnsMuxHandlers: %#v", expected.domain, expected.priority, dnsServer.dnsMuxHandlers)
				}
			}

			var responseMSG *dns.Msg
			responseWriter := &test.MockResponseWriter{
				WriteMsgFunc: func(m *dns.Msg) error {
					responseMSG = m
					return nil
				},
			}
			for _, q := range testCase.expectedLocalQs {
				dnsServer.localResolver.ServeDNS(responseWriter, &dns.Msg{
					Question: []dns.Question{q},
				})
			}

			if len(testCase.expectedLocalQs) > 0 {
				assert.NotNil(t, responseMSG, "response message should not be nil")
				assert.Equal(t, dns.RcodeSuccess, responseMSG.Rcode, "response code should be success")
				assert.NotEmpty(t, responseMSG.Answer, "response message should have answers")
			}
		})
	}
}

func TestDNSFakeResolverHandleUpdates(t *testing.T) {
	ov := os.Getenv("NB_WG_KERNEL_DISABLED")
	defer t.Setenv("NB_WG_KERNEL_DISABLED", ov)

	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	newNet, err := stdnet.NewNet(context.Background(), []string{"utun2301"})
	if err != nil {
		t.Errorf("create stdnet: %v", err)
		return
	}

	privKey, _ := wgtypes.GeneratePrivateKey()
	opts := iface.WGIFaceOpts{
		IFaceName:    "utun2301",
		Address:      wgaddr.MustParseWGAddress("100.66.100.1/32"),
		WGPort:       33100,
		WGPrivKey:    privKey.String(),
		MTU:          iface.DefaultMTU,
		TransportNet: newNet,
	}
	wgIface, err := iface.NewWGIFace(opts)
	if err != nil {
		t.Errorf("build interface wireguard: %v", err)
		return
	}

	err = wgIface.Create()
	if err != nil {
		t.Errorf("create and init wireguard interface: %v", err)
		return
	}
	defer func() {
		if err = wgIface.Close(); err != nil {
			t.Logf("close wireguard interface: %v", err)
		}
	}()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	packetfilter := pfmock.NewMockPacketFilter(ctrl)
	packetfilter.EXPECT().FilterOutbound(gomock.Any(), gomock.Any()).AnyTimes()
	packetfilter.EXPECT().SetUDPPacketHook(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	packetfilter.EXPECT().SetTCPPacketHook(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	if err := wgIface.SetFilter(packetfilter); err != nil {
		t.Errorf("set packet filter: %v", err)
		return
	}

	dnsServer, err := NewDefaultServer(context.Background(), DefaultServerConfig{
		WgInterface:    wgIface,
		CustomAddress:  "",
		StatusRecorder: peer.NewRecorder("mgm"),
		StateManager:   nil,
		DisableSys:     false,
	})
	if err != nil {
		t.Errorf("create DNS server: %v", err)
		return
	}

	err = dnsServer.Initialize()
	if err != nil {
		t.Errorf("run DNS server: %v", err)
		return
	}
	defer func() {
		if err = dnsServer.hostManager.restoreHostDNS(); err != nil {
			t.Logf("restore DNS settings on the host: %v", err)
			return
		}
	}()

	dnsServer.dnsMuxHandlers = []handlerWrapper{
		{
			domain:   zoneRecords[0].Name,
			handler:  &local.Resolver{},
			priority: PriorityUpstream,
		},
	}
	dnsServer.localResolver.Update([]nbdns.CustomZone{{Domain: "netbird.cloud", Records: []nbdns.SimpleRecord{{Name: "netbird.cloud", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"}}}})
	dnsServer.updateSerial = 0

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

	update := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{
				Domain:  "netbird.cloud",
				Records: zoneRecords,
			},
		},
		NameServerGroups: []*nbdns.NameServerGroup{
			{
				Domains:     []string{"netbird.io"},
				NameServers: nameServers,
			},
			{
				NameServers: nameServers,
				Primary:     true,
			},
		},
	}

	// Start the server with regular configuration
	if err := dnsServer.UpdateDNSServer(1, update); err != nil {
		t.Fatalf("update dns server should not fail, got error: %v", err)
		return
	}

	update2 := update
	update2.ServiceEnable = false
	// Disable the server, stop the listener
	if err := dnsServer.UpdateDNSServer(2, update2); err != nil {
		t.Fatalf("update dns server should not fail, got error: %v", err)
		return
	}

	update3 := update2
	update3.NameServerGroups = update3.NameServerGroups[:1]
	// But service still get updates and we checking that we handle
	// internal state in the right way
	if err := dnsServer.UpdateDNSServer(3, update3); err != nil {
		t.Fatalf("update dns server should not fail, got error: %v", err)
		return
	}
}
