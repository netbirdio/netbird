package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/formatter"
	"github.com/netbirdio/netbird/iface"
	pfmock "github.com/netbirdio/netbird/iface/mocks"
)

type mocWGIface struct {
	filter iface.PacketFilter
}

func (w *mocWGIface) Name() string {
	panic("implement me")
}

func (w *mocWGIface) Address() iface.WGAddress {
	ip, network, _ := net.ParseCIDR("100.66.100.0/24")
	return iface.WGAddress{
		IP:      ip,
		Network: network,
	}
}

func (w *mocWGIface) ToInterface() *net.Interface {
	panic("implement me")
}

func (w *mocWGIface) GetFilter() iface.PacketFilter {
	return w.filter
}

func (w *mocWGIface) GetDevice() *iface.DeviceWrapper {
	panic("implement me")
}

func (w *mocWGIface) GetInterfaceGUIDString() (string, error) {
	panic("implement me")
}

func (w *mocWGIface) IsUserspaceBind() bool {
	return false
}

func (w *mocWGIface) SetFilter(filter iface.PacketFilter) error {
	w.filter = filter
	return nil
}

func (w *mocWGIface) GetStats(_ string) (iface.WGStats, error) {
	return iface.WGStats{}, nil
}

var zoneRecords = []nbdns.SimpleRecord{
	{
		Name:  "peera.netbird.cloud",
		Type:  1,
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "1.2.3.4",
	},
}

func init() {
	log.SetLevel(log.TraceLevel)
	formatter.SetTextFormatter(log.StandardLogger())
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

	dummyHandler := &localResolver{}

	testCases := []struct {
		name                string
		initUpstreamMap     registeredHandlerMap
		initLocalMap        registrationMap
		initSerial          uint64
		inputSerial         uint64
		inputUpdate         nbdns.Config
		shouldFail          bool
		expectedUpstreamMap registeredHandlerMap
		expectedLocalMap    registrationMap
	}{
		{
			name:            "Initial Config Should Succeed",
			initLocalMap:    make(registrationMap),
			initUpstreamMap: make(registeredHandlerMap),
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
						Enabled:     true,
						Domains:     []string{"netbird.io"},
						NameServers: nameServers,
					},
					{
						Enabled:     true,
						NameServers: nameServers,
						Primary:     true,
					},
				},
			},
			expectedUpstreamMap: registeredHandlerMap{"netbird.io": dummyHandler, "netbird.cloud": dummyHandler, nbdns.RootZone: dummyHandler},
			expectedLocalMap:    registrationMap{buildRecordKey(zoneRecords[0].Name, 1, 1): struct{}{}},
		},
		{
			name:            "New Config Should Succeed",
			initLocalMap:    registrationMap{"netbird.cloud": struct{}{}},
			initUpstreamMap: registeredHandlerMap{buildRecordKey(zoneRecords[0].Name, 1, 1): dummyHandler},
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
						Enabled:     true,
						Domains:     []string{"netbird.io"},
						NameServers: nameServers,
					},
				},
			},
			expectedUpstreamMap: registeredHandlerMap{"netbird.io": dummyHandler, "netbird.cloud": dummyHandler},
			expectedLocalMap:    registrationMap{buildRecordKey(zoneRecords[0].Name, 1, 1): struct{}{}},
		},
		{
			name:            "Smaller Config Serial Should Be Skipped",
			initLocalMap:    make(registrationMap),
			initUpstreamMap: make(registeredHandlerMap),
			initSerial:      2,
			inputSerial:     1,
			shouldFail:      true,
		},
		{
			name:            "Empty NS Group Domain Or Not Primary Element Should Fail",
			initLocalMap:    make(registrationMap),
			initUpstreamMap: make(registeredHandlerMap),
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
			initLocalMap:    make(registrationMap),
			initUpstreamMap: make(registeredHandlerMap),
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
			name:            "Invalid Custom Zone Records list Should Fail",
			initLocalMap:    make(registrationMap),
			initUpstreamMap: make(registeredHandlerMap),
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
			shouldFail: true,
		},
		{
			name:                "Empty Config Should Succeed and Clean Maps",
			initLocalMap:        registrationMap{"netbird.cloud": struct{}{}},
			initUpstreamMap:     registeredHandlerMap{zoneRecords[0].Name: dummyHandler},
			initSerial:          0,
			inputSerial:         1,
			inputUpdate:         nbdns.Config{ServiceEnable: true},
			expectedUpstreamMap: make(registeredHandlerMap),
			expectedLocalMap:    make(registrationMap),
		},
		{
			name:                "Disabled Service Should clean map",
			initLocalMap:        registrationMap{"netbird.cloud": struct{}{}},
			initUpstreamMap:     registeredHandlerMap{zoneRecords[0].Name: dummyHandler},
			initSerial:          0,
			inputSerial:         1,
			inputUpdate:         nbdns.Config{ServiceEnable: false},
			expectedUpstreamMap: make(registeredHandlerMap),
			expectedLocalMap:    make(registrationMap),
		},
	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			privKey, _ := wgtypes.GenerateKey()
			newNet, err := stdnet.NewNet(nil)
			if err != nil {
				t.Fatal(err)
			}
			wgIface, err := iface.NewWGIFace(fmt.Sprintf("utun230%d", n), fmt.Sprintf("100.66.100.%d/32", n+1), 33100, privKey.String(), iface.DefaultMTU, newNet, nil, nil)
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
			statusRecorder := peer.NewRecorder("https://mgm")
			key := "abc"
			statusRecorder.AddPeer(key, "abc.netbird")
			statusRecorder.UpdatePeerState(peer.State{
				PubKey:           key,
				Mux:              new(sync.RWMutex),
				ConnStatus:       peer.StatusConnected,
				ConnStatusUpdate: time.Now(),
			})
			dnsServer, err := NewDefaultServer(context.Background(), wgIface, "", statusRecorder)
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

			dnsServer.dnsMuxMap = testCase.initUpstreamMap
			dnsServer.localResolver.registeredMap = testCase.initLocalMap
			dnsServer.updateSerial = testCase.initSerial

			err = dnsServer.UpdateDNSServer(testCase.inputSerial, testCase.inputUpdate)
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

func TestDNSFakeResolverHandleUpdates(t *testing.T) {
	ov := os.Getenv("NB_WG_KERNEL_DISABLED")
	defer t.Setenv("NB_WG_KERNEL_DISABLED", ov)

	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	newNet, err := stdnet.NewNet(nil)
	if err != nil {
		t.Errorf("create stdnet: %v", err)
		return
	}

	privKey, _ := wgtypes.GeneratePrivateKey()
	wgIface, err := iface.NewWGIFace("utun2301", "100.66.100.1/32", 33100, privKey.String(), iface.DefaultMTU, newNet, nil, nil)
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

	_, ipNet, err := net.ParseCIDR("100.66.100.1/32")
	if err != nil {
		t.Errorf("parse CIDR: %v", err)
		return
	}

	packetfilter := pfmock.NewMockPacketFilter(ctrl)
	packetfilter.EXPECT().DropOutgoing(gomock.Any()).AnyTimes()
	packetfilter.EXPECT().AddUDPPacketHook(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
	packetfilter.EXPECT().RemovePacketHook(gomock.Any())
	packetfilter.EXPECT().SetNetwork(ipNet)

	if err := wgIface.SetFilter(packetfilter); err != nil {
		t.Errorf("set packet filter: %v", err)
		return
	}

	dnsServer, err := NewDefaultServer(context.Background(), wgIface, "", &peer.Status{})
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

	dnsServer.dnsMuxMap = registeredHandlerMap{zoneRecords[0].Name: &localResolver{}}
	dnsServer.localResolver.registeredMap = registrationMap{"netbird.cloud": struct{}{}}
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
				Enabled:     true,
			},
			{
				NameServers: nameServers,
				Primary:     true,
				Enabled:     true,
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

func TestDNSServerStartStop(t *testing.T) {
	testCases := []struct {
		name     string
		addrPort string
	}{
		{
			name: "Should Pass With Port Discovery",
		},
		{
			name:     "Should Pass With Custom Port",
			addrPort: "127.0.0.1:3535",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			dnsServer, err := NewDefaultServer(context.Background(), &mocWGIface{}, testCase.addrPort, &peer.Status{})
			if err != nil {
				t.Fatalf("%v", err)
			}
			dnsServer.hostManager = newNoopHostMocker()
			err = dnsServer.service.Listen()
			if err != nil {
				t.Fatalf("dns server is not running: %s", err)
			}
			time.Sleep(100 * time.Millisecond)
			defer dnsServer.Stop()
			err = dnsServer.localResolver.registerRecord(zoneRecords[0])
			if err != nil {
				t.Error(err)
			}

			dnsServer.service.RegisterMux("netbird.cloud", dnsServer.localResolver)

			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Second * 5,
					}
					addr := fmt.Sprintf("%s:%d", dnsServer.service.RuntimeIP(), dnsServer.service.RuntimePort())
					conn, err := d.DialContext(ctx, network, addr)
					if err != nil {
						t.Log(err)
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
			ctx, cancel := context.WithTimeout(context.TODO(), time.Second*1)
			defer cancel()
			_, err = resolver.LookupHost(ctx, zoneRecords[0].Name)
			if err == nil {
				t.Fatalf("we should encounter an error when querying a stopped server")
			}
		})
	}
}

func TestDNSServerUpstreamDeactivateCallback(t *testing.T) {
	hostManager := &mockHostConfigurator{}
	server := DefaultServer{
		service: NewServiceViaMemory(&mocWGIface{}),
		localResolver: &localResolver{
			registeredMap: make(registrationMap),
		},
		hostManager: hostManager,
		currentConfig: HostDNSConfig{
			Domains: []DomainConfig{
				{false, "domain0", false},
				{false, "domain1", false},
				{false, "domain2", false},
			},
		},
		statusRecorder: &peer.Status{},
	}

	var domainsUpdate string
	hostManager.applyDNSConfigFunc = func(config HostDNSConfig) error {
		domains := []string{}
		for _, item := range config.Domains {
			if item.Disabled {
				continue
			}
			domains = append(domains, item.Domain)
		}
		domainsUpdate = strings.Join(domains, ",")
		return nil
	}

	deactivate, reactivate := server.upstreamCallbacks(&nbdns.NameServerGroup{
		Domains: []string{"domain1"},
		NameServers: []nbdns.NameServer{
			{IP: netip.MustParseAddr("8.8.0.0"), NSType: nbdns.UDPNameServerType, Port: 53},
		},
	}, nil)

	deactivate(nil)
	expected := "domain0,domain2"
	domains := []string{}
	for _, item := range server.currentConfig.Domains {
		if item.Disabled {
			continue
		}
		domains = append(domains, item.Domain)
	}
	got := strings.Join(domains, ",")
	if expected != got {
		t.Errorf("expected domains list: %q, got %q", expected, got)
	}

	reactivate()
	expected = "domain0,domain1,domain2"
	domains = []string{}
	for _, item := range server.currentConfig.Domains {
		if item.Disabled {
			continue
		}
		domains = append(domains, item.Domain)
	}
	got = strings.Join(domains, ",")
	if expected != got {
		t.Errorf("expected domains list: %q, got %q", expected, domainsUpdate)
	}
}

func TestDNSPermanent_updateHostDNS_emptyUpstream(t *testing.T) {
	wgIFace, err := createWgInterfaceWithBind(t)
	if err != nil {
		t.Fatal("failed to initialize wg interface")
	}
	defer wgIFace.Close()

	var dnsList []string
	dnsConfig := nbdns.Config{}
	dnsServer := NewDefaultServerPermanentUpstream(context.Background(), wgIFace, dnsList, dnsConfig, nil, &peer.Status{})
	err = dnsServer.Initialize()
	if err != nil {
		t.Errorf("failed to initialize DNS server: %v", err)
		return
	}
	defer dnsServer.Stop()

	dnsServer.OnUpdatedHostDNSServer([]string{"8.8.8.8"})

	resolver := newDnsResolver(dnsServer.service.RuntimeIP(), dnsServer.service.RuntimePort())
	_, err = resolver.LookupHost(context.Background(), "netbird.io")
	if err != nil {
		t.Errorf("failed to resolve: %s", err)
	}
}

func TestDNSPermanent_updateUpstream(t *testing.T) {
	wgIFace, err := createWgInterfaceWithBind(t)
	if err != nil {
		t.Fatal("failed to initialize wg interface")
	}
	defer wgIFace.Close()
	dnsConfig := nbdns.Config{}
	dnsServer := NewDefaultServerPermanentUpstream(context.Background(), wgIFace, []string{"8.8.8.8"}, dnsConfig, nil, &peer.Status{})
	err = dnsServer.Initialize()
	if err != nil {
		t.Errorf("failed to initialize DNS server: %v", err)
		return
	}
	defer dnsServer.Stop()

	// check initial state
	resolver := newDnsResolver(dnsServer.service.RuntimeIP(), dnsServer.service.RuntimePort())
	_, err = resolver.LookupHost(context.Background(), "netbird.io")
	if err != nil {
		t.Errorf("failed to resolve: %s", err)
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
				NameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("8.8.4.4"),
						NSType: nbdns.UDPNameServerType,
						Port:   53,
					},
				},
				Enabled: true,
				Primary: true,
			},
		},
	}

	err = dnsServer.UpdateDNSServer(1, update)
	if err != nil {
		t.Errorf("failed to update dns server: %s", err)
	}

	_, err = resolver.LookupHost(context.Background(), "netbird.io")
	if err != nil {
		t.Errorf("failed to resolve: %s", err)
	}
	ips, err := resolver.LookupHost(context.Background(), zoneRecords[0].Name)
	if err != nil {
		t.Fatalf("failed resolve zone record: %v", err)
	}
	if ips[0] != zoneRecords[0].RData {
		t.Fatalf("invalid zone record: %v", err)
	}

	update2 := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{
				Domain:  "netbird.cloud",
				Records: zoneRecords,
			},
		},
		NameServerGroups: []*nbdns.NameServerGroup{},
	}

	err = dnsServer.UpdateDNSServer(2, update2)
	if err != nil {
		t.Errorf("failed to update dns server: %s", err)
	}

	_, err = resolver.LookupHost(context.Background(), "netbird.io")
	if err != nil {
		t.Errorf("failed to resolve: %s", err)
	}

	ips, err = resolver.LookupHost(context.Background(), zoneRecords[0].Name)
	if err != nil {
		t.Fatalf("failed resolve zone record: %v", err)
	}
	if ips[0] != zoneRecords[0].RData {
		t.Fatalf("invalid zone record: %v", err)
	}
}

func TestDNSPermanent_matchOnly(t *testing.T) {
	wgIFace, err := createWgInterfaceWithBind(t)
	if err != nil {
		t.Fatal("failed to initialize wg interface")
	}
	defer wgIFace.Close()
	dnsConfig := nbdns.Config{}
	dnsServer := NewDefaultServerPermanentUpstream(context.Background(), wgIFace, []string{"8.8.8.8"}, dnsConfig, nil, &peer.Status{})
	err = dnsServer.Initialize()
	if err != nil {
		t.Errorf("failed to initialize DNS server: %v", err)
		return
	}
	defer dnsServer.Stop()

	// check initial state
	resolver := newDnsResolver(dnsServer.service.RuntimeIP(), dnsServer.service.RuntimePort())
	_, err = resolver.LookupHost(context.Background(), "netbird.io")
	if err != nil {
		t.Errorf("failed to resolve: %s", err)
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
				NameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("8.8.4.4"),
						NSType: nbdns.UDPNameServerType,
						Port:   53,
					},
					{
						IP:     netip.MustParseAddr("9.9.9.9"),
						NSType: nbdns.UDPNameServerType,
						Port:   53,
					},
				},
				Domains: []string{"customdomain.com"},
				Primary: false,
			},
		},
	}

	err = dnsServer.UpdateDNSServer(1, update)
	if err != nil {
		t.Errorf("failed to update dns server: %s", err)
	}

	_, err = resolver.LookupHost(context.Background(), "netbird.io")
	if err != nil {
		t.Errorf("failed to resolve: %s", err)
	}
	ips, err := resolver.LookupHost(context.Background(), zoneRecords[0].Name)
	if err != nil {
		t.Fatalf("failed resolve zone record: %v", err)
	}
	if ips[0] != zoneRecords[0].RData {
		t.Fatalf("invalid zone record: %v", err)
	}
	_, err = resolver.LookupHost(context.Background(), "customdomain.com")
	if err != nil {
		t.Errorf("failed to resolve: %s", err)
	}
}

func createWgInterfaceWithBind(t *testing.T) (*iface.WGIface, error) {
	t.Helper()
	ov := os.Getenv("NB_WG_KERNEL_DISABLED")
	defer t.Setenv("NB_WG_KERNEL_DISABLED", ov)

	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	newNet, err := stdnet.NewNet(nil)
	if err != nil {
		t.Fatalf("create stdnet: %v", err)
		return nil, err
	}

	privKey, _ := wgtypes.GeneratePrivateKey()
	wgIface, err := iface.NewWGIFace("utun2301", "100.66.100.2/24", 33100, privKey.String(), iface.DefaultMTU, newNet, nil, nil)
	if err != nil {
		t.Fatalf("build interface wireguard: %v", err)
		return nil, err
	}

	err = wgIface.Create()
	if err != nil {
		t.Fatalf("create and init wireguard interface: %v", err)
		return nil, err
	}

	pf, err := uspfilter.Create(wgIface)
	if err != nil {
		t.Fatalf("failed to create uspfilter: %v", err)
		return nil, err
	}

	err = wgIface.SetFilter(pf)
	if err != nil {
		t.Fatalf("set packet filter: %v", err)
		return nil, err
	}

	return wgIface, nil
}

func newDnsResolver(ip string, port int) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 3,
			}
			addr := fmt.Sprintf("%s:%d", ip, port)
			return d.DialContext(ctx, network, addr)
		},
	}
}
