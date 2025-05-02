package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/device"
	pfmock "github.com/netbirdio/netbird/client/iface/mocks"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/netflow"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/formatter"
	"github.com/netbirdio/netbird/management/domain"
)

var flowLogger = netflow.NewManager(nil, []byte{}, nil).GetLogger()

type mocWGIface struct {
	filter device.PacketFilter
}

func (w *mocWGIface) Name() string {
	return "utun2301"
}

func (w *mocWGIface) Address() wgaddr.Address {
	ip, network, _ := net.ParseCIDR("100.66.100.0/24")
	return wgaddr.Address{
		IP:      ip,
		Network: network,
	}
}

func (w *mocWGIface) ToInterface() *net.Interface {
	panic("implement me")
}

func (w *mocWGIface) GetFilter() device.PacketFilter {
	return w.filter
}

func (w *mocWGIface) GetDevice() *device.FilteredDevice {
	panic("implement me")
}

func (w *mocWGIface) GetInterfaceGUIDString() (string, error) {
	panic("implement me")
}

func (w *mocWGIface) IsUserspaceBind() bool {
	return false
}

func (w *mocWGIface) SetFilter(filter device.PacketFilter) error {
	w.filter = filter
	return nil
}

func (w *mocWGIface) GetStats(_ string) (configurer.WGStats, error) {
	return configurer.WGStats{}, nil
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

func generateDummyHandler(domain string, servers []nbdns.NameServer) *upstreamResolverBase {
	var srvs []string
	for _, srv := range servers {
		srvs = append(srvs, getNSHostPort(srv))
	}
	return &upstreamResolverBase{
		domain:          domain,
		upstreamServers: srvs,
		cancel:          func() {},
	}
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
						Domains:     []string{"netbird.io"},
						NameServers: nameServers,
					},
					{
						NameServers: nameServers,
						Primary:     true,
					},
				},
			},
			expectedUpstreamMap: registeredHandlerMap{
				generateDummyHandler("netbird.io", nameServers).id(): handlerWrapper{
					domain:   "netbird.io",
					handler:  dummyHandler,
					priority: PriorityMatchDomain,
				},
				dummyHandler.id(): handlerWrapper{
					domain:   "netbird.cloud",
					handler:  dummyHandler,
					priority: PriorityMatchDomain,
				},
				generateDummyHandler(".", nameServers).id(): handlerWrapper{
					domain:   nbdns.RootZone,
					handler:  dummyHandler,
					priority: PriorityDefault,
				},
			},
			expectedLocalMap: registrationMap{buildRecordKey(zoneRecords[0].Name, 1, 1): struct{}{}},
		},
		{
			name:         "New Config Should Succeed",
			initLocalMap: registrationMap{"netbird.cloud": struct{}{}},
			initUpstreamMap: registeredHandlerMap{
				generateDummyHandler(zoneRecords[0].Name, nameServers).id(): handlerWrapper{
					domain:   buildRecordKey(zoneRecords[0].Name, 1, 1),
					handler:  dummyHandler,
					priority: PriorityMatchDomain,
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
			expectedUpstreamMap: registeredHandlerMap{
				generateDummyHandler("netbird.io", nameServers).id(): handlerWrapper{
					domain:   "netbird.io",
					handler:  dummyHandler,
					priority: PriorityMatchDomain,
				},
				"local-resolver": handlerWrapper{
					domain:   "netbird.cloud",
					handler:  dummyHandler,
					priority: PriorityMatchDomain,
				},
			},
			expectedLocalMap: registrationMap{buildRecordKey(zoneRecords[0].Name, 1, 1): struct{}{}},
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
			name:            "Invalid Custom Zone Records list Should Skip",
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
			expectedUpstreamMap: registeredHandlerMap{generateDummyHandler(".", nameServers).id(): handlerWrapper{
				domain:   ".",
				handler:  dummyHandler,
				priority: PriorityDefault,
			}},
		},
		{
			name:         "Empty Config Should Succeed and Clean Maps",
			initLocalMap: registrationMap{"netbird.cloud": struct{}{}},
			initUpstreamMap: registeredHandlerMap{
				generateDummyHandler(zoneRecords[0].Name, nameServers).id(): handlerWrapper{
					domain:   zoneRecords[0].Name,
					handler:  dummyHandler,
					priority: PriorityMatchDomain,
				},
			},
			initSerial:          0,
			inputSerial:         1,
			inputUpdate:         nbdns.Config{ServiceEnable: true},
			expectedUpstreamMap: make(registeredHandlerMap),
			expectedLocalMap:    make(registrationMap),
		},
		{
			name:         "Disabled Service Should clean map",
			initLocalMap: registrationMap{"netbird.cloud": struct{}{}},
			initUpstreamMap: registeredHandlerMap{
				generateDummyHandler(zoneRecords[0].Name, nameServers).id(): handlerWrapper{
					domain:   zoneRecords[0].Name,
					handler:  dummyHandler,
					priority: PriorityMatchDomain,
				},
			},
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

			opts := iface.WGIFaceOpts{
				IFaceName:    fmt.Sprintf("utun230%d", n),
				Address:      fmt.Sprintf("100.66.100.%d/32", n+1),
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
			dnsServer, err := NewDefaultServer(context.Background(), wgIface, "", peer.NewRecorder("mgm"), nil, false)
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
	newNet, err := stdnet.NewNet([]string{"utun2301"})
	if err != nil {
		t.Errorf("create stdnet: %v", err)
		return
	}

	privKey, _ := wgtypes.GeneratePrivateKey()
	opts := iface.WGIFaceOpts{
		IFaceName:    "utun2301",
		Address:      "100.66.100.1/32",
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

	_, ipNet, err := net.ParseCIDR("100.66.100.1/32")
	if err != nil {
		t.Errorf("parse CIDR: %v", err)
		return
	}

	packetfilter := pfmock.NewMockPacketFilter(ctrl)
	packetfilter.EXPECT().DropOutgoing(gomock.Any(), gomock.Any()).AnyTimes()
	packetfilter.EXPECT().AddUDPPacketHook(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
	packetfilter.EXPECT().RemovePacketHook(gomock.Any())
	packetfilter.EXPECT().SetNetwork(ipNet)

	if err := wgIface.SetFilter(packetfilter); err != nil {
		t.Errorf("set packet filter: %v", err)
		return
	}

	dnsServer, err := NewDefaultServer(context.Background(), wgIface, "", peer.NewRecorder("mgm"), nil, false)
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

	dnsServer.dnsMuxMap = registeredHandlerMap{
		"id1": handlerWrapper{
			domain:   zoneRecords[0].Name,
			handler:  &localResolver{},
			priority: PriorityMatchDomain,
		},
	}
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
			dnsServer, err := NewDefaultServer(context.Background(), &mocWGIface{}, testCase.addrPort, peer.NewRecorder("mgm"), nil, false)
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
			_, err = dnsServer.localResolver.registerRecord(zoneRecords[0])
			if err != nil {
				t.Error(err)
			}

			dnsServer.registerHandler([]string{"netbird.cloud"}, dnsServer.localResolver, 1)

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
		ctx:     context.Background(),
		service: NewServiceViaMemory(&mocWGIface{}),
		localResolver: &localResolver{
			registeredMap: make(registrationMap),
		},
		handlerChain: NewHandlerChain(),
		hostManager:  hostManager,
		currentConfig: HostDNSConfig{
			Domains: []DomainConfig{
				{false, "domain0", false},
				{false, "domain1", false},
				{false, "domain2", false},
			},
		},
		statusRecorder: peer.NewRecorder("mgm"),
	}

	var domainsUpdate string
	hostManager.applyDNSConfigFunc = func(config HostDNSConfig, statemanager *statemanager.Manager) error {
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
	}, nil, 0)

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
	dnsServer := NewDefaultServerPermanentUpstream(context.Background(), wgIFace, dnsList, dnsConfig, nil, peer.NewRecorder("mgm"), false)
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
	dnsServer := NewDefaultServerPermanentUpstream(context.Background(), wgIFace, []string{"8.8.8.8"}, dnsConfig, nil, peer.NewRecorder("mgm"), false)
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
	dnsServer := NewDefaultServerPermanentUpstream(context.Background(), wgIFace, []string{"8.8.8.8"}, dnsConfig, nil, peer.NewRecorder("mgm"), false)
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
				Domains: []string{"google.com"},
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
	_, err = resolver.LookupHost(context.Background(), "google.com")
	if err != nil {
		t.Errorf("failed to resolve: %s", err)
	}
}

func createWgInterfaceWithBind(t *testing.T) (*iface.WGIface, error) {
	t.Helper()
	ov := os.Getenv("NB_WG_KERNEL_DISABLED")
	defer t.Setenv("NB_WG_KERNEL_DISABLED", ov)

	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	newNet, err := stdnet.NewNet([]string{"utun2301"})
	if err != nil {
		t.Fatalf("create stdnet: %v", err)
		return nil, err
	}

	privKey, _ := wgtypes.GeneratePrivateKey()

	opts := iface.WGIFaceOpts{
		IFaceName:    "utun2301",
		Address:      "100.66.100.2/24",
		WGPort:       33100,
		WGPrivKey:    privKey.String(),
		MTU:          iface.DefaultMTU,
		TransportNet: newNet,
	}

	wgIface, err := iface.NewWGIFace(opts)
	if err != nil {
		t.Fatalf("build interface wireguard: %v", err)
		return nil, err
	}

	err = wgIface.Create()
	if err != nil {
		t.Fatalf("create and init wireguard interface: %v", err)
		return nil, err
	}

	pf, err := uspfilter.Create(wgIface, false, flowLogger)
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

// MockHandler implements dns.Handler interface for testing
type MockHandler struct {
	mock.Mock
}

func (m *MockHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m.Called(w, r)
}

type MockSubdomainHandler struct {
	MockHandler
	Subdomains bool
}

func (m *MockSubdomainHandler) MatchSubdomains() bool {
	return m.Subdomains
}

func TestHandlerChain_DomainPriorities(t *testing.T) {
	chain := NewHandlerChain()

	dnsRouteHandler := &MockHandler{}
	upstreamHandler := &MockSubdomainHandler{
		Subdomains: true,
	}

	chain.AddHandler("example.com.", dnsRouteHandler, PriorityDNSRoute)
	chain.AddHandler("example.com.", upstreamHandler, PriorityMatchDomain)

	testCases := []struct {
		name            string
		query           string
		expectedHandler dns.Handler
	}{
		{
			name:            "exact domain with dns route handler",
			query:           "example.com.",
			expectedHandler: dnsRouteHandler,
		},
		{
			name:            "subdomain should use upstream handler",
			query:           "sub.example.com.",
			expectedHandler: upstreamHandler,
		},
		{
			name:            "deep subdomain should use upstream handler",
			query:           "deep.sub.example.com.",
			expectedHandler: upstreamHandler,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := new(dns.Msg)
			r.SetQuestion(tc.query, dns.TypeA)
			w := &ResponseWriterChain{ResponseWriter: &mockResponseWriter{}}

			if mh, ok := tc.expectedHandler.(*MockHandler); ok {
				mh.On("ServeDNS", mock.Anything, r).Once()
			} else if mh, ok := tc.expectedHandler.(*MockSubdomainHandler); ok {
				mh.On("ServeDNS", mock.Anything, r).Once()
			}

			chain.ServeDNS(w, r)

			if mh, ok := tc.expectedHandler.(*MockHandler); ok {
				mh.AssertExpectations(t)
			} else if mh, ok := tc.expectedHandler.(*MockSubdomainHandler); ok {
				mh.AssertExpectations(t)
			}

			// Close mocks
			if mh, ok := tc.expectedHandler.(*MockHandler); ok {
				mh.ExpectedCalls = nil
				mh.Calls = nil
			} else if mh, ok := tc.expectedHandler.(*MockSubdomainHandler); ok {
				mh.ExpectedCalls = nil
				mh.Calls = nil
			}
		})
	}
}

type mockHandler struct {
	Id string
}

func (m *mockHandler) ServeDNS(dns.ResponseWriter, *dns.Msg) {}
func (m *mockHandler) stop()                                 {}
func (m *mockHandler) probeAvailability()                    {}
func (m *mockHandler) id() handlerID                         { return handlerID(m.Id) }

type mockService struct{}

func (m *mockService) Listen() error                   { return nil }
func (m *mockService) Stop()                           {}
func (m *mockService) RuntimeIP() string               { return "127.0.0.1" }
func (m *mockService) RuntimePort() int                { return 53 }
func (m *mockService) RegisterMux(string, dns.Handler) {}
func (m *mockService) DeregisterMux(string)            {}

func TestDefaultServer_UpdateMux(t *testing.T) {
	baseMatchHandlers := registeredHandlerMap{
		"upstream-group1": {
			domain: "example.com",
			handler: &mockHandler{
				Id: "upstream-group1",
			},
			priority: PriorityMatchDomain,
		},
		"upstream-group2": {
			domain: "example.com",
			handler: &mockHandler{
				Id: "upstream-group2",
			},
			priority: PriorityMatchDomain - 1,
		},
	}

	baseRootHandlers := registeredHandlerMap{
		"upstream-root1": {
			domain: ".",
			handler: &mockHandler{
				Id: "upstream-root1",
			},
			priority: PriorityDefault,
		},
		"upstream-root2": {
			domain: ".",
			handler: &mockHandler{
				Id: "upstream-root2",
			},
			priority: PriorityDefault - 1,
		},
	}

	baseMixedHandlers := registeredHandlerMap{
		"upstream-group1": {
			domain: "example.com",
			handler: &mockHandler{
				Id: "upstream-group1",
			},
			priority: PriorityMatchDomain,
		},
		"upstream-group2": {
			domain: "example.com",
			handler: &mockHandler{
				Id: "upstream-group2",
			},
			priority: PriorityMatchDomain - 1,
		},
		"upstream-other": {
			domain: "other.com",
			handler: &mockHandler{
				Id: "upstream-other",
			},
			priority: PriorityMatchDomain,
		},
	}

	tests := []struct {
		name             string
		initialHandlers  registeredHandlerMap
		updates          []handlerWrapper
		expectedHandlers map[string]string // map[handlerID]domain
		description      string
	}{
		{
			name:            "Remove group1 from update",
			initialHandlers: baseMatchHandlers,
			updates: []handlerWrapper{
				// Only group2 remains
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group2",
					},
					priority: PriorityMatchDomain - 1,
				},
			},
			expectedHandlers: map[string]string{
				"upstream-group2": "example.com",
			},
			description: "When group1 is not included in the update, it should be removed while group2 remains",
		},
		{
			name:            "Remove group2 from update",
			initialHandlers: baseMatchHandlers,
			updates: []handlerWrapper{
				// Only group1 remains
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group1",
					},
					priority: PriorityMatchDomain,
				},
			},
			expectedHandlers: map[string]string{
				"upstream-group1": "example.com",
			},
			description: "When group2 is not included in the update, it should be removed while group1 remains",
		},
		{
			name:            "Add group3 in first position",
			initialHandlers: baseMatchHandlers,
			updates: []handlerWrapper{
				// Add group3 with highest priority
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group3",
					},
					priority: PriorityMatchDomain + 1,
				},
				// Keep existing groups with their original priorities
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group1",
					},
					priority: PriorityMatchDomain,
				},
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group2",
					},
					priority: PriorityMatchDomain - 1,
				},
			},
			expectedHandlers: map[string]string{
				"upstream-group1": "example.com",
				"upstream-group2": "example.com",
				"upstream-group3": "example.com",
			},
			description: "When adding group3 with highest priority, it should be first in chain while maintaining existing groups",
		},
		{
			name:            "Add group3 in last position",
			initialHandlers: baseMatchHandlers,
			updates: []handlerWrapper{
				// Keep existing groups with their original priorities
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group1",
					},
					priority: PriorityMatchDomain,
				},
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group2",
					},
					priority: PriorityMatchDomain - 1,
				},
				// Add group3 with lowest priority
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group3",
					},
					priority: PriorityMatchDomain - 2,
				},
			},
			expectedHandlers: map[string]string{
				"upstream-group1": "example.com",
				"upstream-group2": "example.com",
				"upstream-group3": "example.com",
			},
			description: "When adding group3 with lowest priority, it should be last in chain while maintaining existing groups",
		},
		// Root zone tests
		{
			name:            "Remove root1 from update",
			initialHandlers: baseRootHandlers,
			updates: []handlerWrapper{
				{
					domain: ".",
					handler: &mockHandler{
						Id: "upstream-root2",
					},
					priority: PriorityDefault - 1,
				},
			},
			expectedHandlers: map[string]string{
				"upstream-root2": ".",
			},
			description: "When root1 is not included in the update, it should be removed while root2 remains",
		},
		{
			name:            "Remove root2 from update",
			initialHandlers: baseRootHandlers,
			updates: []handlerWrapper{
				{
					domain: ".",
					handler: &mockHandler{
						Id: "upstream-root1",
					},
					priority: PriorityDefault,
				},
			},
			expectedHandlers: map[string]string{
				"upstream-root1": ".",
			},
			description: "When root2 is not included in the update, it should be removed while root1 remains",
		},
		{
			name:            "Add root3 in first position",
			initialHandlers: baseRootHandlers,
			updates: []handlerWrapper{
				{
					domain: ".",
					handler: &mockHandler{
						Id: "upstream-root3",
					},
					priority: PriorityDefault + 1,
				},
				{
					domain: ".",
					handler: &mockHandler{
						Id: "upstream-root1",
					},
					priority: PriorityDefault,
				},
				{
					domain: ".",
					handler: &mockHandler{
						Id: "upstream-root2",
					},
					priority: PriorityDefault - 1,
				},
			},
			expectedHandlers: map[string]string{
				"upstream-root1": ".",
				"upstream-root2": ".",
				"upstream-root3": ".",
			},
			description: "When adding root3 with highest priority, it should be first in chain while maintaining existing root handlers",
		},
		{
			name:            "Add root3 in last position",
			initialHandlers: baseRootHandlers,
			updates: []handlerWrapper{
				{
					domain: ".",
					handler: &mockHandler{
						Id: "upstream-root1",
					},
					priority: PriorityDefault,
				},
				{
					domain: ".",
					handler: &mockHandler{
						Id: "upstream-root2",
					},
					priority: PriorityDefault - 1,
				},
				{
					domain: ".",
					handler: &mockHandler{
						Id: "upstream-root3",
					},
					priority: PriorityDefault - 2,
				},
			},
			expectedHandlers: map[string]string{
				"upstream-root1": ".",
				"upstream-root2": ".",
				"upstream-root3": ".",
			},
			description: "When adding root3 with lowest priority, it should be last in chain while maintaining existing root handlers",
		},
		// Mixed domain tests
		{
			name:            "Update with mixed domains - remove one of duplicate domain",
			initialHandlers: baseMixedHandlers,
			updates: []handlerWrapper{
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group1",
					},
					priority: PriorityMatchDomain,
				},
				{
					domain: "other.com",
					handler: &mockHandler{
						Id: "upstream-other",
					},
					priority: PriorityMatchDomain,
				},
			},
			expectedHandlers: map[string]string{
				"upstream-group1": "example.com",
				"upstream-other":  "other.com",
			},
			description: "When updating mixed domains, should correctly handle removal of one duplicate while maintaining other domains",
		},
		{
			name:            "Update with mixed domains - add new domain",
			initialHandlers: baseMixedHandlers,
			updates: []handlerWrapper{
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group1",
					},
					priority: PriorityMatchDomain,
				},
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group2",
					},
					priority: PriorityMatchDomain - 1,
				},
				{
					domain: "other.com",
					handler: &mockHandler{
						Id: "upstream-other",
					},
					priority: PriorityMatchDomain,
				},
				{
					domain: "new.com",
					handler: &mockHandler{
						Id: "upstream-new",
					},
					priority: PriorityMatchDomain,
				},
			},
			expectedHandlers: map[string]string{
				"upstream-group1": "example.com",
				"upstream-group2": "example.com",
				"upstream-other":  "other.com",
				"upstream-new":    "new.com",
			},
			description: "When updating mixed domains, should maintain existing duplicates and add new domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &DefaultServer{
				dnsMuxMap:    tt.initialHandlers,
				handlerChain: NewHandlerChain(),
				service:      &mockService{},
			}

			// Perform the update
			server.updateMux(tt.updates)

			// Verify the results
			assert.Equal(t, len(tt.expectedHandlers), len(server.dnsMuxMap),
				"Number of handlers after update doesn't match expected")

			// Check each expected handler
			for id, expectedDomain := range tt.expectedHandlers {
				handler, exists := server.dnsMuxMap[handlerID(id)]
				assert.True(t, exists, "Expected handler %s not found", id)
				if exists {
					assert.Equal(t, expectedDomain, handler.domain,
						"Domain mismatch for handler %s", id)
				}
			}

			// Verify no unexpected handlers exist
			for handlerID := range server.dnsMuxMap {
				_, expected := tt.expectedHandlers[string(handlerID)]
				assert.True(t, expected, "Unexpected handler found: %s", handlerID)
			}

			// Verify the handlerChain state and order
			previousPriority := 0
			for _, chainEntry := range server.handlerChain.handlers {
				// Verify priority order
				if previousPriority > 0 {
					assert.True(t, chainEntry.Priority <= previousPriority,
						"Handlers in chain not properly ordered by priority")
				}
				previousPriority = chainEntry.Priority

				// Verify handler exists in mux
				foundInMux := false
				for _, muxEntry := range server.dnsMuxMap {
					if chainEntry.Handler == muxEntry.handler &&
						chainEntry.Priority == muxEntry.priority &&
						chainEntry.Pattern == dns.Fqdn(muxEntry.domain) {
						foundInMux = true
						break
					}
				}
				assert.True(t, foundInMux,
					"Handler in chain not found in dnsMuxMap")
			}
		})
	}
}

func TestExtraDomains(t *testing.T) {
	tests := []struct {
		name                string
		initialConfig       nbdns.Config
		registerDomains     []domain.List
		deregisterDomains   []domain.List
		finalConfig         nbdns.Config
		expectedDomains     []string
		expectedMatchOnly   []string
		applyHostConfigCall int
	}{
		{
			name: "Register domains before config update",
			registerDomains: []domain.List{
				{"extra1.example.com", "extra2.example.com"},
			},
			initialConfig: nbdns.Config{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{Domain: "config.example.com"},
				},
			},
			expectedDomains: []string{
				"config.example.com.",
				"extra1.example.com.",
				"extra2.example.com.",
			},
			expectedMatchOnly: []string{
				"extra1.example.com.",
				"extra2.example.com.",
			},
			applyHostConfigCall: 2,
		},
		{
			name: "Register domains after config update",
			initialConfig: nbdns.Config{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{Domain: "config.example.com"},
				},
			},
			registerDomains: []domain.List{
				{"extra1.example.com", "extra2.example.com"},
			},
			expectedDomains: []string{
				"config.example.com.",
				"extra1.example.com.",
				"extra2.example.com.",
			},
			expectedMatchOnly: []string{
				"extra1.example.com.",
				"extra2.example.com.",
			},
			applyHostConfigCall: 2,
		},
		{
			name: "Register overlapping domains",
			initialConfig: nbdns.Config{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{Domain: "config.example.com"},
					{Domain: "overlap.example.com"},
				},
			},
			registerDomains: []domain.List{
				{"extra.example.com", "overlap.example.com"},
			},
			expectedDomains: []string{
				"config.example.com.",
				"overlap.example.com.",
				"extra.example.com.",
			},
			expectedMatchOnly: []string{
				"extra.example.com.",
			},
			applyHostConfigCall: 2,
		},
		{
			name: "Register and deregister domains",
			initialConfig: nbdns.Config{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{Domain: "config.example.com"},
				},
			},
			registerDomains: []domain.List{
				{"extra1.example.com", "extra2.example.com"},
				{"extra3.example.com", "extra4.example.com"},
			},
			deregisterDomains: []domain.List{
				{"extra1.example.com", "extra3.example.com"},
			},
			expectedDomains: []string{
				"config.example.com.",
				"extra2.example.com.",
				"extra4.example.com.",
			},
			expectedMatchOnly: []string{
				"extra2.example.com.",
				"extra4.example.com.",
			},
			applyHostConfigCall: 4,
		},
		{
			name: "Register domains with ref counter",
			initialConfig: nbdns.Config{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{Domain: "config.example.com"},
				},
			},
			registerDomains: []domain.List{
				{"extra.example.com", "duplicate.example.com"},
				{"other.example.com", "duplicate.example.com"},
			},
			deregisterDomains: []domain.List{
				{"duplicate.example.com"},
			},
			expectedDomains: []string{
				"config.example.com.",
				"extra.example.com.",
				"other.example.com.",
				"duplicate.example.com.",
			},
			expectedMatchOnly: []string{
				"extra.example.com.",
				"other.example.com.",
				"duplicate.example.com.",
			},
			applyHostConfigCall: 4,
		},
		{
			name: "Config update with new domains after registration",
			initialConfig: nbdns.Config{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{Domain: "config.example.com"},
				},
			},
			registerDomains: []domain.List{
				{"extra.example.com", "duplicate.example.com"},
			},
			finalConfig: nbdns.Config{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{Domain: "config.example.com"},
					{Domain: "newconfig.example.com"},
				},
			},
			expectedDomains: []string{
				"config.example.com.",
				"newconfig.example.com.",
				"extra.example.com.",
				"duplicate.example.com.",
			},
			expectedMatchOnly: []string{
				"extra.example.com.",
				"duplicate.example.com.",
			},
			applyHostConfigCall: 3,
		},
		{
			name: "Deregister domain that is part of customZones",
			initialConfig: nbdns.Config{
				ServiceEnable: true,
				CustomZones: []nbdns.CustomZone{
					{Domain: "config.example.com"},
					{Domain: "protected.example.com"},
				},
			},
			registerDomains: []domain.List{
				{"extra.example.com", "protected.example.com"},
			},
			deregisterDomains: []domain.List{
				{"protected.example.com"},
			},
			expectedDomains: []string{
				"extra.example.com.",
				"config.example.com.",
				"protected.example.com.",
			},
			expectedMatchOnly: []string{
				"extra.example.com.",
			},
			applyHostConfigCall: 3,
		},
		{
			name: "Register domain that is part of nameserver group",
			initialConfig: nbdns.Config{
				ServiceEnable: true,
				NameServerGroups: []*nbdns.NameServerGroup{
					{
						Domains: []string{"ns.example.com", "overlap.ns.example.com"},
						NameServers: []nbdns.NameServer{
							{
								IP:     netip.MustParseAddr("8.8.8.8"),
								NSType: nbdns.UDPNameServerType,
								Port:   53,
							},
						},
					},
				},
			},
			registerDomains: []domain.List{
				{"extra.example.com", "overlap.ns.example.com"},
			},
			expectedDomains: []string{
				"ns.example.com.",
				"overlap.ns.example.com.",
				"extra.example.com.",
			},
			expectedMatchOnly: []string{
				"ns.example.com.",
				"overlap.ns.example.com.",
				"extra.example.com.",
			},
			applyHostConfigCall: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedConfigs []HostDNSConfig
			mockHostConfig := &mockHostConfigurator{
				applyDNSConfigFunc: func(config HostDNSConfig, _ *statemanager.Manager) error {
					capturedConfigs = append(capturedConfigs, config)
					return nil
				},
				restoreHostDNSFunc: func() error {
					return nil
				},
				supportCustomPortFunc: func() bool {
					return true
				},
				stringFunc: func() string {
					return "mock"
				},
			}

			mockSvc := &mockService{}

			server := &DefaultServer{
				ctx:            context.Background(),
				handlerChain:   NewHandlerChain(),
				wgInterface:    &mocWGIface{},
				hostManager:    mockHostConfig,
				localResolver:  &localResolver{},
				service:        mockSvc,
				statusRecorder: peer.NewRecorder("test"),
				extraDomains:   make(map[domain.Domain]int),
			}

			// Apply initial configuration
			if tt.initialConfig.ServiceEnable {
				err := server.applyConfiguration(tt.initialConfig)
				assert.NoError(t, err)
			}

			// Register domains
			for _, domains := range tt.registerDomains {
				server.RegisterHandler(domains, &MockHandler{}, PriorityDefault)
			}

			// Deregister domains if specified
			for _, domains := range tt.deregisterDomains {
				server.DeregisterHandler(domains, PriorityDefault)
			}

			// Apply final configuration if specified
			if tt.finalConfig.ServiceEnable {
				err := server.applyConfiguration(tt.finalConfig)
				assert.NoError(t, err)
			}

			// Verify number of calls
			assert.Equal(t, tt.applyHostConfigCall, len(capturedConfigs),
				"Expected %d calls to applyDNSConfig, got %d", tt.applyHostConfigCall, len(capturedConfigs))

			// Get the last applied config
			lastConfig := capturedConfigs[len(capturedConfigs)-1]

			// Check all expected domains are present
			domainMap := make(map[string]bool)
			matchOnlyMap := make(map[string]bool)

			for _, d := range lastConfig.Domains {
				domainMap[d.Domain] = true
				if d.MatchOnly {
					matchOnlyMap[d.Domain] = true
				}
			}

			// Verify expected domains
			for _, d := range tt.expectedDomains {
				assert.True(t, domainMap[d], "Expected domain %s not found in final config", d)
			}

			// Verify match-only domains
			for _, d := range tt.expectedMatchOnly {
				assert.True(t, matchOnlyMap[d], "Expected match-only domain %s not found in final config", d)
			}

			// Verify no unexpected domains
			assert.Equal(t, len(tt.expectedDomains), len(domainMap), "Unexpected number of domains in final config")
			assert.Equal(t, len(tt.expectedMatchOnly), len(matchOnlyMap), "Unexpected number of match-only domains in final config")
		})
	}
}

func TestExtraDomainsRefCounting(t *testing.T) {
	mockHostConfig := &mockHostConfigurator{
		applyDNSConfigFunc: func(config HostDNSConfig, _ *statemanager.Manager) error {
			return nil
		},
		restoreHostDNSFunc: func() error {
			return nil
		},
		supportCustomPortFunc: func() bool {
			return true
		},
		stringFunc: func() string {
			return "mock"
		},
	}

	mockSvc := &mockService{}

	server := &DefaultServer{
		ctx:            context.Background(),
		handlerChain:   NewHandlerChain(),
		hostManager:    mockHostConfig,
		localResolver:  &localResolver{},
		service:        mockSvc,
		statusRecorder: peer.NewRecorder("test"),
		extraDomains:   make(map[domain.Domain]int),
	}

	// Register domains from different handlers with same domain
	server.RegisterHandler(domain.List{"*.shared.example.com"}, &MockHandler{}, PriorityDNSRoute)
	server.RegisterHandler(domain.List{"shared.example.com."}, &MockHandler{}, PriorityMatchDomain)

	// Verify refcount is 2
	zoneKey := toZone("shared.example.com")
	assert.Equal(t, 2, server.extraDomains[zoneKey], "Refcount should be 2 after registering same domain twice")

	// Deregister one handler
	server.DeregisterHandler(domain.List{"shared.example.com"}, PriorityMatchDomain)

	// Verify refcount is 1
	assert.Equal(t, 1, server.extraDomains[zoneKey], "Refcount should be 1 after deregistering one handler")

	// Deregister the other handler
	server.DeregisterHandler(domain.List{"shared.example.com"}, PriorityDNSRoute)

	// Verify domain is removed
	_, exists := server.extraDomains[zoneKey]
	assert.False(t, exists, "Domain should be removed after deregistering all handlers")
}

func TestUpdateConfigWithExistingExtraDomains(t *testing.T) {
	var capturedConfig HostDNSConfig
	mockHostConfig := &mockHostConfigurator{
		applyDNSConfigFunc: func(config HostDNSConfig, _ *statemanager.Manager) error {
			capturedConfig = config
			return nil
		},
		restoreHostDNSFunc: func() error {
			return nil
		},
		supportCustomPortFunc: func() bool {
			return true
		},
		stringFunc: func() string {
			return "mock"
		},
	}

	mockSvc := &mockService{}

	server := &DefaultServer{
		ctx:            context.Background(),
		handlerChain:   NewHandlerChain(),
		hostManager:    mockHostConfig,
		localResolver:  &localResolver{},
		service:        mockSvc,
		statusRecorder: peer.NewRecorder("test"),
		extraDomains:   make(map[domain.Domain]int),
	}

	server.RegisterHandler(domain.List{"extra.example.com"}, &MockHandler{}, PriorityDefault)

	initialConfig := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{Domain: "config.example.com"},
		},
	}
	err := server.applyConfiguration(initialConfig)
	assert.NoError(t, err)

	var domains []string
	for _, d := range capturedConfig.Domains {
		domains = append(domains, d.Domain)
	}
	assert.Contains(t, domains, "config.example.com.")
	assert.Contains(t, domains, "extra.example.com.")

	// Now apply a new configuration with overlapping domain
	updatedConfig := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{Domain: "config.example.com"},
			{Domain: "extra.example.com"},
		},
	}
	err = server.applyConfiguration(updatedConfig)
	assert.NoError(t, err)

	// Verify both domains are in config, but no duplicates
	domains = []string{}
	matchOnlyCount := 0
	for _, d := range capturedConfig.Domains {
		domains = append(domains, d.Domain)
		if d.MatchOnly {
			matchOnlyCount++
		}
	}

	assert.Contains(t, domains, "config.example.com.")
	assert.Contains(t, domains, "extra.example.com.")
	assert.Equal(t, 2, len(domains), "Should have exactly 2 domains with no duplicates")

	// Extra domain should no longer be marked as match-only when in config
	matchOnlyDomain := ""
	for _, d := range capturedConfig.Domains {
		if d.Domain == "extra.example.com." && d.MatchOnly {
			matchOnlyDomain = d.Domain
			break
		}
	}
	assert.Empty(t, matchOnlyDomain, "Domain should not be match-only when included in config")
}

func TestDomainCaseHandling(t *testing.T) {
	var capturedConfig HostDNSConfig
	mockHostConfig := &mockHostConfigurator{
		applyDNSConfigFunc: func(config HostDNSConfig, _ *statemanager.Manager) error {
			capturedConfig = config
			return nil
		},
		restoreHostDNSFunc: func() error {
			return nil
		},
		supportCustomPortFunc: func() bool {
			return true
		},
		stringFunc: func() string {
			return "mock"
		},
	}

	mockSvc := &mockService{}
	server := &DefaultServer{
		ctx:            context.Background(),
		handlerChain:   NewHandlerChain(),
		hostManager:    mockHostConfig,
		localResolver:  &localResolver{},
		service:        mockSvc,
		statusRecorder: peer.NewRecorder("test"),
		extraDomains:   make(map[domain.Domain]int),
	}

	server.RegisterHandler(domain.List{"MIXED.example.com"}, &MockHandler{}, PriorityDefault)
	server.RegisterHandler(domain.List{"mixed.EXAMPLE.com"}, &MockHandler{}, PriorityMatchDomain)

	assert.Equal(t, 1, len(server.extraDomains), "Case differences should be normalized")

	config := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{Domain: "config.example.com"},
		},
	}
	err := server.applyConfiguration(config)
	assert.NoError(t, err)

	var domains []string
	for _, d := range capturedConfig.Domains {
		domains = append(domains, d.Domain)
	}
	assert.Contains(t, domains, "config.example.com.", "Mixed case domain should be normalized and pre.sent")
	assert.Contains(t, domains, "mixed.example.com.", "Mixed case domain should be normalized and present")
}

// TestDefaultServer_UpdateLocalRecords_StaleRecord verifies that updating
// a CustomZone record correctly replaces the old one, preventing stale entries.
func TestDefaultServer_UpdateLocalRecords_StaleRecord(t *testing.T) {
	mockHostMgr := newNoopHostMocker()
	mockSvc := &mockService{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dnsServer := newDefaultServer(
		ctx,
		&mocWGIface{},
		mockSvc,
		peer.NewRecorder("test"),
		nil,
		true,
	)
	dnsServer.hostManager = mockHostMgr

	recordName := "host.example.com."
	recordType := dns.TypeA
	recordClass := dns.ClassINET

	record1 := nbdns.SimpleRecord{
		Name: recordName, Type: int(recordType), Class: nbdns.DefaultClass, TTL: 300, RData: "1.1.1.1",
	}
	config1 := nbdns.Config{
		ServiceEnable: true,
		CustomZones:   []nbdns.CustomZone{{Domain: "example.com", Records: []nbdns.SimpleRecord{record1}}},
	}

	record2 := nbdns.SimpleRecord{
		Name: recordName, Type: int(recordType), Class: nbdns.DefaultClass, TTL: 300, RData: "2.2.2.2",
	}
	config2 := nbdns.Config{
		ServiceEnable: true,
		CustomZones:   []nbdns.CustomZone{{Domain: "example.com", Records: []nbdns.SimpleRecord{record2}}},
	}

	recordKey := buildRecordKey(recordName, uint16(recordClass), uint16(recordType))

	// Update 1
	err := dnsServer.applyConfiguration(config1)
	require.NoError(t, err, "applyConfiguration for config1 failed")

	value1, found1 := dnsServer.localResolver.records.Load(recordKey)
	require.True(t, found1, "Record key %s not found after first update", recordKey)
	rrSlice1, ok1 := value1.([]dns.RR)
	require.True(t, ok1, "Failed to cast value to []dns.RR after first update")
	require.Len(t, rrSlice1, 1, "Should have exactly 1 record after first update")
	assert.Contains(t, rrSlice1[0].String(), record1.RData, "Record after first update should be %s", record1.RData)

	// Update 2
	err = dnsServer.applyConfiguration(config2)
	require.NoError(t, err, "applyConfiguration for config2 failed")

	value2, found2 := dnsServer.localResolver.records.Load(recordKey)
	require.True(t, found2, "Record key %s not found after second update", recordKey)
	rrSlice2, ok2 := value2.([]dns.RR)
	require.True(t, ok2, "Failed to cast value to []dns.RR after second update")

	require.Len(t, rrSlice2, 1, "Should have exactly 1 record after update overwriting the key")

	assert.Contains(t, rrSlice2[0].String(), record2.RData, "The single record should be the updated one (%s)", record2.RData)
	assert.NotContains(t, rrSlice2[0].String(), record1.RData, "The stale record (%s) should not be present", record1.RData)
}
