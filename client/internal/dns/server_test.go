package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/dns/local"
	"github.com/netbirdio/netbird/client/internal/dns/test"
	"github.com/netbirdio/netbird/client/internal/dns/types"
	"github.com/netbirdio/netbird/client/internal/netflow"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/proto"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/formatter"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

var flowLogger = netflow.NewManager(nil, []byte{}, nil).GetLogger()

type mocWGIface struct {
	filter device.PacketFilter
}

func (w *mocWGIface) Name() string {
	return "utun2301"
}

func (w *mocWGIface) Address() wgaddr.Address {
	return wgaddr.Address{
		IP:      netip.MustParseAddr("100.66.100.1"),
		Network: netip.MustParsePrefix("100.66.100.0/24"),
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

func (w *mocWGIface) GetNet() *netstack.Net {
	return nil
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
			dnsServer, err := NewDefaultServer(context.Background(), DefaultServerConfig{
				WgInterface:    &mocWGIface{},
				CustomAddress:  testCase.addrPort,
				StatusRecorder: peer.NewRecorder("mgm"),
				StateManager:   nil,
				DisableSys:     false,
			})
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
			err = dnsServer.localResolver.RegisterRecord(zoneRecords[0])
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

func TestDNSPermanent_updateHostDNS_emptyUpstream(t *testing.T) {
	skipUnlessAndroid(t)
	wgIFace, err := createWgInterfaceWithBind(t)
	if err != nil {
		t.Fatal("failed to initialize wg interface")
	}
	defer wgIFace.Close()

	var dnsList []netip.AddrPort
	dnsConfig := nbdns.Config{}
	dnsServer := NewDefaultServerPermanentUpstream(context.Background(), wgIFace, dnsList, dnsConfig, nil, peer.NewRecorder("mgm"), false)
	err = dnsServer.Initialize()
	if err != nil {
		t.Errorf("failed to initialize DNS server: %v", err)
		return
	}
	defer dnsServer.Stop()

	addrPort := netip.MustParseAddrPort("8.8.8.8:53")
	dnsServer.OnUpdatedHostDNSServer([]netip.AddrPort{addrPort})

	resolver := newDnsResolver(dnsServer.service.RuntimeIP(), dnsServer.service.RuntimePort())
	_, err = resolver.LookupHost(context.Background(), "netbird.io")
	if err != nil {
		t.Errorf("failed to resolve: %s", err)
	}
}

func TestDNSPermanent_updateUpstream(t *testing.T) {
	skipUnlessAndroid(t)
	wgIFace, err := createWgInterfaceWithBind(t)
	if err != nil {
		t.Fatal("failed to initialize wg interface")
	}
	defer wgIFace.Close()
	dnsConfig := nbdns.Config{}
	addrPort := netip.MustParseAddrPort("8.8.8.8:53")
	dnsServer := NewDefaultServerPermanentUpstream(context.Background(), wgIFace, []netip.AddrPort{addrPort}, dnsConfig, nil, peer.NewRecorder("mgm"), false)
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
	skipUnlessAndroid(t)
	wgIFace, err := createWgInterfaceWithBind(t)
	if err != nil {
		t.Fatal("failed to initialize wg interface")
	}
	defer wgIFace.Close()
	dnsConfig := nbdns.Config{}
	addrPort := netip.MustParseAddrPort("8.8.8.8:53")
	dnsServer := NewDefaultServerPermanentUpstream(context.Background(), wgIFace, []netip.AddrPort{addrPort}, dnsConfig, nil, peer.NewRecorder("mgm"), false)
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

// skipUnlessAndroid marks tests that exercise the mobile-permanent DNS path,
// which only matches a real production setup on android (NewDefaultServerPermanentUpstream
// + androidHostManager). On non-android the desktop host manager replaces it
// during Initialize and the assertion stops making sense. Skipped here until we
// have an android CI runner.
func skipUnlessAndroid(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "android" {
		t.Skip("requires android runner; mobile-permanent path doesn't match production on this OS")
	}
}

func createWgInterfaceWithBind(t *testing.T) (*iface.WGIface, error) {
	t.Helper()
	ov := os.Getenv("NB_WG_KERNEL_DISABLED")
	defer t.Setenv("NB_WG_KERNEL_DISABLED", ov)

	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	newNet, err := stdnet.NewNet(context.Background(), []string{"utun2301"})
	if err != nil {
		t.Fatalf("create stdnet: %v", err)
		return nil, err
	}

	privKey, _ := wgtypes.GeneratePrivateKey()

	opts := iface.WGIFaceOpts{
		IFaceName:    "utun2301",
		Address:      wgaddr.MustParseWGAddress("100.66.100.2/24"),
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

	pf, err := uspfilter.Create(wgIface, false, flowLogger, iface.DefaultMTU)
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

func newDnsResolver(ip netip.Addr, port int) *net.Resolver {
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
	chain.AddHandler("example.com.", upstreamHandler, PriorityUpstream)

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
			w := &ResponseWriterChain{ResponseWriter: &test.MockResponseWriter{}}

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
func (m *mockHandler) Stop()                                 {}
func (m *mockHandler) ID() types.HandlerID                   { return types.HandlerID(m.Id) }

type mockService struct{}

func (m *mockService) Listen() error                   { return nil }
func (m *mockService) Stop() error                     { return nil }
func (m *mockService) RuntimeIP() netip.Addr           { return netip.MustParseAddr("127.0.0.1") }
func (m *mockService) RuntimePort() int                { return 53 }
func (m *mockService) RegisterMux(string, dns.Handler) {}
func (m *mockService) DeregisterMux(string)            {}

func TestDefaultServer_UpdateMux(t *testing.T) {
	baseMatchHandlers := []handlerWrapper{
		{
			domain: "example.com",
			handler: &mockHandler{
				Id: "upstream-group1",
			},
			priority: PriorityUpstream,
		},
		{
			domain: "example.com",
			handler: &mockHandler{
				Id: "upstream-group2",
			},
			priority: PriorityUpstream - 1,
		},
	}

	baseRootHandlers := []handlerWrapper{
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
	}

	baseMixedHandlers := []handlerWrapper{
		{
			domain: "example.com",
			handler: &mockHandler{
				Id: "upstream-group1",
			},
			priority: PriorityUpstream,
		},
		{
			domain: "example.com",
			handler: &mockHandler{
				Id: "upstream-group2",
			},
			priority: PriorityUpstream - 1,
		},
		{
			domain: "other.com",
			handler: &mockHandler{
				Id: "upstream-other",
			},
			priority: PriorityUpstream,
		},
	}

	tests := []struct {
		name             string
		initialHandlers  []handlerWrapper
		updates          []handlerWrapper
		expectedHandlers map[string]string // map[HandlerID]domain
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
					priority: PriorityUpstream - 1,
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
					priority: PriorityUpstream,
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
					priority: PriorityUpstream + 1,
				},
				// Keep existing groups with their original priorities
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group1",
					},
					priority: PriorityUpstream,
				},
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group2",
					},
					priority: PriorityUpstream - 1,
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
					priority: PriorityUpstream,
				},
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group2",
					},
					priority: PriorityUpstream - 1,
				},
				// Add group3 with lowest priority
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group3",
					},
					priority: PriorityUpstream - 2,
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
					priority: PriorityUpstream,
				},
				{
					domain: "other.com",
					handler: &mockHandler{
						Id: "upstream-other",
					},
					priority: PriorityUpstream,
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
					priority: PriorityUpstream,
				},
				{
					domain: "example.com",
					handler: &mockHandler{
						Id: "upstream-group2",
					},
					priority: PriorityUpstream - 1,
				},
				{
					domain: "other.com",
					handler: &mockHandler{
						Id: "upstream-other",
					},
					priority: PriorityUpstream,
				},
				{
					domain: "new.com",
					handler: &mockHandler{
						Id: "upstream-new",
					},
					priority: PriorityUpstream,
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
				dnsMuxHandlers: tt.initialHandlers,
				handlerChain:   NewHandlerChain(),
				service:        &mockService{},
			}

			// Perform the update
			server.updateMux(tt.updates)

			// Verify the results
			assert.Equal(t, len(tt.expectedHandlers), len(server.dnsMuxHandlers),
				"Number of handlers after update doesn't match expected")

			// Check each expected handler
			for id, expectedDomain := range tt.expectedHandlers {
				var found *handlerWrapper
				for i := range server.dnsMuxHandlers {
					if server.dnsMuxHandlers[i].handler.ID() == types.HandlerID(id) {
						found = &server.dnsMuxHandlers[i]
						break
					}
				}
				assert.NotNil(t, found, "Expected handler %s not found", id)
				if found != nil {
					assert.Equal(t, expectedDomain, found.domain,
						"Domain mismatch for handler %s", id)
				}
			}

			// Verify no unexpected handlers exist
			for _, entry := range server.dnsMuxHandlers {
				_, expected := tt.expectedHandlers[string(entry.handler.ID())]
				assert.True(t, expected, "Unexpected handler found: %s", entry.handler.ID())
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
				for _, muxEntry := range server.dnsMuxHandlers {
					if chainEntry.Handler == muxEntry.handler &&
						chainEntry.Priority == muxEntry.priority &&
						chainEntry.Pattern == dns.Fqdn(muxEntry.domain) {
						foundInMux = true
						break
					}
				}
				assert.True(t, foundInMux,
					"Handler in chain not found in dnsMuxHandlers")
			}
		})
	}
}

// chainHasPattern reports whether the handler chain holds an entry registered
// for the given fqdn pattern at the given priority.
func chainHasPattern(s *DefaultServer, pattern string, priority int) bool {
	for _, h := range s.handlerChain.handlers {
		if h.OrigPattern == pattern && h.Priority == priority {
			return true
		}
	}
	return false
}

// TestDefaultServer_UpdateMux_SharedHandlerZoneRemoval verifies that updateMux
// tracks each (handler, domain) registration independently when one handler
// serves multiple zones. Every custom zone is served by the same handler
// instance (the local resolver, whose ID is the constant "local-resolver"), so
// removing one zone must deregister exactly that zone's chain entry and leave
// the others in place. Tracking registrations by handler ID alone collapses all
// zones onto one entry, leaving removed zones in the chain to answer
// authoritatively with no records.
func TestDefaultServer_UpdateMux_SharedHandlerZoneRemoval(t *testing.T) {
	// One handler serves every custom zone, mirroring s.localResolver.
	shared := &mockHandler{Id: "local-resolver"}

	server := &DefaultServer{
		handlerChain: NewHandlerChain(),
		service:      &mockService{},
	}

	// Two custom zones under the same handler. The surviving zone is registered
	// last, mirroring the management emission order.
	server.updateMux([]handlerWrapper{
		{domain: "userzone.test", handler: shared, priority: PriorityLocal},
		{domain: "peerzone.test", handler: shared, priority: PriorityLocal},
	})

	require.True(t, chainHasPattern(server, "userzone.test.", PriorityLocal),
		"userzone.test should be registered after the first update")
	require.True(t, chainHasPattern(server, "peerzone.test.", PriorityLocal),
		"peerzone.test should be registered after the first update")

	// Remove one zone, keep the other.
	server.updateMux([]handlerWrapper{
		{domain: "peerzone.test", handler: shared, priority: PriorityLocal},
	})

	assert.True(t, chainHasPattern(server, "peerzone.test.", PriorityLocal),
		"peerzone.test should remain after removing userzone.test")
	assert.False(t, chainHasPattern(server, "userzone.test.", PriorityLocal),
		"userzone.test handler must be deregistered, not leaked in the chain")
}

// TestDefaultServer_UpdateMux_PreservesLocalResolver verifies that updateMux
// does not tear down the shared local resolver during reconfiguration. The
// resolver is a process-lifetime singleton reused across config updates;
// Stop() cancels its lookup context (breaking external CNAME-target
// resolution) and clears its records. updateMux must deregister its chain
// entries without stopping it. Records surviving a teardown update is the
// observable proxy: Stop() would have cleared them.
func TestDefaultServer_UpdateMux_PreservesLocalResolver(t *testing.T) {
	resolver := local.NewResolver()
	require.NoError(t, resolver.RegisterRecord(nbdns.SimpleRecord{
		Name:  "peer.netbird.cloud.",
		Type:  int(dns.TypeA),
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "10.0.0.1",
	}))

	server := &DefaultServer{
		handlerChain:  NewHandlerChain(),
		service:       &mockService{},
		localResolver: resolver,
	}

	server.updateMux([]handlerWrapper{
		{domain: "netbird.cloud", handler: resolver, priority: PriorityLocal},
	})

	// Remove the zone. The resolver must survive so its records and lookup
	// context stay intact for the next registration.
	server.updateMux(nil)

	var response *dns.Msg
	resolver.ServeDNS(&test.MockResponseWriter{
		WriteMsgFunc: func(m *dns.Msg) error {
			response = m
			return nil
		},
	}, &dns.Msg{Question: []dns.Question{{Name: "peer.netbird.cloud.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}})

	require.NotNil(t, response, "local resolver should answer after teardown")
	assert.Equal(t, dns.RcodeSuccess, response.Rcode,
		"local resolver records must survive teardown; updateMux must not Stop() the shared resolver")
	assert.NotEmpty(t, response.Answer, "answer should contain the surviving record")
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
			// Expect 3 calls instead of 4 because when deregistering duplicate.example.com,
			// the domain remains in the config (ref count goes from 2 to 1), so the host
			// config hash doesn't change and applyDNSConfig is not called.
			applyHostConfigCall: 3,
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
			// Expect 2 calls instead of 3 because when deregistering protected.example.com,
			// it's removed from extraDomains but still remains in the config (from customZones),
			// so the host config hash doesn't change and applyDNSConfig is not called.
			applyHostConfigCall: 2,
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
				localResolver:  &local.Resolver{},
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
		localResolver:  &local.Resolver{},
		service:        mockSvc,
		statusRecorder: peer.NewRecorder("test"),
		extraDomains:   make(map[domain.Domain]int),
	}

	// Register domains from different handlers with same domain
	server.RegisterHandler(domain.List{"*.shared.example.com"}, &MockHandler{}, PriorityDNSRoute)
	server.RegisterHandler(domain.List{"shared.example.com."}, &MockHandler{}, PriorityUpstream)

	// Verify refcount is 2
	zoneKey := toZone("shared.example.com")
	assert.Equal(t, 2, server.extraDomains[zoneKey], "Refcount should be 2 after registering same domain twice")

	// Deregister one handler
	server.DeregisterHandler(domain.List{"shared.example.com"}, PriorityUpstream)

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
		localResolver:  &local.Resolver{},
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
		localResolver:  &local.Resolver{},
		service:        mockSvc,
		statusRecorder: peer.NewRecorder("test"),
		extraDomains:   make(map[domain.Domain]int),
	}

	server.RegisterHandler(domain.List{"MIXED.example.com"}, &MockHandler{}, PriorityDefault)
	server.RegisterHandler(domain.List{"mixed.EXAMPLE.com"}, &MockHandler{}, PriorityUpstream)

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

func TestLocalResolverPriorityInServer(t *testing.T) {
	server := &DefaultServer{
		ctx:           context.Background(),
		wgInterface:   &mocWGIface{},
		handlerChain:  NewHandlerChain(),
		localResolver: local.NewResolver(),
		service:       &mockService{},
		extraDomains:  make(map[domain.Domain]int),
	}

	config := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "local.example.com",
				Records: []nbdns.SimpleRecord{
					{
						Name:  "test.local.example.com",
						Type:  int(dns.TypeA),
						Class: nbdns.DefaultClass,
						TTL:   300,
						RData: "192.168.1.100",
					},
				},
			},
		},
		NameServerGroups: []*nbdns.NameServerGroup{
			{
				Domains: []string{"local.example.com"}, // Same domain as local records
				NameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("8.8.8.8"),
						NSType: nbdns.UDPNameServerType,
						Port:   53,
					},
				},
			},
		},
	}

	localMuxUpdates, _, err := server.buildLocalHandlerUpdate(config.CustomZones)
	assert.NoError(t, err)

	upstreamMuxUpdates, err := server.buildUpstreamHandlerUpdate(config.NameServerGroups)
	assert.NoError(t, err)

	// Verify that local handler has higher priority than upstream for same domain
	var localPriority, upstreamPriority int
	localFound, upstreamFound := false, false

	for _, update := range localMuxUpdates {
		if update.domain == "local.example.com" {
			localPriority = update.priority
			localFound = true
		}
	}

	for _, update := range upstreamMuxUpdates {
		if update.domain == "local.example.com" {
			upstreamPriority = update.priority
			upstreamFound = true
		}
	}

	assert.True(t, localFound, "Local handler should be found")
	assert.True(t, upstreamFound, "Upstream handler should be found")
	assert.Greater(t, localPriority, upstreamPriority,
		"Local handler priority (%d) should be higher than upstream priority (%d)",
		localPriority, upstreamPriority)
	assert.Equal(t, PriorityLocal, localPriority, "Local handler should use PriorityLocal")
	assert.Equal(t, PriorityUpstream, upstreamPriority, "Upstream handler should use PriorityUpstream")
}

func TestLocalResolverPriorityConstants(t *testing.T) {
	// Test that priority constants are ordered correctly
	assert.Greater(t, PriorityDNSRoute, PriorityLocal, "DNS Route should be higher than Local priority")
	assert.Greater(t, PriorityLocal, PriorityUpstream, "Local priority should be higher than upstream")
	assert.Greater(t, PriorityUpstream, PriorityDefault, "Upstream priority should be higher than default")

	// Test that local resolver uses the correct priority
	server := &DefaultServer{
		localResolver: local.NewResolver(),
	}

	config := nbdns.Config{
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "local.example.com",
				Records: []nbdns.SimpleRecord{
					{
						Name:  "test.local.example.com",
						Type:  int(dns.TypeA),
						Class: nbdns.DefaultClass,
						TTL:   300,
						RData: "192.168.1.100",
					},
				},
			},
		},
	}

	localMuxUpdates, _, err := server.buildLocalHandlerUpdate(config.CustomZones)
	assert.NoError(t, err)
	assert.Len(t, localMuxUpdates, 1)
	assert.Equal(t, PriorityLocal, localMuxUpdates[0].priority, "Local handler should use PriorityLocal")
	assert.Equal(t, "local.example.com", localMuxUpdates[0].domain)
}

// TestBuildUpstreamHandler_MergesGroupsPerDomain verifies that multiple
// admin-defined nameserver groups targeting the same domain collapse into a
// single handler with each group preserved as a sequential inner list.
func TestBuildUpstreamHandler_MergesGroupsPerDomain(t *testing.T) {
	wgInterface := &mocWGIface{}
	service := NewServiceViaMemory(wgInterface)
	server := &DefaultServer{
		ctx:           context.Background(),
		wgInterface:   wgInterface,
		service:       service,
		localResolver: local.NewResolver(),
		handlerChain:  NewHandlerChain(),
		hostManager:   &noopHostConfigurator{},
	}

	groups := []*nbdns.NameServerGroup{
		{
			NameServers: []nbdns.NameServer{
				{IP: netip.MustParseAddr("192.0.2.1"), NSType: nbdns.UDPNameServerType, Port: 53},
			},
			Domains: []string{"example.com"},
		},
		{
			NameServers: []nbdns.NameServer{
				{IP: netip.MustParseAddr("192.0.2.2"), NSType: nbdns.UDPNameServerType, Port: 53},
				{IP: netip.MustParseAddr("192.0.2.3"), NSType: nbdns.UDPNameServerType, Port: 53},
			},
			Domains: []string{"example.com"},
		},
	}

	muxUpdates, err := server.buildUpstreamHandlerUpdate(groups)
	require.NoError(t, err)
	require.Len(t, muxUpdates, 1, "same-domain groups should merge into one handler")
	assert.Equal(t, "example.com", muxUpdates[0].domain)
	assert.Equal(t, PriorityUpstream, muxUpdates[0].priority)

	handler := muxUpdates[0].handler.(*upstreamResolver)
	require.Len(t, handler.upstreamServers, 2, "handler should have two groups")
	assert.Equal(t, upstreamRace{netip.MustParseAddrPort("192.0.2.1:53")}, handler.upstreamServers[0])
	assert.Equal(t, upstreamRace{
		netip.MustParseAddrPort("192.0.2.2:53"),
		netip.MustParseAddrPort("192.0.2.3:53"),
	}, handler.upstreamServers[1])
}

// TestEvaluateNSGroupHealth covers the records-only verdict. The gate
// (overlay route selected-but-no-active-peer) is intentionally NOT an
// input to the evaluator anymore: the verdict drives the Enabled flag,
// which must always reflect what we actually observed. Gate-aware event
// suppression is tested separately in the projection test.
//
// Matrix per upstream: {no record, fresh Ok, fresh Fail, stale Fail,
// stale Ok, Ok newer than Fail, Fail newer than Ok}.
// Group verdict: any fresh-working → Healthy; any fresh-broken with no
// fresh-working → Unhealthy; otherwise Undecided.
func TestEvaluateNSGroupHealth(t *testing.T) {
	now := time.Now()
	a := netip.MustParseAddrPort("192.0.2.1:53")
	b := netip.MustParseAddrPort("192.0.2.2:53")

	recentOk := UpstreamHealth{LastOk: now.Add(-2 * time.Second)}
	recentFail := UpstreamHealth{LastFail: now.Add(-1 * time.Second), LastErr: "timeout"}
	staleOk := UpstreamHealth{LastOk: now.Add(-10 * time.Minute)}
	staleFail := UpstreamHealth{LastFail: now.Add(-10 * time.Minute), LastErr: "timeout"}
	okThenFail := UpstreamHealth{
		LastOk:   now.Add(-10 * time.Second),
		LastFail: now.Add(-1 * time.Second),
		LastErr:  "timeout",
	}
	failThenOk := UpstreamHealth{
		LastOk:   now.Add(-1 * time.Second),
		LastFail: now.Add(-10 * time.Second),
		LastErr:  "timeout",
	}

	tests := []struct {
		name         string
		health       map[netip.AddrPort]UpstreamHealth
		servers      []netip.AddrPort
		wantVerdict  nsGroupVerdict
		wantErrSubst string
	}{
		{
			name:        "no record, undecided",
			servers:     []netip.AddrPort{a},
			wantVerdict: nsVerdictUndecided,
		},
		{
			name:        "fresh success, healthy",
			health:      map[netip.AddrPort]UpstreamHealth{a: recentOk},
			servers:     []netip.AddrPort{a},
			wantVerdict: nsVerdictHealthy,
		},
		{
			name:         "fresh failure, unhealthy",
			health:       map[netip.AddrPort]UpstreamHealth{a: recentFail},
			servers:      []netip.AddrPort{a},
			wantVerdict:  nsVerdictUnhealthy,
			wantErrSubst: "timeout",
		},
		{
			name:        "only stale success, undecided",
			health:      map[netip.AddrPort]UpstreamHealth{a: staleOk},
			servers:     []netip.AddrPort{a},
			wantVerdict: nsVerdictUndecided,
		},
		{
			name:        "only stale failure, undecided",
			health:      map[netip.AddrPort]UpstreamHealth{a: staleFail},
			servers:     []netip.AddrPort{a},
			wantVerdict: nsVerdictUndecided,
		},
		{
			name:         "both fresh, fail newer, unhealthy",
			health:       map[netip.AddrPort]UpstreamHealth{a: okThenFail},
			servers:      []netip.AddrPort{a},
			wantVerdict:  nsVerdictUnhealthy,
			wantErrSubst: "timeout",
		},
		{
			name:        "both fresh, ok newer, healthy",
			health:      map[netip.AddrPort]UpstreamHealth{a: failThenOk},
			servers:     []netip.AddrPort{a},
			wantVerdict: nsVerdictHealthy,
		},
		{
			name: "two upstreams, one success wins",
			health: map[netip.AddrPort]UpstreamHealth{
				a: recentFail,
				b: recentOk,
			},
			servers:     []netip.AddrPort{a, b},
			wantVerdict: nsVerdictHealthy,
		},
		{
			name: "two upstreams, one fail one unseen, unhealthy",
			health: map[netip.AddrPort]UpstreamHealth{
				a: recentFail,
			},
			servers:      []netip.AddrPort{a, b},
			wantVerdict:  nsVerdictUnhealthy,
			wantErrSubst: "timeout",
		},
		{
			name: "two upstreams, all recent failures, unhealthy",
			health: map[netip.AddrPort]UpstreamHealth{
				a: {LastFail: now.Add(-5 * time.Second), LastErr: "timeout"},
				b: {LastFail: now.Add(-1 * time.Second), LastErr: "SERVFAIL"},
			},
			servers:      []netip.AddrPort{a, b},
			wantVerdict:  nsVerdictUnhealthy,
			wantErrSubst: "SERVFAIL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := evaluateNSGroupHealth(tc.health, tc.servers, now)
			assert.Equal(t, tc.wantVerdict, verdict, "verdict mismatch")
			if tc.wantErrSubst != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrSubst)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// healthStubHandler is a minimal dnsMuxHandlers entry that exposes a fixed
// UpstreamHealth snapshot, letting tests drive recomputeNSGroupStates
// without spinning up real handlers.
type healthStubHandler struct {
	health map[netip.AddrPort]UpstreamHealth
}

func (h *healthStubHandler) ServeDNS(dns.ResponseWriter, *dns.Msg) {}
func (h *healthStubHandler) Stop()                                 {}
func (h *healthStubHandler) ID() types.HandlerID                   { return "health-stub" }
func (h *healthStubHandler) UpstreamHealth() map[netip.AddrPort]UpstreamHealth {
	return h.health
}

// TestProjection_SteadyStateIsSilent guards against duplicate events:
// while a group stays Unhealthy tick after tick, only the first
// Unhealthy transition may emit. Same for staying Healthy.
func TestProjection_SteadyStateIsSilent(t *testing.T) {
	fx := newProjTestFixture(t)

	fx.setHealth(UpstreamHealth{LastFail: time.Now(), LastErr: "timeout"})
	fx.tick()
	fx.expectEvent("unreachable", "first fail emits warning")

	fx.setHealth(UpstreamHealth{LastFail: time.Now(), LastErr: "timeout"})
	fx.tick()
	fx.tick()
	fx.expectNoEvent("staying unhealthy must not re-emit")

	fx.setHealth(UpstreamHealth{LastOk: time.Now()})
	fx.tick()
	fx.expectEvent("recovered", "recovery on transition")

	fx.tick()
	fx.tick()
	fx.expectNoEvent("staying healthy must not re-emit")
}

// projTestFixture is the common setup for the projection tests: a
// single-upstream group whose route classification the test can flip by
// assigning to selected/active. Callers drive failures/successes by
// mutating stub.health and calling refreshHealth.
type projTestFixture struct {
	t        *testing.T
	recorder *peer.Status
	events   <-chan *proto.SystemEvent
	server   *DefaultServer
	stub     *healthStubHandler
	group    *nbdns.NameServerGroup
	srv      netip.AddrPort
	selected route.HAMap
	active   route.HAMap
}

func newProjTestFixture(t *testing.T) *projTestFixture {
	t.Helper()
	recorder := peer.NewRecorder("mgm")
	sub := recorder.SubscribeToEvents()
	t.Cleanup(func() { recorder.UnsubscribeFromEvents(sub) })

	srv := netip.MustParseAddrPort("100.64.0.1:53")
	fx := &projTestFixture{
		t:        t,
		recorder: recorder,
		events:   sub.Events(),
		stub:     &healthStubHandler{health: map[netip.AddrPort]UpstreamHealth{}},
		srv:      srv,
		group: &nbdns.NameServerGroup{
			Domains:     []string{"example.com"},
			NameServers: []nbdns.NameServer{{IP: srv.Addr(), NSType: nbdns.UDPNameServerType, Port: int(srv.Port())}},
		},
	}
	fx.server = &DefaultServer{
		ctx:              context.Background(),
		wgInterface:      &mocWGIface{},
		statusRecorder:   recorder,
		selectedRoutes:   func() route.HAMap { return fx.selected },
		activeRoutes:     func() route.HAMap { return fx.active },
		warningDelayBase: defaultWarningDelayBase,
	}
	fx.server.dnsMuxHandlers = []handlerWrapper{{domain: "example.com", handler: fx.stub, priority: PriorityUpstream}}

	fx.server.mux.Lock()
	fx.server.updateNSGroupStates([]*nbdns.NameServerGroup{fx.group})
	fx.server.mux.Unlock()
	return fx
}

func (f *projTestFixture) setHealth(h UpstreamHealth) {
	f.stub.health = map[netip.AddrPort]UpstreamHealth{f.srv: h}
}

func (f *projTestFixture) tick() []peer.NSGroupState {
	f.server.refreshHealth()
	return f.recorder.GetDNSStates()
}

func (f *projTestFixture) expectNoEvent(why string) {
	f.t.Helper()
	select {
	case evt := <-f.events:
		f.t.Fatalf("unexpected event (%s): %+v", why, evt)
	case <-time.After(100 * time.Millisecond):
	}
}

func (f *projTestFixture) expectEvent(substr, why string) *proto.SystemEvent {
	f.t.Helper()
	select {
	case evt := <-f.events:
		assert.Contains(f.t, evt.Message, substr, why)
		return evt
	case <-time.After(time.Second):
		f.t.Fatalf("expected event (%s) with %q", why, substr)
		return nil
	}
}

var overlayNetForTest = netip.MustParsePrefix("100.64.0.0/16")
var overlayMapForTest = route.HAMap{"overlay": {{Network: overlayNetForTest}}}

// TestProjection_PublicFailEmitsImmediately covers rule 1: an upstream
// that is not inside any selected route (public DNS) fires the warning
// on the first Unhealthy tick, no grace period.
func TestProjection_PublicFailEmitsImmediately(t *testing.T) {
	fx := newProjTestFixture(t)

	fx.setHealth(UpstreamHealth{LastFail: time.Now(), LastErr: "timeout"})
	states := fx.tick()
	require.Len(t, states, 1)
	assert.False(t, states[0].Enabled)
	fx.expectEvent("unreachable", "public DNS failure")
}

// TestProjection_OverlayConnectedFailEmitsImmediately covers rule 2:
// the upstream is inside a selected route AND the route has a Connected
// peer. Tunnel is up, failure is real, emit immediately.
func TestProjection_OverlayConnectedFailEmitsImmediately(t *testing.T) {
	fx := newProjTestFixture(t)
	fx.selected = overlayMapForTest
	fx.active = overlayMapForTest

	fx.setHealth(UpstreamHealth{LastFail: time.Now(), LastErr: "timeout"})
	states := fx.tick()
	require.Len(t, states, 1)
	assert.False(t, states[0].Enabled)
	fx.expectEvent("unreachable", "overlay + connected failure")
}

// TestProjection_OverlayNotConnectedDelaysWarning covers rule 3: the
// upstream is routed but no peer is Connected (Connecting/Idle/missing).
// First tick: Unhealthy display, no warning. After the grace window
// elapses with no recovery, the warning fires.
func TestProjection_OverlayNotConnectedDelaysWarning(t *testing.T) {
	grace := 50 * time.Millisecond
	fx := newProjTestFixture(t)
	fx.server.warningDelayBase = grace
	fx.selected = overlayMapForTest
	// active stays nil: routed but not connected.

	fx.setHealth(UpstreamHealth{LastFail: time.Now(), LastErr: "timeout"})
	states := fx.tick()
	require.Len(t, states, 1)
	assert.False(t, states[0].Enabled, "display must reflect failure even during grace window")
	fx.expectNoEvent("first fail tick within grace window")

	time.Sleep(grace + 10*time.Millisecond)
	fx.setHealth(UpstreamHealth{LastFail: time.Now(), LastErr: "timeout"})
	fx.tick()
	fx.expectEvent("unreachable", "warning after grace window")
}

// TestProjection_OverlayAddrNoRouteDelaysWarning covers an upstream
// whose address is inside the WireGuard overlay range but is not
// covered by any selected route (peer-to-peer DNS without an explicit
// route). Until a peer reports Connected for that address, startup
// failures must be held just like the routed case.
func TestProjection_OverlayAddrNoRouteDelaysWarning(t *testing.T) {
	recorder := peer.NewRecorder("mgm")
	sub := recorder.SubscribeToEvents()
	t.Cleanup(func() { recorder.UnsubscribeFromEvents(sub) })

	overlayPeer := netip.MustParseAddrPort("100.66.100.5:53")
	server := &DefaultServer{
		ctx:              context.Background(),
		wgInterface:      &mocWGIface{},
		statusRecorder:   recorder,
		selectedRoutes:   func() route.HAMap { return nil },
		activeRoutes:     func() route.HAMap { return nil },
		warningDelayBase: 50 * time.Millisecond,
	}
	group := &nbdns.NameServerGroup{
		Domains:     []string{"example.com"},
		NameServers: []nbdns.NameServer{{IP: overlayPeer.Addr(), NSType: nbdns.UDPNameServerType, Port: int(overlayPeer.Port())}},
	}
	stub := &healthStubHandler{health: map[netip.AddrPort]UpstreamHealth{
		overlayPeer: {LastFail: time.Now(), LastErr: "timeout"},
	}}
	server.dnsMuxHandlers = []handlerWrapper{{domain: "example.com", handler: stub, priority: PriorityUpstream}}

	server.mux.Lock()
	server.updateNSGroupStates([]*nbdns.NameServerGroup{group})
	server.mux.Unlock()
	server.refreshHealth()

	select {
	case evt := <-sub.Events():
		t.Fatalf("unexpected event during grace window: %+v", evt)
	case <-time.After(100 * time.Millisecond):
	}

	time.Sleep(60 * time.Millisecond)
	stub.health = map[netip.AddrPort]UpstreamHealth{overlayPeer: {LastFail: time.Now(), LastErr: "timeout"}}
	server.refreshHealth()

	select {
	case evt := <-sub.Events():
		assert.Contains(t, evt.Message, "unreachable")
	case <-time.After(time.Second):
		t.Fatal("expected warning after grace window")
	}
}

// TestProjection_StopClearsHealthState verifies that Stop wipes the
// per-group projection state so a subsequent Start doesn't inherit
// sticky flags (notably everHealthy) that would bypass the grace
// window during the next peer handshake.
func TestProjection_StopClearsHealthState(t *testing.T) {
	wgIface := &mocWGIface{}
	server := &DefaultServer{
		ctx:               context.Background(),
		wgInterface:       wgIface,
		service:           NewServiceViaMemory(wgIface),
		hostManager:       &noopHostConfigurator{},
		extraDomains:      map[domain.Domain]int{},
		statusRecorder:    peer.NewRecorder("mgm"),
		selectedRoutes:    func() route.HAMap { return nil },
		activeRoutes:      func() route.HAMap { return nil },
		warningDelayBase:  defaultWarningDelayBase,
		currentConfigHash: ^uint64(0),
	}
	server.ctx, server.ctxCancel = context.WithCancel(context.Background())

	srv := netip.MustParseAddrPort("8.8.8.8:53")
	group := &nbdns.NameServerGroup{
		Domains:     []string{"example.com"},
		NameServers: []nbdns.NameServer{{IP: srv.Addr(), NSType: nbdns.UDPNameServerType, Port: int(srv.Port())}},
	}
	stub := &healthStubHandler{health: map[netip.AddrPort]UpstreamHealth{srv: {LastOk: time.Now()}}}
	server.dnsMuxHandlers = []handlerWrapper{{domain: "example.com", handler: stub, priority: PriorityUpstream}}

	server.mux.Lock()
	server.updateNSGroupStates([]*nbdns.NameServerGroup{group})
	server.mux.Unlock()
	server.refreshHealth()

	server.healthProjectMu.Lock()
	p, ok := server.nsGroupProj[generateGroupKey(group)]
	server.healthProjectMu.Unlock()
	require.True(t, ok, "projection state should exist after tick")
	require.True(t, p.everHealthy, "tick with success must set everHealthy")

	server.Stop()

	server.healthProjectMu.Lock()
	cleared := server.nsGroupProj == nil
	server.healthProjectMu.Unlock()
	assert.True(t, cleared, "Stop must clear nsGroupProj")
}

// TestProjection_OverlayRecoversDuringGrace covers the happy path of
// rule 3: startup failures while the peer is handshaking, then the peer
// comes up and a query succeeds before the grace window elapses. No
// warning should ever have fired, and no recovery either.
func TestWarningDelayBaseFromEnv(t *testing.T) {
	tests := []struct {
		name string
		set  bool
		val  string
		want time.Duration
	}{
		{name: "unset uses default", set: false, want: defaultWarningDelayBase},
		{name: "valid override", set: true, val: "90s", want: 90 * time.Second},
		{name: "valid minutes", set: true, val: "2m", want: 2 * time.Minute},
		{name: "invalid falls back", set: true, val: "notaduration", want: defaultWarningDelayBase},
		{name: "zero falls back", set: true, val: "0s", want: defaultWarningDelayBase},
		{name: "negative falls back", set: true, val: "-30s", want: defaultWarningDelayBase},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envWarningDelay, tc.val)
			if !tc.set {
				os.Unsetenv(envWarningDelay)
			}
			assert.Equal(t, tc.want, warningDelayBaseFromEnv(), "grace window base")
		})
	}
}

func TestProjection_OverlayRecoversDuringGrace(t *testing.T) {
	fx := newProjTestFixture(t)
	fx.server.warningDelayBase = 200 * time.Millisecond
	fx.selected = overlayMapForTest

	fx.setHealth(UpstreamHealth{LastFail: time.Now(), LastErr: "timeout"})
	fx.tick()
	fx.expectNoEvent("fail within grace, warning suppressed")

	fx.active = overlayMapForTest
	fx.setHealth(UpstreamHealth{LastOk: time.Now()})
	states := fx.tick()
	require.Len(t, states, 1)
	assert.True(t, states[0].Enabled)
	fx.expectNoEvent("recovery without prior warning must not emit")
}

// TestProjection_RecoveryOnlyAfterWarning enforces the invariant the
// whole design leans on: recovery events only appear when a warning
// event was actually emitted for the current streak. A Healthy verdict
// without a prior warning is silent, so the user never sees "recovered"
// out of thin air.
func TestProjection_RecoveryOnlyAfterWarning(t *testing.T) {
	fx := newProjTestFixture(t)

	fx.setHealth(UpstreamHealth{LastOk: time.Now()})
	states := fx.tick()
	require.Len(t, states, 1)
	assert.True(t, states[0].Enabled)
	fx.expectNoEvent("first healthy tick should not recover anything")

	fx.setHealth(UpstreamHealth{LastFail: time.Now(), LastErr: "timeout"})
	fx.tick()
	fx.expectEvent("unreachable", "public fail emits immediately")

	fx.setHealth(UpstreamHealth{LastOk: time.Now()})
	fx.tick()
	fx.expectEvent("recovered", "recovery follows real warning")

	fx.setHealth(UpstreamHealth{LastFail: time.Now(), LastErr: "timeout"})
	fx.tick()
	fx.expectEvent("unreachable", "second cycle warning")

	fx.setHealth(UpstreamHealth{LastOk: time.Now()})
	fx.tick()
	fx.expectEvent("recovered", "second cycle recovery")
}

// TestProjection_EverHealthyOverridesDelay covers rule 4: once a group
// has ever been Healthy, subsequent failures skip the grace window even
// if classification says "routed + not connected". The system has
// proved it can work, so any new failure is real.
func TestProjection_EverHealthyOverridesDelay(t *testing.T) {
	fx := newProjTestFixture(t)
	// Large base so any emission must come from the everHealthy bypass, not elapsed time.
	fx.server.warningDelayBase = time.Hour
	fx.selected = overlayMapForTest
	fx.active = overlayMapForTest

	// Establish "ever healthy".
	fx.setHealth(UpstreamHealth{LastOk: time.Now()})
	fx.tick()
	fx.expectNoEvent("first healthy tick")

	// Peer drops. Query fails. Routed + not connected → normally grace,
	// but everHealthy flag bypasses it.
	fx.active = nil
	fx.setHealth(UpstreamHealth{LastFail: time.Now(), LastErr: "timeout"})
	fx.tick()
	fx.expectEvent("unreachable", "failure after ever-healthy must be immediate")
}

// TestProjection_ReconnectBlipEmitsPair covers the explicit tradeoff
// from the design discussion: once a group has been healthy, a brief
// reconnect that produces a failing tick will fire warning + recovery.
// This is by design: user-visible blips are accurate signal, not noise.
func TestProjection_ReconnectBlipEmitsPair(t *testing.T) {
	fx := newProjTestFixture(t)
	fx.selected = overlayMapForTest
	fx.active = overlayMapForTest

	fx.setHealth(UpstreamHealth{LastOk: time.Now()})
	fx.tick()

	fx.setHealth(UpstreamHealth{LastFail: time.Now(), LastErr: "timeout"})
	fx.tick()
	fx.expectEvent("unreachable", "blip warning")

	fx.setHealth(UpstreamHealth{LastOk: time.Now()})
	fx.tick()
	fx.expectEvent("recovered", "blip recovery")
}

// TestProjection_MixedGroupEmitsImmediately covers the multi-upstream
// rule: a group with at least one public upstream is in the "immediate"
// category regardless of the other upstreams' routing, because the
// public one has no peer-startup excuse. Prevents public-DNS failures
// from being hidden behind a routed sibling.
func TestProjection_MixedGroupEmitsImmediately(t *testing.T) {
	recorder := peer.NewRecorder("mgm")
	sub := recorder.SubscribeToEvents()
	t.Cleanup(func() { recorder.UnsubscribeFromEvents(sub) })
	events := sub.Events()

	public := netip.MustParseAddrPort("8.8.8.8:53")
	overlay := netip.MustParseAddrPort("100.64.0.1:53")
	overlayMap := route.HAMap{"overlay": {{Network: netip.MustParsePrefix("100.64.0.0/16")}}}

	server := &DefaultServer{
		ctx:              context.Background(),
		statusRecorder:   recorder,
		selectedRoutes:   func() route.HAMap { return overlayMap },
		activeRoutes:     func() route.HAMap { return nil },
		warningDelayBase: time.Hour,
	}
	group := &nbdns.NameServerGroup{
		Domains: []string{"example.com"},
		NameServers: []nbdns.NameServer{
			{IP: public.Addr(), NSType: nbdns.UDPNameServerType, Port: int(public.Port())},
			{IP: overlay.Addr(), NSType: nbdns.UDPNameServerType, Port: int(overlay.Port())},
		},
	}
	stub := &healthStubHandler{
		health: map[netip.AddrPort]UpstreamHealth{
			public:  {LastFail: time.Now(), LastErr: "servfail"},
			overlay: {LastFail: time.Now(), LastErr: "timeout"},
		},
	}
	server.dnsMuxHandlers = []handlerWrapper{{domain: "example.com", handler: stub, priority: PriorityUpstream}}

	server.mux.Lock()
	server.updateNSGroupStates([]*nbdns.NameServerGroup{group})
	server.mux.Unlock()
	server.refreshHealth()

	select {
	case evt := <-events:
		assert.Contains(t, evt.Message, "unreachable")
	case <-time.After(time.Second):
		t.Fatal("expected immediate warning because group contains a public upstream")
	}
}

func TestDNSLoopPrevention(t *testing.T) {
	wgInterface := &mocWGIface{}
	service := NewServiceViaMemory(wgInterface)
	dnsServerIP := service.RuntimeIP()

	server := &DefaultServer{
		ctx:           context.Background(),
		wgInterface:   wgInterface,
		service:       service,
		localResolver: local.NewResolver(),
		handlerChain:  NewHandlerChain(),
		hostManager:   &noopHostConfigurator{},
	}

	tests := []struct {
		name              string
		nsGroups          []*nbdns.NameServerGroup
		expectedHandlers  int
		expectedServers   []netip.Addr
		shouldFilterOwnIP bool
	}{
		{
			name: "FilterOwnDNSServerIP",
			nsGroups: []*nbdns.NameServerGroup{
				{
					Primary: true,
					NameServers: []nbdns.NameServer{
						{IP: netip.MustParseAddr("8.8.8.8"), NSType: nbdns.UDPNameServerType, Port: 53},
						{IP: dnsServerIP, NSType: nbdns.UDPNameServerType, Port: 53},
						{IP: netip.MustParseAddr("1.1.1.1"), NSType: nbdns.UDPNameServerType, Port: 53},
					},
					Domains: []string{},
				},
			},
			expectedHandlers:  1,
			expectedServers:   []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")},
			shouldFilterOwnIP: true,
		},
		{
			name: "AllServersFiltered",
			nsGroups: []*nbdns.NameServerGroup{
				{
					Primary: false,
					NameServers: []nbdns.NameServer{
						{IP: dnsServerIP, NSType: nbdns.UDPNameServerType, Port: 53},
					},
					Domains: []string{"example.com"},
				},
			},
			expectedHandlers:  0,
			expectedServers:   []netip.Addr{},
			shouldFilterOwnIP: true,
		},
		{
			name: "MixedServersWithOwnIP",
			nsGroups: []*nbdns.NameServerGroup{
				{
					Primary: false,
					NameServers: []nbdns.NameServer{
						{IP: netip.MustParseAddr("8.8.8.8"), NSType: nbdns.UDPNameServerType, Port: 53},
						{IP: dnsServerIP, NSType: nbdns.UDPNameServerType, Port: 53},
						{IP: netip.MustParseAddr("1.1.1.1"), NSType: nbdns.UDPNameServerType, Port: 53},
						{IP: dnsServerIP, NSType: nbdns.UDPNameServerType, Port: 53}, // duplicate
					},
					Domains: []string{"test.com"},
				},
			},
			expectedHandlers:  1,
			expectedServers:   []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")},
			shouldFilterOwnIP: true,
		},
		{
			name: "NoOwnIPInList",
			nsGroups: []*nbdns.NameServerGroup{
				{
					Primary: true,
					NameServers: []nbdns.NameServer{
						{IP: netip.MustParseAddr("8.8.8.8"), NSType: nbdns.UDPNameServerType, Port: 53},
						{IP: netip.MustParseAddr("1.1.1.1"), NSType: nbdns.UDPNameServerType, Port: 53},
					},
					Domains: []string{},
				},
			},
			expectedHandlers:  1,
			expectedServers:   []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")},
			shouldFilterOwnIP: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			muxUpdates, err := server.buildUpstreamHandlerUpdate(tt.nsGroups)
			assert.NoError(t, err)
			assert.Len(t, muxUpdates, tt.expectedHandlers)

			if tt.expectedHandlers > 0 {
				handler := muxUpdates[0].handler.(*upstreamResolver)
				flat := handler.flatUpstreams()
				assert.Len(t, flat, len(tt.expectedServers))

				if tt.shouldFilterOwnIP {
					for _, upstream := range flat {
						assert.NotEqual(t, dnsServerIP, upstream.Addr())
					}
				}

				for _, expected := range tt.expectedServers {
					found := false
					for _, upstream := range flat {
						if upstream.Addr() == expected {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected server %s not found", expected)
				}
			}
		})
	}
}
