package dnsinterceptor

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/common"
	"github.com/netbirdio/netbird/client/internal/routemanager/fakeip"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/wireguard-go/tun/netstack"
)

const testRoutingPeer = "routing-peer-key"

var (
	testOverlayNet  = netip.MustParsePrefix("100.64.0.0/16")
	testPeerAddr    = netip.MustParsePrefix("100.64.0.10/32")
	testRemoteAddr  = netip.MustParsePrefix("203.0.113.5/32")
	testRemoteAddr2 = netip.MustParsePrefix("203.0.113.6/32")
)

type mockWGIface struct{}

func (mockWGIface) AddAllowedIP(string, netip.Prefix) error    { return nil }
func (mockWGIface) RemoveAllowedIP(string, netip.Prefix) error { return nil }
func (mockWGIface) Name() string                               { return "wt0" }
func (mockWGIface) Address() wgaddr.Address {
	return wgaddr.Address{IP: netip.MustParseAddr("100.64.0.1"), Network: testOverlayNet}
}
func (mockWGIface) ToInterface() *net.Interface             { return nil }
func (mockWGIface) IsUserspaceBind() bool                   { return false }
func (mockWGIface) GetFilter() device.PacketFilter          { return nil }
func (mockWGIface) GetDevice() *device.FilteredDevice       { return nil }
func (mockWGIface) GetNet() *netstack.Net                   { return nil }
func (mockWGIface) GetInterfaceGUIDString() (string, error) { return "", nil }

// allowedIPsRecorder records the AllowedIPs the interceptor hands to the device per peer.
type allowedIPsRecorder struct {
	mu      sync.Mutex
	adds    map[string][]netip.Prefix
	removes map[string][]netip.Prefix
}

func (r *allowedIPsRecorder) counter() *refcounter.AllowedIPsRefCounter {
	return refcounter.NewAllowedIPs(
		func(prefix netip.Prefix, peerKey string) (string, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.adds == nil {
				r.adds = map[string][]netip.Prefix{}
			}
			r.adds[peerKey] = append(r.adds[peerKey], prefix)
			return peerKey, nil
		},
		func(prefix netip.Prefix, peerKey string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.removes == nil {
				r.removes = map[string][]netip.Prefix{}
			}
			r.removes[peerKey] = append(r.removes[peerKey], prefix)
			return nil
		},
	)
}

func (r *allowedIPsRecorder) removed(peerKey string) []netip.Prefix {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.removes[peerKey]
}

func (r *allowedIPsRecorder) added(peerKey string) []netip.Prefix {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.adds[peerKey]
}

type mockResponseWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (w *mockResponseWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }

func newTestInterceptor(t *testing.T, routeCounter *refcounter.RouteRefCounter, allowedIPs *allowedIPsRecorder) *DnsInterceptor {
	t.Helper()

	return New(common.HandlerParams{
		Route: &route.Route{
			ID:          "route-corp",
			NetID:       "corp",
			Peer:        testRoutingPeer,
			Domains:     domain.List{"*.corp.example"},
			NetworkType: route.DomainNetwork,
		},
		RouteRefCounter:      routeCounter,
		AllowedIPsRefCounter: allowedIPs.counter(),
		StatusRecorder:       peer.NewRecorder(""),
		WgInterface:          mockWGIface{},
	})
}

// TestUpdateDomainPrefixes_RefusedPrefixNotReplayed verifies that a prefix the route
// validation refused is not remembered for the domain: AddAllowedIPs replays the
// remembered prefixes onto the routing peer without any further check.
func TestUpdateDomainPrefixes_RefusedPrefixNotReplayed(t *testing.T) {
	for _, keepRoute := range []bool{false, true} {
		t.Run("keepRoute="+map[bool]string{false: "false", true: "true"}[keepRoute], func(t *testing.T) {
			routeCounter := refcounter.New(
				func(prefix netip.Prefix, _ struct{}) (struct{}, error) {
					if testOverlayNet.Contains(prefix.Addr()) {
						return struct{}{}, vars.ErrRouteNotAllowed
					}
					return struct{}{}, nil
				},
				func(netip.Prefix, struct{}) error { return nil },
			)
			allowedIPs := &allowedIPsRecorder{}
			d := newTestInterceptor(t, routeCounter, allowedIPs)
			d.route.KeepRoute = keepRoute
			require.NoError(t, d.AddAllowedIPs(testRoutingPeer))

			resolved := domain.Domain("app.corp.example.")
			logger := log.NewEntry(log.StandardLogger())

			err := d.updateDomainPrefixes(resolved, resolved, []netip.Prefix{testPeerAddr, testRemoteAddr}, logger)
			require.ErrorContains(t, err, vars.ErrRouteNotAllowed.Error())
			assert.Equal(t, []netip.Prefix{testRemoteAddr}, d.interceptedDomains[resolved],
				"only the accepted prefix must be remembered")

			// a later answer that drops the accepted address and keeps the refused one
			err = d.updateDomainPrefixes(resolved, resolved, []netip.Prefix{testPeerAddr, testRemoteAddr2}, logger)
			require.ErrorContains(t, err, vars.ErrRouteNotAllowed.Error())
			if keepRoute {
				assert.ElementsMatch(t, []netip.Prefix{testRemoteAddr, testRemoteAddr2}, d.interceptedDomains[resolved])
			} else {
				assert.Equal(t, []netip.Prefix{testRemoteAddr2}, d.interceptedDomains[resolved])
			}

			// the routing peer reconnects: the watcher re-adds the remembered prefixes
			require.NoError(t, d.RemoveAllowedIPs())
			require.NoError(t, d.AddAllowedIPs(testRoutingPeer))
			assert.NotContains(t, allowedIPs.added(testRoutingPeer), testPeerAddr,
				"a refused prefix must never reach the device as AllowedIP of the routing peer")
		})
	}
}

// TestWriteMsg_IgnoresOverlayAddresses verifies that an answer naming an address
// inside the overlay network is dropped before it becomes a prefix, which is the
// only check in netstack mode, where the route counter accepts everything.
func TestWriteMsg_IgnoresOverlayAddresses(t *testing.T) {
	routeCounter := refcounter.New(
		func(netip.Prefix, struct{}) (struct{}, error) { return struct{}{}, refcounter.ErrIgnore },
		func(netip.Prefix, struct{}) error { return nil },
	)
	allowedIPs := &allowedIPsRecorder{}
	d := newTestInterceptor(t, routeCounter, allowedIPs)
	require.NoError(t, d.AddAllowedIPs(testRoutingPeer))

	reply := new(dns.Msg)
	reply.SetQuestion("app.corp.example.", dns.TypeA)
	for _, addr := range []netip.Prefix{testPeerAddr, testRemoteAddr} {
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "app.corp.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   addr.Addr().AsSlice(),
		})
	}
	reply.Answer = append(reply.Answer, &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "app.corp.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: net.IPv6loopback,
	})
	// a mapped overlay address is only caught because the answer is unmapped first
	reply.Answer = append(reply.Answer, &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "app.corp.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: net.ParseIP("::ffff:100.64.0.10"),
	})

	w := &mockResponseWriter{}
	require.NoError(t, d.writeMsg(w, reply, log.NewEntry(log.StandardLogger())))
	require.NotNil(t, w.msg)

	assert.Equal(t, []netip.Prefix{testRemoteAddr}, allowedIPs.added(testRoutingPeer),
		"only the public address may become an AllowedIP of the routing peer")
	assert.Equal(t, []netip.Prefix{testRemoteAddr}, d.interceptedDomains["app.corp.example."])
}

// An IPv4-mapped AAAA answer names an IPv4 address. It has to be tracked as the plain /32:
// a prefix built from the mapped form would be ::ffff:203.0.113.5/128, not the IPv4 /32 the peer routes.
func TestWriteMsg_MappedAAAAAnswerIsTrackedAsIPv4(t *testing.T) {
	routeCounter := refcounter.New(
		func(netip.Prefix, struct{}) (struct{}, error) { return struct{}{}, nil },
		func(netip.Prefix, struct{}) error { return nil },
	)
	allowedIPs := &allowedIPsRecorder{}
	d := newTestInterceptor(t, routeCounter, allowedIPs)
	require.NoError(t, d.AddAllowedIPs(testRoutingPeer))

	reply := new(dns.Msg)
	reply.SetQuestion("app.corp.example.", dns.TypeAAAA)
	reply.Answer = append(reply.Answer, &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "app.corp.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: net.ParseIP("::ffff:203.0.113.5"),
	})

	w := &mockResponseWriter{}
	require.NoError(t, d.writeMsg(w, reply, log.NewEntry(log.StandardLogger())))

	stored := d.interceptedDomains["app.corp.example."]
	require.Equal(t, []netip.Prefix{testRemoteAddr}, stored, "the mapped answer must be tracked as the plain IPv4 /32")
	for _, prefix := range stored {
		assert.True(t, prefix.IsValid(), "every remembered prefix must be valid, got %s", prefix)
	}
	// A replay for a new routing peer must not fail on what was remembered.
	assert.NoError(t, d.AddAllowedIPs("another-routing-peer"))
}

// An answer whose addresses are all rejected withdraws what an earlier answer installed.
func TestWriteMsg_RejectedOnlyAnswerWithdrawsEarlierRoutes(t *testing.T) {
	var routesRemoved []netip.Prefix
	routeCounter := refcounter.New(
		func(netip.Prefix, struct{}) (struct{}, error) { return struct{}{}, nil },
		func(prefix netip.Prefix, _ struct{}) error {
			routesRemoved = append(routesRemoved, prefix)
			return nil
		},
	)
	allowedIPs := &allowedIPsRecorder{}
	d := newTestInterceptor(t, routeCounter, allowedIPs)
	require.NoError(t, d.AddAllowedIPs(testRoutingPeer))
	logger := log.NewEntry(log.StandardLogger())

	query := func(addr netip.Addr) {
		reply := new(dns.Msg)
		reply.SetQuestion("app.corp.example.", dns.TypeA)
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "app.corp.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   addr.AsSlice(),
		})
		require.NoError(t, d.writeMsg(&mockResponseWriter{}, reply, logger))
	}

	query(testRemoteAddr.Addr())
	require.Equal(t, []netip.Prefix{testRemoteAddr}, d.interceptedDomains["app.corp.example."])

	query(testPeerAddr.Addr())
	assert.Empty(t, d.interceptedDomains["app.corp.example."], "the earlier route must be withdrawn")
	assert.Equal(t, []netip.Prefix{testRemoteAddr}, routesRemoved, "the route must be removed")
	assert.Equal(t, []netip.Prefix{testRemoteAddr}, allowedIPs.removed(testRoutingPeer),
		"the AllowedIP must be removed from the routing peer")
}

// TestRewriteToFakeIPs_OnlyAcceptedPrefixes verifies that an answer address whose route
// was refused keeps its real IP. Its fake IP was already allocated before the route was
// tried, but has no route and no DNAT mapping behind it, so handing it to the client
// would leave the client with an unreachable address.
func TestRewriteToFakeIPs_OnlyAcceptedPrefixes(t *testing.T) {
	routeCounter := refcounter.New(
		func(prefix netip.Prefix, _ struct{}) (struct{}, error) {
			if prefix == testRemoteAddr2 {
				return struct{}{}, errors.New("route refused")
			}
			return struct{}{}, nil
		},
		func(netip.Prefix, struct{}) error { return nil },
	)
	d := newTestInterceptor(t, routeCounter, &allowedIPsRecorder{})
	d.fakeIPManager = fakeip.NewManager()
	require.NoError(t, d.AddAllowedIPs(testRoutingPeer))

	resolved := domain.Domain("app.corp.example.")
	logger := log.NewEntry(log.StandardLogger())

	acceptedFake, err := d.fakeIPManager.AllocateFakeIP(testRemoteAddr.Addr())
	require.NoError(t, err)
	_, err = d.fakeIPManager.AllocateFakeIP(testRemoteAddr2.Addr())
	require.NoError(t, err)

	require.Error(t, d.updateDomainPrefixes(resolved, resolved, []netip.Prefix{testRemoteAddr, testRemoteAddr2}, logger))
	require.Equal(t, []netip.Prefix{testRemoteAddr}, d.interceptedDomains[resolved])

	reply := &dns.Msg{Answer: []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: string(resolved), Rrtype: dns.TypeA, Class: dns.ClassINET}, A: testRemoteAddr.Addr().AsSlice()},
		&dns.A{Hdr: dns.RR_Header{Name: string(resolved), Rrtype: dns.TypeA, Class: dns.ClassINET}, A: testRemoteAddr2.Addr().AsSlice()},
	}}
	d.rewriteToFakeIPs(reply, d.interceptedDomains[resolved], logger)

	assert.Equal(t, net.IP(acceptedFake.AsSlice()), reply.Answer[0].(*dns.A).A, "accepted address must be swapped for its fake IP")
	assert.Equal(t, net.IP(testRemoteAddr2.Addr().AsSlice()), reply.Answer[1].(*dns.A).A, "refused address must keep its real IP")
}
