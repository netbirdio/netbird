package routemanager

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/tun/netstack"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/client/internal/routemanager/client"
	"github.com/netbirdio/netbird/client/internal/routemanager/dnsinterceptor"
	"github.com/netbirdio/netbird/client/internal/routemanager/iface"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

type dnsCleanupInterface struct{ iface.WGIface }

func (*dnsCleanupInterface) GetNet() *netstack.Net { return nil }

func TestFailedDNSRemovalDoesNotDeregisterReplacement(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	started := make(chan struct{})
	server := &dns.Server{
		PacketConn:        upstream,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			reply := new(dns.Msg)
			reply.SetReply(r)
			reply.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET},
				A:   net.IPv4(203, 0, 113, 7),
			}}
			assert.NoError(t, w.WriteMsg(reply), "the loopback DNS reply must be written")
		}),
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() {
		require.NoError(t, server.Shutdown())
		require.NoError(t, <-serveErr)
	})

	chain := nbdns.NewHandlerChain()
	dnsServer := &nbdns.MockServer{
		RegisterHandlerFunc: func(domains domain.List, handler dns.Handler, priority int) {
			for _, name := range domains.ToPunycodeList() {
				chain.AddHandler(name, handler, priority)
			}
		},
		DeregisterHandlerFunc: func(domains domain.List, priority int) {
			for _, name := range domains.ToPunycodeList() {
				chain.RemoveHandler(name, priority)
			}
		},
	}
	store := peerstore.NewConnStore()
	conn, err := peer.NewConn(peer.ConnConfig{WgConfig: peer.WgConfig{
		AllowedIps: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	}}, peer.ServiceDependencies{})
	require.NoError(t, err)
	require.True(t, store.AddPeerConn("peer", conn), "the loopback upstream peer must be registered")
	var failRemoval atomic.Bool
	m := &DefaultManager{
		ctx: context.Background(), activeRoutes: map[route.HAUniqueID]client.RouteHandler{},
		dnsServer: dnsServer, useNewDNSRoute: true, statusRecorder: peer.NewRecorder("https://mgm"),
		wgInterface: &dnsCleanupInterface{}, peerStore: store,
		routeRefCounter: refcounter.New(
			func(netip.Prefix, struct{}) (struct{}, error) { return struct{}{}, nil },
			func(netip.Prefix, struct{}) error {
				if failRemoval.Swap(false) {
					return errors.New("remove route")
				}
				return nil
			}),
		allowedIPsRefCounter: refcounter.NewAllowedIPs(
			func(_ netip.Prefix, peerKey string) (string, error) { return peerKey, nil },
			func(netip.Prefix, string) error { return nil }),
	}
	m.dnsForwarderPort.Store(uint32(upstream.LocalAddr().(*net.UDPAddr).Port))
	dnsDomain := domain.Domain("dns.example.com")
	oldRoute := &route.Route{ID: "old:1", NetID: "old", NetworkType: route.DomainNetwork, Domains: domain.List{dnsDomain}}
	newRoute := oldRoute.Copy()
	newRoute.ID, newRoute.NetID = "new:1", "new"
	oldID, newID := oldRoute.GetHAUniqueID(), newRoute.GetHAUniqueID()
	resolve := func() {
		request := new(dns.Msg)
		request.SetQuestion(string(dnsDomain)+".", dns.TypeA)
		reply, err := chain.ResolveInternal(context.Background(), request, nbdns.PriorityDNSRoute)
		require.NoError(t, err, "the replacement DNS handler must remain registered")
		require.Len(t, reply.Answer, 1, "the production handler must resolve through the loopback upstream")
	}
	require.NoError(t, m.updateSystemRoutes(route.HAMap{oldID: {oldRoute}}))
	require.NoError(t, m.activeRoutes[oldID].AddAllowedIPs("peer"))
	resolve()
	failRemoval.Store(true)
	require.Error(t, m.updateSystemRoutes(route.HAMap{newID: {newRoute}}), "the first cleanup error must be returned")
	replacement := m.activeRoutes[newID]
	require.IsType(t, &dnsinterceptor.DnsInterceptor{}, replacement)
	require.NoError(t, replacement.AddAllowedIPs("peer"))
	resolve()
	before := m.statusRecorder.GetResolvedDomainsStates()
	require.NotEmpty(t, before, "the replacement must have recorded its resolved prefix")

	require.NoError(t, m.updateSystemRoutes(route.HAMap{newID: {newRoute}}))
	assert.Equal(t, before, m.statusRecorder.GetResolvedDomainsStates(), "old cleanup must not clear replacement DNS state")
	assert.Same(t, replacement, m.activeRoutes[newID], "the replacement handler must remain active")
	resolve()
	require.NoError(t, m.updateSystemRoutes(route.HAMap{}))
}
