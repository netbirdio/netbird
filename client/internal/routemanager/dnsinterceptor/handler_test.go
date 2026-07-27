package dnsinterceptor

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/dns/resutil"
	"github.com/netbirdio/netbird/client/internal/dns/test"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/route"
)

// softNegativeWriter records what the handler told the chain: whether to soften
// a negative verdict from the handlers it defers to, and the metadata that ends
// up on the chain's response log line.
type softNegativeWriter struct {
	test.MockResponseWriter
	softNegative bool
	meta         map[resutil.MetaKey]string
}

func (w *softNegativeWriter) RequestSoftNegative() { w.softNegative = true }

func (w *softNegativeWriter) RequestID() string { return "test" }

func (w *softNegativeWriter) SetMeta(key resutil.MetaKey, value string) {
	if w.meta == nil {
		w.meta = make(map[resutil.MetaKey]string)
	}
	w.meta[key] = value
}

// TestServeDNS_QtypeTheForwarderCannotResolve covers the record types no DNS
// forwarder can answer, because the host resolver exposes no API for them.
// Asking the peer only burns a tunnel round trip, so the query goes straight to
// the rest of the chain. No peer key is configured, proving no round trip is
// attempted.
func TestServeDNS_QtypeTheForwarderCannotResolve(t *testing.T) {
	qtypes := []uint16{
		dns.TypeHTTPS,
		dns.TypeSVCB,
		dns.TypeCAA,
		dns.TypeNAPTR,
		dns.TypeTLSA,
		dns.TypeSOA,
	}

	for _, qtype := range qtypes {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			d := &DnsInterceptor{}
			w := &softNegativeWriter{}

			r := new(dns.Msg)
			r.SetQuestion("db.example.com.", qtype)

			d.ServeDNS(w, r)

			resp := w.GetLastResponse()
			require.NotNil(t, resp, "a response must be written")
			assert.Equal(t, dns.RcodeNameError, resp.Rcode, "chain continuation is signalled as NXDOMAIN")
			assert.True(t, resp.MsgHdr.Zero, "Zero bit must be set so the chain continues")
			assert.True(t, w.softNegative,
				"a downstream NXDOMAIN must be softened, or the fallthrough poisons the routed name")
			assert.Equal(t, "dns-route", w.meta[resutil.MetaKeyDeferredBy],
				"the chain's response log line must name us as the handler that stepped aside")
			assert.Equal(t, "unsupported-qtype", w.meta[resutil.MetaKeyDeferredReason],
				"the reason must survive to the log line, or the fallthrough is invisible")
		})
	}
}

// TestServeDNS_AddressQtypeNeverFallsThrough locks in the opposite case: A and
// AAAA are what the route exists for, and the peer is authoritative for them.
// A missing peer is an error the client must see, never a fallthrough to a
// resolver that knows nothing about the routed name.
func TestServeDNS_AddressQtypeNeverFallsThrough(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			d := &DnsInterceptor{}
			w := &softNegativeWriter{}

			r := new(dns.Msg)
			r.SetQuestion("db.example.com.", qtype)

			d.ServeDNS(w, r)

			resp := w.GetLastResponse()
			require.NotNil(t, resp, "a response must be written")
			assert.Equal(t, dns.RcodeServerFailure, resp.Rcode, "an unusable route must fail, not fall through")
			assert.False(t, resp.MsgHdr.Zero, "the chain must not continue for address queries")
			assert.False(t, w.softNegative, "no fallthrough means nothing to soften")
		})
	}
}

// TestDispositionFor pins the query-type policy, and ties the types we ask a
// peer about to the types a forwarder can actually resolve, so the two ends
// cannot drift apart.
func TestDispositionFor(t *testing.T) {
	tests := []struct {
		qtype uint16
		want  disposition
	}{
		{dns.TypeA, dispositionPeer},
		{dns.TypeAAAA, dispositionPeer},
		{dns.TypeMX, dispositionPeerFirst},
		{dns.TypeTXT, dispositionPeerFirst},
		{dns.TypeNS, dispositionPeerFirst},
		{dns.TypeSRV, dispositionPeerFirst},
		{dns.TypeCNAME, dispositionPeerFirst},
		{dns.TypePTR, dispositionPeerFirst},
		{dns.TypeHTTPS, dispositionChain},
		{dns.TypeSVCB, dispositionChain},
		{dns.TypeCAA, dispositionChain},
		{dns.TypeNAPTR, dispositionChain},
		{dns.TypeTLSA, dispositionChain},
		{dns.TypeDS, dispositionChain},
		{dns.TypeDNSKEY, dispositionChain},
		{dns.TypeSOA, dispositionChain},
		{dns.TypeANY, dispositionChain},
	}

	for _, tt := range tests {
		t.Run(dns.TypeToString[tt.qtype], func(t *testing.T) {
			assert.Equal(t, tt.want, dispositionFor(tt.qtype), "disposition for %s", dns.TypeToString[tt.qtype])

			if tt.want != dispositionPeer {
				assert.Equal(t, tt.want == dispositionPeerFirst, resutil.SupportedRecordQtype(tt.qtype),
					"only types a forwarder resolves may be sent to a peer")
			}
		})
	}
}

// TestPeerCannotAnswer separates a peer that cannot resolve a type from one that
// resolved it and found nothing. Only the former may be retried elsewhere:
// treating NODATA or NXDOMAIN as a capability failure would send the client to a
// public resolver behind the peer's back and prefer a public record over the
// private one the route exists to reach.
func TestPeerCannotAnswer(t *testing.T) {
	cannot := []int{dns.RcodeNotImplemented, dns.RcodeFormatError}
	for _, rcode := range cannot {
		assert.True(t, peerCannotAnswer(rcode), "%s means the peer cannot answer", dns.RcodeToString[rcode])
	}

	// REFUSED belongs here, not above: it says the peer does not hold the name,
	// so retrying elsewhere would leak the name of an internal-only domain to a
	// public resolver. No forwarder version reports a missing record type this
	// way, so nothing is lost by keeping it out.
	can := []int{
		dns.RcodeSuccess,
		dns.RcodeNameError,
		dns.RcodeServerFailure,
		dns.RcodeNotAuth,
		dns.RcodeRefused,
	}
	for _, rcode := range can {
		assert.False(t, peerCannotAnswer(rcode), "%s is the peer's answer, not a capability failure", dns.RcodeToString[rcode])
	}
}

// fakeWGIface is the minimum an interceptor needs to reach a peer's DNS
// forwarder over a plain socket. A nil netstack keeps the exchange on the host
// stack so the test can point it at a loopback listener.
type fakeWGIface struct{}

func (fakeWGIface) AddAllowedIP(string, netip.Prefix) error    { return nil }
func (fakeWGIface) RemoveAllowedIP(string, netip.Prefix) error { return nil }
func (fakeWGIface) Name() string                               { return "wt0" }
func (fakeWGIface) Address() wgaddr.Address                    { return wgaddr.Address{} }
func (fakeWGIface) ToInterface() *net.Interface                { return nil }
func (fakeWGIface) IsUserspaceBind() bool                      { return false }
func (fakeWGIface) GetFilter() device.PacketFilter             { return nil }
func (fakeWGIface) GetDevice() *device.FilteredDevice          { return nil }
func (fakeWGIface) GetNet() *netstack.Net                      { return nil }

// fakePeerIPs resolves every peer key to the loopback address the test's
// forwarder stub listens on.
type fakePeerIPs struct {
	addr netip.Addr
}

func (p fakePeerIPs) AllowedIP(string) (netip.Addr, bool) { return p.addr, p.addr.IsValid() }

// forwarderStub stands in for the DNS forwarder of a routing peer, recording
// what it was asked and answering with a canned reply.
type forwarderStub struct {
	mu       sync.Mutex
	queries  []*dns.Msg
	reply    func(q *dns.Msg) *dns.Msg
	port     uint16
	shutdown func()
}

func (s *forwarderStub) received() []*dns.Msg {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*dns.Msg(nil), s.queries...)
}

func newForwarderStub(t *testing.T, reply func(q *dns.Msg) *dns.Msg) *forwarderStub {
	t.Helper()

	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	require.NoError(t, err, "listen for the forwarder stub")

	stub := &forwarderStub{reply: reply}
	stub.port = uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, q *dns.Msg) {
		stub.mu.Lock()
		stub.queries = append(stub.queries, q.Copy())
		stub.mu.Unlock()
		_ = w.WriteMsg(stub.reply(q))
	})

	srv := &dns.Server{PacketConn: conn, Handler: mux}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() {
		_ = srv.ActivateAndServe()
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("forwarder stub did not start")
	}

	stub.shutdown = func() { _ = srv.Shutdown() }
	t.Cleanup(stub.shutdown)

	return stub
}

func newTestInterceptor(t *testing.T, stub *forwarderStub) *DnsInterceptor {
	t.Helper()

	port := new(atomic.Uint32)
	port.Store(uint32(stub.port))

	return &DnsInterceptor{
		route:              &route.Route{Domains: nil},
		statusRecorder:     peer.NewRecorder("https://mgm"),
		currentPeerKey:     "peer-key",
		interceptedDomains: make(domainMap),
		wgInterface:        fakeWGIface{},
		peerStore:          fakePeerIPs{addr: netip.MustParseAddr("127.0.0.1")},
		forwarderPort:      port,
	}
}

// TestServeDNS_PeerCannotResolveQtype is the reported regression: a routing peer
// running a client older than the one that taught the forwarder about non-address
// record types answers NOTIMP for every SRV query, and the interceptor used to
// hand that straight to the application, breaking SRV-based service discovery.
// The client cannot know the peer's capability up front, so it must try the peer
// and fall back to the chain when the peer says it cannot answer.
func TestServeDNS_PeerCannotResolveQtype(t *testing.T) {
	for _, rcode := range []int{dns.RcodeNotImplemented, dns.RcodeFormatError} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			stub := newForwarderStub(t, func(q *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetRcode(q, rcode)
				return resp
			})
			d := newTestInterceptor(t, stub)
			w := &softNegativeWriter{}

			r := new(dns.Msg)
			r.SetQuestion("_mongodb._tcp.db.example.com.", dns.TypeSRV)

			d.ServeDNS(w, r)

			require.Len(t, stub.received(), 1, "the peer must be asked before giving up on it")

			resp := w.GetLastResponse()
			require.NotNil(t, resp, "a response must be written")
			assert.Equal(t, dns.RcodeNameError, resp.Rcode, "chain continuation is signalled as NXDOMAIN")
			assert.True(t, resp.MsgHdr.Zero, "Zero bit must be set so the chain continues")
			assert.True(t, w.softNegative, "the fallthrough must not be allowed to poison the routed name")
			assert.Equal(t, "dns-route", w.meta[resutil.MetaKeyDeferredBy])
			assert.Equal(t, "peer-rcode-"+dns.RcodeToString[rcode], w.meta[resutil.MetaKeyDeferredReason],
				"the peer's verdict must be visible in the log, it is the only trace of the probe")
		})
	}
}

// TestServeDNS_PeerVerdictPassesThrough covers the replies that are the peer's
// answer rather than a statement about its capability. The peer is authoritative
// for a name routed to it, so its verdict reaches the client as it is: retrying
// these elsewhere would send the name of an internal-only domain to a public
// resolver and prefer whatever that resolver says over the route.
func TestServeDNS_PeerVerdictPassesThrough(t *testing.T) {
	// REFUSED means the peer does not consider the name routed to it, which
	// happens while the client and the peer disagree about the route set. It is
	// never how a peer reports a record type it cannot resolve: a forwarder too
	// old for non-address types answers NOTIMP before it looks at the domain.
	for _, rcode := range []int{dns.RcodeRefused, dns.RcodeNameError, dns.RcodeSuccess} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			stub := newForwarderStub(t, func(q *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetRcode(q, rcode)
				return resp
			})
			d := newTestInterceptor(t, stub)
			w := &softNegativeWriter{}

			r := new(dns.Msg)
			r.SetQuestion("_mongodb._tcp.db.example.com.", dns.TypeSRV)

			d.ServeDNS(w, r)

			require.Len(t, stub.received(), 1, "the peer must be asked exactly once")

			resp := w.GetLastResponse()
			require.NotNil(t, resp, "a response must be written")
			assert.Equal(t, rcode, resp.Rcode, "the peer's verdict must reach the client unchanged")
			assert.False(t, resp.MsgHdr.Zero, "the chain must not continue past an answered query")
			assert.False(t, w.softNegative, "nothing was deferred, so nothing may be softened")
		})
	}
}

// TestServeDNS_PeerResolvesQtype guards the common case: a peer that can answer
// the type stays authoritative, and its records reach the client unchanged.
func TestServeDNS_PeerResolvesQtype(t *testing.T) {
	stub := newForwarderStub(t, func(q *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Answer = []dns.RR{&dns.SRV{
			Hdr:    dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 60},
			Target: "shard-00.db.example.com.",
			Port:   27017,
		}}
		return resp
	})
	d := newTestInterceptor(t, stub)
	w := &softNegativeWriter{}

	r := new(dns.Msg)
	r.SetQuestion("_mongodb._tcp.db.example.com.", dns.TypeSRV)

	d.ServeDNS(w, r)

	resp := w.GetLastResponse()
	require.NotNil(t, resp, "a response must be written")
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1, "the peer's records must pass through")
	assert.False(t, resp.MsgHdr.Zero, "an answered query must not continue the chain")
	assert.False(t, w.softNegative)
}

// TestServeDNS_DeferredQueryIsPristine covers what the fallthrough hands to the
// next handler. The interceptor advertises EDNS0 to the peer so the forwarder can
// return an Extended DNS Error, and sets AD, but neither belongs to the client's
// query: on the deferred path they would travel to the public resolver and the
// reply could come back carrying an OPT the client never advertised, which
// RFC 6891 forbids us from passing on.
func TestServeDNS_DeferredQueryIsPristine(t *testing.T) {
	stub := newForwarderStub(t, func(q *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetRcode(q, dns.RcodeNotImplemented)
		return resp
	})
	d := newTestInterceptor(t, stub)
	w := &softNegativeWriter{}

	r := new(dns.Msg)
	r.SetQuestion("_mongodb._tcp.db.example.com.", dns.TypeSRV)

	d.ServeDNS(w, r)

	sent := stub.received()
	require.Len(t, sent, 1)
	assert.NotNil(t, sent[0].IsEdns0(), "the peer must be asked with EDNS0 so it can return an EDE")

	assert.Nil(t, r.IsEdns0(), "the deferred query must not carry an OPT the client never sent")
	assert.False(t, r.AuthenticatedData, "the deferred query must not carry an AD bit the client never set")
	assert.Empty(t, r.Extra, "the deferred query must reach the next handler as the client sent it")
}
