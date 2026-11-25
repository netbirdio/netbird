package stdnet

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDNS answers from a fixed zone, NXDOMAIN for any other name, NODATA for a
// known name without records of the asked type, and records every query. With
// dropAAAA it never answers AAAA queries, like a resolver or middlebox that
// silently drops them.
type fakeDNS struct {
	addr     string
	zone     map[string][]netip.Addr
	dropAAAA bool

	mu      sync.Mutex
	queries []string
}

func startFakeDNS(t *testing.T, zone map[string][]netip.Addr, dropAAAA bool) *fakeDNS {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	f := &fakeDNS{addr: pc.LocalAddr().String(), zone: zone, dropAAAA: dropAAAA}
	started := make(chan struct{})
	served := make(chan error, 1)
	srv := &dns.Server{PacketConn: pc, Handler: f, NotifyStartedFunc: func() { close(started) }}
	go func() {
		served <- srv.ActivateAndServe()
	}()
	t.Cleanup(func() { _ = srv.Shutdown() })
	select {
	case <-started:
	case err := <-served:
		t.Fatalf("fake DNS did not start: %v", err)
	}
	return f
}

func (f *fakeDNS) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	// Without RA, the Go resolver reads an empty answer as a lame referral.
	resp.RecursionAvailable = true
	q := req.Question[0]

	f.mu.Lock()
	f.queries = append(f.queries, dns.TypeToString[q.Qtype]+" "+q.Name)
	f.mu.Unlock()

	if f.dropAAAA && q.Qtype == dns.TypeAAAA {
		return
	}

	addrs, ok := f.zone[strings.ToLower(q.Name)]
	if !ok {
		resp.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(resp)
		return
	}
	for _, addr := range addrs {
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 60}
		switch {
		case q.Qtype == dns.TypeA && addr.Is4():
			hdr.Rrtype = dns.TypeA
			resp.Answer = append(resp.Answer, &dns.A{Hdr: hdr, A: addr.AsSlice()})
		case q.Qtype == dns.TypeAAAA && addr.Is6():
			hdr.Rrtype = dns.TypeAAAA
			resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: hdr, AAAA: addr.AsSlice()})
		}
	}
	_ = w.WriteMsg(resp)
}

func (f *fakeDNS) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

// resolver sends every query of the Go resolver to the fake, whatever
// nameserver resolv.conf lists. The search list still comes from resolv.conf.
func (f *fakeDNS) resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", f.addr)
		},
	}
}

// hostSearchList returns the search domains and ndots from /etc/resolv.conf.
// The Go resolver has no API to inject a search list, so these tests run
// against the host's own.
func hostSearchList(t *testing.T) ([]string, int) {
	t.Helper()

	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		t.Skipf("no /etc/resolv.conf: %v", err)
	}
	defer file.Close()

	var search []string
	ndots := 1
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "search", "domain":
			// Like the Go resolver, ignore the root: systemd-resolved writes
			// "search ." when DHCP hands out no domain.
			search = nil
			for _, s := range fields[1:] {
				if s != "." {
					search = append(search, s)
				}
			}
		case "options":
			for _, opt := range fields[1:] {
				if v, ok := strings.CutPrefix(opt, "ndots:"); ok {
					if n, err := strconv.Atoi(v); err == nil {
						ndots = n
					}
				}
			}
		}
	}
	if len(search) == 0 {
		t.Skip("resolv.conf has no search domain, so the search-list walk cannot be exercised")
	}
	return search, ndots
}

// A STUN/TURN host that has only an A record, like stun.netbird.io. Asking for
// it on the IPv6 lane must not send the name with a search domain appended to
// whoever serves that domain.
func TestResolveAddr_HostWithoutIPv6DoesNotWalkSearchList(t *testing.T) {
	_, ndots := hostSearchList(t)
	const host = "stun.nb-test.example"
	if ndots > strings.Count(host, ".") {
		t.Skipf("ndots:%d tries the search list before the name itself for any lookup", ndots)
	}

	v4 := netip.MustParseAddr("192.0.2.10")
	fake := startFakeDNS(t, map[string][]netip.Addr{host + ".": {v4}}, false)
	n := &Net{ctx: context.Background(), resolver: fake.resolver()}

	got, err := n.resolveAddr("udp4", host+":3478")
	require.NoError(t, err)
	assert.Equal(t, netip.AddrPortFrom(v4, 3478), got, "IPv4 lane should get the A record")

	_, err = n.resolveAddr("udp6", host+":3478")
	assert.ErrorIs(t, err, errNoSuitableAddress, "IPv6 lane should find no address")

	for _, q := range fake.seen() {
		assert.True(t, strings.HasSuffix(q, " "+host+"."), "query %q left the host's own name", q)
	}
}

// A short name that only exists under a search domain, like foo.bar resolving
// as foo.bar.<search>. The search list must keep working for it on both lanes.
func TestResolveAddr_NameUnderSearchDomainStillResolves(t *testing.T) {
	search, ndots := hostSearchList(t)
	const host = "foo.nbtest"
	if ndots > strings.Count(host, ".") {
		t.Skipf("ndots:%d changes the order of the tried names", ndots)
	}

	v4 := netip.MustParseAddr("192.0.2.20")
	v6 := netip.MustParseAddr("2001:db8::20")
	fqdn := host + "." + strings.TrimSuffix(search[0], ".") + "."
	fake := startFakeDNS(t, map[string][]netip.Addr{fqdn: {v4, v6}}, false)
	n := &Net{ctx: context.Background(), resolver: fake.resolver()}

	got, err := n.resolveAddr("udp4", host+":3478")
	require.NoError(t, err)
	assert.Equal(t, netip.AddrPortFrom(v4, 3478), got, "IPv4 lane should resolve through the search domain")

	got, err = n.resolveAddr("udp6", host+":3478")
	require.NoError(t, err)
	assert.Equal(t, netip.AddrPortFrom(v6, 3478), got, "IPv6 lane should resolve through the search domain")
}

// A resolver that silently drops AAAA queries. The IPv4 lane (srflx and every TURN
// relay lookup) must not wait for the AAAA answer: the Go resolver would hold the A
// answer for its 5s query timeout per nameserver, so a 2s budget only passes when
// no AAAA is asked at all.
func TestResolveAddr_IPv4LaneIsNotStalledByDroppedAAAA(t *testing.T) {
	const host = "stun.nb-test.example"
	v4 := netip.MustParseAddr("192.0.2.10")
	fake := startFakeDNS(t, map[string][]netip.Addr{host + ".": {v4}}, true)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	n := &Net{ctx: ctx, resolver: fake.resolver()}

	got, err := n.resolveAddr("udp4", host+":3478")
	require.NoError(t, err, "IPv4 lane should resolve without waiting for the dropped AAAA")
	assert.Equal(t, netip.AddrPortFrom(v4, 3478), got, "IPv4 lane should get the A record")

	for _, q := range fake.seen() {
		assert.True(t, strings.HasPrefix(q, "A "), "IPv4 lane sent %q", q)
	}
}
