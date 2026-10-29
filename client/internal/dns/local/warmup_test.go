package local

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/dns/test"
	nbdns "github.com/netbirdio/netbird/dns"
)

// recordingActivator records the addresses it was asked to warm and returns
// immediately, so ServeDNS is not blocked by the test.
type recordingActivator struct {
	mu     sync.Mutex
	called bool
	addrs  []netip.Addr
}

func (r *recordingActivator) ActivatePeersByIP(_ context.Context, addrs []netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.called = true
	r.addrs = append(r.addrs, addrs...)
}

func serveA(t *testing.T, resolver *Resolver, name string) *dns.Msg {
	t.Helper()
	var resp *dns.Msg
	w := &test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}
	resolver.ServeDNS(w, new(dns.Msg).SetQuestion(name, dns.TypeA))
	return resp
}

// serviceZone registers rec in a match-only (non-authoritative) zone, the shape
// the synthesized private-service zones arrive in.
func serviceZone(t *testing.T, resolver *Resolver, zone string, records ...nbdns.SimpleRecord) {
	t.Helper()
	resolver.Update([]nbdns.CustomZone{{
		Domain:           zone,
		Records:          records,
		NonAuthoritative: true,
	}})
}

func TestLocalResolver_WarmsLazyPeerOnResolve(t *testing.T) {
	// Warm-up fires only for multi-record answers (the HA / round-robin shape of
	// the synthesized private-service zones), so register two peer targets.
	const name = "svc.proxy.netbird.cloud."
	recs := []nbdns.SimpleRecord{
		{Name: name, Type: 1, Class: nbdns.DefaultClass, TTL: 300, RData: "100.64.0.7"},
		{Name: name, Type: 1, Class: nbdns.DefaultClass, TTL: 300, RData: "100.64.0.8"},
	}
	resolver := NewResolver()
	serviceZone(t, resolver, "proxy.netbird.cloud", recs...)

	act := &recordingActivator{}
	resolver.SetPeerActivator(act)

	resp := serveA(t, resolver, name)
	require.NotNil(t, resp, "resolver must answer")
	require.NotEmpty(t, resp.Answer, "answer must carry the A records")

	act.mu.Lock()
	defer act.mu.Unlock()
	assert.True(t, act.called, "activator must be invoked for a multi-record service-zone answer")
	assert.Contains(t, act.addrs, netip.MustParseAddr("100.64.0.7"), "activator must receive the first peer IP")
	assert.Contains(t, act.addrs, netip.MustParseAddr("100.64.0.8"), "activator must receive the second peer IP")
}

func TestLocalResolver_NoWarmupForSingleRecord(t *testing.T) {
	// A single-record answer does not trigger warm-up; the resolver only warms
	// multi-record answers.
	rec := nbdns.SimpleRecord{Name: "svc.proxy.netbird.cloud.", Type: 1, Class: nbdns.DefaultClass, TTL: 300, RData: "100.64.0.7"}
	resolver := NewResolver()
	serviceZone(t, resolver, "proxy.netbird.cloud", rec)

	act := &recordingActivator{}
	resolver.SetPeerActivator(act)

	resp := serveA(t, resolver, rec.Name)
	require.NotNil(t, resp, "resolver must answer")
	require.NotEmpty(t, resp.Answer, "answer must carry the A record")

	act.mu.Lock()
	defer act.mu.Unlock()
	assert.False(t, act.called, "activator must not be invoked for a single-record answer")
}

func TestLocalResolver_NoActivatorNoWarmup(t *testing.T) {
	// With no activator wired the resolver behaves exactly as before.
	rec := nbdns.SimpleRecord{Name: "svc.proxy.netbird.cloud.", Type: 1, Class: nbdns.DefaultClass, TTL: 300, RData: "100.64.0.7"}
	resolver := NewResolver()
	serviceZone(t, resolver, "proxy.netbird.cloud", rec)

	resp := serveA(t, resolver, rec.Name)
	require.NotNil(t, resp, "resolver must still answer without an activator")
	require.NotEmpty(t, resp.Answer, "answer must carry the A record")
}

func TestLocalResolver_NoWarmupForMissingRecord(t *testing.T) {
	// A query that resolves to nothing must not invoke the activator (no IPs).
	resolver := NewResolver()
	serviceZone(t, resolver, "proxy.netbird.cloud",
		nbdns.SimpleRecord{Name: "svc.proxy.netbird.cloud.", Type: 1, Class: nbdns.DefaultClass, TTL: 300, RData: "100.64.0.7"})

	act := &recordingActivator{}
	resolver.SetPeerActivator(act)

	serveA(t, resolver, "absent.proxy.netbird.cloud.")

	act.mu.Lock()
	defer act.mu.Unlock()
	assert.False(t, act.called, "activator must not be invoked when there is no answer")
}

func TestLocalResolver_NoWarmupInAuthoritativeZone(t *testing.T) {
	// The account's peer zone is authoritative; resolving a peer's name there
	// must not wake its lazy connection — warm-up is scoped to match-only
	// (non-authoritative) zones such as the synthesized private-service zones.
	// Use a multi-record answer so the authoritative-zone scoping is the only
	// reason warm-up is skipped, not the single-record guard.
	const name = "peer.netbird.cloud."
	recs := []nbdns.SimpleRecord{
		{Name: name, Type: 1, Class: nbdns.DefaultClass, TTL: 300, RData: "100.64.0.9"},
		{Name: name, Type: 1, Class: nbdns.DefaultClass, TTL: 300, RData: "100.64.0.10"},
	}
	resolver := NewResolver()
	resolver.Update([]nbdns.CustomZone{{
		Domain:  "netbird.cloud",
		Records: recs,
	}})

	act := &recordingActivator{}
	resolver.SetPeerActivator(act)

	resp := serveA(t, resolver, name)
	require.NotNil(t, resp, "resolver must answer")
	require.NotEmpty(t, resp.Answer, "answer must carry the A records")

	act.mu.Lock()
	defer act.mu.Unlock()
	assert.False(t, act.called, "activator must not be invoked for authoritative-zone answers")
}

func TestLazyWarmupTimeoutFromEnv(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		envSet bool
		want   time.Duration
	}{
		{name: "unset uses default", want: defaultLazyWarmupTimeout},
		{name: "valid overrides", value: "5s", envSet: true, want: 5 * time.Second},
		{name: "invalid falls back", value: "not-a-duration", envSet: true, want: defaultLazyWarmupTimeout},
		{name: "negative falls back", value: "-1s", envSet: true, want: defaultLazyWarmupTimeout},
		{name: "zero falls back", value: "0s", envSet: true, want: defaultLazyWarmupTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envSet {
				t.Setenv(envLazyWarmupTimeout, tt.value)
			}
			assert.Equal(t, tt.want, lazyWarmupTimeoutFromEnv())
			assert.Equal(t, tt.want, NewResolver().warmupTimeout, "constructor must resolve the timeout once")
		})
	}
}

func TestExtractRecordAddr(t *testing.T) {
	t.Run("A record yields unmapped v4", func(t *testing.T) {
		// net.ParseIP returns the 16-byte v4-in-v6 form, the same shape
		// miekg/dns stores after parsing an A record; the extracted address
		// must compare equal to a plain v4 netip.Addr.
		addr, ok := extractRecordAddr(&dns.A{A: net.ParseIP("100.64.0.7")})
		require.True(t, ok)
		assert.True(t, addr.Is4())
		assert.Equal(t, netip.MustParseAddr("100.64.0.7"), addr)
	})

	t.Run("AAAA record yields v6", func(t *testing.T) {
		addr, ok := extractRecordAddr(&dns.AAAA{AAAA: net.ParseIP("fd00::1")})
		require.True(t, ok)
		assert.Equal(t, netip.MustParseAddr("fd00::1"), addr)
	})

	t.Run("A record without address", func(t *testing.T) {
		_, ok := extractRecordAddr(&dns.A{})
		assert.False(t, ok)
	})

	t.Run("non-address record", func(t *testing.T) {
		_, ok := extractRecordAddr(&dns.CNAME{Target: "target.netbird.cloud."})
		assert.False(t, ok)
	})
}
