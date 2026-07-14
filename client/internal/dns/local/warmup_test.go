package local

import (
	"context"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/dns/test"
	nbdns "github.com/netbirdio/netbird/dns"
)

// recordingActivator records the IPs it was asked to warm and returns
// immediately, so ServeDNS is not blocked by the test.
type recordingActivator struct {
	mu     sync.Mutex
	called bool
	ips    []string
}

func (r *recordingActivator) ActivatePeersByIP(_ context.Context, ips []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.called = true
	r.ips = append(r.ips, ips...)
}

func serveA(t *testing.T, resolver *Resolver, name string) *dns.Msg {
	t.Helper()
	var resp *dns.Msg
	w := &test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}
	resolver.ServeDNS(w, new(dns.Msg).SetQuestion(name, dns.TypeA))
	return resp
}

func TestLocalResolver_WarmsLazyPeerOnResolve(t *testing.T) {
	rec := nbdns.SimpleRecord{Name: "svc.netbird.cloud.", Type: 1, Class: nbdns.DefaultClass, TTL: 300, RData: "100.64.0.7"}
	resolver := NewResolver()
	require.NoError(t, resolver.RegisterRecord(rec))

	act := &recordingActivator{}
	resolver.SetPeerActivator(act)

	resp := serveA(t, resolver, rec.Name)
	require.NotNil(t, resp, "resolver must answer")
	require.NotEmpty(t, resp.Answer, "answer must carry the A record")

	act.mu.Lock()
	defer act.mu.Unlock()
	assert.True(t, act.called, "activator must be invoked for an overlay A answer")
	assert.Contains(t, act.ips, "100.64.0.7", "activator must receive the answer's peer IP")
}

func TestLocalResolver_NoActivatorNoWarmup(t *testing.T) {
	// With no activator wired the resolver behaves exactly as before.
	rec := nbdns.SimpleRecord{Name: "svc.netbird.cloud.", Type: 1, Class: nbdns.DefaultClass, TTL: 300, RData: "100.64.0.7"}
	resolver := NewResolver()
	require.NoError(t, resolver.RegisterRecord(rec))

	resp := serveA(t, resolver, rec.Name)
	require.NotNil(t, resp, "resolver must still answer without an activator")
	require.NotEmpty(t, resp.Answer, "answer must carry the A record")
}

func TestLocalResolver_NoWarmupForMissingRecord(t *testing.T) {
	// A query that resolves to nothing must not invoke the activator (no IPs).
	resolver := NewResolver()
	require.NoError(t, resolver.RegisterRecord(nbdns.SimpleRecord{Name: "svc.netbird.cloud.", Type: 1, Class: nbdns.DefaultClass, TTL: 300, RData: "100.64.0.7"}))

	act := &recordingActivator{}
	resolver.SetPeerActivator(act)

	serveA(t, resolver, "absent.netbird.cloud.")

	act.mu.Lock()
	defer act.mu.Unlock()
	assert.False(t, act.called, "activator must not be invoked when there is no answer")
}
