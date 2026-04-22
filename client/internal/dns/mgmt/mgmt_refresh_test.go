package mgmt

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/dns/test"
	"github.com/netbirdio/netbird/shared/management/domain"
)

type fakeChain struct {
	mu       sync.Mutex
	calls    map[string]int
	answers  map[string][]dns.RR
	err      error
	hasRoot  bool
	onLookup func()
}

func newFakeChain() *fakeChain {
	return &fakeChain{
		calls:   map[string]int{},
		answers: map[string][]dns.RR{},
		hasRoot: true,
	}
}

func (f *fakeChain) HasRootHandlerAtOrBelow(maxPriority int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hasRoot
}

func (f *fakeChain) ResolveInternal(ctx context.Context, msg *dns.Msg, maxPriority int) (*dns.Msg, error) {
	f.mu.Lock()
	q := msg.Question[0]
	key := q.Name + "|" + dns.TypeToString[q.Qtype]
	f.calls[key]++
	answers := f.answers[key]
	err := f.err
	onLookup := f.onLookup
	f.mu.Unlock()

	if onLookup != nil {
		onLookup()
	}
	if err != nil {
		return nil, err
	}
	resp := &dns.Msg{}
	resp.SetReply(msg)
	resp.Answer = answers
	return resp, nil
}

func (f *fakeChain) setAnswer(name string, qtype uint16, ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := name + "|" + dns.TypeToString[qtype]
	hdr := dns.RR_Header{Name: name, Rrtype: qtype, Class: dns.ClassINET, Ttl: 60}
	switch qtype {
	case dns.TypeA:
		f.answers[key] = []dns.RR{&dns.A{Hdr: hdr, A: net.ParseIP(ip).To4()}}
	case dns.TypeAAAA:
		f.answers[key] = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.ParseIP(ip).To16()}}
	}
}

func (f *fakeChain) callCount(name string, qtype uint16) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name+"|"+dns.TypeToString[qtype]]
}

// waitFor polls the predicate until it returns true or the deadline passes.
func waitFor(t *testing.T, d time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", d)
}

func queryA(t *testing.T, r *Resolver, name string) *dns.Msg {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	w := &test.MockResponseWriter{}
	r.ServeDNS(w, msg)
	return w.GetLastResponse()
}

func firstA(t *testing.T, resp *dns.Msg) string {
	t.Helper()
	require.NotNil(t, resp)
	require.Greater(t, len(resp.Answer), 0, "expected at least one answer")
	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok, "expected A record")
	return a.A.String()
}

func TestResolver_CacheTTLGatesRefresh(t *testing.T) {
	// Same cached entry age, different cacheTTL values: the shorter TTL must
	// trigger a background refresh, the longer one must not. Proves that the
	// per-Resolver cacheTTL field actually drives the stale decision.
	cachedAt := time.Now().Add(-100 * time.Millisecond)

	newRec := func() *cachedRecord {
		return &cachedRecord{
			records: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "mgmt.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("10.0.0.1").To4(),
			}},
			cachedAt: cachedAt,
		}
	}
	q := dns.Question{Name: "mgmt.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	t.Run("short TTL treats entry as stale and refreshes", func(t *testing.T) {
		r := NewResolver()
		r.cacheTTL = 10 * time.Millisecond
		chain := newFakeChain()
		chain.setAnswer(q.Name, dns.TypeA, "10.0.0.2")
		r.SetChainResolver(chain, 50)
		r.records[q] = newRec()

		resp := queryA(t, r, q.Name)
		assert.Equal(t, "10.0.0.1", firstA(t, resp), "stale entry must be served while refresh runs")

		waitFor(t, time.Second, func() bool {
			return chain.callCount(q.Name, dns.TypeA) >= 1
		})
	})

	t.Run("long TTL keeps entry fresh and skips refresh", func(t *testing.T) {
		r := NewResolver()
		r.cacheTTL = time.Hour
		chain := newFakeChain()
		chain.setAnswer(q.Name, dns.TypeA, "10.0.0.2")
		r.SetChainResolver(chain, 50)
		r.records[q] = newRec()

		resp := queryA(t, r, q.Name)
		assert.Equal(t, "10.0.0.1", firstA(t, resp))

		time.Sleep(50 * time.Millisecond)
		assert.Equal(t, 0, chain.callCount(q.Name, dns.TypeA), "fresh entry must not trigger refresh")
	})
}

func TestResolver_ServeFresh_NoRefresh(t *testing.T) {
	r := NewResolver()
	chain := newFakeChain()
	chain.setAnswer("mgmt.example.com.", dns.TypeA, "10.0.0.2")
	r.SetChainResolver(chain, 50)

	r.records[dns.Question{Name: "mgmt.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}] = &cachedRecord{
		records: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: "mgmt.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1").To4(),
		}},
		cachedAt: time.Now(), // fresh
	}

	resp := queryA(t, r, "mgmt.example.com.")
	assert.Equal(t, "10.0.0.1", firstA(t, resp))

	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, 0, chain.callCount("mgmt.example.com.", dns.TypeA), "fresh entry must not trigger refresh")
}

func TestResolver_StaleTriggersAsyncRefresh(t *testing.T) {
	r := NewResolver()
	chain := newFakeChain()
	chain.setAnswer("mgmt.example.com.", dns.TypeA, "10.0.0.2")
	r.SetChainResolver(chain, 50)

	q := dns.Question{Name: "mgmt.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	r.records[q] = &cachedRecord{
		records: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1").To4(),
		}},
		cachedAt: time.Now().Add(-2 * defaultTTL), // stale
	}

	// First query: serves stale immediately.
	resp := queryA(t, r, "mgmt.example.com.")
	assert.Equal(t, "10.0.0.1", firstA(t, resp), "stale entry must be served while refresh runs")

	waitFor(t, time.Second, func() bool {
		return chain.callCount("mgmt.example.com.", dns.TypeA) >= 1
	})

	// Next query should now return the refreshed IP.
	waitFor(t, time.Second, func() bool {
		resp := queryA(t, r, "mgmt.example.com.")
		return resp != nil && len(resp.Answer) > 0 && firstA(t, resp) == "10.0.0.2"
	})
}

func TestResolver_ConcurrentStaleHitsCollapseRefresh(t *testing.T) {
	r := NewResolver()
	chain := newFakeChain()
	chain.setAnswer("mgmt.example.com.", dns.TypeA, "10.0.0.2")

	var inflight atomic.Int32
	var maxInflight atomic.Int32
	chain.onLookup = func() {
		cur := inflight.Add(1)
		defer inflight.Add(-1)
		for {
			prev := maxInflight.Load()
			if cur <= prev || maxInflight.CompareAndSwap(prev, cur) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond) // hold inflight long enough to collide
	}

	r.SetChainResolver(chain, 50)

	q := dns.Question{Name: "mgmt.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	r.records[q] = &cachedRecord{
		records: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1").To4(),
		}},
		cachedAt: time.Now().Add(-2 * defaultTTL),
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			queryA(t, r, "mgmt.example.com.")
		}()
	}
	wg.Wait()

	waitFor(t, 2*time.Second, func() bool {
		return inflight.Load() == 0
	})

	calls := chain.callCount("mgmt.example.com.", dns.TypeA)
	assert.LessOrEqual(t, calls, 2, "singleflight must collapse concurrent refreshes (got %d)", calls)
	assert.Equal(t, int32(1), maxInflight.Load(), "only one refresh should run concurrently")
}

func TestResolver_RefreshFailureArmsBackoff(t *testing.T) {
	r := NewResolver()
	chain := newFakeChain()
	chain.err = errors.New("boom")
	r.SetChainResolver(chain, 50)

	q := dns.Question{Name: "mgmt.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	r.records[q] = &cachedRecord{
		records: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1").To4(),
		}},
		cachedAt: time.Now().Add(-2 * defaultTTL),
	}

	// First stale hit triggers a refresh attempt that fails.
	resp := queryA(t, r, "mgmt.example.com.")
	assert.Equal(t, "10.0.0.1", firstA(t, resp), "stale entry served while refresh fails")

	waitFor(t, time.Second, func() bool {
		return chain.callCount("mgmt.example.com.", dns.TypeA) == 1
	})
	waitFor(t, time.Second, func() bool {
		r.mutex.RLock()
		defer r.mutex.RUnlock()
		c, ok := r.records[q]
		return ok && !c.lastFailedRefresh.IsZero()
	})

	// Subsequent stale hits within backoff window should not schedule more refreshes.
	for i := 0; i < 10; i++ {
		queryA(t, r, "mgmt.example.com.")
	}
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 1, chain.callCount("mgmt.example.com.", dns.TypeA), "backoff must suppress further refreshes")
}

func TestResolver_NoRootHandler_SkipsChain(t *testing.T) {
	r := NewResolver()
	chain := newFakeChain()
	chain.hasRoot = false
	chain.setAnswer("mgmt.example.com.", dns.TypeA, "10.0.0.2")
	r.SetChainResolver(chain, 50)

	// With hasRoot=false the chain must not be consulted. Use a short
	// deadline so the OS fallback returns quickly without waiting on a
	// real network call in CI.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, _, _ = r.lookupBoth(ctx, domain.Domain("mgmt.example.com"), "mgmt.example.com.")

	assert.Equal(t, 0, chain.callCount("mgmt.example.com.", dns.TypeA),
		"chain must not be used when no root handler is registered at the bound priority")
}

func TestResolver_ServeDuringRefreshSetsLoopFlag(t *testing.T) {
	// ServeDNS being invoked for a question while a refresh for that question
	// is inflight indicates a resolver loop (OS resolver sent the recursive
	// query back to us). The inflightRefresh.loopLoggedOnce flag must be set.
	r := NewResolver()

	q := dns.Question{Name: "mgmt.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	r.records[q] = &cachedRecord{
		records: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1").To4(),
		}},
		cachedAt: time.Now(),
	}

	// Simulate an inflight refresh.
	r.markRefreshing(q)
	defer r.clearRefreshing(q)

	resp := queryA(t, r, "mgmt.example.com.")
	assert.Equal(t, "10.0.0.1", firstA(t, resp), "stale entry must still be served to avoid breaking external queries")

	r.mutex.RLock()
	inflight := r.refreshing[q]
	r.mutex.RUnlock()
	require.NotNil(t, inflight)
	assert.True(t, inflight.Load(), "loop flag must be set once a ServeDNS during refresh was observed")
}

func TestResolver_LoopFlagOnlyTrippedOncePerRefresh(t *testing.T) {
	r := NewResolver()

	q := dns.Question{Name: "mgmt.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	r.records[q] = &cachedRecord{
		records: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1").To4(),
		}},
		cachedAt: time.Now(),
	}

	r.markRefreshing(q)
	defer r.clearRefreshing(q)

	// Multiple ServeDNS calls during the same refresh must not re-set the flag
	// (CompareAndSwap from false -> true returns true only on the first call).
	for range 5 {
		queryA(t, r, "mgmt.example.com.")
	}

	r.mutex.RLock()
	inflight := r.refreshing[q]
	r.mutex.RUnlock()
	assert.True(t, inflight.Load())
}

func TestResolver_NoLoopFlagWhenNotRefreshing(t *testing.T) {
	r := NewResolver()

	q := dns.Question{Name: "mgmt.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	r.records[q] = &cachedRecord{
		records: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1").To4(),
		}},
		cachedAt: time.Now(),
	}

	queryA(t, r, "mgmt.example.com.")

	r.mutex.RLock()
	_, ok := r.refreshing[q]
	r.mutex.RUnlock()
	assert.False(t, ok, "no refresh inflight means no loop tracking")
}

func TestResolver_AddDomain_UsesChainWhenRootRegistered(t *testing.T) {
	r := NewResolver()
	chain := newFakeChain()
	chain.setAnswer("mgmt.example.com.", dns.TypeA, "10.0.0.2")
	chain.setAnswer("mgmt.example.com.", dns.TypeAAAA, "fd00::2")
	r.SetChainResolver(chain, 50)

	require.NoError(t, r.AddDomain(context.Background(), domain.Domain("mgmt.example.com")))

	resp := queryA(t, r, "mgmt.example.com.")
	assert.Equal(t, "10.0.0.2", firstA(t, resp))
	assert.Equal(t, 1, chain.callCount("mgmt.example.com.", dns.TypeA))
	assert.Equal(t, 1, chain.callCount("mgmt.example.com.", dns.TypeAAAA))
}
