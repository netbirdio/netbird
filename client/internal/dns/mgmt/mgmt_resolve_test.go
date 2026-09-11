package mgmt

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dnsconfig "github.com/netbirdio/netbird/client/internal/dns/config"
	"github.com/netbirdio/netbird/shared/management/domain"
)

// A domain already in the cache must not be re-resolved on a subsequent server
// domains update; it is left to the stale-while-revalidate refresh path.
func TestResolver_UpdateFromServerDomains_SkipsCached(t *testing.T) {
	r := NewResolver()
	chain := newFakeChain()
	chain.setAnswer("signal.example.com.", dns.TypeA, "10.0.0.2")
	r.SetChainResolver(chain, 50)

	sd := dnsconfig.ServerDomains{Signal: domain.Domain("signal.example.com")}

	_, err := r.UpdateFromServerDomains(context.Background(), sd)
	require.NoError(t, err)
	require.Equal(t, 1, chain.callCount("signal.example.com.", dns.TypeA),
		"first update must resolve the domain")

	_, err = r.UpdateFromServerDomains(context.Background(), sd)
	require.NoError(t, err)
	assert.Equal(t, 1, chain.callCount("signal.example.com.", dns.TypeA),
		"cached domain must not be re-resolved on a subsequent update")
}

// New domains in a single update must resolve concurrently rather than serially.
func TestResolver_AddNewDomains_ResolvesConcurrently(t *testing.T) {
	r := NewResolver()
	chain := newFakeChain()

	var inflight, maxInflight atomic.Int32
	chain.onLookup = func() {
		n := inflight.Add(1)
		for {
			old := maxInflight.Load()
			if n <= old || maxInflight.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		inflight.Add(-1)
	}

	relays := []domain.Domain{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	for _, d := range relays {
		chain.setAnswer(dns.Fqdn(string(d)), dns.TypeA, "10.0.0.2")
	}
	r.SetChainResolver(chain, 50)

	start := time.Now()
	_, err := r.UpdateFromServerDomains(context.Background(), dnsconfig.ServerDomains{Relay: relays})
	require.NoError(t, err)
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, int(maxInflight.Load()), 2, "domains must resolve concurrently")
	// Serial resolution of 4 domains would take at least 4*50ms; concurrent is far less.
	assert.Less(t, elapsed, 300*time.Millisecond, "resolution should not be serial")
}

// A domain that fails to resolve must not be retried on every update; the
// failure backoff suppresses re-resolution until it expires.
func TestResolver_UpdateFromServerDomains_BacksOffFailures(t *testing.T) {
	r := NewResolver()
	chain := newFakeChain()
	chain.err = errors.New("resolve boom")
	r.SetChainResolver(chain, 50)

	sd := dnsconfig.ServerDomains{Signal: domain.Domain("signal.example.com")}

	_, err := r.UpdateFromServerDomains(context.Background(), sd)
	require.NoError(t, err)
	require.Equal(t, 1, chain.callCount("signal.example.com.", dns.TypeA),
		"first update must attempt the resolve")

	_, err = r.UpdateFromServerDomains(context.Background(), sd)
	require.NoError(t, err)
	assert.Equal(t, 1, chain.callCount("signal.example.com.", dns.TypeA),
		"failed resolve must back off and not retry on the next update")
}

// A domain listed under more than one server-domain type (e.g. STUN and TURN on
// the same host) must be resolved once per update, not once per occurrence.
func TestResolver_AddNewDomains_DedupesDuplicateDomains(t *testing.T) {
	r := NewResolver()
	chain := newFakeChain()
	chain.setAnswer("dup.example.com.", dns.TypeA, "10.0.0.9")
	r.SetChainResolver(chain, 50)

	sd := dnsconfig.ServerDomains{
		Stuns: []domain.Domain{"dup.example.com"},
		Turns: []domain.Domain{"dup.example.com"},
	}

	_, err := r.UpdateFromServerDomains(context.Background(), sd)
	require.NoError(t, err)
	assert.Equal(t, 1, chain.callCount("dup.example.com.", dns.TypeA),
		"a domain appearing under multiple server-domain types must resolve once")
}

// A failure marker must be dropped once its domain leaves the server-domains set
// so the map stays bounded to the current set.
func TestResolver_UpdateFromServerDomains_PrunesFailedResolves(t *testing.T) {
	r := NewResolver()
	chain := newFakeChain()
	chain.err = errors.New("resolve boom")
	r.SetChainResolver(chain, 50)

	_, err := r.UpdateFromServerDomains(context.Background(), dnsconfig.ServerDomains{Signal: domain.Domain("gone.example.com")})
	require.NoError(t, err)
	r.mutex.RLock()
	_, marked := r.failedResolves[domain.Domain("gone.example.com")]
	r.mutex.RUnlock()
	require.True(t, marked, "failed resolve must be recorded")

	_, err = r.UpdateFromServerDomains(context.Background(), dnsconfig.ServerDomains{Signal: domain.Domain("other.example.com")})
	require.NoError(t, err)
	r.mutex.RLock()
	_, stillMarked := r.failedResolves[domain.Domain("gone.example.com")]
	r.mutex.RUnlock()
	assert.False(t, stillMarked, "failure marker for a domain no longer in the set must be pruned")
}

// When one family hard-errors while the other resolves, the domain is cached
// for the working family but recorded as incomplete so the failed family is
// retried under backoff instead of being treated as fully resolved forever.
func TestResolver_AddNewDomains_RetriesPartialFamilyFailure(t *testing.T) {
	d := domain.Domain("relay.example.com")
	r := NewResolver()
	chain := newFakeChain()
	chain.setAnswer("relay.example.com.", dns.TypeA, "10.0.0.2")
	chain.setErr("relay.example.com.", dns.TypeAAAA, errors.New("servfail"))
	r.SetChainResolver(chain, 50)

	_, err := r.UpdateFromServerDomains(context.Background(), dnsconfig.ServerDomains{Relay: []domain.Domain{d}})
	require.NoError(t, err)

	r.mutex.RLock()
	_, aCached := r.records[dns.Question{Name: "relay.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}]
	_, marked := r.failedResolves[d]
	r.mutex.RUnlock()
	require.True(t, aCached, "the working family must still be cached")
	require.True(t, marked, "a partial failure must be recorded so the failed family is retried")

	assert.False(t, r.needsResolve(d), "within the backoff window the domain is not retried")

	r.mutex.Lock()
	r.failedResolves[d] = time.Now().Add(-2 * refreshBackoff)
	r.mutex.Unlock()
	assert.True(t, r.needsResolve(d), "after the backoff elapses the domain is retried to pick up the missing family")
}

// A family that returns NODATA (legitimately absent, e.g. an IPv4-only host) is
// not a failure: the domain must not be marked for retry, otherwise it would be
// re-resolved on every sync.
func TestResolver_AddNewDomains_NodataIsNotFailure(t *testing.T) {
	d := domain.Domain("v4only.example.com")
	r := NewResolver()
	chain := newFakeChain()
	chain.setAnswer("v4only.example.com.", dns.TypeA, "10.0.0.2")
	r.SetChainResolver(chain, 50)

	_, err := r.UpdateFromServerDomains(context.Background(), dnsconfig.ServerDomains{Relay: []domain.Domain{d}})
	require.NoError(t, err)

	r.mutex.RLock()
	_, marked := r.failedResolves[d]
	r.mutex.RUnlock()
	assert.False(t, marked, "a NODATA family must not be recorded as a failure")
	assert.False(t, r.needsResolve(d), "an IPv4-only host must not be re-resolved on later syncs")
}
