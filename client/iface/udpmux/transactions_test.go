package udpmux

import (
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

func TestSTUNRequestTransactionID(t *testing.T) {
	request := buildSTUN(t, stun.BindingRequest)
	id, ok := stunRequestTransactionID(request.Raw)
	require.True(t, ok, "a binding request must be recognised")
	assert.Equal(t, transactionID(request.TransactionID), id, "the ID is read from the header")

	for name, raw := range map[string][]byte{
		"success response": buildSTUN(t, stun.BindingSuccess).Raw,
		"error response":   buildSTUN(t, stun.BindingError).Raw,
		"indication":       buildSTUN(t, stun.NewType(stun.MethodBinding, stun.ClassIndication)).Raw,
		"short buffer":     request.Raw[:stunHeaderSize-1],
		"wireguard data":   {4, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
	} {
		_, ok := stunRequestTransactionID(raw)
		assert.False(t, ok, "%s must not be tracked", name)
	}
}

func TestTransactionTracker_Expiry(t *testing.T) {
	tracker := newTransactionTracker(transactionTTL, maxTransactions)
	conn := &udpMuxedConn{}
	start := time.Now()

	tracker.record(transactionID{1}, conn, start)
	tracker.record(transactionID{2}, conn, start)
	assert.Same(t, conn, tracker.take(transactionID{1}, start.Add(transactionTTL-time.Millisecond)), "a request is matched before its TTL")
	assert.Nil(t, tracker.take(transactionID{2}, start.Add(transactionTTL)), "a request is forgotten once its TTL has passed")
	assert.Zero(t, tracker.pending(), "expired requests are dropped")
}

func TestTransactionTracker_ResendRefreshes(t *testing.T) {
	tracker := newTransactionTracker(transactionTTL, maxTransactions)
	first, second := &udpMuxedConn{}, &udpMuxedConn{}
	start := time.Now()

	tracker.record(transactionID{1}, first, start)
	tracker.record(transactionID{1}, first, start.Add(transactionTTL-time.Second))
	assert.Equal(t, 1, tracker.pending(), "a resend does not add a second request")
	assert.Same(t, first, tracker.take(transactionID{1}, start.Add(transactionTTL+time.Second)),
		"a resent request is matched for a full TTL after the resend")

	tracker.record(transactionID{2}, first, start)
	tracker.record(transactionID{2}, second, start)
	assert.Same(t, second, tracker.take(transactionID{2}, start), "the latest sender receives the response")
	assert.Nil(t, tracker.take(transactionID{2}, start), "a request is matched once")
}

func TestTransactionTracker_Bounded(t *testing.T) {
	const limit = 4
	tracker := newTransactionTracker(transactionTTL, limit)
	conn := &udpMuxedConn{}
	now := time.Now()

	for i := byte(0); i < 10; i++ {
		tracker.record(transactionID{i}, conn, now)
	}
	assert.Equal(t, limit, tracker.pending(), "the tracker never holds more than its limit")
	assert.Nil(t, tracker.take(transactionID{5}, now), "the oldest requests are evicted first")
	assert.Same(t, conn, tracker.take(transactionID{6}, now), "the newest requests are kept")

	for i := 0; i < 100; i++ {
		tracker.record(transactionID{42}, conn, now)
	}
	assert.LessOrEqual(t, len(tracker.queue), 2*limit, "resends do not grow the queue past twice the limit")
}

// TestTransactionTracker_AnsweredRequestsDoNotEvict checks that the cap counts
// outstanding requests: a busy mux whose requests are answered quickly must
// not forget the one request still waiting for a slow peer.
func TestTransactionTracker_AnsweredRequestsDoNotEvict(t *testing.T) {
	const limit = 4
	tracker := newTransactionTracker(transactionTTL, limit)
	slow, busy := &udpMuxedConn{}, &udpMuxedConn{}
	now := time.Now()

	tracker.record(transactionID{0xff}, slow, now)
	for i := 0; i < 10*limit; i++ {
		id := transactionID{byte(i), 1}
		tracker.record(id, busy, now)
		require.Same(t, busy, tracker.take(id, now), "an answered request is matched")
	}

	assert.Same(t, slow, tracker.take(transactionID{0xff}, now), "the outstanding request survives answered traffic")
	assert.LessOrEqual(t, len(tracker.queue), 2*limit, "answered records do not grow the queue past twice the limit")
}

func TestTransactionTracker_Forget(t *testing.T) {
	tracker := newTransactionTracker(transactionTTL, maxTransactions)
	mux, _ := newLifecycleTestMux(t)
	first := lifecycleTestConn(t, mux, "first", "candidate:first")
	second := lifecycleTestConn(t, mux, "second", "candidate:second")
	now := time.Now()

	firstSeq := tracker.record(transactionID{1}, first, now)
	tracker.forget(transactionID{1}, first, firstSeq)
	assert.Nil(t, tracker.take(transactionID{1}, now), "a forgotten request is not matched")

	firstSeq = tracker.record(transactionID{2}, first, now)
	tracker.record(transactionID{2}, second, now)
	tracker.forget(transactionID{2}, first, firstSeq)
	assert.Same(t, second, tracker.take(transactionID{2}, now), "forget leaves a request resent by another conn")

	firstSeq = tracker.record(transactionID{3}, first, now)
	secondSeq := tracker.record(transactionID{3}, first, now)
	require.NotEqual(t, firstSeq, secondSeq, "a resend must not reuse the first send's rollback token")
	tracker.forget(transactionID{3}, first, firstSeq)
	assert.Same(t, first, tracker.take(transactionID{3}, now), "an older send error must not forget a newer resend by the same conn")
}

func TestTransactionTracker_RemoveConn(t *testing.T) {
	tracker := newTransactionTracker(transactionTTL, maxTransactions)
	gone, kept := &udpMuxedConn{}, &udpMuxedConn{}
	now := time.Now()

	tracker.record(transactionID{1}, gone, now)
	tracker.record(transactionID{2}, kept, now)
	tracker.removeConn(gone)

	assert.Nil(t, tracker.take(transactionID{1}, now), "requests of a removed conn are forgotten")
	assert.Same(t, kept, tracker.take(transactionID{2}, now), "requests of other conns are kept")

	// A write that passed the conn's closed check before the removal must not
	// leave a record once the conn is closed.
	closed := newUDPMuxedConn(&udpMuxedConnParams{})
	require.NoError(t, closed.Close())
	tracker.record(transactionID{3}, closed, now)
	assert.Zero(t, tracker.pending(), "a closed conn's request is not recorded")
}

func TestUniversalUDPMux_TransactionsBoundedAndReleased(t *testing.T) {
	mux, remote := newLoopbackMux(t)
	conn := getConn(t, mux, "ufragA")

	for i := 0; i < maxTransactions+100; i++ {
		writeTo(t, conn, buildSTUN(t, stun.BindingRequest).Raw, remote)
	}
	assert.Equal(t, maxTransactions, mux.transactions.pending(), "outstanding requests are capped")

	require.NoError(t, conn.Close())
	assert.Eventually(t, func() bool { return mux.transactions.pending() == 0 }, 5*time.Second, 10*time.Millisecond,
		"requests of a closed conn are forgotten")
}

func TestUniversalUDPMux_CloseForgetsTransactions(t *testing.T) {
	mux, remote := newLoopbackMux(t)
	conn := getConn(t, mux, "ufragA")

	writeTo(t, conn, buildSTUN(t, stun.BindingRequest).Raw, remote)
	require.Equal(t, 1, mux.transactions.pending(), "the request is recorded")

	require.NoError(t, mux.Close())
	assert.Zero(t, mux.transactions.pending(), "closing the mux forgets every request")
}

// TestUniversalUDPMux_RefusedWriteIsNotTracked writes a request to an address
// inside the overlay network, which the mux refuses to send.
func TestUniversalUDPMux_RefusedWriteIsNotTracked(t *testing.T) {
	wgAddr, err := wgaddr.ParseWGAddress("100.64.0.1/16")
	require.NoError(t, err)
	mux := startMux(t, UniversalUDPMuxParams{UDPConn: listenUDP(t, net.IPv4(127, 0, 0, 1)), MTU: 1280, WGAddress: wgAddr})
	conn := getConn(t, mux, "ufragA")

	_, err = conn.WriteTo(buildSTUN(t, stun.BindingRequest).Raw, &net.UDPAddr{IP: net.IPv4(100, 64, 0, 2), Port: 51820})
	require.Error(t, err, "a write into the overlay network is refused")
	assert.Zero(t, mux.transactions.pending(), "a request that was never sent is not tracked")
}

func (t *transactionTracker) pending() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}
