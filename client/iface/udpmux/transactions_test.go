package udpmux

import (
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.LessOrEqual(t, len(tracker.queue), limit, "resends do not grow the queue past the limit")
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
}

func TestUniversalUDPMux_TransactionsBoundedAndReleased(t *testing.T) {
	mux, remote := newLoopbackMux(t)
	conn := getConn(t, mux, "ufragA")

	for i := 0; i < maxTransactions+100; i++ {
		writeTo(t, conn, buildSTUN(t, stun.BindingRequest).Raw, remote)
	}
	assert.Equal(t, maxTransactions, mux.transactions.pending(), "outstanding requests are capped")

	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool { return mux.transactions.pending() == 0 }, 5*time.Second, 10*time.Millisecond,
		"requests of a closed conn are forgotten")
}
