package udpmux

import (
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnsweredTransactionsKeepOriginalExpiry(t *testing.T) {
	tracker := newTransactionTracker(transactionTTL, 4)
	mux, _ := newLifecycleTestMux(t)
	conn := lifecycleTestConn(t, mux, "agent", "candidate")
	start := time.Now()
	older, newer := transactionID{1}, transactionID{2}
	tracker.record(older, conn, start)
	tracker.record(newer, conn, start.Add(time.Second))
	assert.Same(t, conn, tracker.take(newer, start.Add(2*time.Second)))
	assert.Same(t, conn, tracker.take(older, start.Add(3*time.Second)))
	assert.Zero(t, tracker.pending(), "responses remove pending entries")
	assert.Same(t, conn, tracker.take(older, start.Add(transactionTTL-time.Millisecond)))
	assert.Nil(t, tracker.take(older, start.Add(transactionTTL)), "a duplicate cannot extend the original deadline")
	assert.Same(t, conn, tracker.take(newer, start.Add(transactionTTL)), "an earlier response can have a later expiry")
	tracker.pruneRecent(start.Add(transactionTTL + time.Second))
	assert.Empty(t, tracker.recent)
	assert.Empty(t, tracker.recentQueue, "physical cleanup must handle expiry order differing from response order")
}

func TestAnsweredTransactionsBoundedWithoutEvictingPending(t *testing.T) {
	const limit = 4
	tracker := newTransactionTracker(transactionTTL, limit)
	mux, _ := newLifecycleTestMux(t)
	conn := lifecycleTestConn(t, mux, "agent", "candidate")
	now := time.Now()
	slow := transactionID{0xff}
	tracker.record(slow, conn, now)
	for i := byte(0); i < 40; i++ {
		id := transactionID{i}
		tracker.record(id, conn, now)
		require.Same(t, conn, tracker.take(id, now))
		assert.LessOrEqual(t, len(tracker.recent), limit)
		assert.LessOrEqual(t, len(tracker.recentQueue), 2*limit)
	}
	assert.Nil(t, tracker.take(transactionID{0}, now), "the oldest answered owner is evicted at the recent cap")
	assert.Same(t, conn, tracker.take(transactionID{39}, now))
	assert.Same(t, conn, tracker.take(slow, now), "answered traffic must not evict an outstanding check")
	for i := 0; i < 40; i++ {
		assert.Zero(t, tracker.record(slow, conn, now), "a resend retains prior same-candidate ownership")
		require.Same(t, conn, tracker.take(slow, now))
	}
	assert.LessOrEqual(t, len(tracker.recent), limit)
	assert.LessOrEqual(t, len(tracker.recentQueue), 2*limit, "reanswered generations must not grow bookkeeping without bound")
	tracker.removeConn(conn)
	assert.Empty(t, tracker.entries)
	assert.Empty(t, tracker.recent, "connection removal must release both pending and recently answered owners")
	tracker.clear()
	assert.Empty(t, tracker.queue)
	assert.Empty(t, tracker.recentQueue)
}

func TestAnsweredTransactionIdleExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mux, remote := newLifecycleTestMux(t)
		conn := lifecycleTestConn(t, mux, "agent", "candidate")
		request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		_, err := conn.WriteTo(request.Raw, remote.LocalAddr())
		require.NoError(t, err)
		require.NoError(t, mux.HandleSTUNMessage(buildResponse(t, request), remote.LocalAddr()))
		mux.transactions.mu.Lock()
		recentCount := len(mux.transactions.recent)
		mux.transactions.mu.Unlock()
		require.Equal(t, 1, recentCount)
		time.Sleep(2 * transactionTTL)
		synctest.Wait()
		mux.transactions.mu.Lock()
		assert.Empty(t, mux.transactions.recent, "an idle mux must release recently answered owners")
		assert.Empty(t, mux.transactions.recentQueue)
		mux.transactions.mu.Unlock()
	})
}

func TestAnsweredTransactionFailedResendKeepsOwner(t *testing.T) {
	mux, remote := newLifecycleTestMux(t)
	sender := lifecycleTestConn(t, mux, "agent", "candidate:sender")
	sibling := lifecycleTestConn(t, mux, "agent", "candidate:sibling")
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	writeLifecycleTestPacket(t, sender, request.Raw, remote)
	writeLifecycleTestPacket(t, sibling, []byte("register sibling"), remote)
	response := buildResponse(t, request)
	require.NoError(t, mux.HandleSTUNMessage(response, remote.LocalAddr()))
	assertLifecycleTestPacket(t, sender, response.Raw)

	require.NoError(t, mux.params.UDPConn.SetWriteDeadline(time.Now().Add(-time.Second)))
	_, err := sender.WriteTo(request.Raw, remote.LocalAddr())
	var timeout net.Error
	require.ErrorAs(t, err, &timeout)
	require.True(t, timeout.Timeout())
	require.NoError(t, mux.params.UDPConn.SetWriteDeadline(time.Time{}))
	require.NoError(t, mux.HandleSTUNMessage(response, remote.LocalAddr()))
	assertLifecycleTestPacket(t, sender, response.Raw)
	assert.Zero(t, sibling.buf.Count(), "a failed resend must not send a known duplicate into broad fallback")
	assert.Zero(t, mux.transactions.pending())
}
