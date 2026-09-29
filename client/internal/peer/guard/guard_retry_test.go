package guard

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer/ice"
)

// switchableStatus is a connection status the test changes while the guard runs.
type switchableStatus struct {
	v atomic.Int32
}

func (s *switchableStatus) get() ConnStatus     { return ConnStatus(s.v.Load()) }
func (s *switchableStatus) set(cs ConnStatus)   { s.v.Store(int32(cs)) }
func newStatus(cs ConnStatus) *switchableStatus { s := &switchableStatus{}; s.set(cs); return s }

// startCountingGuard runs a guard whose backoff caps at 100ms and counts the
// offers it triggers.
func startCountingGuard(t *testing.T, status *switchableStatus) (*Guard, *atomic.Int32) {
	t.Helper()
	srw := NewSRWatcher(nil, nil, nil, ice.Config{})
	g := NewGuard(log.WithField("test", t.Name()), status.get, 100*time.Millisecond, srw, nil)

	var offers atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go g.Start(ctx, func() { offers.Add(1) })
	return g, &offers
}

// requireHourlyRetry waits until the guard spent its partial budget and waits
// for the hourly retry.
func requireHourlyRetry(t *testing.T, offers *atomic.Int32) {
	t.Helper()
	require.Eventually(t, func() bool { return offers.Load() == maxICERetries }, 15*time.Second, 20*time.Millisecond,
		"the guard must spend its partial budget")
	require.Never(t, func() bool { return offers.Load() > maxICERetries }, time.Second, 20*time.Millisecond,
		"an exhausted budget must leave the guard waiting for the hourly retry")
}

// TestGuard_RenegotiationLeavesHourlyRetry covers a renegotiation that fails
// after following a remote restart, with no other transport up. The guard
// keeps its spent budget, but must retry the now disconnected peer on the
// regular schedule instead of after the hourly wait.
func TestGuard_RenegotiationLeavesHourlyRetry(t *testing.T) {
	status := newStatus(ConnStatusPartiallyConnected)
	g, offers := startCountingGuard(t, status)
	requireHourlyRetry(t, offers)

	status.set(ConnStatusDisconnected)
	g.SetICEConnRenegotiating()

	assert.Eventually(t, func() bool { return offers.Load() > maxICERetries }, 5*time.Second, 20*time.Millisecond,
		"a disconnected peer must be retried without waiting for the hourly retry")
}

// TestGuard_RenegotiationKeepsSpentBudget covers renegotiations that succeed:
// the peer stays partially connected, and the spent budget must stay spent.
func TestGuard_RenegotiationKeepsSpentBudget(t *testing.T) {
	status := newStatus(ConnStatusPartiallyConnected)
	g, offers := startCountingGuard(t, status)
	requireHourlyRetry(t, offers)

	for range 3 {
		g.SetICEConnRenegotiating()
		time.Sleep(1500 * time.Millisecond)
	}

	assert.Equal(t, int32(maxICERetries), offers.Load(), "renegotiations must not refill the retry budget")
}

// TestGuard_ICEDisconnectRefillsRetryBudget pins that a plain ICE disconnect
// still gives the peer a fresh budget.
func TestGuard_ICEDisconnectRefillsRetryBudget(t *testing.T) {
	status := newStatus(ConnStatusPartiallyConnected)
	g, offers := startCountingGuard(t, status)
	requireHourlyRetry(t, offers)

	g.SetICEConnDisconnected()

	assert.Eventually(t, func() bool { return offers.Load() == 2*maxICERetries }, 10*time.Second, 20*time.Millisecond,
		"an ICE disconnect must refill the retry budget")
}
