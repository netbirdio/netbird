//go:build linux && !android

package conntrack

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	nfct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

type mockListener struct {
	errChan  chan error
	closed   atomic.Bool
	closedCh chan struct{}
}

func newMockListener() *mockListener {
	return &mockListener{
		errChan:  make(chan error, 1),
		closedCh: make(chan struct{}),
	}
}

func (m *mockListener) Listen(evChan chan<- nfct.Event, _ uint8, _ []netfilter.NetlinkGroup) (chan error, error) {
	return m.errChan, nil
}

func (m *mockListener) Close() error {
	if m.closed.CompareAndSwap(false, true) {
		close(m.closedCh)
	}
	return nil
}

func TestReconnectAfterError(t *testing.T) {
	first := newMockListener()
	second := newMockListener()
	third := newMockListener()
	listeners := []*mockListener{first, second, third}
	callCount := atomic.Int32{}

	ct := New(nil, nil, WithDialer(func() (listener, error) {
		n := int(callCount.Add(1)) - 1
		return listeners[n], nil
	}))

	err := ct.Start(false)
	require.NoError(t, err)

	// Inject an error on the first listener.
	first.errChan <- assert.AnError

	// Wait for reconnect to complete.
	require.Eventually(t, func() bool {
		return callCount.Load() >= 2
	}, 15*time.Second, 100*time.Millisecond, "reconnect should dial a new connection")

	// The first connection must have been closed.
	select {
	case <-first.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("first connection was not closed")
	}

	// Verify the receiver is still running by injecting and handling a second error.
	second.errChan <- assert.AnError

	require.Eventually(t, func() bool {
		return callCount.Load() >= 3
	}, 15*time.Second, 100*time.Millisecond, "second reconnect should succeed")

	ct.Stop()
}

func TestStopDuringReconnectBackoff(t *testing.T) {
	mock := newMockListener()

	ct := New(nil, nil, WithDialer(func() (listener, error) {
		return mock, nil
	}))

	err := ct.Start(false)
	require.NoError(t, err)

	// Trigger an error so the receiver enters reconnect.
	mock.errChan <- assert.AnError

	// Wait for the error handler to close the old listener before calling Stop.
	select {
	case <-mock.closedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for reconnect to start")
	}

	// Stop while reconnecting.
	ct.Stop()

	ct.mux.Lock()
	assert.False(t, ct.started, "started should be false after Stop")
	assert.Nil(t, ct.conn, "conn should be nil after Stop")
	ct.mux.Unlock()
}

func TestStopRaceWithReconnectDial(t *testing.T) {
	first := newMockListener()
	dialStarted := make(chan struct{})
	dialProceed := make(chan struct{})
	second := newMockListener()
	callCount := atomic.Int32{}

	ct := New(nil, nil, WithDialer(func() (listener, error) {
		n := callCount.Add(1)
		if n == 1 {
			return first, nil
		}
		// Second dial: signal that we're in progress, wait for test to call Stop.
		close(dialStarted)
		<-dialProceed
		return second, nil
	}))

	err := ct.Start(false)
	require.NoError(t, err)

	// Trigger error to enter reconnect.
	first.errChan <- assert.AnError

	// Wait for reconnect's second dial to begin.
	select {
	case <-dialStarted:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for reconnect dial")
	}

	// Stop while dial is in progress (conn is nil at this point).
	ct.Stop()

	// Let the dial complete. reconnect should detect started==false and close the new conn.
	close(dialProceed)

	// The second connection should be closed (not leaked).
	select {
	case <-second.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("second connection was leaked after Stop")
	}

	ct.mux.Lock()
	assert.False(t, ct.started)
	assert.Nil(t, ct.conn)
	ct.mux.Unlock()
}

func TestCloseRaceWithReconnectDial(t *testing.T) {
	first := newMockListener()
	dialStarted := make(chan struct{})
	dialProceed := make(chan struct{})
	second := newMockListener()
	callCount := atomic.Int32{}

	ct := New(nil, nil, WithDialer(func() (listener, error) {
		n := callCount.Add(1)
		if n == 1 {
			return first, nil
		}
		close(dialStarted)
		<-dialProceed
		return second, nil
	}))

	err := ct.Start(false)
	require.NoError(t, err)

	first.errChan <- assert.AnError

	select {
	case <-dialStarted:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for reconnect dial")
	}

	// Close while dial is in progress (conn is nil).
	require.NoError(t, ct.Close())

	close(dialProceed)

	// The second connection should be closed (not leaked).
	select {
	case <-second.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("second connection was leaked after Close")
	}

	ct.mux.Lock()
	assert.False(t, ct.started)
	assert.Nil(t, ct.conn)
	ct.mux.Unlock()
}

func TestStartIsIdempotent(t *testing.T) {
	mock := newMockListener()
	callCount := atomic.Int32{}

	ct := New(nil, nil, WithDialer(func() (listener, error) {
		callCount.Add(1)
		return mock, nil
	}))

	err := ct.Start(false)
	require.NoError(t, err)

	// Second Start should be a no-op.
	err = ct.Start(false)
	require.NoError(t, err)

	assert.Equal(t, int32(1), callCount.Load(), "dial should only be called once")

	ct.Stop()
}
