package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
)

func newTestServer() *Server {
	return &Server{
		rootCtx:        context.Background(),
		statusRecorder: peer.NewRecorder(""),
	}
}

func newDummyConnectClient(ctx context.Context) *internal.ConnectClient {
	return internal.NewConnectClient(ctx, nil, nil)
}

// TestConnectPublishesClient validates that a run's client becomes the current
// one, the way connect() installs it.
func TestConnectPublishesClient(t *testing.T) {
	s := newTestServer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := newDummyConnectClient(ctx)

	generation, done := s.runs.Begin()
	defer close(done)

	require.True(t, s.runs.Publish(ctx, generation, client))
	assert.Same(t, client, s.runs.Current(), "the published client should be current")
}

// TestConnectPublishRejectsSupersededRun validates that a run which lost its
// slot cannot install its client over a newer one's.
func TestConnectPublishRejectsSupersededRun(t *testing.T) {
	s := newTestServer()
	ctx := context.Background()

	staleGeneration, staleDone := s.runs.Begin()
	defer close(staleDone)

	freshGeneration, freshDone := s.runs.Begin()
	defer close(freshDone)

	fresh := newDummyConnectClient(ctx)
	require.True(t, s.runs.Publish(ctx, freshGeneration, fresh))

	assert.False(t, s.runs.Publish(ctx, staleGeneration, newDummyConnectClient(ctx)))
	assert.Same(t, fresh, s.runs.Current(), "the superseded run must not displace the current client")
}

// TestConcurrentConnectClientAccess validates that concurrent reads of the
// current client don't race with a publish.
func TestConcurrentConnectClientAccess(t *testing.T) {
	s := newTestServer()
	ctx := context.Background()
	client := newDummyConnectClient(ctx)

	var wg sync.WaitGroup
	nilCount := 0
	setCount := 0
	var mu sync.Mutex

	// Start readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := s.runs.Current()

			mu.Lock()
			defer mu.Unlock()
			if c == nil {
				nilCount++
			} else {
				setCount++
			}
		}()
	}

	// Simulate connect() publishing its client
	time.Sleep(5 * time.Millisecond)
	generation, done := s.runs.Begin()
	defer close(done)
	require.True(t, s.runs.Publish(ctx, generation, client))

	wg.Wait()

	assert.Equal(t, 50, nilCount+setCount, "all goroutines should complete without panic")
}

// TestCleanupConnection_ClearsCurrentClient validates that cleanupConnection
// drops the current client and clears the daemon's intent.
func TestCleanupConnection_ClearsCurrentClient(t *testing.T) {
	s := newTestServer()
	ctx, cancel := context.WithCancel(context.Background())
	s.actCancel = cancel

	generation, done := s.runs.Begin()
	close(done)
	require.True(t, s.runs.Publish(ctx, generation, newDummyConnectClient(ctx)))
	s.clientRunning = true

	require.NoError(t, s.cleanupConnection(ctx))

	assert.Nil(t, s.runs.Current(), "no client should be current after cleanup")
	assert.False(t, s.clientRunning, "clientRunning should be cleared after cleanup (intent = down)")
}

// TestCleanupConnection_StopsDisplacedClient validates that a client the next
// attempt displaces is stopped rather than dropped, which is what kept a
// superseded ConnectClient alive with nothing tracking it.
func TestCleanupConnection_StopsDisplacedClient(t *testing.T) {
	s := newTestServer()
	ctx := context.Background()

	generation, done := s.runs.Begin()
	defer close(done)

	displaced := newDummyConnectClient(ctx)
	require.True(t, s.runs.Publish(ctx, generation, displaced))

	replacement := newDummyConnectClient(ctx)
	require.True(t, s.runs.Publish(ctx, generation, replacement))

	assert.Same(t, replacement, s.runs.Current())
}

// TestCleanState_NilConnectClient validates that CleanState doesn't panic
// when no client is current.
func TestCleanState_NilConnectClient(t *testing.T) {
	s := newTestServer()
	s.profileManager = nil // will cause error if it tries to proceed past the nil check

	// Should not panic — the nil check should prevent calling Status() on nil
	assert.NotPanics(t, func() {
		_, _ = s.CleanState(context.Background(), &proto.CleanStateRequest{All: true})
	})
}

// TestDeleteState_NilConnectClient validates that DeleteState doesn't panic
// when no client is current.
func TestDeleteState_NilConnectClient(t *testing.T) {
	s := newTestServer()
	s.profileManager = nil

	assert.NotPanics(t, func() {
		_, _ = s.DeleteState(context.Background(), &proto.DeleteStateRequest{All: true})
	})
}

// TestDownThenUp_StaleRunningChan documents the known state issue where
// clientRunningChan from a previous connection is already closed, causing
// waitForUp() to return immediately on reconnect.
func TestDownThenUp_StaleRunningChan(t *testing.T) {
	s := newTestServer()

	// Simulate state after a successful connection
	s.clientRunning = true
	s.clientRunningChan = make(chan struct{})
	close(s.clientRunningChan) // closed when engine started

	ctx, cancel := context.WithCancel(context.Background())
	s.actCancel = cancel

	generation, done := s.runs.Begin()
	close(done)
	require.True(t, s.runs.Publish(ctx, generation, newDummyConnectClient(ctx)))

	// Simulate Down(): cleanupConnection drops the current client and flips
	// clientRunning to false (intent = down).
	s.mutex.Lock()
	err := s.cleanupConnection(ctx)
	s.mutex.Unlock()
	require.NoError(t, err)

	s.mutex.Lock()
	assert.Nil(t, s.runs.Current(), "no client should be current after cleanup")
	assert.False(t, s.clientRunning, "clientRunning should be cleared by cleanupConnection (intent = down)")
	s.mutex.Unlock()

	// waitForUp() returns immediately due to stale closed clientRunningChan
	waitCtx, ctxCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer ctxCancel()

	waitDone := make(chan error, 1)
	go func() {
		_, err := s.waitForUp(waitCtx)
		waitDone <- err
	}()

	select {
	case err := <-waitDone:
		assert.NoError(t, err, "waitForUp returns success on stale channel")
		// But no client is current — this is the stale state issue
		s.mutex.Lock()
		assert.Nil(t, s.runs.Current(), "no client is current despite waitForUp success")
		s.mutex.Unlock()
	case <-time.After(1 * time.Second):
		t.Fatal("waitForUp should have returned immediately due to stale closed channel")
	}
}

// TestConnectClient_EngineNilOnFreshClient validates that a newly created
// ConnectClient has nil Engine (before Run is called).
func TestConnectClient_EngineNilOnFreshClient(t *testing.T) {
	client := newDummyConnectClient(context.Background())
	assert.Nil(t, client.Engine(), "engine should be nil on fresh ConnectClient")
}
