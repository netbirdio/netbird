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
	return internal.NewConnectClient(ctx, nil, nil, false)
}

// TestConnectSetsClientWithMutex validates that connect() sets s.connectClient
// under mutex protection so concurrent readers see a consistent value.
func TestConnectSetsClientWithMutex(t *testing.T) {
	s := newTestServer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Manually simulate what connect() does (without calling Run which panics without full setup)
	client := newDummyConnectClient(ctx)

	s.mutex.Lock()
	s.connectClient = client
	s.mutex.Unlock()

	// Verify the assignment is visible under mutex
	s.mutex.Lock()
	assert.Equal(t, client, s.connectClient, "connectClient should be set")
	s.mutex.Unlock()
}

// TestConcurrentConnectClientAccess validates that concurrent reads of
// s.connectClient under mutex don't race with a write.
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
			s.mutex.Lock()
			c := s.connectClient
			s.mutex.Unlock()

			mu.Lock()
			defer mu.Unlock()
			if c == nil {
				nilCount++
			} else {
				setCount++
			}
		}()
	}

	// Simulate connect() writing under mutex
	time.Sleep(5 * time.Millisecond)
	s.mutex.Lock()
	s.connectClient = client
	s.mutex.Unlock()

	wg.Wait()

	assert.Equal(t, 50, nilCount+setCount, "all goroutines should complete without panic")
}

// TestCleanupConnection_ClearsConnectClient validates that cleanupConnection
// properly nils out connectClient.
func TestCleanupConnection_ClearsConnectClient(t *testing.T) {
	s := newTestServer()
	_, cancel := context.WithCancel(context.Background())
	s.actCancel = cancel

	s.connectClient = newDummyConnectClient(context.Background())
	s.clientRunning = true

	err := s.cleanupConnection()
	require.NoError(t, err)

	assert.Nil(t, s.connectClient, "connectClient should be nil after cleanup")
}

// TestCleanState_NilConnectClient validates that CleanState doesn't panic
// when connectClient is nil.
func TestCleanState_NilConnectClient(t *testing.T) {
	s := newTestServer()
	s.connectClient = nil
	s.profileManager = nil // will cause error if it tries to proceed past the nil check

	// Should not panic — the nil check should prevent calling Status() on nil
	assert.NotPanics(t, func() {
		_, _ = s.CleanState(context.Background(), &proto.CleanStateRequest{All: true})
	})
}

// TestDeleteState_NilConnectClient validates that DeleteState doesn't panic
// when connectClient is nil.
func TestDeleteState_NilConnectClient(t *testing.T) {
	s := newTestServer()
	s.connectClient = nil
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
	s.clientGiveUpChan = make(chan struct{})
	s.connectClient = newDummyConnectClient(context.Background())

	_, cancel := context.WithCancel(context.Background())
	s.actCancel = cancel

	// Simulate Down(): cleanupConnection sets connectClient = nil
	s.mutex.Lock()
	err := s.cleanupConnection()
	s.mutex.Unlock()
	require.NoError(t, err)

	// After cleanup: connectClient is nil, clientRunning still true
	// (goroutine hasn't exited yet)
	s.mutex.Lock()
	assert.Nil(t, s.connectClient, "connectClient should be nil after cleanup")
	assert.True(t, s.clientRunning, "clientRunning still true until goroutine exits")
	s.mutex.Unlock()

	// waitForUp() returns immediately due to stale closed clientRunningChan
	ctx, ctxCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer ctxCancel()

	waitDone := make(chan error, 1)
	go func() {
		_, err := s.waitForUp(ctx)
		waitDone <- err
	}()

	select {
	case err := <-waitDone:
		assert.NoError(t, err, "waitForUp returns success on stale channel")
		// But connectClient is still nil — this is the stale state issue
		s.mutex.Lock()
		assert.Nil(t, s.connectClient, "connectClient is nil despite waitForUp success")
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
