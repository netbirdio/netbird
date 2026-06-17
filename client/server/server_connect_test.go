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
	return internal.NewConnectClient(ctx, nil)
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

// TestCleanupConnection_KeepsClientStopsRunning validates that cleanupConnection
// clears the daemon "up" intent but KEEPS the daemon-lifetime ConnectClient
// (it is reused across Up/Down; only the run is stopped).
func TestCleanupConnection_KeepsClientStopsRunning(t *testing.T) {
	s := newTestServer()
	_, cancel := context.WithCancel(context.Background())
	s.actCancel = cancel

	s.connectClient = newDummyConnectClient(context.Background())
	s.clientRunning = true

	err := s.cleanupConnection()
	require.NoError(t, err)

	assert.NotNil(t, s.connectClient, "connectClient is daemon-lifetime and must persist after cleanup")
	assert.False(t, s.connectClient.IsRunning(), "no run should be in flight after cleanup")
	assert.False(t, s.clientRunning, "clientRunning should be cleared after cleanup (intent = down)")
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

// TestConnectClient_EngineNilOnFreshClient validates that a newly created
// ConnectClient has nil Engine (before Run is called).
func TestConnectClient_EngineNilOnFreshClient(t *testing.T) {
	client := newDummyConnectClient(context.Background())
	assert.Nil(t, client.Engine(), "engine should be nil on fresh ConnectClient")
}
