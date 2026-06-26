package roundtrip

import (
	"context"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type mockMgmtClient struct{}

func (m *mockMgmtClient) CreateProxyPeer(_ context.Context, _ *proto.CreateProxyPeerRequest, _ ...grpc.CallOption) (*proto.CreateProxyPeerResponse, error) {
	return &proto.CreateProxyPeerResponse{Success: true}, nil
}

// signalMgmtClient closes entered the first time CreateProxyPeer is called, so
// tests can detect AddPeer reaching client creation.
type signalMgmtClient struct {
	entered chan struct{}
	once    sync.Once
}

func (m *signalMgmtClient) CreateProxyPeer(_ context.Context, _ *proto.CreateProxyPeerRequest, _ ...grpc.CallOption) (*proto.CreateProxyPeerResponse, error) {
	m.once.Do(func() { close(m.entered) })
	return &proto.CreateProxyPeerResponse{Success: true}, nil
}

type mockStatusNotifier struct {
	mu       sync.Mutex
	statuses []statusCall
}

type statusCall struct {
	accountID types.AccountID
	serviceID types.ServiceID
	connected bool
	// ctx is captured so tests can assert the notifier received a
	// fresh background context rather than an inherited request ctx.
	ctx context.Context
}

func (m *mockStatusNotifier) NotifyStatus(ctx context.Context, accountID types.AccountID, serviceID types.ServiceID, connected bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses = append(m.statuses, statusCall{accountID, serviceID, connected, ctx})
	return nil
}

func (m *mockStatusNotifier) calls() []statusCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]statusCall{}, m.statuses...)
}

// mockNetBird creates a NetBird instance for testing without actually connecting.
// It uses an invalid management URL to prevent real connections.
func mockNetBird() *NetBird {
	nb := NewNetBird(context.Background(), "test-proxy", "invalid.test", ClientConfig{
		MgmtAddr:     "http://invalid.test:9999",
		WGPort:       0,
		PreSharedKey: "",
	}, nil, nil, &mockMgmtClient{})
	// Skip the real embed client.Start, which would hang against the unreachable
	// mgmt URL and (now that the lifecycle lock spans startup) serialise removes.
	nb.startClient = func(types.AccountID, *embed.Client) {}
	return nb
}

func TestNetBird_AddPeer_CreatesClientForNewAccount(t *testing.T) {
	nb := mockNetBird()
	accountID := types.AccountID("account-1")

	// Initially no client exists.
	assert.False(t, nb.HasClient(accountID), "should not have client before AddPeer")
	assert.Equal(t, 0, nb.ServiceCount(accountID), "service count should be 0")

	// Add first service - this should create a new client.
	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "setup-key-1", types.ServiceID("proxy-1"))
	require.NoError(t, err)

	assert.True(t, nb.HasClient(accountID), "should have client after AddPeer")
	assert.Equal(t, 1, nb.ServiceCount(accountID), "service count should be 1")
}

func TestNetBird_AddPeer_ReuseClientForSameAccount(t *testing.T) {
	nb := mockNetBird()
	accountID := types.AccountID("account-1")

	// Add first service.
	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "setup-key-1", types.ServiceID("proxy-1"))
	require.NoError(t, err)
	assert.Equal(t, 1, nb.ServiceCount(accountID))

	// Add second service for the same account - should reuse existing client.
	err = nb.AddPeer(context.Background(), accountID, "domain2.test", "setup-key-1", types.ServiceID("proxy-2"))
	require.NoError(t, err)
	assert.Equal(t, 2, nb.ServiceCount(accountID), "service count should be 2 after adding second service")

	// Add third service.
	err = nb.AddPeer(context.Background(), accountID, "domain3.test", "setup-key-1", types.ServiceID("proxy-3"))
	require.NoError(t, err)
	assert.Equal(t, 3, nb.ServiceCount(accountID), "service count should be 3 after adding third service")

	// Still only one client.
	assert.True(t, nb.HasClient(accountID))
}

func TestNetBird_AddPeer_SeparateClientsForDifferentAccounts(t *testing.T) {
	nb := mockNetBird()
	account1 := types.AccountID("account-1")
	account2 := types.AccountID("account-2")

	// Add service for account 1.
	err := nb.AddPeer(context.Background(), account1, "domain1.test", "setup-key-1", types.ServiceID("proxy-1"))
	require.NoError(t, err)

	// Add service for account 2.
	err = nb.AddPeer(context.Background(), account2, "domain2.test", "setup-key-2", types.ServiceID("proxy-2"))
	require.NoError(t, err)

	// Both accounts should have their own clients.
	assert.True(t, nb.HasClient(account1), "account1 should have client")
	assert.True(t, nb.HasClient(account2), "account2 should have client")
	assert.Equal(t, 1, nb.ServiceCount(account1), "account1 service count should be 1")
	assert.Equal(t, 1, nb.ServiceCount(account2), "account2 service count should be 1")
}

func TestNetBird_RemovePeer_KeepsClientWhenServicesRemain(t *testing.T) {
	nb := mockNetBird()
	accountID := types.AccountID("account-1")

	// Add multiple services.
	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "setup-key-1", types.ServiceID("proxy-1"))
	require.NoError(t, err)
	err = nb.AddPeer(context.Background(), accountID, "domain2.test", "setup-key-1", types.ServiceID("proxy-2"))
	require.NoError(t, err)
	err = nb.AddPeer(context.Background(), accountID, "domain3.test", "setup-key-1", types.ServiceID("proxy-3"))
	require.NoError(t, err)
	assert.Equal(t, 3, nb.ServiceCount(accountID))

	// Remove one service - client should remain.
	err = nb.RemovePeer(context.Background(), accountID, "domain1.test")
	require.NoError(t, err)
	assert.True(t, nb.HasClient(accountID), "client should remain after removing one service")
	assert.Equal(t, 2, nb.ServiceCount(accountID), "service count should be 2")

	// Remove another service - client should still remain.
	err = nb.RemovePeer(context.Background(), accountID, "domain2.test")
	require.NoError(t, err)
	assert.True(t, nb.HasClient(accountID), "client should remain after removing second service")
	assert.Equal(t, 1, nb.ServiceCount(accountID), "service count should be 1")
}

func TestNetBird_RemovePeer_RemovesClientWhenLastServiceRemoved(t *testing.T) {
	nb := mockNetBird()
	accountID := types.AccountID("account-1")

	// Add single service.
	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "setup-key-1", types.ServiceID("proxy-1"))
	require.NoError(t, err)
	assert.True(t, nb.HasClient(accountID))

	// Remove the only service - client should be removed.
	_ = nb.RemovePeer(context.Background(), accountID, "domain1.test")

	// After removing all services, client should be gone.
	assert.False(t, nb.HasClient(accountID), "client should be removed after removing last service")
	assert.Equal(t, 0, nb.ServiceCount(accountID), "service count should be 0")
}

func TestNetBird_RemovePeer_NonExistentAccountIsNoop(t *testing.T) {
	nb := mockNetBird()
	accountID := types.AccountID("nonexistent-account")

	// Removing from non-existent account should not error.
	err := nb.RemovePeer(context.Background(), accountID, "domain1.test")
	assert.NoError(t, err, "removing from non-existent account should not error")
}

func TestNetBird_RemovePeer_NonExistentServiceIsNoop(t *testing.T) {
	nb := mockNetBird()
	accountID := types.AccountID("account-1")

	// Add one service.
	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "setup-key-1", types.ServiceID("proxy-1"))
	require.NoError(t, err)

	// Remove non-existent service - should not affect existing service.
	err = nb.RemovePeer(context.Background(), accountID, "nonexistent.test")
	require.NoError(t, err)

	// Original service should still be registered.
	assert.True(t, nb.HasClient(accountID))
	assert.Equal(t, 1, nb.ServiceCount(accountID), "original service should remain")
}

func TestWithAccountID_AndAccountIDFromContext(t *testing.T) {
	ctx := context.Background()
	accountID := types.AccountID("test-account")

	// Initially no account ID in context.
	retrieved := AccountIDFromContext(ctx)
	assert.True(t, retrieved == "", "should be empty when not set")

	// Add account ID to context.
	ctx = WithAccountID(ctx, accountID)
	retrieved = AccountIDFromContext(ctx)
	assert.Equal(t, accountID, retrieved, "should retrieve the same account ID")
}

func TestAccountIDFromContext_ReturnsEmptyForWrongType(t *testing.T) {
	// Create context with wrong type for account ID key.
	ctx := context.WithValue(context.Background(), accountIDContextKey{}, "wrong-type-string")

	retrieved := AccountIDFromContext(ctx)
	assert.True(t, retrieved == "", "should return empty for wrong type")
}

func TestNetBird_StopAll_StopsAllClients(t *testing.T) {
	nb := mockNetBird()
	account1 := types.AccountID("account-1")
	account2 := types.AccountID("account-2")
	account3 := types.AccountID("account-3")

	// Add services for multiple accounts.
	err := nb.AddPeer(context.Background(), account1, "domain1.test", "key-1", types.ServiceID("proxy-1"))
	require.NoError(t, err)
	err = nb.AddPeer(context.Background(), account2, "domain2.test", "key-2", types.ServiceID("proxy-2"))
	require.NoError(t, err)
	err = nb.AddPeer(context.Background(), account3, "domain3.test", "key-3", types.ServiceID("proxy-3"))
	require.NoError(t, err)

	assert.Equal(t, 3, nb.ClientCount(), "should have 3 clients")

	// Stop all clients.
	_ = nb.StopAll(context.Background())

	assert.Equal(t, 0, nb.ClientCount(), "should have 0 clients after StopAll")
	assert.False(t, nb.HasClient(account1), "account1 should not have client")
	assert.False(t, nb.HasClient(account2), "account2 should not have client")
	assert.False(t, nb.HasClient(account3), "account3 should not have client")
}

func TestNetBird_ClientCount(t *testing.T) {
	nb := mockNetBird()

	assert.Equal(t, 0, nb.ClientCount(), "should start with 0 clients")

	// Add clients for different accounts.
	err := nb.AddPeer(context.Background(), types.AccountID("account-1"), "domain1.test", "key-1", types.ServiceID("proxy-1"))
	require.NoError(t, err)
	assert.Equal(t, 1, nb.ClientCount())

	err = nb.AddPeer(context.Background(), types.AccountID("account-2"), "domain2.test", "key-2", types.ServiceID("proxy-2"))
	require.NoError(t, err)
	assert.Equal(t, 2, nb.ClientCount())

	// Adding service to existing account should not increase count.
	err = nb.AddPeer(context.Background(), types.AccountID("account-1"), "domain1b.test", "key-1", types.ServiceID("proxy-1b"))
	require.NoError(t, err)
	assert.Equal(t, 2, nb.ClientCount(), "adding service to existing account should not increase client count")
}

func TestNetBird_RoundTrip_RequiresAccountIDInContext(t *testing.T) {
	nb := mockNetBird()

	// Create a request without account ID in context.
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	require.NoError(t, err)

	// RoundTrip should fail because no account ID in context.
	_, err = nb.RoundTrip(req) //nolint:bodyclose
	require.ErrorIs(t, err, ErrNoAccountID)
}

func TestNetBird_RoundTrip_RequiresExistingClient(t *testing.T) {
	nb := mockNetBird()
	accountID := types.AccountID("nonexistent-account")

	// Create a request with account ID but no client exists.
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	require.NoError(t, err)
	req = req.WithContext(WithAccountID(req.Context(), accountID))

	// RoundTrip should fail because no client for this account.
	_, err = nb.RoundTrip(req) //nolint:bodyclose // Error case, no response body
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no peer connection found for account")
}

func TestNetBird_AddPeer_ExistingStartedClient_NotifiesStatus(t *testing.T) {
	notifier := &mockStatusNotifier{}
	nb := NewNetBird(context.Background(), "test-proxy", "invalid.test", ClientConfig{
		MgmtAddr:     "http://invalid.test:9999",
		WGPort:       0,
		PreSharedKey: "",
	}, nil, notifier, &mockMgmtClient{})
	nb.startClient = func(types.AccountID, *embed.Client) {}
	accountID := types.AccountID("account-1")

	// Add first service — creates a new client entry.
	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "key-1", types.ServiceID("svc-1"))
	require.NoError(t, err)

	// Manually mark client as started to simulate background startup completing.
	nb.clientsMux.Lock()
	nb.clients[accountID].started = true
	nb.clientsMux.Unlock()

	// Add second service with an already-cancelled caller context —
	// should notify immediately (client is started) AND the notification
	// must not inherit the cancelled ctx.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	err = nb.AddPeer(cancelledCtx, accountID, "domain2.test", "key-1", types.ServiceID("svc-2"))
	require.NoError(t, err)

	calls := notifier.calls()
	require.Len(t, calls, 1)
	assert.Equal(t, accountID, calls[0].accountID)
	assert.Equal(t, types.ServiceID("svc-2"), calls[0].serviceID)
	assert.True(t, calls[0].connected)
	require.NotNil(t, calls[0].ctx, "NotifyStatus must receive a context")
	require.NoError(t, calls[0].ctx.Err(),
		"already-started NotifyStatus must use a background ctx, not the cancelled caller ctx")
}

// TestNetBird_IdentityForIP_UnknownAccountReturnsFalse confirms that the
// public lookup short-circuits when no client has been registered for
// the queried account. The auth middleware uses ok=false as a fast deny.
func TestNetBird_IdentityForIP_UnknownAccountReturnsFalse(t *testing.T) {
	nb := mockNetBird()
	_, _, ok := nb.IdentityForIP("acct-missing", netip.MustParseAddr("100.64.0.10"))
	assert.False(t, ok, "unknown account must yield ok=false")
}

// TestClientEntry_IdentityForIP_NilClientGuard ensures the receiver
// methods stay safe when called on partially-initialized state, which
// can happen briefly during AddPeer setup or test fixtures.
func TestClientEntry_IdentityForIP_NilClientGuard(t *testing.T) {
	var e *clientEntry
	_, _, ok := e.IdentityForIP(netip.MustParseAddr("100.64.0.10"))
	assert.False(t, ok, "nil clientEntry must yield ok=false")

	e = &clientEntry{}
	_, _, ok = e.IdentityForIP(netip.MustParseAddr("100.64.0.10"))
	assert.False(t, ok, "clientEntry with nil embed.Client must yield ok=false")
}

// TestClientEntry_IdentityForIP_InvalidIPReturnsFalse covers the input
// guard so callers don't have to repeat the check.
func TestClientEntry_IdentityForIP_InvalidIPReturnsFalse(t *testing.T) {
	e := &clientEntry{}
	_, _, ok := e.IdentityForIP(netip.Addr{})
	assert.False(t, ok, "invalid IP must yield ok=false")
}

func TestNetBird_RemovePeer_NotifiesDisconnection(t *testing.T) {
	notifier := &mockStatusNotifier{}
	nb := NewNetBird(context.Background(), "test-proxy", "invalid.test", ClientConfig{
		MgmtAddr:     "http://invalid.test:9999",
		WGPort:       0,
		PreSharedKey: "",
	}, nil, notifier, &mockMgmtClient{})
	accountID := types.AccountID("account-1")

	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "key-1", types.ServiceID("svc-1"))
	require.NoError(t, err)
	err = nb.AddPeer(context.Background(), accountID, "domain2.test", "key-1", types.ServiceID("svc-2"))
	require.NoError(t, err)

	// Remove one service — client stays, but disconnection notification fires.
	err = nb.RemovePeer(context.Background(), accountID, "domain1.test")
	require.NoError(t, err)
	assert.True(t, nb.HasClient(accountID))

	calls := notifier.calls()
	require.Len(t, calls, 1)
	assert.Equal(t, types.ServiceID("svc-1"), calls[0].serviceID)
	assert.False(t, calls[0].connected)
}

// TestNetBird_RemovePeer_TeardownIsAsync proves the fix for the receive-loop
// stall: RemovePeer must return promptly even when the client teardown blocks,
// because teardown runs off the caller's goroutine. The receive loop calls
// RemovePeer synchronously, so a blocking teardown inline would wedge it.
func TestNetBird_RemovePeer_TeardownIsAsync(t *testing.T) {
	nb := NewNetBird(context.Background(), "test-proxy", "invalid.test", ClientConfig{
		MgmtAddr: "http://invalid.test:9999",
	}, nil, &mockStatusNotifier{}, &mockMgmtClient{})

	accountID := types.AccountID("acct-async-teardown")
	key := DomainServiceKey("svc.example")

	teardownEntered := make(chan struct{})
	releaseTeardown := make(chan struct{})
	nb.SetClientLifecycle(nil, func(types.AccountID, any) {
		close(teardownEntered)
		<-releaseTeardown
	})

	nb.clientsMux.Lock()
	nb.clients[accountID] = &clientEntry{
		services: map[ServiceKey]serviceInfo{key: {serviceID: types.ServiceID("svc-1")}},
		started:  true,
		inbound:  struct{}{},
	}
	nb.clientsMux.Unlock()

	done := make(chan error, 1)
	go func() { done <- nb.RemovePeer(context.Background(), accountID, key) }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("RemovePeer did not return while teardown was blocked — teardown is not async")
	}

	select {
	case <-teardownEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("teardown never ran")
	}

	close(releaseTeardown)
}

// TestNetBird_AddPeer_WaitsForTeardown proves the lifecycle lock serialises a
// new client bringup behind an in-flight teardown for the same account, so a
// slow client.Stop can never race a new client.Start for that account.
//
// It targets the handoff race specifically: AddPeer is launched immediately
// after RemovePeer returns, WITHOUT waiting for the teardown goroutine to start.
// This only passes if RemovePeer acquires the lifecycle lock synchronously
// (before returning) and hands it to the teardown goroutine — if the goroutine
// acquired the lock itself, AddPeer could win the lock in this window and start
// a replacement client while the old teardown is still pending.
func TestNetBird_AddPeer_WaitsForTeardown(t *testing.T) {
	nb := NewNetBird(context.Background(), "test-proxy", "invalid.test", ClientConfig{
		MgmtAddr: "http://invalid.test:9999",
	}, nil, &mockStatusNotifier{}, &mockMgmtClient{})
	nb.startClient = func(types.AccountID, *embed.Client) {}

	accountID := types.AccountID("acct-serialize")
	key := DomainServiceKey("svc.example")

	addEntered := make(chan struct{})
	releaseTeardown := make(chan struct{})
	nb.SetClientLifecycle(nil, func(types.AccountID, any) {
		// Block teardown until released. If AddPeer ever reaches createClientEntry
		// (signalled via the mgmt client below) while we hold the lock, the lock
		// failed to serialise and the test fails before we release.
		<-releaseTeardown
	})

	nb.clientsMux.Lock()
	nb.clients[accountID] = &clientEntry{
		services: map[ServiceKey]serviceInfo{key: {serviceID: types.ServiceID("svc-1")}},
		started:  true,
		inbound:  struct{}{},
	}
	nb.clientsMux.Unlock()

	// createClientEntry calls CreateProxyPeer; closing addEntered there tells us
	// AddPeer got past the lifecycle lock and into client creation.
	nb.mgmtClient = &signalMgmtClient{entered: addEntered}

	require.NoError(t, nb.RemovePeer(context.Background(), accountID, key))

	// Launch AddPeer with NO synchronisation against the teardown goroutine.
	addReturned := make(chan struct{})
	go func() {
		_ = nb.AddPeer(context.Background(), accountID, DomainServiceKey("svc2.example"), "key-2", types.ServiceID("svc-2"))
		close(addReturned)
	}()

	select {
	case <-addEntered:
		t.Fatal("AddPeer entered client creation while teardown held the lifecycle lock — handoff race not closed")
	case <-addReturned:
		t.Fatal("AddPeer completed while teardown held the lifecycle lock — not serialised")
	case <-time.After(300 * time.Millisecond):
	}

	close(releaseTeardown)
	select {
	case <-addReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("AddPeer never completed after teardown released the lifecycle lock")
	}
}

// TestNotifyClientReady_UsesBackgroundCtx pins the contract that the
// post-Start hooks (readyHandler + statusNotifier.NotifyStatus) run on
// a fresh context.Background() rather than inheriting the AddPeer
// caller's request- or stream-scoped ctx. Without this, a cancelled
// caller ctx could abort the inbound listener bring-up or cause the
// management status notification to fail spuriously and leave the
// account in a half-connected state.
func TestNotifyClientReady_UsesBackgroundCtx(t *testing.T) {
	notifier := &mockStatusNotifier{}
	nb := NewNetBird(context.Background(), "test-proxy", "invalid.test", ClientConfig{
		MgmtAddr: "http://invalid.test:9999",
	}, nil, notifier, &mockMgmtClient{})

	accountID := types.AccountID("acct-async")
	// Pre-populate a client entry so notifyClientReady has something
	// to mark started + something to enumerate for NotifyStatus.
	nb.clientsMux.Lock()
	nb.clients[accountID] = &clientEntry{
		services: map[ServiceKey]serviceInfo{
			DomainServiceKey("svc.example"): {serviceID: types.ServiceID("svc-1")},
		},
	}
	nb.clientsMux.Unlock()

	var capturedReadyCtx context.Context
	nb.SetClientLifecycle(
		func(ctx context.Context, _ types.AccountID, _ *embed.Client) any {
			capturedReadyCtx = ctx
			return nil
		},
		nil,
	)

	// Drive the post-Start path directly; a real client.Start would
	// need a working management URL.
	nb.notifyClientReady(accountID, nil)

	require.NotNil(t, capturedReadyCtx, "readyHandler must have been invoked")
	require.NoError(t, capturedReadyCtx.Err(),
		"readyHandler must receive a background context, not an inherited cancelled one")
	deadline, ok := capturedReadyCtx.Deadline()
	assert.False(t, ok, "readyHandler ctx must have no deadline (background); got %v", deadline)

	calls := notifier.calls()
	require.Len(t, calls, 1, "NotifyStatus must be invoked once per registered service")
	require.NotNil(t, calls[0].ctx, "NotifyStatus must receive a context")
	require.NoError(t, calls[0].ctx.Err(),
		"NotifyStatus must receive a background context, not an inherited cancelled one")
}
