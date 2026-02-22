package roundtrip

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type mockMgmtClient struct{}

func (m *mockMgmtClient) CreateProxyPeer(_ context.Context, _ *proto.CreateProxyPeerRequest, _ ...grpc.CallOption) (*proto.CreateProxyPeerResponse, error) {
	return &proto.CreateProxyPeerResponse{Success: true}, nil
}

type mockStatusNotifier struct {
	mu       sync.Mutex
	statuses []statusCall
}

type statusCall struct {
	accountID string
	serviceID string
	connected bool
}

func (m *mockStatusNotifier) NotifyStatus(_ context.Context, accountID, serviceID string, connected bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses = append(m.statuses, statusCall{accountID, serviceID, connected})
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
	return NewNetBird("test-proxy", "invalid.test", ClientConfig{
		MgmtAddr:     "http://invalid.test:9999",
		WGPort:       0,
		PreSharedKey: "",
	}, nil, nil, &mockMgmtClient{})
}

func TestNetBird_AddPeer_CreatesClientForNewAccount(t *testing.T) {
	nb := mockNetBird()
	accountID := types.AccountID("account-1")

	// Initially no client exists.
	assert.False(t, nb.HasClient(accountID), "should not have client before AddPeer")
	assert.Equal(t, 0, nb.ServiceCount(accountID), "service count should be 0")

	// Add first service - this should create a new client.
	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "setup-key-1", "proxy-1")
	require.NoError(t, err)

	assert.True(t, nb.HasClient(accountID), "should have client after AddPeer")
	assert.Equal(t, 1, nb.ServiceCount(accountID), "service count should be 1")
}

func TestNetBird_AddPeer_ReuseClientForSameAccount(t *testing.T) {
	nb := mockNetBird()
	accountID := types.AccountID("account-1")

	// Add first service.
	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "setup-key-1", "proxy-1")
	require.NoError(t, err)
	assert.Equal(t, 1, nb.ServiceCount(accountID))

	// Add second service for the same account - should reuse existing client.
	err = nb.AddPeer(context.Background(), accountID, "domain2.test", "setup-key-1", "proxy-2")
	require.NoError(t, err)
	assert.Equal(t, 2, nb.ServiceCount(accountID), "service count should be 2 after adding second service")

	// Add third service.
	err = nb.AddPeer(context.Background(), accountID, "domain3.test", "setup-key-1", "proxy-3")
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
	err := nb.AddPeer(context.Background(), account1, "domain1.test", "setup-key-1", "proxy-1")
	require.NoError(t, err)

	// Add service for account 2.
	err = nb.AddPeer(context.Background(), account2, "domain2.test", "setup-key-2", "proxy-2")
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
	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "setup-key-1", "proxy-1")
	require.NoError(t, err)
	err = nb.AddPeer(context.Background(), accountID, "domain2.test", "setup-key-1", "proxy-2")
	require.NoError(t, err)
	err = nb.AddPeer(context.Background(), accountID, "domain3.test", "setup-key-1", "proxy-3")
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
	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "setup-key-1", "proxy-1")
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
	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "setup-key-1", "proxy-1")
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
	err := nb.AddPeer(context.Background(), account1, "domain1.test", "key-1", "proxy-1")
	require.NoError(t, err)
	err = nb.AddPeer(context.Background(), account2, "domain2.test", "key-2", "proxy-2")
	require.NoError(t, err)
	err = nb.AddPeer(context.Background(), account3, "domain3.test", "key-3", "proxy-3")
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
	err := nb.AddPeer(context.Background(), types.AccountID("account-1"), "domain1.test", "key-1", "proxy-1")
	require.NoError(t, err)
	assert.Equal(t, 1, nb.ClientCount())

	err = nb.AddPeer(context.Background(), types.AccountID("account-2"), "domain2.test", "key-2", "proxy-2")
	require.NoError(t, err)
	assert.Equal(t, 2, nb.ClientCount())

	// Adding service to existing account should not increase count.
	err = nb.AddPeer(context.Background(), types.AccountID("account-1"), "domain1b.test", "key-1", "proxy-1b")
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
	nb := NewNetBird("test-proxy", "invalid.test", ClientConfig{
		MgmtAddr:     "http://invalid.test:9999",
		WGPort:       0,
		PreSharedKey: "",
	}, nil, notifier, &mockMgmtClient{})
	accountID := types.AccountID("account-1")

	// Add first service — creates a new client entry.
	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "key-1", "svc-1")
	require.NoError(t, err)

	// Manually mark client as started to simulate background startup completing.
	nb.clientsMux.Lock()
	nb.clients[accountID].started = true
	nb.clientsMux.Unlock()

	// Add second service — should notify immediately since client is already started.
	err = nb.AddPeer(context.Background(), accountID, "domain2.test", "key-1", "svc-2")
	require.NoError(t, err)

	calls := notifier.calls()
	require.Len(t, calls, 1)
	assert.Equal(t, string(accountID), calls[0].accountID)
	assert.Equal(t, "svc-2", calls[0].serviceID)
	assert.True(t, calls[0].connected)
}

func TestNetBird_RemovePeer_NotifiesDisconnection(t *testing.T) {
	notifier := &mockStatusNotifier{}
	nb := NewNetBird("test-proxy", "invalid.test", ClientConfig{
		MgmtAddr:     "http://invalid.test:9999",
		WGPort:       0,
		PreSharedKey: "",
	}, nil, notifier, &mockMgmtClient{})
	accountID := types.AccountID("account-1")

	err := nb.AddPeer(context.Background(), accountID, "domain1.test", "key-1", "svc-1")
	require.NoError(t, err)
	err = nb.AddPeer(context.Background(), accountID, "domain2.test", "key-1", "svc-2")
	require.NoError(t, err)

	// Remove one service — client stays, but disconnection notification fires.
	err = nb.RemovePeer(context.Background(), accountID, "domain1.test")
	require.NoError(t, err)
	assert.True(t, nb.HasClient(accountID))

	calls := notifier.calls()
	require.Len(t, calls, 1)
	assert.Equal(t, "svc-1", calls[0].serviceID)
	assert.False(t, calls[0].connected)
}
