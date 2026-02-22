package manager

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/store"
)

func TestReapExpiredExposes(t *testing.T) {
	mgr, testStore := setupIntegrationTest(t)
	ctx := context.Background()

	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port: 8080,
		Mode: "http",
	})
	require.NoError(t, err)

	// Manually expire the service by backdating meta_last_renewed_at
	expireEphemeralService(t, testStore, testAccountID, resp.Domain)

	// Create a non-expired service
	resp2, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port: 8081,
		Mode: "http",
	})
	require.NoError(t, err)

	mgr.exposeReaper.reapExpiredExposes(ctx)

	// Expired service should be deleted
	_, err = testStore.GetHTTPServiceByDomain(ctx, testAccountID, resp.Domain)
	require.Error(t, err, "expired service should be deleted")

	// Non-expired service should remain
	_, err = testStore.GetHTTPServiceByDomain(ctx, testAccountID, resp2.Domain)
	require.NoError(t, err, "active service should remain")
}

func TestReapAlreadyDeletedService(t *testing.T) {
	mgr, testStore := setupIntegrationTest(t)
	ctx := context.Background()

	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port: 8080,
		Mode: "http",
	})
	require.NoError(t, err)

	expireEphemeralService(t, testStore, testAccountID, resp.Domain)

	// Delete the service before reaping
	err = mgr.StopServiceFromPeer(ctx, testAccountID, testPeerID, resp.ServiceID)
	require.NoError(t, err)

	// Reaping should handle the already-deleted service gracefully
	mgr.exposeReaper.reapExpiredExposes(ctx)
}

func TestConcurrentReapAndRenew(t *testing.T) {
	mgr, testStore := setupIntegrationTest(t)
	ctx := context.Background()

	for i := range 5 {
		_, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
			Port: uint16(8080 + i),
			Mode: "http",
		})
		require.NoError(t, err)
	}

	// Expire all services
	services, err := testStore.GetAccountServices(ctx, store.LockingStrengthNone, testAccountID)
	require.NoError(t, err)
	for _, svc := range services {
		if svc.Source == rpservice.SourceEphemeral {
			expireEphemeralService(t, testStore, testAccountID, svc.Domain)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		mgr.exposeReaper.reapExpiredExposes(ctx)
	}()
	go func() {
		defer wg.Done()
		_, _ = mgr.store.CountEphemeralServicesByPeer(ctx, store.LockingStrengthNone, testAccountID, testPeerID)
	}()
	wg.Wait()

	count, err := mgr.store.CountEphemeralServicesByPeer(ctx, store.LockingStrengthNone, testAccountID, testPeerID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "all expired services should be reaped")
}

func TestRenewEphemeralService(t *testing.T) {
	mgr, _ := setupIntegrationTest(t)
	ctx := context.Background()

	t.Run("renew succeeds for active service", func(t *testing.T) {
		resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
			Port: 8082,
			Mode: "http",
		})
		require.NoError(t, err)

		err = mgr.RenewServiceFromPeer(ctx, testAccountID, testPeerID, resp.ServiceID)
		require.NoError(t, err)
	})

	t.Run("renew fails for nonexistent domain", func(t *testing.T) {
		err := mgr.RenewServiceFromPeer(ctx, testAccountID, testPeerID, "nonexistent-service-id")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no active expose session")
	})
}

func TestCountAndExistsEphemeralServices(t *testing.T) {
	mgr, _ := setupIntegrationTest(t)
	ctx := context.Background()

	count, err := mgr.store.CountEphemeralServicesByPeer(ctx, store.LockingStrengthNone, testAccountID, testPeerID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port: 8083,
		Mode: "http",
	})
	require.NoError(t, err)

	count, err = mgr.store.CountEphemeralServicesByPeer(ctx, store.LockingStrengthNone, testAccountID, testPeerID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	exists, err := mgr.store.EphemeralServiceExists(ctx, store.LockingStrengthNone, testAccountID, testPeerID, resp.Domain)
	require.NoError(t, err)
	assert.True(t, exists, "service should exist")

	exists, err = mgr.store.EphemeralServiceExists(ctx, store.LockingStrengthNone, testAccountID, testPeerID, "no-such.domain")
	require.NoError(t, err)
	assert.False(t, exists, "non-existent service should not exist")
}

func TestMaxExposesPerPeerEnforced(t *testing.T) {
	mgr, _ := setupIntegrationTest(t)
	ctx := context.Background()

	for i := range maxExposesPerPeer {
		_, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
			Port: uint16(8090 + i),
			Mode: "http",
		})
		require.NoError(t, err, "expose %d should succeed", i)
	}

	_, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port: 9999,
		Mode: "http",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum number of active expose sessions")
}

func TestReapSkipsRenewedService(t *testing.T) {
	mgr, testStore := setupIntegrationTest(t)
	ctx := context.Background()

	resp, err := mgr.CreateServiceFromPeer(ctx, testAccountID, testPeerID, &rpservice.ExposeServiceRequest{
		Port: 8086,
		Mode: "http",
	})
	require.NoError(t, err)

	// Expire the service
	expireEphemeralService(t, testStore, testAccountID, resp.Domain)

	// Renew it before the reaper runs
	err = mgr.RenewServiceFromPeer(ctx, testAccountID, testPeerID, resp.ServiceID)
	require.NoError(t, err)

	// Reaper should skip it because the re-check sees a fresh timestamp
	mgr.exposeReaper.reapExpiredExposes(ctx)

	_, err = testStore.GetHTTPServiceByDomain(ctx, testAccountID, resp.Domain)
	require.NoError(t, err, "renewed service should survive reaping")
}

// expireEphemeralService backdates meta_last_renewed_at to force expiration.
func expireEphemeralService(t *testing.T, s store.Store, accountID, domain string) {
	t.Helper()
	svc, err := s.GetHTTPServiceByDomain(context.Background(), accountID, domain)
	require.NoError(t, err)

	expired := time.Now().Add(-2 * exposeTTL)
	svc.Meta.LastRenewedAt = &expired
	err = s.UpdateService(context.Background(), svc)
	require.NoError(t, err)
}
