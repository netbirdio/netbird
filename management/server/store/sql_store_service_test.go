package store

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestSqlStore_GetAccount_PrivateServiceRoundtrip(t *testing.T) {
	if os.Getenv("CI") == "true" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		account := newAccountWithId(ctx, "account_private_svc", "testuser", "")
		require.NoError(t, store.SaveAccount(ctx, account))

		svc := &rpservice.Service{
			ID:           "svc-private",
			AccountID:    account.Id,
			Name:         "private-svc",
			Domain:       "private.example",
			ProxyCluster: "cluster.example",
			Enabled:      true,
			Mode:         rpservice.ModeHTTP,
			Private:      true,
			AccessGroups: []string{"grp-admins", "grp-ops"},
		}
		require.NoError(t, store.CreateService(ctx, svc))

		loaded, err := store.GetAccount(ctx, account.Id)
		require.NoError(t, err)
		require.Len(t, loaded.Services, 1)

		got := loaded.Services[0]
		assert.True(t, got.Private)
		assert.Equal(t, []string{"grp-admins", "grp-ops"}, got.AccessGroups)
	})
}

func TestSqlStore_MultiPortServiceCollectionUpdate(t *testing.T) {
	if os.Getenv("CI") == "true" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, sqlStore Store) {
		ctx := context.Background()
		account := newAccountWithId(ctx, "account_multiport_svc", "testuser", "")
		require.NoError(t, sqlStore.SaveAccount(ctx, account))

		svc := &rpservice.Service{
			ID: "svc-multiport", AccountID: account.Id, Name: "game",
			Domain: "game.example.test", ProxyCluster: "proxy.example.test",
			Enabled: true, Mode: rpservice.ModeTCP, ListenPort: 8080,
			Targets: []*rpservice.Target{{
				AccountID: account.Id, TargetId: "peer-1", TargetType: rpservice.TargetTypePeer,
				Host: "100.64.0.10", Protocol: rpservice.TargetProtoTCP, Port: 18080, Enabled: true,
			}},
			PortMappings: []*rpservice.PortMapping{
				{Protocol: rpservice.ModeTCP, ListenPortStart: 8080, ListenPortEnd: 8080, TargetPortStart: 18080, TargetPortEnd: 18080},
				{Protocol: rpservice.ModeTCP, ListenPortStart: 9000, ListenPortEnd: 9000, TargetPortStart: 19000, TargetPortEnd: 19000},
				{Protocol: rpservice.ModeUDP, ListenPortStart: 9001, ListenPortEnd: 9003, TargetPortStart: 19001, TargetPortEnd: 19003},
			},
		}
		require.NoError(t, sqlStore.CreateService(ctx, svc))

		loadedAccount, err := sqlStore.GetAccount(ctx, account.Id)
		require.NoError(t, err)
		require.Len(t, loadedAccount.Services, 1)
		require.Len(t, loadedAccount.Services[0].PortMappings, 3)
		assert.Equal(t, []uint16{8080, 9000, 9001}, []uint16{
			loadedAccount.Services[0].PortMappings[0].ListenPortStart,
			loadedAccount.Services[0].PortMappings[1].ListenPortStart,
			loadedAccount.Services[0].PortMappings[2].ListenPortStart,
		})

		loaded, err := sqlStore.GetServiceByID(ctx, LockingStrengthNone, account.Id, svc.ID)
		require.NoError(t, err)
		require.Len(t, loaded.PortMappings, 3)
		assert.Equal(t, []uint16{8080, 9000, 9001}, []uint16{
			loaded.PortMappings[0].ListenPortStart,
			loaded.PortMappings[1].ListenPortStart,
			loaded.PortMappings[2].ListenPortStart,
		})

		inRange, err := sqlStore.GetServicesByClusterAndPort(
			ctx, LockingStrengthNone, svc.ProxyCluster, rpservice.ModeUDP, 9002,
		)
		require.NoError(t, err)
		require.Len(t, inRange, 1, "a lookup inside an inclusive range must find its owner")
		assert.Equal(t, svc.ID, inRange[0].ID)

		// Remove only the middle TCP mapping and move UDP first. The service and
		// its target remain while the ordered child collection is replaced atomically.
		loaded.PortMappings = []*rpservice.PortMapping{loaded.PortMappings[2], loaded.PortMappings[0]}
		loaded.PortMappingsSet = true
		require.NoError(t, sqlStore.UpdateService(ctx, loaded))

		updated, err := sqlStore.GetServiceByID(ctx, LockingStrengthNone, account.Id, svc.ID)
		require.NoError(t, err)
		assert.Equal(t, svc.ID, updated.ID)
		require.Len(t, updated.Targets, 1)
		assert.Equal(t, "peer-1", updated.Targets[0].TargetId)
		require.Len(t, updated.PortMappings, 2)
		assert.Equal(t, []uint16{9001, 8080}, []uint16{
			updated.PortMappings[0].ListenPortStart,
			updated.PortMappings[1].ListenPortStart,
		})

		removed, err := sqlStore.GetServicesByClusterAndPort(
			ctx, LockingStrengthNone, svc.ProxyCluster, rpservice.ModeTCP, 9000,
		)
		require.NoError(t, err)
		assert.Empty(t, removed)

		require.NoError(t, sqlStore.DeleteService(ctx, account.Id, svc.ID))
		concreteStore, ok := sqlStore.(*SqlStore)
		require.True(t, ok)
		var mappingCount int64
		require.NoError(t, concreteStore.db.Model(&rpservice.PortMapping{}).
			Where("service_id = ?", svc.ID).
			Count(&mappingCount).Error)
		assert.Zero(t, mappingCount, "deleting a service must remove all mapping rows")
	})
}

func TestSqlStore_SharedCanonicalServiceDomain(t *testing.T) {
	if os.Getenv("CI") == "true" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, sqlStore Store) {
		ctx := context.Background()
		account := newAccountWithId(ctx, "account_shared_domain", "testuser", "")
		require.NoError(t, sqlStore.SaveAccount(ctx, account))

		services := []*rpservice.Service{
			{ID: "tcp", AccountID: account.Id, Name: "tcp", Domain: "SHARED.EXAMPLE", Mode: rpservice.ModeTCP, ListenPort: 2200},
			{ID: "udp", AccountID: account.Id, Name: "udp", Domain: "shared.example.", Mode: rpservice.ModeUDP, ListenPort: 5300},
			{ID: "http", AccountID: account.Id, Name: "web", Domain: " Shared.Example. ", Mode: rpservice.ModeHTTP},
		}
		for _, service := range services {
			require.NoError(t, sqlStore.CreateService(ctx, service))
		}

		shared, err := sqlStore.GetServicesByDomain(ctx, LockingStrengthNone, " SHARED.EXAMPLE. ")
		require.NoError(t, err)
		require.Len(t, shared, 3)
		ids := make([]string, 0, len(shared))
		for _, service := range shared {
			ids = append(ids, service.ID)
			assert.Equal(t, "shared.example", service.Domain)
			if service.Mode == rpservice.ModeHTTP {
				require.NotNil(t, service.HTTPDomain)
				assert.Equal(t, service.Domain, *service.HTTPDomain)
			} else {
				assert.Nil(t, service.HTTPDomain)
			}
		}
		assert.ElementsMatch(t, []string{"http", "tcp", "udp"}, ids)
		httpService, err := sqlStore.GetHTTPServiceByDomain(ctx, " SHARED.EXAMPLE. ")
		require.NoError(t, err)
		assert.Equal(t, "http", httpService.ID, "HTTP lookup must not depend on L4 insertion order")

		_, err = sqlStore.GetServiceByDomain(ctx, "shared.example")
		require.Error(t, err)
		sErr, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, status.PreconditionFailed, sErr.Type())

		duplicateHTTP := &rpservice.Service{
			ID: "http-duplicate", AccountID: account.Id, Name: "web-duplicate",
			Domain: "SHARED.EXAMPLE.", Mode: rpservice.ModeHTTP,
		}
		err = sqlStore.CreateService(ctx, duplicateHTTP)
		require.Error(t, err, "the nullable unique HTTP ownership key must close create races")
		sErr, ok = status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, status.AlreadyExists, sErr.Type())

		tcpService, err := sqlStore.GetServiceByID(ctx, LockingStrengthNone, account.Id, "tcp")
		require.NoError(t, err)
		tcpService.Mode = rpservice.ModeHTTP
		tcpService.ListenPort = 0
		tcpService.PortMappings = nil
		err = sqlStore.UpdateService(ctx, tcpService)
		require.Error(t, err)
		sErr, ok = status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, status.AlreadyExists, sErr.Type())

		persistedTCP, err := sqlStore.GetServiceByID(ctx, LockingStrengthNone, account.Id, "tcp")
		require.NoError(t, err)
		assert.Equal(t, rpservice.ModeTCP, persistedTCP.Mode, "failed ownership update must roll back")
	})
}

func TestSqlStore_ServiceDomainLockSerializesAbsentHostname(t *testing.T) {
	if os.Getenv("CI") == "true" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, sqlStore Store) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		firstLocked := make(chan struct{})
		releaseFirst := make(chan struct{})
		firstResult := make(chan error, 1)
		go func() {
			firstResult <- sqlStore.ExecuteInTransaction(ctx, func(tx Store) error {
				if err := tx.AcquireServiceDomainLock(ctx, " Lock.Example. "); err != nil {
					return err
				}
				close(firstLocked)
				select {
				case <-releaseFirst:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		}()

		select {
		case <-firstLocked:
		case err := <-firstResult:
			require.NoError(t, err)
			t.Fatal("first transaction completed before acquiring the test lock")
		case <-ctx.Done():
			t.Fatal("timed out acquiring first domain lock")
		}

		secondResult := make(chan error, 1)
		go func() {
			secondResult <- sqlStore.ExecuteInTransaction(ctx, func(tx Store) error {
				return tx.AcquireServiceDomainLock(ctx, "lock.example")
			})
		}()

		select {
		case err := <-secondResult:
			require.NoError(t, err)
			t.Fatal("second transaction acquired an absent-domain key before the first transaction committed")
		case <-time.After(100 * time.Millisecond):
		}

		close(releaseFirst)
		require.NoError(t, <-firstResult)
		require.NoError(t, <-secondResult)

		concreteStore, ok := sqlStore.(*SqlStore)
		require.True(t, ok)
		var count int64
		require.NoError(t, concreteStore.db.Model(&rpservice.DomainLock{}).
			Where("domain = ?", "lock.example").Count(&count).Error)
		assert.EqualValues(t, 1, count, "canonical aliases must share one durable serialization row")
	})
}

func TestSqlStore_GetEphemeralServiceByPeerAndCanonicalDomain(t *testing.T) {
	if os.Getenv("CI") == "true" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, sqlStore Store) {
		ctx := context.Background()
		account := newAccountWithId(ctx, "account_expose_domain", "testuser", "")
		require.NoError(t, sqlStore.SaveAccount(ctx, account))

		services := []*rpservice.Service{
			{
				ID: "permanent", AccountID: account.Id, Name: "permanent", Domain: "expose.example",
				Mode: rpservice.ModeTCP, Source: rpservice.SourcePermanent, SourcePeer: "peer-a",
			},
			{
				ID: "other-peer", AccountID: account.Id, Name: "other-peer", Domain: "EXPOSE.EXAMPLE.",
				Mode: rpservice.ModeUDP, Source: rpservice.SourceEphemeral, SourcePeer: "peer-b",
			},
			{
				ID: "wanted", AccountID: account.Id, Name: "wanted", Domain: " Expose.Example. ",
				Mode: rpservice.ModeTCP, Source: rpservice.SourceEphemeral, SourcePeer: "peer-a",
			},
		}
		for _, service := range services {
			require.NoError(t, sqlStore.CreateService(ctx, service))
		}

		got, err := sqlStore.GetEphemeralServiceByPeerAndDomain(
			ctx,
			LockingStrengthNone,
			account.Id,
			"peer-a",
			" EXPOSE.EXAMPLE. ",
		)
		require.NoError(t, err)
		assert.Equal(t, "wanted", got.ID)
		assert.Equal(t, "expose.example", got.Domain)
	})
}
