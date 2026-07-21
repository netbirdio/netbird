package store

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
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
