package migration_test

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/migration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateNormalizeServiceDomains(t *testing.T) {
	db := setupDatabase(t)
	require.NoError(t, db.AutoMigrate(&rpservice.Service{}))
	t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(&rpservice.Service{})) })

	ctx := context.Background()
	rows := []rpservice.Service{
		{ID: "lower", Domain: "lower.service.example"},
		{ID: "upper", Domain: "UPPER.SERVICE.EXAMPLE"},
		{ID: "mixed-upper", Domain: "mixed.SERVICE.example"},
		{ID: "mixed-lower", Domain: "mixed.service.example"},
	}
	require.NoError(t, db.Create(&rows).Error)

	require.NoError(t, migration.MigrateNormalizeServiceDomains(ctx, db))

	var results []map[string]any
	require.NoError(t, db.Model(&rpservice.Service{}).Select("ID", "domain").Find(&results).Error)
	assert.Equal(t, []map[string]any{
		{"id": "lower", "domain": "lower.service.example"},
		{"id": "upper", "domain": "upper.service.example"},
		{"id": "mixed-upper", "domain": "mixed.SERVICE.example"},
		{"id": "mixed-lower", "domain": "mixed.service.example"},
	}, results)
}

func TestMigrateNormalizeProxyClusterDomains(t *testing.T) {
	db := setupDatabase(t)
	require.NoError(t, db.AutoMigrate(&proxy.Proxy{}))
	t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(&proxy.Proxy{})) })

	ctx := context.Background()
	rows := []proxy.Proxy{
		{ID: "lower", ClusterAddress: "lower.service.example"},
		{ID: "upper", ClusterAddress: "UPPER.SERVICE.EXAMPLE"},
		{ID: "mixed-upper", ClusterAddress: "mixed.SERVICE.example"},
		{ID: "mixed-lower", ClusterAddress: "mixed.service.example"},
	}
	require.NoError(t, db.Create(&rows).Error)

	require.NoError(t, migration.MigrateNormalizeProxyClusterDomains(ctx, db))

	var results []map[string]any
	require.NoError(t, db.Model(&proxy.Proxy{}).Select("ID", "cluster_address").Find(&results).Error)
	assert.Equal(t, []map[string]any{
		{"id": "lower", "cluster_address": "lower.service.example"},
		{"id": "upper", "cluster_address": "upper.service.example"},
		{"id": "mixed-upper", "cluster_address": "mixed.SERVICE.example"},
		{"id": "mixed-lower", "cluster_address": "mixed.service.example"},
	}, results)
}
