package migration_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/migration"
)

func TestMigrateReverseProxyPortMappings_BackfillsLegacyRowsIdempotently(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")
	db := setupDatabase(t)
	require.NoError(t, db.Migrator().DropTable(
		&rpservice.PortMapping{},
		&rpservice.Target{},
		&rpservice.Service{},
	))
	require.NoError(t, db.AutoMigrate(
		&rpservice.Service{},
		&rpservice.Target{},
		&rpservice.PortMapping{},
	))

	services := []*rpservice.Service{
		{ID: "legacy-tcp", AccountID: "account-1", Name: "tcp", Domain: "tcp.example.test", Mode: rpservice.ModeTCP, ListenPort: 18080, Enabled: true},
		{ID: "legacy-udp", AccountID: "account-1", Name: "udp", Domain: "udp.example.test", Mode: rpservice.ModeUDP, ListenPort: 19001, Enabled: true},
		{ID: "legacy-tls", AccountID: "account-1", Name: "tls", Domain: "tls.example.test", Mode: rpservice.ModeTLS, ListenPort: 443, Enabled: true},
		{ID: "http", AccountID: "account-1", Name: "http", Domain: "http.example.test", Mode: rpservice.ModeHTTP, Enabled: true},
		{ID: "invalid", AccountID: "account-1", Name: "invalid", Domain: "invalid.example.test", Mode: rpservice.ModeTCP, ListenPort: 0, Enabled: true},
		{ID: "already-mapped", AccountID: "account-1", Name: "mapped", Domain: "mapped.example.test", Mode: rpservice.ModeTCP, ListenPort: 20000, Enabled: true},
	}
	for _, service := range services {
		require.NoError(t, db.Create(service).Error)
	}

	targets := []*rpservice.Target{
		{AccountID: "account-1", ServiceID: "legacy-tcp", TargetId: "peer-1", TargetType: rpservice.TargetTypePeer, Protocol: rpservice.TargetProtoTCP, Port: 8080, Enabled: true},
		{AccountID: "account-1", ServiceID: "legacy-udp", TargetId: "peer-1", TargetType: rpservice.TargetTypePeer, Protocol: rpservice.TargetProtoUDP, Port: 9001, Enabled: true},
		{AccountID: "account-1", ServiceID: "legacy-tls", TargetId: "peer-1", TargetType: rpservice.TargetTypePeer, Protocol: rpservice.TargetProtoTCP, Port: 8443, Enabled: true},
		{AccountID: "account-1", ServiceID: "http", TargetId: "peer-1", TargetType: rpservice.TargetTypePeer, Protocol: "http", Port: 80, Enabled: true},
		{AccountID: "account-1", ServiceID: "invalid", TargetId: "peer-1", TargetType: rpservice.TargetTypePeer, Protocol: rpservice.TargetProtoTCP, Port: 8080, Enabled: true},
		{AccountID: "account-1", ServiceID: "already-mapped", TargetId: "peer-1", TargetType: rpservice.TargetTypePeer, Protocol: rpservice.TargetProtoTCP, Port: 10000, Enabled: true},
	}
	for _, target := range targets {
		require.NoError(t, db.Create(target).Error)
	}
	existing := &rpservice.PortMapping{
		AccountID: "account-1", ServiceID: "already-mapped", Protocol: rpservice.ModeTCP,
		ListenPortStart: 20000, ListenPortEnd: 20001, TargetPortStart: 10000, TargetPortEnd: 10001,
	}
	require.NoError(t, db.Create(existing).Error)

	for range 2 {
		require.NoError(t, migration.MigrateReverseProxyPortMappings(context.Background(), db))
	}

	var mappings []*rpservice.PortMapping
	require.NoError(t, db.Order("service_id ASC, position ASC").Find(&mappings).Error)
	require.Len(t, mappings, 4, "three valid legacy rows plus the existing mapping")

	byService := make(map[string]*rpservice.PortMapping, len(mappings))
	for _, mapping := range mappings {
		byService[mapping.ServiceID] = mapping
	}
	assert.Equal(t, &rpservice.PortMapping{
		ID:        byService["legacy-tcp"].ID,
		AccountID: "account-1", ServiceID: "legacy-tcp", Protocol: rpservice.ModeTCP,
		ListenPortStart: 18080, ListenPortEnd: 18080, TargetPortStart: 8080, TargetPortEnd: 8080,
	}, byService["legacy-tcp"])
	assert.Equal(t, uint16(19001), byService["legacy-udp"].ListenPortStart)
	assert.Equal(t, uint16(9001), byService["legacy-udp"].TargetPortStart)
	assert.Equal(t, uint16(443), byService["legacy-tls"].ListenPortStart)
	assert.Equal(t, uint16(8443), byService["legacy-tls"].TargetPortStart)
	assert.Equal(t, uint16(20001), byService["already-mapped"].ListenPortEnd,
		"an existing collection must not be overwritten")
	assert.NotContains(t, byService, "http")
	assert.NotContains(t, byService, "invalid")

	var legacy rpservice.Service
	require.NoError(t, db.First(&legacy, "id = ?", "legacy-tcp").Error)
	assert.Equal(t, "legacy-tcp", legacy.ID)
	assert.Equal(t, uint16(18080), legacy.ListenPort, "legacy downgrade fields must remain intact")
	var target rpservice.Target
	require.NoError(t, db.First(&target, "service_id = ?", "legacy-tcp").Error)
	assert.Equal(t, uint16(8080), target.Port, "legacy target rows must remain intact")
}
