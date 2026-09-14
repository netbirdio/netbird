package migration_test

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/migration"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestFillEmptyJson_NameserverGroup(t *testing.T) {
	db := setupNsGroupsTestDB(t)

	res, err := db.ConnPool.ExecContext(context.Background(), `insert into name_server_groups (id,account_id,name,name_servers,groups,domains) values('id-1','account-id-1','test-nsg-2','','','')`)
	require.NoError(t, err)
	n, _ := res.RowsAffected()
	require.Equal(t, n, int64(1))

	err = migration.FillEmptyNameserverGroupJsonColumns(context.Background(), db)
	require.NoError(t, err)

	rows, err := db.ConnPool.QueryContext(context.Background(), "select id from name_server_groups where name_servers='' or name_servers=null or groups='' or groups=null or domains='' or domains=null")
	require.NoError(t, err)

	rows.Next()
	require.False(t, rows.Next())
}

func TestFillEmptyJson_Peers(t *testing.T) {
	db := setupPeersTestDB(t)

	res, err := db.ConnPool.ExecContext(context.Background(),
		`insert into peers (id,account_id,ip,ipv6,meta_network_addresses,meta_environment,meta_flags,meta_files,meta_capabilities,location_connection_ip,extra_dns_labels)
		 values('id-1','account-id-1','','','','','','','','','')`)
	require.NoError(t, err)
	n, _ := res.RowsAffected()
	require.Equal(t, n, int64(1))

	err = migration.FillEmptyPeerJsonColumns(context.Background(), db)
	require.NoError(t, err)

	rows, err := db.ConnPool.QueryContext(context.Background(),
		`select id from peers where ip='' or ip=null or ipv6='' or ipv6=null or meta_network_addresses='' or meta_network_addresses=null 
		 or meta_environment='' or meta_environment=null or meta_flags='' or meta_flags=null or meta_files='' or meta_files=null 
		 or meta_capabilities='' or meta_capabilities=null or location_connection_ip='' or location_connection_ip=null 
		 or extra_dns_labels='' or extra_dns_labels=null`)
	require.NoError(t, err)
	rows.Next()
	require.False(t, rows.Next())
}

func TestFillEmptyJson_Settings(t *testing.T) {
	db := setupAccountsTestDB(t)

	res, err := db.ConnPool.ExecContext(context.Background(),
		`insert into accounts (id,settings_jwt_allow_groups,settings_network_range,settings_network_range_v6,settings_peer_expose_groups,settings_ipv6_enabled_groups,settings_extra_integrated_validator_groups)
		 values('id-1','','','','','','')`)
	require.NoError(t, err)
	n, _ := res.RowsAffected()
	require.Equal(t, n, int64(1))

	err = migration.FillEmptySettingsJsonColumns(context.Background(), db)
	require.NoError(t, err)

	rows, err := db.ConnPool.QueryContext(context.Background(),
		`select id from accounts where settings_jwt_allow_groups='' or settings_jwt_allow_groups=null or settings_network_range='' or settings_network_range=null or settings_network_range_v6='' or settings_network_range_v6=null 
		 or settings_peer_expose_groups='' or settings_peer_expose_groups=null or settings_ipv6_enabled_groups='' or settings_ipv6_enabled_groups=null or settings_extra_integrated_validator_groups='' or settings_extra_integrated_validator_groups=null`)
	require.NoError(t, err)
	rows.Next()
	require.False(t, rows.Next())
}

func setupNsGroupsTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&dns.NameServerGroup{})
	err := db.AutoMigrate(&dns.NameServerGroup{})
	require.NoError(t, err, "Failed to auto-migrate tables")
	return db
}

func setupPeersTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&peer.Peer{})
	err := db.AutoMigrate(&peer.Peer{})
	require.NoError(t, err, "Failed to auto-migrate tables")
	return db
}

func setupAccountsTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&types.Account{})
	err := db.AutoMigrate(&peer.Peer{})
	require.NoError(t, err, "Failed to auto-migrate tables")
	return db
}
