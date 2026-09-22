package migration_test

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/migration"
	net_types "github.com/netbirdio/netbird/management/server/networks/resources/types"
	router_types "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
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

func TestFillEmptyJson_PolicyRule(t *testing.T) {
	db := setupPolicyRulesTestDB(t)

	res, err := db.ConnPool.ExecContext(context.Background(),
		`insert into policies (id) values('policy-id-1')`)
	require.NoError(t, err)

	res, err = db.ConnPool.ExecContext(context.Background(),
		`insert into policy_rules (id,policy_id,destinations,destination_resource,sources,source_resource,ports,port_ranges,authorized_groups)
		 values('id-1','policy-id-1','','','','','','','')`)
	require.NoError(t, err)
	n, _ := res.RowsAffected()
	require.Equal(t, n, int64(1))

	err = migration.FillEmptyPolicyRuleJsonColumns(context.Background(), db)
	require.NoError(t, err)

	rows, err := db.ConnPool.QueryContext(context.Background(),
		`select id from policy_rules where destinations='' or destinations=null or destination_resource='' or destination_resource=null or sources='' or sources=null 
		 or source_resource='' or source_resource=null or ports='' or ports=null or port_ranges='' or port_ranges=null or authorized_groups='' or authorized_groups=null`)
	require.NoError(t, err)
	rows.Next()
	require.False(t, rows.Next())
}

func TestFillEmptyJson_Route(t *testing.T) {
	db := setupRouteTestDB(t)

	res, err := db.ConnPool.ExecContext(context.Background(), `insert into routes (id,account_id,network,domains,peer_groups,groups,access_control_groups) values('id-1','account-id-1','','','','','')`)
	require.NoError(t, err)
	n, _ := res.RowsAffected()
	require.Equal(t, n, int64(1))

	err = migration.FillEmptyRouteJsonColumns(context.Background(), db)
	require.NoError(t, err)

	rows, err := db.ConnPool.QueryContext(context.Background(), "select id from routes where network='' or network=null or domains='' or domains=null or peer_groups='' or peer_groups=null or groups='' or groups=null or access_control_groups='' or access_control_groups=null")
	require.NoError(t, err)

	rows.Next()
	require.False(t, rows.Next())
}

func TestFillEmptyJson_Service(t *testing.T) {
	db := setupServicesTestDB(t)

	res, err := db.ConnPool.ExecContext(context.Background(), `insert into services (id,account_id,auth,restrictions,access_groups) values('id-1','account-id-1','','','')`)
	require.NoError(t, err)
	n, _ := res.RowsAffected()
	require.Equal(t, n, int64(1))

	err = migration.FillEmptyServiceJsonColumns(context.Background(), db)
	require.NoError(t, err)

	rows, err := db.ConnPool.QueryContext(context.Background(), "select id from services where auth='' or auth=null or restrictions='' or restrictions=null or access_groups='' or access_groups=null")
	require.NoError(t, err)

	rows.Next()
	require.False(t, rows.Next())
}

func TestFillEmptyJson_ServiceTargets(t *testing.T) {
	db := setupServicesTestDB(t)

	res, err := db.ConnPool.ExecContext(context.Background(), `insert into services (id,account_id) values('id-2','account-id-1')`)
	require.NoError(t, err)
	n, _ := res.RowsAffected()
	require.Equal(t, n, int64(1))

	res, err = db.ConnPool.ExecContext(context.Background(), `insert into targets (service_id,account_id,custom_headers,middlewares,capture_content_types) values('id-2','account-id-1','','','')`)
	require.NoError(t, err)
	n, _ = res.RowsAffected()
	require.Equal(t, n, int64(1))

	err = migration.FillEmptyServiceTargetsJsonColumns(context.Background(), db)
	require.NoError(t, err)

	rows, err := db.ConnPool.QueryContext(context.Background(), "select id from targets where custom_headers='' or custom_headers=null or middlewares='' or middlewares=null or capture_content_types='' or capture_content_types=null")
	require.NoError(t, err)
	rows.Next()
	require.False(t, rows.Next())
}

func TestFillEmptyJson_AccountNetwork(t *testing.T) {
	db := setupAccountsTestDB(t)

	res, err := db.ConnPool.ExecContext(context.Background(),
		`insert into accounts (id,network_net,network_net_v6) values('id-1','','')`)
	require.NoError(t, err)
	n, _ := res.RowsAffected()
	require.Equal(t, n, int64(1))

	err = migration.FillEmptyAccountNetworkJsonColumns(context.Background(), db)
	require.NoError(t, err)

	rows, err := db.ConnPool.QueryContext(context.Background(), "select id from accounts where network_net='' or network_net=null or network_net_v6='' or network_net_v6=null")
	require.NoError(t, err)
	rows.Next()
	require.False(t, rows.Next())
}

func TestFillEmptyJsonField_NetworkResource(t *testing.T) {
	db := setupNetworkResourceTestDB(t)

	res, err := db.ConnPool.ExecContext(context.Background(),
		`insert into network_resources (id,prefix) values('id-1','')`)
	require.NoError(t, err)
	n, _ := res.RowsAffected()
	require.Equal(t, n, int64(1))

	err = migration.FillEmptyNetworkResourceJsonColumns(context.Background(), db)
	require.NoError(t, err)

	rows, err := db.ConnPool.QueryContext(context.Background(), "select id from network_resources where prefix='' or prefix=null")
	require.NoError(t, err)
	rows.Next()
	require.False(t, rows.Next())
}

func TestFillEmptyJsonField_NetworkRouter(t *testing.T) {
	db := setupNetworkRouterTestDB(t)

	res, err := db.ConnPool.ExecContext(context.Background(),
		`insert into network_routers (id,peer_groups) values('id-1','')`)
	require.NoError(t, err)
	n, _ := res.RowsAffected()
	require.Equal(t, n, int64(1))

	err = migration.FillEmptyNetworkRouterJsonColumns(context.Background(), db)
	require.NoError(t, err)

	rows, err := db.ConnPool.QueryContext(context.Background(), "select id from network_routers where peer_groups='' or peer_groups=null")
	require.NoError(t, err)
	rows.Next()
	require.False(t, rows.Next())
}

func TestFillEmptyJsonField_AccountDnsSettings(t *testing.T) {
	db := setupAccountsTestDB(t)

	res, err := db.ConnPool.ExecContext(context.Background(),
		`insert into accounts (id,dns_settings_disabled_management_groups) values('id-1','')`)
	require.NoError(t, err)
	n, _ := res.RowsAffected()
	require.Equal(t, n, int64(1))

	err = migration.FillEmptyAccountDnsSettingsJsonColumns(context.Background(), db)
	require.NoError(t, err)

	rows, err := db.ConnPool.QueryContext(context.Background(), "select id from accounts where dns_settings_disabled_management_groups='' or dns_settings_disabled_management_groups=null")
	require.NoError(t, err)
	rows.Next()
	require.False(t, rows.Next())
}

func TestFillEmptyJsonField_User(t *testing.T) {
	db := setupUserTestDB(t)

	res, err := db.ConnPool.ExecContext(context.Background(),
		`insert into users (id,auto_groups) values('id-1','')`)
	require.NoError(t, err)
	n, _ := res.RowsAffected()
	require.Equal(t, n, int64(1))

	err = migration.FillEmptyUserJsonColumns(context.Background(), db)
	require.NoError(t, err)

	rows, err := db.ConnPool.QueryContext(context.Background(), "select id from users where auto_groups='' or auto_groups=null")
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

func setupPolicyRulesTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&types.Policy{}, &types.PolicyRule{})
	err := db.AutoMigrate(&types.Policy{}, &types.PolicyRule{})
	require.NoError(t, err, "Failed to auto-migrate tables")
	return db
}

func setupRouteTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&route.Route{})
	err := db.AutoMigrate(&route.Route{})
	require.NoError(t, err, "Failed to auto-migrate tables")
	return db
}

func setupServicesTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&service.Service{})
	err := db.AutoMigrate(&service.Service{})
	_ = db.Migrator().DropTable(&service.Target{})
	err = db.AutoMigrate(&service.Target{})
	require.NoError(t, err, "Failed to auto-migrate tables")
	return db
}

func setupNetworkResourceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&net_types.NetworkResource{})
	err := db.AutoMigrate(&net_types.NetworkResource{})
	require.NoError(t, err, "Failed to auto-migrate tables")
	return db
}

func setupNetworkRouterTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&router_types.NetworkRouter{})
	err := db.AutoMigrate(&router_types.NetworkRouter{})
	require.NoError(t, err, "Failed to auto-migrate tables")
	return db
}

func setupUserTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := setupDatabase(t)
	_ = db.Migrator().DropTable(&types.User{})
	err := db.AutoMigrate(&types.User{})
	require.NoError(t, err, "Failed to auto-migrate tables")
	return db
}
