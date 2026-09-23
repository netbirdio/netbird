package migration_test

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/dns"
	agn_types "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/server/migration"
	net_types "github.com/netbirdio/netbird/management/server/networks/resources/types"
	router_types "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestFillEmptyJsonFields(t *testing.T) {
	db := setupDatabase(t)

	var tests = []struct {
		description   string
		setupFuncs    []func(t *testing.T, db *gorm.DB)
		migrationFunc func(context.Context, *gorm.DB) error
		createSQL     string
		querySQL      string
	}{
		{
			description: "empty peer json fields",
			createSQL: `insert into peers (id,account_id,ip,ipv6,meta_network_addresses,meta_environment,meta_flags,meta_files,meta_capabilities,location_connection_ip,extra_dns_labels)
		 values('id-1','account-id-1','','','','','','','','','')`,
			querySQL: `select id from peers where ip='' or ip=null or ipv6='' or ipv6=null or meta_network_addresses='' or meta_network_addresses=null 
		 or meta_environment='' or meta_environment=null or meta_flags='' or meta_flags=null or meta_files='' or meta_files=null 
		 or meta_capabilities='' or meta_capabilities=null or location_connection_ip='' or location_connection_ip=null 
		 or extra_dns_labels='' or extra_dns_labels=null`,
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[peer.Peer]},
			migrationFunc: migration.FillEmptyPeerJsonColumns,
		},
		{
			description: "empty policy rule json fields",
			createSQL: `insert into policies (id) values('policy-id-1');insert into policy_rules (id,policy_id,destinations,destination_resource,sources,source_resource,ports,port_ranges,authorized_groups)
		 values('id-1','policy-id-1','','','','','','','')`,
			querySQL: `select id from policy_rules where destinations='' or destinations=null or destination_resource='' or destination_resource=null or sources='' or sources=null 
		 or source_resource='' or source_resource=null or ports='' or ports=null or port_ranges='' or port_ranges=null or authorized_groups='' or authorized_groups=null`,
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[types.Policy], setupTestDB[types.PolicyRule]},
			migrationFunc: migration.FillEmptyPolicyRuleJsonColumns,
		},
		{
			description:   "empty policy json fields",
			createSQL:     `insert into policies (id,source_posture_checks) values('policy-id-1','')`,
			querySQL:      `select id from policies where source_posture_checks='' or source_posture_checks=null`,
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[types.Policy]},
			migrationFunc: migration.FillEmptyPolicyJsonColumns,
		},
		{
			description:   "empty service json fields",
			createSQL:     `insert into services (id,account_id,auth,restrictions,access_groups) values('id-1','account-id-1','','','')`,
			querySQL:      `select id from services where auth='' or auth=null or restrictions='' or restrictions=null or access_groups='' or access_groups=null`,
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[service.Service], setupTestDB[service.Target]},
			migrationFunc: migration.FillEmptyServiceJsonColumns,
		},
		{
			description: "empty service targets json fields",
			createSQL: `insert into services (id,account_id) values('id-2','account-id-1');
			insert into targets (service_id,account_id,custom_headers,middlewares,capture_content_types) values('id-2','account-id-1','','','')`,
			querySQL:      `select id from targets where custom_headers='' or custom_headers=null or middlewares='' or middlewares=null or capture_content_types='' or capture_content_types=null`,
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[service.Service], setupTestDB[service.Target]},
			migrationFunc: migration.FillEmptyServiceJsonColumns,
		},
		{
			description:   "empty name_server_groups json fields",
			createSQL:     `insert into name_server_groups (id,account_id,name,name_servers,groups,domains) values('id-1','account-id-1','test-nsg-2','','','')`,
			querySQL:      `select id from name_server_groups where name_servers='' or name_servers=null or groups='' or groups=null or domains='' or domains=null`,
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[dns.NameServerGroup]},
			migrationFunc: migration.FillEmptyNameserverGroupJsonColumns,
		},
		{
			description: "empty account settings json fields",
			createSQL: `insert into accounts (id,settings_jwt_allow_groups,settings_network_range,settings_network_range_v6,settings_peer_expose_groups,settings_ipv6_enabled_groups,settings_extra_integrated_validator_groups)
		 values('id-1','','','','','','')`,
			querySQL: `select id from accounts where settings_jwt_allow_groups='' or settings_jwt_allow_groups=null or settings_network_range='' or settings_network_range=null or settings_network_range_v6='' or settings_network_range_v6=null 
		 or settings_peer_expose_groups='' or settings_peer_expose_groups=null or settings_ipv6_enabled_groups='' or settings_ipv6_enabled_groups=null or settings_extra_integrated_validator_groups='' or settings_extra_integrated_validator_groups=null`,
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[types.Account]},
			migrationFunc: migration.FillEmptySettingsJsonColumns,
		},
		{
			description: "empty routes json fields",
			createSQL: `insert into accounts (id) values('account-id-1');
			insert into routes (id,account_id,network,domains,peer_groups,groups,access_control_groups) values('id-1','account-id-1','','','','','')`,
			querySQL:      "select id from routes where network='' or network=null or domains='' or domains=null or peer_groups='' or peer_groups=null or groups='' or groups=null or access_control_groups='' or access_control_groups=null",
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[route.Route]},
			migrationFunc: migration.FillEmptyRouteJsonColumns,
		},
		{
			description:   "empty accounts.networks",
			createSQL:     "insert into accounts (id,network_net,network_net_v6) values('id-1','','')",
			querySQL:      "select id from accounts where network_net='' or network_net=null or network_net_v6='' or network_net_v6=null",
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[types.Account]},
			migrationFunc: migration.FillEmptyAccountNetworkJsonColumns,
		},
		{
			description:   "empty network_resources.prefix",
			createSQL:     "insert into network_resources (id,prefix) values('id-1','')",
			querySQL:      "select id from network_resources where prefix='' or prefix=null",
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[net_types.NetworkResource]},
			migrationFunc: migration.FillEmptyNetworkResourceJsonColumns,
		},
		{
			description:   "empty network_routers.peer_groups",
			createSQL:     "insert into network_routers (id,peer_groups) values('id-1','')",
			querySQL:      "select id from network_routers where peer_groups='' or peer_groups=null",
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[router_types.NetworkRouter]},
			migrationFunc: migration.FillEmptyNetworkRouterJsonColumns,
		},
		{
			description:   "empty accounts.dns_settings_disabled_management_groups",
			createSQL:     "insert into accounts (id,dns_settings_disabled_management_groups) values('id-1','')",
			querySQL:      "select id from accounts where dns_settings_disabled_management_groups='' or dns_settings_disabled_management_groups=null",
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[types.Account]},
			migrationFunc: migration.FillEmptyAccountDnsSettingsJsonColumns,
		},
		{
			description:   "empty users.auto_groups",
			createSQL:     "insert into users (id,auto_groups) values('id-1','')",
			querySQL:      "select id from users where auto_groups='' or auto_groups=null",
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[types.User]},
			migrationFunc: migration.FillEmptyUserJsonColumns,
		},
		{
			description:   "empty posture_checks.checks",
			createSQL:     "insert into posture_checks (id,checks) values('id-1','')",
			querySQL:      "select id from posture_checks where checks='' or checks=null",
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[posture.Checks]},
			migrationFunc: migration.FillEmptyPostureCheckJsonColumns,
		},
		{
			description:   "empty setup_keys.auto_groups",
			createSQL:     "insert into setup_keys (id,auto_groups) values('id-1','')",
			querySQL:      "select id from setup_keys where auto_groups='' or auto_groups=null",
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[types.SetupKey]},
			migrationFunc: migration.FillEmptySetupKeyJsonColumns,
		},
		{
			description: "empty user_invites.auto_groups",
			createSQL: `insert into user_invites (id,account_id,auto_groups,email,name,role,hashed_token,expires_at,created_at,created_by)
			values('id-1','account-id-2','','test@test.test','Test Test','test-role','12345','02/01/2026 02:03:04','01/01/2026 02:03:04','Test Test')`,
			querySQL:      "select id from user_invites where auto_groups='' or auto_groups=null",
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[types.UserInviteRecord]},
			migrationFunc: migration.FillEmptyUserInvitesJsonColumns,
		},
		{
			description:   "empty group.resources",
			createSQL:     `insert into groups (id,resources) values('id-1','')`,
			querySQL:      "select id from groups where resources='' or resources=null",
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[types.Group]},
			migrationFunc: migration.FillEmptyGroupJsonColumns,
		},
		{
			description:   "empty zone.distribution_groups",
			createSQL:     `insert into zones (id,distribution_groups) values('id-1','')`,
			querySQL:      "select id from zones where distribution_groups='' or distribution_groups=null",
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[zones.Zone]},
			migrationFunc: migration.FillEmptyZoneJsonColumns,
		},
		{
			description:   "empty access_log_entries.metadata",
			createSQL:     `insert into access_log_entries (id,metadata) values('id-1','')`,
			querySQL:      "select id from access_log_entries where metadata='' or metadata=null",
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[accesslogs.AccessLogEntry]},
			migrationFunc: migration.FillEmptyZoneJsonColumns,
		},
		{
			description:   "empty agent_network_budget_rules",
			createSQL:     `insert into agent_network_budget_rules (id,target_groups,target_users,limits) values('id-1','','','')`,
			querySQL:      "select id from agent_network_budget_rules where target_groups='' or target_groups=null or target_users='' or target_users=null or limits='' or limits=null",
			setupFuncs:    []func(t *testing.T, db *gorm.DB){setupTestDB[agn_types.AccountBudgetRule]},
			migrationFunc: migration.FillEmptyAccountBudgetRulesJsonColumns,
		},
	}
	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			for _, f := range tt.setupFuncs {
				f(t, db)
			}

			res, err := db.ConnPool.ExecContext(context.Background(), tt.createSQL)
			require.NoError(t, err)
			n, _ := res.RowsAffected()
			require.Equal(t, n, int64(1))

			err = tt.migrationFunc(context.Background(), db)
			require.NoError(t, err)

			rows, err := db.ConnPool.QueryContext(context.Background(), tt.querySQL)
			require.NoError(t, err)
			rows.Next()
			require.False(t, rows.Next())
		})
	}
}

func setupTestDB[T any](t *testing.T, db *gorm.DB) {
	t.Helper()
	_ = db.Migrator().DropTable(new(T))
	err := db.AutoMigrate(new(T))
	require.NoError(t, err, "Failed to auto-migrate tables")
}
