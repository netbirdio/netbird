package migration_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/netbirdio/netbird/dns"
	agn_types "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	net_types "github.com/netbirdio/netbird/management/server/networks/resources/types"
	router_types "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestDefaultJsonFields(t *testing.T) {
	db := setupDatabase(t)

	var tests = []struct {
		description       string
		setupFuncs        []func(t *testing.T, db *gorm.DB)
		unmarshallTargets []any
		createSQL         string
		querySQL          string
	}{
		{
			description:       "peer json fields",
			createSQL:         `insert into peers (id,account_id) values('id-1','account-id-1')`,
			querySQL:          `select ip,ipv6,meta_network_addresses,meta_environment,meta_flags,meta_files,meta_capabilities,location_connection_ip,extra_dns_labels from peers where id='id-1'`,
			setupFuncs:        []func(t *testing.T, db *gorm.DB){setupTestDB[peer.Peer]},
			unmarshallTargets: []any{peer.Peer{}.IP, peer.Peer{}.IP, peer.Peer{}.Meta.NetworkAddresses, peer.Peer{}.Meta.Environment, peer.Peer{}.Meta.Flags, peer.Peer{}.Meta.Files, peer.Peer{}.Meta.Capabilities, peer.Peer{}.Location.ConnectionIP, peer.Peer{}.ExtraDNSLabels},
		},
		{
			description:       "policy rule json fields",
			createSQL:         `insert into policies (id) values('policy-id-1');insert into policy_rules (id,policy_id) values('id-1','policy-id-1')`,
			setupFuncs:        []func(t *testing.T, db *gorm.DB){setupTestDB[types.Policy], setupTestDB[types.PolicyRule]},
			querySQL:          `select destinations,destination_resource,sources,source_resource,ports,port_ranges,authorized_groups from policy_rules where id='id-1'`,
			unmarshallTargets: []any{types.PolicyRule{}.Destinations, types.PolicyRule{}.DestinationResource, types.PolicyRule{}.Sources, types.PolicyRule{}.SourceResource, types.PolicyRule{}.Ports, types.PolicyRule{}.PortRanges, types.PolicyRule{}.AuthorizedGroups},
		},
		{
			description:       "policy json fields",
			createSQL:         `insert into policies (id) values('policy-id-1')`,
			setupFuncs:        []func(t *testing.T, db *gorm.DB){setupTestDB[types.Policy]},
			querySQL:          `select source_posture_checks from policies where id='policy-id-1'`,
			unmarshallTargets: []any{types.Policy{}.SourcePostureChecks},
		},
		{
			description:       "service json fields",
			createSQL:         `insert into services (id,account_id) values('id-1','account-id-1')`,
			setupFuncs:        []func(t *testing.T, db *gorm.DB){setupTestDB[service.Service], setupTestDB[service.Target]},
			querySQL:          `select auth,restrictions,access_groups from services where id='id-1'`,
			unmarshallTargets: []any{service.Service{}.Auth, service.Service{}.Restrictions, service.Service{}.AccessGroups},
		},
		{
			description: "service targets json fields",
			createSQL: `insert into services (id,account_id) values('id-2','account-id-1');
			insert into targets (service_id,account_id) values('id-2','account-id-1')`,
			setupFuncs:        []func(t *testing.T, db *gorm.DB){setupTestDB[service.Service], setupTestDB[service.Target]},
			querySQL:          `select custom_headers,middlewares,capture_content_types from targets where service_id='id-2'`,
			unmarshallTargets: []any{service.Target{}.Options.CustomHeaders, service.Target{}.Options.Middlewares, service.Target{}.Options.CaptureContentTypes},
		},
		{
			description: "empty name_server_groups json fields",
			createSQL:   `insert into name_server_groups (id,account_id,name,name_servers,groups,domains) values('id-1','account-id-1','test-nsg-2','','','')`,
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[dns.NameServerGroup]},
		},
		{
			description: "empty account settings json fields",
			createSQL: `insert into accounts (id,settings_jwt_allow_groups,settings_network_range,settings_network_range_v6,settings_peer_expose_groups,settings_ipv6_enabled_groups,settings_extra_integrated_validator_groups)
		 values('id-1','','','','','','')`,
			setupFuncs: []func(t *testing.T, db *gorm.DB){setupTestDB[types.Account]},
		},
		{
			description: "empty routes json fields",
			createSQL: `insert into accounts (id) values('account-id-1');
			insert into routes (id,account_id,network,domains,peer_groups,groups,access_control_groups) values('id-1','account-id-1','','','','','')`,
			setupFuncs: []func(t *testing.T, db *gorm.DB){setupTestDB[types.Account], setupTestDB[route.Route]},
		},
		{
			description: "empty accounts.networks",
			createSQL:   "insert into accounts (id,network_net,network_net_v6) values('id-1','','')",
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[types.Account]},
		},
		{
			description: "empty network_resources.prefix",
			createSQL:   "insert into network_resources (id,prefix) values('id-1','')",
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[net_types.NetworkResource]},
		},
		{
			description: "empty network_routers.peer_groups",
			createSQL:   "insert into network_routers (id,peer_groups) values('id-1','')",
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[router_types.NetworkRouter]},
		},
		{
			description: "empty accounts.dns_settings_disabled_management_groups",
			createSQL:   "insert into accounts (id,dns_settings_disabled_management_groups) values('id-1','')",
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[types.Account]},
		},
		{
			description: "empty users.auto_groups",
			createSQL:   "insert into users (id,auto_groups) values('id-1','')",
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[types.User]},
		},
		{
			description: "empty posture_checks.checks",
			createSQL:   "insert into posture_checks (id,checks) values('id-1','')",
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[posture.Checks]},
		},
		{
			description: "empty setup_keys.auto_groups",
			createSQL:   "insert into setup_keys (id,auto_groups) values('id-1','')",
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[types.SetupKey]},
		},
		{
			description: "empty user_invites.auto_groups",
			createSQL: `insert into user_invites (id,account_id,auto_groups,email,name,role,hashed_token,expires_at,created_at,created_by)
			values('id-1','account-id-2','','test@test.test','Test Test','test-role','12345','02/01/2026 02:03:04','01/01/2026 02:03:04','Test Test')`,
			setupFuncs: []func(t *testing.T, db *gorm.DB){setupTestDB[types.UserInviteRecord]},
		},
		{
			description: "empty group.resources",
			createSQL:   `insert into groups (id,resources) values('id-1','')`,
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[types.Group]},
		},
		{
			description: "empty zone.distribution_groups",
			createSQL:   `insert into zones (id,distribution_groups) values('id-1','')`,
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[zones.Zone]},
		},
		{
			description: "empty access_log_entries.metadata",
			createSQL:   `insert into access_log_entries (id,metadata) values('id-1','')`,
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[accesslogs.AccessLogEntry]},
		},
		{
			description: "empty agent_network_budget_rules",
			createSQL:   `insert into agent_network_budget_rules (id,target_groups,target_users,limits) values('id-1','','','')`,
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[agn_types.AccountBudgetRule]},
		},
		{
			description: "empty agent_network_policies",
			createSQL:   `insert into agent_network_policies (id,source_groups,destination_provider_ids,guardrail_ids,limits) values('id-1','','','','')`,
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[agn_types.Policy]},
		},
		{
			description: "empty agent_network_providers",
			createSQL:   `insert into agent_network_providers (id,extra_values,models) values('id-1','','')`,
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[agn_types.Provider]},
		},
		{
			description: "empty agent_network_guardrails",
			createSQL:   `insert into agent_network_guardrails (id,checks) values('id-1','')`,
			setupFuncs:  []func(t *testing.T, db *gorm.DB){setupTestDB[agn_types.Guardrail]},
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

			row := db.ConnPool.QueryRowContext(context.Background(), tt.querySQL)
			require.NoError(t, row.Err())

			cols := toScanDest(len(tt.unmarshallTargets))
			require.NoError(t, row.Scan(cols...))

			for i, v := range cols {
				vv, _ := v.(*string)
				require.NoError(t, json.Unmarshal([]byte(*vv), &tt.unmarshallTargets[i]))
			}
			t.Log(cols)
		})
	}
}

func toScanDest(numOfCols int) []any {
	vals := make([]string, 0, numOfCols)
	for i := 0; i < numOfCols; i++ {
		vals = append(vals, "")
	}
	toret := make([]any, 0, numOfCols)
	for _, v := range vals {
		toret = append(toret, &v)
	}
	return toret
}
