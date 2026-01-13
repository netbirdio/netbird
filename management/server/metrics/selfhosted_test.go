package metrics

import (
	"context"
	"testing"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/idp/dex"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

type mockDatasource struct{}

// GetAllConnectedPeers returns a map of connected peer IDs for use in tests with predefined information
func (mockDatasource) GetAllConnectedPeers() map[string]struct{} {
	return map[string]struct{}{
		"1": {},
	}
}

// GetAllAccounts returns a list of *server.Account for use in tests with predefined information
func (mockDatasource) GetAllAccounts(_ context.Context) []*types.Account {
	localUserID := dex.EncodeDexUserID("10", "local")
	idpUserID := dex.EncodeDexUserID("20", "zitadel")
	return []*types.Account{
		{
			Id:       "1",
			Settings: &types.Settings{PeerLoginExpirationEnabled: true},
			SetupKeys: map[string]*types.SetupKey{
				"1": {
					Id:        "1",
					Ephemeral: true,
					UsedTimes: 1,
				},
			},
			Groups: map[string]*types.Group{
				"1": {},
				"2": {},
			},
			NameServerGroups: map[string]*nbdns.NameServerGroup{
				"1": {},
			},
			Peers: map[string]*nbpeer.Peer{
				"1": {
					ID:         "1",
					UserID:     "test",
					SSHEnabled: false,
					Meta:       nbpeer.PeerSystemMeta{GoOS: "linux", WtVersion: "0.0.1", Flags: nbpeer.Flags{ServerSSHAllowed: true, RosenpassEnabled: true}},
				},
			},
			Policies: []*types.Policy{
				{
					Rules: []*types.PolicyRule{
						{
							Bidirectional: true,
							Protocol:      types.PolicyRuleProtocolTCP,
						},
					},
				},
				{
					Rules: []*types.PolicyRule{
						{
							Bidirectional: false,
							Protocol:      types.PolicyRuleProtocolTCP,
						},
					},
					SourcePostureChecks: []string{"1"},
				},
			},
			Routes: map[route.ID]*route.Route{
				"1": {
					ID:         "1",
					PeerGroups: make([]string, 1),
				},
			},
			PostureChecks: []*posture.Checks{
				{
					ID:   "1",
					Name: "test",
					Checks: posture.ChecksDefinition{
						NBVersionCheck: &posture.NBVersionCheck{
							MinVersion: "0.0.1",
						},
					},
				},
				{
					ID:   "2",
					Name: "tes2",
					Checks: posture.ChecksDefinition{
						NBVersionCheck: &posture.NBVersionCheck{
							MinVersion: "0.0.2",
						},
					},
				},
			},
			Users: map[string]*types.User{
				"1": {
					Id:            "1",
					IsServiceUser: true,
					PATs: map[string]*types.PersonalAccessToken{
						"1": {},
					},
				},
				localUserID: {
					Id:            localUserID,
					IsServiceUser: false,
					PATs: map[string]*types.PersonalAccessToken{
						"1": {},
					},
				},
			},
		},
		{
			Id:       "2",
			Settings: &types.Settings{PeerLoginExpirationEnabled: true},
			SetupKeys: map[string]*types.SetupKey{
				"1": {
					Id:        "1",
					Ephemeral: true,
					UsedTimes: 1,
				},
			},
			Groups: map[string]*types.Group{
				"1": {},
				"2": {},
			},
			NameServerGroups: map[string]*nbdns.NameServerGroup{
				"1": {},
			},
			Peers: map[string]*nbpeer.Peer{
				"1": {
					ID:         "1",
					UserID:     "test",
					SSHEnabled: true,
					Meta:       nbpeer.PeerSystemMeta{GoOS: "linux", WtVersion: "0.0.1"},
				},
			},
			Policies: []*types.Policy{
				{
					Rules: []*types.PolicyRule{
						{
							Bidirectional: true,
							Protocol:      types.PolicyRuleProtocolTCP,
						},
					},
				},
				{
					Rules: []*types.PolicyRule{
						{
							Bidirectional: false,
							Protocol:      types.PolicyRuleProtocolTCP,
						},
					},
				},
			},
			Routes: map[route.ID]*route.Route{
				"1": {
					ID:         "1",
					PeerGroups: make([]string, 1),
				},
			},
			Users: map[string]*types.User{
				"1": {
					Id:            "1",
					IsServiceUser: true,
					PATs: map[string]*types.PersonalAccessToken{
						"1": {},
					},
				},
				idpUserID: {
					Id:            idpUserID,
					IsServiceUser: false,
					PATs: map[string]*types.PersonalAccessToken{
						"1": {},
					},
				},
			},
			Networks: []*networkTypes.Network{
				{
					ID:        "1",
					AccountID: "1",
				},
			},
			NetworkResources: []*resourceTypes.NetworkResource{
				{
					ID:        "1",
					AccountID: "1",
					NetworkID: "1",
				},
				{
					ID:        "2",
					AccountID: "1",
					NetworkID: "1",
				},
			},
			NetworkRouters: []*routerTypes.NetworkRouter{
				{
					ID:        "1",
					AccountID: "1",
					NetworkID: "1",
				},
			},
		},
	}
}

// GetStoreEngine returns FileStoreEngine
func (mockDatasource) GetStoreEngine() types.Engine {
	return types.FileStoreEngine
}

// TestGenerateProperties tests and validate the properties generation by using the mockDatasource for the Worker.generateProperties
func TestGenerateProperties(t *testing.T) {
	ds := mockDatasource{}
	worker := Worker{
		dataSource:  ds,
		connManager: ds,
		idpManager:  EmbeddedType,
	}

	properties := worker.generateProperties(context.Background())

	if properties["accounts"] != 2 {
		t.Errorf("expected 2 accounts, got %d", properties["accounts"])
	}
	if properties["peers"] != 2 {
		t.Errorf("expected 2 peers, got %d", properties["peers"])
	}
	if properties["routes"] != 2 {
		t.Errorf("expected 2 routes, got %d", properties["routes"])
	}
	if properties["networks"] != 1 {
		t.Errorf("expected 1 networks, got %d", properties["networks"])
	}
	if properties["network_resources"] != 2 {
		t.Errorf("expected 2 network_resources, got %d", properties["network_resources"])
	}
	if properties["network_routers"] != 1 {
		t.Errorf("expected 1 network_routers, got %d", properties["network_routers"])
	}
	if properties["rules"] != 4 {
		t.Errorf("expected 4 rules, got %d", properties["rules"])
	}
	if properties["users"] != 2 {
		t.Errorf("expected 1 users, got %d", properties["users"])
	}
	if properties["setup_keys_usage"] != 2 {
		t.Errorf("expected 1 setup_keys_usage, got %d", properties["setup_keys_usage"])
	}
	if properties["pats"] != 4 {
		t.Errorf("expected 4 personal_access_tokens, got %d", properties["pats"])
	}
	if properties["peers_ssh_enabled"] != 2 {
		t.Errorf("expected 2 peers_ssh_enabled, got %d", properties["peers_ssh_enabled"])
	}
	if properties["routes_with_routing_groups"] != 2 {
		t.Errorf("expected 2 routes_with_routing_groups, got %d", properties["routes_with_routing_groups"])
	}
	if properties["rules_protocol_tcp"] != 4 {
		t.Errorf("expected 4 rules_protocol_tcp, got %d", properties["rules_protocol_tcp"])
	}
	if properties["rules_direction_oneway"] != 2 {
		t.Errorf("expected 2 rules_direction_oneway, got %d", properties["rules_direction_oneway"])
	}

	if properties["active_peers_last_day"] != 2 {
		t.Errorf("expected 2 active_peers_last_day, got %d", properties["active_peers_last_day"])
	}
	if properties["min_active_peer_version"] != "0.0.1" {
		t.Errorf("expected 0.0.1 min_active_peer_version, got %s", properties["min_active_peer_version"])
	}
	if properties["max_active_peer_version"] != "0.0.1" {
		t.Errorf("expected 0.0.1 max_active_peer_version, got %s", properties["max_active_peer_version"])
	}

	if properties["peers_login_expiration_enabled"] != 2 {
		t.Errorf("expected 2 peers_login_expiration_enabled, got %d", properties["peers_login_expiration_enabled"])
	}

	if properties["service_users"] != 2 {
		t.Errorf("expected 2 service_users, got %d", properties["service_users"])
	}

	if properties["peer_os_linux"] != 2 {
		t.Errorf("expected 2 peer_os_linux, got %d", properties["peer_os_linux"])
	}

	if properties["ephemeral_peers_setup_keys"] != 2 {
		t.Errorf("expected 2 ephemeral_peers_setup_keys, got %d", properties["ephemeral_peers_setup_keys_usage"])
	}

	if properties["ephemeral_peers_setup_keys_usage"] != 2 {
		t.Errorf("expected 2 ephemeral_peers_setup_keys_usage, got %d", properties["ephemeral_peers_setup_keys_usage"])
	}

	if properties["nameservers"] != 2 {
		t.Errorf("expected 2 nameservers, got %d", properties["nameservers"])
	}

	if properties["groups"] != 4 {
		t.Errorf("expected 4 groups, got %d", properties["groups"])
	}

	if properties["user_peers"] != 2 {
		t.Errorf("expected 2 user_peers, got %d", properties["user_peers"])
	}

	if properties["store_engine"] != types.FileStoreEngine {
		t.Errorf("expected JsonFile, got %s", properties["store_engine"])
	}

	if properties["rules_with_src_posture_checks"] != 1 {
		t.Errorf("expected 1 rules_with_src_posture_checks, got %d", properties["rules_with_src_posture_checks"])
	}

	if properties["posture_checks"] != 2 {
		t.Errorf("expected 2 posture_checks, got %d", properties["posture_checks"])
	}

	if properties["rosenpass_enabled"] != 1 {
		t.Errorf("expected 1 rosenpass_enabled, got %d", properties["rosenpass_enabled"])
	}

	if properties["active_user_peers_last_day"] != 2 {
		t.Errorf("expected 2 active_user_peers_last_day, got %d", properties["active_user_peers_last_day"])
	}

	if properties["active_users_last_day"] != 1 {
		t.Errorf("expected 1 active_users_last_day, got %d", properties["active_users_last_day"])
	}

	if properties["local_users_count"] != 1 {
		t.Errorf("expected 1 local_users_count, got %d", properties["local_users_count"])
	}
	if properties["idp_users_count"] != 1 {
		t.Errorf("expected 1 idp_users_count, got %d", properties["idp_users_count"])
	}
}
