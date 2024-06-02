package metrics

import (
	"testing"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
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
func (mockDatasource) GetAllAccounts() []*server.Account {
	return []*server.Account{
		{
			Id:       "1",
			Settings: &server.Settings{PeerLoginExpirationEnabled: true},
			SetupKeys: map[string]*server.SetupKey{
				"1": {
					Id:        "1",
					Ephemeral: true,
					UsedTimes: 1,
				},
			},
			Groups: map[string]*group.Group{
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
			Policies: []*server.Policy{
				{
					Rules: []*server.PolicyRule{
						{
							Bidirectional: true,
							Protocol:      server.PolicyRuleProtocolTCP,
						},
					},
				},
				{
					Rules: []*server.PolicyRule{
						{
							Bidirectional: false,
							Protocol:      server.PolicyRuleProtocolTCP,
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
			Users: map[string]*server.User{
				"1": {
					IsServiceUser: true,
					PATs: map[string]*server.PersonalAccessToken{
						"1": {},
					},
				},
				"2": {
					IsServiceUser: false,
					PATs: map[string]*server.PersonalAccessToken{
						"1": {},
					},
				},
			},
		},
		{
			Id:       "2",
			Settings: &server.Settings{PeerLoginExpirationEnabled: true},
			SetupKeys: map[string]*server.SetupKey{
				"1": {
					Id:        "1",
					Ephemeral: true,
					UsedTimes: 1,
				},
			},
			Groups: map[string]*group.Group{
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
			Policies: []*server.Policy{
				{
					Rules: []*server.PolicyRule{
						{
							Bidirectional: true,
							Protocol:      server.PolicyRuleProtocolTCP,
						},
					},
				},
				{
					Rules: []*server.PolicyRule{
						{
							Bidirectional: false,
							Protocol:      server.PolicyRuleProtocolTCP,
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
			Users: map[string]*server.User{
				"1": {
					IsServiceUser: true,
					PATs: map[string]*server.PersonalAccessToken{
						"1": {},
					},
				},
				"2": {
					IsServiceUser: false,
					PATs: map[string]*server.PersonalAccessToken{
						"1": {},
					},
				},
			},
		},
	}
}

// GetStoreEngine returns FileStoreEngine
func (mockDatasource) GetStoreEngine() server.StoreEngine {
	return server.FileStoreEngine
}

// TestGenerateProperties tests and validate the properties generation by using the mockDatasource for the Worker.generateProperties
func TestGenerateProperties(t *testing.T) {
	ds := mockDatasource{}
	worker := Worker{
		dataSource:  ds,
		connManager: ds,
	}

	properties := worker.generateProperties()

	if properties["accounts"] != 2 {
		t.Errorf("expected 2 accounts, got %d", properties["accounts"])
	}
	if properties["peers"] != 2 {
		t.Errorf("expected 2 peers, got %d", properties["peers"])
	}
	if properties["routes"] != 2 {
		t.Errorf("expected 2 routes, got %d", properties["routes"])
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

	if properties["store_engine"] != server.FileStoreEngine {
		t.Errorf("expected JsonFile, got %s", properties["store_engine"])
	}

	if properties["rules_with_src_posture_checks"] != 1 {
		t.Errorf("expected 1 rules_with_src_posture_checks, got %d", properties["rules_with_src_posture_checks"])
	}

	if properties["posture_checks"] != 2 {
		t.Errorf("expected 1 posture_checks, got %d", properties["posture_checks"])
	}

}
