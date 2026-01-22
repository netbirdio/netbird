package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	ephemeral_manager "github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/job"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	dnsGroup1ID      = "group1"
	dnsGroup2ID      = "group2"
	dnsPeer1Key      = "BhRPtynAAYRDy08+q4HTMsos8fs4plTP4NOSh7C1ry8="
	dnsPeer2Key      = "/yF0+vCfv+mRR5k0dca0TrGdO/oiNeAI58gToZm5NyI="
	dnsAccountID     = "testingAcc"
	dnsAdminUserID   = "testingAdminUser"
	dnsRegularUserID = "testingRegularUser"
	dnsNSGroup1      = "ns1"
)

func TestGetDNSSettings(t *testing.T) {
	am, err := createDNSManager(t)
	if err != nil {
		t.Error("failed to create account manager")
	}

	account, err := initTestDNSAccount(t, am)
	if err != nil {
		t.Fatalf("failed to init testing account: %s", err)
	}

	dnsSettings, err := am.GetDNSSettings(context.Background(), account.Id, dnsAdminUserID)
	if err != nil {
		t.Fatalf("Got an error when trying to retrieve the DNS settings with an admin user, err: %s", err)
	}

	if dnsSettings == nil {
		t.Fatal("DNS settings for new accounts shouldn't return nil")
	}

	account.DNSSettings = types.DNSSettings{
		DisabledManagementGroups: []string{group1ID},
	}

	err = am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Error("failed to save testing account with new DNS settings")
	}

	dnsSettings, err = am.GetDNSSettings(context.Background(), account.Id, dnsAdminUserID)
	if err != nil {
		t.Errorf("Got an error when trying to retrieve the DNS settings with an admin user, err: %s", err)
	}

	if len(dnsSettings.DisabledManagementGroups) != 1 {
		t.Errorf("DNS settings should have one disabled mgmt group, groups: %s", dnsSettings.DisabledManagementGroups)
	}

	_, err = am.GetDNSSettings(context.Background(), account.Id, dnsRegularUserID)
	if err == nil {
		t.Errorf("An error should be returned when getting the DNS settings with a regular user")
	}

	s, ok := status.FromError(err)
	if !ok && s.Type() != status.PermissionDenied {
		t.Errorf("returned error should be Permission Denied, got err: %s", err)
	}
}

func TestSaveDNSSettings(t *testing.T) {
	testCases := []struct {
		name          string
		userID        string
		inputSettings *types.DNSSettings
		shouldFail    bool
	}{
		{
			name:   "Saving As Admin Should Be OK",
			userID: dnsAdminUserID,
			inputSettings: &types.DNSSettings{
				DisabledManagementGroups: []string{dnsGroup1ID},
			},
		},
		{
			name:   "Should Not Update Settings As Regular User",
			userID: dnsRegularUserID,
			inputSettings: &types.DNSSettings{
				DisabledManagementGroups: []string{dnsGroup1ID},
			},
			shouldFail: true,
		},
		{
			name:          "Should Not Update Settings If Input is Nil",
			userID:        dnsAdminUserID,
			inputSettings: nil,
			shouldFail:    true,
		},
		{
			name:   "Should Not Update Settings If Group Is Invalid",
			userID: dnsAdminUserID,
			inputSettings: &types.DNSSettings{
				DisabledManagementGroups: []string{"non-existing-group"},
			},
			shouldFail: true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			am, err := createDNSManager(t)
			if err != nil {
				t.Fatalf("failed to create account manager")
			}

			account, err := initTestDNSAccount(t, am)
			if err != nil {
				t.Fatalf("failed to init testing account: %v", err)
			}

			err = am.SaveDNSSettings(context.Background(), account.Id, testCase.userID, testCase.inputSettings)
			if err != nil {
				if testCase.shouldFail {
					return
				}
				t.Error(err)
			}

			updatedAccount, err := am.Store.GetAccount(context.Background(), account.Id)
			if err != nil {
				t.Errorf("should be able to retrieve updated account, got err: %s", err)
			}

			require.ElementsMatchf(t, testCase.inputSettings.DisabledManagementGroups, updatedAccount.DNSSettings.DisabledManagementGroups,
				"resulting DNS settings should match input")

		})
	}
}

func TestGetNetworkMap_DNSConfigSync(t *testing.T) {

	am, err := createDNSManager(t)
	if err != nil {
		t.Fatalf("failed to create account manager: %s", err)
	}

	account, err := initTestDNSAccount(t, am)
	if err != nil {
		t.Fatalf("failed to init testing account: %s", err)
	}

	peer1, err := account.FindPeerByPubKey(dnsPeer1Key)
	if err != nil {
		t.Fatalf("failed to init testing account: %s", err)
	}

	peer2, err := account.FindPeerByPubKey(dnsPeer2Key)
	if err != nil {
		t.Fatalf("failed to init testing account: %s", err)
	}

	newAccountDNSConfig, err := am.GetNetworkMap(context.Background(), peer1.ID)
	require.NoError(t, err)
	require.Len(t, newAccountDNSConfig.DNSConfig.CustomZones, 1, "default DNS config should have one custom zone for peers")
	require.True(t, newAccountDNSConfig.DNSConfig.ServiceEnable, "default DNS config should have local DNS service enabled")
	require.Len(t, newAccountDNSConfig.DNSConfig.NameServerGroups, 0, "updated DNS config should have no nameserver groups since peer 1 is NS for the only existing NS group")

	dnsSettings := account.DNSSettings.Copy()
	dnsSettings.DisabledManagementGroups = append(dnsSettings.DisabledManagementGroups, dnsGroup1ID)
	account.DNSSettings = dnsSettings
	err = am.Store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	updatedAccountDNSConfig, err := am.GetNetworkMap(context.Background(), peer1.ID)
	require.NoError(t, err)
	require.Len(t, updatedAccountDNSConfig.DNSConfig.CustomZones, 0, "updated DNS config should have no custom zone when peer belongs to a disabled group")
	require.False(t, updatedAccountDNSConfig.DNSConfig.ServiceEnable, "updated DNS config should have local DNS service disabled when peer belongs to a disabled group")
	peer2AccountDNSConfig, err := am.GetNetworkMap(context.Background(), peer2.ID)
	require.NoError(t, err)
	require.Len(t, peer2AccountDNSConfig.DNSConfig.CustomZones, 1, "DNS config should have one custom zone for peers not in the disabled group")
	require.True(t, peer2AccountDNSConfig.DNSConfig.ServiceEnable, "DNS config should have DNS service enabled for peers not in the disabled group")
	require.Len(t, peer2AccountDNSConfig.DNSConfig.NameServerGroups, 1, "updated DNS config should have 1 nameserver groups since peer 2 is part of the group All")
}

func createDNSManager(t *testing.T) (*DefaultAccountManager, error) {
	t.Helper()
	store, err := createDNSStore(t)
	if err != nil {
		return nil, err
	}
	eventStore := &activity.InMemoryEventStore{}

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	settingsMockManager := settings.NewMockManager(ctrl)
	// return empty extra settings for expected calls to UpdateAccountPeers
	settingsMockManager.EXPECT().GetExtraSettings(gomock.Any(), gomock.Any()).Return(&types.ExtraSettings{}, nil).AnyTimes()
	permissionsManager := permissions.NewManager(store)
	peersManager := peers.NewManager(store, permissionsManager)

	ctx := context.Background()
	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := NewAccountRequestBuffer(ctx, store)
	networkMapController := controller.NewController(ctx, store, metrics, updateManager, requestBuffer, MockIntegratedValidator{}, settingsMockManager, "netbird.test", port_forwarding.NewControllerMock(), ephemeral_manager.NewEphemeralManager(store, peers.NewManager(store, permissionsManager)), &config.Config{})

	return BuildManager(context.Background(), nil, store, networkMapController, job.NewJobManager(nil, store, peersManager), nil, "", eventStore, nil, false, MockIntegratedValidator{}, metrics, port_forwarding.NewControllerMock(), settingsMockManager, permissionsManager, false)
}

func createDNSStore(t *testing.T) (store.Store, error) {
	t.Helper()
	dataDir := t.TempDir()
	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "", dataDir)
	if err != nil {
		return nil, err
	}
	t.Cleanup(cleanUp)

	return store, nil
}

func initTestDNSAccount(t *testing.T, am *DefaultAccountManager) (*types.Account, error) {
	t.Helper()
	peer1 := &nbpeer.Peer{
		Key:  dnsPeer1Key,
		Name: "test-host1@netbird.io",
		Meta: nbpeer.PeerSystemMeta{
			Hostname:  "test-host1@netbird.io",
			GoOS:      "linux",
			Kernel:    "Linux",
			Core:      "21.04",
			Platform:  "x86_64",
			OS:        "Ubuntu",
			WtVersion: "development",
			UIVersion: "development",
		},
		DNSLabel: dnsPeer1Key,
	}
	peer2 := &nbpeer.Peer{
		Key:  dnsPeer2Key,
		Name: "test-host2@netbird.io",
		Meta: nbpeer.PeerSystemMeta{
			Hostname:  "test-host2@netbird.io",
			GoOS:      "linux",
			Kernel:    "Linux",
			Core:      "21.04",
			Platform:  "x86_64",
			OS:        "Ubuntu",
			WtVersion: "development",
			UIVersion: "development",
		},
		DNSLabel: dnsPeer2Key,
	}

	domain := "example.com"

	account := newAccountWithId(context.Background(), dnsAccountID, dnsAdminUserID, domain, "", "", false)

	account.Users[dnsRegularUserID] = &types.User{
		Id:   dnsRegularUserID,
		Role: types.UserRoleUser,
	}

	err := am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		return nil, err
	}

	savedPeer1, _, _, err := am.AddPeer(context.Background(), "", "", dnsAdminUserID, peer1, false)
	if err != nil {
		return nil, err
	}
	_, _, _, err = am.AddPeer(context.Background(), "", "", dnsAdminUserID, peer2, false)
	if err != nil {
		return nil, err
	}

	account, err = am.Store.GetAccount(context.Background(), account.Id)
	if err != nil {
		return nil, err
	}

	peer1, err = account.FindPeerByPubKey(peer1.Key)
	if err != nil {
		return nil, err
	}

	_, err = account.FindPeerByPubKey(peer2.Key)
	if err != nil {
		return nil, err
	}

	newGroup1 := &types.Group{
		ID:    dnsGroup1ID,
		Peers: []string{peer1.ID},
		Name:  dnsGroup1ID,
	}

	newGroup2 := &types.Group{
		ID:   dnsGroup2ID,
		Name: dnsGroup2ID,
	}

	account.Groups[newGroup1.ID] = newGroup1
	account.Groups[newGroup2.ID] = newGroup2

	allGroup, err := account.GetGroupAll()
	if err != nil {
		return nil, err
	}

	account.NameServerGroups[dnsNSGroup1] = &nbdns.NameServerGroup{
		ID:   dnsNSGroup1,
		Name: "ns-group-1",
		NameServers: []nbdns.NameServer{{
			IP:     netip.MustParseAddr(savedPeer1.IP.String()),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		}},
		Primary: true,
		Enabled: true,
		Groups:  []string{allGroup.ID},
	}

	err = am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		return nil, err
	}

	return am.Store.GetAccount(context.Background(), account.Id)
}

func TestDNSAccountPeersUpdate(t *testing.T) {
	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	err := manager.CreateGroups(context.Background(), account.Id, userID, []*types.Group{
		{
			ID:    "groupA",
			Name:  "GroupA",
			Peers: []string{},
		},
		{
			ID:    "groupB",
			Name:  "GroupB",
			Peers: []string{},
		},
	})
	assert.NoError(t, err)

	updMsg := updateManager.CreateChannel(context.Background(), peer1.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(context.Background(), peer1.ID)
	})

	// Saving DNS settings with groups that have no peers should not trigger updates to account peers or send peer updates
	t.Run("saving dns setting with unused groups", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SaveDNSSettings(context.Background(), account.Id, userID, &types.DNSSettings{
			DisabledManagementGroups: []string{"groupA"},
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// Creating DNS settings with groups that have no peers should not update account peers or send peer update
	t.Run("creating dns setting with unused groups", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err = manager.CreateNameServerGroup(
			context.Background(), account.Id, "ns-group", "ns-group", []nbdns.NameServer{{
				IP:     netip.MustParseAddr(peer1.IP.String()),
				NSType: nbdns.UDPNameServerType,
				Port:   nbdns.DefaultDNSPort,
			}},
			[]string{"groupB"},
			true, []string{}, true, userID, false,
		)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// Creating DNS settings with groups that have peers should update account peers and send peer update
	t.Run("creating dns setting with used groups", func(t *testing.T) {
		err = manager.UpdateGroup(context.Background(), account.Id, userID, &types.Group{
			ID:    "groupA",
			Name:  "GroupA",
			Peers: []string{peer1.ID, peer2.ID, peer3.ID},
		})
		assert.NoError(t, err)

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err = manager.CreateNameServerGroup(
			context.Background(), account.Id, "ns-group-1", "ns-group-1", []nbdns.NameServer{{
				IP:     netip.MustParseAddr(peer1.IP.String()),
				NSType: nbdns.UDPNameServerType,
				Port:   nbdns.DefaultDNSPort,
			}},
			[]string{"groupA"},
			true, []string{}, true, userID, false,
		)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Saving DNS settings with groups that have peers should update account peers and send peer update
	t.Run("saving dns setting with used groups", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SaveDNSSettings(context.Background(), account.Id, userID, &types.DNSSettings{
			DisabledManagementGroups: []string{"groupA", "groupB"},
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Removing group with no peers from DNS settings  should not trigger updates to account peers or send peer updates
	t.Run("removing group with no peers from dns settings", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SaveDNSSettings(context.Background(), account.Id, userID, &types.DNSSettings{
			DisabledManagementGroups: []string{"groupA"},
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// Removing group with peers from DNS settings should trigger updates to account peers and send peer updates
	t.Run("removing group with peers from dns settings", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SaveDNSSettings(context.Background(), account.Id, userID, &types.DNSSettings{
			DisabledManagementGroups: []string{},
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})
}
