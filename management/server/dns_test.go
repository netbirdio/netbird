package server

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
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
		t.Fatal("failed to init testing account")
	}

	dnsSettings, err := am.GetDNSSettings(context.Background(), account.Id, dnsAdminUserID)
	if err != nil {
		t.Fatalf("Got an error when trying to retrieve the DNS settings with an admin user, err: %s", err)
	}

	if dnsSettings == nil {
		t.Fatal("DNS settings for new accounts shouldn't return nil")
	}

	account.DNSSettings = DNSSettings{
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
		inputSettings *DNSSettings
		shouldFail    bool
	}{
		{
			name:   "Saving As Admin Should Be OK",
			userID: dnsAdminUserID,
			inputSettings: &DNSSettings{
				DisabledManagementGroups: []string{dnsGroup1ID},
			},
		},
		{
			name:   "Should Not Update Settings As Regular User",
			userID: dnsRegularUserID,
			inputSettings: &DNSSettings{
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
			inputSettings: &DNSSettings{
				DisabledManagementGroups: []string{"non-existing-group"},
			},
			shouldFail: true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			am, err := createDNSManager(t)
			if err != nil {
				t.Error("failed to create account manager")
			}

			account, err := initTestDNSAccount(t, am)
			if err != nil {
				t.Error("failed to init testing account")
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
		t.Error("failed to create account manager")
	}

	account, err := initTestDNSAccount(t, am)
	if err != nil {
		t.Error("failed to init testing account")
	}

	peer1, err := account.FindPeerByPubKey(dnsPeer1Key)
	if err != nil {
		t.Error("failed to init testing account")
	}

	peer2, err := account.FindPeerByPubKey(dnsPeer2Key)
	if err != nil {
		t.Error("failed to init testing account")
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

	return BuildManager(context.Background(), store, NewPeersUpdateManager(nil), nil, "", "netbird.test", eventStore, nil, false, MocIntegratedValidator{}, metrics)
}

func createDNSStore(t *testing.T) (Store, error) {
	t.Helper()
	dataDir := t.TempDir()
	store, cleanUp, err := NewTestStoreFromJson(context.Background(), dataDir)
	if err != nil {
		return nil, err
	}
	t.Cleanup(cleanUp)

	return store, nil
}

func initTestDNSAccount(t *testing.T, am *DefaultAccountManager) (*Account, error) {
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

	account := newAccountWithId(context.Background(), dnsAccountID, dnsAdminUserID, domain)

	account.Users[dnsRegularUserID] = &User{
		Id:   dnsRegularUserID,
		Role: UserRoleUser,
	}

	err := am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		return nil, err
	}

	savedPeer1, _, _, err := am.AddPeer(context.Background(), "", dnsAdminUserID, peer1)
	if err != nil {
		return nil, err
	}
	_, _, _, err = am.AddPeer(context.Background(), "", dnsAdminUserID, peer2)
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

	newGroup1 := &group.Group{
		ID:    dnsGroup1ID,
		Peers: []string{peer1.ID},
		Name:  dnsGroup1ID,
	}

	newGroup2 := &group.Group{
		ID:   dnsGroup2ID,
		Name: dnsGroup2ID,
	}

	account.Groups[newGroup1.ID] = newGroup1
	account.Groups[newGroup2.ID] = newGroup2

	allGroup, err := account.GetGroupAll()
	if err != nil {
		return nil, err
	}

	account.NameServerGroups[dnsNSGroup1] = &dns.NameServerGroup{
		ID:   dnsNSGroup1,
		Name: "ns-group-1",
		NameServers: []dns.NameServer{{
			IP:     netip.MustParseAddr(savedPeer1.IP.String()),
			NSType: dns.UDPNameServerType,
			Port:   dns.DefaultDNSPort,
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

func generateTestData(size int) nbdns.Config {
	config := nbdns.Config{
		ServiceEnable:    true,
		CustomZones:      make([]nbdns.CustomZone, size),
		NameServerGroups: make([]*nbdns.NameServerGroup, size),
	}

	for i := 0; i < size; i++ {
		config.CustomZones[i] = nbdns.CustomZone{
			Domain: fmt.Sprintf("domain%d.com", i),
			Records: []nbdns.SimpleRecord{
				{
					Name:  fmt.Sprintf("record%d", i),
					Type:  1,
					Class: "IN",
					TTL:   3600,
					RData: "192.168.1.1",
				},
			},
		}

		config.NameServerGroups[i] = &nbdns.NameServerGroup{
			ID:                   fmt.Sprintf("group%d", i),
			Primary:              i == 0,
			Domains:              []string{fmt.Sprintf("domain%d.com", i)},
			SearchDomainsEnabled: true,
			NameServers: []nbdns.NameServer{
				{
					IP:     netip.MustParseAddr("8.8.8.8"),
					Port:   53,
					NSType: 1,
				},
			},
		}
	}

	return config
}

func BenchmarkToProtocolDNSConfig(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		testData := generateTestData(size)

		b.Run(fmt.Sprintf("WithCache-Size%d", size), func(b *testing.B) {
			cache := &DNSConfigCache{}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				toProtocolDNSConfig(testData, cache)
			}
		})

		b.Run(fmt.Sprintf("WithoutCache-Size%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cache := &DNSConfigCache{}
				toProtocolDNSConfig(testData, cache)
			}
		})
	}
}

func TestToProtocolDNSConfigWithCache(t *testing.T) {
	var cache DNSConfigCache

	// Create two different configs
	config1 := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "example.com",
				Records: []nbdns.SimpleRecord{
					{Name: "www", Type: 1, Class: "IN", TTL: 300, RData: "192.168.1.1"},
				},
			},
		},
		NameServerGroups: []*nbdns.NameServerGroup{
			{
				ID:   "group1",
				Name: "Group 1",
				NameServers: []nbdns.NameServer{
					{IP: netip.MustParseAddr("8.8.8.8"), Port: 53},
				},
			},
		},
	}

	config2 := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "example.org",
				Records: []nbdns.SimpleRecord{
					{Name: "mail", Type: 1, Class: "IN", TTL: 300, RData: "192.168.1.2"},
				},
			},
		},
		NameServerGroups: []*nbdns.NameServerGroup{
			{
				ID:   "group2",
				Name: "Group 2",
				NameServers: []nbdns.NameServer{
					{IP: netip.MustParseAddr("8.8.4.4"), Port: 53},
				},
			},
		},
	}

	// First run with config1
	result1 := toProtocolDNSConfig(config1, &cache)

	// Second run with config2
	result2 := toProtocolDNSConfig(config2, &cache)

	// Third run with config1 again
	result3 := toProtocolDNSConfig(config1, &cache)

	// Verify that result1 and result3 are identical
	if !reflect.DeepEqual(result1, result3) {
		t.Errorf("Results are not identical when run with the same input. Expected %v, got %v", result1, result3)
	}

	// Verify that result2 is different from result1 and result3
	if reflect.DeepEqual(result1, result2) || reflect.DeepEqual(result2, result3) {
		t.Errorf("Results should be different for different inputs")
	}

	// Verify that the cache contains elements from both configs
	if _, exists := cache.GetCustomZone("example.com"); !exists {
		t.Errorf("Cache should contain custom zone for example.com")
	}

	if _, exists := cache.GetCustomZone("example.org"); !exists {
		t.Errorf("Cache should contain custom zone for example.org")
	}

	if _, exists := cache.GetNameServerGroup("group1"); !exists {
		t.Errorf("Cache should contain name server group 'group1'")
	}

	if _, exists := cache.GetNameServerGroup("group2"); !exists {
		t.Errorf("Cache should contain name server group 'group2'")
	}
}

func TestDNSAccountPeerUpdate(t *testing.T) {
	manager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	err := manager.SaveGroup(context.Background(), account.Id, userID, &group.Group{
		ID:    "group-id",
		Name:  "GroupA",
		Peers: []string{},
	})
	assert.NoError(t, err)

	updMsg := manager.peersUpdateManager.CreateChannel(context.Background(), peer1.ID)
	t.Cleanup(func() {
		manager.peersUpdateManager.CloseChannel(context.Background(), peer1.ID)
	})

	// Saving DNS settings with groups that have no peers should not trigger updates to account peers or send peer updates
	t.Run("saving dns setting with unused groups", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SaveDNSSettings(context.Background(), account.Id, userID, &DNSSettings{
			DisabledManagementGroups: []string{"group-id"},
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	err = manager.SaveGroup(context.Background(), account.Id, userID, &group.Group{
		ID:    "group-id",
		Name:  "GroupA",
		Peers: []string{peer1.ID, peer2.ID, peer3.ID},
	})
	assert.NoError(t, err)

	_, err = manager.CreateNameServerGroup(
		context.Background(), account.Id, "ns-group-1", "ns-group-1", []dns.NameServer{{
			IP:     netip.MustParseAddr(peer1.IP.String()),
			NSType: dns.UDPNameServerType,
			Port:   dns.DefaultDNSPort,
		}},
		[]string{"group-id"},
		true, []string{}, true, userID, false,
	)
	assert.NoError(t, err)

	// Saving DNS settings with groups that have peers should update account peers and send peer update
	t.Run("saving dns setting with used groups", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SaveDNSSettings(context.Background(), account.Id, userID, &DNSSettings{
			DisabledManagementGroups: []string{"group-id"},
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Saving unchanged DNS settings with used groups should update account peers and not send peer update
	// since there is no change in the network map
	t.Run("saving unchanged dns setting with used groups", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SaveDNSSettings(context.Background(), account.Id, userID, &DNSSettings{
			DisabledManagementGroups: []string{"group-id"},
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

}
