package server

import (
	"net/netip"
	"testing"

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
	dnsNSGroup2      = "ns2"
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

	dnsSettings, err := am.GetDNSSettings(account.Id, dnsAdminUserID)
	if err != nil {
		t.Fatalf("Got an error when trying to retrieve the DNS settings with an admin user, err: %s", err)
	}

	if dnsSettings == nil {
		t.Fatal("DNS settings for new accounts shouldn't return nil")
	}

	account.DNSSettings = DNSSettings{
		DisabledManagementGroups: []string{group1ID},
	}

	err = am.Store.SaveAccount(account)
	if err != nil {
		t.Error("failed to save testing account with new DNS settings")
	}

	dnsSettings, err = am.GetDNSSettings(account.Id, dnsAdminUserID)
	if err != nil {
		t.Errorf("Got an error when trying to retrieve the DNS settings with an admin user, err: %s", err)
	}

	if len(dnsSettings.DisabledManagementGroups) != 1 {
		t.Errorf("DNS settings should have one disabled mgmt group, groups: %s", dnsSettings.DisabledManagementGroups)
	}

	_, err = am.GetDNSSettings(account.Id, dnsRegularUserID)
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

			err = am.SaveDNSSettings(account.Id, testCase.userID, testCase.inputSettings)
			if err != nil {
				if testCase.shouldFail {
					return
				}
				t.Error(err)
			}

			updatedAccount, err := am.Store.GetAccount(account.Id)
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

	newAccountDNSConfig, err := am.GetNetworkMap(peer1.ID)
	require.NoError(t, err)
	require.Len(t, newAccountDNSConfig.DNSConfig.CustomZones, 1, "default DNS config should have one custom zone for peers")
	require.True(t, newAccountDNSConfig.DNSConfig.ServiceEnable, "default DNS config should have local DNS service enabled")
	require.Len(t, newAccountDNSConfig.DNSConfig.NameServerGroups, 0, "updated DNS config should have no nameserver groups since peer 1 is NS for the only existing NS group")

	dnsSettings := account.DNSSettings.Copy()
	dnsSettings.DisabledManagementGroups = append(dnsSettings.DisabledManagementGroups, dnsGroup1ID)
	account.DNSSettings = dnsSettings
	err = am.Store.SaveAccount(account)
	require.NoError(t, err)

	updatedAccountDNSConfig, err := am.GetNetworkMap(peer1.ID)
	require.NoError(t, err)
	require.Len(t, updatedAccountDNSConfig.DNSConfig.CustomZones, 0, "updated DNS config should have no custom zone when peer belongs to a disabled group")
	require.False(t, updatedAccountDNSConfig.DNSConfig.ServiceEnable, "updated DNS config should have local DNS service disabled when peer belongs to a disabled group")
	peer2AccountDNSConfig, err := am.GetNetworkMap(peer2.ID)
	require.NoError(t, err)
	require.Len(t, peer2AccountDNSConfig.DNSConfig.CustomZones, 1, "DNS config should have one custom zone for peers not in the disabled group")
	require.True(t, peer2AccountDNSConfig.DNSConfig.ServiceEnable, "DNS config should have DNS service enabled for peers not in the disabled group")
	require.Len(t, peer2AccountDNSConfig.DNSConfig.NameServerGroups, 2, "updated DNS config should have 2 nameserver groups since peer 2 is part of the group All and supports IPv6")
}

func createDNSManager(t *testing.T) (*DefaultAccountManager, error) {
	t.Helper()
	store, err := createDNSStore(t)
	if err != nil {
		return nil, err
	}
	eventStore := &activity.InMemoryEventStore{}
	return BuildManager(store, NewPeersUpdateManager(nil), nil, "", "netbird.test", eventStore, nil, false, MocIntegratedValidator{})
}

func createDNSStore(t *testing.T) (Store, error) {
	t.Helper()
	dataDir := t.TempDir()
	store, cleanUp, err := NewTestStoreFromJson(dataDir)
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
			Hostname:      "test-host1@netbird.io",
			GoOS:          "linux",
			Kernel:        "Linux",
			Core:          "21.04",
			Platform:      "x86_64",
			OS:            "Ubuntu",
			WtVersion:     "development",
			UIVersion:     "development",
			Ipv6Supported: false,
		},
		DNSLabel: dnsPeer1Key,
	}
	peer2 := &nbpeer.Peer{
		Key:  dnsPeer2Key,
		Name: "test-host2@netbird.io",
		Meta: nbpeer.PeerSystemMeta{
			Hostname:      "test-host2@netbird.io",
			GoOS:          "linux",
			Kernel:        "Linux",
			Core:          "21.04",
			Platform:      "x86_64",
			OS:            "Ubuntu",
			WtVersion:     "development",
			UIVersion:     "development",
			Ipv6Supported: true,
		},
		V6Setting: nbpeer.V6Enabled,
		DNSLabel:  dnsPeer2Key,
	}

	domain := "example.com"

	account := newAccountWithId(dnsAccountID, dnsAdminUserID, domain)

	account.Users[dnsRegularUserID] = &User{
		Id:   dnsRegularUserID,
		Role: UserRoleUser,
	}

	err := am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	savedPeer1, _, err := am.AddPeer("", dnsAdminUserID, peer1)
	if err != nil {
		return nil, err
	}
	_, _, err = am.AddPeer("", dnsAdminUserID, peer2)
	if err != nil {
		return nil, err
	}

	account, err = am.Store.GetAccount(account.Id)
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

	account.NameServerGroups[dnsNSGroup2] = &dns.NameServerGroup{
		ID:   dnsNSGroup2,
		Name: "ns-group-2",
		NameServers: []dns.NameServer{{
			IP:     netip.MustParseAddr("2001:4860:4860:0:0:0:0:8888"), // Google DNS
			NSType: dns.UDPNameServerType,
			Port:   dns.DefaultDNSPort,
		}},
		Primary: false,
		Domains: []string{"example.com"},
		Enabled: true,
		Groups:  []string{allGroup.ID},
	}

	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	return am.Store.GetAccount(account.Id)
}
