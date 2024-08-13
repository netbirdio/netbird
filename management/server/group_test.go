package server

import (
	"errors"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/stretchr/testify/require"
	"testing"

	nbdns "github.com/netbirdio/netbird/dns"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/route"
)

const (
	groupAdminUserID = "testingAdminUser"
	groupPeer1Key    = "BhRPtynAAYRDy08+q4HTMsos8fs4plTP4NOSh7C1ry8="
	groupPeer2Key    = "/yF0+vCfv+mRR5k0dca0TrGdO/oiNeAI58gToZm5NyI="
)

func TestDefaultAccountManager_CreateGroup(t *testing.T) {
	am, err := createManager(t)
	if err != nil {
		t.Error("failed to create account manager")
	}

	_, account, err := initTestGroupAccount(am)
	if err != nil {
		t.Error("failed to init testing account")
	}
	for _, group := range account.Groups {
		group.Issued = nbgroup.GroupIssuedIntegration
		err = am.SaveGroup(account.Id, groupAdminUserID, group)
		if err != nil {
			t.Errorf("should allow to create %s groups", nbgroup.GroupIssuedIntegration)
		}
	}

	for _, group := range account.Groups {
		group.Issued = nbgroup.GroupIssuedJWT
		err = am.SaveGroup(account.Id, groupAdminUserID, group)
		if err != nil {
			t.Errorf("should allow to create %s groups", nbgroup.GroupIssuedJWT)
		}
	}
	for _, group := range account.Groups {
		group.Issued = nbgroup.GroupIssuedAPI
		group.ID = ""
		err = am.SaveGroup(account.Id, groupAdminUserID, group)
		if err == nil {
			t.Errorf("should not create api group with the same name, %s", group.Name)
		}
	}
}

func TestDefaultAccountManager_DeleteGroup(t *testing.T) {
	am, err := createManager(t)
	if err != nil {
		t.Error("failed to create account manager")
	}

	_, account, err := initTestGroupAccount(am)
	if err != nil {
		t.Error("failed to init testing account")
	}

	testCases := []struct {
		name           string
		groupID        string
		expectedReason string
	}{
		{
			"route",
			"grp-for-route",
			"route",
		},
		{
			"route with peer groups",
			"grp-for-route2",
			"route",
		},
		{
			"name server groups",
			"grp-for-name-server-grp",
			"name server groups",
		},
		{
			"policy",
			"grp-for-policies",
			"policy",
		},
		{
			"setup keys",
			"grp-for-keys",
			"setup key",
		},
		{
			"users",
			"grp-for-users",
			"user",
		},
		{
			"integration",
			"grp-for-integration",
			"only service users with admin power can delete integration group",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err = am.DeleteGroup(account.Id, groupAdminUserID, testCase.groupID)
			if err == nil {
				t.Errorf("delete %s group successfully", testCase.groupID)
				return
			}

			var sErr *status.Error
			if errors.As(err, &sErr) {
				if sErr.Message != testCase.expectedReason {
					t.Errorf("invalid error case: %s, expected: %s", sErr.Message, testCase.expectedReason)
				}
				return
			}

			var gErr *GroupLinkError
			ok := errors.As(err, &gErr)
			if !ok {
				t.Error("invalid error type")
				return
			}
			if gErr.Resource != testCase.expectedReason {
				t.Errorf("invalid error case: %s, expected: %s", gErr.Resource, testCase.expectedReason)
			}
		})
	}
}

func TestDefaultAccountManager_GroupIPv6Consistency(t *testing.T) {
	am, err := createManager(t)
	if err != nil {
		t.Error("failed to create account manager")
	}

	peers, account, err := initTestGroupAccount(am)
	peer1Id := peers[0]
	peer2Id := peers[1]
	if err != nil {
		t.Error("failed to init testing account")
	}

	group := account.GetGroup("grp-for-ipv6")

	// First, add one member to the IPv6 group before enabling IPv6.
	group.Peers = append(group.Peers, peer1Id)
	err = am.SaveGroup(account.Id, groupAdminUserID, group)
	require.NoError(t, err, "unable to update group")
	account, err = am.Store.GetAccount(account.Id)
	require.NoError(t, err, "unable to update account")
	group = account.GetGroup("grp-for-ipv6")
	require.Nil(t, account.Peers[peer1Id].IP6, "peer1 should not have an IPv6 address if the group doesn't have it enabled.")
	require.Nil(t, account.Peers[peer2Id].IP6, "peer2 should not have an IPv6 address.")

	// Now, enable IPv6.
	group.IPv6Enabled = true
	err = am.SaveGroup(account.Id, groupAdminUserID, group)
	require.NoError(t, err, "unable to update group")
	account, err = am.Store.GetAccount(account.Id)
	require.NoError(t, err, "unable to update account")
	group = account.GetGroup("grp-for-ipv6")
	require.NotNil(t, account.Peers[peer1Id].IP6, "peer1 should have an IPv6 address as it is a member of the IPv6-enabled group.")
	require.Nil(t, account.Peers[peer2Id].IP6, "peer2 should not have an IPv6 address as it is not a member of the IPv6-enabled group.")

	// Add the second peer.
	group.Peers = append(group.Peers, peer2Id)
	err = am.SaveGroup(account.Id, groupAdminUserID, group)
	require.NoError(t, err, "unable to update group")
	account, err = am.Store.GetAccount(account.Id)
	require.NoError(t, err, "unable to update account")
	group = account.GetGroup("grp-for-ipv6")
	require.NotNil(t, account.Peers[peer1Id].IP6, "peer1 should have an IPv6 address as it is a member of the IPv6-enabled group.")
	require.NotNil(t, account.Peers[peer2Id].IP6, "peer2 should have an IPv6 address as it is a member of the IPv6-enabled group.")

	// Disable IPv6 and simultaneously delete the first peer.
	group.IPv6Enabled = false
	group.Peers = group.Peers[1:]
	err = am.SaveGroup(account.Id, groupAdminUserID, group)
	require.NoError(t, err, "unable to update group")
	account, err = am.Store.GetAccount(account.Id)
	require.NoError(t, err, "unable to update account")
	group = account.GetGroup("grp-for-ipv6")
	require.Nil(t, account.Peers[peer1Id].IP6, "peer1 should not have an IPv6 address as it is not a member of any IPv6-enabled group.")
	require.Nil(t, account.Peers[peer2Id].IP6, "peer2 should not have an IPv6 address as the group has IPv6 disabled.")

	// Enable IPv6 and simultaneously add the first peer again.
	group.IPv6Enabled = true
	group.Peers = append(group.Peers, peer1Id)
	err = am.SaveGroup(account.Id, groupAdminUserID, group)
	require.NoError(t, err, "unable to update group")
	account, err = am.Store.GetAccount(account.Id)
	require.NoError(t, err, "unable to update account")
	require.NotNil(t, account.Peers[peer1Id].IP6, "peer1 should have an IPv6 address as it is a member of the IPv6-enabled group.")
	require.NotNil(t, account.Peers[peer2Id].IP6, "peer2 should have an IPv6 address as it is a member of the IPv6-enabled group.")

	// Force disable IPv6.
	peer1 := account.GetPeer(peer1Id)
	peer2 := account.GetPeer(peer2Id)
	peer1.V6Setting = nbpeer.V6Disabled
	peer2.V6Setting = nbpeer.V6Disabled
	_, err = am.UpdatePeer(account.Id, groupAdminUserID, peer1)
	require.NoError(t, err, "unable to update peer1")
	_, err = am.UpdatePeer(account.Id, groupAdminUserID, peer2)
	require.NoError(t, err, "unable to update peer2")
	account, err = am.Store.GetAccount(account.Id)
	require.NoError(t, err, "unable to fetch updated account")
	group = account.GetGroup("grp-for-ipv6")
	require.Nil(t, account.GetPeer(peer1Id).IP6, "peer1 should not have an IPv6 address as it is force disabled.")
	require.Nil(t, account.GetPeer(peer2Id).IP6, "peer2 should not have an IPv6 address as it is force disabled.")

	// Delete Group.
	err = am.DeleteGroup(account.Id, groupAdminUserID, group.ID)
	require.NoError(t, err, "unable to delete group")
	account, err = am.Store.GetAccount(account.Id)
	require.NoError(t, err, "unable to update account")
	group = account.GetGroup("grp-for-ipv6")
	require.Nil(t, group, "Group should no longer exist.")
	require.Nil(t, account.Peers[peer1Id].IP6, "peer1 should not have an IPv6 address as the only IPv6-enabled group was deleted.")
	require.Nil(t, account.Peers[peer2Id].IP6, "peer2 should not have an IPv6 address as the only IPv6-enabled group was deleted.")
}

func initTestGroupAccount(am *DefaultAccountManager) ([]string, *Account, error) {
	accountID := "testingAcc"
	domain := "example.com"

	peer1 := &nbpeer.Peer{
		Key:  peer1Key,
		Name: "peer1",
		Meta: nbpeer.PeerSystemMeta{
			Hostname:      "test-host1@netbird.io",
			GoOS:          "linux",
			Kernel:        "Linux",
			Core:          "21.04",
			Platform:      "x86_64",
			OS:            "Ubuntu",
			WtVersion:     "development",
			UIVersion:     "development",
			Ipv6Supported: true,
		},
		V6Setting: nbpeer.V6Auto,
		DNSLabel:  groupPeer1Key,
	}
	peer2 := &nbpeer.Peer{
		Key:  peer2Key,
		Name: "peer2",
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
		V6Setting: nbpeer.V6Auto,
		DNSLabel:  groupPeer2Key,
	}

	groupForRoute := &nbgroup.Group{
		ID:        "grp-for-route",
		AccountID: "account-id",
		Name:      "Group for route",
		Issued:    nbgroup.GroupIssuedAPI,
		Peers:     make([]string, 0),
	}

	groupForRoute2 := &nbgroup.Group{
		ID:        "grp-for-route2",
		AccountID: "account-id",
		Name:      "Group for route",
		Issued:    nbgroup.GroupIssuedAPI,
		Peers:     make([]string, 0),
	}

	groupForNameServerGroups := &nbgroup.Group{
		ID:        "grp-for-name-server-grp",
		AccountID: "account-id",
		Name:      "Group for name server groups",
		Issued:    nbgroup.GroupIssuedAPI,
		Peers:     make([]string, 0),
	}

	groupForPolicies := &nbgroup.Group{
		ID:        "grp-for-policies",
		AccountID: "account-id",
		Name:      "Group for policies",
		Issued:    nbgroup.GroupIssuedAPI,
		Peers:     make([]string, 0),
	}

	groupForSetupKeys := &nbgroup.Group{
		ID:        "grp-for-keys",
		AccountID: "account-id",
		Name:      "Group for setup keys",
		Issued:    nbgroup.GroupIssuedAPI,
		Peers:     make([]string, 0),
	}

	groupForUsers := &nbgroup.Group{
		ID:        "grp-for-users",
		AccountID: "account-id",
		Name:      "Group for users",
		Issued:    nbgroup.GroupIssuedAPI,
		Peers:     make([]string, 0),
	}

	groupForIntegration := &nbgroup.Group{
		ID:        "grp-for-integration",
		AccountID: "account-id",
		Name:      "Group for users integration",
		Issued:    nbgroup.GroupIssuedIntegration,
		Peers:     make([]string, 0),
	}

	groupForIPv6 := &nbgroup.Group{
		ID:        "grp-for-ipv6",
		AccountID: "account-id",
		Name:      "Group for IPv6",
		Issued:    nbgroup.GroupIssuedAPI,
		Peers:     make([]string, 0),
	}

	routeResource := &route.Route{
		ID:     "example route",
		Groups: []string{groupForRoute.ID},
	}

	routePeerGroupResource := &route.Route{
		ID:         "example route with peer groups",
		PeerGroups: []string{groupForRoute2.ID},
	}

	nameServerGroup := &nbdns.NameServerGroup{
		ID:     "example name server group",
		Groups: []string{groupForNameServerGroups.ID},
	}

	policy := &Policy{
		ID: "example policy",
		Rules: []*PolicyRule{
			{
				ID:           "example policy rule",
				Destinations: []string{groupForPolicies.ID},
			},
		},
	}

	setupKey := &SetupKey{
		Id:         "example setup key",
		AutoGroups: []string{groupForSetupKeys.ID},
	}

	user := &User{
		Id:         "example user",
		AutoGroups: []string{groupForUsers.ID},
	}
	account := newAccountWithId(accountID, groupAdminUserID, domain)
	account.Routes[routeResource.ID] = routeResource
	account.Routes[routePeerGroupResource.ID] = routePeerGroupResource
	account.NameServerGroups[nameServerGroup.ID] = nameServerGroup
	account.Policies = append(account.Policies, policy)
	account.SetupKeys[setupKey.Id] = setupKey
	account.Users[user.Id] = user

	err := am.Store.SaveAccount(account)
	if err != nil {
		return nil, nil, err
	}

	_ = am.SaveGroup(accountID, groupAdminUserID, groupForRoute)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForRoute2)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForNameServerGroups)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForPolicies)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForSetupKeys)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForUsers)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForIntegration)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForIPv6)
	peer1, _, _ = am.AddPeer(setupKey.Key, user.Id, peer1)
	peer2, _, _ = am.AddPeer(setupKey.Key, user.Id, peer2)

	account, err = am.Store.GetAccount(account.Id)

	return []string{peer1.ID, peer2.ID}, account, err
}
