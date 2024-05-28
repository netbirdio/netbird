package server

import (
	"errors"
	"testing"

	nbdns "github.com/netbirdio/netbird/dns"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/route"
)

const (
	groupAdminUserID = "testingAdminUser"
)

func TestDefaultAccountManager_CreateGroup(t *testing.T) {
	am, err := createManager(t)
	if err != nil {
		t.Error("failed to create account manager")
	}

	account, err := initTestGroupAccount(am)
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

	account, err := initTestGroupAccount(am)
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

func initTestGroupAccount(am *DefaultAccountManager) (*Account, error) {
	accountID := "testingAcc"
	domain := "example.com"

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
		return nil, err
	}

	_ = am.SaveGroup(accountID, groupAdminUserID, groupForRoute)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForRoute2)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForNameServerGroups)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForPolicies)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForSetupKeys)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForUsers)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForIntegration)

	return am.Store.GetAccount(account.Id)
}
