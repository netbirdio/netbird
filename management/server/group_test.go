package server

import (
	"testing"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/route"
)

const (
	groupAdminUserID = "testingAdminUser"
)

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
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err = am.DeleteGroup(account.Id, "", testCase.groupID)
			if err == nil {
				t.Errorf("delete %s group successfully", testCase.groupID)
				return
			}

			gErr, ok := err.(*GroupLinkError)
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

	groupForRoute := &Group{
		"grp-for-route",
		"account-id",
		"Group for route",
		GroupIssuedAPI,
		make([]string, 0),
	}

	groupForNameServerGroups := &Group{
		"grp-for-name-server-grp",
		"account-id",
		"Group for name server groups",
		GroupIssuedAPI,
		make([]string, 0),
	}

	groupForPolicies := &Group{
		"grp-for-policies",
		"account-id",
		"Group for policies",
		GroupIssuedAPI,
		make([]string, 0),
	}

	groupForSetupKeys := &Group{
		"grp-for-keys",
		"account-id",
		"Group for setup keys",
		GroupIssuedAPI,
		make([]string, 0),
	}

	groupForUsers := &Group{
		"grp-for-users",
		"account-id",
		"Group for users",
		GroupIssuedAPI,
		make([]string, 0),
	}

	routeResource := &route.Route{
		ID:     "example route",
		Groups: []string{groupForRoute.ID},
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
	account.NameServerGroups[nameServerGroup.ID] = nameServerGroup
	account.Policies = append(account.Policies, policy)
	account.SetupKeys[setupKey.Id] = setupKey
	account.Users[user.Id] = user

	err := am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	_ = am.SaveGroup(accountID, groupAdminUserID, groupForRoute)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForNameServerGroups)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForPolicies)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForSetupKeys)
	_ = am.SaveGroup(accountID, groupAdminUserID, groupForUsers)

	return am.Store.GetAccount(account.Id)
}
