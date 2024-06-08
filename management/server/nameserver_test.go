package server

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/activity"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

const (
	group1ID            = "group1"
	group2ID            = "group2"
	existingNSGroupName = "existing"
	existingNSGroupID   = "existingNSGroup"
	nsGroupPeer1Key     = "BhRPtynAAYRDy08+q4HTMsos8fs4plTP4NOSh7C1ry8="
	nsGroupPeer2Key     = "/yF0+vCfv+mRR5k0dca0TrGdO/oiNeAI58gToZm5NyI="
	validDomain         = "example.com"
	invalidDomain       = "dnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdns.com"
	testUserID          = "testingUser"
)

func TestCreateNameServerGroup(t *testing.T) {
	type input struct {
		name          string
		description   string
		enabled       bool
		groups        []string
		nameServers   []nbdns.NameServer
		primary       bool
		domains       []string
		searchDomains bool
	}

	testCases := []struct {
		name            string
		inputArgs       input
		shouldCreate    bool
		errFunc         require.ErrorAssertionFunc
		expectedNSGroup *nbdns.NameServerGroup
	}{
		{
			name: "Create A NS Group With Primary Status",
			inputArgs: input{
				name:        "super",
				description: "super",
				groups:      []string{group1ID},
				primary:     true,
				nameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.2.2"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				enabled: true,
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedNSGroup: &nbdns.NameServerGroup{
				Name:        "super",
				Description: "super",
				Primary:     true,
				Groups:      []string{group1ID},
				NameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.2.2"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				Enabled: true,
			},
		},
		{
			name: "Create A NS Group With Domains",
			inputArgs: input{
				name:        "super",
				description: "super",
				groups:      []string{group1ID},
				primary:     false,
				domains:     []string{validDomain},
				nameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.2.2"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				enabled: true,
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedNSGroup: &nbdns.NameServerGroup{
				Name:        "super",
				Description: "super",
				Primary:     false,
				Domains:     []string{"example.com"},
				Groups:      []string{group1ID},
				NameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.2.2"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				Enabled: true,
			},
		},
		{
			name: "Should Not Create If Name Exist",
			inputArgs: input{
				name:        existingNSGroupName,
				description: "super",
				primary:     true,
				groups:      []string{group1ID},
				nameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.2.2"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				enabled: true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Should Not Create If Name Is Small",
			inputArgs: input{
				name:        "",
				description: "super",
				primary:     true,
				groups:      []string{group1ID},
				nameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.2.2"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				enabled: true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Should Not Create If Name Is Large",
			inputArgs: input{
				name:        "1234567890123456789012345678901234567890extra",
				description: "super",
				primary:     true,
				groups:      []string{group1ID},
				nameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.2.2"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				enabled: true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Create A NS Group With No Nameservers Should Fail",
			inputArgs: input{
				name:        "super",
				description: "super",
				primary:     true,
				groups:      []string{group1ID},
				nameServers: []nbdns.NameServer{},
				enabled:     true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Create A NS Group With More Than 3 Nameservers Should Fail",
			inputArgs: input{
				name:        "super",
				description: "super",
				primary:     true,
				groups:      []string{group1ID},
				nameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.2.2"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.3.3"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.4.4"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				enabled: true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Should Not Create If Groups Is Empty",
			inputArgs: input{
				name:        "super",
				description: "super",
				primary:     true,
				groups:      []string{},
				nameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.2.2"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				enabled: true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Should Not Create If Group Doesn't Exist",
			inputArgs: input{
				name:        "super",
				description: "super",
				primary:     true,
				groups:      []string{"missingGroup"},
				nameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.2.2"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				enabled: true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Should Not Create If Group ID Is Invalid",
			inputArgs: input{
				name:        "super",
				description: "super",
				primary:     true,
				groups:      []string{""},
				nameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.2.2"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				enabled: true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Should Not Create If No Domain Or Primary",
			inputArgs: input{
				name:        "super",
				description: "super",
				groups:      []string{group1ID},
				nameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.2.2"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				enabled: true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Should Not Create If Domain List Is Invalid",
			inputArgs: input{
				name:        "super",
				description: "super",
				groups:      []string{group1ID},
				domains:     []string{invalidDomain},
				nameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("1.1.1.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("1.1.2.2"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				enabled: true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			am, err := createNSManager(t)
			if err != nil {
				t.Error("failed to create account manager")
			}

			account, err := initTestNSAccount(t, am)
			if err != nil {
				t.Error("failed to init testing account")
			}

			outNSGroup, err := am.CreateNameServerGroup(
				account.Id,
				testCase.inputArgs.name,
				testCase.inputArgs.description,
				testCase.inputArgs.nameServers,
				testCase.inputArgs.groups,
				testCase.inputArgs.primary,
				testCase.inputArgs.domains,
				testCase.inputArgs.enabled,
				userID,
				testCase.inputArgs.searchDomains,
			)

			testCase.errFunc(t, err)

			if !testCase.shouldCreate {
				return
			}

			// assign generated ID
			testCase.expectedNSGroup.ID = outNSGroup.ID

			if !testCase.expectedNSGroup.IsEqual(outNSGroup) {
				t.Errorf("new nameserver group didn't match expected ns group:\nGot %#v\nExpected:%#v\n", outNSGroup, testCase.expectedNSGroup)
			}
		})
	}
}

func TestSaveNameServerGroup(t *testing.T) {

	existingNSGroup := &nbdns.NameServerGroup{
		ID:          "testingNSGroup",
		Name:        "super",
		Description: "super",
		Primary:     true,
		NameServers: []nbdns.NameServer{
			{
				IP:     netip.MustParseAddr("1.1.1.1"),
				NSType: nbdns.UDPNameServerType,
				Port:   nbdns.DefaultDNSPort,
			},
			{
				IP:     netip.MustParseAddr("1.1.2.2"),
				NSType: nbdns.UDPNameServerType,
				Port:   nbdns.DefaultDNSPort,
			},
		},
		Groups:  []string{group1ID},
		Enabled: true,
	}

	validGroups := []string{group2ID}
	invalidGroups := []string{"nonExisting"}
	disabledPrimary := false
	validDomains := []string{validDomain}
	invalidDomains := []string{invalidDomain}

	validNameServerList := []nbdns.NameServer{
		{
			IP:     netip.MustParseAddr("1.1.1.1"),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		},
	}
	invalidNameServerListLarge := []nbdns.NameServer{
		{
			IP:     netip.MustParseAddr("1.1.1.1"),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		},
		{
			IP:     netip.MustParseAddr("1.1.2.2"),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		},
		{
			IP:     netip.MustParseAddr("1.1.3.3"),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		},
		{
			IP:     netip.MustParseAddr("1.1.4.4"),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		},
	}
	invalidID := "doesntExist"
	validName := "12345678901234567890qw"
	invalidNameLarge := "12345678901234567890qwertyuiopqwertyuiop1"
	invalidNameSmall := ""
	invalidNameExisting := existingNSGroupName

	testCases := []struct {
		name            string
		existingNSGroup *nbdns.NameServerGroup
		newID           *string
		newName         *string
		newPrimary      *bool
		newDomains      []string
		newNSList       []nbdns.NameServer
		newGroups       []string
		skipCopying     bool
		shouldCreate    bool
		errFunc         require.ErrorAssertionFunc
		expectedNSGroup *nbdns.NameServerGroup
	}{
		{
			name:            "Should Config Name Server Group",
			existingNSGroup: existingNSGroup,
			newName:         &validName,
			newGroups:       validGroups,
			newPrimary:      &disabledPrimary,
			newDomains:      validDomains,
			newNSList:       validNameServerList,
			errFunc:         require.NoError,
			shouldCreate:    true,
			expectedNSGroup: &nbdns.NameServerGroup{
				ID:          "testingNSGroup",
				Name:        validName,
				Primary:     false,
				Domains:     validDomains,
				Description: "super",
				NameServers: validNameServerList,
				Groups:      validGroups,
				Enabled:     true,
			},
		},
		{
			name:            "Should Not Config If Name Is Small",
			existingNSGroup: existingNSGroup,
			newName:         &invalidNameSmall,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Config If Name Is Large",
			existingNSGroup: existingNSGroup,
			newName:         &invalidNameLarge,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Config If Name Exists",
			existingNSGroup: existingNSGroup,
			newName:         &invalidNameExisting,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Config If ID Don't Exist",
			existingNSGroup: existingNSGroup,
			newID:           &invalidID,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Config If Nameserver List Is Small",
			existingNSGroup: existingNSGroup,
			newNSList:       []nbdns.NameServer{},
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Config If Nameserver List Is Large",
			existingNSGroup: existingNSGroup,
			newNSList:       invalidNameServerListLarge,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Config If Groups List Is Empty",
			existingNSGroup: existingNSGroup,
			newGroups:       []string{},
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Config If Groups List Has Empty ID",
			existingNSGroup: existingNSGroup,
			newGroups:       []string{""},
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Config If Groups List Has Non Existing Group ID",
			existingNSGroup: existingNSGroup,
			newGroups:       invalidGroups,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Config If Domains List Is Empty",
			existingNSGroup: existingNSGroup,
			newPrimary:      &disabledPrimary,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Config If Primary And Domains",
			existingNSGroup: existingNSGroup,
			newPrimary:      &existingNSGroup.Primary,
			newDomains:      validDomains,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Config If Domains List Is Invalid",
			existingNSGroup: existingNSGroup,
			newPrimary:      &disabledPrimary,
			newDomains:      invalidDomains,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			am, err := createNSManager(t)
			if err != nil {
				t.Error("failed to create account manager")
			}

			account, err := initTestNSAccount(t, am)
			if err != nil {
				t.Error("failed to init testing account")
			}

			account.NameServerGroups[testCase.existingNSGroup.ID] = testCase.existingNSGroup

			err = am.Store.SaveAccount(account)
			if err != nil {
				t.Error("account should be saved")
			}

			var nsGroupToSave *nbdns.NameServerGroup

			if !testCase.skipCopying {
				nsGroupToSave = testCase.existingNSGroup.Copy()

				if testCase.newID != nil {
					nsGroupToSave.ID = *testCase.newID
				}

				if testCase.newName != nil {
					nsGroupToSave.Name = *testCase.newName
				}

				if testCase.newGroups != nil {
					nsGroupToSave.Groups = testCase.newGroups
				}

				if testCase.newNSList != nil {
					nsGroupToSave.NameServers = testCase.newNSList
				}

				if testCase.newPrimary != nil {
					nsGroupToSave.Primary = *testCase.newPrimary
				}

				if testCase.newDomains != nil {
					nsGroupToSave.Domains = testCase.newDomains
				}
			}

			err = am.SaveNameServerGroup(account.Id, userID, nsGroupToSave)

			testCase.errFunc(t, err)

			if !testCase.shouldCreate {
				return
			}

			account, err = am.Store.GetAccount(account.Id)
			if err != nil {
				t.Fatal(err)
			}

			savedNSGroup, saved := account.NameServerGroups[testCase.expectedNSGroup.ID]
			require.True(t, saved)

			if !testCase.expectedNSGroup.IsEqual(savedNSGroup) {
				t.Errorf("new nameserver group didn't match expected group:\nGot %#v\nExpected:%#v\n", savedNSGroup, testCase.expectedNSGroup)
			}

		})
	}
}

func TestDeleteNameServerGroup(t *testing.T) {
	nsGroupID := "testingNSGroup"

	testingNSGroup := &nbdns.NameServerGroup{
		ID:          nsGroupID,
		Name:        "super",
		Description: "super",
		NameServers: []nbdns.NameServer{
			{
				IP:     netip.MustParseAddr("1.1.1.1"),
				NSType: nbdns.UDPNameServerType,
				Port:   nbdns.DefaultDNSPort,
			},
			{
				IP:     netip.MustParseAddr("1.1.2.2"),
				NSType: nbdns.UDPNameServerType,
				Port:   nbdns.DefaultDNSPort,
			},
		},
		Groups:  []string{group1ID},
		Enabled: true,
	}

	am, err := createNSManager(t)
	if err != nil {
		t.Error("failed to create account manager")
	}

	account, err := initTestNSAccount(t, am)
	if err != nil {
		t.Error("failed to init testing account")
	}

	account.NameServerGroups[testingNSGroup.ID] = testingNSGroup

	err = am.Store.SaveAccount(account)
	if err != nil {
		t.Error("failed to save account")
	}

	err = am.DeleteNameServerGroup(account.Id, testingNSGroup.ID, userID)
	if err != nil {
		t.Error("deleting nameserver group failed with error: ", err)
	}

	savedAccount, err := am.Store.GetAccount(account.Id)
	if err != nil {
		t.Error("failed to retrieve saved account with error: ", err)
	}

	_, found := savedAccount.NameServerGroups[testingNSGroup.ID]
	if found {
		t.Error("nameserver group shouldn't be found after delete")
	}
}

func TestGetNameServerGroup(t *testing.T) {

	am, err := createNSManager(t)
	if err != nil {
		t.Error("failed to create account manager")
	}

	account, err := initTestNSAccount(t, am)
	if err != nil {
		t.Error("failed to init testing account")
	}

	foundGroup, err := am.GetNameServerGroup(account.Id, testUserID, existingNSGroupID)
	if err != nil {
		t.Error("getting existing nameserver group failed with error: ", err)
	}

	if foundGroup == nil {
		t.Error("got a nil group while getting nameserver group with ID")
	}

	_, err = am.GetNameServerGroup(account.Id, testUserID, "not existing")
	if err == nil {
		t.Error("getting not existing nameserver group should return error, got nil")
	}
}

func createNSManager(t *testing.T) (*DefaultAccountManager, error) {
	t.Helper()
	store, err := createNSStore(t)
	if err != nil {
		return nil, err
	}
	eventStore := &activity.InMemoryEventStore{}
	return BuildManager(store, NewPeersUpdateManager(nil), nil, "", "netbird.selfhosted", eventStore, nil, false, MocIntegratedValidator{})
}

func createNSStore(t *testing.T) (Store, error) {
	t.Helper()
	dataDir := t.TempDir()
	store, cleanUp, err := NewTestStoreFromJson(dataDir)
	if err != nil {
		return nil, err
	}
	t.Cleanup(cleanUp)

	return store, nil
}

func initTestNSAccount(t *testing.T, am *DefaultAccountManager) (*Account, error) {
	t.Helper()
	peer1 := &nbpeer.Peer{
		Key:  nsGroupPeer1Key,
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
			Ipv6Supported: false,
		},
	}
	peer2 := &nbpeer.Peer{
		Key:  nsGroupPeer2Key,
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
			Ipv6Supported: false,
		},
	}
	existingNSGroup := nbdns.NameServerGroup{
		ID:          existingNSGroupID,
		Name:        existingNSGroupName,
		Description: "",
		NameServers: []nbdns.NameServer{
			{
				IP:     netip.MustParseAddr("8.8.8.8"),
				NSType: nbdns.UDPNameServerType,
				Port:   nbdns.DefaultDNSPort,
			},
			{
				IP:     netip.MustParseAddr("8.8.4.4"),
				NSType: nbdns.UDPNameServerType,
				Port:   nbdns.DefaultDNSPort,
			},
		},
		Groups:  []string{group1ID},
		Enabled: true,
	}

	accountID := "testingAcc"
	userID := testUserID
	domain := "example.com"

	account := newAccountWithId(accountID, userID, domain)

	account.NameServerGroups[existingNSGroup.ID] = &existingNSGroup

	newGroup1 := &nbgroup.Group{
		ID:   group1ID,
		Name: group1ID,
	}

	newGroup2 := &nbgroup.Group{
		ID:   group2ID,
		Name: group2ID,
	}

	account.Groups[newGroup1.ID] = newGroup1
	account.Groups[newGroup2.ID] = newGroup2

	err := am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	_, _, err = am.AddPeer("", userID, peer1)
	if err != nil {
		return nil, err
	}
	_, _, err = am.AddPeer("", userID, peer2)
	if err != nil {
		return nil, err
	}

	return account, nil
}

func TestValidateDomain(t *testing.T) {
	testCases := []struct {
		name    string
		domain  string
		errFunc require.ErrorAssertionFunc
	}{
		{
			name:    "Valid domain name with multiple labels",
			domain:  "123.example.com",
			errFunc: require.NoError,
		},
		{
			name:    "Valid domain name with hyphen",
			domain:  "test-example.com",
			errFunc: require.NoError,
		},
		{
			name:    "Invalid domain name with double hyphen",
			domain:  "test--example.com",
			errFunc: require.Error,
		},
		{
			name:    "Invalid domain name with only one label",
			domain:  "com",
			errFunc: require.Error,
		},
		{
			name:    "Invalid domain name with a label exceeding 63 characters",
			domain:  "dnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdns.com",
			errFunc: require.Error,
		},
		{
			name:    "Invalid domain name starting with a hyphen",
			domain:  "-example.com",
			errFunc: require.Error,
		},
		{
			name:    "Invalid domain name ending with a hyphen",
			domain:  "example.com-",
			errFunc: require.Error,
		},
		{
			name:    "Invalid domain with unicode",
			domain:  "example?,.com",
			errFunc: require.Error,
		},
		{
			name:    "Invalid domain with space before top-level domain",
			domain:  "space .example.com",
			errFunc: require.Error,
		},
		{
			name:    "Invalid domain with trailing space",
			domain:  "example.com ",
			errFunc: require.Error,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.errFunc(t, validateDomain(testCase.domain))
		})
	}

}
