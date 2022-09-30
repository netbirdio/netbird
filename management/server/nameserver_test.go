package server

import (
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/stretchr/testify/require"
	"net/netip"
	"testing"
)

const (
	group1ID            = "group1"
	group2ID            = "group2"
	existingNSGroupName = "existing"
	nsGroupPeer1Key     = "BhRPtynAAYRDy08+q4HTMsos8fs4plTP4NOSh7C1ry8="
	nsGroupPeer2Key     = "/yF0+vCfv+mRR5k0dca0TrGdO/oiNeAI58gToZm5NyI="
)

func TestCreateNameServerGroup(t *testing.T) {
	type input struct {
		name        string
		description string
		enabled     bool
		groups      []string
		nameServers []nbdns.NameServer
	}

	testCases := []struct {
		name            string
		inputArgs       input
		shouldCreate    bool
		errFunc         require.ErrorAssertionFunc
		expectedNSGroup *nbdns.NameServerGroup
	}{
		{
			name: "Create A NS Group",
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
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedNSGroup: &nbdns.NameServerGroup{
				Name:        "super",
				Description: "super",
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
				groups:      []string{group1ID},
				nameServers: []nbdns.NameServer{},
				enabled:     true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Create A NS Group With More Than 2 Nameservers Should Fail",
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
					{
						IP:     netip.MustParseAddr("1.1.3.3"),
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
				testCase.inputArgs.enabled,
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
		newNSList       []nbdns.NameServer
		newGroups       []string
		skipCopying     bool
		shouldCreate    bool
		errFunc         require.ErrorAssertionFunc
		expectedNSGroup *nbdns.NameServerGroup
	}{
		{
			name:            "Should Update Name Server Group",
			existingNSGroup: existingNSGroup,
			newName:         &validName,
			newGroups:       validGroups,
			newNSList:       validNameServerList,
			errFunc:         require.NoError,
			shouldCreate:    true,
			expectedNSGroup: &nbdns.NameServerGroup{
				ID:          "testingNSGroup",
				Name:        validName,
				Description: "super",
				NameServers: validNameServerList,
				Groups:      validGroups,
				Enabled:     true,
			},
		},
		{
			name:            "Should Not Update If Name Is Small",
			existingNSGroup: existingNSGroup,
			newName:         &invalidNameSmall,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Update If Name Is Large",
			existingNSGroup: existingNSGroup,
			newName:         &invalidNameLarge,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Update If Name Exists",
			existingNSGroup: existingNSGroup,
			newName:         &invalidNameExisting,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Update If ID Don't Exist",
			existingNSGroup: existingNSGroup,
			newID:           &invalidID,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Update If Nameserver List Is Small",
			existingNSGroup: existingNSGroup,
			newNSList:       []nbdns.NameServer{},
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Update If Nameserver List Is Large",
			existingNSGroup: existingNSGroup,
			newNSList:       invalidNameServerListLarge,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Update If Groups List Is Empty",
			existingNSGroup: existingNSGroup,
			newGroups:       []string{},
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Update If Groups List Has Empty ID",
			existingNSGroup: existingNSGroup,
			newGroups:       []string{""},
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name:            "Should Not Update If Groups List Has Non Existing Group ID",
			existingNSGroup: existingNSGroup,
			newGroups:       invalidGroups,
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
			}

			err = am.SaveNameServerGroup(account.Id, nsGroupToSave)

			testCase.errFunc(t, err)

			if !testCase.shouldCreate {
				return
			}

			savedNSGroup, saved := account.NameServerGroups[testCase.expectedNSGroup.ID]
			require.True(t, saved)

			if !testCase.expectedNSGroup.IsEqual(savedNSGroup) {
				t.Errorf("new nameserver group didn't match expected group:\nGot %#v\nExpected:%#v\n", savedNSGroup, testCase.expectedNSGroup)
			}

		})
	}
}

func TestUpdateNameServerGroup(t *testing.T) {
	nsGroupID := "testingNSGroup"

	existingNSGroup := &nbdns.NameServerGroup{
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

	testCases := []struct {
		name            string
		existingNSGroup *nbdns.NameServerGroup
		nsGroupID       string
		operations      []NameServerGroupUpdateOperation
		shouldCreate    bool
		errFunc         require.ErrorAssertionFunc
		expectedNSGroup *nbdns.NameServerGroup
	}{
		{
			name:            "Should Update Single Property",
			existingNSGroup: existingNSGroup,
			nsGroupID:       existingNSGroup.ID,
			operations: []NameServerGroupUpdateOperation{
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupName,
					Values: []string{"superNew"},
				},
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedNSGroup: &nbdns.NameServerGroup{
				ID:          nsGroupID,
				Name:        "superNew",
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
			},
		},
		{
			name:            "Should Update Multiple Properties",
			existingNSGroup: existingNSGroup,
			nsGroupID:       existingNSGroup.ID,
			operations: []NameServerGroupUpdateOperation{
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupName,
					Values: []string{"superNew"},
				},
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupDescription,
					Values: []string{"superDescription"},
				},
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupNameServers,
					Values: []string{"udp://127.0.0.1:53", "udp://8.8.8.8:53"},
				},
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupGroups,
					Values: []string{group1ID, group2ID},
				},
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupEnabled,
					Values: []string{"false"},
				},
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedNSGroup: &nbdns.NameServerGroup{
				ID:          nsGroupID,
				Name:        "superNew",
				Description: "superDescription",
				NameServers: []nbdns.NameServer{
					{
						IP:     netip.MustParseAddr("127.0.0.1"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
					{
						IP:     netip.MustParseAddr("8.8.8.8"),
						NSType: nbdns.UDPNameServerType,
						Port:   nbdns.DefaultDNSPort,
					},
				},
				Groups:  []string{group1ID, group2ID},
				Enabled: false,
			},
		},
		{
			name:            "Should Not Update On Invalid ID",
			existingNSGroup: existingNSGroup,
			nsGroupID:       "nonExistingNSGroup",
			errFunc:         require.Error,
		},
		{
			name:            "Should Not Update On Empty Operations",
			existingNSGroup: existingNSGroup,
			nsGroupID:       existingNSGroup.ID,
			operations:      []NameServerGroupUpdateOperation{},
			errFunc:         require.Error,
		},
		{
			name:            "Should Not Update On Empty Values",
			existingNSGroup: existingNSGroup,
			nsGroupID:       existingNSGroup.ID,
			operations: []NameServerGroupUpdateOperation{
				NameServerGroupUpdateOperation{
					Type: UpdateNameServerGroupName,
				},
			},
			errFunc: require.Error,
		},
		{
			name:            "Should Not Update On Empty String",
			existingNSGroup: existingNSGroup,
			nsGroupID:       existingNSGroup.ID,
			operations: []NameServerGroupUpdateOperation{
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupName,
					Values: []string{""},
				},
			},
			errFunc: require.Error,
		},
		{
			name:            "Should Not Update On Invalid Name Large String",
			existingNSGroup: existingNSGroup,
			nsGroupID:       existingNSGroup.ID,
			operations: []NameServerGroupUpdateOperation{
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupName,
					Values: []string{"12345678901234567890qwertyuiopqwertyuiop1"},
				},
			},
			errFunc: require.Error,
		},
		{
			name:            "Should Not Update On Invalid On Existing Name",
			existingNSGroup: existingNSGroup,
			nsGroupID:       existingNSGroup.ID,
			operations: []NameServerGroupUpdateOperation{
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupName,
					Values: []string{existingNSGroupName},
				},
			},
			errFunc: require.Error,
		},
		{
			name:            "Should Not Update On Invalid On Multiple Name Values",
			existingNSGroup: existingNSGroup,
			nsGroupID:       existingNSGroup.ID,
			operations: []NameServerGroupUpdateOperation{
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupName,
					Values: []string{"nameOne", "nameTwo"},
				},
			},
			errFunc: require.Error,
		},
		{
			name:            "Should Not Update On Invalid Boolean",
			existingNSGroup: existingNSGroup,
			nsGroupID:       existingNSGroup.ID,
			operations: []NameServerGroupUpdateOperation{
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupEnabled,
					Values: []string{"yes"},
				},
			},
			errFunc: require.Error,
		},
		{
			name:            "Should Not Update On Invalid Nameservers Wrong Schema",
			existingNSGroup: existingNSGroup,
			nsGroupID:       existingNSGroup.ID,
			operations: []NameServerGroupUpdateOperation{
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupNameServers,
					Values: []string{"https://127.0.0.1:53"},
				},
			},
			errFunc: require.Error,
		},
		{
			name:            "Should Not Update On Invalid Nameservers Wrong IP",
			existingNSGroup: existingNSGroup,
			nsGroupID:       existingNSGroup.ID,
			operations: []NameServerGroupUpdateOperation{
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupNameServers,
					Values: []string{"udp://8.8.8.300:53"},
				},
			},
			errFunc: require.Error,
		},
		{
			name:            "Should Not Update On Large Number Of Nameservers",
			existingNSGroup: existingNSGroup,
			nsGroupID:       existingNSGroup.ID,
			operations: []NameServerGroupUpdateOperation{
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupNameServers,
					Values: []string{"udp://127.0.0.1:53", "udp://8.8.8.8:53", "udp://8.8.4.4:53"},
				},
			},
			errFunc: require.Error,
		},
		{
			name:            "Should Not Update On Invalid GroupID",
			existingNSGroup: existingNSGroup,
			nsGroupID:       existingNSGroup.ID,
			operations: []NameServerGroupUpdateOperation{
				NameServerGroupUpdateOperation{
					Type:   UpdateNameServerGroupGroups,
					Values: []string{"nonExistingGroupID"},
				},
			},
			errFunc: require.Error,
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

			updatedRoute, err := am.UpdateNameServerGroup(account.Id, testCase.nsGroupID, testCase.operations)
			testCase.errFunc(t, err)

			if !testCase.shouldCreate {
				return
			}

			testCase.expectedNSGroup.ID = updatedRoute.ID

			if !testCase.expectedNSGroup.IsEqual(updatedRoute) {
				t.Errorf("new nameserver group didn't match expected group:\nGot %#v\nExpected:%#v\n", updatedRoute, testCase.expectedNSGroup)
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

	err = am.DeleteNameServerGroup(account.Id, testingNSGroup.ID)
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

func createNSManager(t *testing.T) (*DefaultAccountManager, error) {
	store, err := createNSStore(t)
	if err != nil {
		return nil, err
	}
	return BuildManager(store, NewPeersUpdateManager(), nil)
}

func createNSStore(t *testing.T) (Store, error) {
	dataDir := t.TempDir()
	store, err := NewStore(dataDir)
	if err != nil {
		return nil, err
	}

	return store, nil
}

func initTestNSAccount(t *testing.T, am *DefaultAccountManager) (*Account, error) {
	peer1 := &Peer{
		Key:  nsGroupPeer1Key,
		Name: "test-host1@netbird.io",
		Meta: PeerSystemMeta{
			Hostname:  "test-host1@netbird.io",
			GoOS:      "linux",
			Kernel:    "Linux",
			Core:      "21.04",
			Platform:  "x86_64",
			OS:        "Ubuntu",
			WtVersion: "development",
			UIVersion: "development",
		},
	}
	peer2 := &Peer{
		Key:  nsGroupPeer2Key,
		Name: "test-host2@netbird.io",
		Meta: PeerSystemMeta{
			Hostname:  "test-host2@netbird.io",
			GoOS:      "linux",
			Kernel:    "Linux",
			Core:      "21.04",
			Platform:  "x86_64",
			OS:        "Ubuntu",
			WtVersion: "development",
			UIVersion: "development",
		},
	}
	existingNSGroup := nbdns.NameServerGroup{
		ID:          "existingNSGroup",
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
	userID := "testingUser"
	domain := "example.com"

	account := newAccountWithId(accountID, userID, domain)

	account.NameServerGroups[existingNSGroup.ID] = &existingNSGroup

	defaultGroup, err := account.GetGroupAll()
	if err != nil {
		return nil, err
	}
	newGroup1 := defaultGroup.Copy()
	newGroup1.ID = group1ID
	newGroup2 := defaultGroup.Copy()
	newGroup2.ID = group2ID

	account.Groups[newGroup1.ID] = newGroup1
	account.Groups[newGroup2.ID] = newGroup2

	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	_, err = am.AddPeer("", userID, peer1)
	if err != nil {
		return nil, err
	}
	_, err = am.AddPeer("", userID, peer2)
	if err != nil {
		return nil, err
	}

	return account, nil
}
