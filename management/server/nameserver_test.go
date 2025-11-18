package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
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
				t.Fatalf("failed to create account manager: %s", err)
			}

			account, err := initTestNSAccount(t, am)
			if err != nil {
				t.Fatalf("failed to init testing account: %s", err)
			}

			outNSGroup, err := am.CreateNameServerGroup(
				context.Background(),
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
				t.Fatalf("failed to create account manager: %s", err)
			}

			account, err := initTestNSAccount(t, am)
			if err != nil {
				t.Fatalf("failed to init testing account: %s", err)
			}

			account.NameServerGroups[testCase.existingNSGroup.ID] = testCase.existingNSGroup

			err = am.Store.SaveAccount(context.Background(), account)
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

			err = am.SaveNameServerGroup(context.Background(), account.Id, userID, nsGroupToSave)

			testCase.errFunc(t, err)

			if !testCase.shouldCreate {
				return
			}

			account, err = am.Store.GetAccount(context.Background(), account.Id)
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
		t.Fatalf("failed to init testing account: %s", err)
	}

	account.NameServerGroups[testingNSGroup.ID] = testingNSGroup

	err = am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Error("failed to save account")
	}

	err = am.DeleteNameServerGroup(context.Background(), account.Id, testingNSGroup.ID, userID)
	if err != nil {
		t.Error("deleting nameserver group failed with error: ", err)
	}

	savedAccount, err := am.Store.GetAccount(context.Background(), account.Id)
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
		t.Fatalf("failed to init testing account: %s", err)
	}

	foundGroup, err := am.GetNameServerGroup(context.Background(), account.Id, testUserID, existingNSGroupID)
	if err != nil {
		t.Error("getting existing nameserver group failed with error: ", err)
	}

	if foundGroup == nil {
		t.Error("got a nil group while getting nameserver group with ID")
	}

	_, err = am.GetNameServerGroup(context.Background(), account.Id, testUserID, "not existing")
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

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMockManager := settings.NewMockManager(ctrl)
	settingsMockManager.
		EXPECT().
		GetExtraSettings(gomock.Any(), gomock.Any()).
		Return(&types.ExtraSettings{}, nil).
		AnyTimes()

	permissionsManager := permissions.NewManager(store)

	ctx := context.Background()
	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := NewAccountRequestBuffer(ctx, store)
	networkMapController := controller.NewController(ctx, store, metrics, updateManager, requestBuffer, MockIntegratedValidator{}, settingsMockManager, "netbird.selfhosted", port_forwarding.NewControllerMock(), &config.Config{})

	return BuildManager(context.Background(), nil, store, networkMapController, nil, "", eventStore, nil, false, MockIntegratedValidator{}, metrics, port_forwarding.NewControllerMock(), settingsMockManager, permissionsManager, false)
}

func createNSStore(t *testing.T) (store.Store, error) {
	t.Helper()
	dataDir := t.TempDir()
	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "", dataDir)
	if err != nil {
		return nil, err
	}
	t.Cleanup(cleanUp)

	return store, nil
}

func initTestNSAccount(t *testing.T, am *DefaultAccountManager) (*types.Account, error) {
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

	account := newAccountWithId(context.Background(), accountID, userID, domain, false)

	account.NameServerGroups[existingNSGroup.ID] = &existingNSGroup

	newGroup1 := &types.Group{
		ID:   group1ID,
		Name: group1ID,
	}

	newGroup2 := &types.Group{
		ID:   group2ID,
		Name: group2ID,
	}

	account.Groups[newGroup1.ID] = newGroup1
	account.Groups[newGroup2.ID] = newGroup2

	err := am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		return nil, err
	}

	_, _, _, err = am.AddPeer(context.Background(), "", "", userID, peer1, false)
	if err != nil {
		return nil, err
	}
	_, _, _, err = am.AddPeer(context.Background(), "", "", userID, peer2, false)
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
			name:    "Valid domain name with only one label",
			domain:  "example",
			errFunc: require.NoError,
		},
		{
			name:    "Valid domain name with trailing dot",
			domain:  "example.",
			errFunc: require.NoError,
		},
		{
			name:    "Invalid wildcard domain name",
			domain:  "*.example",
			errFunc: require.Error,
		},
		{
			name:    "Invalid domain name with leading dot",
			domain:  ".com",
			errFunc: require.Error,
		},
		{
			name:    "Invalid domain name with dot only",
			domain:  ".",
			errFunc: require.Error,
		},
		{
			name:    "Invalid domain name with double hyphen",
			domain:  "test--example.com",
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

func TestNameServerAccountPeersUpdate(t *testing.T) {
	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	var newNameServerGroupA *nbdns.NameServerGroup
	var newNameServerGroupB *nbdns.NameServerGroup

	err := manager.CreateGroup(context.Background(), account.Id, userID, &types.Group{
		ID:    "groupA",
		Name:  "GroupA",
		Peers: []string{},
	})
	assert.NoError(t, err)

	err = manager.CreateGroup(context.Background(), account.Id, userID, &types.Group{
		ID:    "groupB",
		Name:  "GroupB",
		Peers: []string{peer1.ID, peer2.ID, peer3.ID},
	})
	assert.NoError(t, err)

	updMsg := updateManager.CreateChannel(context.Background(), peer1.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(context.Background(), peer1.ID)
	})

	// Creating a nameserver group with a distribution group no peers should not update account peers
	// and not send peer update
	t.Run("creating nameserver group with distribution group no peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		newNameServerGroupA, err = manager.CreateNameServerGroup(
			context.Background(), account.Id, "nsGroupA", "nsGroupA", []nbdns.NameServer{{
				IP:     netip.MustParseAddr("1.1.1.1"),
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
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// saving a nameserver group with a distribution group with no peers should not update account peers
	// and not send peer update
	t.Run("saving nameserver group with distribution group no peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		err = manager.SaveNameServerGroup(context.Background(), account.Id, userID, newNameServerGroupA)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}
	})

	// Creating a nameserver group with a distribution group no peers should update account peers and send peer update
	t.Run("creating nameserver group with distribution group has peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		newNameServerGroupB, err = manager.CreateNameServerGroup(
			context.Background(), account.Id, "nsGroupB", "nsGroupB", []nbdns.NameServer{{
				IP:     netip.MustParseAddr("1.1.1.1"),
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

	// saving a nameserver group with a distribution group with peers should update account peers and send peer update
	t.Run("saving nameserver group with distribution group has peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		newNameServerGroupB.NameServers = []nbdns.NameServer{
			{
				IP:     netip.MustParseAddr("1.1.1.2"),
				NSType: nbdns.UDPNameServerType,
				Port:   nbdns.DefaultDNSPort,
			},
			{
				IP:     netip.MustParseAddr("8.8.8.8"),
				NSType: nbdns.UDPNameServerType,
				Port:   nbdns.DefaultDNSPort,
			},
		}
		err = manager.SaveNameServerGroup(context.Background(), account.Id, userID, newNameServerGroupB)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Deleting a nameserver group should update account peers and send peer update
	t.Run("deleting nameserver group", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err = manager.DeleteNameServerGroup(context.Background(), account.Id, newNameServerGroupB.ID, userID)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})
}
