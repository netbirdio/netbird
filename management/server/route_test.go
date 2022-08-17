package server

import (
	"github.com/netbirdio/netbird/route"
	"github.com/stretchr/testify/require"
	"net/netip"
	"testing"
)

const peer1Key = "BhRPtynAAYRDy08+q4HTMsos8fs4plTP4NOSh7C1ry8="
const peer2Key = "/yF0+vCfv+mRR5k0dca0TrGdO/oiNeAI58gToZm5NyI="

func TestCreateRoute(t *testing.T) {

	type input struct {
		prefix      string
		peer        string
		description string
		masquerade  bool
		metric      int
		enabled     bool
	}

	testCases := []struct {
		name          string
		inputArgs     input
		shouldCreate  bool
		errFunc       require.ErrorAssertionFunc
		expectedRoute *route.Route
	}{
		{
			name: "Happy Path",
			inputArgs: input{
				prefix:      "192.168.0.0/16",
				peer:        peer1Key,
				description: "super",
				masquerade:  false,
				metric:      9999,
				enabled:     true,
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				Prefix:      netip.MustParsePrefix("192.168.0.0/16"),
				PrefixType:  route.IPv4Prefix,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
			},
		},
		{
			name: "Bad Prefix",
			inputArgs: input{
				prefix:      "192.168.0.0/34",
				peer:        peer1Key,
				description: "super",
				masquerade:  false,
				metric:      9999,
				enabled:     true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Bad Peer",
			inputArgs: input{
				prefix:      "192.168.0.0/16",
				peer:        "notExistingPeer",
				description: "super",
				masquerade:  false,
				metric:      9999,
				enabled:     true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Empty Peer",
			inputArgs: input{
				prefix:      "192.168.0.0/16",
				peer:        "",
				description: "super",
				masquerade:  false,
				metric:      9999,
				enabled:     false,
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				Prefix:      netip.MustParsePrefix("192.168.0.0/16"),
				PrefixType:  route.IPv4Prefix,
				Peer:        "",
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     false,
			},
		},
		{
			name: "Large Metric",
			inputArgs: input{
				prefix:      "192.168.0.0/16",
				peer:        peer1Key,
				description: "super",
				masquerade:  false,
				metric:      99999,
				enabled:     true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Small Metric",
			inputArgs: input{
				prefix:      "192.168.0.0/16",
				peer:        peer1Key,
				description: "super",
				masquerade:  false,
				metric:      0,
				enabled:     true,
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			am, err := createRouterManager(t)
			if err != nil {
				t.Error("failed to create account manager")
			}

			account, err := initTestRouteAccount(t, am)
			if err != nil {
				t.Error("failed to init testing account")
			}

			outRoute, err := am.CreateRoute(
				account.Id,
				testCase.inputArgs.prefix,
				testCase.inputArgs.peer,
				testCase.inputArgs.description,
				testCase.inputArgs.masquerade,
				testCase.inputArgs.metric,
				testCase.inputArgs.enabled,
			)

			testCase.errFunc(t, err)

			if !testCase.shouldCreate {
				return
			}

			// assign generated ID
			testCase.expectedRoute.ID = outRoute.ID

			if !testCase.expectedRoute.IsEqual(outRoute) {
				t.Errorf("new route didn't match expected route:\nGot %#v\nExpected:%#v\n", outRoute, testCase.expectedRoute)
			}

		})
	}
}

func TestSaveRoute(t *testing.T) {

	validPeer := peer2Key
	invalidPeer := "nonExisting"
	validPrefix := netip.MustParsePrefix("192.168.0.0/24")
	invalidPrefix, _ := netip.ParsePrefix("192.168.0.0/34")
	validMetric := 1000
	invalidMetric := 99999

	testCases := []struct {
		name          string
		existingRoute *route.Route
		newPeer       *string
		newMetric     *int
		newPrefix     *netip.Prefix
		skipCopying   bool
		shouldCreate  bool
		errFunc       require.ErrorAssertionFunc
		expectedRoute *route.Route
	}{
		{
			name: "Happy Path",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Prefix:      netip.MustParsePrefix("192.168.0.0/16"),
				PrefixType:  route.IPv4Prefix,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
			},
			newPeer:      &validPeer,
			newMetric:    &validMetric,
			newPrefix:    &validPrefix,
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				ID:          "testingRoute",
				Prefix:      validPrefix,
				PrefixType:  route.IPv4Prefix,
				Peer:        validPeer,
				Description: "super",
				Masquerade:  false,
				Metric:      validMetric,
				Enabled:     true,
			},
		},
		{
			name: "Bad Prefix",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Prefix:      netip.MustParsePrefix("192.168.0.0/16"),
				PrefixType:  route.IPv4Prefix,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
			},
			newPrefix: &invalidPrefix,
			errFunc:   require.Error,
		},
		{
			name: "Bad Peer",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Prefix:      netip.MustParsePrefix("192.168.0.0/16"),
				PrefixType:  route.IPv4Prefix,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
			},
			newPeer: &invalidPeer,
			errFunc: require.Error,
		},
		{
			name: "Invalid Metric",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Prefix:      netip.MustParsePrefix("192.168.0.0/16"),
				PrefixType:  route.IPv4Prefix,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
			},
			newMetric: &invalidMetric,
			errFunc:   require.Error,
		},
		{
			name: "Nil Route",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Prefix:      netip.MustParsePrefix("192.168.0.0/16"),
				PrefixType:  route.IPv4Prefix,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
			},
			skipCopying: true,
			errFunc:     require.Error,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			am, err := createRouterManager(t)
			if err != nil {
				t.Error("failed to create account manager")
			}

			account, err := initTestRouteAccount(t, am)
			if err != nil {
				t.Error("failed to init testing account")
			}

			account.Routes[testCase.existingRoute.ID] = testCase.existingRoute

			err = am.Store.SaveAccount(account)
			if err != nil {
				t.Error("account should be saved")
			}

			var routeToSave *route.Route

			if !testCase.skipCopying {
				routeToSave = testCase.existingRoute.Copy()
				if testCase.newPeer != nil {
					routeToSave.Peer = *testCase.newPeer
				}

				if testCase.newMetric != nil {
					routeToSave.Metric = *testCase.newMetric
				}

				if testCase.newPrefix != nil {
					routeToSave.Prefix = *testCase.newPrefix
				}
			}

			err = am.SaveRoute(account.Id, routeToSave)

			testCase.errFunc(t, err)

			if !testCase.shouldCreate {
				return
			}

			savedRoute, saved := account.Routes[testCase.expectedRoute.ID]
			require.True(t, saved)

			if !testCase.expectedRoute.IsEqual(savedRoute) {
				t.Errorf("new route didn't match expected route:\nGot %#v\nExpected:%#v\n", savedRoute, testCase.expectedRoute)
			}

		})
	}
}

func TestUpdateRoute(t *testing.T) {
	routeID := "testingRouteID"

	existingRoute := &route.Route{
		ID:          routeID,
		Prefix:      netip.MustParsePrefix("192.168.0.0/16"),
		PrefixType:  route.IPv4Prefix,
		Peer:        peer1Key,
		Description: "super",
		Masquerade:  false,
		Metric:      9999,
		Enabled:     true,
	}

	testCases := []struct {
		name          string
		existingRoute *route.Route
		operations    []RouteUpdateOperation
		shouldCreate  bool
		errFunc       require.ErrorAssertionFunc
		expectedRoute *route.Route
	}{
		{
			name:          "Happy Path Single OPS",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				RouteUpdateOperation{
					Type:   UpdateRoutePeer,
					Values: []string{peer2Key},
				},
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				ID:          routeID,
				Prefix:      netip.MustParsePrefix("192.168.0.0/16"),
				PrefixType:  route.IPv4Prefix,
				Peer:        peer2Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
			},
		},
		{
			name:          "Happy Path Multiple OPS",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				RouteUpdateOperation{
					Type:   UpdateRouteDescription,
					Values: []string{"great"},
				},
				RouteUpdateOperation{
					Type:   UpdateRoutePrefix,
					Values: []string{"192.168.0.0/24"},
				},
				RouteUpdateOperation{
					Type:   UpdateRoutePeer,
					Values: []string{peer2Key},
				},
				RouteUpdateOperation{
					Type:   UpdateRouteMetric,
					Values: []string{"3030"},
				},
				RouteUpdateOperation{
					Type:   UpdateRouteMasquerade,
					Values: []string{"true"},
				},
				RouteUpdateOperation{
					Type:   UpdateRouteEnabled,
					Values: []string{"false"},
				},
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				ID:          routeID,
				Prefix:      netip.MustParsePrefix("192.168.0.0/24"),
				PrefixType:  route.IPv4Prefix,
				Peer:        peer2Key,
				Description: "great",
				Masquerade:  true,
				Metric:      3030,
				Enabled:     false,
			},
		},
		{
			name:          "Empty Values",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				RouteUpdateOperation{
					Type: UpdateRoutePeer,
				},
			},
			errFunc: require.Error,
		},
		{
			name:          "Multiple Values",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				RouteUpdateOperation{
					Type:   UpdateRoutePeer,
					Values: []string{peer2Key, peer1Key},
				},
			},
			errFunc: require.Error,
		},
		{
			name:          "Bad Prefix",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				RouteUpdateOperation{
					Type:   UpdateRoutePrefix,
					Values: []string{"192.168.0.0/34"},
				},
			},
			errFunc: require.Error,
		},
		{
			name:          "Bad Peer",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				RouteUpdateOperation{
					Type:   UpdateRoutePeer,
					Values: []string{"non existing Peer"},
				},
			},
			errFunc: require.Error,
		},
		{
			name:          "Empty Peer",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				RouteUpdateOperation{
					Type:   UpdateRoutePeer,
					Values: []string{""},
				},
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				ID:          routeID,
				Prefix:      netip.MustParsePrefix("192.168.0.0/16"),
				PrefixType:  route.IPv4Prefix,
				Peer:        "",
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
			},
		},
		{
			name:          "Invalid Metric",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				RouteUpdateOperation{
					Type:   UpdateRouteMetric,
					Values: []string{"999999"},
				},
			},
			errFunc: require.Error,
		},
		{
			name:          "Invalid Boolean",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				RouteUpdateOperation{
					Type:   UpdateRouteMasquerade,
					Values: []string{"yes"},
				},
			},
			errFunc: require.Error,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			am, err := createRouterManager(t)
			if err != nil {
				t.Error("failed to create account manager")
			}

			account, err := initTestRouteAccount(t, am)
			if err != nil {
				t.Error("failed to init testing account")
			}

			account.Routes[testCase.existingRoute.ID] = testCase.existingRoute

			err = am.Store.SaveAccount(account)
			if err != nil {
				t.Error("account should be saved")
			}

			updatedRoute, err := am.UpdateRoute(account.Id, testCase.existingRoute.ID, testCase.operations)

			testCase.errFunc(t, err)

			if !testCase.shouldCreate {
				return
			}

			testCase.expectedRoute.ID = updatedRoute.ID

			if !testCase.expectedRoute.IsEqual(updatedRoute) {
				t.Errorf("new route didn't match expected route:\nGot %#v\nExpected:%#v\n", updatedRoute, testCase.expectedRoute)
			}

		})
	}
}

func TestDeleteRoute(t *testing.T) {

	testingRoute := &route.Route{
		ID:          "testingRoute",
		Prefix:      netip.MustParsePrefix("192.168.0.0/16"),
		PrefixType:  route.IPv4Prefix,
		Peer:        peer1Key,
		Description: "super",
		Masquerade:  false,
		Metric:      9999,
		Enabled:     true,
	}

	am, err := createRouterManager(t)
	if err != nil {
		t.Error("failed to create account manager")
	}

	account, err := initTestRouteAccount(t, am)
	if err != nil {
		t.Error("failed to init testing account")
	}

	account.Routes[testingRoute.ID] = testingRoute

	err = am.Store.SaveAccount(account)
	if err != nil {
		t.Error("failed to save account")
	}

	err = am.DeleteRoute(account.Id, testingRoute.ID)
	if err != nil {
		t.Error("deleting route failed with error: ", err)
	}

	savedAccount, err := am.Store.GetAccount(account.Id)
	if err != nil {
		t.Error("failed to retrieve saved account with error: ", err)
	}

	_, found := savedAccount.Routes[testingRoute.ID]
	if found {
		t.Error("route shouldn't be found after delete")
	}
}

func createRouterManager(t *testing.T) (*DefaultAccountManager, error) {
	store, err := createRouterStore(t)
	if err != nil {
		return nil, err
	}
	return BuildManager(store, NewPeersUpdateManager(), nil)
}

func createRouterStore(t *testing.T) (Store, error) {
	dataDir := t.TempDir()
	store, err := NewStore(dataDir)
	if err != nil {
		return nil, err
	}

	return store, nil
}

func initTestRouteAccount(t *testing.T, am *DefaultAccountManager) (*Account, error) {
	peer1 := &Peer{
		Key:  peer1Key,
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
		Key:  peer2Key,
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

	accountID := "testingAcc"
	userID := "testingUser"
	domain := "example.com"

	account := newAccountWithId(accountID, userID, domain)
	err := am.Store.SaveAccount(account)
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
