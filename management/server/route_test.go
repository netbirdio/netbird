package server

import (
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/route"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	"net/netip"
	"testing"
)

const (
	peer1Key           = "BhRPtynAAYRDy08+q4HTMsos8fs4plTP4NOSh7C1ry8="
	peer2Key           = "/yF0+vCfv+mRR5k0dca0TrGdO/oiNeAI58gToZm5NyI="
	routeGroup1        = "routeGroup1"
	routeGroup2        = "routeGroup2"
	routeInvalidGroup1 = "routeInvalidGroup1"
	userID             = "testingUser"
)

func TestCreateRoute(t *testing.T) {

	type input struct {
		network     string
		netID       string
		peer        string
		description string
		masquerade  bool
		metric      int
		enabled     bool
		groups      []string
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
				network:     "192.168.0.0/16",
				netID:       "happy",
				peer:        peer1Key,
				description: "super",
				masquerade:  false,
				metric:      9999,
				enabled:     true,
				groups:      []string{routeGroup1},
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetworkType: route.IPv4Network,
				NetID:       "happy",
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
		},
		{
			name: "Bad Prefix Should Fail",
			inputArgs: input{
				network:     "192.168.0.0/34",
				netID:       "happy",
				peer:        peer1Key,
				description: "super",
				masquerade:  false,
				metric:      9999,
				enabled:     true,
				groups:      []string{routeGroup1},
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Bad Peer Should Fail",
			inputArgs: input{
				network:     "192.168.0.0/16",
				netID:       "happy",
				peer:        "notExistingPeer",
				description: "super",
				masquerade:  false,
				metric:      9999,
				enabled:     true,
				groups:      []string{routeGroup1},
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Empty Peer Should Create",
			inputArgs: input{
				network:     "192.168.0.0/16",
				netID:       "happy",
				peer:        "",
				description: "super",
				masquerade:  false,
				metric:      9999,
				enabled:     false,
				groups:      []string{routeGroup1},
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetworkType: route.IPv4Network,
				NetID:       "happy",
				Peer:        "",
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     false,
				Groups:      []string{routeGroup1},
			},
		},
		{
			name: "Large Metric Should Fail",
			inputArgs: input{
				network:     "192.168.0.0/16",
				peer:        peer1Key,
				netID:       "happy",
				description: "super",
				masquerade:  false,
				metric:      99999,
				enabled:     true,
				groups:      []string{routeGroup1},
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Small Metric Should Fail",
			inputArgs: input{
				network:     "192.168.0.0/16",
				netID:       "happy",
				peer:        peer1Key,
				description: "super",
				masquerade:  false,
				metric:      0,
				enabled:     true,
				groups:      []string{routeGroup1},
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Large NetID Should Fail",
			inputArgs: input{
				network:     "192.168.0.0/16",
				peer:        peer1Key,
				netID:       "12345678901234567890qwertyuiopqwertyuiop1",
				description: "super",
				masquerade:  false,
				metric:      9999,
				enabled:     true,
				groups:      []string{routeGroup1},
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Small NetID Should Fail",
			inputArgs: input{
				network:     "192.168.0.0/16",
				netID:       "",
				peer:        peer1Key,
				description: "",
				masquerade:  false,
				metric:      9999,
				enabled:     true,
				groups:      []string{routeGroup1},
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Empty Group List Should Fail",
			inputArgs: input{
				network:     "192.168.0.0/16",
				netID:       "NewId",
				peer:        peer1Key,
				description: "",
				masquerade:  false,
				metric:      9999,
				enabled:     true,
				groups:      []string{},
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Empty Group ID string Should Fail",
			inputArgs: input{
				network:     "192.168.0.0/16",
				netID:       "NewId",
				peer:        peer1Key,
				description: "",
				masquerade:  false,
				metric:      9999,
				enabled:     true,
				groups:      []string{""},
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Invalid Group Should Fail",
			inputArgs: input{
				network:     "192.168.0.0/16",
				netID:       "NewId",
				peer:        peer1Key,
				description: "",
				masquerade:  false,
				metric:      9999,
				enabled:     true,
				groups:      []string{routeInvalidGroup1},
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
				testCase.inputArgs.network,
				testCase.inputArgs.peer,
				testCase.inputArgs.description,
				testCase.inputArgs.netID,
				testCase.inputArgs.masquerade,
				testCase.inputArgs.metric,
				testCase.inputArgs.groups,
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
	validNetID := "12345678901234567890qw"
	invalidNetID := "12345678901234567890qwertyuiopqwertyuiop1"

	testCases := []struct {
		name          string
		existingRoute *route.Route
		newPeer       *string
		newMetric     *int
		newPrefix     *netip.Prefix
		newGroups     []string
		skipCopying   bool
		shouldCreate  bool
		errFunc       require.ErrorAssertionFunc
		expectedRoute *route.Route
	}{
		{
			name: "Happy Path",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newPeer:      &validPeer,
			newMetric:    &validMetric,
			newPrefix:    &validPrefix,
			newGroups:    []string{routeGroup2},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				ID:          "testingRoute",
				Network:     validPrefix,
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        validPeer,
				Description: "super",
				Masquerade:  false,
				Metric:      validMetric,
				Enabled:     true,
				Groups:      []string{routeGroup2},
			},
		},
		{
			name: "Bad Prefix Should Fail",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newPrefix: &invalidPrefix,
			errFunc:   require.Error,
		},
		{
			name: "Bad Peer Should Fail",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newPeer: &invalidPeer,
			errFunc: require.Error,
		},
		{
			name: "Invalid Metric Should Fail",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newMetric: &invalidMetric,
			errFunc:   require.Error,
		},
		{
			name: "Invalid NetID Should Fail",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       invalidNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newMetric: &invalidMetric,
			errFunc:   require.Error,
		},
		{
			name: "Nil Route Should Fail",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			skipCopying: true,
			errFunc:     require.Error,
		},
		{
			name: "Empty Group List Should Fail",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newGroups: []string{},
			errFunc:   require.Error,
		},
		{
			name: "Empty Group ID String Should Fail",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newGroups: []string{""},
			errFunc:   require.Error,
		},
		{
			name: "Invalid Group Should Fail",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newGroups: []string{routeInvalidGroup1},
			errFunc:   require.Error,
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
					routeToSave.Network = *testCase.newPrefix
				}

				if testCase.newGroups != nil {
					routeToSave.Groups = testCase.newGroups
				}
			}

			err = am.SaveRoute(account.Id, routeToSave)

			testCase.errFunc(t, err)

			if !testCase.shouldCreate {
				return
			}

			account, err = am.Store.GetAccount(account.Id)
			if err != nil {
				t.Fatal(err)
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
		Network:     netip.MustParsePrefix("192.168.0.0/16"),
		NetID:       "superRoute",
		NetworkType: route.IPv4Network,
		Peer:        peer1Key,
		Description: "super",
		Masquerade:  false,
		Metric:      9999,
		Enabled:     true,
		Groups:      []string{routeGroup1},
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
				{
					Type:   UpdateRoutePeer,
					Values: []string{peer2Key},
				},
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				ID:          routeID,
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       "superRoute",
				NetworkType: route.IPv4Network,
				Peer:        peer2Key,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
		},
		{
			name:          "Happy Path Multiple OPS",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				{
					Type:   UpdateRouteDescription,
					Values: []string{"great"},
				},
				{
					Type:   UpdateRouteNetwork,
					Values: []string{"192.168.0.0/24"},
				},
				{
					Type:   UpdateRoutePeer,
					Values: []string{peer2Key},
				},
				{
					Type:   UpdateRouteMetric,
					Values: []string{"3030"},
				},
				{
					Type:   UpdateRouteMasquerade,
					Values: []string{"true"},
				},
				{
					Type:   UpdateRouteEnabled,
					Values: []string{"false"},
				},
				{
					Type:   UpdateRouteNetworkIdentifier,
					Values: []string{"megaRoute"},
				},
				{
					Type:   UpdateRouteGroups,
					Values: []string{routeGroup2},
				},
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				ID:          routeID,
				Network:     netip.MustParsePrefix("192.168.0.0/24"),
				NetID:       "megaRoute",
				NetworkType: route.IPv4Network,
				Peer:        peer2Key,
				Description: "great",
				Masquerade:  true,
				Metric:      3030,
				Enabled:     false,
				Groups:      []string{routeGroup2},
			},
		},
		{
			name:          "Empty Values Should Fail",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				{
					Type: UpdateRoutePeer,
				},
			},
			errFunc: require.Error,
		},
		{
			name:          "Multiple Values Should Fail",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				{
					Type:   UpdateRoutePeer,
					Values: []string{peer2Key, peer1Key},
				},
			},
			errFunc: require.Error,
		},
		{
			name:          "Bad Prefix Should Fail",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				{
					Type:   UpdateRouteNetwork,
					Values: []string{"192.168.0.0/34"},
				},
			},
			errFunc: require.Error,
		},
		{
			name:          "Bad Peer Should Fail",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				{
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
				{
					Type:   UpdateRoutePeer,
					Values: []string{""},
				},
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				ID:          routeID,
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       "superRoute",
				NetworkType: route.IPv4Network,
				Peer:        "",
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
		},
		{
			name:          "Large Network ID Should Fail",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				{
					Type:   UpdateRouteNetworkIdentifier,
					Values: []string{"12345678901234567890qwertyuiopqwertyuiop1"},
				},
			},
			errFunc: require.Error,
		},
		{
			name:          "Empty Network ID Should Fail",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				{
					Type:   UpdateRouteNetworkIdentifier,
					Values: []string{""},
				},
			},
			errFunc: require.Error,
		},
		{
			name:          "Invalid Metric Should Fail",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				{
					Type:   UpdateRouteMetric,
					Values: []string{"999999"},
				},
			},
			errFunc: require.Error,
		},
		{
			name:          "Invalid Boolean Should Fail",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				{
					Type:   UpdateRouteMasquerade,
					Values: []string{"yes"},
				},
			},
			errFunc: require.Error,
		},
		{
			name:          "Invalid Group Should Fail",
			existingRoute: existingRoute,
			operations: []RouteUpdateOperation{
				{
					Type:   UpdateRouteGroups,
					Values: []string{routeInvalidGroup1},
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
		Network:     netip.MustParsePrefix("192.168.0.0/16"),
		NetworkType: route.IPv4Network,
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

func TestGetNetworkMap_RouteSync(t *testing.T) {
	// no routes for peer in different groups
	// no routes when route is deleted
	baseRoute := &route.Route{
		ID:          "testingRoute",
		Network:     netip.MustParsePrefix("192.168.0.0/16"),
		NetID:       "superNet",
		NetworkType: route.IPv4Network,
		Peer:        peer1Key,
		Description: "super",
		Masquerade:  false,
		Metric:      9999,
		Enabled:     true,
		Groups:      []string{routeGroup1},
	}

	am, err := createRouterManager(t)
	if err != nil {
		t.Error("failed to create account manager")
	}

	account, err := initTestRouteAccount(t, am)
	if err != nil {
		t.Error("failed to init testing account")
	}

	newAccountRoutes, err := am.GetNetworkMap(peer1Key)
	require.NoError(t, err)
	require.Len(t, newAccountRoutes.Routes, 0, "new accounts should have no routes")

	createdRoute, err := am.CreateRoute(account.Id, baseRoute.Network.String(), baseRoute.Peer,
		baseRoute.Description, baseRoute.NetID, baseRoute.Masquerade, baseRoute.Metric, baseRoute.Groups, false)
	require.NoError(t, err)

	noDisabledRoutes, err := am.GetNetworkMap(peer1Key)
	require.NoError(t, err)
	require.Len(t, noDisabledRoutes.Routes, 0, "no routes for disabled routes")

	enabledRoute := createdRoute.Copy()
	enabledRoute.Enabled = true

	err = am.SaveRoute(account.Id, enabledRoute)
	require.NoError(t, err)

	peer1Routes, err := am.GetNetworkMap(peer1Key)
	require.NoError(t, err)
	require.Len(t, peer1Routes.Routes, 1, "we should receive one route for peer1")
	require.True(t, enabledRoute.IsEqual(peer1Routes.Routes[0]), "received route should be equal")

	peer2Routes, err := am.GetNetworkMap(peer2Key)
	require.NoError(t, err)
	require.Len(t, peer2Routes.Routes, 0, "no routes for peers not in the distribution group")

	err = am.GroupAddPeer(account.Id, routeGroup1, peer2Key)
	require.NoError(t, err)

	peer2Routes, err = am.GetNetworkMap(peer2Key)
	require.NoError(t, err)
	require.Len(t, peer2Routes.Routes, 1, "we should receive one route")
	require.True(t, peer1Routes.Routes[0].IsEqual(peer2Routes.Routes[0]), "routes should be the same for peers in the same group")

	newGroup := &Group{
		ID:    xid.New().String(),
		Name:  "peer1 group",
		Peers: []string{peer1Key},
	}
	err = am.SaveGroup(account.Id, userID, newGroup)
	require.NoError(t, err)

	rules, err := am.ListRules(account.Id, "testingUser")
	require.NoError(t, err)

	defaultRule := rules[0]
	newRule := defaultRule.Copy()
	newRule.ID = xid.New().String()
	newRule.Name = "peer1 only"
	newRule.Source = []string{newGroup.ID}
	newRule.Destination = []string{newGroup.ID}

	err = am.SaveRule(account.Id, userID, newRule)
	require.NoError(t, err)

	err = am.DeleteRule(account.Id, defaultRule.ID, userID)
	require.NoError(t, err)

	peer1GroupRoutes, err := am.GetNetworkMap(peer1Key)
	require.NoError(t, err)
	require.Len(t, peer1GroupRoutes.Routes, 1, "we should receive one route for peer1")

	peer2GroupRoutes, err := am.GetNetworkMap(peer2Key)
	require.NoError(t, err)
	require.Len(t, peer2GroupRoutes.Routes, 0, "we should not receive routes for peer2")

	err = am.DeleteRoute(account.Id, enabledRoute.ID)
	require.NoError(t, err)

	peer1DeletedRoute, err := am.GetNetworkMap(peer1Key)
	require.NoError(t, err)
	require.Len(t, peer1DeletedRoute.Routes, 0, "we should receive one route for peer1")

}

func createRouterManager(t *testing.T) (*DefaultAccountManager, error) {
	store, err := createRouterStore(t)
	if err != nil {
		return nil, err
	}
	eventStore := &activity.NoopEventStore{}
	return BuildManager(store, NewPeersUpdateManager(), nil, "", "", eventStore)
}

func createRouterStore(t *testing.T) (Store, error) {
	dataDir := t.TempDir()
	store, err := NewFileStore(dataDir)
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
	newGroup := &Group{
		ID:    routeGroup1,
		Name:  routeGroup1,
		Peers: []string{peer1Key},
	}
	err = am.SaveGroup(accountID, userID, newGroup)
	if err != nil {
		return nil, err
	}

	newGroup = &Group{
		ID:    routeGroup2,
		Name:  routeGroup2,
		Peers: []string{peer1Key},
	}

	err = am.SaveGroup(accountID, userID, newGroup)
	if err != nil {
		return nil, err
	}

	return am.Store.GetAccount(account.Id)
}
