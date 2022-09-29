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

//func TestSaveNameServerGroup(t *testing.T) {
//
//	validPeer := nsGroupPeer2Key
//	invalidPeer := "nonExisting"
//	validPrefix := netip.MustParsePrefix("192.168.0.0/24")
//	invalidPrefix, _ := netip.ParsePrefix("192.168.0.0/34")
//	validMetric := 1000
//	invalidMetric := 99999
//	validNetID := "12345678901234567890qw"
//	invalidNetID := "12345678901234567890qwertyuiopqwertyuiop1"
//
//	testCases := []struct {
//		name          string
//		existingRoute *route.Route
//		newPeer       *string
//		newMetric     *int
//		newPrefix     *netip.Prefix
//		skipCopying   bool
//		shouldCreate  bool
//		errFunc       require.ErrorAssertionFunc
//		expectedRoute *route.Route
//	}{
//		{
//			name: "Happy Path",
//			existingRoute: &route.Route{
//				ID:          "testingRoute",
//				Network:     netip.MustParsePrefix("192.168.0.0/16"),
//				NetID:       validNetID,
//				NetworkType: route.IPv4Network,
//				Peer:        nsGroupPeer1Key,
//				Description: "super",
//				Masquerade:  false,
//				Metric:      9999,
//				Enabled:     true,
//			},
//			newPeer:      &validPeer,
//			newMetric:    &validMetric,
//			newPrefix:    &validPrefix,
//			errFunc:      require.NoError,
//			shouldCreate: true,
//			expectedRoute: &route.Route{
//				ID:          "testingRoute",
//				Network:     validPrefix,
//				NetID:       validNetID,
//				NetworkType: route.IPv4Network,
//				Peer:        validPeer,
//				Description: "super",
//				Masquerade:  false,
//				Metric:      validMetric,
//				Enabled:     true,
//			},
//		},
//		{
//			name: "Bad Prefix",
//			existingRoute: &route.Route{
//				ID:          "testingRoute",
//				Network:     netip.MustParsePrefix("192.168.0.0/16"),
//				NetID:       validNetID,
//				NetworkType: route.IPv4Network,
//				Peer:        nsGroupPeer1Key,
//				Description: "super",
//				Masquerade:  false,
//				Metric:      9999,
//				Enabled:     true,
//			},
//			newPrefix: &invalidPrefix,
//			errFunc:   require.Error,
//		},
//		{
//			name: "Bad Peer",
//			existingRoute: &route.Route{
//				ID:          "testingRoute",
//				Network:     netip.MustParsePrefix("192.168.0.0/16"),
//				NetID:       validNetID,
//				NetworkType: route.IPv4Network,
//				Peer:        nsGroupPeer1Key,
//				Description: "super",
//				Masquerade:  false,
//				Metric:      9999,
//				Enabled:     true,
//			},
//			newPeer: &invalidPeer,
//			errFunc: require.Error,
//		},
//		{
//			name: "Invalid Metric",
//			existingRoute: &route.Route{
//				ID:          "testingRoute",
//				Network:     netip.MustParsePrefix("192.168.0.0/16"),
//				NetID:       validNetID,
//				NetworkType: route.IPv4Network,
//				Peer:        nsGroupPeer1Key,
//				Description: "super",
//				Masquerade:  false,
//				Metric:      9999,
//				Enabled:     true,
//			},
//			newMetric: &invalidMetric,
//			errFunc:   require.Error,
//		},
//		{
//			name: "Invalid NetID",
//			existingRoute: &route.Route{
//				ID:          "testingRoute",
//				Network:     netip.MustParsePrefix("192.168.0.0/16"),
//				NetID:       invalidNetID,
//				NetworkType: route.IPv4Network,
//				Peer:        nsGroupPeer1Key,
//				Description: "super",
//				Masquerade:  false,
//				Metric:      9999,
//				Enabled:     true,
//			},
//			newMetric: &invalidMetric,
//			errFunc:   require.Error,
//		},
//		{
//			name: "Nil Route",
//			existingRoute: &route.Route{
//				ID:          "testingRoute",
//				Network:     netip.MustParsePrefix("192.168.0.0/16"),
//				NetID:       validNetID,
//				NetworkType: route.IPv4Network,
//				Peer:        nsGroupPeer1Key,
//				Description: "super",
//				Masquerade:  false,
//				Metric:      9999,
//				Enabled:     true,
//			},
//			skipCopying: true,
//			errFunc:     require.Error,
//		},
//	}
//	for _, testCase := range testCases {
//		t.Run(testCase.name, func(t *testing.T) {
//			am, err := createNSManager(t)
//			if err != nil {
//				t.Error("failed to create account manager")
//			}
//
//			account, err := initTestNSAccount(t, am)
//			if err != nil {
//				t.Error("failed to init testing account")
//			}
//
//			account.Routes[testCase.existingRoute.ID] = testCase.existingRoute
//
//			err = am.Store.SaveAccount(account)
//			if err != nil {
//				t.Error("account should be saved")
//			}
//
//			var routeToSave *route.Route
//
//			if !testCase.skipCopying {
//				routeToSave = testCase.existingRoute.Copy()
//				if testCase.newPeer != nil {
//					routeToSave.Peer = *testCase.newPeer
//				}
//
//				if testCase.newMetric != nil {
//					routeToSave.Metric = *testCase.newMetric
//				}
//
//				if testCase.newPrefix != nil {
//					routeToSave.Network = *testCase.newPrefix
//				}
//			}
//
//			err = am.SaveRoute(account.Id, routeToSave)
//
//			testCase.errFunc(t, err)
//
//			if !testCase.shouldCreate {
//				return
//			}
//
//			savedRoute, saved := account.Routes[testCase.expectedRoute.ID]
//			require.True(t, saved)
//
//			if !testCase.expectedRoute.IsEqual(savedRoute) {
//				t.Errorf("new route didn't match expected route:\nGot %#v\nExpected:%#v\n", savedRoute, testCase.expectedRoute)
//			}
//
//		})
//	}
//}
//
//func TestUpdateNameServerGroup(t *testing.T) {
//	routeID := "testingRouteID"
//
//	existingRoute := &route.Route{
//		ID:          routeID,
//		Network:     netip.MustParsePrefix("192.168.0.0/16"),
//		NetID:       "superRoute",
//		NetworkType: route.IPv4Network,
//		Peer:        nsGroupPeer1Key,
//		Description: "super",
//		Masquerade:  false,
//		Metric:      9999,
//		Enabled:     true,
//	}
//
//	testCases := []struct {
//		name          string
//		existingRoute *route.Route
//		operations    []RouteUpdateOperation
//		shouldCreate  bool
//		errFunc       require.ErrorAssertionFunc
//		expectedRoute *route.Route
//	}{
//		{
//			name:          "Happy Path Single OPS",
//			existingRoute: existingRoute,
//			operations: []RouteUpdateOperation{
//				RouteUpdateOperation{
//					Type:   UpdateRoutePeer,
//					Values: []string{nsGroupPeer2Key},
//				},
//			},
//			errFunc:      require.NoError,
//			shouldCreate: true,
//			expectedRoute: &route.Route{
//				ID:          routeID,
//				Network:     netip.MustParsePrefix("192.168.0.0/16"),
//				NetID:       "superRoute",
//				NetworkType: route.IPv4Network,
//				Peer:        nsGroupPeer2Key,
//				Description: "super",
//				Masquerade:  false,
//				Metric:      9999,
//				Enabled:     true,
//			},
//		},
//		{
//			name:          "Happy Path Multiple OPS",
//			existingRoute: existingRoute,
//			operations: []RouteUpdateOperation{
//				RouteUpdateOperation{
//					Type:   UpdateRouteDescription,
//					Values: []string{"great"},
//				},
//				RouteUpdateOperation{
//					Type:   UpdateRouteNetwork,
//					Values: []string{"192.168.0.0/24"},
//				},
//				RouteUpdateOperation{
//					Type:   UpdateRoutePeer,
//					Values: []string{nsGroupPeer2Key},
//				},
//				RouteUpdateOperation{
//					Type:   UpdateRouteMetric,
//					Values: []string{"3030"},
//				},
//				RouteUpdateOperation{
//					Type:   UpdateRouteMasquerade,
//					Values: []string{"true"},
//				},
//				RouteUpdateOperation{
//					Type:   UpdateRouteEnabled,
//					Values: []string{"false"},
//				},
//				RouteUpdateOperation{
//					Type:   UpdateRouteNetworkIdentifier,
//					Values: []string{"megaRoute"},
//				},
//			},
//			errFunc:      require.NoError,
//			shouldCreate: true,
//			expectedRoute: &route.Route{
//				ID:          routeID,
//				Network:     netip.MustParsePrefix("192.168.0.0/24"),
//				NetID:       "megaRoute",
//				NetworkType: route.IPv4Network,
//				Peer:        nsGroupPeer2Key,
//				Description: "great",
//				Masquerade:  true,
//				Metric:      3030,
//				Enabled:     false,
//			},
//		},
//		{
//			name:          "Empty Values",
//			existingRoute: existingRoute,
//			operations: []RouteUpdateOperation{
//				RouteUpdateOperation{
//					Type: UpdateRoutePeer,
//				},
//			},
//			errFunc: require.Error,
//		},
//		{
//			name:          "Multiple Values",
//			existingRoute: existingRoute,
//			operations: []RouteUpdateOperation{
//				RouteUpdateOperation{
//					Type:   UpdateRoutePeer,
//					Values: []string{nsGroupPeer2Key, nsGroupPeer1Key},
//				},
//			},
//			errFunc: require.Error,
//		},
//		{
//			name:          "Bad Prefix",
//			existingRoute: existingRoute,
//			operations: []RouteUpdateOperation{
//				RouteUpdateOperation{
//					Type:   UpdateRouteNetwork,
//					Values: []string{"192.168.0.0/34"},
//				},
//			},
//			errFunc: require.Error,
//		},
//		{
//			name:          "Bad Peer",
//			existingRoute: existingRoute,
//			operations: []RouteUpdateOperation{
//				RouteUpdateOperation{
//					Type:   UpdateRoutePeer,
//					Values: []string{"non existing Peer"},
//				},
//			},
//			errFunc: require.Error,
//		},
//		{
//			name:          "Empty Peer",
//			existingRoute: existingRoute,
//			operations: []RouteUpdateOperation{
//				RouteUpdateOperation{
//					Type:   UpdateRoutePeer,
//					Values: []string{""},
//				},
//			},
//			errFunc:      require.NoError,
//			shouldCreate: true,
//			expectedRoute: &route.Route{
//				ID:          routeID,
//				Network:     netip.MustParsePrefix("192.168.0.0/16"),
//				NetID:       "superRoute",
//				NetworkType: route.IPv4Network,
//				Peer:        "",
//				Description: "super",
//				Masquerade:  false,
//				Metric:      9999,
//				Enabled:     true,
//			},
//		},
//		{
//			name:          "Large Network ID",
//			existingRoute: existingRoute,
//			operations: []RouteUpdateOperation{
//				RouteUpdateOperation{
//					Type:   UpdateRouteNetworkIdentifier,
//					Values: []string{"12345678901234567890qwertyuiopqwertyuiop1"},
//				},
//			},
//			errFunc: require.Error,
//		},
//		{
//			name:          "Empty Network ID",
//			existingRoute: existingRoute,
//			operations: []RouteUpdateOperation{
//				RouteUpdateOperation{
//					Type:   UpdateRouteNetworkIdentifier,
//					Values: []string{""},
//				},
//			},
//			errFunc: require.Error,
//		},
//		{
//			name:          "Invalid Metric",
//			existingRoute: existingRoute,
//			operations: []RouteUpdateOperation{
//				RouteUpdateOperation{
//					Type:   UpdateRouteMetric,
//					Values: []string{"999999"},
//				},
//			},
//			errFunc: require.Error,
//		},
//		{
//			name:          "Invalid Boolean",
//			existingRoute: existingRoute,
//			operations: []RouteUpdateOperation{
//				RouteUpdateOperation{
//					Type:   UpdateRouteMasquerade,
//					Values: []string{"yes"},
//				},
//			},
//			errFunc: require.Error,
//		},
//	}
//	for _, testCase := range testCases {
//		t.Run(testCase.name, func(t *testing.T) {
//			am, err := createNSManager(t)
//			if err != nil {
//				t.Error("failed to create account manager")
//			}
//
//			account, err := initTestNSAccount(t, am)
//			if err != nil {
//				t.Error("failed to init testing account")
//			}
//
//			account.Routes[testCase.existingRoute.ID] = testCase.existingRoute
//
//			err = am.Store.SaveAccount(account)
//			if err != nil {
//				t.Error("account should be saved")
//			}
//
//			updatedRoute, err := am.UpdateRoute(account.Id, testCase.existingRoute.ID, testCase.operations)
//
//			testCase.errFunc(t, err)
//
//			if !testCase.shouldCreate {
//				return
//			}
//
//			testCase.expectedRoute.ID = updatedRoute.ID
//
//			if !testCase.expectedRoute.IsEqual(updatedRoute) {
//				t.Errorf("new route didn't match expected route:\nGot %#v\nExpected:%#v\n", updatedRoute, testCase.expectedRoute)
//			}
//
//		})
//	}
//}
//
//func TestDeleteNameServerGroup(t *testing.T) {
//
//	testingRoute := &route.Route{
//		ID:          "testingRoute",
//		Network:     netip.MustParsePrefix("192.168.0.0/16"),
//		NetworkType: route.IPv4Network,
//		Peer:        nsGroupPeer1Key,
//		Description: "super",
//		Masquerade:  false,
//		Metric:      9999,
//		Enabled:     true,
//	}
//
//	am, err := createNSManager(t)
//	if err != nil {
//		t.Error("failed to create account manager")
//	}
//
//	account, err := initTestNSAccount(t, am)
//	if err != nil {
//		t.Error("failed to init testing account")
//	}
//
//	account.Routes[testingRoute.ID] = testingRoute
//
//	err = am.Store.SaveAccount(account)
//	if err != nil {
//		t.Error("failed to save account")
//	}
//
//	err = am.DeleteRoute(account.Id, testingRoute.ID)
//	if err != nil {
//		t.Error("deleting route failed with error: ", err)
//	}
//
//	savedAccount, err := am.Store.GetAccount(account.Id)
//	if err != nil {
//		t.Error("failed to retrieve saved account with error: ", err)
//	}
//
//	_, found := savedAccount.Routes[testingRoute.ID]
//	if found {
//		t.Error("route shouldn't be found after delete")
//	}
//}
//
//func TestGetNetworkMap_NameServerGroupSync(t *testing.T) {
//	// no routes for peer in different groups
//	// no routes when route is deleted
//
//	baseRoute := &route.Route{
//		ID:          "testingRoute",
//		Network:     netip.MustParsePrefix("192.168.0.0/16"),
//		NetID:       "superNet",
//		NetworkType: route.IPv4Network,
//		Peer:        nsGroupPeer1Key,
//		Description: "super",
//		Masquerade:  false,
//		Metric:      9999,
//		Enabled:     true,
//	}
//
//	am, err := createNSManager(t)
//	if err != nil {
//		t.Error("failed to create account manager")
//	}
//
//	account, err := initTestNSAccount(t, am)
//	if err != nil {
//		t.Error("failed to init testing account")
//	}
//
//	newAccountRoutes, err := am.GetNetworkMap(nsGroupPeer1Key)
//	require.NoError(t, err)
//	require.Len(t, newAccountRoutes.Routes, 0, "new accounts should have no routes")
//
//	createdRoute, err := am.CreateRoute(account.Id, baseRoute.Network.String(), baseRoute.Peer,
//		baseRoute.Description, baseRoute.NetID, baseRoute.Masquerade, baseRoute.Metric, false)
//	require.NoError(t, err)
//
//	noDisabledRoutes, err := am.GetNetworkMap(nsGroupPeer1Key)
//	require.NoError(t, err)
//	require.Len(t, noDisabledRoutes.Routes, 0, "no routes for disabled routes")
//
//	enabledRoute := createdRoute.Copy()
//	enabledRoute.Enabled = true
//
//	err = am.SaveRoute(account.Id, enabledRoute)
//	require.NoError(t, err)
//
//	peer1Routes, err := am.GetNetworkMap(nsGroupPeer1Key)
//	require.NoError(t, err)
//	require.Len(t, peer1Routes.Routes, 1, "we should receive one route for peer1")
//	require.True(t, enabledRoute.IsEqual(peer1Routes.Routes[0]), "received route should be equal")
//
//	peer2Routes, err := am.GetNetworkMap(nsGroupPeer2Key)
//	require.NoError(t, err)
//	require.Len(t, peer2Routes.Routes, 1, "we should receive one route for peer2")
//	require.True(t, peer1Routes.Routes[0].IsEqual(peer2Routes.Routes[0]), "routes should be the same for peers in the same group")
//
//	newGroup := &Group{
//		ID:    xid.New().String(),
//		Name:  "peer1 group",
//		Peers: []string{nsGroupPeer1Key},
//	}
//	err = am.SaveGroup(account.Id, newGroup)
//	require.NoError(t, err)
//
//	rules, err := am.ListRules(account.Id)
//	require.NoError(t, err)
//
//	defaultRule := rules[0]
//	newRule := defaultRule.Copy()
//	newRule.ID = xid.New().String()
//	newRule.Name = "peer1 only"
//	newRule.Source = []string{newGroup.ID}
//	newRule.Destination = []string{newGroup.ID}
//
//	err = am.SaveRule(account.Id, newRule)
//	require.NoError(t, err)
//
//	err = am.DeleteRule(account.Id, defaultRule.ID)
//	require.NoError(t, err)
//
//	peer1GroupRoutes, err := am.GetNetworkMap(nsGroupPeer1Key)
//	require.NoError(t, err)
//	require.Len(t, peer1GroupRoutes.Routes, 1, "we should receive one route for peer1")
//
//	peer2GroupRoutes, err := am.GetNetworkMap(nsGroupPeer2Key)
//	require.NoError(t, err)
//	require.Len(t, peer2GroupRoutes.Routes, 0, "we should not receive routes for peer2")
//
//	err = am.DeleteRoute(account.Id, enabledRoute.ID)
//	require.NoError(t, err)
//
//	peer1DeletedRoute, err := am.GetNetworkMap(nsGroupPeer1Key)
//	require.NoError(t, err)
//	require.Len(t, peer1DeletedRoute.Routes, 0, "we should receive one route for peer1")
//
//}

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
