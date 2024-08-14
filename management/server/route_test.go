package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/management/server/activity"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/route"
)

const (
	peer1Key           = "BhRPtynAAYRDy08+q4HTMsos8fs4plTP4NOSh7C1ry8="
	peer2Key           = "/yF0+vCfv+mRR5k0dca0TrGdO/oiNeAI58gToZm5NyI="
	peer3Key           = "ayF0+vCfv+mRR5k0dca0TrGdO/oiNeAI58gToZm5NaF="
	peer4Key           = "ayF0+vCfv+mRR5k0dca0TrGdO/oiNeAI58gToZm5acc="
	peer5Key           = "ayF0+vCfv+mRR5k0dca0TrGdO/oiNeAI58gToZm5a55="
	peer1ID            = "peer-1-id"
	peer2ID            = "peer-2-id"
	peer3ID            = "peer-3-id"
	peer4ID            = "peer-4-id"
	peer5ID            = "peer-5-id"
	routeGroup1        = "routeGroup1"
	routeGroup2        = "routeGroup2"
	routeGroup3        = "routeGroup3" // for existing route
	routeGroup4        = "routeGroup4" // for existing route
	routeGroupHA1      = "routeGroupHA1"
	routeGroupHA2      = "routeGroupHA2"
	routeInvalidGroup1 = "routeInvalidGroup1"
	userID             = "testingUser"
	existingRouteID    = "random-id"
)

var existingNetwork = netip.MustParsePrefix("10.10.10.0/24")
var existingDomains = domain.List{"example.com"}

func TestCreateRoute(t *testing.T) {
	type input struct {
		network             netip.Prefix
		domains             domain.List
		keepRoute           bool
		networkType         route.NetworkType
		netID               route.NetID
		peerKey             string
		peerGroupIDs        []string
		description         string
		masquerade          bool
		metric              int
		enabled             bool
		groups              []string
		accessControlGroups []string
	}

	testCases := []struct {
		name            string
		inputArgs       input
		createInitRoute bool
		shouldCreate    bool
		errFunc         require.ErrorAssertionFunc
		expectedRoute   *route.Route
	}{
		{
			name: "Happy Path Network",
			inputArgs: input{
				network:             netip.MustParsePrefix("192.168.0.0/16"),
				networkType:         route.IPv4Network,
				netID:               "happy",
				peerKey:             peer1ID,
				description:         "super",
				masquerade:          false,
				metric:              9999,
				enabled:             true,
				groups:              []string{routeGroup1},
				accessControlGroups: []string{routeGroup1},
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				Network:             netip.MustParsePrefix("192.168.0.0/16"),
				NetworkType:         route.IPv4Network,
				NetID:               "happy",
				Peer:                peer1ID,
				Description:         "super",
				Masquerade:          false,
				Metric:              9999,
				Enabled:             true,
				Groups:              []string{routeGroup1},
				AccessControlGroups: []string{routeGroup1},
			},
		},
		{
			name: "Happy Path Domains",
			inputArgs: input{
				domains:             domain.List{"domain1", "domain2"},
				keepRoute:           true,
				networkType:         route.DomainNetwork,
				netID:               "happy",
				peerKey:             peer1ID,
				description:         "super",
				masquerade:          false,
				metric:              9999,
				enabled:             true,
				groups:              []string{routeGroup1},
				accessControlGroups: []string{routeGroup1},
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				Network:             netip.MustParsePrefix("192.0.2.0/32"),
				Domains:             domain.List{"domain1", "domain2"},
				NetworkType:         route.DomainNetwork,
				NetID:               "happy",
				Peer:                peer1ID,
				Description:         "super",
				Masquerade:          false,
				Metric:              9999,
				Enabled:             true,
				Groups:              []string{routeGroup1},
				KeepRoute:           true,
				AccessControlGroups: []string{routeGroup1},
			},
		},
		{
			name: "Happy Path Peer Groups",
			inputArgs: input{
				network:             netip.MustParsePrefix("192.168.0.0/16"),
				networkType:         route.IPv4Network,
				netID:               "happy",
				peerGroupIDs:        []string{routeGroupHA1, routeGroupHA2},
				description:         "super",
				masquerade:          false,
				metric:              9999,
				enabled:             true,
				groups:              []string{routeGroup1, routeGroup2},
				accessControlGroups: []string{routeGroup1, routeGroup2},
			},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				Network:             netip.MustParsePrefix("192.168.0.0/16"),
				NetworkType:         route.IPv4Network,
				NetID:               "happy",
				PeerGroups:          []string{routeGroupHA1, routeGroupHA2},
				Description:         "super",
				Masquerade:          false,
				Metric:              9999,
				Enabled:             true,
				Groups:              []string{routeGroup1, routeGroup2},
				AccessControlGroups: []string{routeGroup1, routeGroup2},
			},
		},
		{
			name: "Both network and domains provided should fail",
			inputArgs: input{
				network:             netip.MustParsePrefix("192.168.0.0/16"),
				domains:             domain.List{"domain1", "domain2"},
				netID:               "happy",
				peerKey:             peer1ID,
				peerGroupIDs:        []string{routeGroupHA1},
				description:         "super",
				masquerade:          false,
				metric:              9999,
				enabled:             true,
				groups:              []string{routeGroup1},
				accessControlGroups: []string{routeGroup2},
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Both peer and peer_groups Provided Should Fail",
			inputArgs: input{
				network:             netip.MustParsePrefix("192.168.0.0/16"),
				networkType:         route.IPv4Network,
				netID:               "happy",
				peerKey:             peer1ID,
				peerGroupIDs:        []string{routeGroupHA1},
				description:         "super",
				masquerade:          false,
				metric:              9999,
				enabled:             true,
				groups:              []string{routeGroup1},
				accessControlGroups: []string{routeGroup2},
			},
			errFunc:      require.Error,
			shouldCreate: false,
		},
		{
			name: "Bad Peer Should Fail",
			inputArgs: input{
				network:     netip.MustParsePrefix("192.168.0.0/16"),
				networkType: route.IPv4Network,
				netID:       "happy",
				peerKey:     "notExistingPeer",
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
			name: "Bad Peer already has this network route",
			inputArgs: input{
				network:     existingNetwork,
				networkType: route.IPv4Network,
				netID:       "bad",
				peerKey:     peer5ID,
				description: "super",
				masquerade:  false,
				metric:      9999,
				enabled:     true,
				groups:      []string{routeGroup1},
			},
			createInitRoute: true,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name: "Bad Peer already has this domains route",
			inputArgs: input{
				domains:     existingDomains,
				networkType: route.DomainNetwork,
				netID:       "bad",
				peerKey:     peer5ID,
				description: "super",
				masquerade:  false,
				metric:      9999,
				enabled:     true,
				groups:      []string{routeGroup1},
			},
			createInitRoute: true,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name: "Bad Peers Group already has this network route",
			inputArgs: input{
				network:      existingNetwork,
				networkType:  route.IPv4Network,
				netID:        "bad",
				peerGroupIDs: []string{routeGroup1, routeGroup3},
				description:  "super",
				masquerade:   false,
				metric:       9999,
				enabled:      true,
				groups:       []string{routeGroup1},
			},
			createInitRoute: true,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name: "Bad Peers Group already has this domains route",
			inputArgs: input{
				domains:      existingDomains,
				networkType:  route.DomainNetwork,
				netID:        "bad",
				peerGroupIDs: []string{routeGroup1, routeGroup3},
				description:  "super",
				masquerade:   false,
				metric:       9999,
				enabled:      true,
				groups:       []string{routeGroup1},
			},
			createInitRoute: true,
			errFunc:         require.Error,
			shouldCreate:    false,
		},
		{
			name: "Empty Peer Should Create",
			inputArgs: input{
				network:     netip.MustParsePrefix("192.168.0.0/16"),
				networkType: route.IPv4Network,
				netID:       "happy",
				peerKey:     "",
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
				network:     netip.MustParsePrefix("192.168.0.0/16"),
				networkType: route.IPv4Network,
				peerKey:     peer1ID,
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
				network:     netip.MustParsePrefix("192.168.0.0/16"),
				networkType: route.IPv4Network,
				netID:       "happy",
				peerKey:     peer1ID,
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
				network:     netip.MustParsePrefix("192.168.0.0/16"),
				networkType: route.IPv4Network,
				peerKey:     peer1ID,
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
				network:     netip.MustParsePrefix("192.168.0.0/16"),
				networkType: route.IPv4Network,
				netID:       "",
				peerKey:     peer1ID,
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
				network:     netip.MustParsePrefix("192.168.0.0/16"),
				networkType: route.IPv4Network,
				netID:       "NewId",
				peerKey:     peer1ID,
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
				network:     netip.MustParsePrefix("192.168.0.0/16"),
				networkType: route.IPv4Network,
				netID:       "NewId",
				peerKey:     peer1ID,
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
				network:     netip.MustParsePrefix("192.168.0.0/16"),
				networkType: route.IPv4Network,
				netID:       "NewId",
				peerKey:     peer1ID,
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
				t.Errorf("failed to init testing account: %s", err)
			}

			if testCase.createInitRoute {
				groupAll, errInit := account.GetGroupAll()
				require.NoError(t, errInit)
				_, errInit = am.CreateRoute(context.Background(), account.Id, existingNetwork, 1, nil, "", []string{routeGroup3, routeGroup4}, "", existingRouteID, false, 1000, []string{groupAll.ID}, []string{}, true, userID, false)
				require.NoError(t, errInit)
				_, errInit = am.CreateRoute(context.Background(), account.Id, netip.Prefix{}, 3, existingDomains, "", []string{routeGroup3, routeGroup4}, "", existingRouteID, false, 1000, []string{groupAll.ID}, []string{groupAll.ID}, true, userID, false)
				require.NoError(t, errInit)
			}

			outRoute, err := am.CreateRoute(context.Background(), account.Id, testCase.inputArgs.network, testCase.inputArgs.networkType, testCase.inputArgs.domains, testCase.inputArgs.peerKey, testCase.inputArgs.peerGroupIDs, testCase.inputArgs.description, testCase.inputArgs.netID, testCase.inputArgs.masquerade, testCase.inputArgs.metric, testCase.inputArgs.groups, testCase.inputArgs.accessControlGroups, testCase.inputArgs.enabled, userID, testCase.inputArgs.keepRoute)

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
	validPeer := peer2ID
	validUsedPeer := peer5ID
	invalidPeer := "nonExisting"
	validPrefix := netip.MustParsePrefix("192.168.0.0/24")
	placeholderPrefix := netip.MustParsePrefix("192.0.2.0/32")
	invalidPrefix, _ := netip.ParsePrefix("192.168.0.0/34")
	validMetric := 1000
	trueKeepRoute := true
	falseKeepRoute := false
	ipv4networkType := route.IPv4Network
	domainNetworkType := route.DomainNetwork
	invalidMetric := 99999
	validNetID := route.NetID("12345678901234567890qw")
	invalidNetID := route.NetID("12345678901234567890qwertyuiopqwertyuiop1")
	validGroupHA1 := routeGroupHA1
	validGroupHA2 := routeGroupHA2

	testCases := []struct {
		name            string
		existingRoute   *route.Route
		createInitRoute bool
		newPeer         *string
		newPeerGroups   []string
		newMetric       *int
		newPrefix       *netip.Prefix
		newDomains      domain.List
		newNetworkType  *route.NetworkType
		newKeepRoute    *bool
		newGroups       []string
		skipCopying     bool
		shouldCreate    bool
		errFunc         require.ErrorAssertionFunc
		expectedRoute   *route.Route
	}{
		{
			name: "Happy Path Network",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1ID,
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
			name: "Happy Path Domains",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.Prefix{},
				Domains:     domain.List{"example.com"},
				KeepRoute:   false,
				NetID:       validNetID,
				NetworkType: route.DomainNetwork,
				Peer:        peer1ID,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newPeer:      &validPeer,
			newMetric:    &validMetric,
			newPrefix:    &netip.Prefix{},
			newDomains:   domain.List{"example.com", "example2.com"},
			newKeepRoute: &trueKeepRoute,
			newGroups:    []string{routeGroup1},
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				ID:          "testingRoute",
				Network:     placeholderPrefix,
				Domains:     domain.List{"example.com", "example2.com"},
				KeepRoute:   true,
				NetID:       validNetID,
				NetworkType: route.DomainNetwork,
				Peer:        validPeer,
				Description: "super",
				Masquerade:  false,
				Metric:      validMetric,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
		},
		{
			name: "Happy Path Peer Groups",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newPeerGroups: []string{validGroupHA1, validGroupHA2},
			newMetric:     &validMetric,
			newPrefix:     &validPrefix,
			newGroups:     []string{routeGroup2},
			errFunc:       require.NoError,
			shouldCreate:  true,
			expectedRoute: &route.Route{
				ID:          "testingRoute",
				Network:     validPrefix,
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				PeerGroups:  []string{validGroupHA1, validGroupHA2},
				Description: "super",
				Masquerade:  false,
				Metric:      validMetric,
				Enabled:     true,
				Groups:      []string{routeGroup2},
			},
		},
		{
			name: "Both network and domains provided should fail",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newPrefix:  &validPrefix,
			newDomains: domain.List{"example.com"},
			errFunc:    require.Error,
		},
		{
			name: "Both peer and peers_roup Provided Should Fail",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newPeer:       &validPeer,
			newPeerGroups: []string{validGroupHA1},
			errFunc:       require.Error,
		},
		{
			name: "Bad Prefix Should Fail",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     netip.MustParsePrefix("192.168.0.0/16"),
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1ID,
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
				Peer:        peer1ID,
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
				Peer:        peer1ID,
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
				Peer:        peer1ID,
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
				Peer:        peer1ID,
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
				Peer:        peer1ID,
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
				Peer:        peer1ID,
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
				Peer:        peer1ID,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newGroups: []string{routeInvalidGroup1},
			errFunc:   require.Error,
		},
		{
			name: "Allow to modify existing route with new peer",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     existingNetwork,
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1ID,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newPeer:      &validPeer,
			errFunc:      require.NoError,
			shouldCreate: true,
			expectedRoute: &route.Route{
				ID:          "testingRoute",
				Network:     existingNetwork,
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        validPeer,
				PeerGroups:  []string{},
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
		},
		{
			name: "Do not allow to modify existing route with a peer from another route",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     existingNetwork,
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1ID,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			createInitRoute: true,
			newPeer:         &validUsedPeer,
			errFunc:         require.Error,
		},
		{
			name: "Do not allow to modify existing route with a peers group from another route",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     existingNetwork,
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				PeerGroups:  []string{routeGroup3},
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			createInitRoute: true,
			newPeerGroups:   []string{routeGroup4},
			errFunc:         require.Error,
		},
		{
			name: "Allow switching from network route to domains route",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     validPrefix,
				Domains:     nil,
				KeepRoute:   false,
				NetID:       validNetID,
				NetworkType: route.IPv4Network,
				Peer:        peer1ID,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newPrefix:      &netip.Prefix{},
			newDomains:     domain.List{"example.com"},
			newNetworkType: &domainNetworkType,
			newKeepRoute:   &trueKeepRoute,
			errFunc:        require.NoError,
			shouldCreate:   true,
			expectedRoute: &route.Route{
				ID:          "testingRoute",
				Network:     placeholderPrefix,
				NetworkType: route.DomainNetwork,
				Domains:     domain.List{"example.com"},
				KeepRoute:   true,
				NetID:       validNetID,
				Peer:        peer1ID,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
		},
		{
			name: "Allow switching from domains route to network route",
			existingRoute: &route.Route{
				ID:          "testingRoute",
				Network:     placeholderPrefix,
				Domains:     domain.List{"example.com"},
				KeepRoute:   true,
				NetID:       validNetID,
				NetworkType: route.DomainNetwork,
				Peer:        peer1ID,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
			newPrefix:      &validPrefix,
			newDomains:     nil,
			newKeepRoute:   &falseKeepRoute,
			newNetworkType: &ipv4networkType,
			errFunc:        require.NoError,
			shouldCreate:   true,
			expectedRoute: &route.Route{
				ID:          "testingRoute",
				Network:     validPrefix,
				NetworkType: route.IPv4Network,
				KeepRoute:   false,
				Domains:     nil,
				NetID:       validNetID,
				Peer:        peer1ID,
				Description: "super",
				Masquerade:  false,
				Metric:      9999,
				Enabled:     true,
				Groups:      []string{routeGroup1},
			},
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

			if testCase.createInitRoute {
				account.Routes["initRoute"] = &route.Route{
					ID:          "initRoute",
					Network:     existingNetwork,
					NetID:       existingRouteID,
					NetworkType: route.IPv4Network,
					PeerGroups:  []string{routeGroup4},
					Description: "super",
					Masquerade:  false,
					Metric:      9999,
					Enabled:     true,
					Groups:      []string{routeGroup1},
				}
			}

			account.Routes[testCase.existingRoute.ID] = testCase.existingRoute

			err = am.Store.SaveAccount(context.Background(), account)
			if err != nil {
				t.Error("account should be saved")
			}

			var routeToSave *route.Route

			if !testCase.skipCopying {
				routeToSave = testCase.existingRoute.Copy()
				if testCase.newPeer != nil {
					routeToSave.Peer = *testCase.newPeer
				}
				if len(testCase.newPeerGroups) != 0 {
					routeToSave.PeerGroups = testCase.newPeerGroups
				}
				if testCase.newMetric != nil {
					routeToSave.Metric = *testCase.newMetric
				}

				if testCase.newPrefix != nil {
					routeToSave.Network = *testCase.newPrefix
				}

				routeToSave.Domains = testCase.newDomains

				if testCase.newNetworkType != nil {
					routeToSave.NetworkType = *testCase.newNetworkType
				}

				if testCase.newKeepRoute != nil {
					routeToSave.KeepRoute = *testCase.newKeepRoute
				}

				if testCase.newGroups != nil {
					routeToSave.Groups = testCase.newGroups
				}
			}

			err = am.SaveRoute(context.Background(), account.Id, userID, routeToSave)

			testCase.errFunc(t, err)

			if !testCase.shouldCreate {
				return
			}

			account, err = am.Store.GetAccount(context.Background(), account.Id)
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

func TestDeleteRoute(t *testing.T) {
	testingRoute := &route.Route{
		ID:          "testingRoute",
		Network:     netip.MustParsePrefix("192.168.0.0/16"),
		Domains:     domain.List{"domain1", "domain2"},
		KeepRoute:   true,
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

	err = am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Error("failed to save account")
	}

	err = am.DeleteRoute(context.Background(), account.Id, testingRoute.ID, userID)
	if err != nil {
		t.Error("deleting route failed with error: ", err)
	}

	savedAccount, err := am.Store.GetAccount(context.Background(), account.Id)
	if err != nil {
		t.Error("failed to retrieve saved account with error: ", err)
	}

	_, found := savedAccount.Routes[testingRoute.ID]
	if found {
		t.Error("route shouldn't be found after delete")
	}
}

func TestGetNetworkMap_RouteSyncPeerGroups(t *testing.T) {
	baseRoute := &route.Route{
		Network:             netip.MustParsePrefix("192.168.0.0/16"),
		NetID:               "superNet",
		NetworkType:         route.IPv4Network,
		PeerGroups:          []string{routeGroupHA1, routeGroupHA2},
		Description:         "ha route",
		Masquerade:          false,
		Metric:              9999,
		Enabled:             true,
		Groups:              []string{routeGroup1, routeGroup2},
		AccessControlGroups: []string{routeGroup1},
	}

	am, err := createRouterManager(t)
	if err != nil {
		t.Error("failed to create account manager")
	}

	account, err := initTestRouteAccount(t, am)
	if err != nil {
		t.Error("failed to init testing account")
	}

	newAccountRoutes, err := am.GetNetworkMap(context.Background(), peer1ID)
	require.NoError(t, err)
	require.Len(t, newAccountRoutes.Routes, 0, "new accounts should have no routes")

	newRoute, err := am.CreateRoute(context.Background(), account.Id, baseRoute.Network, baseRoute.NetworkType, baseRoute.Domains, baseRoute.Peer, baseRoute.PeerGroups, baseRoute.Description, baseRoute.NetID, baseRoute.Masquerade, baseRoute.Metric, baseRoute.Groups, baseRoute.AccessControlGroups, baseRoute.Enabled, userID, baseRoute.KeepRoute)
	require.NoError(t, err)
	require.Equal(t, newRoute.Enabled, true)

	peer1Routes, err := am.GetNetworkMap(context.Background(), peer1ID)
	require.NoError(t, err)
	assert.Len(t, peer1Routes.Routes, 1, "HA route should have 1 server route")

	peer2Routes, err := am.GetNetworkMap(context.Background(), peer2ID)
	require.NoError(t, err)
	assert.Len(t, peer2Routes.Routes, 1, "HA route should have 1 server route")

	peer4Routes, err := am.GetNetworkMap(context.Background(), peer4ID)
	require.NoError(t, err)
	assert.Len(t, peer4Routes.Routes, 1, "HA route should have 1 server route")

	groups, err := am.ListGroups(context.Background(), account.Id)
	require.NoError(t, err)
	var groupHA1, groupHA2 *nbgroup.Group
	for _, group := range groups {
		switch group.Name {
		case routeGroupHA1:
			groupHA1 = group
		case routeGroupHA2:
			groupHA2 = group
		}
	}

	err = am.GroupDeletePeer(context.Background(), account.Id, groupHA1.ID, peer2ID)
	require.NoError(t, err)

	peer2RoutesAfterDelete, err := am.GetNetworkMap(context.Background(), peer2ID)
	require.NoError(t, err)
	assert.Len(t, peer2RoutesAfterDelete.Routes, 2, "after peer deletion group should have 2 client routes")

	err = am.GroupDeletePeer(context.Background(), account.Id, groupHA2.ID, peer4ID)
	require.NoError(t, err)

	peer2RoutesAfterDelete, err = am.GetNetworkMap(context.Background(), peer2ID)
	require.NoError(t, err)
	assert.Len(t, peer2RoutesAfterDelete.Routes, 1, "after peer deletion group should have only 1 route")

	err = am.GroupAddPeer(context.Background(), account.Id, groupHA2.ID, peer4ID)
	require.NoError(t, err)

	peer1RoutesAfterAdd, err := am.GetNetworkMap(context.Background(), peer1ID)
	require.NoError(t, err)
	assert.Len(t, peer1RoutesAfterAdd.Routes, 1, "HA route should have more than 1 route")

	peer2RoutesAfterAdd, err := am.GetNetworkMap(context.Background(), peer2ID)
	require.NoError(t, err)
	assert.Len(t, peer2RoutesAfterAdd.Routes, 2, "HA route should have 2 client routes")

	err = am.DeleteRoute(context.Background(), account.Id, newRoute.ID, userID)
	require.NoError(t, err)

	peer1DeletedRoute, err := am.GetNetworkMap(context.Background(), peer1ID)
	require.NoError(t, err)
	assert.Len(t, peer1DeletedRoute.Routes, 0, "we should receive one route for peer1")
}

func TestGetNetworkMap_RouteSync(t *testing.T) {
	// no routes for peer in different groups
	// no routes when route is deleted
	baseRoute := &route.Route{
		ID:                  "testingRoute",
		Network:             netip.MustParsePrefix("192.168.0.0/16"),
		NetID:               "superNet",
		NetworkType:         route.IPv4Network,
		Peer:                peer1ID,
		Description:         "super",
		Masquerade:          false,
		Metric:              9999,
		Enabled:             true,
		Groups:              []string{routeGroup1},
		AccessControlGroups: []string{routeGroup1},
	}

	am, err := createRouterManager(t)
	if err != nil {
		t.Error("failed to create account manager")
	}

	account, err := initTestRouteAccount(t, am)
	if err != nil {
		t.Error("failed to init testing account")
	}

	newAccountRoutes, err := am.GetNetworkMap(context.Background(), peer1ID)
	require.NoError(t, err)
	require.Len(t, newAccountRoutes.Routes, 0, "new accounts should have no routes")

	createdRoute, err := am.CreateRoute(context.Background(), account.Id, baseRoute.Network, baseRoute.NetworkType, baseRoute.Domains, peer1ID, []string{}, baseRoute.Description, baseRoute.NetID, baseRoute.Masquerade, baseRoute.Metric, baseRoute.Groups, baseRoute.AccessControlGroups, false, userID, baseRoute.KeepRoute)
	require.NoError(t, err)

	noDisabledRoutes, err := am.GetNetworkMap(context.Background(), peer1ID)
	require.NoError(t, err)
	require.Len(t, noDisabledRoutes.Routes, 0, "no routes for disabled routes")

	enabledRoute := createdRoute.Copy()
	enabledRoute.Enabled = true

	// network map contains route.Route objects that have Route.Peer field filled with Peer.Key instead of Peer.ID
	expectedRoute := enabledRoute.Copy()
	expectedRoute.Peer = peer1Key

	err = am.SaveRoute(context.Background(), account.Id, userID, enabledRoute)
	require.NoError(t, err)

	peer1Routes, err := am.GetNetworkMap(context.Background(), peer1ID)
	require.NoError(t, err)
	require.Len(t, peer1Routes.Routes, 1, "we should receive one route for peer1")
	require.True(t, expectedRoute.IsEqual(peer1Routes.Routes[0]), "received route should be equal")

	peer2Routes, err := am.GetNetworkMap(context.Background(), peer2ID)
	require.NoError(t, err)
	require.Len(t, peer2Routes.Routes, 0, "no routes for peers not in the distribution group")

	err = am.GroupAddPeer(context.Background(), account.Id, routeGroup1, peer2ID)
	require.NoError(t, err)

	peer2Routes, err = am.GetNetworkMap(context.Background(), peer2ID)
	require.NoError(t, err)
	require.Len(t, peer2Routes.Routes, 1, "we should receive one route")
	require.True(t, peer1Routes.Routes[0].IsEqual(peer2Routes.Routes[0]), "routes should be the same for peers in the same group")

	newGroup := &nbgroup.Group{
		ID:    xid.New().String(),
		Name:  "peer1 group",
		Peers: []string{peer1ID},
	}
	err = am.SaveGroup(context.Background(), account.Id, userID, newGroup)
	require.NoError(t, err)

	rules, err := am.ListPolicies(context.Background(), account.Id, "testingUser")
	require.NoError(t, err)

	defaultRule := rules[0]
	newPolicy := defaultRule.Copy()
	newPolicy.ID = xid.New().String()
	newPolicy.Name = "peer1 only"
	newPolicy.Rules[0].Sources = []string{newGroup.ID}
	newPolicy.Rules[0].Destinations = []string{newGroup.ID}

	err = am.SavePolicy(context.Background(), account.Id, userID, newPolicy)
	require.NoError(t, err)

	err = am.DeletePolicy(context.Background(), account.Id, defaultRule.ID, userID)
	require.NoError(t, err)

	peer1GroupRoutes, err := am.GetNetworkMap(context.Background(), peer1ID)
	require.NoError(t, err)
	require.Len(t, peer1GroupRoutes.Routes, 1, "we should receive one route for peer1")

	peer2GroupRoutes, err := am.GetNetworkMap(context.Background(), peer2ID)
	require.NoError(t, err)
	require.Len(t, peer2GroupRoutes.Routes, 0, "we should not receive routes for peer2")

	err = am.DeleteRoute(context.Background(), account.Id, enabledRoute.ID, userID)
	require.NoError(t, err)

	peer1DeletedRoute, err := am.GetNetworkMap(context.Background(), peer1ID)
	require.NoError(t, err)
	require.Len(t, peer1DeletedRoute.Routes, 0, "we should receive one route for peer1")
}

func createRouterManager(t *testing.T) (*DefaultAccountManager, error) {
	t.Helper()
	store, err := createRouterStore(t)
	if err != nil {
		return nil, err
	}
	eventStore := &activity.InMemoryEventStore{}
	return BuildManager(context.Background(), store, NewPeersUpdateManager(nil), nil, "", "netbird.selfhosted", eventStore, nil, false, MocIntegratedValidator{})
}

func createRouterStore(t *testing.T) (Store, error) {
	t.Helper()
	dataDir := t.TempDir()
	store, cleanUp, err := NewTestStoreFromJson(context.Background(), dataDir)
	if err != nil {
		return nil, err
	}
	t.Cleanup(cleanUp)

	return store, nil
}

func initTestRouteAccount(t *testing.T, am *DefaultAccountManager) (*Account, error) {
	t.Helper()

	accountID := "testingAcc"
	domain := "example.com"

	account := newAccountWithId(context.Background(), accountID, userID, domain)
	err := am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		return nil, err
	}

	ips := account.getTakenIPs()
	peer1IP, err := AllocatePeerIP(account.Network.Net, ips)
	if err != nil {
		return nil, err
	}

	peer1 := &nbpeer.Peer{
		IP:     peer1IP,
		ID:     peer1ID,
		Key:    peer1Key,
		Name:   "test-host1@netbird.io",
		UserID: userID,
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
		Status: &nbpeer.PeerStatus{},
	}
	account.Peers[peer1.ID] = peer1

	ips = account.getTakenIPs()
	peer2IP, err := AllocatePeerIP(account.Network.Net, ips)
	if err != nil {
		return nil, err
	}

	peer2 := &nbpeer.Peer{
		IP:     peer2IP,
		ID:     peer2ID,
		Key:    peer2Key,
		Name:   "test-host2@netbird.io",
		UserID: userID,
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
		Status: &nbpeer.PeerStatus{},
	}
	account.Peers[peer2.ID] = peer2

	ips = account.getTakenIPs()
	peer3IP, err := AllocatePeerIP(account.Network.Net, ips)
	if err != nil {
		return nil, err
	}

	peer3 := &nbpeer.Peer{
		IP:     peer3IP,
		ID:     peer3ID,
		Key:    peer3Key,
		Name:   "test-host3@netbird.io",
		UserID: userID,
		Meta: nbpeer.PeerSystemMeta{
			Hostname:  "test-host3@netbird.io",
			GoOS:      "darwin",
			Kernel:    "Darwin",
			Core:      "13.4.1",
			Platform:  "arm64",
			OS:        "darwin",
			WtVersion: "development",
			UIVersion: "development",
		},
		Status: &nbpeer.PeerStatus{},
	}
	account.Peers[peer3.ID] = peer3

	ips = account.getTakenIPs()
	peer4IP, err := AllocatePeerIP(account.Network.Net, ips)
	if err != nil {
		return nil, err
	}

	peer4 := &nbpeer.Peer{
		IP:     peer4IP,
		ID:     peer4ID,
		Key:    peer4Key,
		Name:   "test-host4@netbird.io",
		UserID: userID,
		Meta: nbpeer.PeerSystemMeta{
			Hostname:  "test-host4@netbird.io",
			GoOS:      "linux",
			Kernel:    "Linux",
			Core:      "21.04",
			Platform:  "x86_64",
			OS:        "Ubuntu",
			WtVersion: "development",
			UIVersion: "development",
		},
		Status: &nbpeer.PeerStatus{},
	}
	account.Peers[peer4.ID] = peer4

	ips = account.getTakenIPs()
	peer5IP, err := AllocatePeerIP(account.Network.Net, ips)
	if err != nil {
		return nil, err
	}

	peer5 := &nbpeer.Peer{
		IP:     peer5IP,
		ID:     peer5ID,
		Key:    peer5Key,
		Name:   "test-host4@netbird.io",
		UserID: userID,
		Meta: nbpeer.PeerSystemMeta{
			Hostname:  "test-host4@netbird.io",
			GoOS:      "linux",
			Kernel:    "Linux",
			Core:      "21.04",
			Platform:  "x86_64",
			OS:        "Ubuntu",
			WtVersion: "development",
			UIVersion: "development",
		},
		Status: &nbpeer.PeerStatus{},
	}
	account.Peers[peer5.ID] = peer5

	err = am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		return nil, err
	}
	groupAll, err := account.GetGroupAll()
	if err != nil {
		return nil, err
	}
	err = am.GroupAddPeer(context.Background(), accountID, groupAll.ID, peer1ID)
	if err != nil {
		return nil, err
	}
	err = am.GroupAddPeer(context.Background(), accountID, groupAll.ID, peer2ID)
	if err != nil {
		return nil, err
	}
	err = am.GroupAddPeer(context.Background(), accountID, groupAll.ID, peer3ID)
	if err != nil {
		return nil, err
	}
	err = am.GroupAddPeer(context.Background(), accountID, groupAll.ID, peer4ID)
	if err != nil {
		return nil, err
	}

	newGroup := []*nbgroup.Group{
		{
			ID:    routeGroup1,
			Name:  routeGroup1,
			Peers: []string{peer1.ID},
		},
		{
			ID:    routeGroup2,
			Name:  routeGroup2,
			Peers: []string{peer2.ID},
		},
		{
			ID:    routeGroup3,
			Name:  routeGroup3,
			Peers: []string{peer5.ID},
		},
		{
			ID:    routeGroup4,
			Name:  routeGroup4,
			Peers: []string{peer5.ID},
		},
		{
			ID:    routeGroupHA1,
			Name:  routeGroupHA1,
			Peers: []string{peer1.ID, peer2.ID, peer3.ID}, // we have one non Linux peer, see peer3
		},
		{
			ID:    routeGroupHA2,
			Name:  routeGroupHA2,
			Peers: []string{peer1.ID, peer4.ID},
		},
	}

	for _, group := range newGroup {
		err = am.SaveGroup(context.Background(), accountID, userID, group)
		if err != nil {
			return nil, err
		}
	}

	return am.Store.GetAccount(context.Background(), account.Id)
}

func TestAccount_getPeersRoutesFirewall(t *testing.T) {
	var (
		peerBIp = "100.65.80.39"
		peerCIp = "100.65.254.139"
		peerHIp = "100.65.29.55"
	)

	account := &Account{
		Peers: map[string]*nbpeer.Peer{
			"peerA": {
				ID:     "peerA",
				IP:     net.ParseIP("100.65.14.88"),
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS: "linux",
				},
			},
			"peerB": {
				ID:     "peerB",
				IP:     net.ParseIP(peerBIp),
				Status: &nbpeer.PeerStatus{},
				Meta:   nbpeer.PeerSystemMeta{},
			},
			"peerC": {
				ID:     "peerC",
				IP:     net.ParseIP(peerCIp),
				Status: &nbpeer.PeerStatus{},
			},
			"peerD": {
				ID:     "peerD",
				IP:     net.ParseIP("100.65.62.5"),
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS: "linux",
				},
			},
			"peerE": {
				ID:     "peerE",
				IP:     net.ParseIP("100.65.32.206"),
				Key:    peer1Key,
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS: "linux",
				},
			},
			"peerF": {
				ID:     "peerF",
				IP:     net.ParseIP("100.65.250.202"),
				Status: &nbpeer.PeerStatus{},
			},
			"peerG": {
				ID:     "peerG",
				IP:     net.ParseIP("100.65.13.186"),
				Status: &nbpeer.PeerStatus{},
			},
			"peerH": {
				ID:     "peerH",
				IP:     net.ParseIP(peerHIp),
				Status: &nbpeer.PeerStatus{},
			},
		},
		Groups: map[string]*nbgroup.Group{
			"routingPeer1": {
				ID:   "routingPeer1",
				Name: "RoutingPeer1",
				Peers: []string{
					"peerA",
				},
			},
			"routingPeer2": {
				ID:   "routingPeer2",
				Name: "RoutingPeer2",
				Peers: []string{
					"peerD",
				},
			},
			"route1": {
				ID:    "route1",
				Name:  "Route1",
				Peers: []string{},
			},
			"route2": {
				ID:    "route2",
				Name:  "Route2",
				Peers: []string{},
			},
			"finance": {
				ID:   "finance",
				Name: "Finance",
				Peers: []string{
					"peerF",
					"peerG",
				},
			},
			"dev": {
				ID:   "dev",
				Name: "Dev",
				Peers: []string{
					"peerC",
					"peerH",
					"peerB",
				},
			},
			"contractors": {
				ID:    "contractors",
				Name:  "Contractors",
				Peers: []string{},
			},
		},
		Routes: map[route.ID]*route.Route{
			"route1": {
				ID:                  "route1",
				Network:             netip.MustParsePrefix("192.168.0.0/16"),
				NetID:               "route1",
				NetworkType:         route.IPv4Network,
				PeerGroups:          []string{"routingPeer1", "routingPeer2"},
				Description:         "Route1 ha route",
				Masquerade:          false,
				Metric:              9999,
				Enabled:             true,
				Groups:              []string{"dev"},
				AccessControlGroups: []string{"route1"},
			},
			"route2": {
				ID:                  "route2",
				Network:             existingNetwork,
				NetID:               "route2",
				NetworkType:         route.IPv4Network,
				Peer:                "peerE",
				Description:         "Allow",
				Masquerade:          false,
				Metric:              9999,
				Enabled:             true,
				Groups:              []string{"finance"},
				AccessControlGroups: []string{"route2"},
			},
			"route3": {
				ID:                  "route3",
				Network:             netip.MustParsePrefix("192.0.2.0/32"),
				Domains:             domain.List{"example.com"},
				NetID:               "route3",
				NetworkType:         route.DomainNetwork,
				Peer:                "peerE",
				Description:         "Allow all traffic to routed DNS network",
				Masquerade:          false,
				Metric:              9999,
				Enabled:             true,
				Groups:              []string{"contractors"},
				AccessControlGroups: []string{},
			},
		},
		Policies: []*Policy{
			{
				ID:      "RuleRoute1",
				Name:    "Route1",
				Enabled: true,
				Rules: []*PolicyRule{
					{
						ID:            "RuleRoute1",
						Name:          "ruleRoute1",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      PolicyRuleProtocolALL,
						Action:        PolicyTrafficActionAccept,
						Ports:         []string{"80", "320"},
						Sources: []string{
							"dev",
						},
						Destinations: []string{
							"route1",
						},
					},
				},
			},
			{
				ID:      "RuleRoute2",
				Name:    "Route2",
				Enabled: true,
				Rules: []*PolicyRule{
					{
						ID:            "RuleRoute2",
						Name:          "ruleRoute2",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      PolicyRuleProtocolTCP,
						Action:        PolicyTrafficActionAccept,
						PortRanges: []RulePortRange{
							{
								Start: 80,
								End:   350,
							}, {
								Start: 80,
								End:   350,
							},
						},
						Sources: []string{
							"finance",
						},
						Destinations: []string{
							"route2",
						},
					},
				},
			},
		},
	}

	validatedPeers := make(map[string]struct{})
	for p := range account.Peers {
		validatedPeers[p] = struct{}{}
	}

	t.Run("check applied policies for the route", func(t *testing.T) {
		route1 := account.Routes["route1"]
		policies := getAllRoutePoliciesFromGroups(account, route1.AccessControlGroups)
		assert.Len(t, policies, 1)

		route2 := account.Routes["route2"]
		policies = getAllRoutePoliciesFromGroups(account, route2.AccessControlGroups)
		assert.Len(t, policies, 1)

		route3 := account.Routes["route3"]
		policies = getAllRoutePoliciesFromGroups(account, route3.AccessControlGroups)
		assert.Len(t, policies, 0)
	})

	t.Run("check peer routes firewall rules", func(t *testing.T) {
		routesFirewallRules := account.getPeerRoutesFirewallRules(context.Background(), "peerA", validatedPeers)
		assert.Len(t, routesFirewallRules, 2)

		expectedRoutesFirewallRules := []*RouteFirewallRule{
			{
				SourceRanges: []string{
					fmt.Sprintf(AllowedIPsFormat, peerCIp),
					fmt.Sprintf(AllowedIPsFormat, peerHIp),
					fmt.Sprintf(AllowedIPsFormat, peerBIp),
				},
				Direction:   firewallRuleDirectionIN,
				Action:      "accept",
				Destination: "192.168.0.0/16",
				Protocol:    "all",
				NetworkType: int(route.IPv4Network),
				Port:        80,
			},
			{
				SourceRanges: []string{
					fmt.Sprintf(AllowedIPsFormat, peerCIp),
					fmt.Sprintf(AllowedIPsFormat, peerHIp),
					fmt.Sprintf(AllowedIPsFormat, peerBIp),
				},
				Direction:   firewallRuleDirectionIN,
				Action:      "accept",
				Destination: "192.168.0.0/16",
				Protocol:    "all",
				NetworkType: int(route.IPv4Network),
				Port:        320,
			},
		}
		assert.ElementsMatch(t, routesFirewallRules, expectedRoutesFirewallRules)

		//peerD is also the routing peer for route1, should contain same routes firewall rules as peerA
		routesFirewallRules = account.getPeerRoutesFirewallRules(context.Background(), "peerD", validatedPeers)
		assert.Len(t, routesFirewallRules, 2)
		assert.ElementsMatch(t, routesFirewallRules, expectedRoutesFirewallRules)

		// peerE is a single routing peer for route 2 and route 3
		routesFirewallRules = account.getPeerRoutesFirewallRules(context.Background(), "peerE", validatedPeers)
		assert.Len(t, routesFirewallRules, 3)

		expectedRoutesFirewallRules = []*RouteFirewallRule{
			{
				SourceRanges: []string{"100.65.250.202/32", "100.65.13.186/32"},
				Direction:    firewallRuleDirectionIN,
				Action:       "accept",
				Destination:  existingNetwork.String(),
				Protocol:     "tcp",
				NetworkType:  int(route.IPv4Network),
				PortRange:    RulePortRange{Start: 80, End: 350},
			},
			{
				SourceRanges: []string{"0.0.0.0/0"},
				Direction:    firewallRuleDirectionIN,
				Action:       "accept",
				Destination:  "192.0.2.0/32",
				Protocol:     "all",
				NetworkType:  int(route.DomainNetwork),
				IsDynamic:    true,
			},
			{
				SourceRanges: []string{"::/0"},
				Direction:    firewallRuleDirectionIN,
				Action:       "accept",
				Destination:  "192.0.2.0/32",
				Protocol:     "all",
				NetworkType:  int(route.DomainNetwork),
				IsDynamic:    true,
			},
		}
		assert.ElementsMatch(t, routesFirewallRules, expectedRoutesFirewallRules)

		// peerC is part of route1 distribution groups but should not receive the routes firewall rules
		routesFirewallRules = account.getPeerRoutesFirewallRules(context.Background(), "peerC", validatedPeers)
		assert.Len(t, routesFirewallRules, 0)
	})

}
