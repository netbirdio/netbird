package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"

	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
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

	groups, err := am.Store.GetAccountGroups(context.Background(), store.LockingStrengthShare, account.Id)
	require.NoError(t, err)
	var groupHA1, groupHA2 *types.Group
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

	newGroup := &types.Group{
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
	newPolicy.Name = "peer1 only"
	newPolicy.Rules[0].Sources = []string{newGroup.ID}
	newPolicy.Rules[0].Destinations = []string{newGroup.ID}

	_, err = am.SavePolicy(context.Background(), account.Id, userID, newPolicy)
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

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	require.NoError(t, err)

	return BuildManager(context.Background(), store, NewPeersUpdateManager(nil), nil, "", "netbird.selfhosted", eventStore, nil, false, MocIntegratedValidator{}, metrics)
}

func createRouterStore(t *testing.T) (store.Store, error) {
	t.Helper()
	dataDir := t.TempDir()
	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "", dataDir)
	if err != nil {
		return nil, err
	}
	t.Cleanup(cleanUp)

	return store, nil
}

func initTestRouteAccount(t *testing.T, am *DefaultAccountManager) (*types.Account, error) {
	t.Helper()

	accountID := "testingAcc"
	domain := "example.com"

	account := newAccountWithId(context.Background(), accountID, userID, domain)
	err := am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		return nil, err
	}

	ips := account.GetTakenIPs()
	peer1IP, err := types.AllocatePeerIP(account.Network.Net, ips)
	if err != nil {
		return nil, err
	}

	peer1 := &nbpeer.Peer{
		IP:       peer1IP,
		ID:       peer1ID,
		Key:      peer1Key,
		Name:     "test-host1@netbird.io",
		DNSLabel: "test-host1",
		UserID:   userID,
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
		Status: &nbpeer.PeerStatus{LastSeen: time.Now().UTC(), Connected: true},
	}
	account.Peers[peer1.ID] = peer1

	ips = account.GetTakenIPs()
	peer2IP, err := types.AllocatePeerIP(account.Network.Net, ips)
	if err != nil {
		return nil, err
	}

	peer2 := &nbpeer.Peer{
		IP:       peer2IP,
		ID:       peer2ID,
		Key:      peer2Key,
		Name:     "test-host2@netbird.io",
		DNSLabel: "test-host2",
		UserID:   userID,
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
		Status: &nbpeer.PeerStatus{LastSeen: time.Now().UTC(), Connected: true},
	}
	account.Peers[peer2.ID] = peer2

	ips = account.GetTakenIPs()
	peer3IP, err := types.AllocatePeerIP(account.Network.Net, ips)
	if err != nil {
		return nil, err
	}

	peer3 := &nbpeer.Peer{
		IP:       peer3IP,
		ID:       peer3ID,
		Key:      peer3Key,
		Name:     "test-host3@netbird.io",
		DNSLabel: "test-host3",
		UserID:   userID,
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
		Status: &nbpeer.PeerStatus{LastSeen: time.Now().UTC(), Connected: true},
	}
	account.Peers[peer3.ID] = peer3

	ips = account.GetTakenIPs()
	peer4IP, err := types.AllocatePeerIP(account.Network.Net, ips)
	if err != nil {
		return nil, err
	}

	peer4 := &nbpeer.Peer{
		IP:       peer4IP,
		ID:       peer4ID,
		Key:      peer4Key,
		Name:     "test-host4@netbird.io",
		DNSLabel: "test-host4",
		UserID:   userID,
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
		Status: &nbpeer.PeerStatus{LastSeen: time.Now().UTC(), Connected: true},
	}
	account.Peers[peer4.ID] = peer4

	ips = account.GetTakenIPs()
	peer5IP, err := types.AllocatePeerIP(account.Network.Net, ips)
	if err != nil {
		return nil, err
	}

	peer5 := &nbpeer.Peer{
		IP:       peer5IP,
		ID:       peer5ID,
		Key:      peer5Key,
		Name:     "test-host5@netbird.io",
		DNSLabel: "test-host5",
		UserID:   userID,
		Meta: nbpeer.PeerSystemMeta{
			Hostname:  "test-host5@netbird.io",
			GoOS:      "linux",
			Kernel:    "Linux",
			Core:      "21.04",
			Platform:  "x86_64",
			OS:        "Ubuntu",
			WtVersion: "development",
			UIVersion: "development",
		},
		Status: &nbpeer.PeerStatus{LastSeen: time.Now().UTC(), Connected: true},
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

	newGroup := []*types.Group{
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
		peerJIp = "100.65.29.65"
		peerKIp = "100.65.29.66"
	)

	account := &types.Account{
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
			"peerJ": {
				ID:     "peerJ",
				IP:     net.ParseIP(peerJIp),
				Status: &nbpeer.PeerStatus{},
			},
			"peerK": {
				ID:     "peerK",
				IP:     net.ParseIP(peerKIp),
				Status: &nbpeer.PeerStatus{},
			},
		},
		Groups: map[string]*types.Group{
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
			"route4": {
				ID:    "route4",
				Name:  "route4",
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
			"qa": {
				ID:   "qa",
				Name: "QA",
				Peers: []string{
					"peerJ",
					"peerK",
				},
			},
			"restrictQA": {
				ID:   "restrictQA",
				Name: "restrictQA",
				Peers: []string{
					"peerJ",
				},
			},
			"unrestrictedQA": {
				ID:   "unrestrictedQA",
				Name: "unrestrictedQA",
				Peers: []string{
					"peerK",
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
			"route4": {
				ID:                  "route4",
				Network:             netip.MustParsePrefix("192.168.10.0/16"),
				NetID:               "route4",
				NetworkType:         route.IPv4Network,
				PeerGroups:          []string{"routingPeer1"},
				Description:         "Route4",
				Masquerade:          false,
				Metric:              9999,
				Enabled:             true,
				Groups:              []string{"qa"},
				AccessControlGroups: []string{"route4"},
			},
		},
		Policies: []*types.Policy{
			{
				ID:      "RuleRoute1",
				Name:    "Route1",
				Enabled: true,
				Rules: []*types.PolicyRule{
					{
						ID:            "RuleRoute1",
						Name:          "ruleRoute1",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolALL,
						Action:        types.PolicyTrafficActionAccept,
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
				Rules: []*types.PolicyRule{
					{
						ID:            "RuleRoute2",
						Name:          "ruleRoute2",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolTCP,
						Action:        types.PolicyTrafficActionAccept,
						PortRanges: []types.RulePortRange{
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
			{
				ID:      "RuleRoute4",
				Name:    "RuleRoute4",
				Enabled: true,
				Rules: []*types.PolicyRule{
					{
						ID:            "RuleRoute4",
						Name:          "RuleRoute4",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolTCP,
						Action:        types.PolicyTrafficActionAccept,
						Ports:         []string{"80"},
						Sources: []string{
							"restrictQA",
						},
						Destinations: []string{
							"route4",
						},
					},
				},
			},
			{
				ID:      "RuleRoute5",
				Name:    "RuleRoute5",
				Enabled: true,
				Rules: []*types.PolicyRule{
					{
						ID:            "RuleRoute5",
						Name:          "RuleRoute5",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolALL,
						Action:        types.PolicyTrafficActionAccept,
						Sources: []string{
							"unrestrictedQA",
						},
						Destinations: []string{
							"route4",
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
		policies := types.GetAllRoutePoliciesFromGroups(account, route1.AccessControlGroups)
		assert.Len(t, policies, 1)

		route2 := account.Routes["route2"]
		policies = types.GetAllRoutePoliciesFromGroups(account, route2.AccessControlGroups)
		assert.Len(t, policies, 1)

		route3 := account.Routes["route3"]
		policies = types.GetAllRoutePoliciesFromGroups(account, route3.AccessControlGroups)
		assert.Len(t, policies, 0)
	})

	t.Run("check peer routes firewall rules", func(t *testing.T) {
		routesFirewallRules := account.GetPeerRoutesFirewallRules(context.Background(), "peerA", validatedPeers)
		assert.Len(t, routesFirewallRules, 4)

		expectedRoutesFirewallRules := []*types.RouteFirewallRule{
			{
				SourceRanges: []string{
					fmt.Sprintf(types.AllowedIPsFormat, peerCIp),
					fmt.Sprintf(types.AllowedIPsFormat, peerHIp),
					fmt.Sprintf(types.AllowedIPsFormat, peerBIp),
				},
				Action:      "accept",
				Destination: "192.168.0.0/16",
				Protocol:    "all",
				Port:        80,
			},
			{
				SourceRanges: []string{
					fmt.Sprintf(types.AllowedIPsFormat, peerCIp),
					fmt.Sprintf(types.AllowedIPsFormat, peerHIp),
					fmt.Sprintf(types.AllowedIPsFormat, peerBIp),
				},
				Action:      "accept",
				Destination: "192.168.0.0/16",
				Protocol:    "all",
				Port:        320,
			},
		}
		additionalFirewallRule := []*types.RouteFirewallRule{
			{
				SourceRanges: []string{
					fmt.Sprintf(types.AllowedIPsFormat, peerJIp),
				},
				Action:      "accept",
				Destination: "192.168.10.0/16",
				Protocol:    "tcp",
				Port:        80,
			},
			{
				SourceRanges: []string{
					fmt.Sprintf(types.AllowedIPsFormat, peerKIp),
				},
				Action:      "accept",
				Destination: "192.168.10.0/16",
				Protocol:    "all",
			},
		}

		assert.ElementsMatch(t, orderRuleSourceRanges(routesFirewallRules), orderRuleSourceRanges(append(expectedRoutesFirewallRules, additionalFirewallRule...)))

		// peerD is also the routing peer for route1, should contain same routes firewall rules as peerA
		routesFirewallRules = account.GetPeerRoutesFirewallRules(context.Background(), "peerD", validatedPeers)
		assert.Len(t, routesFirewallRules, 2)
		assert.ElementsMatch(t, orderRuleSourceRanges(routesFirewallRules), orderRuleSourceRanges(expectedRoutesFirewallRules))

		// peerE is a single routing peer for route 2 and route 3
		routesFirewallRules = account.GetPeerRoutesFirewallRules(context.Background(), "peerE", validatedPeers)
		assert.Len(t, routesFirewallRules, 3)

		expectedRoutesFirewallRules = []*types.RouteFirewallRule{
			{
				SourceRanges: []string{"100.65.250.202/32", "100.65.13.186/32"},
				Action:       "accept",
				Destination:  existingNetwork.String(),
				Protocol:     "tcp",
				PortRange:    types.RulePortRange{Start: 80, End: 350},
			},
			{
				SourceRanges: []string{"0.0.0.0/0"},
				Action:       "accept",
				Destination:  "192.0.2.0/32",
				Protocol:     "all",
				Domains:      domain.List{"example.com"},
				IsDynamic:    true,
			},
			{
				SourceRanges: []string{"::/0"},
				Action:       "accept",
				Destination:  "192.0.2.0/32",
				Protocol:     "all",
				Domains:      domain.List{"example.com"},
				IsDynamic:    true,
			},
		}
		assert.ElementsMatch(t, orderRuleSourceRanges(routesFirewallRules), orderRuleSourceRanges(expectedRoutesFirewallRules))

		// peerC is part of route1 distribution groups but should not receive the routes firewall rules
		routesFirewallRules = account.GetPeerRoutesFirewallRules(context.Background(), "peerC", validatedPeers)
		assert.Len(t, routesFirewallRules, 0)
	})

}

// orderList is a helper function to sort a list of strings
func orderRuleSourceRanges(ruleList []*types.RouteFirewallRule) []*types.RouteFirewallRule {
	for _, rule := range ruleList {
		sort.Strings(rule.SourceRanges)
	}
	return ruleList
}

func TestRouteAccountPeersUpdate(t *testing.T) {
	manager, err := createRouterManager(t)
	require.NoError(t, err, "failed to create account manager")

	account, err := initTestRouteAccount(t, manager)
	require.NoError(t, err, "failed to init testing account")

	err = manager.SaveGroups(context.Background(), account.Id, userID, []*types.Group{
		{
			ID:    "groupA",
			Name:  "GroupA",
			Peers: []string{},
		},
		{
			ID:    "groupB",
			Name:  "GroupB",
			Peers: []string{},
		},
		{
			ID:    "groupC",
			Name:  "GroupC",
			Peers: []string{},
		},
	})
	assert.NoError(t, err)

	updMsg := manager.peersUpdateManager.CreateChannel(context.Background(), peer1ID)
	t.Cleanup(func() {
		manager.peersUpdateManager.CloseChannel(context.Background(), peer1ID)
	})

	// Creating a route with no routing peer and no peers in PeerGroups or Groups should not update account peers and not send peer update
	t.Run("creating route no routing peer and no peers in groups", func(t *testing.T) {
		route := route.Route{
			ID:          "testingRoute1",
			Network:     netip.MustParsePrefix("100.65.250.202/32"),
			NetID:       "superNet",
			NetworkType: route.IPv4Network,
			PeerGroups:  []string{"groupA"},
			Description: "super",
			Masquerade:  false,
			Metric:      9999,
			Enabled:     true,
			Groups:      []string{"groupA"},
		}

		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err := manager.CreateRoute(
			context.Background(), account.Id, route.Network, route.NetworkType, route.Domains, route.Peer,
			route.PeerGroups, route.Description, route.NetID, route.Masquerade, route.Metric,
			route.Groups, []string{}, true, userID, route.KeepRoute,
		)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldNotReceiveUpdate")
		}

	})

	// Creating a route with no routing peer and having peers in groups should update account peers and send peer update
	t.Run("creating a route with peers in  PeerGroups and Groups", func(t *testing.T) {
		route := route.Route{
			ID:          "testingRoute2",
			Network:     netip.MustParsePrefix("192.0.2.0/32"),
			NetID:       "superNet",
			NetworkType: route.IPv4Network,
			PeerGroups:  []string{routeGroup3},
			Description: "super",
			Masquerade:  false,
			Metric:      9999,
			Enabled:     true,
			Groups:      []string{routeGroup3},
		}

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		_, err := manager.CreateRoute(
			context.Background(), account.Id, route.Network, route.NetworkType, route.Domains, route.Peer,
			route.PeerGroups, route.Description, route.NetID, route.Masquerade, route.Metric,
			route.Groups, []string{}, true, userID, route.KeepRoute,
		)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}

	})

	baseRoute := route.Route{
		ID:          "testingRoute3",
		Network:     netip.MustParsePrefix("192.168.0.0/16"),
		NetID:       "superNet",
		NetworkType: route.IPv4Network,
		Peer:        peer1ID,
		Description: "super",
		Masquerade:  false,
		Metric:      9999,
		Enabled:     true,
		Groups:      []string{routeGroup1},
	}

	// Creating route should update account peers and send peer update
	t.Run("creating route with a routing peer", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		newRoute, err := manager.CreateRoute(
			context.Background(), account.Id, baseRoute.Network, baseRoute.NetworkType, baseRoute.Domains, baseRoute.Peer,
			baseRoute.PeerGroups, baseRoute.Description, baseRoute.NetID, baseRoute.Masquerade, baseRoute.Metric,
			baseRoute.Groups, []string{}, true, userID, baseRoute.KeepRoute,
		)
		require.NoError(t, err)
		baseRoute = *newRoute

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Updating the route should update account peers and send peer update when there is peers in group
	t.Run("updating route", func(t *testing.T) {
		baseRoute.Groups = []string{routeGroup1, routeGroup2}

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.SaveRoute(context.Background(), account.Id, userID, &baseRoute)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Deleting the route should update account peers and send peer update
	t.Run("deleting route", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err := manager.DeleteRoute(context.Background(), account.Id, baseRoute.ID, userID)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Adding peer to route peer groups that do not have any peers should update account peers and send peer update
	t.Run("adding peer to route peer groups that do not have any peers", func(t *testing.T) {
		newRoute := route.Route{
			Network:     netip.MustParsePrefix("192.168.12.0/16"),
			NetID:       "superNet",
			NetworkType: route.IPv4Network,
			PeerGroups:  []string{"groupB"},
			Description: "super",
			Masquerade:  false,
			Metric:      9999,
			Enabled:     true,
			Groups:      []string{routeGroup1},
		}
		_, err := manager.CreateRoute(
			context.Background(), account.Id, newRoute.Network, newRoute.NetworkType, newRoute.Domains, newRoute.Peer,
			newRoute.PeerGroups, newRoute.Description, newRoute.NetID, newRoute.Masquerade, newRoute.Metric,
			newRoute.Groups, []string{}, true, userID, newRoute.KeepRoute,
		)
		require.NoError(t, err)

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err = manager.SaveGroup(context.Background(), account.Id, userID, &types.Group{
			ID:    "groupB",
			Name:  "GroupB",
			Peers: []string{peer1ID},
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})

	// Adding peer to route groups that do not have any peers should update account peers and send peer update
	t.Run("adding peer to route groups that do not have any peers", func(t *testing.T) {
		newRoute := route.Route{
			Network:     netip.MustParsePrefix("192.168.13.0/16"),
			NetID:       "superNet",
			NetworkType: route.IPv4Network,
			PeerGroups:  []string{"groupB"},
			Description: "super",
			Masquerade:  false,
			Metric:      9999,
			Enabled:     true,
			Groups:      []string{"groupC"},
		}
		_, err := manager.CreateRoute(
			context.Background(), account.Id, newRoute.Network, newRoute.NetworkType, newRoute.Domains, newRoute.Peer,
			newRoute.PeerGroups, newRoute.Description, newRoute.NetID, newRoute.Masquerade, newRoute.Metric,
			newRoute.Groups, []string{}, true, userID, newRoute.KeepRoute,
		)
		require.NoError(t, err)

		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg)
			close(done)
		}()

		err = manager.SaveGroup(context.Background(), account.Id, userID, &types.Group{
			ID:    "groupC",
			Name:  "GroupC",
			Peers: []string{peer1ID},
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for peerShouldReceiveUpdate")
		}
	})
}

func TestAccount_GetPeerNetworkResourceFirewallRules(t *testing.T) {
	var (
		peerBIp = "100.65.80.39"
		peerCIp = "100.65.254.139"
		peerHIp = "100.65.29.55"
		peerJIp = "100.65.29.65"
		peerKIp = "100.65.29.66"
		peerMIp = "100.65.29.67"
		peerOIp = "100.65.29.68"
	)

	account := &types.Account{
		Peers: map[string]*nbpeer.Peer{
			"peerA": {
				ID:     "peerA",
				IP:     net.ParseIP("100.65.14.88"),
				Key:    "peerA",
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
				Key:    "peerD",
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS: "linux",
				},
			},
			"peerE": {
				ID:     "peerE",
				IP:     net.ParseIP("100.65.32.206"),
				Key:    "peerE",
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
			"peerJ": {
				ID:     "peerJ",
				IP:     net.ParseIP(peerJIp),
				Status: &nbpeer.PeerStatus{},
			},
			"peerK": {
				ID:     "peerK",
				IP:     net.ParseIP(peerKIp),
				Status: &nbpeer.PeerStatus{},
			},
			"peerL": {
				ID:     "peerL",
				IP:     net.ParseIP("100.65.19.186"),
				Key:    "peerL",
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS: "linux",
				},
			},
			"peerM": {
				ID:     "peerM",
				IP:     net.ParseIP(peerMIp),
				Status: &nbpeer.PeerStatus{},
			},
			"peerN": {
				ID:     "peerN",
				IP:     net.ParseIP("100.65.20.18"),
				Key:    "peerN",
				Status: &nbpeer.PeerStatus{},
				Meta: nbpeer.PeerSystemMeta{
					GoOS: "linux",
				},
			},
			"peerO": {
				ID:     "peerO",
				IP:     net.ParseIP(peerOIp),
				Status: &nbpeer.PeerStatus{},
			},
		},
		Groups: map[string]*types.Group{
			"router1": {
				ID:   "router1",
				Name: "router1",
				Peers: []string{
					"peerA",
				},
			},
			"router2": {
				ID:   "router2",
				Name: "router2",
				Peers: []string{
					"peerD",
				},
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
				Resources: []types.Resource{
					{ID: "resource2"},
				},
			},
			"qa": {
				ID:   "qa",
				Name: "QA",
				Peers: []string{
					"peerJ",
					"peerK",
				},
			},
			"restrictQA": {
				ID:   "restrictQA",
				Name: "restrictQA",
				Peers: []string{
					"peerJ",
				},
				Resources: []types.Resource{
					{ID: "resource4"},
				},
			},
			"unrestrictedQA": {
				ID:   "unrestrictedQA",
				Name: "unrestrictedQA",
				Peers: []string{
					"peerK",
				},
				Resources: []types.Resource{
					{ID: "resource4"},
				},
			},
			"contractors": {
				ID:    "contractors",
				Name:  "Contractors",
				Peers: []string{},
			},
			"pipeline": {
				ID:    "pipeline",
				Name:  "Pipeline",
				Peers: []string{"peerM"},
			},
			"metrics": {
				ID:    "metrics",
				Name:  "Metrics",
				Peers: []string{"peerN", "peerO"},
				Resources: []types.Resource{
					{ID: "resource6"},
				},
			},
		},
		Networks: []*networkTypes.Network{
			{
				ID:   "network1",
				Name: "Finance Network",
			},
			{
				ID:   "network2",
				Name: "Devs Network",
			},
			{
				ID:   "network3",
				Name: "Contractors Network",
			},
			{
				ID:   "network4",
				Name: "QA Network",
			},
			{
				ID:   "network5",
				Name: "Pipeline Network",
			},
			{
				ID:   "network6",
				Name: "Metrics Network",
			},
		},
		NetworkRouters: []*routerTypes.NetworkRouter{
			{
				ID:         "router1",
				NetworkID:  "network1",
				Peer:       "peerE",
				PeerGroups: nil,
				Masquerade: false,
				Metric:     9999,
				Enabled:    true,
			},
			{
				ID:         "router2",
				NetworkID:  "network2",
				PeerGroups: []string{"router1", "router2"},
				Masquerade: false,
				Metric:     9999,
				Enabled:    true,
			},
			{
				ID:         "router3",
				NetworkID:  "network3",
				Peer:       "peerE",
				PeerGroups: []string{},
				Enabled:    true,
			},
			{
				ID:         "router4",
				NetworkID:  "network4",
				PeerGroups: []string{"router1"},
				Masquerade: false,
				Metric:     9999,
				Enabled:    true,
			},
			{
				ID:         "router5",
				NetworkID:  "network5",
				Peer:       "peerL",
				Masquerade: false,
				Metric:     9999,
				Enabled:    true,
			},
			{
				ID:         "router6",
				NetworkID:  "network6",
				Peer:       "peerN",
				Masquerade: false,
				Metric:     9999,
				Enabled:    true,
			},
		},
		NetworkResources: []*resourceTypes.NetworkResource{
			{
				ID:        "resource1",
				NetworkID: "network1",
				Name:      "Resource 1",
				Type:      "subnet",
				Prefix:    netip.MustParsePrefix("10.10.10.0/24"),
				Enabled:   true,
			},
			{
				ID:        "resource2",
				NetworkID: "network2",
				Name:      "Resource 2",
				Type:      "subnet",
				Prefix:    netip.MustParsePrefix("192.168.0.0/16"),
				Enabled:   true,
			},
			{
				ID:        "resource3",
				NetworkID: "network3",
				Name:      "Resource 3",
				Type:      "domain",
				Domain:    "example.com",
				Enabled:   true,
			},
			{
				ID:        "resource4",
				NetworkID: "network4",
				Name:      "Resource 4",
				Type:      "domain",
				Domain:    "example.com",
				Enabled:   true,
			},
			{
				ID:        "resource5",
				NetworkID: "network5",
				Name:      "Resource 5",
				Type:      "host",
				Prefix:    netip.MustParsePrefix("10.12.12.1/32"),
				Enabled:   true,
			},
			{
				ID:        "resource6",
				NetworkID: "network6",
				Name:      "Resource 6",
				Type:      "domain",
				Domain:    "*.google.com",
				Enabled:   true,
			},
		},
		Policies: []*types.Policy{
			{
				ID:      "policyResource1",
				Name:    "Policy for resource 1",
				Enabled: true,
				Rules: []*types.PolicyRule{
					{
						ID:            "ruleResource1",
						Name:          "ruleResource1",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolTCP,
						Action:        types.PolicyTrafficActionAccept,
						PortRanges: []types.RulePortRange{
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
						DestinationResource: types.Resource{ID: "resource1"},
					},
				},
			},
			{
				ID:      "policyResource2",
				Name:    "Policy for resource 2",
				Enabled: true,
				Rules: []*types.PolicyRule{
					{
						ID:            "ruleResource2",
						Name:          "ruleResource2",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolALL,
						Action:        types.PolicyTrafficActionAccept,
						Ports:         []string{"80", "320"},
						Sources:       []string{"dev"},
						Destinations:  []string{"dev"},
					},
				},
			},
			{
				ID:      "policyResource3",
				Name:    "policyResource3",
				Enabled: true,
				Rules: []*types.PolicyRule{
					{
						ID:            "ruleResource3",
						Name:          "ruleResource3",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolTCP,
						Action:        types.PolicyTrafficActionAccept,
						Ports:         []string{"80"},
						Sources:       []string{"restrictQA"},
						Destinations:  []string{"restrictQA"},
					},
				},
			},
			{
				ID:      "policyResource4",
				Name:    "policyResource4",
				Enabled: true,
				Rules: []*types.PolicyRule{
					{
						ID:            "ruleResource4",
						Name:          "ruleResource4",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolALL,
						Action:        types.PolicyTrafficActionAccept,
						Sources:       []string{"unrestrictedQA"},
						Destinations:  []string{"unrestrictedQA"},
					},
				},
			},
			{
				ID:      "policyResource5",
				Name:    "policyResource5",
				Enabled: true,
				Rules: []*types.PolicyRule{
					{
						ID:                  "ruleResource5",
						Name:                "ruleResource5",
						Bidirectional:       true,
						Enabled:             true,
						Protocol:            types.PolicyRuleProtocolTCP,
						Action:              types.PolicyTrafficActionAccept,
						Ports:               []string{"8080"},
						Sources:             []string{"pipeline"},
						DestinationResource: types.Resource{ID: "resource5"},
					},
				},
			},
			{
				ID:      "policyResource6",
				Name:    "policyResource6",
				Enabled: true,
				Rules: []*types.PolicyRule{
					{
						ID:            "ruleResource6",
						Name:          "ruleResource6",
						Bidirectional: true,
						Enabled:       true,
						Protocol:      types.PolicyRuleProtocolTCP,
						Action:        types.PolicyTrafficActionAccept,
						Ports:         []string{"9090"},
						Sources:       []string{"metrics"},
						Destinations:  []string{"metrics"},
					},
				},
			},
		},
	}

	validatedPeers := make(map[string]struct{})
	for p := range account.Peers {
		validatedPeers[p] = struct{}{}
	}

	t.Run("validate applied policies for different network resources", func(t *testing.T) {
		// Test case: Resource1 is directly applied to the policy (policyResource1)
		policies := account.GetPoliciesForNetworkResource("resource1")
		assert.Len(t, policies, 1, "resource1 should have exactly 1 policy applied directly")

		// Test case: Resource2 is applied to an access control group (dev),
		// which is part of the destination in the policy (policyResource2)
		policies = account.GetPoliciesForNetworkResource("resource2")
		assert.Len(t, policies, 1, "resource2 should have exactly 1 policy applied via access control group")

		// Test case: Resource3 is not applied to any access control group or policy
		policies = account.GetPoliciesForNetworkResource("resource3")
		assert.Len(t, policies, 0, "resource3 should have no policies applied")

		// Test case: Resource4 is applied to the access control groups (restrictQA and unrestrictedQA),
		// which is part of the destination in the policies (policyResource3 and policyResource4)
		policies = account.GetPoliciesForNetworkResource("resource4")
		assert.Len(t, policies, 2, "resource4 should have exactly 2 policy applied via access control groups")

		// Test case: Resource6 is applied to the access control groups (metrics),
		policies = account.GetPoliciesForNetworkResource("resource6")
		assert.Len(t, policies, 1, "resource6 should have exactly 1 policy applied via access control groups")
	})

	t.Run("validate routing peer firewall rules for network resources", func(t *testing.T) {
		resourcePoliciesMap := account.GetResourcePoliciesMap()
		resourceRoutersMap := account.GetResourceRoutersMap()
		_, routes, sourcePeers := account.GetNetworkResourcesRoutesToSync(context.Background(), "peerA", resourcePoliciesMap, resourceRoutersMap)
		firewallRules := account.GetPeerNetworkResourceFirewallRules(context.Background(), account.Peers["peerA"], validatedPeers, routes, resourcePoliciesMap)
		assert.Len(t, firewallRules, 4)
		assert.Len(t, sourcePeers, 5)

		expectedFirewallRules := []*types.RouteFirewallRule{
			{
				SourceRanges: []string{
					fmt.Sprintf(types.AllowedIPsFormat, peerCIp),
					fmt.Sprintf(types.AllowedIPsFormat, peerHIp),
					fmt.Sprintf(types.AllowedIPsFormat, peerBIp),
				},
				Action:      "accept",
				Destination: "192.168.0.0/16",
				Protocol:    "all",
				Port:        80,
			},
			{
				SourceRanges: []string{
					fmt.Sprintf(types.AllowedIPsFormat, peerCIp),
					fmt.Sprintf(types.AllowedIPsFormat, peerHIp),
					fmt.Sprintf(types.AllowedIPsFormat, peerBIp),
				},
				Action:      "accept",
				Destination: "192.168.0.0/16",
				Protocol:    "all",
				Port:        320,
			},
		}

		additionalFirewallRules := []*types.RouteFirewallRule{
			{
				SourceRanges: []string{
					fmt.Sprintf(types.AllowedIPsFormat, peerJIp),
				},
				Action:      "accept",
				Destination: "192.0.2.0/32",
				Protocol:    "tcp",
				Port:        80,
				Domains:     domain.List{"example.com"},
				IsDynamic:   true,
			},
			{
				SourceRanges: []string{
					fmt.Sprintf(types.AllowedIPsFormat, peerKIp),
				},
				Action:      "accept",
				Destination: "192.0.2.0/32",
				Protocol:    "all",
				Domains:     domain.List{"example.com"},
				IsDynamic:   true,
			},
		}
		assert.ElementsMatch(t, orderRuleSourceRanges(firewallRules), orderRuleSourceRanges(append(expectedFirewallRules, additionalFirewallRules...)))

		// peerD is also the routing peer for resource2
		_, routes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), "peerD", resourcePoliciesMap, resourceRoutersMap)
		firewallRules = account.GetPeerNetworkResourceFirewallRules(context.Background(), account.Peers["peerD"], validatedPeers, routes, resourcePoliciesMap)
		assert.Len(t, firewallRules, 2)
		assert.ElementsMatch(t, orderRuleSourceRanges(firewallRules), orderRuleSourceRanges(expectedFirewallRules))
		assert.Len(t, sourcePeers, 3)

		// peerE is a single routing peer for resource1 and resource3
		// PeerE should only receive rules for resource1 since resource3 has no applied policy
		_, routes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), "peerE", resourcePoliciesMap, resourceRoutersMap)
		firewallRules = account.GetPeerNetworkResourceFirewallRules(context.Background(), account.Peers["peerE"], validatedPeers, routes, resourcePoliciesMap)
		assert.Len(t, firewallRules, 1)
		assert.Len(t, sourcePeers, 2)

		expectedFirewallRules = []*types.RouteFirewallRule{
			{
				SourceRanges: []string{"100.65.250.202/32", "100.65.13.186/32"},
				Action:       "accept",
				Destination:  "10.10.10.0/24",
				Protocol:     "tcp",
				PortRange:    types.RulePortRange{Start: 80, End: 350},
			},
		}
		assert.ElementsMatch(t, orderRuleSourceRanges(firewallRules), orderRuleSourceRanges(expectedFirewallRules))

		// peerC is part of distribution groups for resource2 but should not receive the firewall rules
		firewallRules = account.GetPeerRoutesFirewallRules(context.Background(), "peerC", validatedPeers)
		assert.Len(t, firewallRules, 0)

		// peerL is the single routing peer for resource5
		_, routes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), "peerL", resourcePoliciesMap, resourceRoutersMap)
		assert.Len(t, routes, 1)
		firewallRules = account.GetPeerNetworkResourceFirewallRules(context.Background(), account.Peers["peerL"], validatedPeers, routes, resourcePoliciesMap)
		assert.Len(t, firewallRules, 1)
		assert.Len(t, sourcePeers, 1)

		expectedFirewallRules = []*types.RouteFirewallRule{
			{
				SourceRanges: []string{"100.65.29.67/32"},
				Action:       "accept",
				Destination:  "10.12.12.1/32",
				Protocol:     "tcp",
				Port:         8080,
			},
		}
		assert.ElementsMatch(t, orderRuleSourceRanges(firewallRules), orderRuleSourceRanges(expectedFirewallRules))

		_, routes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), "peerM", resourcePoliciesMap, resourceRoutersMap)
		assert.Len(t, routes, 1)
		assert.Len(t, sourcePeers, 0)

		_, routes, sourcePeers = account.GetNetworkResourcesRoutesToSync(context.Background(), "peerN", resourcePoliciesMap, resourceRoutersMap)
		assert.Len(t, routes, 1)
		assert.Len(t, sourcePeers, 2)
	})
}
