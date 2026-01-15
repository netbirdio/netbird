package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/prometheus/client_golang/prometheus/push"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	ephemeral_manager "github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/internals/server/config"
	nbAccount "github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/auth"
)

func verifyCanAddPeerToAccount(t *testing.T, manager nbAccount.Manager, account *types.Account, userID string) {
	t.Helper()
	peer := &nbpeer.Peer{
		Key:  "BhRPtynAAYRDy08+q4HTMsos8fs4plTP4NOSh7C1ry8=",
		Name: "test-host@netbird.io",
		Meta: nbpeer.PeerSystemMeta{
			Hostname:  "test-host@netbird.io",
			GoOS:      "linux",
			Kernel:    "Linux",
			Core:      "21.04",
			Platform:  "x86_64",
			OS:        "Ubuntu",
			WtVersion: "development",
			UIVersion: "development",
		},
	}

	var setupKey string
	for _, key := range account.SetupKeys {
		setupKey = key.Key
	}

	_, _, _, err := manager.AddPeer(context.Background(), "", setupKey, userID, peer, false)
	if err != nil {
		t.Error("expected to add new peer successfully after creating new account, but failed", err)
	}
}

func verifyNewAccountHasDefaultFields(t *testing.T, account *types.Account, createdBy string, domain string, expectedUsers []string) {
	t.Helper()
	if len(account.Peers) != 0 {
		t.Errorf("expected account to have len(Peers) = %v, got %v", 0, len(account.Peers))
	}

	if len(account.SetupKeys) != 0 {
		t.Errorf("expected account to have len(SetupKeys) = %v, got %v", 2, len(account.SetupKeys))
	}

	ipNet := net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.IPMask{255, 192, 0, 0}}
	if !ipNet.Contains(account.Network.Net.IP) {
		t.Errorf("expected account's Network to be a subnet of %v, got %v", ipNet.String(), account.Network.Net.String())
	}

	g, err := account.GetGroupAll()
	if err != nil {
		t.Fatal(err)
	}
	if g.Name != "All" {
		t.Errorf("expecting account to have group ALL added by default")
	}
	if len(account.Users) != len(expectedUsers) {
		t.Errorf("expecting account to have %d users, got %d", len(expectedUsers), len(account.Users))
	}

	if account.Users[createdBy] == nil {
		t.Errorf("expecting account to have createdBy user %s in a user map ", createdBy)
	}

	for _, expectedUserID := range expectedUsers {
		if account.Users[expectedUserID] == nil {
			t.Errorf("expecting account to have a user %s in a user map", expectedUserID)
		}
	}

	if account.CreatedBy != createdBy {
		t.Errorf("expecting newly created account to be created by user %s, got %s", createdBy, account.CreatedBy)
	}

	if account.CreatedAt.IsZero() {
		t.Errorf("expecting newly created account to have a non-zero creation time")
	}

	if account.Domain != domain {
		t.Errorf("expecting newly created account to have domain %s, got %s", domain, account.Domain)
	}
}

func TestAccount_GetPeerNetworkMap(t *testing.T) {
	peerID1 := "peer-1"
	peerID2 := "peer-2"
	// peerID3 := "peer-3"
	tt := []struct {
		name                 string
		accountSettings      types.Settings
		peerID               string
		expectedPeers        []string
		expectedOfflinePeers []string
		peers                map[string]*nbpeer.Peer
	}{
		{
			name:                 "Should return ALL peers when global peer login expiration disabled",
			accountSettings:      types.Settings{PeerLoginExpirationEnabled: false, PeerLoginExpiration: time.Hour},
			peerID:               peerID1,
			expectedPeers:        []string{peerID2},
			expectedOfflinePeers: []string{},
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					ID:       peerID1,
					Key:      "peer-1-key",
					IP:       net.IP{100, 64, 0, 1},
					Name:     peerID1,
					DNSLabel: peerID1,
					Status: &nbpeer.PeerStatus{
						LastSeen:     time.Now().UTC(),
						Connected:    false,
						LoginExpired: true,
					},
					UserID:    userID,
					LastLogin: util.ToPtr(time.Now().UTC().Add(-time.Hour * 24 * 30 * 30)),
				},
				"peer-2": {
					ID:       peerID2,
					Key:      "peer-2-key",
					IP:       net.IP{100, 64, 0, 1},
					Name:     peerID2,
					DNSLabel: peerID2,
					Status: &nbpeer.PeerStatus{
						LastSeen:     time.Now().UTC(),
						Connected:    false,
						LoginExpired: false,
					},
					UserID:                 userID,
					LastLogin:              util.ToPtr(time.Now().UTC()),
					LoginExpirationEnabled: true,
				},
			},
		},
		{
			name:                 "Should return no peers when global peer login expiration enabled and peers expired",
			accountSettings:      types.Settings{PeerLoginExpirationEnabled: true, PeerLoginExpiration: time.Hour},
			peerID:               peerID1,
			expectedPeers:        []string{},
			expectedOfflinePeers: []string{peerID2},
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					ID:       peerID1,
					Key:      "peer-1-key",
					IP:       net.IP{100, 64, 0, 1},
					Name:     peerID1,
					DNSLabel: peerID1,
					Status: &nbpeer.PeerStatus{
						LastSeen:     time.Now().UTC(),
						Connected:    false,
						LoginExpired: true,
					},
					UserID:                 userID,
					LastLogin:              util.ToPtr(time.Now().UTC().Add(-time.Hour * 24 * 30 * 30)),
					LoginExpirationEnabled: true,
				},
				"peer-2": {
					ID:       peerID2,
					Key:      "peer-2-key",
					IP:       net.IP{100, 64, 0, 1},
					Name:     peerID2,
					DNSLabel: peerID2,
					Status: &nbpeer.PeerStatus{
						LastSeen:     time.Now().UTC(),
						Connected:    false,
						LoginExpired: true,
					},
					UserID:                 userID,
					LastLogin:              util.ToPtr(time.Now().UTC().Add(-time.Hour * 24 * 30 * 30)),
					LoginExpirationEnabled: true,
				},
			},
		},
		// {
		// 	name:                 "Should return only peers that are approved when peer approval is enabled",
		// 	accountSettings:      Settings{PeerApprovalEnabled: true},
		// 	peerID:               peerID1,
		// 	expectedPeers:        []string{peerID3},
		// 	expectedOfflinePeers: []string{},
		// 	peers: map[string]*Peer{
		// 		"peer-1": {
		// 			ID:       peerID1,
		// 			Key:      "peer-1-key",
		// 			IP:       net.IP{100, 64, 0, 1},
		// 			Name:     peerID1,
		// 			DNSLabel: peerID1,
		// 			Status: &PeerStatus{
		// 				LastSeen:  time.Now().UTC(),
		// 				Connected: false,
		// 				Approved:  true,
		// 			},
		// 			UserID:    userID,
		// 			LastLogin: time.Now().UTC().Add(-time.Hour * 24 * 30 * 30),
		// 		},
		// 		"peer-2": {
		// 			ID:       peerID2,
		// 			Key:      "peer-2-key",
		// 			IP:       net.IP{100, 64, 0, 1},
		// 			Name:     peerID2,
		// 			DNSLabel: peerID2,
		// 			Status: &PeerStatus{
		// 				LastSeen:  time.Now().UTC(),
		// 				Connected: false,
		// 				Approved:  false,
		// 			},
		// 			UserID:    userID,
		// 			LastLogin: time.Now().UTC().Add(-time.Hour * 24 * 30 * 30),
		// 		},
		// 		"peer-3": {
		// 			ID:       peerID3,
		// 			Key:      "peer-3-key",
		// 			IP:       net.IP{100, 64, 0, 1},
		// 			Name:     peerID3,
		// 			DNSLabel: peerID3,
		// 			Status: &PeerStatus{
		// 				LastSeen:  time.Now().UTC(),
		// 				Connected: false,
		// 				Approved:  true,
		// 			},
		// 			UserID:    userID,
		// 			LastLogin: time.Now().UTC().Add(-time.Hour * 24 * 30 * 30),
		// 		},
		// 	},
		// },
		// {
		// 	name:                 "Should return all peers when peer approval is disabled",
		// 	accountSettings:      Settings{PeerApprovalEnabled: false},
		// 	peerID:               peerID1,
		// 	expectedPeers:        []string{peerID2, peerID3},
		// 	expectedOfflinePeers: []string{},
		// 	peers: map[string]*Peer{
		// 		"peer-1": {
		// 			ID:       peerID1,
		// 			Key:      "peer-1-key",
		// 			IP:       net.IP{100, 64, 0, 1},
		// 			Name:     peerID1,
		// 			DNSLabel: peerID1,
		// 			Status: &PeerStatus{
		// 				LastSeen:  time.Now().UTC(),
		// 				Connected: false,
		// 				Approved:  true,
		// 			},
		// 			UserID:    userID,
		// 			LastLogin: time.Now().UTC().Add(-time.Hour * 24 * 30 * 30),
		// 		},
		// 		"peer-2": {
		// 			ID:       peerID2,
		// 			Key:      "peer-2-key",
		// 			IP:       net.IP{100, 64, 0, 1},
		// 			Name:     peerID2,
		// 			DNSLabel: peerID2,
		// 			Status: &PeerStatus{
		// 				LastSeen:  time.Now().UTC(),
		// 				Connected: false,
		// 				Approved:  false,
		// 			},
		// 			UserID:    userID,
		// 			LastLogin: time.Now().UTC().Add(-time.Hour * 24 * 30 * 30),
		// 		},
		// 		"peer-3": {
		// 			ID:       peerID3,
		// 			Key:      "peer-3-key",
		// 			IP:       net.IP{100, 64, 0, 1},
		// 			Name:     peerID3,
		// 			DNSLabel: peerID3,
		// 			Status: &PeerStatus{
		// 				LastSeen:  time.Now().UTC(),
		// 				Connected: false,
		// 				Approved:  true,
		// 			},
		// 			UserID:    userID,
		// 			LastLogin: time.Now().UTC().Add(-time.Hour * 24 * 30 * 30),
		// 		},
		// 	},
		// },
		// {
		// 	name:                 "Should return no peers when peer approval is enabled and the requesting peer is not approved",
		// 	accountSettings:      Settings{PeerApprovalEnabled: true},
		// 	peerID:               peerID1,
		// 	expectedPeers:        []string{},
		// 	expectedOfflinePeers: []string{},
		// 	peers: map[string]*Peer{
		// 		"peer-1": {
		// 			ID:       peerID1,
		// 			Key:      "peer-1-key",
		// 			IP:       net.IP{100, 64, 0, 1},
		// 			Name:     peerID1,
		// 			DNSLabel: peerID1,
		// 			Status: &PeerStatus{
		// 				LastSeen:  time.Now().UTC(),
		// 				Connected: false,
		// 				Approved:  false,
		// 			},
		// 			UserID:    userID,
		// 			LastLogin: time.Now().UTC().Add(-time.Hour * 24 * 30 * 30),
		// 		},
		// 		"peer-2": {
		// 			ID:       peerID2,
		// 			Key:      "peer-2-key",
		// 			IP:       net.IP{100, 64, 0, 1},
		// 			Name:     peerID2,
		// 			DNSLabel: peerID2,
		// 			Status: &PeerStatus{
		// 				LastSeen:  time.Now().UTC(),
		// 				Connected: false,
		// 				Approved:  true,
		// 			},
		// 			UserID:    userID,
		// 			LastLogin: time.Now().UTC().Add(-time.Hour * 24 * 30 * 30),
		// 		},
		// 		"peer-3": {
		// 			ID:       peerID3,
		// 			Key:      "peer-3-key",
		// 			IP:       net.IP{100, 64, 0, 1},
		// 			Name:     peerID3,
		// 			DNSLabel: peerID3,
		// 			Status: &PeerStatus{
		// 				LastSeen:  time.Now().UTC(),
		// 				Connected: false,
		// 				Approved:  true,
		// 			},
		// 			UserID:    userID,
		// 			LastLogin: time.Now().UTC().Add(-time.Hour * 24 * 30 * 30),
		// 		},
		// 	},
		// },
	}

	netIP := net.IP{100, 64, 0, 0}
	netMask := net.IPMask{255, 255, 0, 0}
	network := &types.Network{
		Identifier: "network",
		Net:        net.IPNet{IP: netIP, Mask: netMask},
		Dns:        "netbird.selfhosted",
		Serial:     0,
		Mu:         sync.Mutex{},
	}

	for _, testCase := range tt {
		account := newAccountWithId(context.Background(), "account-1", userID, "netbird.io", "", "", false)
		account.UpdateSettings(&testCase.accountSettings)
		account.Network = network
		account.Peers = testCase.peers
		for _, peer := range account.Peers {
			all, _ := account.GetGroupAll()
			account.Groups[all.ID].Peers = append(account.Groups[all.ID].Peers, peer.ID)
		}

		validatedPeers := map[string]struct{}{}
		for p := range account.Peers {
			validatedPeers[p] = struct{}{}
		}

		customZone := account.GetPeersCustomZone(context.Background(), "netbird.io")
		networkMap := account.GetPeerNetworkMap(context.Background(), testCase.peerID, customZone, validatedPeers, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap(), nil, account.GetActiveGroupUsers())
		assert.Len(t, networkMap.Peers, len(testCase.expectedPeers))
		assert.Len(t, networkMap.OfflinePeers, len(testCase.expectedOfflinePeers))
	}
}

func TestNewAccount(t *testing.T) {
	domain := "netbird.io"
	userId := "account_creator"
	accountID := "account_id"
	account := newAccountWithId(context.Background(), accountID, userId, domain, "", "", false)
	verifyNewAccountHasDefaultFields(t, account, userId, domain, []string{userId})
}

func TestAccountManager_GetOrCreateAccountByUser(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID, Domain: ""})
	if err != nil {
		t.Fatal(err)
	}
	if account == nil {
		t.Fatalf("expected to create an account for a user %s", userID)
		return
	}

	account, err = manager.Store.GetAccountByUser(context.Background(), userID)
	if err != nil {
		t.Errorf("expected to get existing account after creation, no account was found for a user %s", userID)
		return
	}

	if account != nil && account.Users[userID] == nil {
		t.Fatalf("expected to create an account for a user %s but no user was found after creation under the account %s", userID, account.Id)
		return
	}

	// check the corresponding events that should have been generated
	ev := getEvent(t, account.Id, manager, activity.AccountCreated)

	assert.NotNil(t, ev)
	assert.Equal(t, account.Id, ev.AccountID)
	assert.Equal(t, userID, ev.InitiatorID)
	assert.Equal(t, account.Id, ev.TargetID)
}

func TestDefaultAccountManager_GetAccountIDFromToken(t *testing.T) {
	type initUserParams auth.UserAuth

	var (
		publicDomain  = "public.com"
		privateDomain = "private.com"
		unknownDomain = "unknown.com"
	)

	defaultInitAccount := initUserParams{
		Domain: publicDomain,
		UserId: "defaultUser",
	}

	initUnknown := defaultInitAccount
	initUnknown.DomainCategory = types.UnknownCategory
	initUnknown.Domain = unknownDomain

	privateInitAccount := defaultInitAccount
	privateInitAccount.Domain = privateDomain
	privateInitAccount.DomainCategory = types.PrivateCategory

	testCases := []struct {
		name                        string
		inputClaims                 auth.UserAuth
		inputInitUserParams         initUserParams
		inputUpdateAttrs            bool
		inputUpdateClaimAccount     bool
		testingFunc                 require.ComparisonAssertionFunc
		expectedMSG                 string
		expectedUserRole            types.UserRole
		expectedDomainCategory      string
		expectedDomain              string
		expectedPrimaryDomainStatus bool
		expectedCreatedBy           string
		expectedUsers               []string
	}{
		{
			name: "New User With Public Domain",
			inputClaims: auth.UserAuth{
				Domain:         publicDomain,
				UserId:         "pub-domain-user",
				DomainCategory: types.PublicCategory,
			},
			inputInitUserParams:         defaultInitAccount,
			testingFunc:                 require.NotEqual,
			expectedMSG:                 "account IDs shouldn't match",
			expectedUserRole:            types.UserRoleOwner,
			expectedDomainCategory:      "",
			expectedDomain:              publicDomain,
			expectedPrimaryDomainStatus: false,
			expectedCreatedBy:           "pub-domain-user",
			expectedUsers:               []string{"pub-domain-user"},
		},
		{
			name: "New User With Unknown Domain",
			inputClaims: auth.UserAuth{
				Domain:         unknownDomain,
				UserId:         "unknown-domain-user",
				DomainCategory: types.UnknownCategory,
			},
			inputInitUserParams:         initUnknown,
			testingFunc:                 require.NotEqual,
			expectedMSG:                 "account IDs shouldn't match",
			expectedUserRole:            types.UserRoleOwner,
			expectedDomain:              unknownDomain,
			expectedDomainCategory:      "",
			expectedPrimaryDomainStatus: false,
			expectedCreatedBy:           "unknown-domain-user",
			expectedUsers:               []string{"unknown-domain-user"},
		},
		{
			name: "New User With Private Domain",
			inputClaims: auth.UserAuth{
				Domain:         privateDomain,
				UserId:         "pvt-domain-user",
				DomainCategory: types.PrivateCategory,
			},
			inputInitUserParams:         defaultInitAccount,
			testingFunc:                 require.NotEqual,
			expectedMSG:                 "account IDs shouldn't match",
			expectedUserRole:            types.UserRoleOwner,
			expectedDomain:              privateDomain,
			expectedDomainCategory:      types.PrivateCategory,
			expectedPrimaryDomainStatus: true,
			expectedCreatedBy:           "pvt-domain-user",
			expectedUsers:               []string{"pvt-domain-user"},
		},
		{
			name: "New Regular User With Existing Private Domain",
			inputClaims: auth.UserAuth{
				Domain:         privateDomain,
				UserId:         "new-pvt-domain-user",
				DomainCategory: types.PrivateCategory,
			},
			inputUpdateAttrs:            true,
			inputInitUserParams:         privateInitAccount,
			testingFunc:                 require.Equal,
			expectedMSG:                 "account IDs should match",
			expectedUserRole:            types.UserRoleUser,
			expectedDomain:              privateDomain,
			expectedDomainCategory:      types.PrivateCategory,
			expectedPrimaryDomainStatus: true,
			expectedCreatedBy:           defaultInitAccount.UserId,
			expectedUsers:               []string{defaultInitAccount.UserId, "new-pvt-domain-user"},
		},
		{
			name: "Existing User With Existing Reclassified Private Domain",
			inputClaims: auth.UserAuth{
				Domain:         defaultInitAccount.Domain,
				UserId:         defaultInitAccount.UserId,
				DomainCategory: types.PrivateCategory,
			},
			inputInitUserParams:         defaultInitAccount,
			testingFunc:                 require.Equal,
			expectedMSG:                 "account IDs should match",
			expectedUserRole:            types.UserRoleOwner,
			expectedDomain:              defaultInitAccount.Domain,
			expectedDomainCategory:      types.PrivateCategory,
			expectedPrimaryDomainStatus: true,
			expectedCreatedBy:           defaultInitAccount.UserId,
			expectedUsers:               []string{defaultInitAccount.UserId},
		},
		{
			name: "Existing Account Id With Existing Reclassified Private Domain",
			inputClaims: auth.UserAuth{
				Domain:         defaultInitAccount.Domain,
				UserId:         defaultInitAccount.UserId,
				DomainCategory: types.PrivateCategory,
			},
			inputUpdateClaimAccount:     true,
			inputInitUserParams:         defaultInitAccount,
			testingFunc:                 require.Equal,
			expectedMSG:                 "account IDs should match",
			expectedUserRole:            types.UserRoleOwner,
			expectedDomain:              defaultInitAccount.Domain,
			expectedDomainCategory:      types.PrivateCategory,
			expectedPrimaryDomainStatus: true,
			expectedCreatedBy:           defaultInitAccount.UserId,
			expectedUsers:               []string{defaultInitAccount.UserId},
		},
		{
			name: "User With Private Category And Empty Domain",
			inputClaims: auth.UserAuth{
				Domain:         "",
				UserId:         "pvt-domain-user",
				DomainCategory: types.PrivateCategory,
			},
			inputInitUserParams:         defaultInitAccount,
			testingFunc:                 require.NotEqual,
			expectedMSG:                 "account IDs shouldn't match",
			expectedUserRole:            types.UserRoleOwner,
			expectedDomain:              "",
			expectedDomainCategory:      "",
			expectedPrimaryDomainStatus: false,
			expectedCreatedBy:           "pvt-domain-user",
			expectedUsers:               []string{"pvt-domain-user"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			manager, _, err := createManager(t)
			require.NoError(t, err, "unable to create account manager")

			accountID, err := manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: testCase.inputInitUserParams.UserId, Domain: testCase.inputInitUserParams.Domain})
			require.NoError(t, err, "create init user failed")

			initAccount, err := manager.Store.GetAccount(context.Background(), accountID)
			require.NoError(t, err, "get init account failed")

			if testCase.inputUpdateAttrs {
				err = manager.updateAccountDomainAttributesIfNotUpToDate(context.Background(), initAccount.Id, auth.UserAuth{UserId: testCase.inputInitUserParams.UserId, Domain: testCase.inputInitUserParams.Domain, DomainCategory: testCase.inputInitUserParams.DomainCategory}, true)
				require.NoError(t, err, "update init user failed")
			}

			if testCase.inputUpdateClaimAccount {
				testCase.inputClaims.AccountId = initAccount.Id
			}

			accountID, _, err = manager.GetAccountIDFromUserAuth(context.Background(), testCase.inputClaims)
			require.NoError(t, err, "support function failed")

			account, err := manager.Store.GetAccount(context.Background(), accountID)
			require.NoError(t, err, "get account failed")

			verifyNewAccountHasDefaultFields(t, account, testCase.expectedCreatedBy, testCase.inputClaims.Domain, testCase.expectedUsers)
			verifyCanAddPeerToAccount(t, manager, account, testCase.expectedCreatedBy)

			testCase.testingFunc(t, initAccount.Id, account.Id, testCase.expectedMSG)

			require.EqualValues(t, testCase.expectedUserRole, account.Users[testCase.inputClaims.UserId].Role, "expected user role should match")
			require.EqualValues(t, testCase.expectedDomainCategory, account.DomainCategory, "expected account domain category should match")
			require.EqualValues(t, testCase.expectedPrimaryDomainStatus, account.IsDomainPrimaryAccount, "expected account primary status should match")
			require.EqualValues(t, testCase.expectedDomain, account.Domain, "expected account domain should match")
		})
	}
}

func TestDefaultAccountManager_SyncUserJWTGroups(t *testing.T) {
	userId := "user-id"
	domain := "test.domain"
	_ = newAccountWithId(context.Background(), "", userId, domain, "", "", false)
	manager, _, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")
	accountID, err := manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: userId, Domain: domain})
	require.NoError(t, err, "create init user failed")
	// as initAccount was created without account id we have to take the id after account initialization
	// that happens inside the GetAccountIDByUserID where the id is getting generated
	// it is important to set the id as it help to avoid creating additional account with empty Id and re-pointing indices to it
	initAccount, err := manager.Store.GetAccount(context.Background(), accountID)
	require.NoError(t, err, "get init account failed")
	claims := auth.UserAuth{
		AccountId:      accountID, // is empty as it is based on accountID right after initialization of initAccount
		Domain:         domain,
		UserId:         userId,
		DomainCategory: "test-category",
		Groups:         []string{"group1", "group2"},
	}
	t.Run("JWT groups disabled", func(t *testing.T) {
		err := manager.SyncUserJWTGroups(context.Background(), claims)
		require.NoError(t, err, "synt user jwt groups failed")
		account, err := manager.Store.GetAccount(context.Background(), accountID)
		require.NoError(t, err, "get account failed")
		require.Len(t, account.Groups, 1, "only ALL group should exists")
	})
	t.Run("JWT groups enabled without claim name", func(t *testing.T) {
		initAccount.Settings.JWTGroupsEnabled = true
		err := manager.Store.SaveAccount(context.Background(), initAccount)
		require.NoError(t, err, "save account failed")
		require.Len(t, manager.Store.GetAllAccounts(context.Background()), 1, "only one account should exist")
		err = manager.SyncUserJWTGroups(context.Background(), claims)
		require.NoError(t, err, "synt user jwt groups failed")
		account, err := manager.Store.GetAccount(context.Background(), accountID)
		require.NoError(t, err, "get account failed")
		require.Len(t, account.Groups, 1, "if group claim is not set no group added from JWT")
	})
	t.Run("JWT groups enabled", func(t *testing.T) {
		initAccount.Settings.JWTGroupsEnabled = true
		initAccount.Settings.JWTGroupsClaimName = "idp-groups"
		err := manager.Store.SaveAccount(context.Background(), initAccount)
		require.NoError(t, err, "save account failed")
		require.Len(t, manager.Store.GetAllAccounts(context.Background()), 1, "only one account should exist")
		err = manager.SyncUserJWTGroups(context.Background(), claims)
		require.NoError(t, err, "synt user jwt groups failed")
		account, err := manager.Store.GetAccount(context.Background(), accountID)
		require.NoError(t, err, "get account failed")
		require.Len(t, account.Groups, 3, "groups should be added to the account")
		groupsByNames := map[string]*types.Group{}
		for _, g := range account.Groups {
			groupsByNames[g.Name] = g
		}
		g1, ok := groupsByNames["group1"]
		require.True(t, ok, "group1 should be added to the account")
		require.Equal(t, g1.Name, "group1", "group1 name should match")
		require.Equal(t, g1.Issued, types.GroupIssuedJWT, "group1 issued should match")
		g2, ok := groupsByNames["group2"]
		require.True(t, ok, "group2 should be added to the account")
		require.Equal(t, g2.Name, "group2", "group2 name should match")
		require.Equal(t, g2.Issued, types.GroupIssuedJWT, "group2 issued should match")
	})
}

func TestAccountManager_PrivateAccount(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userId := "test_user"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userId, Domain: ""})
	if err != nil {
		t.Fatal(err)
	}
	if account == nil {
		t.Fatalf("expected to create an account for a user %s", userId)
	}

	account, err = manager.Store.GetAccountByUser(context.Background(), userId)
	if err != nil {
		t.Errorf("expected to get existing account after creation, no account was found for a user %s", userId)
	}

	if account != nil && account.Users[userId] == nil {
		t.Fatalf("expected to create an account for a user %s but no user was found after creation under the account %s", userId, account.Id)
	}
}

func TestAccountManager_SetOrUpdateDomain(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userId := "test_user"
	domain := "hotmail.com"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userId, Domain: domain})
	if err != nil {
		t.Fatal(err)
	}
	if account == nil {
		t.Fatalf("expected to create an account for a user %s", userId)
	}

	if account.Domain != domain {
		t.Errorf("setting account domain failed, expected %s, got %s", domain, account.Domain)
	}

	domain = "gmail.com"

	account, err = manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userId, Domain: domain})
	if err != nil {
		t.Fatalf("got the following error while retrieving existing acc: %v", err)
	}

	if account == nil {
		t.Fatalf("expected to get an account for a user %s", userId)
	}

	if account.Domain != domain {
		t.Errorf("updating domain. expected %s got %s", domain, account.Domain)
	}
}

func TestAccountManager_GetAccountByUserID(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userId := "test_user"

	accountID, err := manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: userId, Domain: ""})
	if err != nil {
		t.Fatal(err)
	}
	if accountID == "" {
		t.Fatalf("expected to create an account for a user %s", userId)
		return
	}

	exists, err := manager.Store.AccountExists(context.Background(), store.LockingStrengthNone, accountID)
	assert.NoError(t, err)
	assert.True(t, exists, "expected to get existing account after creation using userid")

	_, err = manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: "", Domain: ""})
	if err == nil {
		t.Errorf("expected an error when user ID is empty")
	}
}

func createAccount(am *DefaultAccountManager, accountID, userID, domain string) (*types.Account, error) {
	account := newAccountWithId(context.Background(), accountID, userID, domain, "", "", false)
	err := am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		return nil, err
	}
	return account, nil
}

func TestAccountManager_GetAccount(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedId := "test_account"
	userId := "account_creator"
	account, err := createAccount(manager, expectedId, userId, "")
	if err != nil {
		t.Fatal(err)
	}

	// AddAccount has been already tested so we can assume it is correct and compare results
	getAccount, err := manager.Store.GetAccount(context.Background(), account.Id)
	if err != nil {
		t.Fatal(err)
		return
	}

	if account.Id != getAccount.Id {
		t.Errorf("expected account.Id %s, got %s", account.Id, getAccount.Id)
	}

	for _, peer := range account.Peers {
		if _, ok := getAccount.Peers[peer.ID]; !ok {
			t.Errorf("expected account to have peer %s, not found", peer.ID)
		}
	}

	for _, key := range account.SetupKeys {
		if _, ok := getAccount.SetupKeys[key.Key]; !ok {
			t.Errorf("expected account to have setup key %s, not found", key.Key)
		}
	}
}

func TestAccountManager_DeleteAccount(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedId := "test_account"
	userId := "account_creator"
	account, err := createAccount(manager, expectedId, userId, "")
	if err != nil {
		t.Fatal(err)
	}

	account.Users["service-user-1"] = &types.User{
		Id:            "service-user-1",
		Role:          types.UserRoleAdmin,
		IsServiceUser: true,
		Issued:        types.UserIssuedAPI,
		PATs: map[string]*types.PersonalAccessToken{
			"pat-1": {
				ID:          "pat-1",
				UserID:      "service-user-1",
				Name:        "service-user-1",
				HashedToken: "hashedToken",
				CreatedAt:   time.Now(),
			},
		},
	}
	account.Users[userId] = &types.User{
		Id:            "service-user-2",
		Role:          types.UserRoleUser,
		IsServiceUser: true,
		Issued:        types.UserIssuedAPI,
		PATs: map[string]*types.PersonalAccessToken{
			"pat-2": {
				ID:          "pat-2",
				UserID:      userId,
				Name:        userId,
				HashedToken: "hashedToken",
				CreatedAt:   time.Now(),
			},
		},
	}

	err = manager.Store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatal(err)
	}

	err = manager.DeleteAccount(context.Background(), account.Id, userId)
	if err != nil {
		t.Fatal(err)
	}

	getAccount, err := manager.Store.GetAccount(context.Background(), account.Id)
	if err == nil {
		t.Fatal(fmt.Errorf("expected to get an error when trying to get deleted account, got %v", getAccount))
	}

	pats, err := manager.Store.GetUserPATs(context.Background(), store.LockingStrengthNone, "service-user-1")
	require.NoError(t, err)
	assert.Len(t, pats, 0)

	pats, err = manager.Store.GetUserPATs(context.Background(), store.LockingStrengthNone, userId)
	require.NoError(t, err)
	assert.Len(t, pats, 0)
}

func BenchmarkTest_GetAccountWithclaims(b *testing.B) {
	claims := auth.UserAuth{
		Domain:         "example.com",
		UserId:         "pvt-domain-user",
		DomainCategory: types.PrivateCategory,
	}

	publicClaims := auth.UserAuth{
		Domain:         "test.com",
		UserId:         "public-domain-user",
		DomainCategory: types.PublicCategory,
	}

	am, _, err := createManager(b)
	if err != nil {
		b.Fatal(err)
		return
	}
	id, err := am.getAccountIDWithAuthorizationClaims(context.Background(), claims)
	if err != nil {
		b.Fatal(err)
	}

	pid, err := am.getAccountIDWithAuthorizationClaims(context.Background(), publicClaims)
	if err != nil {
		b.Fatal(err)
	}

	users := genUsers("priv", 100)

	acc, err := am.Store.GetAccount(context.Background(), id)
	if err != nil {
		b.Fatal(err)
	}
	acc.Users = users

	err = am.Store.SaveAccount(context.Background(), acc)
	if err != nil {
		b.Fatal(err)
	}

	userP := genUsers("pub", 100)

	pacc, err := am.Store.GetAccount(context.Background(), pid)
	if err != nil {
		b.Fatal(err)
	}

	pacc.Users = userP

	err = am.Store.SaveAccount(context.Background(), pacc)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("public without account ID", func(b *testing.B) {
		// b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := am.getAccountIDWithAuthorizationClaims(context.Background(), publicClaims)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("private without account ID", func(b *testing.B) {
		// b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := am.getAccountIDWithAuthorizationClaims(context.Background(), claims)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("private with account ID", func(b *testing.B) {
		claims.AccountId = id
		// b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := am.getAccountIDWithAuthorizationClaims(context.Background(), claims)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

}

func genUsers(p string, n int) map[string]*types.User {
	users := map[string]*types.User{}
	now := time.Now()
	for i := 0; i < n; i++ {
		users[fmt.Sprintf("%s-%d", p, i)] = &types.User{
			Id:         fmt.Sprintf("%s-%d", p, i),
			Role:       types.UserRoleAdmin,
			LastLogin:  util.ToPtr(now),
			CreatedAt:  now,
			Issued:     "api",
			AutoGroups: []string{"one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"},
		}
	}
	return users
}

func TestAccountManager_AddPeer(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userID := "testingUser"
	account, err := createAccount(manager, "test_account", userID, "netbird.cloud")
	if err != nil {
		t.Fatal(err)
	}

	serial := account.Network.CurrentSerial() // should be 0

	setupKey, err := manager.CreateSetupKey(context.Background(), account.Id, "test-key", types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	if err != nil {
		t.Fatal("error creating setup key")
		return
	}

	if account.Network.Serial != 0 {
		t.Errorf("expecting account network to have an initial Serial=0")
		return
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}
	expectedPeerKey := key.PublicKey().String()

	peer, _, _, err := manager.AddPeer(context.Background(), "", setupKey.Key, "", &nbpeer.Peer{
		Key:  expectedPeerKey,
		Meta: nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
	}, false)
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	account, err = manager.Store.GetAccount(context.Background(), account.Id)
	if err != nil {
		t.Fatal(err)
		return
	}

	if peer.Key != expectedPeerKey {
		t.Errorf("expecting just added peer to have key = %s, got %s", expectedPeerKey, peer.Key)
	}

	if !account.Network.Net.Contains(peer.IP) {
		t.Errorf("expecting just added peer's IP %s to be in a network range %s", peer.IP.String(), account.Network.Net.String())
	}

	if account.Network.CurrentSerial() != 1 {
		t.Errorf("expecting Network Serial=%d to be incremented by 1 and be equal to %d when adding new peer to account", serial, account.Network.CurrentSerial())
	}
	ev := getEvent(t, account.Id, manager, activity.PeerAddedWithSetupKey)

	assert.NotNil(t, ev)
	assert.Equal(t, account.Id, ev.AccountID)
	assert.Equal(t, peer.Name, ev.Meta["name"])
	assert.Equal(t, peer.FQDN(account.Domain), ev.Meta["fqdn"])
	assert.Equal(t, setupKey.Id, ev.InitiatorID)
	assert.Equal(t, peer.ID, ev.TargetID)
	assert.Equal(t, peer.IP.String(), fmt.Sprint(ev.Meta["ip"]))
}

func TestAccountManager_AddPeerWithUserID(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID, Domain: "netbird.cloud"})
	if err != nil {
		t.Fatal(err)
	}

	serial := account.Network.CurrentSerial() // should be 0

	if account.Network.Serial != 0 {
		t.Errorf("expecting account network to have an initial Serial=0")
		return
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}
	expectedPeerKey := key.PublicKey().String()
	expectedUserID := userID

	peer, _, _, err := manager.AddPeer(context.Background(), "", "", userID, &nbpeer.Peer{
		Key:  expectedPeerKey,
		Meta: nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
	}, false)
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v, account users: %v", err, account.CreatedBy)
		return
	}

	account, err = manager.Store.GetAccount(context.Background(), account.Id)
	if err != nil {
		t.Fatal(err)
		return
	}

	if peer.Key != expectedPeerKey {
		t.Errorf("expecting just added peer to have key = %s, got %s", expectedPeerKey, peer.Key)
	}

	if !account.Network.Net.Contains(peer.IP) {
		t.Errorf("expecting just added peer's IP %s to be in a network range %s", peer.IP.String(), account.Network.Net.String())
	}

	if peer.UserID != expectedUserID {
		t.Errorf("expecting just added peer to have UserID = %s, got %s", expectedUserID, peer.UserID)
	}

	if account.Network.CurrentSerial() != 1 {
		t.Errorf("expecting Network Serial=%d to be incremented by 1 and be equal to %d when adding new peer to account", serial, account.Network.CurrentSerial())
	}

	ev := getEvent(t, account.Id, manager, activity.PeerAddedByUser)

	assert.NotNil(t, ev)
	assert.Equal(t, account.Id, ev.AccountID)
	assert.Equal(t, peer.Name, ev.Meta["name"])
	assert.Equal(t, peer.FQDN(account.Domain), ev.Meta["fqdn"])
	assert.Equal(t, userID, ev.InitiatorID)
	assert.Equal(t, peer.ID, ev.TargetID)
	assert.Equal(t, peer.IP.String(), fmt.Sprint(ev.Meta["ip"]))
}

func TestAccountManager_NetworkUpdates_SaveGroup_Experimental(t *testing.T) {
	t.Setenv(network_map.EnvNewNetworkMapBuilder, "true")
	testAccountManager_NetworkUpdates_SaveGroup(t)
}

func TestAccountManager_NetworkUpdates_SaveGroup(t *testing.T) {
	testAccountManager_NetworkUpdates_SaveGroup(t)
}

func testAccountManager_NetworkUpdates_SaveGroup(t *testing.T) {
	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	group := types.Group{
		ID:    "groupA",
		Name:  "GroupA",
		Peers: []string{},
	}
	if err := manager.CreateGroup(context.Background(), account.Id, userID, &group); err != nil {
		t.Errorf("save group: %v", err)
		return
	}

	_, err := manager.SavePolicy(context.Background(), account.Id, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"groupA"},
				Destinations:  []string{"groupA"},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	updMsg := updateManager.CreateChannel(context.Background(), peer1.ID)
	defer updateManager.CloseChannel(context.Background(), peer1.ID)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		message := <-updMsg
		networkMap := message.Update.GetNetworkMap()
		if len(networkMap.RemotePeers) != 2 {
			t.Errorf("mismatch peers count: 2 expected, got %v", len(networkMap.RemotePeers))
		}
	}()

	group.Peers = []string{peer1.ID, peer2.ID, peer3.ID}
	if err := manager.UpdateGroup(context.Background(), account.Id, userID, &group); err != nil {
		t.Errorf("save group: %v", err)
		return
	}

	wg.Wait()
}

func TestAccountManager_NetworkUpdates_DeletePolicy_Experimental(t *testing.T) {
	t.Setenv(network_map.EnvNewNetworkMapBuilder, "true")
	testAccountManager_NetworkUpdates_DeletePolicy(t)
}

func TestAccountManager_NetworkUpdates_DeletePolicy(t *testing.T) {
	testAccountManager_NetworkUpdates_DeletePolicy(t)
}

func testAccountManager_NetworkUpdates_DeletePolicy(t *testing.T) {
	manager, updateManager, account, peer1, _, _ := setupNetworkMapTest(t)

	updMsg := updateManager.CreateChannel(context.Background(), peer1.ID)
	defer updateManager.CloseChannel(context.Background(), peer1.ID)

	// Ensure that we do not receive an update message before the policy is deleted
	time.Sleep(time.Second)
	select {
	case <-updMsg:
		t.Logf("received addPeer update message before policy deletion")
	default:
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		message := <-updMsg
		networkMap := message.Update.GetNetworkMap()
		if len(networkMap.RemotePeers) != 0 {
			t.Errorf("mismatch peers count: 0 expected, got %v", len(networkMap.RemotePeers))
		}
	}()

	if err := manager.DeletePolicy(context.Background(), account.Id, account.Policies[0].ID, userID); err != nil {
		t.Errorf("delete default rule: %v", err)
		return
	}

	wg.Wait()
}

func TestAccountManager_NetworkUpdates_SavePolicy_Experimental(t *testing.T) {
	t.Setenv(network_map.EnvNewNetworkMapBuilder, "true")
	testAccountManager_NetworkUpdates_SavePolicy(t)
}

func TestAccountManager_NetworkUpdates_SavePolicy(t *testing.T) {
	testAccountManager_NetworkUpdates_SavePolicy(t)
}

func testAccountManager_NetworkUpdates_SavePolicy(t *testing.T) {
	manager, updateManager, account, peer1, peer2, _ := setupNetworkMapTest(t)

	group := types.Group{
		AccountID: account.Id,
		ID:        "groupA",
		Name:      "GroupA",
		Peers:     []string{peer1.ID, peer2.ID},
	}
	if err := manager.CreateGroup(context.Background(), account.Id, userID, &group); err != nil {
		t.Errorf("save group: %v", err)
		return
	}

	updMsg := updateManager.CreateChannel(context.Background(), peer1.ID)
	defer updateManager.CloseChannel(context.Background(), peer1.ID)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		message := <-updMsg
		networkMap := message.Update.GetNetworkMap()
		if len(networkMap.RemotePeers) != 2 {
			t.Errorf("mismatch peers count: 2 expected, got %v", len(networkMap.RemotePeers))
		}
	}()

	_, err := manager.SavePolicy(context.Background(), account.Id, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"groupA"},
				Destinations:  []string{"groupA"},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	if err != nil {
		t.Errorf("delete default rule: %v", err)
		return
	}

	wg.Wait()
}

func TestAccountManager_NetworkUpdates_DeletePeer_Experimental(t *testing.T) {
	t.Setenv(network_map.EnvNewNetworkMapBuilder, "true")
	testAccountManager_NetworkUpdates_DeletePeer(t)
}

func TestAccountManager_NetworkUpdates_DeletePeer(t *testing.T) {
	testAccountManager_NetworkUpdates_DeletePeer(t)
}

func testAccountManager_NetworkUpdates_DeletePeer(t *testing.T) {
	manager, updateManager, account, peer1, _, peer3 := setupNetworkMapTest(t)

	group := types.Group{
		ID:    "groupA",
		Name:  "GroupA",
		Peers: []string{peer1.ID, peer3.ID},
	}
	if err := manager.CreateGroup(context.Background(), account.Id, userID, &group); err != nil {
		t.Errorf("save group: %v", err)
		return
	}

	_, err := manager.SavePolicy(context.Background(), account.Id, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"groupA"},
				Destinations:  []string{"groupA"},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	if err != nil {
		t.Errorf("save policy: %v", err)
		return
	}

	// We need to sleep to wait for the buffer peer update
	time.Sleep(300 * time.Millisecond)

	updMsg := updateManager.CreateChannel(context.Background(), peer1.ID)
	defer updateManager.CloseChannel(context.Background(), peer1.ID)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		message := <-updMsg
		networkMap := message.Update.GetNetworkMap()
		if len(networkMap.RemotePeers) != 1 {
			t.Errorf("mismatch peers count: 1 expected, got %v", len(networkMap.RemotePeers))
		}
	}()

	if err := manager.DeletePeer(context.Background(), account.Id, peer3.ID, userID); err != nil {
		t.Errorf("delete peer: %v", err)
		return
	}

	wg.Wait()
}

func TestAccountManager_NetworkUpdates_DeleteGroup_Experimental(t *testing.T) {
	t.Setenv(network_map.EnvNewNetworkMapBuilder, "true")
	testAccountManager_NetworkUpdates_DeleteGroup(t)
}

func TestAccountManager_NetworkUpdates_DeleteGroup(t *testing.T) {
	testAccountManager_NetworkUpdates_DeleteGroup(t)
}

func testAccountManager_NetworkUpdates_DeleteGroup(t *testing.T) {
	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	updMsg := updateManager.CreateChannel(context.Background(), peer1.ID)
	defer updateManager.CloseChannel(context.Background(), peer1.ID)

	err := manager.CreateGroup(context.Background(), account.Id, userID, &types.Group{
		ID:    "groupA",
		Name:  "GroupA",
		Peers: []string{peer1.ID, peer2.ID, peer3.ID},
	})

	require.NoError(t, err, "failed to save group")

	if err := manager.DeletePolicy(context.Background(), account.Id, account.Policies[0].ID, userID); err != nil {
		t.Errorf("delete default rule: %v", err)
		return
	}

	policy, err := manager.SavePolicy(context.Background(), account.Id, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"groupA"},
				Destinations:  []string{"groupA"},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	if err != nil {
		t.Errorf("save policy: %v", err)
		return
	}

	for drained := false; !drained; {
		select {
		case <-updMsg:
		default:
			drained = true
		}
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		message := <-updMsg
		networkMap := message.Update.GetNetworkMap()
		if len(networkMap.RemotePeers) != 0 {
			t.Errorf("mismatch peers count: 0 expected, got %v", len(networkMap.RemotePeers))
		}
	}()

	// clean policy is pre requirement for delete group
	if err := manager.DeletePolicy(context.Background(), account.Id, policy.ID, userID); err != nil {
		t.Errorf("delete default rule: %v", err)
		return
	}

	if err := manager.DeleteGroup(context.Background(), account.Id, userID, "groupA"); err != nil {
		t.Errorf("delete group: %v", err)
		return
	}

	wg.Wait()
}

func TestAccountManager_DeletePeer(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	account, err := createAccount(manager, "test_account", userID, "netbird.cloud")
	if err != nil {
		t.Fatal(err)
	}

	setupKey, err := manager.CreateSetupKey(context.Background(), account.Id, "test-key", types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	if err != nil {
		t.Fatal("error creating setup key")
		return
	}

	key, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peerKey := key.PublicKey().String()

	peer, _, _, err := manager.AddPeer(context.Background(), "", setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey,
		Meta: nbpeer.PeerSystemMeta{Hostname: peerKey},
	}, false)
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	err = manager.DeletePeer(context.Background(), account.Id, peer.ID, userID)
	if err != nil {
		return
	}

	account, err = manager.Store.GetAccount(context.Background(), account.Id)
	if err != nil {
		t.Fatal(err)
		return
	}

	if account.Network.CurrentSerial() != 2 {
		t.Errorf("expecting Network Serial=%d to be incremented and be equal to 2 after adding and deleting a peer", account.Network.CurrentSerial())
	}

	ev := getEvent(t, account.Id, manager, activity.PeerRemovedByUser)

	assert.NotNil(t, ev)
	assert.Equal(t, account.Id, ev.AccountID)
	assert.Equal(t, peer.Name, ev.Meta["name"])
	assert.Equal(t, peer.FQDN(account.Domain), ev.Meta["fqdn"])
	assert.Equal(t, userID, ev.InitiatorID)
	assert.Equal(t, peer.ID, ev.TargetID)
	assert.Equal(t, peer.IP.String(), fmt.Sprint(ev.Meta["ip"]))
}

func getEvent(t *testing.T, accountID string, manager nbAccount.Manager, eventType activity.Activity) *activity.Event {
	t.Helper()
	for {
		select {
		case <-time.After(time.Second):
			t.Fatal("no PeerAddedWithSetupKey event was generated")
		default:
			events, err := manager.GetEvents(context.Background(), accountID, userID)
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range events {
				if event.Activity == eventType {
					return event
				}
			}
		}
	}
}

func TestGetUsersFromAccount(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	users := map[string]*types.User{"1": {Id: "1", Role: types.UserRoleOwner}, "2": {Id: "2", Role: "user"}, "3": {Id: "3", Role: "user"}}
	accountId := "test_account_id"

	account, err := createAccount(manager, accountId, users["1"].Id, "")
	if err != nil {
		t.Fatal(err)
	}

	// add a user to the account
	for _, user := range users {
		account.Users[user.Id] = user
	}

	userInfos, err := manager.GetUsersFromAccount(context.Background(), accountId, "1")
	if err != nil {
		t.Fatal(err)
	}

	for _, userInfo := range userInfos {
		id := userInfo.ID
		assert.Equal(t, userInfo.ID, users[id].Id)
		assert.Equal(t, userInfo.Role, string(users[id].Role))
		assert.Equal(t, userInfo.Name, "")
		assert.Equal(t, userInfo.Email, "")
	}
}

func TestFileStore_GetRoutesByPrefix(t *testing.T) {
	_, prefix, err := route.ParseNetwork("192.168.64.0/24")
	if err != nil {
		t.Fatal(err)
	}
	account := &types.Account{
		Routes: map[route.ID]*route.Route{
			"route-1": {
				ID:          "route-1",
				Network:     prefix,
				NetID:       "network-1",
				Description: "network-1",
				Peer:        "peer-1",
				NetworkType: 0,
				Masquerade:  false,
				Metric:      999,
				Enabled:     true,
			},
			"route-2": {
				ID:          "route-2",
				Network:     prefix,
				NetID:       "network-1",
				Description: "network-1",
				Peer:        "peer-2",
				NetworkType: 0,
				Masquerade:  false,
				Metric:      999,
				Enabled:     true,
			},
		},
	}

	routes := account.GetRoutesByPrefixOrDomains(prefix, nil)

	assert.Len(t, routes, 2)
	routeIDs := make(map[route.ID]struct{}, 2)
	for _, r := range routes {
		routeIDs[r.ID] = struct{}{}
	}
	assert.Contains(t, routeIDs, route.ID("route-1"))
	assert.Contains(t, routeIDs, route.ID("route-2"))
}

func TestAccount_GetRoutesToSync(t *testing.T) {
	_, prefix, err := route.ParseNetwork("192.168.64.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, prefix2, err := route.ParseNetwork("192.168.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	account := &types.Account{
		Peers: map[string]*nbpeer.Peer{
			"peer-1": {Key: "peer-1", Meta: nbpeer.PeerSystemMeta{GoOS: "linux"}}, "peer-2": {Key: "peer-2", Meta: nbpeer.PeerSystemMeta{GoOS: "linux"}}, "peer-3": {Key: "peer-1", Meta: nbpeer.PeerSystemMeta{GoOS: "linux"}},
		},
		Groups: map[string]*types.Group{"group1": {ID: "group1", Peers: []string{"peer-1", "peer-2"}}},
		Routes: map[route.ID]*route.Route{
			"route-1": {
				ID:          "route-1",
				Network:     prefix,
				NetID:       "network-1",
				Description: "network-1",
				Peer:        "peer-1",
				NetworkType: 0,
				Masquerade:  false,
				Metric:      999,
				Enabled:     true,
				Groups:      []string{"group1"},
			},
			"route-2": {
				ID:          "route-2",
				Network:     prefix2,
				NetID:       "network-2",
				Description: "network-2",
				Peer:        "peer-2",
				NetworkType: 0,
				Masquerade:  false,
				Metric:      999,
				Enabled:     true,
				Groups:      []string{"group1"},
			},
			"route-3": {
				ID:          "route-3",
				Network:     prefix,
				NetID:       "network-1",
				Description: "network-1",
				Peer:        "peer-2",
				NetworkType: 0,
				Masquerade:  false,
				Metric:      999,
				Enabled:     true,
				Groups:      []string{"group1"},
			},
		},
	}

	routes := account.GetRoutesToSync(context.Background(), "peer-2", []*nbpeer.Peer{{Key: "peer-1"}, {Key: "peer-3"}})

	assert.Len(t, routes, 2)
	routeIDs := make(map[route.ID]struct{}, 2)
	for _, r := range routes {
		routeIDs[r.ID] = struct{}{}
	}
	assert.Contains(t, routeIDs, route.ID("route-2"))
	assert.Contains(t, routeIDs, route.ID("route-3"))

	emptyRoutes := account.GetRoutesToSync(context.Background(), "peer-3", []*nbpeer.Peer{{Key: "peer-1"}, {Key: "peer-2"}})

	assert.Len(t, emptyRoutes, 0)
}

func TestAccount_Copy(t *testing.T) {
	account := &types.Account{
		Id:                     "account1",
		CreatedBy:              "tester",
		CreatedAt:              time.Now().UTC(),
		Domain:                 "test.com",
		DomainCategory:         "public",
		IsDomainPrimaryAccount: true,
		SetupKeys: map[string]*types.SetupKey{
			"setup1": {
				Id:         "setup1",
				AutoGroups: []string{"group1"},
			},
		},
		Network: &types.Network{
			Identifier: "net1",
		},
		Peers: map[string]*nbpeer.Peer{
			"peer1": {
				Key: "key1",
				Status: &nbpeer.PeerStatus{
					LastSeen:     time.Now(),
					Connected:    true,
					LoginExpired: false,
				},
			},
		},
		Users: map[string]*types.User{
			"user1": {
				Id:         "user1",
				Role:       types.UserRoleAdmin,
				AutoGroups: []string{"group1"},
				PATs: map[string]*types.PersonalAccessToken{
					"pat1": {
						ID:             "pat1",
						Name:           "First PAT",
						HashedToken:    "SoMeHaShEdToKeN",
						ExpirationDate: util.ToPtr(time.Now().UTC().AddDate(0, 0, 7)),
						CreatedBy:      "user1",
						CreatedAt:      time.Now().UTC(),
						LastUsed:       util.ToPtr(time.Now().UTC()),
					},
				},
			},
		},
		Groups: map[string]*types.Group{
			"group1": {
				ID:         "group1",
				Peers:      []string{"peer1"},
				Resources:  []types.Resource{},
				GroupPeers: []types.GroupPeer{},
			},
		},
		Policies: []*types.Policy{
			{
				ID:                  "policy1",
				Enabled:             true,
				Rules:               make([]*types.PolicyRule, 0),
				SourcePostureChecks: make([]string, 0),
			},
		},
		Routes: map[route.ID]*route.Route{
			"route1": {
				ID:                  "route1",
				PeerGroups:          []string{},
				Groups:              []string{"group1"},
				AccessControlGroups: []string{},
			},
		},
		NameServerGroups: map[string]*nbdns.NameServerGroup{
			"nsGroup1": {
				ID:          "nsGroup1",
				Domains:     []string{},
				Groups:      []string{},
				NameServers: []nbdns.NameServer{},
			},
		},
		DNSSettings: types.DNSSettings{DisabledManagementGroups: []string{}},
		PostureChecks: []*posture.Checks{
			{
				ID: "posture Checks1",
			},
		},
		Settings: &types.Settings{},
		Networks: []*networkTypes.Network{
			{
				ID: "network1",
			},
		},
		NetworkRouters: []*routerTypes.NetworkRouter{
			{
				ID:         "router1",
				NetworkID:  "network1",
				PeerGroups: []string{"group1"},
				Masquerade: false,
				Metric:     0,
			},
		},
		NetworkResources: []*resourceTypes.NetworkResource{
			{
				ID:        "resource1",
				NetworkID: "network1",
				Name:      "resource",
				Type:      "Subnet",
				Address:   "172.12.6.1/24",
			},
		},
		NetworkMapCache: &types.NetworkMapBuilder{},
	}
	account.InitOnce()
	err := hasNilField(account)
	if err != nil {
		t.Fatal(err)
	}
	accountCopy := account.Copy()
	accBytes, err := json.Marshal(account)
	if err != nil {
		t.Fatal(err)
	}
	account.Peers["peer1"].Status.Connected = false // we change original object to confirm that copy won't change
	accCopyBytes, err := json.Marshal(accountCopy)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, string(accBytes), string(accCopyBytes), "account copy returned a different value than expected")
}

// hasNilField validates pointers, maps and slices if they are nil
// TODO: make it check nested fields too
func hasNilField(x interface{}) error {
	rv := reflect.ValueOf(x)
	rv = rv.Elem()
	for i := 0; i < rv.NumField(); i++ {
		// skip gorm internal fields
		if json, ok := rv.Type().Field(i).Tag.Lookup("json"); ok && json == "-" {
			continue
		}
		if f := rv.Field(i); f.IsValid() {
			k := f.Kind()
			switch k {
			case reflect.Ptr:
				if f.IsNil() {
					return fmt.Errorf("field %s is nil", f.String())
				}
			case reflect.Map, reflect.Slice:
				if f.Len() == 0 || f.IsNil() {
					return fmt.Errorf("field %s is nil", f.String())
				}
			}
		}
	}
	return nil
}

func TestDefaultAccountManager_DefaultAccountSettings(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")

	accountID, err := manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err, "unable to create an account")

	settings, err := manager.Store.GetAccountSettings(context.Background(), store.LockingStrengthNone, accountID)
	require.NoError(t, err, "unable to get account settings")

	assert.NotNil(t, settings)
	assert.Equal(t, settings.PeerLoginExpirationEnabled, true)
	assert.Equal(t, settings.PeerLoginExpiration, 24*time.Hour)
}

func TestDefaultAccountManager_UpdatePeer_PeerLoginExpiration(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")

	_, err = manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err, "unable to create an account")

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err, "unable to generate WireGuard key")
	peer, _, _, err := manager.AddPeer(context.Background(), "", "", userID, &nbpeer.Peer{
		Key:                    key.PublicKey().String(),
		Meta:                   nbpeer.PeerSystemMeta{Hostname: "test-peer"},
		LoginExpirationEnabled: true,
	}, false)
	require.NoError(t, err, "unable to add peer")

	accountID, err := manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err, "unable to get the account")

	err = manager.MarkPeerConnected(context.Background(), key.PublicKey().String(), true, nil, accountID)
	require.NoError(t, err, "unable to mark peer connected")

	_, err = manager.UpdateAccountSettings(context.Background(), accountID, userID, &types.Settings{
		PeerLoginExpiration:        time.Hour,
		PeerLoginExpirationEnabled: true,
		Extra:                      &types.ExtraSettings{},
	})
	require.NoError(t, err, "expecting to update account settings successfully but got error")

	wg := &sync.WaitGroup{}
	wg.Add(2)
	manager.peerLoginExpiry = &MockScheduler{
		CancelFunc: func(ctx context.Context, IDs []string) {
			wg.Done()
		},
		ScheduleFunc: func(ctx context.Context, in time.Duration, ID string, job func() (nextRunIn time.Duration, reschedule bool)) {
			wg.Done()
		},
	}

	// disable expiration first
	update := peer.Copy()
	update.LoginExpirationEnabled = false
	_, err = manager.UpdatePeer(context.Background(), accountID, userID, update)
	require.NoError(t, err, "unable to update peer")
	// enabling expiration should trigger the routine
	update.LoginExpirationEnabled = true
	_, err = manager.UpdatePeer(context.Background(), accountID, userID, update)
	require.NoError(t, err, "unable to update peer")

	failed := waitTimeout(wg, time.Second)
	if failed {
		t.Fatal("timeout while waiting for test to finish")
	}
}

func TestDefaultAccountManager_MarkPeerConnected_PeerLoginExpiration(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")

	accountID, err := manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err, "unable to create an account")

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err, "unable to generate WireGuard key")
	_, _, _, err = manager.AddPeer(context.Background(), "", "", userID, &nbpeer.Peer{
		Key:                    key.PublicKey().String(),
		Meta:                   nbpeer.PeerSystemMeta{Hostname: "test-peer"},
		LoginExpirationEnabled: true,
	}, false)
	require.NoError(t, err, "unable to add peer")
	_, err = manager.UpdateAccountSettings(context.Background(), accountID, userID, &types.Settings{
		PeerLoginExpiration:        time.Hour,
		PeerLoginExpirationEnabled: true,
		Extra:                      &types.ExtraSettings{},
	})
	require.NoError(t, err, "expecting to update account settings successfully but got error")

	wg := &sync.WaitGroup{}
	wg.Add(1)
	manager.peerLoginExpiry = &MockScheduler{
		ScheduleFunc: func(ctx context.Context, in time.Duration, ID string, job func() (nextRunIn time.Duration, reschedule bool)) {
			wg.Done()
		},
	}

	accountID, err = manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err, "unable to get the account")

	// when we mark peer as connected, the peer login expiration routine should trigger
	err = manager.MarkPeerConnected(context.Background(), key.PublicKey().String(), true, nil, accountID)
	require.NoError(t, err, "unable to mark peer connected")

	failed := waitTimeout(wg, time.Second)
	if failed {
		t.Fatal("timeout while waiting for test to finish")
	}
}

func TestDefaultAccountManager_UpdateAccountSettings_PeerLoginExpiration(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")

	_, err = manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err, "unable to create an account")

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err, "unable to generate WireGuard key")
	_, _, _, err = manager.AddPeer(context.Background(), "", "", userID, &nbpeer.Peer{
		Key:                    key.PublicKey().String(),
		Meta:                   nbpeer.PeerSystemMeta{Hostname: "test-peer"},
		LoginExpirationEnabled: true,
	}, false)
	require.NoError(t, err, "unable to add peer")

	accountID, err := manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err, "unable to get the account")

	account, err := manager.Store.GetAccount(context.Background(), accountID)
	require.NoError(t, err, "unable to get the account")

	err = manager.MarkPeerConnected(context.Background(), key.PublicKey().String(), true, nil, accountID)
	require.NoError(t, err, "unable to mark peer connected")

	wg := &sync.WaitGroup{}
	wg.Add(2)
	manager.peerLoginExpiry = &MockScheduler{
		CancelFunc: func(ctx context.Context, IDs []string) {
			wg.Done()
		},
		ScheduleFunc: func(ctx context.Context, in time.Duration, ID string, job func() (nextRunIn time.Duration, reschedule bool)) {
			wg.Done()
		},
	}
	// enabling PeerLoginExpirationEnabled should trigger the expiration job
	_, err = manager.UpdateAccountSettings(context.Background(), account.Id, userID, &types.Settings{
		PeerLoginExpiration:        time.Hour,
		PeerLoginExpirationEnabled: true,
		Extra:                      &types.ExtraSettings{},
	})
	require.NoError(t, err, "expecting to update account settings successfully but got error")

	failed := waitTimeout(wg, time.Second)
	if failed {
		t.Fatal("timeout while waiting for test to finish")
	}
	wg.Add(1)

	// disabling PeerLoginExpirationEnabled should trigger cancel
	_, err = manager.UpdateAccountSettings(context.Background(), account.Id, userID, &types.Settings{
		PeerLoginExpiration:        time.Hour,
		PeerLoginExpirationEnabled: false,
		Extra:                      &types.ExtraSettings{},
	})
	require.NoError(t, err, "expecting to update account settings successfully but got error")
	failed = waitTimeout(wg, time.Second)
	if failed {
		t.Fatal("timeout while waiting for test to finish")
	}
}

func TestDefaultAccountManager_UpdateAccountSettings(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")

	accountID, err := manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err, "unable to create an account")

	updatedSettings, err := manager.UpdateAccountSettings(context.Background(), accountID, userID, &types.Settings{
		PeerLoginExpiration:        time.Hour,
		PeerLoginExpirationEnabled: false,
		Extra:                      &types.ExtraSettings{},
	})
	require.NoError(t, err, "expecting to update account settings successfully but got error")
	assert.False(t, updatedSettings.PeerLoginExpirationEnabled)
	assert.Equal(t, updatedSettings.PeerLoginExpiration, time.Hour)

	settings, err := manager.Store.GetAccountSettings(context.Background(), store.LockingStrengthNone, accountID)
	require.NoError(t, err, "unable to get account settings")

	assert.False(t, settings.PeerLoginExpirationEnabled)
	assert.Equal(t, settings.PeerLoginExpiration, time.Hour)

	_, err = manager.UpdateAccountSettings(context.Background(), accountID, userID, &types.Settings{
		PeerLoginExpiration:        time.Second,
		PeerLoginExpirationEnabled: false,
		Extra:                      &types.ExtraSettings{},
	})
	require.Error(t, err, "expecting to fail when providing PeerLoginExpiration less than one hour")

	_, err = manager.UpdateAccountSettings(context.Background(), accountID, userID, &types.Settings{
		PeerLoginExpiration:        time.Hour * 24 * 181,
		PeerLoginExpirationEnabled: false,
		Extra:                      &types.ExtraSettings{},
	})
	require.Error(t, err, "expecting to fail when providing PeerLoginExpiration more than 180 days")
}

func TestDefaultAccountManager_UpdateAccountSettings_PeerApproval(t *testing.T) {
	manager, _, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

	accountID := account.Id
	userID := account.Users[account.CreatedBy].Id
	ctx := context.Background()

	newSettings := account.Settings.Copy()
	newSettings.Extra = &types.ExtraSettings{
		PeerApprovalEnabled: true,
	}
	_, err := manager.UpdateAccountSettings(ctx, accountID, userID, newSettings)
	require.NoError(t, err)

	peer1.Status.RequiresApproval = true
	peer2.Status.RequiresApproval = true
	peer3.Status.RequiresApproval = false

	require.NoError(t, manager.Store.SavePeer(ctx, accountID, peer1))
	require.NoError(t, manager.Store.SavePeer(ctx, accountID, peer2))
	require.NoError(t, manager.Store.SavePeer(ctx, accountID, peer3))

	newSettings = account.Settings.Copy()
	newSettings.Extra = &types.ExtraSettings{
		PeerApprovalEnabled: false,
	}
	_, err = manager.UpdateAccountSettings(ctx, accountID, userID, newSettings)
	require.NoError(t, err)

	accountPeers, err := manager.Store.GetAccountPeers(ctx, store.LockingStrengthNone, accountID, "", "")
	require.NoError(t, err)

	for _, peer := range accountPeers {
		assert.False(t, peer.Status.RequiresApproval, "peer %s should not require approval after disabling peer approval", peer.ID)
	}
}

func TestAccount_GetExpiredPeers(t *testing.T) {
	type test struct {
		name          string
		peers         map[string]*nbpeer.Peer
		expectedPeers map[string]struct{}
	}
	testCases := []test{
		{
			name: "Peers with login expiration disabled, no expired peers",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					LoginExpirationEnabled: false,
				},
				"peer-2": {
					LoginExpirationEnabled: false,
				},
			},
			expectedPeers: map[string]struct{}{},
		},
		{
			name: "Two peers expired",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					ID:                     "peer-1",
					LoginExpirationEnabled: true,
					Status: &nbpeer.PeerStatus{
						LastSeen:     time.Now().UTC(),
						Connected:    true,
						LoginExpired: false,
					},
					LastLogin: util.ToPtr(time.Now().UTC().Add(-30 * time.Minute)),
					UserID:    userID,
				},
				"peer-2": {
					ID:                     "peer-2",
					LoginExpirationEnabled: true,
					Status: &nbpeer.PeerStatus{
						LastSeen:     time.Now().UTC(),
						Connected:    true,
						LoginExpired: false,
					},
					LastLogin: util.ToPtr(time.Now().UTC().Add(-2 * time.Hour)),
					UserID:    userID,
				},

				"peer-3": {
					ID:                     "peer-3",
					LoginExpirationEnabled: true,
					Status: &nbpeer.PeerStatus{
						LastSeen:     time.Now().UTC(),
						Connected:    true,
						LoginExpired: false,
					},
					LastLogin: util.ToPtr(time.Now().UTC().Add(-1 * time.Hour)),
					UserID:    userID,
				},
			},
			expectedPeers: map[string]struct{}{
				"peer-2": {},
				"peer-3": {},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			account := &types.Account{
				Peers: testCase.peers,
				Settings: &types.Settings{
					PeerLoginExpirationEnabled: true,
					PeerLoginExpiration:        time.Hour,
				},
			}

			expiredPeers := account.GetExpiredPeers()
			assert.Len(t, expiredPeers, len(testCase.expectedPeers))
			for _, peer := range expiredPeers {
				if _, ok := testCase.expectedPeers[peer.ID]; !ok {
					t.Fatalf("expected to have peer %s expired", peer.ID)
				}
			}
		})
	}
}

func TestAccount_GetInactivePeers(t *testing.T) {
	type test struct {
		name          string
		peers         map[string]*nbpeer.Peer
		expectedPeers map[string]struct{}
	}
	testCases := []test{
		{
			name: "Peers with inactivity expiration disabled, no expired peers",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					InactivityExpirationEnabled: false,
				},
				"peer-2": {
					InactivityExpirationEnabled: false,
				},
			},
			expectedPeers: map[string]struct{}{},
		},
		{
			name: "Two peers expired",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					ID:                          "peer-1",
					InactivityExpirationEnabled: true,
					Status: &nbpeer.PeerStatus{
						LastSeen:     time.Now().UTC().Add(-45 * time.Second),
						Connected:    false,
						LoginExpired: false,
					},
					LastLogin: util.ToPtr(time.Now().UTC().Add(-30 * time.Minute)),
					UserID:    userID,
				},
				"peer-2": {
					ID:                          "peer-2",
					InactivityExpirationEnabled: true,
					Status: &nbpeer.PeerStatus{
						LastSeen:     time.Now().UTC().Add(-45 * time.Second),
						Connected:    false,
						LoginExpired: false,
					},
					LastLogin: util.ToPtr(time.Now().UTC().Add(-2 * time.Hour)),
					UserID:    userID,
				},
				"peer-3": {
					ID:                          "peer-3",
					InactivityExpirationEnabled: true,
					Status: &nbpeer.PeerStatus{
						LastSeen:     time.Now().UTC(),
						Connected:    true,
						LoginExpired: false,
					},
					LastLogin: util.ToPtr(time.Now().UTC().Add(-1 * time.Hour)),
					UserID:    userID,
				},
			},
			expectedPeers: map[string]struct{}{
				"peer-1": {},
				"peer-2": {},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			account := &types.Account{
				Peers: testCase.peers,
				Settings: &types.Settings{
					PeerInactivityExpirationEnabled: true,
					PeerInactivityExpiration:        time.Second,
				},
			}

			expiredPeers := account.GetInactivePeers()
			assert.Len(t, expiredPeers, len(testCase.expectedPeers))
			for _, peer := range expiredPeers {
				if _, ok := testCase.expectedPeers[peer.ID]; !ok {
					t.Fatalf("expected to have peer %s expired", peer.ID)
				}
			}
		})
	}
}

func TestAccount_GetPeersWithExpiration(t *testing.T) {
	type test struct {
		name          string
		peers         map[string]*nbpeer.Peer
		expectedPeers map[string]struct{}
	}

	testCases := []test{
		{
			name:          "No account peers, no peers with expiration",
			peers:         map[string]*nbpeer.Peer{},
			expectedPeers: map[string]struct{}{},
		},
		{
			name: "Peers with login expiration disabled, no peers with expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					LoginExpirationEnabled: false,
					UserID:                 userID,
				},
				"peer-2": {
					LoginExpirationEnabled: false,
					UserID:                 userID,
				},
			},
			expectedPeers: map[string]struct{}{},
		},
		{
			name: "Peers with login expiration enabled, return peers with expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					ID:                     "peer-1",
					LoginExpirationEnabled: true,
					UserID:                 userID,
				},
				"peer-2": {
					LoginExpirationEnabled: false,
					UserID:                 userID,
				},
			},
			expectedPeers: map[string]struct{}{
				"peer-1": {},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			account := &types.Account{
				Peers: testCase.peers,
			}

			actual := account.GetPeersWithExpiration()
			assert.Len(t, actual, len(testCase.expectedPeers))
			if len(testCase.expectedPeers) > 0 {
				for k := range testCase.expectedPeers {
					contains := false
					for _, peer := range actual {
						if k == peer.ID {
							contains = true
						}
					}
					assert.True(t, contains)
				}
			}
		})
	}
}

func TestAccount_GetPeersWithInactivity(t *testing.T) {
	type test struct {
		name          string
		peers         map[string]*nbpeer.Peer
		expectedPeers map[string]struct{}
	}

	testCases := []test{
		{
			name:          "No account peers, no peers with expiration",
			peers:         map[string]*nbpeer.Peer{},
			expectedPeers: map[string]struct{}{},
		},
		{
			name: "Peers with login expiration disabled, no peers with expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					InactivityExpirationEnabled: false,
					UserID:                      userID,
				},
				"peer-2": {
					InactivityExpirationEnabled: false,
					UserID:                      userID,
				},
			},
			expectedPeers: map[string]struct{}{},
		},
		{
			name: "Peers with login expiration enabled, return peers with expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					ID:                          "peer-1",
					InactivityExpirationEnabled: true,
					UserID:                      userID,
				},
				"peer-2": {
					InactivityExpirationEnabled: false,
					UserID:                      userID,
				},
			},
			expectedPeers: map[string]struct{}{
				"peer-1": {},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			account := &types.Account{
				Peers: testCase.peers,
			}

			actual := account.GetPeersWithInactivity()
			assert.Len(t, actual, len(testCase.expectedPeers))
			if len(testCase.expectedPeers) > 0 {
				for k := range testCase.expectedPeers {
					contains := false
					for _, peer := range actual {
						if k == peer.ID {
							contains = true
						}
					}
					assert.True(t, contains)
				}
			}
		})
	}
}

func TestAccount_GetNextPeerExpiration(t *testing.T) {
	type test struct {
		name                   string
		peers                  map[string]*nbpeer.Peer
		expiration             time.Duration
		expirationEnabled      bool
		expectedNextRun        bool
		expectedNextExpiration time.Duration
	}

	expectedNextExpiration := time.Minute
	testCases := []test{
		{
			name:                   "No peers, no expiration",
			peers:                  map[string]*nbpeer.Peer{},
			expiration:             time.Second,
			expirationEnabled:      false,
			expectedNextRun:        false,
			expectedNextExpiration: time.Duration(0),
		},
		{
			name: "No connected peers, no expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					Status: &nbpeer.PeerStatus{
						Connected: false,
					},
					LoginExpirationEnabled: true,
					UserID:                 userID,
				},
				"peer-2": {
					Status: &nbpeer.PeerStatus{
						Connected: true,
					},
					LoginExpirationEnabled: false,
					UserID:                 userID,
				},
			},
			expiration:             time.Second,
			expirationEnabled:      false,
			expectedNextRun:        false,
			expectedNextExpiration: time.Duration(0),
		},
		{
			name: "Connected peers with disabled expiration, no expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					Status: &nbpeer.PeerStatus{
						Connected: true,
					},
					LoginExpirationEnabled: false,
					UserID:                 userID,
				},
				"peer-2": {
					Status: &nbpeer.PeerStatus{
						Connected: true,
					},
					LoginExpirationEnabled: false,
					UserID:                 userID,
				},
			},
			expiration:             time.Second,
			expirationEnabled:      false,
			expectedNextRun:        false,
			expectedNextExpiration: time.Duration(0),
		},
		{
			name: "Expired peers, no expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					Status: &nbpeer.PeerStatus{
						Connected:    true,
						LoginExpired: true,
					},
					LoginExpirationEnabled: true,
					UserID:                 userID,
				},
				"peer-2": {
					Status: &nbpeer.PeerStatus{
						Connected:    true,
						LoginExpired: true,
					},
					LoginExpirationEnabled: true,
					UserID:                 userID,
				},
			},
			expiration:             time.Second,
			expirationEnabled:      false,
			expectedNextRun:        false,
			expectedNextExpiration: time.Duration(0),
		},
		{
			name: "To be expired peer, return expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					Status: &nbpeer.PeerStatus{
						Connected:    true,
						LoginExpired: false,
					},
					LoginExpirationEnabled: true,
					LastLogin:              util.ToPtr(time.Now().UTC()),
					UserID:                 userID,
				},
				"peer-2": {
					Status: &nbpeer.PeerStatus{
						Connected:    true,
						LoginExpired: true,
					},
					LoginExpirationEnabled: true,
					UserID:                 userID,
				},
			},
			expiration:             time.Minute,
			expirationEnabled:      false,
			expectedNextRun:        true,
			expectedNextExpiration: expectedNextExpiration,
		},
		{
			name: "Peers added with setup keys, no expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					Status: &nbpeer.PeerStatus{
						Connected:    true,
						LoginExpired: false,
					},
					LoginExpirationEnabled: true,
				},
				"peer-2": {
					Status: &nbpeer.PeerStatus{
						Connected:    true,
						LoginExpired: false,
					},
					LoginExpirationEnabled: true,
				},
			},
			expiration:             time.Second,
			expirationEnabled:      false,
			expectedNextRun:        false,
			expectedNextExpiration: time.Duration(0),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			account := &types.Account{
				Peers:    testCase.peers,
				Settings: &types.Settings{PeerLoginExpiration: testCase.expiration, PeerLoginExpirationEnabled: testCase.expirationEnabled},
			}

			expiration, ok := account.GetNextPeerExpiration()
			assert.Equal(t, ok, testCase.expectedNextRun)
			if testCase.expectedNextRun {
				assert.True(t, expiration >= 0 && expiration <= testCase.expectedNextExpiration)
			} else {
				assert.Equal(t, expiration, testCase.expectedNextExpiration)
			}
		})
	}
}

func TestAccount_GetNextInactivePeerExpiration(t *testing.T) {
	type test struct {
		name                   string
		peers                  map[string]*nbpeer.Peer
		expiration             time.Duration
		expirationEnabled      bool
		expectedNextRun        bool
		expectedNextExpiration time.Duration
	}

	expectedNextExpiration := time.Minute
	testCases := []test{
		{
			name:                   "No peers, no expiration",
			peers:                  map[string]*nbpeer.Peer{},
			expiration:             time.Second,
			expirationEnabled:      false,
			expectedNextRun:        false,
			expectedNextExpiration: time.Duration(0),
		},
		{
			name: "No connected peers, no expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					Status: &nbpeer.PeerStatus{
						Connected: false,
					},
					InactivityExpirationEnabled: false,
					UserID:                      userID,
				},
				"peer-2": {
					Status: &nbpeer.PeerStatus{
						Connected: false,
					},
					InactivityExpirationEnabled: false,
					UserID:                      userID,
				},
			},
			expiration:             time.Second,
			expirationEnabled:      false,
			expectedNextRun:        false,
			expectedNextExpiration: time.Duration(0),
		},
		{
			name: "Connected peers with disabled expiration, no expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					Status: &nbpeer.PeerStatus{
						Connected: true,
					},
					InactivityExpirationEnabled: false,
					UserID:                      userID,
				},
				"peer-2": {
					Status: &nbpeer.PeerStatus{
						Connected: true,
					},
					InactivityExpirationEnabled: false,
					UserID:                      userID,
				},
			},
			expiration:             time.Second,
			expirationEnabled:      false,
			expectedNextRun:        false,
			expectedNextExpiration: time.Duration(0),
		},
		{
			name: "Expired peers, no expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					Status: &nbpeer.PeerStatus{
						Connected:    true,
						LoginExpired: true,
					},
					InactivityExpirationEnabled: true,
					UserID:                      userID,
				},
				"peer-2": {
					Status: &nbpeer.PeerStatus{
						Connected:    true,
						LoginExpired: true,
					},
					InactivityExpirationEnabled: true,
					UserID:                      userID,
				},
			},
			expiration:             time.Second,
			expirationEnabled:      false,
			expectedNextRun:        false,
			expectedNextExpiration: time.Duration(0),
		},
		{
			name: "To be expired peer, return expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					Status: &nbpeer.PeerStatus{
						Connected:    false,
						LoginExpired: false,
						LastSeen:     time.Now().Add(-1 * time.Second),
					},
					InactivityExpirationEnabled: true,
					LastLogin:                   util.ToPtr(time.Now().UTC()),
					UserID:                      userID,
				},
				"peer-2": {
					Status: &nbpeer.PeerStatus{
						Connected:    true,
						LoginExpired: true,
					},
					InactivityExpirationEnabled: true,
					UserID:                      userID,
				},
			},
			expiration:             time.Minute,
			expirationEnabled:      false,
			expectedNextRun:        true,
			expectedNextExpiration: expectedNextExpiration,
		},
		{
			name: "Peers added with setup keys, no expiration",
			peers: map[string]*nbpeer.Peer{
				"peer-1": {
					Status: &nbpeer.PeerStatus{
						Connected:    true,
						LoginExpired: false,
					},
					InactivityExpirationEnabled: true,
				},
				"peer-2": {
					Status: &nbpeer.PeerStatus{
						Connected:    true,
						LoginExpired: false,
					},
					InactivityExpirationEnabled: true,
				},
			},
			expiration:             time.Second,
			expirationEnabled:      false,
			expectedNextRun:        false,
			expectedNextExpiration: time.Duration(0),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			account := &types.Account{
				Peers:    testCase.peers,
				Settings: &types.Settings{PeerInactivityExpiration: testCase.expiration, PeerInactivityExpirationEnabled: testCase.expirationEnabled},
			}

			expiration, ok := account.GetNextInactivePeerExpiration()
			assert.Equal(t, testCase.expectedNextRun, ok)
			if testCase.expectedNextRun {
				assert.True(t, expiration >= 0 && expiration <= testCase.expectedNextExpiration)
			} else {
				assert.Equal(t, expiration, testCase.expectedNextExpiration)
			}
		})
	}
}

func TestAccount_SetJWTGroups(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", "postgres")
	manager, _, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")

	// create a new account
	account := &types.Account{
		Id: "accountID",
		Peers: map[string]*nbpeer.Peer{
			"peer1": {ID: "peer1", Key: "key1", UserID: "user1", IP: net.IP{1, 1, 1, 1}, DNSLabel: "peer1.domain.test"},
			"peer2": {ID: "peer2", Key: "key2", UserID: "user1", IP: net.IP{2, 2, 2, 2}, DNSLabel: "peer2.domain.test"},
			"peer3": {ID: "peer3", Key: "key3", UserID: "user1", IP: net.IP{3, 3, 3, 3}, DNSLabel: "peer3.domain.test"},
			"peer4": {ID: "peer4", Key: "key4", UserID: "user2", IP: net.IP{4, 4, 4, 4}, DNSLabel: "peer4.domain.test"},
			"peer5": {ID: "peer5", Key: "key5", UserID: "user2", IP: net.IP{5, 5, 5, 5}, DNSLabel: "peer5.domain.test"},
		},
		Groups: map[string]*types.Group{
			"group1": {ID: "group1", Name: "group1", Issued: types.GroupIssuedAPI, Peers: []string{}},
		},
		Settings: &types.Settings{GroupsPropagationEnabled: true, JWTGroupsEnabled: true, JWTGroupsClaimName: "groups"},
		Users: map[string]*types.User{
			"user1": {Id: "user1", AccountID: "accountID", CreatedAt: time.Now()},
			"user2": {Id: "user2", AccountID: "accountID", CreatedAt: time.Now()},
		},
	}

	assert.NoError(t, manager.Store.SaveAccount(context.Background(), account), "unable to save account")

	t.Run("skip sync for token auth type", func(t *testing.T) {
		claims := auth.UserAuth{
			UserId:    "user1",
			AccountId: "accountID",
			Groups:    []string{"group3"},
			IsPAT:     true,
		}
		err = manager.SyncUserJWTGroups(context.Background(), claims)
		assert.NoError(t, err, "unable to sync jwt groups")

		user, err := manager.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, "user1")
		assert.NoError(t, err, "unable to get user")
		assert.Len(t, user.AutoGroups, 0, "JWT groups should not be synced")
	})

	t.Run("empty jwt groups", func(t *testing.T) {
		claims := auth.UserAuth{
			UserId:    "user1",
			AccountId: "accountID",
			Groups:    []string{},
		}
		err := manager.SyncUserJWTGroups(context.Background(), claims)
		assert.NoError(t, err, "unable to sync jwt groups")

		user, err := manager.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, "user1")
		assert.NoError(t, err, "unable to get user")
		assert.Empty(t, user.AutoGroups, "auto groups must be empty")
	})

	t.Run("jwt match existing api group", func(t *testing.T) {
		claims := auth.UserAuth{
			UserId:    "user1",
			AccountId: "accountID",
			Groups:    []string{"group1"},
		}
		err := manager.SyncUserJWTGroups(context.Background(), claims)
		assert.NoError(t, err, "unable to sync jwt groups")

		user, err := manager.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, "user1")
		assert.NoError(t, err, "unable to get user")
		assert.Len(t, user.AutoGroups, 0)

		group1, err := manager.Store.GetGroupByID(context.Background(), store.LockingStrengthNone, "accountID", "group1")
		assert.NoError(t, err, "unable to get group")
		assert.Equal(t, group1.Issued, types.GroupIssuedAPI, "group should be api issued")
	})

	t.Run("jwt match existing api group in user auto groups", func(t *testing.T) {
		account.Users["user1"].AutoGroups = []string{"group1"}
		assert.NoError(t, manager.Store.SaveUser(context.Background(), account.Users["user1"]))

		claims := auth.UserAuth{
			UserId:    "user1",
			AccountId: "accountID",
			Groups:    []string{"group1"},
		}
		err = manager.SyncUserJWTGroups(context.Background(), claims)
		assert.NoError(t, err, "unable to sync jwt groups")

		user, err := manager.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, "user1")
		assert.NoError(t, err, "unable to get user")
		assert.Len(t, user.AutoGroups, 1)

		group1, err := manager.Store.GetGroupByID(context.Background(), store.LockingStrengthNone, "accountID", "group1")
		assert.NoError(t, err, "unable to get group")
		assert.Equal(t, group1.Issued, types.GroupIssuedAPI, "group should be api issued")
	})

	t.Run("add jwt group", func(t *testing.T) {
		claims := auth.UserAuth{
			UserId:    "user1",
			AccountId: "accountID",
			Groups:    []string{"group1", "group2"},
		}
		err = manager.SyncUserJWTGroups(context.Background(), claims)
		assert.NoError(t, err, "unable to sync jwt groups")

		user, err := manager.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, "user1")
		assert.NoError(t, err, "unable to get user")
		assert.Len(t, user.AutoGroups, 2, "groups count should not be change")
	})

	t.Run("existed group not update", func(t *testing.T) {
		claims := auth.UserAuth{
			UserId:    "user1",
			AccountId: "accountID",
			Groups:    []string{"group2"},
		}
		err = manager.SyncUserJWTGroups(context.Background(), claims)
		assert.NoError(t, err, "unable to sync jwt groups")

		user, err := manager.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, "user1")
		assert.NoError(t, err, "unable to get user")
		assert.Len(t, user.AutoGroups, 2, "groups count should not be change")
	})

	t.Run("add new group", func(t *testing.T) {
		claims := auth.UserAuth{
			UserId:    "user2",
			AccountId: "accountID",
			Groups:    []string{"group1", "group3"},
		}
		err = manager.SyncUserJWTGroups(context.Background(), claims)
		assert.NoError(t, err, "unable to sync jwt groups")

		groups, err := manager.Store.GetAccountGroups(context.Background(), store.LockingStrengthNone, "accountID")
		assert.NoError(t, err)
		assert.Len(t, groups, 3, "new group3 should be added")

		user, err := manager.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, "user2")
		assert.NoError(t, err, "unable to get user")
		assert.Len(t, user.AutoGroups, 1, "new group should be added")
	})

	t.Run("remove all JWT groups when list is empty", func(t *testing.T) {
		claims := auth.UserAuth{
			UserId:    "user1",
			AccountId: "accountID",
			Groups:    []string{},
		}
		err = manager.SyncUserJWTGroups(context.Background(), claims)
		assert.NoError(t, err, "unable to sync jwt groups")

		user, err := manager.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, "user1")
		assert.NoError(t, err, "unable to get user")
		assert.Len(t, user.AutoGroups, 1, "only non-JWT groups should remain")
		assert.Contains(t, user.AutoGroups, "group1", "group1 should still be present")
	})

	t.Run("remove all JWT groups when claim does not exist", func(t *testing.T) {
		claims := auth.UserAuth{
			UserId:    "user2",
			AccountId: "accountID",
			Groups:    []string{},
		}
		err = manager.SyncUserJWTGroups(context.Background(), claims)
		assert.NoError(t, err, "unable to sync jwt groups")

		user, err := manager.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, "user2")
		assert.NoError(t, err, "unable to get user")
		assert.Len(t, user.AutoGroups, 0, "all JWT groups should be removed")
	})
}

func TestAccount_UserGroupsAddToPeers(t *testing.T) {
	account := &types.Account{
		Peers: map[string]*nbpeer.Peer{
			"peer1": {ID: "peer1", Key: "key1", UserID: "user1"},
			"peer2": {ID: "peer2", Key: "key2", UserID: "user1"},
			"peer3": {ID: "peer3", Key: "key3", UserID: "user1"},
			"peer4": {ID: "peer4", Key: "key4", UserID: "user2"},
			"peer5": {ID: "peer5", Key: "key5", UserID: "user2"},
		},
		Groups: map[string]*types.Group{
			"group1": {ID: "group1", Name: "group1", Issued: types.GroupIssuedAPI, Peers: []string{}},
			"group2": {ID: "group2", Name: "group2", Issued: types.GroupIssuedAPI, Peers: []string{}},
			"group3": {ID: "group3", Name: "group3", Issued: types.GroupIssuedAPI, Peers: []string{}},
		},
		Users: map[string]*types.User{"user1": {Id: "user1"}, "user2": {Id: "user2"}},
	}

	t.Run("add groups", func(t *testing.T) {
		account.UserGroupsAddToPeers("user1", "group1", "group2")
		assert.ElementsMatch(t, account.Groups["group1"].Peers, []string{"peer1", "peer2", "peer3"}, "group1 contains users peers")
		assert.ElementsMatch(t, account.Groups["group2"].Peers, []string{"peer1", "peer2", "peer3"}, "group2 contains users peers")
	})

	t.Run("add same groups", func(t *testing.T) {
		account.UserGroupsAddToPeers("user1", "group1", "group2")
		assert.Len(t, account.Groups["group1"].Peers, 3, "peers amount in group1 didn't change")
		assert.Len(t, account.Groups["group2"].Peers, 3, "peers amount in group2 didn't change")
	})

	t.Run("add second user peers", func(t *testing.T) {
		account.UserGroupsAddToPeers("user2", "group2")
		assert.ElementsMatch(t, account.Groups["group2"].Peers,
			[]string{"peer1", "peer2", "peer3", "peer4", "peer5"}, "group2 contains first and second user peers")
	})
}

func TestAccount_UserGroupsRemoveFromPeers(t *testing.T) {
	account := &types.Account{
		Peers: map[string]*nbpeer.Peer{
			"peer1": {ID: "peer1", Key: "key1", UserID: "user1"},
			"peer2": {ID: "peer2", Key: "key2", UserID: "user1"},
			"peer3": {ID: "peer3", Key: "key3", UserID: "user1"},
			"peer4": {ID: "peer4", Key: "key4", UserID: "user2"},
			"peer5": {ID: "peer5", Key: "key5", UserID: "user2"},
		},
		Groups: map[string]*types.Group{
			"group1": {ID: "group1", Name: "group1", Issued: types.GroupIssuedAPI, Peers: []string{"peer1", "peer2", "peer3"}},
			"group2": {ID: "group2", Name: "group2", Issued: types.GroupIssuedAPI, Peers: []string{"peer1", "peer2", "peer3", "peer4", "peer5"}},
			"group3": {ID: "group3", Name: "group3", Issued: types.GroupIssuedAPI, Peers: []string{"peer4", "peer5"}},
		},
		Users: map[string]*types.User{"user1": {Id: "user1"}, "user2": {Id: "user2"}},
	}

	t.Run("remove groups", func(t *testing.T) {
		account.UserGroupsRemoveFromPeers("user1", "group1", "group2")
		assert.Empty(t, account.Groups["group1"].Peers, "remove all peers from group1")
		assert.ElementsMatch(t, account.Groups["group2"].Peers, []string{"peer4", "peer5"}, "group2 contains only second users peers")
	})

	t.Run("remove group with no peers", func(t *testing.T) {
		account.UserGroupsRemoveFromPeers("user1", "group3")
		assert.Len(t, account.Groups["group3"].Peers, 2, "peers amount should not change")
	})
}

// type TB interface {
//	Cleanup(func())
//	Helper()
//	TempDir() string
//	Errorf(format string, args ...interface{})
//	Fatalf(format string, args ...interface{})
// }

func createManager(t testing.TB) (*DefaultAccountManager, *update_channel.PeersUpdateManager, error) {
	t.Helper()

	store, err := createStore(t)
	if err != nil {
		return nil, nil, err
	}
	eventStore := &activity.InMemoryEventStore{}

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	if err != nil {
		return nil, nil, err
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	settingsMockManager := settings.NewMockManager(ctrl)
	settingsMockManager.EXPECT().
		GetExtraSettings(gomock.Any(), gomock.Any()).
		Return(&types.ExtraSettings{}, nil).
		AnyTimes()
	settingsMockManager.EXPECT().
		UpdateExtraSettings(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(false, nil).
		AnyTimes()

	permissionsManager := permissions.NewManager(store)

	ctx := context.Background()

	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := NewAccountRequestBuffer(ctx, store)
	networkMapController := controller.NewController(ctx, store, metrics, updateManager, requestBuffer, MockIntegratedValidator{}, settingsMockManager, "netbird.cloud", port_forwarding.NewControllerMock(), ephemeral_manager.NewEphemeralManager(store, peers.NewManager(store, permissionsManager)), &config.Config{})
	manager, err := BuildManager(ctx, &config.Config{}, store, networkMapController, nil, "", eventStore, nil, false, MockIntegratedValidator{}, metrics, port_forwarding.NewControllerMock(), settingsMockManager, permissionsManager, false)
	if err != nil {
		return nil, nil, err
	}

	return manager, updateManager, nil
}

func createStore(t testing.TB) (store.Store, error) {
	t.Helper()
	dataDir := t.TempDir()
	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "", dataDir)
	if err != nil {
		return nil, err
	}
	t.Cleanup(cleanUp)

	return store, nil
}

func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false
	case <-time.After(timeout):
		return true
	}
}

func setupNetworkMapTest(t *testing.T) (*DefaultAccountManager, *update_channel.PeersUpdateManager, *types.Account, *nbpeer.Peer, *nbpeer.Peer, *nbpeer.Peer) {
	t.Helper()

	manager, updateManager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	account, err := createAccount(manager, "test_account", userID, "")
	if err != nil {
		t.Fatal(err)
	}

	setupKey, err := manager.CreateSetupKey(context.Background(), account.Id, "test-key", types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	if err != nil {
		t.Fatal("error creating setup key")
	}

	getPeer := func(manager *DefaultAccountManager, setupKey *types.SetupKey) *nbpeer.Peer {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		expectedPeerKey := key.PublicKey().String()

		peer, _, _, err := manager.AddPeer(context.Background(), "", setupKey.Key, "", &nbpeer.Peer{
			Key:  expectedPeerKey,
			Meta: nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
			Status: &nbpeer.PeerStatus{
				Connected: true,
				LastSeen:  time.Now().UTC(),
			},
		}, false)
		if err != nil {
			t.Fatalf("expecting peer to be added, got failure %v", err)
		}

		return peer
	}

	peer1 := getPeer(manager, setupKey)
	peer2 := getPeer(manager, setupKey)
	peer3 := getPeer(manager, setupKey)

	return manager, updateManager, account, peer1, peer2, peer3
}

func peerShouldNotReceiveUpdate(t *testing.T, updateMessage <-chan *network_map.UpdateMessage) {
	t.Helper()
	select {
	case msg := <-updateMessage:
		t.Errorf("Unexpected message received: %+v", msg)
	case <-time.After(500 * time.Millisecond):
		return
	}
}

func peerShouldReceiveUpdate(t *testing.T, updateMessage <-chan *network_map.UpdateMessage) {
	t.Helper()

	select {
	case msg := <-updateMessage:
		if msg == nil {
			t.Errorf("Received nil update message, expected valid message")
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("Timed out waiting for update message")
	}
}

func BenchmarkSyncAndMarkPeer(b *testing.B) {
	b.Setenv("NB_GET_ACCOUNT_BUFFER_INTERVAL", "0")

	benchCases := []struct {
		name   string
		peers  int
		groups int
		// We need different expectations for CI/CD and local runs because of the different performance characteristics
		minMsPerOpLocal float64
		maxMsPerOpLocal float64
		minMsPerOpCICD  float64
		maxMsPerOpCICD  float64
	}{
		{"Small", 50, 5, 1, 5, 3, 24},
		{"Medium", 500, 100, 7, 22, 10, 135},
		{"Large", 5000, 200, 65, 110, 60, 320},
		{"Small single", 50, 10, 1, 4, 3, 80},
		{"Medium single", 500, 10, 7, 13, 10, 43},
		{"Large 5", 5000, 15, 65, 80, 60, 220},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			manager, updateManager, accountID, _, err := setupTestAccountManager(b, bc.peers, bc.groups)
			if err != nil {
				b.Fatalf("Failed to setup test account manager: %v", err)
			}
			ctx := context.Background()
			account, err := manager.Store.GetAccount(ctx, accountID)
			if err != nil {
				b.Fatalf("Failed to get account: %v", err)
			}
			for peerID := range account.Peers {
				updateManager.CreateChannel(ctx, peerID)
			}

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				_, _, _, _, err := manager.SyncAndMarkPeer(context.Background(), account.Id, account.Peers["peer-1"].Key, nbpeer.PeerSystemMeta{Hostname: strconv.Itoa(i)}, net.IP{1, 1, 1, 1})
				assert.NoError(b, err)
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")

			maxExpected := bc.maxMsPerOpLocal
			if os.Getenv("CI") == "true" {
				maxExpected = bc.maxMsPerOpCICD
				testing_tools.EvaluateBenchmarkResults(b, bc.name, time.Since(start), "sync", "syncAndMark")
			}

			if msPerOp > maxExpected {
				b.Logf("Benchmark %s: too slow (%.2f ms/op, max %.2f ms/op)", bc.name, msPerOp, maxExpected)
			}
		})
	}
}

func BenchmarkLoginPeer_ExistingPeer(b *testing.B) {
	b.Setenv("NB_GET_ACCOUNT_BUFFER_INTERVAL", "0")
	benchCases := []struct {
		name   string
		peers  int
		groups int
		// We need different expectations for CI/CD and local runs because of the different performance characteristics
		minMsPerOpLocal float64
		maxMsPerOpLocal float64
		minMsPerOpCICD  float64
		maxMsPerOpCICD  float64
	}{
		{"Small", 50, 5, 2, 10, 3, 35},
		{"Medium", 500, 100, 5, 40, 20, 140},
		{"Large", 5000, 200, 60, 100, 120, 320},
		{"Small single", 50, 10, 2, 10, 5, 40},
		{"Medium single", 500, 10, 5, 40, 10, 60},
		{"Large 5", 5000, 15, 60, 100, 60, 180},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			manager, updateManager, accountID, _, err := setupTestAccountManager(b, bc.peers, bc.groups)
			if err != nil {
				b.Fatalf("Failed to setup test account manager: %v", err)
			}
			ctx := context.Background()
			account, err := manager.Store.GetAccount(ctx, accountID)
			if err != nil {
				b.Fatalf("Failed to get account: %v", err)
			}

			for peerID := range account.Peers {
				updateManager.CreateChannel(ctx, peerID)
			}

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				_, _, _, err := manager.LoginPeer(context.Background(), types.PeerLogin{
					WireGuardPubKey: account.Peers["peer-1"].Key,
					SSHKey:          "someKey",
					Meta:            nbpeer.PeerSystemMeta{Hostname: strconv.Itoa(i)},
					UserID:          "regular_user",
					SetupKey:        "",
					ConnectionIP:    net.IP{1, 1, 1, 1},
				})
				assert.NoError(b, err)
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")

			maxExpected := bc.maxMsPerOpLocal
			if os.Getenv("CI") == "true" {
				maxExpected = bc.maxMsPerOpCICD
				testing_tools.EvaluateBenchmarkResults(b, bc.name, time.Since(start), "login", "existingPeer")
			}

			if msPerOp > maxExpected {
				b.Logf("Benchmark %s: too slow (%.2f ms/op, max %.2f ms/op)", bc.name, msPerOp, maxExpected)
			}
		})
	}
}

func BenchmarkLoginPeer_NewPeer(b *testing.B) {
	b.Setenv("NB_GET_ACCOUNT_BUFFER_INTERVAL", "0")
	benchCases := []struct {
		name   string
		peers  int
		groups int
		// We need different expectations for CI/CD and local runs because of the different performance characteristics
		minMsPerOpLocal float64
		maxMsPerOpLocal float64
		minMsPerOpCICD  float64
		maxMsPerOpCICD  float64
	}{
		{"Small", 50, 5, 7, 20, 5, 80},
		{"Medium", 500, 100, 5, 40, 30, 140},
		{"Large", 5000, 200, 80, 120, 140, 390},
		{"Small single", 50, 10, 7, 20, 6, 80},
		{"Medium single", 500, 10, 5, 40, 15, 85},
		{"Large 5", 5000, 15, 80, 120, 80, 200},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			manager, updateManager, accountID, _, err := setupTestAccountManager(b, bc.peers, bc.groups)
			if err != nil {
				b.Fatalf("Failed to setup test account manager: %v", err)
			}
			ctx := context.Background()
			account, err := manager.Store.GetAccount(ctx, accountID)
			if err != nil {
				b.Fatalf("Failed to get account: %v", err)
			}

			for peerID := range account.Peers {
				updateManager.CreateChannel(ctx, peerID)
			}

			b.ResetTimer()
			start := time.Now()
			for i := 0; i < b.N; i++ {
				_, _, _, err := manager.LoginPeer(context.Background(), types.PeerLogin{
					WireGuardPubKey: "some-new-key" + strconv.Itoa(i),
					SSHKey:          "someKey",
					Meta:            nbpeer.PeerSystemMeta{Hostname: strconv.Itoa(i)},
					UserID:          "regular_user",
					SetupKey:        "",
					ConnectionIP:    net.IP{1, 1, 1, 1},
				})
				assert.NoError(b, err)
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")

			maxExpected := bc.maxMsPerOpLocal
			if os.Getenv("CI") == "true" {
				maxExpected = bc.maxMsPerOpCICD
				testing_tools.EvaluateBenchmarkResults(b, bc.name, time.Since(start), "login", "newPeer")
			}

			if msPerOp > maxExpected {
				b.Logf("Benchmark %s: too slow (%.2f ms/op, max %.2f ms/op)", bc.name, msPerOp, maxExpected)
			}
		})
	}
}

func TestMain(m *testing.M) {
	exitCode := m.Run()

	if exitCode == 0 && os.Getenv("CI") == "true" {
		runID := os.Getenv("GITHUB_RUN_ID")
		storeEngine := os.Getenv("NETBIRD_STORE_ENGINE")
		err := push.New("http://localhost:9091", "account_manager_benchmark").
			Collector(testing_tools.BenchmarkDuration).
			Grouping("ci_run", runID).
			Grouping("store_engine", storeEngine).
			Push()
		if err != nil {
			log.Printf("Failed to push metrics: %v", err)
		} else {
			time.Sleep(1 * time.Minute)
			_ = push.New("http://localhost:9091", "account_manager_benchmark").
				Grouping("ci_run", runID).
				Grouping("store_engine", storeEngine).
				Delete()
		}
	}

	os.Exit(exitCode)
}

func Test_GetCreateAccountByPrivateDomain(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	ctx := context.Background()
	initiatorId := "test-user"
	domain := "example.com"

	account, created, err := manager.GetOrCreateAccountByPrivateDomain(ctx, initiatorId, domain)
	assert.NoError(t, err)

	assert.True(t, created)
	assert.False(t, account.IsDomainPrimaryAccount)
	assert.Equal(t, domain, account.Domain)
	assert.Equal(t, types.PrivateCategory, account.DomainCategory)
	assert.Equal(t, initiatorId, account.CreatedBy)
	assert.Equal(t, 1, len(account.Groups))
	assert.Equal(t, 0, len(account.Users))
	assert.Equal(t, 0, len(account.SetupKeys))

	// should return a new account because the previous one is not primary
	account2, created2, err := manager.GetOrCreateAccountByPrivateDomain(ctx, initiatorId, domain)
	assert.NoError(t, err)

	assert.True(t, created2)
	assert.False(t, account2.IsDomainPrimaryAccount)
	assert.Equal(t, domain, account2.Domain)
	assert.Equal(t, types.PrivateCategory, account2.DomainCategory)
	assert.Equal(t, initiatorId, account2.CreatedBy)
	assert.Equal(t, 1, len(account2.Groups))
	assert.Equal(t, 0, len(account2.Users))
	assert.Equal(t, 0, len(account2.SetupKeys))

	err = manager.UpdateToPrimaryAccount(ctx, account.Id)
	assert.NoError(t, err)
	account, err = manager.Store.GetAccount(ctx, account.Id)
	assert.NoError(t, err)
	assert.True(t, account.IsDomainPrimaryAccount)

	err = manager.UpdateToPrimaryAccount(ctx, account2.Id)
	assert.Error(t, err, "should not be able to update a second account to primary")
}

func Test_UpdateToPrimaryAccount(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	ctx := context.Background()
	initiatorId := "test-user"
	domain := "example.com"

	account, created, err := manager.GetOrCreateAccountByPrivateDomain(ctx, initiatorId, domain)
	assert.NoError(t, err)
	assert.True(t, created)
	assert.False(t, account.IsDomainPrimaryAccount)
	assert.Equal(t, domain, account.Domain)

	err = manager.UpdateToPrimaryAccount(ctx, account.Id)
	assert.NoError(t, err)
	account, err = manager.Store.GetAccount(ctx, account.Id)
	assert.NoError(t, err)
	assert.True(t, account.IsDomainPrimaryAccount)

	account2, created2, err := manager.GetOrCreateAccountByPrivateDomain(ctx, initiatorId, domain)
	assert.NoError(t, err)
	assert.False(t, created2)
	assert.True(t, account.IsDomainPrimaryAccount)
	assert.Equal(t, account.Id, account2.Id)
}

func TestDefaultAccountManager_IsCacheCold(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	t.Run("memory cache", func(t *testing.T) {
		t.Run("should always return true", func(t *testing.T) {
			cacheStore, err := cache.NewStore(context.Background(), 100*time.Millisecond, 300*time.Millisecond, 100)
			require.NoError(t, err)

			cold, err := manager.isCacheCold(context.Background(), cacheStore)
			assert.NoError(t, err)
			assert.True(t, cold)
		})
	})

	t.Run("redis cache", func(t *testing.T) {
		cleanup, redisURL, err := testutil.CreateRedisTestContainer()
		require.NoError(t, err)
		t.Cleanup(cleanup)
		t.Setenv(cache.RedisStoreEnvVar, redisURL)

		cacheStore, err := cache.NewStore(context.Background(), 100*time.Millisecond, 300*time.Millisecond, 100)
		require.NoError(t, err)

		t.Run("should return true when no account exists", func(t *testing.T) {
			cold, err := manager.isCacheCold(context.Background(), cacheStore)
			assert.NoError(t, err)
			assert.True(t, cold)
		})

		account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID})
		require.NoError(t, err)

		t.Run("should return true when account is not found in cache", func(t *testing.T) {
			cold, err := manager.isCacheCold(context.Background(), cacheStore)
			assert.NoError(t, err)
			assert.True(t, cold)
		})

		t.Run("should return false when account is found in cache", func(t *testing.T) {
			err = cacheStore.Set(context.Background(), account.Id, &idp.UserData{ID: "v", Name: "vv"})
			require.NoError(t, err)

			cold, err := manager.isCacheCold(context.Background(), cacheStore)
			assert.NoError(t, err)
			assert.False(t, cold)
		})
	})
}

func TestPropagateUserGroupMemberships(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	ctx := context.Background()
	initiatorId := "test-user"
	domain := "example.com"

	account, err := manager.GetOrCreateAccountByUser(ctx, auth.UserAuth{UserId: initiatorId, Domain: domain})
	require.NoError(t, err)

	peer1 := &nbpeer.Peer{ID: "peer1", AccountID: account.Id, Key: "key1", UserID: initiatorId, IP: net.IP{1, 1, 1, 1}, DNSLabel: "peer1.domain.test"}
	err = manager.Store.AddPeerToAccount(ctx, peer1)
	require.NoError(t, err)

	peer2 := &nbpeer.Peer{ID: "peer2", AccountID: account.Id, Key: "key2", UserID: initiatorId, IP: net.IP{2, 2, 2, 2}, DNSLabel: "peer2.domain.test"}
	err = manager.Store.AddPeerToAccount(ctx, peer2)
	require.NoError(t, err)

	t.Run("should skip propagation when the user has no groups", func(t *testing.T) {
		groupsUpdated, groupChangesAffectPeers, err := propagateUserGroupMemberships(ctx, manager.Store, account.Id)
		require.NoError(t, err)
		assert.False(t, groupsUpdated)
		assert.False(t, groupChangesAffectPeers)
	})

	t.Run("should update membership but no account peers update for unused groups", func(t *testing.T) {
		group1 := &types.Group{ID: "group1", Name: "Group 1", AccountID: account.Id}
		require.NoError(t, manager.Store.CreateGroup(ctx, group1))

		user, err := manager.Store.GetUserByUserID(ctx, store.LockingStrengthNone, initiatorId)
		require.NoError(t, err)

		user.AutoGroups = append(user.AutoGroups, group1.ID)
		require.NoError(t, manager.Store.SaveUser(ctx, user))

		groupsUpdated, groupChangesAffectPeers, err := propagateUserGroupMemberships(ctx, manager.Store, account.Id)
		require.NoError(t, err)
		assert.True(t, groupsUpdated)
		assert.False(t, groupChangesAffectPeers)

		group, err := manager.Store.GetGroupByID(ctx, store.LockingStrengthNone, account.Id, group1.ID)
		require.NoError(t, err)
		assert.Len(t, group.Peers, 2)
		assert.Contains(t, group.Peers, "peer1")
		assert.Contains(t, group.Peers, "peer2")
	})

	t.Run("should update membership and account peers for used groups", func(t *testing.T) {
		group2 := &types.Group{ID: "group2", Name: "Group 2", AccountID: account.Id}
		require.NoError(t, manager.Store.CreateGroup(ctx, group2))

		user, err := manager.Store.GetUserByUserID(ctx, store.LockingStrengthNone, initiatorId)
		require.NoError(t, err)

		user.AutoGroups = append(user.AutoGroups, group2.ID)
		require.NoError(t, manager.Store.SaveUser(ctx, user))

		_, err = manager.SavePolicy(context.Background(), account.Id, initiatorId, &types.Policy{
			Name:      "Group1 Policy",
			AccountID: account.Id,
			Enabled:   true,
			Rules: []*types.PolicyRule{
				{
					Enabled:       true,
					Sources:       []string{"group1"},
					Destinations:  []string{"group2"},
					Bidirectional: true,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}, true)
		require.NoError(t, err)

		groupsUpdated, groupChangesAffectPeers, err := propagateUserGroupMemberships(ctx, manager.Store, account.Id)
		require.NoError(t, err)
		assert.True(t, groupsUpdated)
		assert.True(t, groupChangesAffectPeers)

		groups, err := manager.Store.GetGroupsByIDs(ctx, store.LockingStrengthNone, account.Id, []string{"group1", "group2"})
		require.NoError(t, err)
		for _, group := range groups {
			assert.Len(t, group.Peers, 2)
			assert.Contains(t, group.Peers, "peer1")
			assert.Contains(t, group.Peers, "peer2")
		}
	})

	t.Run("should not update membership or account peers when no changes", func(t *testing.T) {
		groupsUpdated, groupChangesAffectPeers, err := propagateUserGroupMemberships(ctx, manager.Store, account.Id)
		require.NoError(t, err)
		assert.False(t, groupsUpdated)
		assert.False(t, groupChangesAffectPeers)
	})

	t.Run("should not remove peers when groups are removed from user", func(t *testing.T) {
		user, err := manager.Store.GetUserByUserID(ctx, store.LockingStrengthNone, initiatorId)
		require.NoError(t, err)

		user.AutoGroups = []string{"group1"}
		require.NoError(t, manager.Store.SaveUser(ctx, user))

		groupsUpdated, groupChangesAffectPeers, err := propagateUserGroupMemberships(ctx, manager.Store, account.Id)
		require.NoError(t, err)
		assert.False(t, groupsUpdated)
		assert.False(t, groupChangesAffectPeers)

		groups, err := manager.Store.GetGroupsByIDs(ctx, store.LockingStrengthNone, account.Id, []string{"group1", "group2"})
		require.NoError(t, err)
		for _, group := range groups {
			assert.Len(t, group.Peers, 2)
			assert.Contains(t, group.Peers, "peer1")
			assert.Contains(t, group.Peers, "peer2")
		}
	})
}

func TestDefaultAccountManager_GetAccountOnboarding(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err)

	t.Run("should return account onboarding when onboarding exist", func(t *testing.T) {
		onboarding, err := manager.GetAccountOnboarding(context.Background(), account.Id, userID)
		require.NoError(t, err)
		require.NotNil(t, onboarding)
		assert.Equal(t, account.Id, onboarding.AccountID)
		assert.Equal(t, true, onboarding.OnboardingFlowPending)
		assert.Equal(t, true, onboarding.SignupFormPending)
		if onboarding.UpdatedAt.IsZero() {
			t.Errorf("Onboarding was not retrieved from the store")
		}
	})

	t.Run("should return account onboarding when onboard don't exist", func(t *testing.T) {
		account.Id = "with-zero-onboarding"
		account.Onboarding = types.AccountOnboarding{}
		err = manager.Store.SaveAccount(context.Background(), account)
		require.NoError(t, err)
		onboarding, err := manager.GetAccountOnboarding(context.Background(), account.Id, userID)
		require.NoError(t, err)
		require.NotNil(t, onboarding)
		_, err = manager.Store.GetAccountOnboarding(context.Background(), account.Id)
		require.Error(t, err, "should return error when onboarding is not set")
	})
}

func TestDefaultAccountManager_UpdateAccountOnboarding(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err)

	onboarding := &types.AccountOnboarding{
		OnboardingFlowPending: true,
		SignupFormPending:     true,
	}

	t.Run("update onboarding with no change", func(t *testing.T) {
		updated, err := manager.UpdateAccountOnboarding(context.Background(), account.Id, userID, onboarding)
		require.NoError(t, err)
		assert.Equal(t, onboarding.OnboardingFlowPending, updated.OnboardingFlowPending)
		assert.Equal(t, onboarding.SignupFormPending, updated.SignupFormPending)
		if updated.UpdatedAt.IsZero() {
			t.Errorf("Onboarding was updated in the store")
		}
	})

	onboarding.OnboardingFlowPending = false
	onboarding.SignupFormPending = false

	t.Run("update onboarding", func(t *testing.T) {
		updated, err := manager.UpdateAccountOnboarding(context.Background(), account.Id, userID, onboarding)
		require.NoError(t, err)
		require.NotNil(t, updated)
		assert.Equal(t, onboarding.OnboardingFlowPending, updated.OnboardingFlowPending)
		assert.Equal(t, onboarding.SignupFormPending, updated.SignupFormPending)
	})

	t.Run("update onboarding with no onboarding", func(t *testing.T) {
		_, err = manager.UpdateAccountOnboarding(context.Background(), account.Id, userID, nil)
		require.NoError(t, err)
	})
}

func TestDefaultAccountManager_UpdatePeerIP(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")

	accountID, err := manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err, "unable to create an account")

	key1, err := wgtypes.GenerateKey()
	require.NoError(t, err, "unable to generate WireGuard key")
	key2, err := wgtypes.GenerateKey()
	require.NoError(t, err, "unable to generate WireGuard key")

	peer1, _, _, err := manager.AddPeer(context.Background(), "", "", userID, &nbpeer.Peer{
		Key:  key1.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-1"},
	}, false)
	require.NoError(t, err, "unable to add peer1")

	peer2, _, _, err := manager.AddPeer(context.Background(), "", "", userID, &nbpeer.Peer{
		Key:  key2.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "test-peer-2"},
	}, false)
	require.NoError(t, err, "unable to add peer2")

	t.Run("update peer IP successfully", func(t *testing.T) {
		account, err := manager.Store.GetAccount(context.Background(), accountID)
		require.NoError(t, err, "unable to get account")

		newIP, err := types.AllocatePeerIP(account.Network.Net, []net.IP{peer1.IP, peer2.IP})
		require.NoError(t, err, "unable to allocate new IP")

		newAddr := netip.MustParseAddr(newIP.String())
		err = manager.UpdatePeerIP(context.Background(), accountID, userID, peer1.ID, newAddr)
		require.NoError(t, err, "unable to update peer IP")

		updatedPeer, err := manager.GetPeer(context.Background(), accountID, peer1.ID, userID)
		require.NoError(t, err, "unable to get updated peer")
		assert.Equal(t, newIP.String(), updatedPeer.IP.String(), "peer IP should be updated")
	})

	t.Run("update peer IP with same IP should be no-op", func(t *testing.T) {
		currentAddr := netip.MustParseAddr(peer1.IP.String())
		err := manager.UpdatePeerIP(context.Background(), accountID, userID, peer1.ID, currentAddr)
		require.NoError(t, err, "updating with same IP should not error")
	})

	t.Run("update peer IP with collision should fail", func(t *testing.T) {
		peer2Addr := netip.MustParseAddr(peer2.IP.String())
		err := manager.UpdatePeerIP(context.Background(), accountID, userID, peer1.ID, peer2Addr)
		require.Error(t, err, "should fail when IP is already assigned")
		assert.Contains(t, err.Error(), "already assigned", "error should mention IP collision")
	})

	t.Run("update peer IP outside network range should fail", func(t *testing.T) {
		invalidAddr := netip.MustParseAddr("192.168.1.100")
		err := manager.UpdatePeerIP(context.Background(), accountID, userID, peer1.ID, invalidAddr)
		require.Error(t, err, "should fail when IP is outside network range")
		assert.Contains(t, err.Error(), "not within the account network range", "error should mention network range")
	})

	t.Run("update peer IP with invalid peer ID should fail", func(t *testing.T) {
		newAddr := netip.MustParseAddr("100.64.0.101")
		err := manager.UpdatePeerIP(context.Background(), accountID, userID, "invalid-peer-id", newAddr)
		require.Error(t, err, "should fail with invalid peer ID")
	})
}

func TestAddNewUserToDomainAccountWithApproval(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	// Create a domain-based account with user approval enabled
	existingAccountID := "existing-account"
	account := newAccountWithId(context.Background(), existingAccountID, "owner-user", "example.com", "", "", false)
	account.Settings.Extra = &types.ExtraSettings{
		UserApprovalRequired: true,
	}
	err = manager.Store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	// Set the account as domain primary account
	account.IsDomainPrimaryAccount = true
	account.DomainCategory = types.PrivateCategory
	err = manager.Store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	// Test adding new user to existing account with approval required
	newUserID := "new-user-id"
	userAuth := auth.UserAuth{
		UserId:         newUserID,
		Domain:         "example.com",
		DomainCategory: types.PrivateCategory,
	}

	acc, err := manager.Store.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)
	require.True(t, acc.IsDomainPrimaryAccount, "Account should be primary for the domain")
	require.Equal(t, "example.com", acc.Domain, "Account domain should match")

	returnedAccountID, err := manager.getAccountIDWithAuthorizationClaims(context.Background(), userAuth)
	require.NoError(t, err)
	require.Equal(t, existingAccountID, returnedAccountID)

	// Verify user was created with pending approval
	user, err := manager.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, newUserID)
	require.NoError(t, err)
	assert.True(t, user.Blocked, "User should be blocked when approval is required")
	assert.True(t, user.PendingApproval, "User should be pending approval")
	assert.Equal(t, existingAccountID, user.AccountID)
}

func TestAddNewUserToDomainAccountWithoutApproval(t *testing.T) {
	manager, _, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	// Create a domain-based account without user approval
	ownerUserAuth := auth.UserAuth{
		UserId:         "owner-user",
		Domain:         "example.com",
		DomainCategory: types.PrivateCategory,
	}
	existingAccountID, err := manager.getAccountIDWithAuthorizationClaims(context.Background(), ownerUserAuth)
	require.NoError(t, err)

	// Modify the account to disable user approval
	account, err := manager.Store.GetAccount(context.Background(), existingAccountID)
	require.NoError(t, err)
	account.Settings.Extra = &types.ExtraSettings{
		UserApprovalRequired: false,
	}
	err = manager.Store.SaveAccount(context.Background(), account)
	require.NoError(t, err)

	// Test adding new user to existing account without approval required
	newUserID := "new-user-id"
	userAuth := auth.UserAuth{
		UserId:         newUserID,
		Domain:         "example.com",
		DomainCategory: types.PrivateCategory,
	}

	returnedAccountID, err := manager.getAccountIDWithAuthorizationClaims(context.Background(), userAuth)
	require.NoError(t, err)
	require.Equal(t, existingAccountID, returnedAccountID)

	// Verify user was created without pending approval
	user, err := manager.Store.GetUserByUserID(context.Background(), store.LockingStrengthNone, newUserID)
	require.NoError(t, err)
	assert.False(t, user.Blocked, "User should not be blocked when approval is not required")
	assert.False(t, user.PendingApproval, "User should not be pending approval")
	assert.Equal(t, existingAccountID, user.AccountID)
}
