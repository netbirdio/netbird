package server

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/route"
)

type MocIntegratedValidator struct {
}

func (a MocIntegratedValidator) ValidateExtraSettings(_ context.Context, newExtraSettings *account.ExtraSettings, oldExtraSettings *account.ExtraSettings, peers map[string]*nbpeer.Peer, userID string, accountID string) error {
	return nil
}

func (a MocIntegratedValidator) ValidatePeer(_ context.Context, update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *account.ExtraSettings) (*nbpeer.Peer, error) {
	return update, nil
}
func (a MocIntegratedValidator) GetValidatedPeers(accountID string, groups map[string]*group.Group, peers map[string]*nbpeer.Peer, extraSettings *account.ExtraSettings) (map[string]struct{}, error) {
	validatedPeers := make(map[string]struct{})
	for _, peer := range peers {
		validatedPeers[peer.ID] = struct{}{}
	}
	return validatedPeers, nil
}

func (MocIntegratedValidator) PreparePeer(_ context.Context, accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) *nbpeer.Peer {
	return peer
}

func (MocIntegratedValidator) IsNotValidPeer(_ context.Context, accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) (bool, bool, error) {
	return false, false, nil
}

func (MocIntegratedValidator) PeerDeleted(_ context.Context, _, _ string) error {
	return nil
}

func (MocIntegratedValidator) SetPeerInvalidationListener(func(accountID string)) {

}

func (MocIntegratedValidator) Stop(_ context.Context) {
}

func verifyCanAddPeerToAccount(t *testing.T, manager AccountManager, account *Account, userID string) {
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

	_, _, _, err := manager.AddPeer(context.Background(), setupKey, userID, peer)
	if err != nil {
		t.Error("expected to add new peer successfully after creating new account, but failed", err)
	}
}

func verifyNewAccountHasDefaultFields(t *testing.T, account *Account, createdBy string, domain string, expectedUsers []string) {
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
		accountSettings      Settings
		peerID               string
		expectedPeers        []string
		expectedOfflinePeers []string
		peers                map[string]*nbpeer.Peer
	}{
		{
			name:                 "Should return ALL peers when global peer login expiration disabled",
			accountSettings:      Settings{PeerLoginExpirationEnabled: false, PeerLoginExpiration: time.Hour},
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
					LastLogin: time.Now().UTC().Add(-time.Hour * 24 * 30 * 30),
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
					LastLogin:              time.Now().UTC(),
					LoginExpirationEnabled: true,
				},
			},
		},
		{
			name:                 "Should return no peers when global peer login expiration enabled and peers expired",
			accountSettings:      Settings{PeerLoginExpirationEnabled: true, PeerLoginExpiration: time.Hour},
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
					LastLogin:              time.Now().UTC().Add(-time.Hour * 24 * 30 * 30),
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
					LastLogin:              time.Now().UTC().Add(-time.Hour * 24 * 30 * 30),
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
	network := &Network{
		Identifier: "network",
		Net:        net.IPNet{IP: netIP, Mask: netMask},
		Dns:        "netbird.selfhosted",
		Serial:     0,
		mu:         sync.Mutex{},
	}

	for _, testCase := range tt {
		account := newAccountWithId(context.Background(), "account-1", userID, "netbird.io")
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
		networkMap := account.GetPeerNetworkMap(context.Background(), testCase.peerID, customZone, validatedPeers, nil)
		assert.Len(t, networkMap.Peers, len(testCase.expectedPeers))
		assert.Len(t, networkMap.OfflinePeers, len(testCase.expectedOfflinePeers))
	}
}

func TestNewAccount(t *testing.T) {
	domain := "netbird.io"
	userId := "account_creator"
	accountID := "account_id"
	account := newAccountWithId(context.Background(), accountID, userId, domain)
	verifyNewAccountHasDefaultFields(t, account, userId, domain, []string{userId})
}

func TestAccountManager_GetOrCreateAccountByUser(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	account, err := manager.GetOrCreateAccountByUser(context.Background(), userID, "")
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

func TestDefaultAccountManager_GetAccountFromToken(t *testing.T) {
	type initUserParams jwtclaims.AuthorizationClaims

	type test struct {
		name                        string
		inputClaims                 jwtclaims.AuthorizationClaims
		inputInitUserParams         initUserParams
		inputUpdateAttrs            bool
		inputUpdateClaimAccount     bool
		testingFunc                 require.ComparisonAssertionFunc
		expectedMSG                 string
		expectedUserRole            UserRole
		expectedDomainCategory      string
		expectedDomain              string
		expectedPrimaryDomainStatus bool
		expectedCreatedBy           string
		expectedUsers               []string
	}

	var (
		publicDomain  = "public.com"
		privateDomain = "private.com"
		unknownDomain = "unknown.com"
	)

	defaultInitAccount := initUserParams{
		Domain: publicDomain,
		UserId: "defaultUser",
	}

	testCase1 := test{
		name: "New User With Public Domain",
		inputClaims: jwtclaims.AuthorizationClaims{
			Domain:         publicDomain,
			UserId:         "pub-domain-user",
			DomainCategory: PublicCategory,
		},
		inputInitUserParams:         defaultInitAccount,
		testingFunc:                 require.NotEqual,
		expectedMSG:                 "account IDs shouldn't match",
		expectedUserRole:            UserRoleOwner,
		expectedDomainCategory:      "",
		expectedDomain:              publicDomain,
		expectedPrimaryDomainStatus: false,
		expectedCreatedBy:           "pub-domain-user",
		expectedUsers:               []string{"pub-domain-user"},
	}

	initUnknown := defaultInitAccount
	initUnknown.DomainCategory = UnknownCategory
	initUnknown.Domain = unknownDomain

	testCase2 := test{
		name: "New User With Unknown Domain",
		inputClaims: jwtclaims.AuthorizationClaims{
			Domain:         unknownDomain,
			UserId:         "unknown-domain-user",
			DomainCategory: UnknownCategory,
		},
		inputInitUserParams:         initUnknown,
		testingFunc:                 require.NotEqual,
		expectedMSG:                 "account IDs shouldn't match",
		expectedUserRole:            UserRoleOwner,
		expectedDomain:              unknownDomain,
		expectedDomainCategory:      "",
		expectedPrimaryDomainStatus: false,
		expectedCreatedBy:           "unknown-domain-user",
		expectedUsers:               []string{"unknown-domain-user"},
	}

	testCase3 := test{
		name: "New User With Private Domain",
		inputClaims: jwtclaims.AuthorizationClaims{
			Domain:         privateDomain,
			UserId:         "pvt-domain-user",
			DomainCategory: PrivateCategory,
		},
		inputInitUserParams:         defaultInitAccount,
		testingFunc:                 require.NotEqual,
		expectedMSG:                 "account IDs shouldn't match",
		expectedUserRole:            UserRoleOwner,
		expectedDomain:              privateDomain,
		expectedDomainCategory:      PrivateCategory,
		expectedPrimaryDomainStatus: true,
		expectedCreatedBy:           "pvt-domain-user",
		expectedUsers:               []string{"pvt-domain-user"},
	}

	privateInitAccount := defaultInitAccount
	privateInitAccount.Domain = privateDomain
	privateInitAccount.DomainCategory = PrivateCategory

	testCase4 := test{
		name: "New Regular User With Existing Private Domain",
		inputClaims: jwtclaims.AuthorizationClaims{
			Domain:         privateDomain,
			UserId:         "new-pvt-domain-user",
			DomainCategory: PrivateCategory,
		},
		inputUpdateAttrs:            true,
		inputInitUserParams:         privateInitAccount,
		testingFunc:                 require.Equal,
		expectedMSG:                 "account IDs should match",
		expectedUserRole:            UserRoleUser,
		expectedDomain:              privateDomain,
		expectedDomainCategory:      PrivateCategory,
		expectedPrimaryDomainStatus: true,
		expectedCreatedBy:           defaultInitAccount.UserId,
		expectedUsers:               []string{defaultInitAccount.UserId, "new-pvt-domain-user"},
	}

	testCase5 := test{
		name: "Existing User With Existing Reclassified Private Domain",
		inputClaims: jwtclaims.AuthorizationClaims{
			Domain:         defaultInitAccount.Domain,
			UserId:         defaultInitAccount.UserId,
			DomainCategory: PrivateCategory,
		},
		inputInitUserParams:         defaultInitAccount,
		testingFunc:                 require.Equal,
		expectedMSG:                 "account IDs should match",
		expectedUserRole:            UserRoleOwner,
		expectedDomain:              defaultInitAccount.Domain,
		expectedDomainCategory:      PrivateCategory,
		expectedPrimaryDomainStatus: true,
		expectedCreatedBy:           defaultInitAccount.UserId,
		expectedUsers:               []string{defaultInitAccount.UserId},
	}

	testCase6 := test{
		name: "Existing Account Id With Existing Reclassified Private Domain",
		inputClaims: jwtclaims.AuthorizationClaims{
			Domain:         defaultInitAccount.Domain,
			UserId:         defaultInitAccount.UserId,
			DomainCategory: PrivateCategory,
		},
		inputUpdateClaimAccount:     true,
		inputInitUserParams:         defaultInitAccount,
		testingFunc:                 require.Equal,
		expectedMSG:                 "account IDs should match",
		expectedUserRole:            UserRoleOwner,
		expectedDomain:              defaultInitAccount.Domain,
		expectedDomainCategory:      PrivateCategory,
		expectedPrimaryDomainStatus: true,
		expectedCreatedBy:           defaultInitAccount.UserId,
		expectedUsers:               []string{defaultInitAccount.UserId},
	}

	testCase7 := test{
		name: "User With Private Category And Empty Domain",
		inputClaims: jwtclaims.AuthorizationClaims{
			Domain:         "",
			UserId:         "pvt-domain-user",
			DomainCategory: PrivateCategory,
		},
		inputInitUserParams:         defaultInitAccount,
		testingFunc:                 require.NotEqual,
		expectedMSG:                 "account IDs shouldn't match",
		expectedUserRole:            UserRoleOwner,
		expectedDomain:              "",
		expectedDomainCategory:      "",
		expectedPrimaryDomainStatus: false,
		expectedCreatedBy:           "pvt-domain-user",
		expectedUsers:               []string{"pvt-domain-user"},
	}

	for _, testCase := range []test{testCase1, testCase2, testCase3, testCase4, testCase5, testCase6, testCase7} {
		t.Run(testCase.name, func(t *testing.T) {
			manager, err := createManager(t)
			require.NoError(t, err, "unable to create account manager")

			initAccount, err := manager.GetAccountByUserOrAccountID(context.Background(), testCase.inputInitUserParams.UserId, testCase.inputInitUserParams.AccountId, testCase.inputInitUserParams.Domain)
			require.NoError(t, err, "create init user failed")

			if testCase.inputUpdateAttrs {
				err = manager.updateAccountDomainAttributes(context.Background(), initAccount, jwtclaims.AuthorizationClaims{UserId: testCase.inputInitUserParams.UserId, Domain: testCase.inputInitUserParams.Domain, DomainCategory: testCase.inputInitUserParams.DomainCategory}, true)
				require.NoError(t, err, "update init user failed")
			}

			if testCase.inputUpdateClaimAccount {
				testCase.inputClaims.AccountId = initAccount.Id
			}

			account, _, err := manager.GetAccountFromToken(context.Background(), testCase.inputClaims)
			require.NoError(t, err, "support function failed")
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

func TestDefaultAccountManager_GetGroupsFromTheToken(t *testing.T) {
	userId := "user-id"
	domain := "test.domain"

	initAccount := newAccountWithId(context.Background(), "", userId, domain)
	manager, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")

	accountID := initAccount.Id
	acc, err := manager.GetAccountByUserOrAccountID(context.Background(), userId, accountID, domain)
	require.NoError(t, err, "create init user failed")
	// as initAccount was created without account id we have to take the id after account initialization
	// that happens inside the GetAccountByUserOrAccountID where the id is getting generated
	// it is important to set the id as it help to avoid creating additional account with empty Id and re-pointing indices to it
	initAccount = acc

	claims := jwtclaims.AuthorizationClaims{
		AccountId:      accountID, // is empty as it is based on accountID right after initialization of initAccount
		Domain:         domain,
		UserId:         userId,
		DomainCategory: "test-category",
		Raw:            jwt.MapClaims{"idp-groups": []interface{}{"group1", "group2"}},
	}

	t.Run("JWT groups disabled", func(t *testing.T) {
		account, _, err := manager.GetAccountFromToken(context.Background(), claims)
		require.NoError(t, err, "get account by token failed")
		require.Len(t, account.Groups, 1, "only ALL group should exists")
	})

	t.Run("JWT groups enabled without claim name", func(t *testing.T) {
		initAccount.Settings.JWTGroupsEnabled = true
		err := manager.Store.SaveAccount(context.Background(), initAccount)
		require.NoError(t, err, "save account failed")
		require.Len(t, manager.Store.GetAllAccounts(context.Background()), 1, "only one account should exist")

		account, _, err := manager.GetAccountFromToken(context.Background(), claims)
		require.NoError(t, err, "get account by token failed")
		require.Len(t, account.Groups, 1, "if group claim is not set no group added from JWT")
	})

	t.Run("JWT groups enabled", func(t *testing.T) {
		initAccount.Settings.JWTGroupsEnabled = true
		initAccount.Settings.JWTGroupsClaimName = "idp-groups"
		err := manager.Store.SaveAccount(context.Background(), initAccount)
		require.NoError(t, err, "save account failed")
		require.Len(t, manager.Store.GetAllAccounts(context.Background()), 1, "only one account should exist")

		account, _, err := manager.GetAccountFromToken(context.Background(), claims)
		require.NoError(t, err, "get account by token failed")
		require.Len(t, account.Groups, 3, "groups should be added to the account")

		groupsByNames := map[string]*group.Group{}
		for _, g := range account.Groups {
			groupsByNames[g.Name] = g
		}

		g1, ok := groupsByNames["group1"]
		require.True(t, ok, "group1 should be added to the account")
		require.Equal(t, g1.Name, "group1", "group1 name should match")
		require.Equal(t, g1.Issued, group.GroupIssuedJWT, "group1 issued should match")

		g2, ok := groupsByNames["group2"]
		require.True(t, ok, "group2 should be added to the account")
		require.Equal(t, g2.Name, "group2", "group2 name should match")
		require.Equal(t, g2.Issued, group.GroupIssuedJWT, "group2 issued should match")
	})
}

func TestAccountManager_GetAccountFromPAT(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(context.Background(), "account_id", "testuser", "")

	token := "nbp_9999EUDNdkeusjentDLSJEn1902u84390W6W"
	hashedToken := sha256.Sum256([]byte(token))
	encodedHashedToken := b64.StdEncoding.EncodeToString(hashedToken[:])
	account.Users["someUser"] = &User{
		Id: "someUser",
		PATs: map[string]*PersonalAccessToken{
			"tokenId": {
				ID:          "tokenId",
				HashedToken: encodedHashedToken,
			},
		},
	}
	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store: store,
	}

	account, user, pat, err := am.GetAccountFromPAT(context.Background(), token)
	if err != nil {
		t.Fatalf("Error when getting Account from PAT: %s", err)
	}

	assert.Equal(t, "account_id", account.Id)
	assert.Equal(t, "someUser", user.Id)
	assert.Equal(t, account.Users["someUser"].PATs["tokenId"], pat)
}

func TestDefaultAccountManager_MarkPATUsed(t *testing.T) {
	store := newStore(t)
	account := newAccountWithId(context.Background(), "account_id", "testuser", "")

	token := "nbp_9999EUDNdkeusjentDLSJEn1902u84390W6W"
	hashedToken := sha256.Sum256([]byte(token))
	encodedHashedToken := b64.StdEncoding.EncodeToString(hashedToken[:])
	account.Users["someUser"] = &User{
		Id: "someUser",
		PATs: map[string]*PersonalAccessToken{
			"tokenId": {
				ID:          "tokenId",
				HashedToken: encodedHashedToken,
				LastUsed:    time.Time{},
			},
		},
	}
	err := store.SaveAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("Error when saving account: %s", err)
	}

	am := DefaultAccountManager{
		Store: store,
	}

	err = am.MarkPATUsed(context.Background(), "tokenId")
	if err != nil {
		t.Fatalf("Error when marking PAT used: %s", err)
	}

	account, err = am.Store.GetAccount(context.Background(), "account_id")
	if err != nil {
		t.Fatalf("Error when getting account: %s", err)
	}
	assert.True(t, !account.Users["someUser"].PATs["tokenId"].LastUsed.IsZero())
}

func TestAccountManager_PrivateAccount(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userId := "test_user"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), userId, "")
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
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userId := "test_user"
	domain := "hotmail.com"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), userId, domain)
	if err != nil {
		t.Fatal(err)
	}
	if account == nil {
		t.Fatalf("expected to create an account for a user %s", userId)
	}

	if account != nil && account.Domain != domain {
		t.Errorf("setting account domain failed, expected %s, got %s", domain, account.Domain)
	}

	domain = "gmail.com"

	account, err = manager.GetOrCreateAccountByUser(context.Background(), userId, domain)
	if err != nil {
		t.Fatalf("got the following error while retrieving existing acc: %v", err)
	}

	if account == nil {
		t.Fatalf("expected to get an account for a user %s", userId)
	}

	if account != nil && account.Domain != domain {
		t.Errorf("updating domain. expected %s got %s", domain, account.Domain)
	}
}

func TestAccountManager_GetAccountByUserOrAccountId(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userId := "test_user"

	account, err := manager.GetAccountByUserOrAccountID(context.Background(), userId, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if account == nil {
		t.Fatalf("expected to create an account for a user %s", userId)
		return
	}

	_, err = manager.GetAccountByUserOrAccountID(context.Background(), "", account.Id, "")
	if err != nil {
		t.Errorf("expected to get existing account after creation using userid, no account was found for a account %s", account.Id)
	}

	_, err = manager.GetAccountByUserOrAccountID(context.Background(), "", "", "")
	if err == nil {
		t.Errorf("expected an error when user and account IDs are empty")
	}
}

func createAccount(am *DefaultAccountManager, accountID, userID, domain string) (*Account, error) {
	account := newAccountWithId(context.Background(), accountID, userID, domain)
	err := am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		return nil, err
	}
	return account, nil
}

func TestAccountManager_GetAccount(t *testing.T) {
	manager, err := createManager(t)
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
	manager, err := createManager(t)
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

	err = manager.DeleteAccount(context.Background(), account.Id, userId)
	if err != nil {
		t.Fatal(err)
	}

	getAccount, err := manager.Store.GetAccount(context.Background(), account.Id)
	if err == nil {
		t.Fatal(fmt.Errorf("expected to get an error when trying to get deleted account, got %v", getAccount))
	}
}

func TestAccountManager_AddPeer(t *testing.T) {
	manager, err := createManager(t)
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

	setupKey, err := manager.CreateSetupKey(context.Background(), account.Id, "test-key", SetupKeyReusable, time.Hour, nil, 999, userID, false)
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
	expectedSetupKey := setupKey.Key

	peer, _, _, err := manager.AddPeer(context.Background(), setupKey.Key, "", &nbpeer.Peer{
		Key:  expectedPeerKey,
		Meta: nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
	})
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

	if peer.SetupKey != expectedSetupKey {
		t.Errorf("expecting just added peer to have SetupKey = %s, got %s", expectedSetupKey, peer.SetupKey)
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
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	account, err := manager.GetOrCreateAccountByUser(context.Background(), userID, "netbird.cloud")
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

	peer, _, _, err := manager.AddPeer(context.Background(), "", userID, &nbpeer.Peer{
		Key:  expectedPeerKey,
		Meta: nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
	})
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

func TestAccountManager_NetworkUpdates(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userID := "account_creator"

	account, err := createAccount(manager, "test_account", userID, "")
	if err != nil {
		t.Fatal(err)
	}

	setupKey, err := manager.CreateSetupKey(context.Background(), account.Id, "test-key", SetupKeyReusable, time.Hour, nil, 999, userID, false)
	if err != nil {
		t.Fatal("error creating setup key")
		return
	}

	if account.Network.Serial != 0 {
		t.Errorf("expecting account network to have an initial Serial=0")
		return
	}

	getPeer := func() *nbpeer.Peer {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
			return nil
		}
		expectedPeerKey := key.PublicKey().String()

		peer, _, _, err := manager.AddPeer(context.Background(), setupKey.Key, "", &nbpeer.Peer{
			Key:  expectedPeerKey,
			Meta: nbpeer.PeerSystemMeta{Hostname: expectedPeerKey},
		})
		if err != nil {
			t.Fatalf("expecting peer1 to be added, got failure %v", err)
			return nil
		}

		return peer
	}

	peer1 := getPeer()
	peer2 := getPeer()
	peer3 := getPeer()

	account, err = manager.Store.GetAccount(context.Background(), account.Id)
	if err != nil {
		t.Fatal(err)
		return
	}

	updMsg := manager.peersUpdateManager.CreateChannel(context.Background(), peer1.ID)
	defer manager.peersUpdateManager.CloseChannel(context.Background(), peer1.ID)

	group := group.Group{
		ID:    "group-id",
		Name:  "GroupA",
		Peers: []string{peer1.ID, peer2.ID, peer3.ID},
	}

	policy := Policy{
		Enabled: true,
		Rules: []*PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"group-id"},
				Destinations:  []string{"group-id"},
				Bidirectional: true,
				Action:        PolicyTrafficActionAccept,
			},
		},
	}

	wg := sync.WaitGroup{}
	t.Run("save group update", func(t *testing.T) {
		wg.Add(1)
		go func() {
			defer wg.Done()

			message := <-updMsg
			networkMap := message.Update.GetNetworkMap()
			if len(networkMap.RemotePeers) != 2 {
				t.Errorf("mismatch peers count: 2 expected, got %v", len(networkMap.RemotePeers))
			}
		}()

		if err := manager.SaveGroup(context.Background(), account.Id, userID, &group); err != nil {
			t.Errorf("save group: %v", err)
			return
		}

		wg.Wait()
	})

	t.Run("delete policy update", func(t *testing.T) {
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
	})

	t.Run("save policy update", func(t *testing.T) {
		wg.Add(1)
		go func() {
			defer wg.Done()

			message := <-updMsg
			networkMap := message.Update.GetNetworkMap()
			if len(networkMap.RemotePeers) != 2 {
				t.Errorf("mismatch peers count: 2 expected, got %v", len(networkMap.RemotePeers))
			}
		}()

		if err := manager.SavePolicy(context.Background(), account.Id, userID, &policy); err != nil {
			t.Errorf("delete default rule: %v", err)
			return
		}

		wg.Wait()
	})
	t.Run("delete peer update", func(t *testing.T) {
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
	})

	t.Run("delete group update", func(t *testing.T) {
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
		_ = manager.DeletePolicy(context.Background(), account.Id, policy.ID, userID)

		if err := manager.DeleteGroup(context.Background(), account.Id, "", group.ID); err != nil {
			t.Errorf("delete group: %v", err)
			return
		}

		wg.Wait()
	})
}

func TestAccountManager_DeletePeer(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userID := "account_creator"
	account, err := createAccount(manager, "test_account", userID, "netbird.cloud")
	if err != nil {
		t.Fatal(err)
	}

	setupKey, err := manager.CreateSetupKey(context.Background(), account.Id, "test-key", SetupKeyReusable, time.Hour, nil, 999, userID, false)
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

	peer, _, _, err := manager.AddPeer(context.Background(), setupKey.Key, "", &nbpeer.Peer{
		Key:  peerKey,
		Meta: nbpeer.PeerSystemMeta{Hostname: peerKey},
	})
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	err = manager.DeletePeer(context.Background(), account.Id, peerKey, userID)
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
	assert.Equal(t, peer.IP.String(), ev.TargetID)
	assert.Equal(t, peer.IP.String(), fmt.Sprint(ev.Meta["ip"]))
}

func getEvent(t *testing.T, accountID string, manager AccountManager, eventType activity.Activity) *activity.Event {
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
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	users := map[string]*User{"1": {Id: "1", Role: UserRoleOwner}, "2": {Id: "2", Role: "user"}, "3": {Id: "3", Role: "user"}}
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
	account := &Account{
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
	account := &Account{
		Peers: map[string]*nbpeer.Peer{
			"peer-1": {Key: "peer-1", Meta: nbpeer.PeerSystemMeta{GoOS: "linux"}}, "peer-2": {Key: "peer-2", Meta: nbpeer.PeerSystemMeta{GoOS: "linux"}}, "peer-3": {Key: "peer-1", Meta: nbpeer.PeerSystemMeta{GoOS: "linux"}},
		},
		Groups: map[string]*group.Group{"group1": {ID: "group1", Peers: []string{"peer-1", "peer-2"}}},
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

	routes := account.getRoutesToSync(context.Background(), "peer-2", []*nbpeer.Peer{{Key: "peer-1"}, {Key: "peer-3"}})

	assert.Len(t, routes, 2)
	routeIDs := make(map[route.ID]struct{}, 2)
	for _, r := range routes {
		routeIDs[r.ID] = struct{}{}
	}
	assert.Contains(t, routeIDs, route.ID("route-2"))
	assert.Contains(t, routeIDs, route.ID("route-3"))

	emptyRoutes := account.getRoutesToSync(context.Background(), "peer-3", []*nbpeer.Peer{{Key: "peer-1"}, {Key: "peer-2"}})

	assert.Len(t, emptyRoutes, 0)
}

func TestAccount_Copy(t *testing.T) {
	account := &Account{
		Id:                     "account1",
		CreatedBy:              "tester",
		CreatedAt:              time.Now().UTC(),
		Domain:                 "test.com",
		DomainCategory:         "public",
		IsDomainPrimaryAccount: true,
		SetupKeys: map[string]*SetupKey{
			"setup1": {
				Id:         "setup1",
				AutoGroups: []string{"group1"},
			},
		},
		Network: &Network{
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
		Users: map[string]*User{
			"user1": {
				Id:         "user1",
				Role:       UserRoleAdmin,
				AutoGroups: []string{"group1"},
				PATs: map[string]*PersonalAccessToken{
					"pat1": {
						ID:             "pat1",
						Name:           "First PAT",
						HashedToken:    "SoMeHaShEdToKeN",
						ExpirationDate: time.Now().UTC().AddDate(0, 0, 7),
						CreatedBy:      "user1",
						CreatedAt:      time.Now().UTC(),
						LastUsed:       time.Now().UTC(),
					},
				},
			},
		},
		Groups: map[string]*group.Group{
			"group1": {
				ID:    "group1",
				Peers: []string{"peer1"},
			},
		},
		Policies: []*Policy{
			{
				ID:                  "policy1",
				Enabled:             true,
				Rules:               make([]*PolicyRule, 0),
				SourcePostureChecks: make([]string, 0),
			},
		},
		Routes: map[route.ID]*route.Route{
			"route1": {
				ID:         "route1",
				PeerGroups: []string{},
				Groups:     []string{"group1"},
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
		DNSSettings: DNSSettings{DisabledManagementGroups: []string{}},
		PostureChecks: []*posture.Checks{
			{
				ID: "posture Checks1",
			},
		},
		Settings: &Settings{},
	}
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
	manager, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")

	account, err := manager.GetAccountByUserOrAccountID(context.Background(), userID, "", "")
	require.NoError(t, err, "unable to create an account")

	assert.NotNil(t, account.Settings)
	assert.Equal(t, account.Settings.PeerLoginExpirationEnabled, true)
	assert.Equal(t, account.Settings.PeerLoginExpiration, 24*time.Hour)
}

func TestDefaultAccountManager_UpdatePeer_PeerLoginExpiration(t *testing.T) {
	manager, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")

	_, err = manager.GetAccountByUserOrAccountID(context.Background(), userID, "", "")
	require.NoError(t, err, "unable to create an account")

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err, "unable to generate WireGuard key")
	peer, _, _, err := manager.AddPeer(context.Background(), "", userID, &nbpeer.Peer{
		Key:                    key.PublicKey().String(),
		Meta:                   nbpeer.PeerSystemMeta{Hostname: "test-peer"},
		LoginExpirationEnabled: true,
	})
	require.NoError(t, err, "unable to add peer")

	account, err := manager.GetAccountByUserOrAccountID(context.Background(), userID, "", "")
	require.NoError(t, err, "unable to get the account")
	err = manager.MarkPeerConnected(context.Background(), key.PublicKey().String(), true, nil, account)
	require.NoError(t, err, "unable to mark peer connected")
	account, err = manager.UpdateAccountSettings(context.Background(), account.Id, userID, &Settings{
		PeerLoginExpiration:        time.Hour,
		PeerLoginExpirationEnabled: true,
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
	_, err = manager.UpdatePeer(context.Background(), account.Id, userID, update)
	require.NoError(t, err, "unable to update peer")
	// enabling expiration should trigger the routine
	update.LoginExpirationEnabled = true
	_, err = manager.UpdatePeer(context.Background(), account.Id, userID, update)
	require.NoError(t, err, "unable to update peer")

	failed := waitTimeout(wg, time.Second)
	if failed {
		t.Fatal("timeout while waiting for test to finish")
	}
}

func TestDefaultAccountManager_MarkPeerConnected_PeerLoginExpiration(t *testing.T) {
	manager, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")

	account, err := manager.GetAccountByUserOrAccountID(context.Background(), userID, "", "")
	require.NoError(t, err, "unable to create an account")

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err, "unable to generate WireGuard key")
	_, _, _, err = manager.AddPeer(context.Background(), "", userID, &nbpeer.Peer{
		Key:                    key.PublicKey().String(),
		Meta:                   nbpeer.PeerSystemMeta{Hostname: "test-peer"},
		LoginExpirationEnabled: true,
	})
	require.NoError(t, err, "unable to add peer")
	_, err = manager.UpdateAccountSettings(context.Background(), account.Id, userID, &Settings{
		PeerLoginExpiration:        time.Hour,
		PeerLoginExpirationEnabled: true,
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

	account, err = manager.GetAccountByUserOrAccountID(context.Background(), userID, "", "")
	require.NoError(t, err, "unable to get the account")
	// when we mark peer as connected, the peer login expiration routine should trigger
	err = manager.MarkPeerConnected(context.Background(), key.PublicKey().String(), true, nil, account)
	require.NoError(t, err, "unable to mark peer connected")

	failed := waitTimeout(wg, time.Second)
	if failed {
		t.Fatal("timeout while waiting for test to finish")
	}
}

func TestDefaultAccountManager_UpdateAccountSettings_PeerLoginExpiration(t *testing.T) {
	manager, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")

	_, err = manager.GetAccountByUserOrAccountID(context.Background(), userID, "", "")
	require.NoError(t, err, "unable to create an account")

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err, "unable to generate WireGuard key")
	_, _, _, err = manager.AddPeer(context.Background(), "", userID, &nbpeer.Peer{
		Key:                    key.PublicKey().String(),
		Meta:                   nbpeer.PeerSystemMeta{Hostname: "test-peer"},
		LoginExpirationEnabled: true,
	})
	require.NoError(t, err, "unable to add peer")

	account, err := manager.GetAccountByUserOrAccountID(context.Background(), userID, "", "")
	require.NoError(t, err, "unable to get the account")
	err = manager.MarkPeerConnected(context.Background(), key.PublicKey().String(), true, nil, account)
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
	account, err = manager.UpdateAccountSettings(context.Background(), account.Id, userID, &Settings{
		PeerLoginExpiration:        time.Hour,
		PeerLoginExpirationEnabled: true,
	})
	require.NoError(t, err, "expecting to update account settings successfully but got error")

	failed := waitTimeout(wg, time.Second)
	if failed {
		t.Fatal("timeout while waiting for test to finish")
	}
	wg.Add(1)

	// disabling PeerLoginExpirationEnabled should trigger cancel
	_, err = manager.UpdateAccountSettings(context.Background(), account.Id, userID, &Settings{
		PeerLoginExpiration:        time.Hour,
		PeerLoginExpirationEnabled: false,
	})
	require.NoError(t, err, "expecting to update account settings successfully but got error")
	failed = waitTimeout(wg, time.Second)
	if failed {
		t.Fatal("timeout while waiting for test to finish")
	}
}

func TestDefaultAccountManager_UpdateAccountSettings(t *testing.T) {
	manager, err := createManager(t)
	require.NoError(t, err, "unable to create account manager")

	account, err := manager.GetAccountByUserOrAccountID(context.Background(), userID, "", "")
	require.NoError(t, err, "unable to create an account")

	updated, err := manager.UpdateAccountSettings(context.Background(), account.Id, userID, &Settings{
		PeerLoginExpiration:        time.Hour,
		PeerLoginExpirationEnabled: false,
	})
	require.NoError(t, err, "expecting to update account settings successfully but got error")
	assert.False(t, updated.Settings.PeerLoginExpirationEnabled)
	assert.Equal(t, updated.Settings.PeerLoginExpiration, time.Hour)

	account, err = manager.GetAccountByUserOrAccountID(context.Background(), "", account.Id, "")
	require.NoError(t, err, "unable to get account by ID")

	assert.False(t, account.Settings.PeerLoginExpirationEnabled)
	assert.Equal(t, account.Settings.PeerLoginExpiration, time.Hour)

	_, err = manager.UpdateAccountSettings(context.Background(), account.Id, userID, &Settings{
		PeerLoginExpiration:        time.Second,
		PeerLoginExpirationEnabled: false,
	})
	require.Error(t, err, "expecting to fail when providing PeerLoginExpiration less than one hour")

	_, err = manager.UpdateAccountSettings(context.Background(), account.Id, userID, &Settings{
		PeerLoginExpiration:        time.Hour * 24 * 181,
		PeerLoginExpirationEnabled: false,
	})
	require.Error(t, err, "expecting to fail when providing PeerLoginExpiration more than 180 days")
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
					LastLogin: time.Now().UTC().Add(-30 * time.Minute),
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
					LastLogin: time.Now().UTC().Add(-2 * time.Hour),
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
					LastLogin: time.Now().UTC().Add(-1 * time.Hour),
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
			account := &Account{
				Peers: testCase.peers,
				Settings: &Settings{
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
					LastLogin: time.Now().UTC().Add(-30 * time.Minute),
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
					LastLogin: time.Now().UTC().Add(-2 * time.Hour),
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
					LastLogin: time.Now().UTC().Add(-1 * time.Hour),
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
			account := &Account{
				Peers: testCase.peers,
				Settings: &Settings{
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
			account := &Account{
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
			account := &Account{
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
					LastLogin:              time.Now().UTC(),
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
					SetupKey:               "key",
				},
				"peer-2": {
					Status: &nbpeer.PeerStatus{
						Connected:    true,
						LoginExpired: false,
					},
					LoginExpirationEnabled: true,
					SetupKey:               "key",
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
			account := &Account{
				Peers:    testCase.peers,
				Settings: &Settings{PeerLoginExpiration: testCase.expiration, PeerLoginExpirationEnabled: testCase.expirationEnabled},
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
					LastLogin:                   time.Now().UTC(),
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
					SetupKey:                    "key",
				},
				"peer-2": {
					Status: &nbpeer.PeerStatus{
						Connected:    true,
						LoginExpired: false,
					},
					InactivityExpirationEnabled: true,
					SetupKey:                    "key",
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
			account := &Account{
				Peers:    testCase.peers,
				Settings: &Settings{PeerInactivityExpiration: testCase.expiration, PeerInactivityExpirationEnabled: testCase.expirationEnabled},
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
	// create a new account
	account := &Account{
		Peers: map[string]*nbpeer.Peer{
			"peer1": {ID: "peer1", Key: "key1", UserID: "user1"},
			"peer2": {ID: "peer2", Key: "key2", UserID: "user1"},
			"peer3": {ID: "peer3", Key: "key3", UserID: "user1"},
			"peer4": {ID: "peer4", Key: "key4", UserID: "user2"},
			"peer5": {ID: "peer5", Key: "key5", UserID: "user2"},
		},
		Groups: map[string]*group.Group{
			"group1": {ID: "group1", Name: "group1", Issued: group.GroupIssuedAPI, Peers: []string{}},
		},
		Settings: &Settings{GroupsPropagationEnabled: true},
		Users: map[string]*User{
			"user1": {Id: "user1"},
			"user2": {Id: "user2"},
		},
	}

	t.Run("empty jwt groups", func(t *testing.T) {
		updated := account.SetJWTGroups("user1", []string{})
		assert.False(t, updated, "account should not be updated")
		assert.Empty(t, account.Users["user1"].AutoGroups, "auto groups must be empty")
	})

	t.Run("jwt match existing api group", func(t *testing.T) {
		updated := account.SetJWTGroups("user1", []string{"group1"})
		assert.False(t, updated, "account should not be updated")
		assert.Equal(t, 0, len(account.Users["user1"].AutoGroups))
		assert.Equal(t, account.Groups["group1"].Issued, group.GroupIssuedAPI, "group should be api issued")
	})

	t.Run("jwt match existing api group in user auto groups", func(t *testing.T) {
		account.Users["user1"].AutoGroups = []string{"group1"}

		updated := account.SetJWTGroups("user1", []string{"group1"})
		assert.False(t, updated, "account should not be updated")
		assert.Equal(t, 1, len(account.Users["user1"].AutoGroups))
		assert.Equal(t, account.Groups["group1"].Issued, group.GroupIssuedAPI, "group should be api issued")
	})

	t.Run("add jwt group", func(t *testing.T) {
		updated := account.SetJWTGroups("user1", []string{"group1", "group2"})
		assert.True(t, updated, "account should be updated")
		assert.Len(t, account.Groups, 2, "new group should be added")
		assert.Len(t, account.Users["user1"].AutoGroups, 2, "new group should be added")
		assert.Contains(t, account.Groups, account.Users["user1"].AutoGroups[0], "groups must contain group2 from user groups")
	})

	t.Run("existed group not update", func(t *testing.T) {
		updated := account.SetJWTGroups("user1", []string{"group2"})
		assert.False(t, updated, "account should not be updated")
		assert.Len(t, account.Groups, 2, "groups count should not be changed")
	})

	t.Run("add new group", func(t *testing.T) {
		updated := account.SetJWTGroups("user2", []string{"group1", "group3"})
		assert.True(t, updated, "account should be updated")
		assert.Len(t, account.Groups, 3, "new group should be added")
		assert.Len(t, account.Users["user2"].AutoGroups, 1, "new group should be added")
		assert.Contains(t, account.Groups, account.Users["user2"].AutoGroups[0], "groups must contain group3 from user groups")
	})

	t.Run("remove all JWT groups", func(t *testing.T) {
		updated := account.SetJWTGroups("user1", []string{})
		assert.True(t, updated, "account should be updated")
		assert.Len(t, account.Users["user1"].AutoGroups, 1, "only non-JWT groups should remain")
		assert.Contains(t, account.Users["user1"].AutoGroups, "group1", " group1 should still be present")
	})
}

func TestAccount_UserGroupsAddToPeers(t *testing.T) {
	account := &Account{
		Peers: map[string]*nbpeer.Peer{
			"peer1": {ID: "peer1", Key: "key1", UserID: "user1"},
			"peer2": {ID: "peer2", Key: "key2", UserID: "user1"},
			"peer3": {ID: "peer3", Key: "key3", UserID: "user1"},
			"peer4": {ID: "peer4", Key: "key4", UserID: "user2"},
			"peer5": {ID: "peer5", Key: "key5", UserID: "user2"},
		},
		Groups: map[string]*group.Group{
			"group1": {ID: "group1", Name: "group1", Issued: group.GroupIssuedAPI, Peers: []string{}},
			"group2": {ID: "group2", Name: "group2", Issued: group.GroupIssuedAPI, Peers: []string{}},
			"group3": {ID: "group3", Name: "group3", Issued: group.GroupIssuedAPI, Peers: []string{}},
		},
		Users: map[string]*User{"user1": {Id: "user1"}, "user2": {Id: "user2"}},
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
	account := &Account{
		Peers: map[string]*nbpeer.Peer{
			"peer1": {ID: "peer1", Key: "key1", UserID: "user1"},
			"peer2": {ID: "peer2", Key: "key2", UserID: "user1"},
			"peer3": {ID: "peer3", Key: "key3", UserID: "user1"},
			"peer4": {ID: "peer4", Key: "key4", UserID: "user2"},
			"peer5": {ID: "peer5", Key: "key5", UserID: "user2"},
		},
		Groups: map[string]*group.Group{
			"group1": {ID: "group1", Name: "group1", Issued: group.GroupIssuedAPI, Peers: []string{"peer1", "peer2", "peer3"}},
			"group2": {ID: "group2", Name: "group2", Issued: group.GroupIssuedAPI, Peers: []string{"peer1", "peer2", "peer3", "peer4", "peer5"}},
			"group3": {ID: "group3", Name: "group3", Issued: group.GroupIssuedAPI, Peers: []string{"peer4", "peer5"}},
		},
		Users: map[string]*User{"user1": {Id: "user1"}, "user2": {Id: "user2"}},
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

type TB interface {
	Cleanup(func())
	Helper()
	TempDir() string
}

func createManager(t TB) (*DefaultAccountManager, error) {
	t.Helper()

	store, err := createStore(t)
	if err != nil {
		return nil, err
	}
	eventStore := &activity.InMemoryEventStore{}

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	if err != nil {
		return nil, err
	}

	manager, err := BuildManager(context.Background(), store, NewPeersUpdateManager(nil), nil, "", "netbird.cloud", eventStore, nil, false, MocIntegratedValidator{}, metrics)
	if err != nil {
		return nil, err
	}

	return manager, nil
}

func createStore(t TB) (Store, error) {
	t.Helper()
	dataDir := t.TempDir()
	store, cleanUp, err := NewTestStoreFromJson(context.Background(), dataDir)
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
