package server

import (
	"fmt"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/route"
	"net"
	"reflect"
	"sync"
	"testing"

	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func verifyCanAddPeerToAccount(t *testing.T, manager AccountManager, account *Account, userID string) {
	peer := &Peer{
		Key:  "BhRPtynAAYRDy08+q4HTMsos8fs4plTP4NOSh7C1ry8=",
		Name: "test-host@netbird.io",
		Meta: PeerSystemMeta{
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

	_, err := manager.AddPeer(setupKey, userID, peer)
	if err != nil {
		t.Error("expected to add new peer successfully after creating new account, but failed", err)
	}
}

func verifyNewAccountHasDefaultFields(t *testing.T, account *Account, createdBy string, domain string, expectedUsers []string) {
	if len(account.Peers) != 0 {
		t.Errorf("expected account to have len(Peers) = %v, got %v", 0, len(account.Peers))
	}

	if len(account.SetupKeys) != 2 {
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

	if account.Domain != domain {
		t.Errorf("expecting newly created account to have domain %s, got %s", domain, account.Domain)
	}

	if len(account.Rules) != 1 {
		t.Errorf("expecting newly created account to have 1 rule, got %d", len(account.Rules))
	}

	for _, rule := range account.Rules {
		if rule.Name != "Default" {
			t.Errorf("expecting newly created account to have Default rule, got %s", rule.Name)
		}
	}
}

func TestNewAccount(t *testing.T) {

	domain := "netbird.io"
	userId := "account_creator"
	accountID := "account_id"
	account := newAccountWithId(accountID, userId, domain)
	verifyNewAccountHasDefaultFields(t, account, userId, domain, []string{userId})
}

func TestAccountManager_GetOrCreateAccountByUser(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userId := "test_user"
	account, err := manager.GetOrCreateAccountByUser(userId, "")
	if err != nil {
		t.Fatal(err)
	}
	if account == nil {
		t.Fatalf("expected to create an account for a user %s", userId)
	}

	account, err = manager.Store.GetAccountByUser(userId)
	if err != nil {
		t.Errorf("expected to get existing account after creation, no account was found for a user %s", userId)
	}

	if account != nil && account.Users[userId] == nil {
		t.Fatalf("expected to create an account for a user %s but no user was found after creation udner the account %s", userId, account.Id)
	}
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
		expectedUserRole:            UserRoleAdmin,
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
		expectedUserRole:            UserRoleAdmin,
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
		expectedUserRole:            UserRoleAdmin,
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
		expectedUserRole:            UserRoleAdmin,
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
		expectedUserRole:            UserRoleAdmin,
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
		expectedUserRole:            UserRoleAdmin,
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

			initAccount, err := manager.GetAccountByUserOrAccountID(testCase.inputInitUserParams.UserId, testCase.inputInitUserParams.AccountId, testCase.inputInitUserParams.Domain)
			require.NoError(t, err, "create init user failed")

			if testCase.inputUpdateAttrs {
				err = manager.updateAccountDomainAttributes(initAccount, jwtclaims.AuthorizationClaims{UserId: testCase.inputInitUserParams.UserId, Domain: testCase.inputInitUserParams.Domain, DomainCategory: testCase.inputInitUserParams.DomainCategory}, true)
				require.NoError(t, err, "update init user failed")
			}

			if testCase.inputUpdateClaimAccount {
				testCase.inputClaims.AccountId = initAccount.Id
			}

			account, _, err := manager.GetAccountFromToken(testCase.inputClaims)
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

func TestAccountManager_PrivateAccount(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userId := "test_user"
	account, err := manager.GetOrCreateAccountByUser(userId, "")
	if err != nil {
		t.Fatal(err)
	}
	if account == nil {
		t.Fatalf("expected to create an account for a user %s", userId)
	}

	account, err = manager.Store.GetAccountByUser(userId)
	if err != nil {
		t.Errorf("expected to get existing account after creation, no account was found for a user %s", userId)
	}

	if account != nil && account.Users[userId] == nil {
		t.Fatalf("expected to create an account for a user %s but no user was found after creation udner the account %s", userId, account.Id)
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
	account, err := manager.GetOrCreateAccountByUser(userId, domain)
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

	account, err = manager.GetOrCreateAccountByUser(userId, domain)
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

func TestAccountManager_GetAccountByUserOrAccountId(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userId := "test_user"

	account, err := manager.GetAccountByUserOrAccountID(userId, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if account == nil {
		t.Fatalf("expected to create an account for a user %s", userId)
	}

	accountId := account.Id

	_, err = manager.GetAccountByUserOrAccountID("", accountId, "")
	if err != nil {
		t.Errorf("expected to get existing account after creation using userid, no account was found for a account %s", accountId)
	}

	_, err = manager.GetAccountByUserOrAccountID("", "", "")
	if err == nil {
		t.Errorf("expected an error when user and account IDs are empty")
	}
}

func createAccount(am *DefaultAccountManager, accountID, userID, domain string) (*Account, error) {
	account := newAccountWithId(accountID, userID, domain)
	err := am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}
	return account, nil
}

func TestAccountManager_AccountExists(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedId := "test_account"
	userId := "account_creator"
	_, err = createAccount(manager, expectedId, userId, "")
	if err != nil {
		t.Fatal(err)
	}

	exists, err := manager.AccountExists(expectedId)
	if err != nil {
		t.Fatal(err)
	}

	if !*exists {
		t.Errorf("expected account to exist after creation, got false")
	}
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
	getAccount, err := manager.Store.GetAccount(account.Id)
	if err != nil {
		t.Fatal(err)
		return
	}

	if account.Id != getAccount.Id {
		t.Errorf("expected account.Id %s, got %s", account.Id, getAccount.Id)
	}

	for _, peer := range account.Peers {
		if _, ok := getAccount.Peers[peer.Key]; !ok {
			t.Errorf("expected account to have peer %s, not found", peer.Key)
		}
	}

	for _, key := range account.SetupKeys {
		if _, ok := getAccount.SetupKeys[key.Key]; !ok {
			t.Errorf("expected account to have setup key %s, not found", key.Key)
		}
	}
}

func TestAccountManager_AddPeer(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	account, err := createAccount(manager, "test_account", "account_creator", "")
	if err != nil {
		t.Fatal(err)
	}

	serial := account.Network.CurrentSerial() // should be 0

	var setupKey *SetupKey
	for _, key := range account.SetupKeys {
		setupKey = key
	}

	if setupKey == nil {
		t.Errorf("expecting account to have a default setup key")
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

	peer, err := manager.AddPeer(setupKey.Key, "", &Peer{
		Key:  expectedPeerKey,
		Meta: PeerSystemMeta{},
		Name: expectedPeerKey,
	})
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	account, err = manager.Store.GetAccount(account.Id)
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
}

func TestAccountManager_AddPeerWithUserID(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userId := "account_creator"

	account, err := manager.GetOrCreateAccountByUser(userId, "")
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
	expectedUserId := userId

	peer, err := manager.AddPeer("", userId, &Peer{
		Key:  expectedPeerKey,
		Meta: PeerSystemMeta{},
		Name: expectedPeerKey,
	})
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v, account users: %v", err, account.CreatedBy)
		return
	}

	account, err = manager.Store.GetAccount(account.Id)
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

	if peer.UserID != expectedUserId {
		t.Errorf("expecting just added peer to have UserID = %s, got %s", expectedUserId, peer.UserID)
	}

	if account.Network.CurrentSerial() != 1 {
		t.Errorf("expecting Network Serial=%d to be incremented by 1 and be equal to %d when adding new peer to account", serial, account.Network.CurrentSerial())
	}
}

func TestAccountManager_NetworkUpdates(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	account, err := createAccount(manager, "test_account", "account_creator", "")
	if err != nil {
		t.Fatal(err)
	}

	var setupKey *SetupKey
	for _, key := range account.SetupKeys {
		setupKey = key
		if setupKey.Type == SetupKeyReusable {
			break
		}
	}

	if setupKey == nil {
		t.Errorf("expecting account to have a default setup key")
		return
	}

	if account.Network.Serial != 0 {
		t.Errorf("expecting account network to have an initial Serial=0")
		return
	}

	getPeer := func() *Peer {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
			return nil
		}
		expectedPeerKey := key.PublicKey().String()

		peer, err := manager.AddPeer(setupKey.Key, "", &Peer{
			Key:  expectedPeerKey,
			Meta: PeerSystemMeta{},
			Name: expectedPeerKey,
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

	account, err = manager.Store.GetAccount(account.Id)
	if err != nil {
		t.Fatal(err)
		return
	}

	updMsg := manager.peersUpdateManager.CreateChannel(peer1.Key)
	defer manager.peersUpdateManager.CloseChannel(peer1.Key)

	group := Group{
		ID:    "group-id",
		Name:  "GroupA",
		Peers: []string{peer1.Key, peer2.Key, peer3.Key},
	}

	rule := Rule{
		Source:      []string{"group-id"},
		Destination: []string{"group-id"},
		Flow:        TrafficFlowBidirect,
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

		if err := manager.SaveGroup(account.Id, &group); err != nil {
			t.Errorf("save group: %v", err)
			return
		}

		wg.Wait()
	})

	t.Run("delete rule update", func(t *testing.T) {
		wg.Add(1)
		go func() {
			defer wg.Done()

			message := <-updMsg
			networkMap := message.Update.GetNetworkMap()
			if len(networkMap.RemotePeers) != 0 {
				t.Errorf("mismatch peers count: 0 expected, got %v", len(networkMap.RemotePeers))
			}
		}()

		var defaultRule *Rule
		for _, r := range account.Rules {
			defaultRule = r
		}

		if err := manager.DeleteRule(account.Id, defaultRule.ID); err != nil {
			t.Errorf("delete default rule: %v", err)
			return
		}

		wg.Wait()
	})

	t.Run("save rule update", func(t *testing.T) {
		wg.Add(1)
		go func() {
			defer wg.Done()

			message := <-updMsg
			networkMap := message.Update.GetNetworkMap()
			if len(networkMap.RemotePeers) != 2 {
				t.Errorf("mismatch peers count: 2 expected, got %v", len(networkMap.RemotePeers))
			}
		}()

		if err := manager.SaveRule(account.Id, &rule); err != nil {
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

		if _, err := manager.DeletePeer(account.Id, peer3.Key); err != nil {
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

		if err := manager.DeleteGroup(account.Id, group.ID); err != nil {
			t.Errorf("delete group rule: %v", err)
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

	account, err := createAccount(manager, "test_account", "account_creator", "")
	if err != nil {
		t.Fatal(err)
	}

	var setupKey *SetupKey
	for _, key := range account.SetupKeys {
		setupKey = key
	}

	key, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peerKey := key.PublicKey().String()

	_, err = manager.AddPeer(setupKey.Key, "", &Peer{
		Key:  peerKey,
		Meta: PeerSystemMeta{},
		Name: peerKey,
	})
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	_, err = manager.DeletePeer(account.Id, peerKey)
	if err != nil {
		return
	}

	account, err = manager.Store.GetAccount(account.Id)
	if err != nil {
		t.Fatal(err)
		return
	}

	if account.Network.CurrentSerial() != 2 {
		t.Errorf("expecting Network Serial=%d to be incremented and be equal to 2 after adding and deleteing a peer", account.Network.CurrentSerial())
	}
}

func TestGetUsersFromAccount(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
	}

	users := map[string]*User{"1": {Id: "1", Role: "admin"}, "2": {Id: "2", Role: "user"}, "3": {Id: "3", Role: "user"}}
	accountId := "test_account_id"

	account, err := createAccount(manager, accountId, users["1"].Id, "")
	if err != nil {
		t.Fatal(err)
	}

	// add a user to the account
	for _, user := range users {
		account.Users[user.Id] = user
	}

	userInfos, err := manager.GetUsersFromAccount(accountId, "1")
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

func TestAccountManager_UpdatePeerMeta(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	account, err := createAccount(manager, "test_account", "account_creator", "")
	if err != nil {
		t.Fatal(err)
	}

	var setupKey *SetupKey
	for _, key := range account.SetupKeys {
		setupKey = key
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	peer, err := manager.AddPeer(setupKey.Key, "", &Peer{
		Key: key.PublicKey().String(),
		Meta: PeerSystemMeta{
			Hostname:  "Hostname",
			GoOS:      "GoOS",
			Kernel:    "Kernel",
			Core:      "Core",
			Platform:  "Platform",
			OS:        "OS",
			WtVersion: "WtVersion",
		},
		Name: key.PublicKey().String(),
	})
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	newMeta := PeerSystemMeta{
		Hostname:  "new-Hostname",
		GoOS:      "new-GoOS",
		Kernel:    "new-Kernel",
		Core:      "new-Core",
		Platform:  "new-Platform",
		OS:        "new-OS",
		WtVersion: "new-WtVersion",
	}
	err = manager.UpdatePeerMeta(peer.Key, newMeta)
	if err != nil {
		t.Error(err)
		return
	}

	p, err := manager.GetPeer(peer.Key)
	if err != nil {
		return
	}

	if err != nil {
		t.Fatal(err)
		return
	}

	assert.Equal(t, newMeta, p.Meta)
}

func TestAccount_GetPeerRules(t *testing.T) {

	groups := map[string]*Group{
		"group_1": {
			ID:    "group_1",
			Name:  "group_1",
			Peers: []string{"peer-1", "peer-2"},
		},
		"group_2": {
			ID:    "group_2",
			Name:  "group_2",
			Peers: []string{"peer-2", "peer-3"},
		},
		"group_3": {
			ID:    "group_3",
			Name:  "group_3",
			Peers: []string{"peer-4"},
		},
		"group_4": {
			ID:    "group_4",
			Name:  "group_4",
			Peers: []string{"peer-1"},
		},
		"group_5": {
			ID:    "group_5",
			Name:  "group_5",
			Peers: []string{"peer-1"},
		},
	}
	rules := map[string]*Rule{
		"rule-1": {
			ID:          "rule-1",
			Name:        "rule-1",
			Description: "rule-1",
			Disabled:    false,
			Source:      []string{"group_1", "group_5"},
			Destination: []string{"group_2"},
			Flow:        0,
		},
		"rule-2": {
			ID:          "rule-2",
			Name:        "rule-2",
			Description: "rule-2",
			Disabled:    false,
			Source:      []string{"group_1"},
			Destination: []string{"group_1"},
			Flow:        0,
		},
		"rule-3": {
			ID:          "rule-3",
			Name:        "rule-3",
			Description: "rule-3",
			Disabled:    false,
			Source:      []string{"group_3"},
			Destination: []string{"group_3"},
			Flow:        0,
		},
	}

	account := &Account{
		Groups: groups,
		Rules:  rules,
	}

	srcRules, dstRules := account.GetPeerRules("peer-1")

	assert.Equal(t, 2, len(srcRules))
	assert.Equal(t, 1, len(dstRules))

}

func TestFileStore_GetRoutesByPrefix(t *testing.T) {
	_, prefix, err := route.ParseNetwork("192.168.64.0/24")
	if err != nil {
		t.Fatal(err)
	}
	account := &Account{
		Routes: map[string]*route.Route{
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

	routes := account.GetRoutesByPrefix(prefix)

	assert.Len(t, routes, 2)
	routeIDs := make(map[string]struct{}, 2)
	for _, r := range routes {
		routeIDs[r.ID] = struct{}{}
	}
	assert.Contains(t, routeIDs, "route-1")
	assert.Contains(t, routeIDs, "route-2")
}

func TestAccount_GetRoutesToSync(t *testing.T) {
	_, prefix, err := route.ParseNetwork("192.168.64.0/24")
	if err != nil {
		t.Fatal(err)
	}
	account := &Account{
		Peers: map[string]*Peer{
			"peer-1": {Key: "peer-1"}, "peer-2": {Key: "peer-2"}, "peer-3": {Key: "peer-1"},
		},
		Groups: map[string]*Group{"group1": {ID: "group1", Peers: []string{"peer-1", "peer-2"}}},
		Routes: map[string]*route.Route{
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

	routes := account.getRoutesToSync("peer-2", []*Peer{{Key: "peer-1"}, {Key: "peer-3"}})

	assert.Len(t, routes, 2)
	routeIDs := make(map[string]struct{}, 2)
	for _, r := range routes {
		routeIDs[r.ID] = struct{}{}
	}
	assert.Contains(t, routeIDs, "route-1")
	assert.Contains(t, routeIDs, "route-2")

	emptyRoutes := account.getRoutesToSync("peer-3", []*Peer{{Key: "peer-1"}, {Key: "peer-2"}})

	assert.Len(t, emptyRoutes, 0)
}

func TestAccount_Copy(t *testing.T) {
	account := &Account{
		Id:                     "account1",
		CreatedBy:              "tester",
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
			Id: "net1",
		},
		Peers: map[string]*Peer{
			"peer1": {
				Key: "key1",
			},
		},
		Users: map[string]*User{
			"user1": {
				Id:         "user1",
				Role:       UserRoleAdmin,
				AutoGroups: []string{"group1"},
			},
		},
		Groups: map[string]*Group{
			"group1": {
				ID: "group1",
			},
		},
		Rules: map[string]*Rule{
			"rule1": {
				ID: "rule1",
			},
		},
		Routes: map[string]*route.Route{
			"route1": {
				ID: "route1",
			},
		},
		NameServerGroups: map[string]*nbdns.NameServerGroup{
			"nsGroup1": {
				ID: "nsGroup1",
			},
		},
	}
	err := hasNilField(account)
	if err != nil {
		t.Fatal(err)
	}
	accountCopy := account.Copy()
	assert.Equal(t, account, accountCopy, "account copy returned a different value than expected")
}

// hasNilField validates pointers, maps and slices if they are nil
func hasNilField(x interface{}) error {
	rv := reflect.ValueOf(x)
	rv = rv.Elem()
	for i := 0; i < rv.NumField(); i++ {
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

func createManager(t *testing.T) (*DefaultAccountManager, error) {
	store, err := createStore(t)
	if err != nil {
		return nil, err
	}
	return BuildManager(store, NewPeersUpdateManager(), nil, "", "")
}

func createStore(t *testing.T) (Store, error) {
	dataDir := t.TempDir()
	store, err := NewFileStore(dataDir)
	if err != nil {
		return nil, err
	}

	return store, nil
}
