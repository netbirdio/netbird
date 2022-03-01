package server

import (
	"github.com/stretchr/testify/require"
	"github.com/wiretrustee/wiretrustee/management/server/jwtclaims"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"testing"
)

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

	account, err = manager.GetAccountByUser(userId)
	if err != nil {
		t.Errorf("expected to get existing account after creation, no account was found for a user %s", userId)
	}

	if account != nil && account.Users[userId] == nil {
		t.Fatalf("expected to create an account for a user %s but no user was found after creation udner the account %s", userId, account.Id)
	}
}

func TestDefaultAccountManager_GetAccountWithAuthorizationClaims(t *testing.T) {

	type initUserParams jwtclaims.AuthorizationClaims

	type test struct {
		name                string
		inputClaims         jwtclaims.AuthorizationClaims
		inputInitUserParams initUserParams
		inputUpdateAttrs    bool
		testingFunc         require.ComparisonAssertionFunc
		expectedMSG         string
		expectedUserRole    UserRole
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
		inputInitUserParams: defaultInitAccount,
		testingFunc:         require.NotEqual,
		expectedMSG:         "account IDs shouldn't match",
		expectedUserRole:    UserRoleAdmin,
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
		inputInitUserParams: initUnknown,
		testingFunc:         require.NotEqual,
		expectedMSG:         "account IDs shouldn't match",
		expectedUserRole:    UserRoleAdmin,
	}

	testCase3 := test{
		name: "New User With Private Domain",
		inputClaims: jwtclaims.AuthorizationClaims{
			Domain:         privateDomain,
			UserId:         "pvt-domain-user",
			DomainCategory: PrivateCategory,
		},
		inputInitUserParams: defaultInitAccount,
		testingFunc:         require.NotEqual,
		expectedMSG:         "account IDs shouldn't match",
		expectedUserRole:    UserRoleAdmin,
	}

	privateInitAccount := defaultInitAccount
	privateInitAccount.Domain = privateDomain
	privateInitAccount.DomainCategory = PrivateCategory

	testCase4 := test{
		name: "New Regular User With Existing Private Domain",
		inputClaims: jwtclaims.AuthorizationClaims{
			Domain:         privateDomain,
			UserId:         "pvt-domain-user",
			DomainCategory: PrivateCategory,
		},
		inputUpdateAttrs:    true,
		inputInitUserParams: privateInitAccount,
		testingFunc:         require.Equal,
		expectedMSG:         "account IDs should match",
		expectedUserRole:    UserRoleUser,
	}

	testCase5 := test{
		name: "Existing User With Existing Reclassified Private Domain",
		inputClaims: jwtclaims.AuthorizationClaims{
			Domain:         defaultInitAccount.Domain,
			UserId:         defaultInitAccount.UserId,
			DomainCategory: PrivateCategory,
		},
		inputInitUserParams: defaultInitAccount,
		testingFunc:         require.Equal,
		expectedMSG:         "account IDs should match",
		expectedUserRole:    UserRoleAdmin,
	}

	for _, testCase := range []test{testCase1, testCase2, testCase3, testCase4, testCase5} {
		t.Run(testCase.name, func(t *testing.T) {

			manager, err := createManager(t)
			require.NoError(t, err, "unable to create account manager")

			initAccount, err := manager.GetAccountByUserOrAccountId(testCase.inputInitUserParams.UserId, testCase.inputInitUserParams.AccountId, testCase.inputInitUserParams.Domain)
			require.NoError(t, err, "create init user failed")

			if testCase.inputUpdateAttrs {
				err = manager.updateAccountDomainAttributes(initAccount, jwtclaims.AuthorizationClaims{UserId: testCase.inputInitUserParams.UserId, Domain: testCase.inputInitUserParams.Domain, DomainCategory: testCase.inputInitUserParams.DomainCategory}, true)
				require.NoError(t, err, "update init user failed")
			}

			account, err := manager.GetAccountWithAuthorizationClaims(testCase.inputClaims)
			require.NoError(t, err, "support function failed")

			testCase.testingFunc(t, initAccount.Id, account.Id, testCase.expectedMSG)

			require.EqualValues(t, testCase.expectedUserRole, account.Users[testCase.inputClaims.UserId].Role, "user role should match")
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

	account, err = manager.GetAccountByUser(userId)
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

func TestAccountManager_AddAccount(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedId := "test_account"
	userId := "account_creator"
	expectedPeersSize := 0
	expectedSetupKeysSize := 2
	expectedNetwork := net.IPNet{
		IP:   net.IP{100, 64, 0, 0},
		Mask: net.IPMask{255, 192, 0, 0},
	}

	account, err := manager.AddAccount(expectedId, userId, "")
	if err != nil {
		t.Fatal(err)
	}

	if account.Id != expectedId {
		t.Errorf("expected account to have Id = %s, got %s", expectedId, account.Id)
	}

	if len(account.Peers) != expectedPeersSize {
		t.Errorf("expected account to have len(Peers) = %v, got %v", expectedPeersSize, len(account.Peers))
	}

	if len(account.SetupKeys) != expectedSetupKeysSize {
		t.Errorf("expected account to have len(SetupKeys) = %v, got %v", expectedSetupKeysSize, len(account.SetupKeys))
	}

	if account.Network.Net.String() != expectedNetwork.String() {
		t.Errorf("expected account to have Network = %v, got %v", expectedNetwork.String(), account.Network.Net.String())
	}
}

func TestAccountManager_GetAccountByUserOrAccountId(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	userId := "test_user"

	account, err := manager.GetAccountByUserOrAccountId(userId, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if account == nil {
		t.Fatalf("expected to create an account for a user %s", userId)
	}

	accountId := account.Id

	_, err = manager.GetAccountByUserOrAccountId("", accountId, "")
	if err != nil {
		t.Errorf("expected to get existing account after creation using userid, no account was found for a account %s", accountId)
	}

	_, err = manager.GetAccountByUserOrAccountId("", "", "")
	if err == nil {
		t.Errorf("expected an error when user and account IDs are empty")
	}
}

func TestAccountManager_AccountExists(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	expectedId := "test_account"
	userId := "account_creator"
	_, err = manager.AddAccount(expectedId, userId, "")
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
	account, err := manager.AddAccount(expectedId, userId, "")
	if err != nil {
		t.Fatal(err)
	}

	//AddAccount has been already tested so we can assume it is correct and compare results
	getAccount, err := manager.GetAccountById(expectedId)
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

	account, err := manager.AddAccount("test_account", "account_creator", "")
	if err != nil {
		t.Fatal(err)
	}

	serial := account.Network.Serial() //should be 0

	var setupKey *SetupKey
	for _, key := range account.SetupKeys {
		setupKey = key
	}

	if setupKey == nil {
		t.Errorf("expecting account to have a default setup key")
		return
	}

	if account.Network.serial != 0 {
		t.Errorf("expecting account network to have an initial serial=0")
		return
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}
	expectedPeerKey := key.PublicKey().String()
	expectedPeerIP := "100.64.0.1"

	peer, err := manager.AddPeer(setupKey.Key, &Peer{
		Key:  expectedPeerKey,
		Meta: PeerSystemMeta{},
		Name: expectedPeerKey,
	})
	if err != nil {
		t.Errorf("expecting peer to be added, got failure %v", err)
		return
	}

	account, err = manager.GetAccountById(account.Id)
	if err != nil {
		t.Fatal(err)
		return
	}

	if peer.Key != expectedPeerKey {
		t.Errorf("expecting just added peer to have key = %s, got %s", expectedPeerKey, peer.Key)
	}

	if peer.Key != expectedPeerKey {
		t.Errorf("expecting just added peer to have IP = %s, got %s", expectedPeerIP, peer.IP.String())
	}

	if account.Network.Serial() != 1 {
		t.Errorf("expecting Network serial=%d to be incremented by 1 and be equal to %d when adding new peer to account", serial, account.Network.Serial())
	}

}

func TestAccountManager_DeletePeer(t *testing.T) {
	manager, err := createManager(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	account, err := manager.AddAccount("test_account", "account_creator", "")
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

	_, err = manager.AddPeer(setupKey.Key, &Peer{
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

	account, err = manager.GetAccountById(account.Id)
	if err != nil {
		t.Fatal(err)
		return
	}

	if account.Network.Serial() != 2 {
		t.Errorf("expecting Network serial=%d to be incremented and be equal to 2 after adding and deleteing a peer", account.Network.Serial())
	}

}

func createManager(t *testing.T) (*DefaultAccountManager, error) {
	store, err := createStore(t)
	if err != nil {
		return nil, err
	}
	return NewManager(store, NewPeersUpdateManager(), nil), nil
}

func createStore(t *testing.T) (Store, error) {
	dataDir := t.TempDir()
	store, err := NewStore(dataDir)
	if err != nil {
		return nil, err
	}

	return store, nil
}
