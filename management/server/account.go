package server

import (
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/management/server/idp"
	"github.com/wiretrustee/wiretrustee/management/server/jwtclaims"
	"github.com/wiretrustee/wiretrustee/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
	"sync"
)

const (
	PublicCategory  = "public"
	PrivateCategory = "private"
	UnknownCategory = "unknown"
)

type AccountManager interface {
	GetOrCreateAccountByUser(userId, domain string) (*Account, error)
	GetAccountByUser(userId string) (*Account, error)
	AddSetupKey(accountId string, keyName string, keyType SetupKeyType, expiresIn *util.Duration) (*SetupKey, error)
	RevokeSetupKey(accountId string, keyId string) (*SetupKey, error)
	RenameSetupKey(accountId string, keyId string, newName string) (*SetupKey, error)
	GetAccountById(accountId string) (*Account, error)
	GetAccountByUserOrAccountId(userId, accountId, domain string) (*Account, error)
	GetAccountWithAuthorizationClaims(claims jwtclaims.AuthorizationClaims) (*Account, error)
	AccountExists(accountId string) (*bool, error)
	AddAccount(accountId, userId, domain string) (*Account, error)
	GetPeer(peerKey string) (*Peer, error)
	MarkPeerConnected(peerKey string, connected bool) error
	RenamePeer(accountId string, peerKey string, newName string) (*Peer, error)
	DeletePeer(accountId string, peerKey string) (*Peer, error)
	GetPeerByIP(accountId string, peerIP string) (*Peer, error)
	GetNetworkMap(peerKey string) (*NetworkMap, error)
	AddPeer(setupKey string, peer *Peer) (*Peer, error)
}

type DefaultAccountManager struct {
	Store Store
	// mutex to synchronise account operations (e.g. generating Peer IP address inside the Network)
	mux                sync.Mutex
	peersUpdateManager *PeersUpdateManager
	idpManager         idp.Manager
}

// Account represents a unique account of the system
type Account struct {
	Id string
	// User.Id it was created by
	CreatedBy              string
	Domain                 string
	DomainCategory         string
	IsDomainPrimaryAccount bool
	SetupKeys              map[string]*SetupKey
	Network                *Network
	Peers                  map[string]*Peer
	Users                  map[string]*User
}

// NewAccount creates a new Account with a generated ID and generated default setup keys
func NewAccount(userId, domain string) *Account {
	accountId := xid.New().String()
	return newAccountWithId(accountId, userId, domain)
}

func (a *Account) Copy() *Account {
	peers := map[string]*Peer{}
	for id, peer := range a.Peers {
		peers[id] = peer.Copy()
	}

	users := map[string]*User{}
	for id, user := range a.Users {
		users[id] = user.Copy()
	}

	setupKeys := map[string]*SetupKey{}
	for id, key := range a.SetupKeys {
		setupKeys[id] = key.Copy()
	}

	return &Account{
		Id:        a.Id,
		CreatedBy: a.CreatedBy,
		SetupKeys: setupKeys,
		Network:   a.Network.Copy(),
		Peers:     peers,
		Users:     users,
	}
}

// NewManager creates a new DefaultAccountManager with a provided Store
func NewManager(store Store, peersUpdateManager *PeersUpdateManager, idpManager idp.Manager) *DefaultAccountManager {
	return &DefaultAccountManager{
		Store:              store,
		mux:                sync.Mutex{},
		peersUpdateManager: peersUpdateManager,
		idpManager:         idpManager,
	}
}

//AddSetupKey generates a new setup key with a given name and type, and adds it to the specified account
func (am *DefaultAccountManager) AddSetupKey(accountId string, keyName string, keyType SetupKeyType, expiresIn *util.Duration) (*SetupKey, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	keyDuration := DefaultSetupKeyDuration
	if expiresIn != nil {
		keyDuration = expiresIn.Duration
	}

	account, err := am.Store.GetAccount(accountId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	setupKey := GenerateSetupKey(keyName, keyType, keyDuration)
	account.SetupKeys[setupKey.Key] = setupKey

	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed adding account key")
	}

	return setupKey, nil
}

//RevokeSetupKey marks SetupKey as revoked - becomes not valid anymore
func (am *DefaultAccountManager) RevokeSetupKey(accountId string, keyId string) (*SetupKey, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	setupKey := getAccountSetupKeyById(account, keyId)
	if setupKey == nil {
		return nil, status.Errorf(codes.NotFound, "unknown setupKey %s", keyId)
	}

	keyCopy := setupKey.Copy()
	keyCopy.Revoked = true
	account.SetupKeys[keyCopy.Key] = keyCopy
	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed adding account key")
	}

	return keyCopy, nil
}

//RenameSetupKey renames existing setup key of the specified account.
func (am *DefaultAccountManager) RenameSetupKey(accountId string, keyId string, newName string) (*SetupKey, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	setupKey := getAccountSetupKeyById(account, keyId)
	if setupKey == nil {
		return nil, status.Errorf(codes.NotFound, "unknown setupKey %s", keyId)
	}

	keyCopy := setupKey.Copy()
	keyCopy.Name = newName
	account.SetupKeys[keyCopy.Key] = keyCopy
	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed adding account key")
	}

	return keyCopy, nil
}

//GetAccountById returns an existing account using its ID or error (NotFound) if doesn't exist
func (am *DefaultAccountManager) GetAccountById(accountId string) (*Account, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	return account, nil
}

//GetAccountByUserOrAccountId look for an account by user or account Id, if no account is provided and
// user id doesn't have an account associated with it, one account is created
func (am *DefaultAccountManager) GetAccountByUserOrAccountId(userId, accountId, domain string) (*Account, error) {

	if accountId != "" {
		return am.GetAccountById(accountId)
	} else if userId != "" {
		account, err := am.GetOrCreateAccountByUser(userId, domain)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "account not found using user id: %s", userId)
		}
		err = am.updateIDPMetadata(userId, account.Id)
		if err != nil {
			return nil, err
		}
		return account, nil
	}

	return nil, status.Errorf(codes.NotFound, "no valid user or account Id provided")
}

// updateIDPMetadata update user's  app metadata in idp manager
func (am *DefaultAccountManager) updateIDPMetadata(userId, accountID string) error {
	if am.idpManager != nil {
		err := am.idpManager.UpdateUserAppMetadata(userId, idp.AppMetadata{WTAccountId: accountID})
		if err != nil {
			return status.Errorf(codes.Internal, "updating user's app metadata failed with: %v", err)
		}
	}
	return nil
}

// updateAccountDomainAttributes updates the account domain attributes and then, saves the account
func (am *DefaultAccountManager) updateAccountDomainAttributes(account *Account, claims jwtclaims.AuthorizationClaims, primaryDomain bool) error {
	account.IsDomainPrimaryAccount = primaryDomain
	account.Domain = strings.ToLower(claims.Domain)
	account.DomainCategory = claims.DomainCategory
	err := am.Store.SaveAccount(account)
	if err != nil {
		return status.Errorf(codes.Internal, "failed saving updated account")
	}
	return nil
}

// GetAccountWithAuthorizationClaims retrievs an account using JWT Claims.
// if domain is of the PrivateCategory category, it will evaluate
// if account is new, existing or if there is another account with the same domain
func (am *DefaultAccountManager) GetAccountWithAuthorizationClaims(claims jwtclaims.AuthorizationClaims) (*Account, error) {
	if claims.DomainCategory != PrivateCategory || claims.AccountId != "" {
		return am.GetAccountByUserOrAccountId(claims.UserId, claims.AccountId, claims.Domain)
	}

	am.mux.Lock()
	defer am.mux.Unlock()

	isDomainIndexed := false

	domainAccount, err := am.Store.GetAccountByPrivateDomain(claims.Domain)
	if err != nil {
		if _, ok := status.FromError(err); !ok {
			return nil, err
		}
	} else {
		isDomainIndexed = true
	}

	account, err := am.Store.GetUserAccount(claims.UserId)
	if err == nil {
		log.Infoln("exxisting account: ", account.Id)
		if !isDomainIndexed || account.Id != domainAccount.Id {
			log.Infoln("not indexed account: ", account.Id)
			err = am.updateAccountDomainAttributes(account, claims, !isDomainIndexed)
			if err != nil {
				return nil, err
			}
		}

		err = am.updateIDPMetadata(claims.UserId, account.Id)
		if err != nil {
			return nil, err
		}

		return account, nil

	} else if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
		lowerDomain := strings.ToLower(claims.Domain)
		if isDomainIndexed {
			account = domainAccount
			account.Users[claims.UserId] = NewRegularUser(claims.UserId)

		} else {
			log.Infoln("account not found for: ", claims.UserId, isDomainIndexed)
			account = NewAccount(claims.UserId, lowerDomain)
			account.Users[claims.UserId] = NewAdminUser(claims.UserId)
		}

		err = am.updateAccountDomainAttributes(account, claims, !isDomainIndexed)
		if err != nil {
			return nil, err
		}

		err = am.updateIDPMetadata(claims.UserId, account.Id)
		if err != nil {
			return nil, err
		}

		return account, nil

	} else {
		// other error
		return nil, err
	}
}

//AccountExists checks whether account exists (returns true) or not (returns false)
func (am *DefaultAccountManager) AccountExists(accountId string) (*bool, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	var res bool
	_, err := am.Store.GetAccount(accountId)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			res = false
			return &res, nil
		} else {
			return nil, err
		}
	}

	res = true
	return &res, nil
}

// AddAccount generates a new Account with a provided accountId and userId, saves to the Store
func (am *DefaultAccountManager) AddAccount(accountId, userId, domain string) (*Account, error) {

	am.mux.Lock()
	defer am.mux.Unlock()

	return am.createAccount(accountId, userId, domain)

}

func (am *DefaultAccountManager) createAccount(accountId, userId, domain string) (*Account, error) {
	account := newAccountWithId(accountId, userId, domain)

	err := am.Store.SaveAccount(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed creating account")
	}

	return account, nil
}

// newAccountWithId creates a new Account with a default SetupKey (doesn't store in a Store) and provided id
func newAccountWithId(accountId, userId, domain string) *Account {

	log.Debugf("creating new account")

	setupKeys := make(map[string]*SetupKey)
	defaultKey := GenerateDefaultSetupKey()
	oneOffKey := GenerateSetupKey("One-off key", SetupKeyOneOff, DefaultSetupKeyDuration)
	setupKeys[defaultKey.Key] = defaultKey
	setupKeys[oneOffKey.Key] = oneOffKey
	network := NewNetwork()
	peers := make(map[string]*Peer)
	users := make(map[string]*User)

	log.Debugf("created new account %s with setup key %s", accountId, defaultKey.Key)

	return &Account{
		Id:        accountId,
		SetupKeys: setupKeys,
		Network:   network,
		Peers:     peers,
		Users:     users,
		CreatedBy: userId,
		Domain:    domain,
	}
}

func getAccountSetupKeyById(acc *Account, keyId string) *SetupKey {
	for _, k := range acc.SetupKeys {
		if keyId == k.Id {
			return k
		}
	}
	return nil
}

func getAccountSetupKeyByKey(acc *Account, key string) *SetupKey {
	for _, k := range acc.SetupKeys {
		if key == k.Key {
			return k
		}
	}
	return nil
}
