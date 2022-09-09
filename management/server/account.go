package server

import (
	"context"
	"fmt"
	"github.com/eko/gocache/v2/cache"
	cacheStore "github.com/eko/gocache/v2/store"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/route"
	gocache "github.com/patrickmn/go-cache"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"time"
)

const (
	PublicCategory     = "public"
	PrivateCategory    = "private"
	UnknownCategory    = "unknown"
	CacheExpirationMax = 7 * 24 * 3600 * time.Second // 7 days
	CacheExpirationMin = 3 * 24 * 3600 * time.Second // 3 days
)

type AccountManager interface {
	GetOrCreateAccountByUser(userId, domain string) (*Account, error)
	GetAccountByUser(userId string) (*Account, error)
	CreateSetupKey(
		accountId string,
		keyName string,
		keyType SetupKeyType,
		expiresIn time.Duration,
		autoGroups []string,
	) (*SetupKey, error)
	SaveSetupKey(accountID string, key *SetupKey) (*SetupKey, error)
	GetSetupKey(accountId, keyID string) (*SetupKey, error)
	GetAccountById(accountId string) (*Account, error)
	GetAccountByUserOrAccountId(userId, accountId, domain string) (*Account, error)
	GetAccountWithAuthorizationClaims(claims jwtclaims.AuthorizationClaims) (*Account, error)
	IsUserAdmin(claims jwtclaims.AuthorizationClaims) (bool, error)
	AccountExists(accountId string) (*bool, error)
	GetPeer(peerKey string) (*Peer, error)
	MarkPeerConnected(peerKey string, connected bool) error
	RenamePeer(accountId string, peerKey string, newName string) (*Peer, error)
	DeletePeer(accountId string, peerKey string) (*Peer, error)
	GetPeerByIP(accountId string, peerIP string) (*Peer, error)
	UpdatePeer(accountID string, peer *Peer) (*Peer, error)
	GetNetworkMap(peerKey string) (*NetworkMap, error)
	GetPeerNetwork(peerKey string) (*Network, error)
	AddPeer(setupKey string, userId string, peer *Peer) (*Peer, error)
	UpdatePeerMeta(peerKey string, meta PeerSystemMeta) error
	UpdatePeerSSHKey(peerKey string, sshKey string) error
	GetUsersFromAccount(accountId string) ([]*UserInfo, error)
	GetGroup(accountId, groupID string) (*Group, error)
	SaveGroup(accountId string, group *Group) error
	UpdateGroup(accountID string, groupID string, operations []GroupUpdateOperation) (*Group, error)
	DeleteGroup(accountId, groupID string) error
	ListGroups(accountId string) ([]*Group, error)
	GroupAddPeer(accountId, groupID, peerKey string) error
	GroupDeletePeer(accountId, groupID, peerKey string) error
	GroupListPeers(accountId, groupID string) ([]*Peer, error)
	GetRule(accountId, ruleID string) (*Rule, error)
	SaveRule(accountID string, rule *Rule) error
	UpdateRule(accountID string, ruleID string, operations []RuleUpdateOperation) (*Rule, error)
	DeleteRule(accountId, ruleID string) error
	ListRules(accountId string) ([]*Rule, error)
	GetRoute(accountID, routeID string) (*route.Route, error)
	CreateRoute(accountID string, prefix, peer, description, netID string, masquerade bool, metric int, enabled bool) (*route.Route, error)
	SaveRoute(accountID string, route *route.Route) error
	UpdateRoute(accountID string, routeID string, operations []RouteUpdateOperation) (*route.Route, error)
	DeleteRoute(accountID, routeID string) error
	ListRoutes(accountID string) ([]*route.Route, error)
}

type DefaultAccountManager struct {
	Store Store
	// mutex to synchronise account operations (e.g. generating Peer IP address inside the Network)
	mux                sync.Mutex
	peersUpdateManager *PeersUpdateManager
	idpManager         idp.Manager
	cacheManager       cache.CacheInterface
	ctx                context.Context
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
	Groups                 map[string]*Group
	Rules                  map[string]*Rule
	Routes                 map[string]*route.Route
}

type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
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

	groups := map[string]*Group{}
	for id, group := range a.Groups {
		groups[id] = group.Copy()
	}

	rules := map[string]*Rule{}
	for id, rule := range a.Rules {
		rules[id] = rule.Copy()
	}

	return &Account{
		Id:        a.Id,
		CreatedBy: a.CreatedBy,
		SetupKeys: setupKeys,
		Network:   a.Network.Copy(),
		Peers:     peers,
		Users:     users,
		Groups:    groups,
		Rules:     rules,
	}
}

func (a *Account) GetGroupAll() (*Group, error) {
	for _, g := range a.Groups {
		if g.Name == "All" {
			return g, nil
		}
	}
	return nil, fmt.Errorf("no group ALL found")
}

// BuildManager creates a new DefaultAccountManager with a provided Store
func BuildManager(
	store Store, peersUpdateManager *PeersUpdateManager, idpManager idp.Manager,
) (*DefaultAccountManager, error) {
	am := &DefaultAccountManager{
		Store:              store,
		mux:                sync.Mutex{},
		peersUpdateManager: peersUpdateManager,
		idpManager:         idpManager,
		ctx:                context.Background(),
	}

	// if account has not default group
	// we create 'all' group and add all peers into it
	// also we create default rule with source as destination
	for _, account := range store.GetAllAccounts() {
		_, err := account.GetGroupAll()
		if err != nil {
			addAllGroup(account)
			if err := store.SaveAccount(account); err != nil {
				return nil, err
			}
		}
	}

	gocacheClient := gocache.New(CacheExpirationMax, 30*time.Minute)
	gocacheStore := cacheStore.NewGoCache(gocacheClient, nil)

	am.cacheManager = cache.NewLoadable(am.loadFromCache, cache.New(gocacheStore))

	if !isNil(am.idpManager) {
		go func() {
			err := am.warmupIDPCache()
			if err != nil {
				log.Warnf("failed warming up cache due to error: %v", err)
				//todo retry?
				return
			}
		}()
	}

	return am, nil

}

// newAccount creates a new Account with a generated ID and generated default setup keys.
// If ID is already in use (due to collision) we try one more time before returning error
func (am *DefaultAccountManager) newAccount(userID, domain string) (*Account, error) {
	for i := 0; i < 2; i++ {
		accountId := xid.New().String()

		_, err := am.Store.GetAccount(accountId)
		statusErr, _ := status.FromError(err)
		if err == nil {
			log.Warnf("an account with ID already exists, retrying...")
			continue
		} else if statusErr.Code() == codes.NotFound {
			return newAccountWithId(accountId, userID, domain), nil
		} else {
			return nil, err
		}
	}

	return nil, status.Errorf(codes.Internal, "error while creating new account")
}

func (am *DefaultAccountManager) warmupIDPCache() error {
	userData, err := am.idpManager.GetAllAccounts()
	if err != nil {
		return err
	}

	for accountID, users := range userData {
		rand.Seed(time.Now().UnixNano())

		r := rand.Intn(int(CacheExpirationMax.Milliseconds()-CacheExpirationMin.Milliseconds())) + int(CacheExpirationMin.Milliseconds())
		expiration := time.Duration(r) * time.Millisecond
		err = am.cacheManager.Set(am.ctx, accountID, users, &cacheStore.Options{Expiration: expiration})
		if err != nil {
			return err
		}
	}
	log.Infof("warmed up IDP cache with %d entries", len(userData))
	return nil
}

// GetAccountById returns an existing account using its ID or error (NotFound) if doesn't exist
func (am *DefaultAccountManager) GetAccountById(accountId string) (*Account, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	return account, nil
}

// GetAccountByUserOrAccountId look for an account by user or account Id, if no account is provided and
// user id doesn't have an account associated with it, one account is created
func (am *DefaultAccountManager) GetAccountByUserOrAccountId(
	userId, accountId, domain string,
) (*Account, error) {
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

func isNil(i idp.Manager) bool {
	return i == nil || reflect.ValueOf(i).IsNil()
}

// updateIDPMetadata update user's  app metadata in idp manager
func (am *DefaultAccountManager) updateIDPMetadata(userId, accountID string) error {
	if !isNil(am.idpManager) {
		err := am.idpManager.UpdateUserAppMetadata(userId, idp.AppMetadata{WTAccountId: accountID})
		if err != nil {
			return status.Errorf(
				codes.Internal,
				"updating user's app metadata failed with: %v",
				err,
			)
		}
	}
	return nil
}

func mergeLocalAndQueryUser(queried idp.UserData, local User) *UserInfo {
	return &UserInfo{
		ID:    local.Id,
		Email: queried.Email,
		Name:  queried.Name,
		Role:  string(local.Role),
	}
}

func (am *DefaultAccountManager) loadFromCache(_ context.Context, accountID interface{}) (interface{}, error) {
	return am.idpManager.GetAccount(fmt.Sprintf("%v", accountID))
}

func (am *DefaultAccountManager) lookupCache(accountUsers map[string]*User, accountID string) ([]*idp.UserData, error) {
	data, err := am.cacheManager.Get(am.ctx, accountID)
	if err != nil {
		return nil, err
	}

	userData := data.([]*idp.UserData)

	userDataMap := make(map[string]struct{})
	for _, datum := range userData {
		userDataMap[datum.ID] = struct{}{}
	}

	// check whether we need to reload the cache
	// the accountUsers ID list is the source of truth and all the users should be in the cache
	reload := len(accountUsers) != len(userData)
	for user := range accountUsers {
		if _, ok := userDataMap[user]; !ok {
			reload = true
		}
	}

	if reload {
		// reload cache once avoiding loops
		err := am.cacheManager.Delete(am.ctx, accountID)
		if err != nil {
			return nil, err
		}
		data, err = am.cacheManager.Get(am.ctx, accountID)
		if err != nil {
			return nil, err
		}

		userData = data.([]*idp.UserData)
	}

	return userData, err
}

// GetUsersFromAccount performs a batched request for users from IDP by account id
func (am *DefaultAccountManager) GetUsersFromAccount(accountID string) ([]*UserInfo, error) {
	account, err := am.GetAccountById(accountID)
	if err != nil {
		return nil, err
	}

	queriedUsers := make([]*idp.UserData, 0)
	if !isNil(am.idpManager) {
		queriedUsers, err = am.lookupCache(account.Users, accountID)
		if err != nil {
			return nil, err
		}
	}

	userInfo := make([]*UserInfo, 0)

	// in case of self-hosted, or IDP doesn't return anything, we will return the locally stored userInfo
	if len(queriedUsers) == 0 {
		for _, user := range account.Users {
			userInfo = append(userInfo, &UserInfo{
				ID:    user.Id,
				Email: "",
				Name:  "",
				Role:  string(user.Role),
			})
		}
		return userInfo, nil
	}

	for _, queriedUser := range queriedUsers {
		if localUser, contains := account.Users[queriedUser.ID]; contains {
			userInfo = append(userInfo, mergeLocalAndQueryUser(*queriedUser, *localUser))
			log.Debugf("Merged userinfo to send back; %v", userInfo)
		}
	}

	return userInfo, nil
}

// updateAccountDomainAttributes updates the account domain attributes and then, saves the account
func (am *DefaultAccountManager) updateAccountDomainAttributes(
	account *Account,
	claims jwtclaims.AuthorizationClaims,
	primaryDomain bool,
) error {
	account.IsDomainPrimaryAccount = primaryDomain

	lowerDomain := strings.ToLower(claims.Domain)
	userObj := account.Users[claims.UserId]
	if account.Domain != lowerDomain && userObj.Role == UserRoleAdmin {
		account.Domain = lowerDomain
	}
	// prevent updating category for different domain until admin logs in
	if account.Domain == lowerDomain {
		account.DomainCategory = claims.DomainCategory
	}

	err := am.Store.SaveAccount(account)
	if err != nil {
		return status.Errorf(codes.Internal, "failed saving updated account")
	}
	return nil
}

// handleExistingUserAccount handles existing User accounts and update its domain attributes.
//
// If there is no primary domain account yet, we set the account as primary for the domain. Otherwise,
// we compare the account's ID with the domain account ID, and if they don't match, we set the account as
// non-primary account for the domain. We don't merge accounts at this stage, because of cases when a domain
// was previously unclassified or classified as public so N users that logged int that time, has they own account
// and peers that shouldn't be lost.
func (am *DefaultAccountManager) handleExistingUserAccount(
	existingAcc *Account,
	domainAcc *Account,
	claims jwtclaims.AuthorizationClaims,
) error {
	var err error

	if domainAcc != nil && existingAcc.Id != domainAcc.Id {
		err = am.updateAccountDomainAttributes(existingAcc, claims, false)
		if err != nil {
			return err
		}
	} else {
		err = am.updateAccountDomainAttributes(existingAcc, claims, true)
		if err != nil {
			return err
		}
	}

	// we should register the account ID to this user's metadata in our IDP manager
	err = am.updateIDPMetadata(claims.UserId, existingAcc.Id)
	if err != nil {
		return err
	}

	return nil
}

// handleNewUserAccount validates if there is an existing primary account for the domain, if so it adds the new user to that account,
// otherwise it will create a new account and make it primary account for the domain.
func (am *DefaultAccountManager) handleNewUserAccount(
	domainAcc *Account,
	claims jwtclaims.AuthorizationClaims,
) (*Account, error) {
	var (
		account *Account
		err     error
	)
	lowerDomain := strings.ToLower(claims.Domain)
	// if domain already has a primary account, add regular user
	if domainAcc != nil {
		account = domainAcc
		account.Users[claims.UserId] = NewRegularUser(claims.UserId)
		err = am.Store.SaveAccount(account)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed saving updated account")
		}
	} else {
		account, err = am.newAccount(claims.UserId, lowerDomain)
		if err != nil {
			return nil, err
		}
		err = am.updateAccountDomainAttributes(account, claims, true)
		if err != nil {
			return nil, err
		}
	}

	err = am.updateIDPMetadata(claims.UserId, account.Id)
	if err != nil {
		return nil, err
	}

	return account, nil
}

// GetAccountWithAuthorizationClaims retrievs an account using JWT Claims.
// if domain is of the PrivateCategory category, it will evaluate
// if account is new, existing or if there is another account with the same domain
//
// Use cases:
//
// New user + New account + New domain -> create account, user role = admin (if private domain, index domain)
//
// New user + New account + Existing Private Domain -> add user to the existing account, user role = regular (not admin)
//
// New user + New account + Existing Public Domain -> create account, user role = admin
//
// Existing user + Existing account + Existing Domain -> Nothing changes (if private, index domain)
//
// Existing user + Existing account + Existing Indexed Domain -> Nothing changes
//
// Existing user + Existing account + Existing domain reclassified Domain as private -> Nothing changes (index domain)
func (am *DefaultAccountManager) GetAccountWithAuthorizationClaims(
	claims jwtclaims.AuthorizationClaims,
) (*Account, error) {
	// if Account ID is part of the claims
	// it means that we've already classified the domain and user has an account
	if claims.DomainCategory != PrivateCategory {
		return am.GetAccountByUserOrAccountId(claims.UserId, claims.AccountId, claims.Domain)
	} else if claims.AccountId != "" {
		accountFromID, err := am.GetAccountById(claims.AccountId)
		if err != nil {
			return nil, err
		}
		if _, ok := accountFromID.Users[claims.UserId]; !ok {
			return nil, fmt.Errorf("user %s is not part of the account id %s", claims.UserId, claims.AccountId)
		}
		if accountFromID.DomainCategory == PrivateCategory || claims.DomainCategory != PrivateCategory {
			return accountFromID, nil
		}
	}

	am.mux.Lock()
	defer am.mux.Unlock()

	// We checked if the domain has a primary account already
	domainAccount, err := am.Store.GetAccountByPrivateDomain(claims.Domain)
	accStatus, _ := status.FromError(err)
	if accStatus.Code() != codes.OK && accStatus.Code() != codes.NotFound {
		return nil, err
	}

	account, err := am.Store.GetUserAccount(claims.UserId)
	if err == nil {
		err = am.handleExistingUserAccount(account, domainAccount, claims)
		if err != nil {
			return nil, err
		}
		return account, nil
	} else if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
		return am.handleNewUserAccount(domainAccount, claims)
	} else {
		// other error
		return nil, err
	}
}

// AccountExists checks whether account exists (returns true) or not (returns false)
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

// addAllGroup to account object if it doesn't exists
func addAllGroup(account *Account) {
	if len(account.Groups) == 0 {
		allGroup := &Group{
			ID:   xid.New().String(),
			Name: "All",
		}
		for _, peer := range account.Peers {
			allGroup.Peers = append(allGroup.Peers, peer.Key)
		}
		account.Groups = map[string]*Group{allGroup.ID: allGroup}

		defaultRule := &Rule{
			ID:          xid.New().String(),
			Name:        DefaultRuleName,
			Description: DefaultRuleDescription,
			Disabled:    false,
			Source:      []string{allGroup.ID},
			Destination: []string{allGroup.ID},
		}
		account.Rules = map[string]*Rule{defaultRule.ID: defaultRule}
	}
}

// newAccountWithId creates a new Account with a default SetupKey (doesn't store in a Store) and provided id
func newAccountWithId(accountId, userId, domain string) *Account {
	log.Debugf("creating new account")

	setupKeys := make(map[string]*SetupKey)
	defaultKey := GenerateDefaultSetupKey()
	oneOffKey := GenerateSetupKey("One-off key", SetupKeyOneOff, DefaultSetupKeyDuration, []string{})
	setupKeys[defaultKey.Key] = defaultKey
	setupKeys[oneOffKey.Key] = oneOffKey
	network := NewNetwork()
	peers := make(map[string]*Peer)
	users := make(map[string]*User)
	routes := make(map[string]*route.Route)
	users[userId] = NewAdminUser(userId)
	log.Debugf("created new account %s with setup key %s", accountId, defaultKey.Key)

	acc := &Account{
		Id:        accountId,
		SetupKeys: setupKeys,
		Network:   network,
		Peers:     peers,
		Users:     users,
		CreatedBy: userId,
		Domain:    domain,
		Routes:    routes,
	}

	addAllGroup(acc)
	return acc
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

func removeFromList(inputList []string, toRemove []string) []string {
	toRemoveMap := make(map[string]struct{})
	for _, item := range toRemove {
		toRemoveMap[item] = struct{}{}
	}

	var resultList []string
	for _, item := range inputList {
		_, ok := toRemoveMap[item]
		if !ok {
			resultList = append(resultList, item)
		}
	}
	return resultList
}
