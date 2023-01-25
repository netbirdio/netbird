package server

import (
	"context"
	"fmt"
	"github.com/eko/gocache/v3/cache"
	cacheStore "github.com/eko/gocache/v3/store"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/route"
	gocache "github.com/patrickmn/go-cache"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"net"
	"net/netip"
	"reflect"
	"regexp"
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

func cacheEntryExpiration() time.Duration {
	r := rand.Intn(int(CacheExpirationMax.Milliseconds()-CacheExpirationMin.Milliseconds())) + int(CacheExpirationMin.Milliseconds())
	return time.Duration(r) * time.Millisecond
}

type AccountManager interface {
	GetOrCreateAccountByUser(userId, domain string) (*Account, error)
	CreateSetupKey(accountID string, keyName string, keyType SetupKeyType, expiresIn time.Duration,
		autoGroups []string, usageLimit int, userID string) (*SetupKey, error)
	SaveSetupKey(accountID string, key *SetupKey, userID string) (*SetupKey, error)
	CreateUser(accountID, userID string, key *UserInfo) (*UserInfo, error)
	ListSetupKeys(accountID, userID string) ([]*SetupKey, error)
	SaveUser(accountID, userID string, update *User) (*UserInfo, error)
	GetSetupKey(accountID, userID, keyID string) (*SetupKey, error)
	GetAccountByUserOrAccountID(userID, accountID, domain string) (*Account, error)
	GetAccountFromToken(claims jwtclaims.AuthorizationClaims) (*Account, *User, error)
	IsUserAdmin(claims jwtclaims.AuthorizationClaims) (bool, error)
	AccountExists(accountId string) (*bool, error)
	GetPeer(peerKey string) (*Peer, error)
	GetPeers(accountID, userID string) ([]*Peer, error)
	MarkPeerConnected(peerKey string, connected bool) error
	DeletePeer(accountID, peerKey, userID string) (*Peer, error)
	GetPeerByIP(accountId string, peerIP string) (*Peer, error)
	UpdatePeer(accountID, userID string, peer *Peer) (*Peer, error)
	GetNetworkMap(peerKey string) (*NetworkMap, error)
	GetPeerNetwork(peerKey string) (*Network, error)
	AddPeer(setupKey, userID string, peer *Peer) (*Peer, error)
	UpdatePeerMeta(peerKey string, meta PeerSystemMeta) error
	UpdatePeerSSHKey(peerKey string, sshKey string) error
	GetUsersFromAccount(accountID, userID string) ([]*UserInfo, error)
	GetGroup(accountId, groupID string) (*Group, error)
	SaveGroup(accountID, userID string, group *Group) error
	UpdateGroup(accountID string, groupID string, operations []GroupUpdateOperation) (*Group, error)
	DeleteGroup(accountId, groupID string) error
	ListGroups(accountId string) ([]*Group, error)
	GroupAddPeer(accountId, groupID, peerKey string) error
	GroupDeletePeer(accountId, groupID, peerKey string) error
	GroupListPeers(accountId, groupID string) ([]*Peer, error)
	GetRule(accountID, ruleID, userID string) (*Rule, error)
	SaveRule(accountID, userID string, rule *Rule) error
	UpdateRule(accountID string, ruleID string, operations []RuleUpdateOperation) (*Rule, error)
	DeleteRule(accountID, ruleID, userID string) error
	ListRules(accountID, userID string) ([]*Rule, error)
	GetRoute(accountID, routeID, userID string) (*route.Route, error)
	CreateRoute(accountID string, prefix, peerIP, description, netID string, masquerade bool, metric int, groups []string, enabled bool, userID string) (*route.Route, error)
	SaveRoute(accountID, userID string, route *route.Route) error
	UpdateRoute(accountID, routeID string, operations []RouteUpdateOperation) (*route.Route, error)
	DeleteRoute(accountID, routeID, userID string) error
	ListRoutes(accountID, userID string) ([]*route.Route, error)
	GetNameServerGroup(accountID, nsGroupID string) (*nbdns.NameServerGroup, error)
	CreateNameServerGroup(accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool) (*nbdns.NameServerGroup, error)
	SaveNameServerGroup(accountID string, nsGroupToSave *nbdns.NameServerGroup) error
	UpdateNameServerGroup(accountID, nsGroupID string, operations []NameServerGroupUpdateOperation) (*nbdns.NameServerGroup, error)
	DeleteNameServerGroup(accountID, nsGroupID string) error
	ListNameServerGroups(accountID string) ([]*nbdns.NameServerGroup, error)
	GetDNSDomain() string
	GetEvents(accountID, userID string) ([]*activity.Event, error)
	GetDNSSettings(accountID string, userID string) (*DNSSettings, error)
	SaveDNSSettings(accountID string, userID string, dnsSettingsToSave *DNSSettings) error
}

type DefaultAccountManager struct {
	Store Store
	// cacheMux and cacheLoading helps to make sure that only a single cache reload runs at a time per accountID
	cacheMux sync.Mutex
	// cacheLoading keeps the accountIDs that are currently reloading. The accountID has to be removed once cache has been reloaded
	cacheLoading       map[string]chan struct{}
	peersUpdateManager *PeersUpdateManager
	idpManager         idp.Manager
	cacheManager       cache.CacheInterface[[]*idp.UserData]
	ctx                context.Context
	eventStore         activity.Store

	// singleAccountMode indicates whether the instance has a single account.
	// If true, then every new user will end up under the same account.
	// This value will be set to false if management service has more than one account.
	singleAccountMode bool
	// singleAccountModeDomain is a domain to use in singleAccountMode setup
	singleAccountModeDomain string
	// dnsDomain is used for peer resolution. This is appended to the peer's name
	dnsDomain string
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
	NameServerGroups       map[string]*nbdns.NameServerGroup
	DNSSettings            *DNSSettings
}

type UserInfo struct {
	ID         string   `json:"id"`
	Email      string   `json:"email"`
	Name       string   `json:"name"`
	Role       string   `json:"role"`
	AutoGroups []string `json:"auto_groups"`
	Status     string   `json:"-"`
}

// getRoutesToSync returns the enabled routes for the peer ID and the routes
// from the ACL peers that have distribution groups associated with the peer ID
func (a *Account) getRoutesToSync(peerID string, aclPeers []*Peer) []*route.Route {
	routes, peerDisabledRoutes := a.getEnabledAndDisabledRoutesByPeer(peerID)
	peerRoutesMembership := make(lookupMap)
	for _, r := range append(routes, peerDisabledRoutes...) {
		peerRoutesMembership[route.GetHAUniqueID(r)] = struct{}{}
	}

	groupListMap := a.getPeerGroups(peerID)
	for _, peer := range aclPeers {
		activeRoutes, _ := a.getEnabledAndDisabledRoutesByPeer(peer.Key)
		groupFilteredRoutes := a.filterRoutesByGroups(activeRoutes, groupListMap)
		filteredRoutes := a.filterRoutesFromPeersOfSameHAGroup(groupFilteredRoutes, peerRoutesMembership)
		routes = append(routes, filteredRoutes...)
	}

	return routes
}

// filterRoutesByHAMembership filters and returns a list of routes that don't share the same HA route membership
func (a *Account) filterRoutesFromPeersOfSameHAGroup(routes []*route.Route, peerMemberships lookupMap) []*route.Route {
	var filteredRoutes []*route.Route
	for _, r := range routes {
		_, found := peerMemberships[route.GetHAUniqueID(r)]
		if !found {
			filteredRoutes = append(filteredRoutes, r)
		}
	}
	return filteredRoutes
}

// filterRoutesByGroups returns a list with routes that have distribution groups in the group's map
func (a *Account) filterRoutesByGroups(routes []*route.Route, groupListMap lookupMap) []*route.Route {
	var filteredRoutes []*route.Route
	for _, r := range routes {
		for _, groupID := range r.Groups {
			_, found := groupListMap[groupID]
			if found {
				filteredRoutes = append(filteredRoutes, r)
				break
			}
		}
	}
	return filteredRoutes
}

// getEnabledAndDisabledRoutesByPeer returns the enabled and disabled lists of routes that belong to a peer
func (a *Account) getEnabledAndDisabledRoutesByPeer(peerPubKey string) ([]*route.Route, []*route.Route) {
	//TODO Peer.ID migration: we will need to replace search by Peer.ID here
	var enabledRoutes []*route.Route
	var disabledRoutes []*route.Route
	for _, r := range a.Routes {
		if r.Peer == peerPubKey {
			if r.Enabled {
				enabledRoutes = append(enabledRoutes, r)
				continue
			}
			disabledRoutes = append(disabledRoutes, r)
		}
	}
	return enabledRoutes, disabledRoutes
}

// GetRoutesByPrefix return list of routes by account and route prefix
func (a *Account) GetRoutesByPrefix(prefix netip.Prefix) []*route.Route {

	var routes []*route.Route
	for _, r := range a.Routes {
		if r.Network.String() == prefix.String() {
			routes = append(routes, r)
		}
	}

	return routes
}

// GetPeerByIP returns peer by it's IP if exists under account or nil otherwise
func (a *Account) GetPeerByIP(peerIP string) *Peer {
	for _, peer := range a.Peers {
		if peerIP == peer.IP.String() {
			return peer
		}
	}

	return nil
}

// GetPeerRules returns a list of source or destination rules of a given peer.
func (a *Account) GetPeerRules(peerPubKey string) (srcRules []*Rule, dstRules []*Rule) {

	// Rules are group based so there is no direct access to peers.
	// First, find all groups that the given peer belongs to
	peerGroups := make(map[string]struct{})

	for s, group := range a.Groups {
		for _, peer := range group.Peers {
			if peerPubKey == peer {
				peerGroups[s] = struct{}{}
				break
			}
		}
	}

	// Second, find all rules that have discovered source and destination groups
	srcRulesMap := make(map[string]*Rule)
	dstRulesMap := make(map[string]*Rule)
	for _, rule := range a.Rules {
		for _, g := range rule.Source {
			if _, ok := peerGroups[g]; ok && srcRulesMap[rule.ID] == nil {
				srcRules = append(srcRules, rule)
				srcRulesMap[rule.ID] = rule
			}
		}
		for _, g := range rule.Destination {
			if _, ok := peerGroups[g]; ok && dstRulesMap[rule.ID] == nil {
				dstRules = append(dstRules, rule)
				dstRulesMap[rule.ID] = rule
			}
		}
	}

	return srcRules, dstRules
}

// GetGroup returns a group by ID if exists, nil otherwise
func (a *Account) GetGroup(groupID string) *Group {
	return a.Groups[groupID]
}

// GetPeers returns a list of all Account peers
func (a *Account) GetPeers() []*Peer {
	var peers []*Peer
	for _, peer := range a.Peers {
		peers = append(peers, peer)
	}
	return peers
}

// UpdatePeer saves new or replaces existing peer
func (a *Account) UpdatePeer(update *Peer) {
	//TODO Peer.ID migration: we will need to replace search by Peer.ID here
	a.Peers[update.Key] = update
}

// DeletePeer deletes peer from the account cleaning up all the references
func (a *Account) DeletePeer(peerPubKey string) {
	// TODO Peer.ID migration: we will need to replace search by Peer.ID here

	// delete peer from groups
	for _, g := range a.Groups {
		for i, pk := range g.Peers {
			if pk == peerPubKey {
				g.Peers = append(g.Peers[:i], g.Peers[i+1:]...)
				break
			}
		}
	}

	for _, r := range a.Routes {
		if r.Peer == peerPubKey {
			r.Enabled = false
			r.Peer = ""
		}
	}

	delete(a.Peers, peerPubKey)
	a.Network.IncSerial()
}

// FindPeerByPubKey looks for a Peer by provided WireGuard public key in the Account or returns error if it wasn't found.
// It will return an object copy of the peer.
func (a *Account) FindPeerByPubKey(peerPubKey string) (*Peer, error) {
	for _, peer := range a.Peers {
		if peer.Key == peerPubKey {
			return peer.Copy(), nil
		}
	}

	return nil, status.Errorf(status.NotFound, "peer with the public key %s not found", peerPubKey)
}

// FindUser looks for a given user in the Account or returns error if user wasn't found.
func (a *Account) FindUser(userID string) (*User, error) {
	user := a.Users[userID]
	if user == nil {
		return nil, status.Errorf(status.NotFound, "user %s not found", userID)
	}

	return user, nil
}

// FindSetupKey looks for a given SetupKey in the Account or returns error if it wasn't found.
func (a *Account) FindSetupKey(setupKey string) (*SetupKey, error) {
	key := a.SetupKeys[setupKey]
	if key == nil {
		return nil, status.Errorf(status.NotFound, "setup key not found")
	}

	return key, nil
}

func (a *Account) getUserGroups(userID string) ([]string, error) {
	user, err := a.FindUser(userID)
	if err != nil {
		return nil, err
	}
	return user.AutoGroups, nil
}

func (a *Account) getPeerDNSManagementStatus(peerID string) bool {
	peerGroups := a.getPeerGroups(peerID)
	enabled := true
	if a.DNSSettings != nil {
		for _, groupID := range a.DNSSettings.DisabledManagementGroups {
			_, found := peerGroups[groupID]
			if found {
				enabled = false
				break
			}
		}
	}
	return enabled
}

func (a *Account) getPeerGroups(peerID string) lookupMap {
	groupList := make(lookupMap)
	for groupID, group := range a.Groups {
		for _, id := range group.Peers {
			if id == peerID {
				groupList[groupID] = struct{}{}
				break
			}
		}
	}
	return groupList
}

func (a *Account) getSetupKeyGroups(setupKey string) ([]string, error) {
	key, err := a.FindSetupKey(setupKey)
	if err != nil {
		return nil, err
	}
	return key.AutoGroups, nil
}

func (a *Account) getTakenIPs() []net.IP {
	var takenIps []net.IP
	for _, existingPeer := range a.Peers {
		takenIps = append(takenIps, existingPeer.IP)
	}

	return takenIps
}

func (a *Account) getPeerDNSLabels() lookupMap {
	existingLabels := make(lookupMap)
	for _, peer := range a.Peers {
		if peer.DNSLabel != "" {
			existingLabels[peer.DNSLabel] = struct{}{}
		}
	}
	return existingLabels
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

	routes := map[string]*route.Route{}
	for id, route := range a.Routes {
		routes[id] = route.Copy()
	}

	nsGroups := map[string]*nbdns.NameServerGroup{}
	for id, nsGroup := range a.NameServerGroups {
		nsGroups[id] = nsGroup.Copy()
	}

	var dnsSettings *DNSSettings
	if a.DNSSettings != nil {
		dnsSettings = a.DNSSettings
	}

	return &Account{
		Id:                     a.Id,
		CreatedBy:              a.CreatedBy,
		Domain:                 a.Domain,
		DomainCategory:         a.DomainCategory,
		IsDomainPrimaryAccount: a.IsDomainPrimaryAccount,
		SetupKeys:              setupKeys,
		Network:                a.Network.Copy(),
		Peers:                  peers,
		Users:                  users,
		Groups:                 groups,
		Rules:                  rules,
		Routes:                 routes,
		NameServerGroups:       nsGroups,
		DNSSettings:            dnsSettings,
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
func BuildManager(store Store, peersUpdateManager *PeersUpdateManager, idpManager idp.Manager,
	singleAccountModeDomain string, dnsDomain string, eventStore activity.Store) (*DefaultAccountManager, error) {
	am := &DefaultAccountManager{
		Store:              store,
		peersUpdateManager: peersUpdateManager,
		idpManager:         idpManager,
		ctx:                context.Background(),
		cacheMux:           sync.Mutex{},
		cacheLoading:       map[string]chan struct{}{},
		dnsDomain:          dnsDomain,
		eventStore:         eventStore,
	}
	allAccounts := store.GetAllAccounts()
	// enable single account mode only if configured by user and number of existing accounts is not grater than 1
	am.singleAccountMode = singleAccountModeDomain != "" && len(allAccounts) <= 1
	if am.singleAccountMode {
		if !isDomainValid(singleAccountModeDomain) {
			return nil, status.Errorf(status.InvalidArgument, "invalid domain \"%s\" provided for single accound mode. Please review your input for --single-account-mode-domain", singleAccountModeDomain)
		}
		am.singleAccountModeDomain = singleAccountModeDomain
		log.Infof("single account mode enabled, accounts number %d", len(allAccounts))
	} else {
		log.Infof("single account mode disabled, accounts number %d", len(allAccounts))
	}

	// if account doesn't have a default group
	// we create 'all' group and add all peers into it
	// also we create default rule with source as destination
	for _, account := range allAccounts {
		shouldSave := false

		_, err := account.GetGroupAll()
		if err != nil {
			addAllGroup(account)
			shouldSave = true
		}

		if shouldSave {
			err = store.SaveAccount(account)
			if err != nil {
				return nil, err
			}
		}
	}

	goCacheClient := gocache.New(CacheExpirationMax, 30*time.Minute)
	goCacheStore := cacheStore.NewGoCache(goCacheClient)

	am.cacheManager = cache.NewLoadable[[]*idp.UserData](am.loadAccount, cache.New[[]*idp.UserData](goCacheStore))

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
		} else if statusErr.Type() == status.NotFound {
			newAccount := newAccountWithId(accountId, userID, domain)
			am.storeEvent(userID, newAccount.Id, accountId, activity.AccountCreated, nil)
			return newAccount, nil
		} else {
			return nil, err
		}
	}

	return nil, status.Errorf(status.Internal, "error while creating new account")
}

func (am *DefaultAccountManager) warmupIDPCache() error {
	userData, err := am.idpManager.GetAllAccounts()
	if err != nil {
		return err
	}

	for accountID, users := range userData {
		err = am.cacheManager.Set(am.ctx, accountID, users, cacheStore.WithExpiration(cacheEntryExpiration()))
		if err != nil {
			return err
		}
	}
	log.Infof("warmed up IDP cache with %d entries", len(userData))
	return nil
}

// GetAccountByUserOrAccountID looks for an account by user or accountID, if no account is provided and
// userID doesn't have an account associated with it, one account is created
func (am *DefaultAccountManager) GetAccountByUserOrAccountID(userID, accountID, domain string) (*Account, error) {
	if accountID != "" {
		return am.Store.GetAccount(accountID)
	} else if userID != "" {
		account, err := am.GetOrCreateAccountByUser(userID, domain)
		if err != nil {
			return nil, status.Errorf(status.NotFound, "account not found using user id: %s", userID)
		}
		err = am.addAccountIDToIDPAppMeta(userID, account)
		if err != nil {
			return nil, err
		}
		return account, nil
	}

	return nil, status.Errorf(status.NotFound, "no valid user or account Id provided")
}

func isNil(i idp.Manager) bool {
	return i == nil || reflect.ValueOf(i).IsNil()
}

// addAccountIDToIDPAppMeta update user's  app metadata in idp manager
func (am *DefaultAccountManager) addAccountIDToIDPAppMeta(userID string, account *Account) error {
	if !isNil(am.idpManager) {

		// user can be nil if it wasn't found (e.g., just created)
		user, err := am.lookupUserInCache(userID, account)
		if err != nil {
			return err
		}

		if user != nil && user.AppMetadata.WTAccountID == account.Id {
			// it was already set, so we skip the unnecessary update
			log.Debugf("skipping IDP App Meta update because accountID %s has been already set for user %s",
				account.Id, userID)
			return nil
		}

		err = am.idpManager.UpdateUserAppMetadata(userID, idp.AppMetadata{WTAccountID: account.Id})
		if err != nil {
			return err
		}

		if err != nil {
			return status.Errorf(status.Internal, "updating user's app metadata failed with: %v", err)
		}
		// refresh cache to reflect the update
		_, err = am.refreshCache(account.Id)
		if err != nil {
			return err
		}
	}
	return nil
}

func (am *DefaultAccountManager) loadAccount(_ context.Context, accountID interface{}) ([]*idp.UserData, error) {
	log.Debugf("account %s not found in cache, reloading", accountID)
	return am.idpManager.GetAccount(fmt.Sprintf("%v", accountID))
}

func (am *DefaultAccountManager) lookupUserInCacheByEmail(email string, accountID string) (*idp.UserData, error) {
	data, err := am.getAccountFromCache(accountID, false)
	if err != nil {
		return nil, err
	}

	for _, datum := range data {
		if datum.Email == email {
			return datum, nil
		}
	}

	return nil, nil

}

// lookupUserInCache looks up user in the IdP cache and returns it. If the user wasn't found, the function returns nil
func (am *DefaultAccountManager) lookupUserInCache(userID string, account *Account) (*idp.UserData, error) {
	users := make(map[string]struct{}, len(account.Users))
	for _, user := range account.Users {
		users[user.Id] = struct{}{}
	}
	log.Debugf("looking up user %s of account %s in cache", userID, account.Id)
	userData, err := am.lookupCache(users, account.Id)
	if err != nil {
		return nil, err
	}

	for _, datum := range userData {
		if datum.ID == userID {
			return datum, nil
		}
	}

	return nil, nil
}

func (am *DefaultAccountManager) refreshCache(accountID string) ([]*idp.UserData, error) {
	return am.getAccountFromCache(accountID, true)
}

// getAccountFromCache returns user data for a given account ensuring that cache load happens only once
func (am *DefaultAccountManager) getAccountFromCache(accountID string, forceReload bool) ([]*idp.UserData, error) {
	am.cacheMux.Lock()
	loadingChan := am.cacheLoading[accountID]
	if loadingChan == nil {
		loadingChan = make(chan struct{})
		am.cacheLoading[accountID] = loadingChan
		am.cacheMux.Unlock()

		defer func() {
			am.cacheMux.Lock()
			delete(am.cacheLoading, accountID)
			close(loadingChan)
			am.cacheMux.Unlock()
		}()

		if forceReload {
			err := am.cacheManager.Delete(am.ctx, accountID)
			if err != nil {
				return nil, err
			}
		}

		return am.cacheManager.Get(am.ctx, accountID)
	}
	am.cacheMux.Unlock()

	log.Debugf("one request to get account %s is already running", accountID)

	select {
	case <-loadingChan:
		// channel has been closed meaning cache was loaded => simply return from cache
		return am.cacheManager.Get(am.ctx, accountID)
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("timeout while waiting for account %s cache to reload", accountID)
	}
}

func (am *DefaultAccountManager) lookupCache(accountUsers map[string]struct{}, accountID string) ([]*idp.UserData, error) {
	data, err := am.getAccountFromCache(accountID, false)
	if err != nil {
		return nil, err
	}

	userDataMap := make(map[string]struct{})
	for _, datum := range data {
		userDataMap[datum.ID] = struct{}{}
	}

	// check whether we need to reload the cache
	// the accountUsers ID list is the source of truth and all the users should be in the cache
	reload := len(accountUsers) != len(data)
	for user := range accountUsers {
		if _, ok := userDataMap[user]; !ok {
			reload = true
		}
	}

	if reload {
		// reload cache once avoiding loops
		data, err = am.refreshCache(accountID)
		if err != nil {
			return nil, err
		}
	}

	return data, err
}

// updateAccountDomainAttributes updates the account domain attributes and then, saves the account
func (am *DefaultAccountManager) updateAccountDomainAttributes(account *Account, claims jwtclaims.AuthorizationClaims,
	primaryDomain bool) error {
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
		return err
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
	err = am.addAccountIDToIDPAppMeta(claims.UserId, existingAcc)
	if err != nil {
		return err
	}

	return nil
}

// handleNewUserAccount validates if there is an existing primary account for the domain, if so it adds the new user to that account,
// otherwise it will create a new account and make it primary account for the domain.
func (am *DefaultAccountManager) handleNewUserAccount(domainAcc *Account, claims jwtclaims.AuthorizationClaims) (*Account, error) {
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
			return nil, err
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

	err = am.addAccountIDToIDPAppMeta(claims.UserId, account)
	if err != nil {
		return nil, err
	}

	am.storeEvent(claims.UserId, claims.UserId, account.Id, activity.UserJoined, nil)

	return account, nil
}

// redeemInvite checks whether user has been invited and redeems the invite
func (am *DefaultAccountManager) redeemInvite(account *Account, userID string) error {
	// only possible with the enabled IdP manager
	if am.idpManager == nil {
		log.Warnf("invites only work with enabled IdP manager")
		return nil
	}

	user, err := am.lookupUserInCache(userID, account)
	if err != nil {
		return err
	}

	if user == nil {
		return status.Errorf(status.NotFound, "user %s not found in the IdP", userID)
	}

	if user.AppMetadata.WTPendingInvite != nil && *user.AppMetadata.WTPendingInvite {
		log.Infof("redeeming invite for user %s account %s", userID, account.Id)
		// User has already logged in, meaning that IdP should have set wt_pending_invite to false.
		// Our job is to just reload cache.
		go func() {
			_, err = am.refreshCache(account.Id)
			if err != nil {
				log.Warnf("failed reloading cache when redeeming user %s under account %s", userID, account.Id)
				return
			}
			log.Debugf("user %s of account %s redeemed invite", user.ID, account.Id)
			am.storeEvent(userID, userID, account.Id, activity.UserJoined, nil)
		}()
	}

	return nil
}

// GetAccountFromToken returns an account associated with this token
func (am *DefaultAccountManager) GetAccountFromToken(claims jwtclaims.AuthorizationClaims) (*Account, *User, error) {

	if am.singleAccountMode && am.singleAccountModeDomain != "" {
		// This section is mostly related to self-hosted installations.
		// We override incoming domain claims to group users under a single account.
		claims.Domain = am.singleAccountModeDomain
		claims.DomainCategory = PrivateCategory
		log.Infof("overriding JWT Domain and DomainCategory claims since single account mode is enabled")
	}

	account, err := am.getAccountWithAuthorizationClaims(claims)
	if err != nil {
		return nil, nil, err
	}

	user := account.Users[claims.UserId]
	if user == nil {
		// this is not really possible because we got an account by user ID
		return nil, nil, status.Errorf(status.NotFound, "user %s not found", claims.UserId)
	}

	err = am.redeemInvite(account, claims.UserId)
	if err != nil {
		return nil, nil, err
	}

	return account, user, nil
}

// getAccountWithAuthorizationClaims retrievs an account using JWT Claims.
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
func (am *DefaultAccountManager) getAccountWithAuthorizationClaims(claims jwtclaims.AuthorizationClaims) (*Account, error) {
	// if Account ID is part of the claims
	// it means that we've already classified the domain and user has an account
	if claims.DomainCategory != PrivateCategory || !isDomainValid(claims.Domain) {
		return am.GetAccountByUserOrAccountID(claims.UserId, claims.AccountId, claims.Domain)
	} else if claims.AccountId != "" {
		accountFromID, err := am.Store.GetAccount(claims.AccountId)
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

	unlock := am.Store.AcquireGlobalLock()
	defer unlock()

	// We checked if the domain has a primary account already
	domainAccount, err := am.Store.GetAccountByPrivateDomain(claims.Domain)
	if err != nil {
		// if NotFound we are good to continue, otherwise return error
		e, ok := status.FromError(err)
		if !ok || e.Type() != status.NotFound {
			return nil, err
		}
	}

	account, err := am.Store.GetAccountByUser(claims.UserId)
	if err == nil {
		err = am.handleExistingUserAccount(account, domainAccount, claims)
		if err != nil {
			return nil, err
		}
		return account, nil
	} else if s, ok := status.FromError(err); ok && s.Type() == status.NotFound {
		return am.handleNewUserAccount(domainAccount, claims)
	} else {
		// other error
		return nil, err
	}
}

func isDomainValid(domain string) bool {
	re := regexp.MustCompile(`^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$`)
	return re.Match([]byte(domain))
}

// AccountExists checks whether account exists (returns true) or not (returns false)
func (am *DefaultAccountManager) AccountExists(accountID string) (*bool, error) {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	var res bool
	_, err := am.Store.GetAccount(accountID)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Type() == status.NotFound {
			res = false
			return &res, nil
		} else {
			return nil, err
		}
	}

	res = true
	return &res, nil
}

// GetDNSDomain returns the configured dnsDomain
func (am *DefaultAccountManager) GetDNSDomain() string {
	return am.dnsDomain
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
	oneOffKey := GenerateSetupKey("One-off key", SetupKeyOneOff, DefaultSetupKeyDuration, []string{},
		SetupKeyUnlimitedUsage)
	setupKeys[defaultKey.Key] = defaultKey
	setupKeys[oneOffKey.Key] = oneOffKey
	network := NewNetwork()
	peers := make(map[string]*Peer)
	users := make(map[string]*User)
	routes := make(map[string]*route.Route)
	nameServersGroups := make(map[string]*nbdns.NameServerGroup)
	users[userId] = NewAdminUser(userId)
	dnsSettings := &DNSSettings{
		DisabledManagementGroups: make([]string, 0),
	}
	log.Debugf("created new account %s with setup key %s", accountId, defaultKey.Key)

	acc := &Account{
		Id:               accountId,
		SetupKeys:        setupKeys,
		Network:          network,
		Peers:            peers,
		Users:            users,
		CreatedBy:        userId,
		Domain:           domain,
		Routes:           routes,
		NameServerGroups: nameServersGroups,
		DNSSettings:      dnsSettings,
	}

	addAllGroup(acc)
	return acc
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
