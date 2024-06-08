package server

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"hash/crc32"
	"math/rand"
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/eko/gocache/v3/cache"
	cacheStore "github.com/eko/gocache/v3/store"
	gocache "github.com/patrickmn/go-cache"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/base62"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/geolocation"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/integrated_validator"
	"github.com/netbirdio/netbird/management/server/integration_reference"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/route"
)

const (
	PublicCategory             = "public"
	PrivateCategory            = "private"
	UnknownCategory            = "unknown"
	CacheExpirationMax         = 7 * 24 * 3600 * time.Second // 7 days
	CacheExpirationMin         = 3 * 24 * 3600 * time.Second // 3 days
	DefaultPeerLoginExpiration = 24 * time.Hour
)

type userLoggedInOnce bool

type ExternalCacheManager cache.CacheInterface[*idp.UserData]

func cacheEntryExpiration() time.Duration {
	r := rand.Intn(int(CacheExpirationMax.Milliseconds()-CacheExpirationMin.Milliseconds())) + int(CacheExpirationMin.Milliseconds())
	return time.Duration(r) * time.Millisecond
}

type AccountManager interface {
	GetOrCreateAccountByUser(userId, domain string) (*Account, error)
	CreateSetupKey(accountID string, keyName string, keyType SetupKeyType, expiresIn time.Duration,
		autoGroups []string, usageLimit int, userID string, ephemeral bool) (*SetupKey, error)
	SaveSetupKey(accountID string, key *SetupKey, userID string) (*SetupKey, error)
	CreateUser(accountID, initiatorUserID string, key *UserInfo) (*UserInfo, error)
	DeleteUser(accountID, initiatorUserID string, targetUserID string) error
	InviteUser(accountID string, initiatorUserID string, targetUserID string) error
	ListSetupKeys(accountID, userID string) ([]*SetupKey, error)
	SaveUser(accountID, initiatorUserID string, update *User) (*UserInfo, error)
	SaveOrAddUser(accountID, initiatorUserID string, update *User, addIfNotExists bool) (*UserInfo, error)
	GetSetupKey(accountID, userID, keyID string) (*SetupKey, error)
	GetAccountByUserOrAccountID(userID, accountID, domain string) (*Account, error)
	GetAccountFromToken(claims jwtclaims.AuthorizationClaims) (*Account, *User, error)
	CheckUserAccessByJWTGroups(claims jwtclaims.AuthorizationClaims) error
	GetAccountFromPAT(pat string) (*Account, *User, *PersonalAccessToken, error)
	DeleteAccount(accountID, userID string) error
	MarkPATUsed(tokenID string) error
	GetUser(claims jwtclaims.AuthorizationClaims) (*User, error)
	ListUsers(accountID string) ([]*User, error)
	GetPeers(accountID, userID string) ([]*nbpeer.Peer, error)
	MarkPeerConnected(peerKey string, connected bool, realIP net.IP, account *Account) error
	DeletePeer(accountID, peerID, userID string) error
	UpdatePeer(accountID, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, error)
	GetNetworkMap(peerID string) (*NetworkMap, error)
	GetPeerNetwork(peerID string) (*Network, error)
	AddPeer(setupKey, userID string, peer *nbpeer.Peer) (*nbpeer.Peer, *NetworkMap, error)
	CreatePAT(accountID string, initiatorUserID string, targetUserID string, tokenName string, expiresIn int) (*PersonalAccessTokenGenerated, error)
	DeletePAT(accountID string, initiatorUserID string, targetUserID string, tokenID string) error
	GetPAT(accountID string, initiatorUserID string, targetUserID string, tokenID string) (*PersonalAccessToken, error)
	GetAllPATs(accountID string, initiatorUserID string, targetUserID string) ([]*PersonalAccessToken, error)
	UpdatePeerSSHKey(peerID string, sshKey string) error
	GetUsersFromAccount(accountID, userID string) ([]*UserInfo, error)
	GetGroup(accountId, groupID, userID string) (*nbgroup.Group, error)
	GetAllGroups(accountID, userID string) ([]*nbgroup.Group, error)
	GetGroupByName(groupName, accountID string) (*nbgroup.Group, error)
	SaveGroup(accountID, userID string, group *nbgroup.Group) error
	DeleteGroup(accountId, userId, groupID string) error
	ListGroups(accountId string) ([]*nbgroup.Group, error)
	GroupAddPeer(accountId, groupID, peerID string) error
	GroupDeletePeer(accountId, groupID, peerID string) error
	GetPolicy(accountID, policyID, userID string) (*Policy, error)
	SavePolicy(accountID, userID string, policy *Policy) error
	DeletePolicy(accountID, policyID, userID string) error
	ListPolicies(accountID, userID string) ([]*Policy, error)
	GetRoute(accountID string, routeID route.ID, userID string) (*route.Route, error)
	CreateRoute(accountID, prefix, peerID string, peerGroupIDs []string, description string, netID route.NetID, masquerade bool, metric int, groups []string, enabled bool, userID string) (*route.Route, error)
	SaveRoute(accountID, userID string, route *route.Route) error
	DeleteRoute(accountID string, routeID route.ID, userID string) error
	ListRoutes(accountID, userID string) ([]*route.Route, error)
	GetNameServerGroup(accountID, userID, nsGroupID string) (*nbdns.NameServerGroup, error)
	CreateNameServerGroup(accountID string, name, description string, nameServerList []nbdns.NameServer, groups []string, primary bool, domains []string, enabled bool, userID string, searchDomainsEnabled bool) (*nbdns.NameServerGroup, error)
	SaveNameServerGroup(accountID, userID string, nsGroupToSave *nbdns.NameServerGroup) error
	DeleteNameServerGroup(accountID, nsGroupID, userID string) error
	ListNameServerGroups(accountID string, userID string) ([]*nbdns.NameServerGroup, error)
	GetDNSDomain() string
	StoreEvent(initiatorID, targetID, accountID string, activityID activity.ActivityDescriber, meta map[string]any)
	GetEvents(accountID, userID string) ([]*activity.Event, error)
	GetDNSSettings(accountID string, userID string) (*DNSSettings, error)
	SaveDNSSettings(accountID string, userID string, dnsSettingsToSave *DNSSettings) error
	GetPeer(accountID, peerID, userID string) (*nbpeer.Peer, error)
	UpdateAccountSettings(accountID, userID string, newSettings *Settings) (*Account, error)
	LoginPeer(login PeerLogin) (*nbpeer.Peer, *NetworkMap, error)                // used by peer gRPC API
	SyncPeer(sync PeerSync, account *Account) (*nbpeer.Peer, *NetworkMap, error) // used by peer gRPC API
	GetAllConnectedPeers() (map[string]struct{}, error)
	HasConnectedChannel(peerID string) bool
	GetExternalCacheManager() ExternalCacheManager
	GetPostureChecks(accountID, postureChecksID, userID string) (*posture.Checks, error)
	SavePostureChecks(accountID, userID string, postureChecks *posture.Checks) error
	DeletePostureChecks(accountID, postureChecksID, userID string) error
	ListPostureChecks(accountID, userID string) ([]*posture.Checks, error)
	GetIdpManager() idp.Manager
	UpdateIntegratedValidatorGroups(accountID string, userID string, groups []string) error
	GroupValidation(accountId string, groups []string) (bool, error)
	GetValidatedPeers(account *Account) (map[string]struct{}, error)
	SyncAndMarkPeer(peerPubKey string, realIP net.IP) (*nbpeer.Peer, *NetworkMap, error)
	CancelPeerRoutines(peer *nbpeer.Peer) error
	FindExistingPostureCheck(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error)
}

type DefaultAccountManager struct {
	Store Store
	// cacheMux and cacheLoading helps to make sure that only a single cache reload runs at a time per accountID
	cacheMux sync.Mutex
	// cacheLoading keeps the accountIDs that are currently reloading. The accountID has to be removed once cache has been reloaded
	cacheLoading         map[string]chan struct{}
	peersUpdateManager   *PeersUpdateManager
	idpManager           idp.Manager
	cacheManager         cache.CacheInterface[[]*idp.UserData]
	externalCacheManager ExternalCacheManager
	ctx                  context.Context
	eventStore           activity.Store
	geo                  *geolocation.Geolocation

	// singleAccountMode indicates whether the instance has a single account.
	// If true, then every new user will end up under the same account.
	// This value will be set to false if management service has more than one account.
	singleAccountMode bool
	// singleAccountModeDomain is a domain to use in singleAccountMode setup
	singleAccountModeDomain string
	// dnsDomain is used for peer resolution. This is appended to the peer's name
	dnsDomain       string
	peerLoginExpiry Scheduler

	// userDeleteFromIDPEnabled allows to delete user from IDP when user is deleted from account
	userDeleteFromIDPEnabled bool

	integratedPeerValidator integrated_validator.IntegratedValidator
}

// Settings represents Account settings structure that can be modified via API and Dashboard
type Settings struct {
	// PeerLoginExpirationEnabled globally enables or disables peer login expiration
	PeerLoginExpirationEnabled bool

	// PeerLoginExpiration is a setting that indicates when peer login expires.
	// Applies to all peers that have Peer.LoginExpirationEnabled set to true.
	PeerLoginExpiration time.Duration

	// RegularUsersViewBlocked allows to block regular users from viewing even their own peers and some UI elements
	RegularUsersViewBlocked bool

	// GroupsPropagationEnabled allows to propagate auto groups from the user to the peer
	GroupsPropagationEnabled bool

	// JWTGroupsEnabled allows extract groups from JWT claim, which name defined in the JWTGroupsClaimName
	// and add it to account groups.
	JWTGroupsEnabled bool

	// JWTGroupsClaimName from which we extract groups name to add it to account groups
	JWTGroupsClaimName string

	// JWTAllowGroups list of groups to which users are allowed access
	JWTAllowGroups []string `gorm:"serializer:json"`

	// Extra is a dictionary of Account settings
	Extra *account.ExtraSettings `gorm:"embedded;embeddedPrefix:extra_"`
}

// Copy copies the Settings struct
func (s *Settings) Copy() *Settings {
	settings := &Settings{
		PeerLoginExpirationEnabled: s.PeerLoginExpirationEnabled,
		PeerLoginExpiration:        s.PeerLoginExpiration,
		JWTGroupsEnabled:           s.JWTGroupsEnabled,
		JWTGroupsClaimName:         s.JWTGroupsClaimName,
		GroupsPropagationEnabled:   s.GroupsPropagationEnabled,
		JWTAllowGroups:             s.JWTAllowGroups,
		RegularUsersViewBlocked:    s.RegularUsersViewBlocked,
	}
	if s.Extra != nil {
		settings.Extra = s.Extra.Copy()
	}
	return settings
}

// Account represents a unique account of the system
type Account struct {
	// we have to name column to aid as it collides with Network.Id when work with associations
	Id string `gorm:"primaryKey"`

	// User.Id it was created by
	CreatedBy              string
	CreatedAt              time.Time
	Domain                 string `gorm:"index"`
	DomainCategory         string
	IsDomainPrimaryAccount bool
	SetupKeys              map[string]*SetupKey              `gorm:"-"`
	SetupKeysG             []SetupKey                        `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Network                *Network                          `gorm:"embedded;embeddedPrefix:network_"`
	Peers                  map[string]*nbpeer.Peer           `gorm:"-"`
	PeersG                 []nbpeer.Peer                     `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Users                  map[string]*User                  `gorm:"-"`
	UsersG                 []User                            `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Groups                 map[string]*nbgroup.Group         `gorm:"-"`
	GroupsG                []nbgroup.Group                   `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Policies               []*Policy                         `gorm:"foreignKey:AccountID;references:id"`
	Routes                 map[route.ID]*route.Route         `gorm:"-"`
	RoutesG                []route.Route                     `json:"-" gorm:"foreignKey:AccountID;references:id"`
	NameServerGroups       map[string]*nbdns.NameServerGroup `gorm:"-"`
	NameServerGroupsG      []nbdns.NameServerGroup           `json:"-" gorm:"foreignKey:AccountID;references:id"`
	DNSSettings            DNSSettings                       `gorm:"embedded;embeddedPrefix:dns_settings_"`
	PostureChecks          []*posture.Checks                 `gorm:"foreignKey:AccountID;references:id"`
	// Settings is a dictionary of Account settings
	Settings *Settings `gorm:"embedded;embeddedPrefix:settings_"`
}

// Subclass used in gorm to only load settings and not whole account
type AccountSettings struct {
	Settings *Settings `gorm:"embedded;embeddedPrefix:settings_"`
}

type UserPermissions struct {
	DashboardView string `json:"dashboard_view"`
}

type UserInfo struct {
	ID                   string                                     `json:"id"`
	Email                string                                     `json:"email"`
	Name                 string                                     `json:"name"`
	Role                 string                                     `json:"role"`
	AutoGroups           []string                                   `json:"auto_groups"`
	Status               string                                     `json:"-"`
	IsServiceUser        bool                                       `json:"is_service_user"`
	IsBlocked            bool                                       `json:"is_blocked"`
	NonDeletable         bool                                       `json:"non_deletable"`
	LastLogin            time.Time                                  `json:"last_login"`
	Issued               string                                     `json:"issued"`
	IntegrationReference integration_reference.IntegrationReference `json:"-"`
	Permissions          UserPermissions                            `json:"permissions"`
}

// getRoutesToSync returns the enabled routes for the peer ID and the routes
// from the ACL peers that have distribution groups associated with the peer ID.
// Please mind, that the returned route.Route objects will contain Peer.Key instead of Peer.ID.
func (a *Account) getRoutesToSync(peerID string, aclPeers []*nbpeer.Peer) []*route.Route {
	routes, peerDisabledRoutes := a.getRoutingPeerRoutes(peerID)
	peerRoutesMembership := make(lookupMap)
	for _, r := range append(routes, peerDisabledRoutes...) {
		peerRoutesMembership[string(route.GetHAUniqueID(r))] = struct{}{}
	}

	groupListMap := a.getPeerGroups(peerID)
	for _, peer := range aclPeers {
		activeRoutes, _ := a.getRoutingPeerRoutes(peer.ID)
		addressFamilyFilteredRoutes := a.filterRoutesByIPv6Enabled(activeRoutes, a.GetPeer(peerID).IP6 != nil && peer.IP6 != nil)
		groupFilteredRoutes := a.filterRoutesByGroups(addressFamilyFilteredRoutes, groupListMap)
		filteredRoutes := a.filterRoutesFromPeersOfSameHAGroup(groupFilteredRoutes, peerRoutesMembership)
		routes = append(routes, filteredRoutes...)
	}

	return routes
}

// filterRoutesFromPeersOfSameHAGroup filters and returns a list of routes that don't share the same HA route membership
func (a *Account) filterRoutesFromPeersOfSameHAGroup(routes []*route.Route, peerMemberships lookupMap) []*route.Route {
	var filteredRoutes []*route.Route
	for _, r := range routes {
		_, found := peerMemberships[string(route.GetHAUniqueID(r))]
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

// Filters out IPv6 routes if the peer does not support them.
func (a *Account) filterRoutesByIPv6Enabled(routes []*route.Route, v6Supported bool) []*route.Route {
	if v6Supported {
		return routes
	}
	var filteredRoutes []*route.Route
	for _, rt := range routes {
		if rt.Network.Addr().Is4() {
			filteredRoutes = append(filteredRoutes, rt)
		}
	}
	return filteredRoutes
}

// getRoutingPeerRoutes returns the enabled and disabled lists of routes that the given routing peer serves
// Please mind, that the returned route.Route objects will contain Peer.Key instead of Peer.ID.
// If the given is not a routing peer, then the lists are empty.
func (a *Account) getRoutingPeerRoutes(peerID string) (enabledRoutes []*route.Route, disabledRoutes []*route.Route) {

	peer := a.GetPeer(peerID)
	if peer == nil {
		log.Errorf("peer %s that doesn't exist under account %s", peerID, a.Id)
		return enabledRoutes, disabledRoutes
	}

	// currently we support only linux routing peers
	if peer.Meta.GoOS != "linux" {
		return enabledRoutes, disabledRoutes
	}

	seenRoute := make(map[route.ID]struct{})

	takeRoute := func(r *route.Route, id string) {
		if _, ok := seenRoute[r.ID]; ok {
			return
		}
		seenRoute[r.ID] = struct{}{}

		if r.Enabled {
			r.Peer = peer.Key
			enabledRoutes = append(enabledRoutes, r)
			return
		}
		disabledRoutes = append(disabledRoutes, r)
	}

	for _, r := range a.Routes {
		// Skip IPv6 routes if IPv6 is currently not enabled.
		if peer.IP6 == nil && r.NetworkType == route.IPv6Network {
			continue
		}
		for _, groupID := range r.PeerGroups {
			group := a.GetGroup(groupID)
			if group == nil {
				log.Errorf("route %s has peers group %s that doesn't exist under account %s", r.ID, groupID, a.Id)
				continue
			}
			for _, id := range group.Peers {
				if id != peerID {
					continue
				}

				newPeerRoute := r.Copy()
				newPeerRoute.Peer = id
				newPeerRoute.PeerGroups = nil
				newPeerRoute.ID = route.ID(string(r.ID) + ":" + id) // we have to provide unique route id when distribute network map
				takeRoute(newPeerRoute, id)
				break
			}
		}
		if r.Peer == peerID {
			takeRoute(r.Copy(), peerID)
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

// GetGroup returns a group by ID if exists, nil otherwise
func (a *Account) GetGroup(groupID string) *nbgroup.Group {
	return a.Groups[groupID]
}

// GetPeerNetworkMap returns a group by ID if exists, nil otherwise
func (a *Account) GetPeerNetworkMap(peerID, dnsDomain string, validatedPeersMap map[string]struct{}) *NetworkMap {
	peer := a.Peers[peerID]
	if peer == nil {
		return &NetworkMap{
			Network: a.Network.Copy(),
		}
	}

	if _, ok := validatedPeersMap[peerID]; !ok {
		return &NetworkMap{
			Network: a.Network.Copy(),
		}
	}

	aclPeers, firewallRules := a.getPeerConnectionResources(peerID, validatedPeersMap)
	// exclude expired peers
	var peersToConnect []*nbpeer.Peer
	var expiredPeers []*nbpeer.Peer
	for _, p := range aclPeers {
		expired, _ := p.LoginExpired(a.Settings.PeerLoginExpiration)
		if a.Settings.PeerLoginExpirationEnabled && expired {
			expiredPeers = append(expiredPeers, p)
			continue
		}
		peersToConnect = append(peersToConnect, p)
	}

	routesUpdate := a.getRoutesToSync(peerID, peersToConnect)

	dnsManagementStatus := a.getPeerDNSManagementStatus(peerID)
	dnsUpdate := nbdns.Config{
		ServiceEnable: dnsManagementStatus,
	}

	if dnsManagementStatus {
		var zones []nbdns.CustomZone
		peersCustomZone := getPeersCustomZone(a, dnsDomain, peer.IP6 != nil)
		if peersCustomZone.Domain != "" {
			zones = append(zones, peersCustomZone)
		}
		dnsUpdate.CustomZones = zones
		dnsUpdate.NameServerGroups = getPeerNSGroups(a, peerID)
	}

	return &NetworkMap{
		Peers:         peersToConnect,
		Network:       a.Network.Copy(),
		Routes:        routesUpdate,
		DNSConfig:     dnsUpdate,
		OfflinePeers:  expiredPeers,
		FirewallRules: firewallRules,
	}
}

// GetExpiredPeers returns peers that have been expired
func (a *Account) GetExpiredPeers() []*nbpeer.Peer {
	var peers []*nbpeer.Peer
	for _, peer := range a.GetPeersWithExpiration() {
		expired, _ := peer.LoginExpired(a.Settings.PeerLoginExpiration)
		if expired {
			peers = append(peers, peer)
		}
	}

	return peers
}

// GetNextPeerExpiration returns the minimum duration in which the next peer of the account will expire if it was found.
// If there is no peer that expires this function returns false and a duration of 0.
// This function only considers peers that haven't been expired yet and that are connected.
func (a *Account) GetNextPeerExpiration() (time.Duration, bool) {
	peersWithExpiry := a.GetPeersWithExpiration()
	if len(peersWithExpiry) == 0 {
		return 0, false
	}
	var nextExpiry *time.Duration
	for _, peer := range peersWithExpiry {
		// consider only connected peers because others will require login on connecting to the management server
		if peer.Status.LoginExpired || !peer.Status.Connected {
			continue
		}
		_, duration := peer.LoginExpired(a.Settings.PeerLoginExpiration)
		if nextExpiry == nil || duration < *nextExpiry {
			// if expiration is below 1s return 1s duration
			// this avoids issues with ticker that can't be set to < 0
			if duration < time.Second {
				return time.Second, true
			}
			nextExpiry = &duration
		}
	}

	if nextExpiry == nil {
		return 0, false
	}

	return *nextExpiry, true
}

// GetPeersWithExpiration returns a list of peers that have Peer.LoginExpirationEnabled set to true and that were added by a user
func (a *Account) GetPeersWithExpiration() []*nbpeer.Peer {
	peers := make([]*nbpeer.Peer, 0)
	for _, peer := range a.Peers {
		if peer.LoginExpirationEnabled && peer.AddedWithSSOLogin() {
			peers = append(peers, peer)
		}
	}
	return peers
}

// GetPeers returns a list of all Account peers
func (a *Account) GetPeers() []*nbpeer.Peer {
	var peers []*nbpeer.Peer
	for _, peer := range a.Peers {
		peers = append(peers, peer)
	}
	return peers
}

// UpdateSettings saves new account settings
func (a *Account) UpdateSettings(update *Settings) *Account {
	a.Settings = update.Copy()
	return a
}

// UpdatePeer saves new or replaces existing peer
func (a *Account) UpdatePeer(update *nbpeer.Peer) {
	a.Peers[update.ID] = update
}

// DeletePeer deletes peer from the account cleaning up all the references
func (a *Account) DeletePeer(peerID string) {
	// delete peer from groups
	for _, g := range a.Groups {
		for i, pk := range g.Peers {
			if pk == peerID {
				g.Peers = append(g.Peers[:i], g.Peers[i+1:]...)
				break
			}
		}
	}

	for _, r := range a.Routes {
		if r.Peer == peerID {
			r.Enabled = false
			r.Peer = ""
		}
	}

	delete(a.Peers, peerID)
	a.Network.IncSerial()
}

// FindPeerByPubKey looks for a Peer by provided WireGuard public key in the Account or returns error if it wasn't found.
// It will return an object copy of the peer.
func (a *Account) FindPeerByPubKey(peerPubKey string) (*nbpeer.Peer, error) {
	for _, peer := range a.Peers {
		if peer.Key == peerPubKey {
			return peer.Copy(), nil
		}
	}

	return nil, status.Errorf(status.NotFound, "peer with the public key %s not found", peerPubKey)
}

// FindUserPeers returns a list of peers that user owns (created)
func (a *Account) FindUserPeers(userID string) ([]*nbpeer.Peer, error) {
	peers := make([]*nbpeer.Peer, 0)
	for _, peer := range a.Peers {
		if peer.UserID == userID {
			peers = append(peers, peer)
		}
	}

	return peers, nil
}

// FindUser looks for a given user in the Account or returns error if user wasn't found.
func (a *Account) FindUser(userID string) (*User, error) {
	user := a.Users[userID]
	if user == nil {
		return nil, status.Errorf(status.NotFound, "user %s not found", userID)
	}

	return user, nil
}

// FindGroupByName looks for a given group in the Account by name or returns error if the group wasn't found.
func (a *Account) FindGroupByName(groupName string) (*nbgroup.Group, error) {
	for _, group := range a.Groups {
		if group.Name == groupName {
			return group, nil
		}
	}
	return nil, status.Errorf(status.NotFound, "group %s not found", groupName)
}

// FindSetupKey looks for a given SetupKey in the Account or returns error if it wasn't found.
func (a *Account) FindSetupKey(setupKey string) (*SetupKey, error) {
	key := a.SetupKeys[setupKey]
	if key == nil {
		return nil, status.Errorf(status.NotFound, "setup key not found")
	}

	return key, nil
}

// GetPeerGroupsList return with the list of groups ID.
func (a *Account) GetPeerGroupsList(peerID string) []string {
	var grps []string
	for groupID, group := range a.Groups {
		for _, id := range group.Peers {
			if id == peerID {
				grps = append(grps, groupID)
				break
			}
		}
	}
	return grps
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
	for _, groupID := range a.DNSSettings.DisabledManagementGroups {
		_, found := peerGroups[groupID]
		if found {
			enabled = false
			break
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

func (a *Account) getTakenIP6s() []net.IP {
	var takenIps []net.IP
	for _, existingPeer := range a.Peers {
		if existingPeer.IP6 != nil {
			takenIps = append(takenIps, *existingPeer.IP6)
		}
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
	peers := map[string]*nbpeer.Peer{}
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

	groups := map[string]*nbgroup.Group{}
	for id, group := range a.Groups {
		groups[id] = group.Copy()
	}

	policies := []*Policy{}
	for _, policy := range a.Policies {
		policies = append(policies, policy.Copy())
	}

	routes := map[route.ID]*route.Route{}
	for id, r := range a.Routes {
		routes[id] = r.Copy()
	}

	nsGroups := map[string]*nbdns.NameServerGroup{}
	for id, nsGroup := range a.NameServerGroups {
		nsGroups[id] = nsGroup.Copy()
	}

	dnsSettings := a.DNSSettings.Copy()

	var settings *Settings
	if a.Settings != nil {
		settings = a.Settings.Copy()
	}

	postureChecks := []*posture.Checks{}
	for _, postureCheck := range a.PostureChecks {
		postureChecks = append(postureChecks, postureCheck.Copy())
	}

	return &Account{
		Id:                     a.Id,
		CreatedBy:              a.CreatedBy,
		CreatedAt:              a.CreatedAt,
		Domain:                 a.Domain,
		DomainCategory:         a.DomainCategory,
		IsDomainPrimaryAccount: a.IsDomainPrimaryAccount,
		SetupKeys:              setupKeys,
		Network:                a.Network.Copy(),
		Peers:                  peers,
		Users:                  users,
		Groups:                 groups,
		Policies:               policies,
		Routes:                 routes,
		NameServerGroups:       nsGroups,
		DNSSettings:            dnsSettings,
		PostureChecks:          postureChecks,
		Settings:               settings,
	}
}

func (a *Account) GetGroupAll() (*nbgroup.Group, error) {
	for _, g := range a.Groups {
		if g.Name == "All" {
			return g, nil
		}
	}
	return nil, fmt.Errorf("no group ALL found")
}

// GetPeer looks up a Peer by ID
func (a *Account) GetPeer(peerID string) *nbpeer.Peer {
	return a.Peers[peerID]
}

// SetJWTGroups to account and to user autoassigned groups
func (a *Account) SetJWTGroups(userID string, groupsNames []string) bool {
	user, ok := a.Users[userID]
	if !ok {
		return false
	}

	existedGroupsByName := make(map[string]*nbgroup.Group)
	for _, group := range a.Groups {
		existedGroupsByName[group.Name] = group
	}

	// remove JWT groups from the autogroups, to sync them again
	removed := 0
	jwtAutoGroups := make(map[string]struct{})
	for i, id := range user.AutoGroups {
		if group, ok := a.Groups[id]; ok && group.Issued == nbgroup.GroupIssuedJWT {
			jwtAutoGroups[group.Name] = struct{}{}
			user.AutoGroups = append(user.AutoGroups[:i-removed], user.AutoGroups[i-removed+1:]...)
			removed++
		}
	}

	// create JWT groups if they doesn't exist
	// and all of them to the autogroups
	var modified bool
	for _, name := range groupsNames {
		group, ok := existedGroupsByName[name]
		if !ok {
			group = &nbgroup.Group{
				ID:     xid.New().String(),
				Name:   name,
				Issued: nbgroup.GroupIssuedJWT,
			}
			a.Groups[group.ID] = group
		}
		// only JWT groups will be synced
		if group.Issued == nbgroup.GroupIssuedJWT {
			user.AutoGroups = append(user.AutoGroups, group.ID)
			if _, ok := jwtAutoGroups[name]; !ok {
				modified = true
			}
			delete(jwtAutoGroups, name)
		}
	}

	// if not empty it means we removed some groups
	if len(jwtAutoGroups) > 0 {
		modified = true
	}

	return modified
}

// UserGroupsAddToPeers adds groups to all peers of user
func (a *Account) UserGroupsAddToPeers(userID string, groups ...string) {
	userPeers := make(map[string]struct{})
	for pid, peer := range a.Peers {
		if peer.UserID == userID {
			userPeers[pid] = struct{}{}
		}
	}

	for _, gid := range groups {
		group, ok := a.Groups[gid]
		if !ok {
			continue
		}

		groupPeers := make(map[string]struct{})
		for _, pid := range group.Peers {
			groupPeers[pid] = struct{}{}
		}

		for pid := range userPeers {
			groupPeers[pid] = struct{}{}
		}

		group.Peers = group.Peers[:0]
		for pid := range groupPeers {
			group.Peers = append(group.Peers, pid)
		}
	}
}

// UserGroupsRemoveFromPeers removes groups from all peers of user
func (a *Account) UserGroupsRemoveFromPeers(userID string, groups ...string) {
	for _, gid := range groups {
		group, ok := a.Groups[gid]
		if !ok {
			continue
		}
		update := make([]string, 0, len(group.Peers))
		for _, pid := range group.Peers {
			peer, ok := a.Peers[pid]
			if !ok {
				continue
			}
			if peer.UserID != userID {
				update = append(update, pid)
			}
		}
		group.Peers = update
	}
}

// BuildManager creates a new DefaultAccountManager with a provided Store
func BuildManager(store Store, peersUpdateManager *PeersUpdateManager, idpManager idp.Manager,
	singleAccountModeDomain string, dnsDomain string, eventStore activity.Store, geo *geolocation.Geolocation,
	userDeleteFromIDPEnabled bool,
	integratedPeerValidator integrated_validator.IntegratedValidator,
) (*DefaultAccountManager, error) {
	am := &DefaultAccountManager{
		Store:                    store,
		geo:                      geo,
		peersUpdateManager:       peersUpdateManager,
		idpManager:               idpManager,
		ctx:                      context.Background(),
		cacheMux:                 sync.Mutex{},
		cacheLoading:             map[string]chan struct{}{},
		dnsDomain:                dnsDomain,
		eventStore:               eventStore,
		peerLoginExpiry:          NewDefaultScheduler(),
		userDeleteFromIDPEnabled: userDeleteFromIDPEnabled,
		integratedPeerValidator:  integratedPeerValidator,
	}
	allAccounts := store.GetAllAccounts()
	// enable single account mode only if configured by user and number of existing accounts is not grater than 1
	am.singleAccountMode = singleAccountModeDomain != "" && len(allAccounts) <= 1
	if am.singleAccountMode {
		if !isDomainValid(singleAccountModeDomain) {
			return nil, status.Errorf(status.InvalidArgument, "invalid domain \"%s\" provided for a single account mode. Please review your input for --single-account-mode-domain", singleAccountModeDomain)
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
			if err := addAllGroup(account); err != nil {
				return nil, err
			}
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

	// TODO: what is max expiration time? Should be quite long
	am.externalCacheManager = cache.New[*idp.UserData](
		cacheStore.NewGoCache(goCacheClient),
	)

	if !isNil(am.idpManager) {
		go func() {
			err := am.warmupIDPCache()
			if err != nil {
				log.Warnf("failed warming up cache due to error: %v", err)
				// todo retry?
				return
			}
		}()
	}

	am.integratedPeerValidator.SetPeerInvalidationListener(am.onPeersInvalidated)

	return am, nil
}

func (am *DefaultAccountManager) GetExternalCacheManager() ExternalCacheManager {
	return am.externalCacheManager
}

func (am *DefaultAccountManager) GetIdpManager() idp.Manager {
	return am.idpManager
}

// UpdateAccountSettings updates Account settings.
// Only users with role UserRoleAdmin can update the account.
// User that performs the update has to belong to the account.
// Returns an updated Account
func (am *DefaultAccountManager) UpdateAccountSettings(accountID, userID string, newSettings *Settings) (*Account, error) {
	halfYearLimit := 180 * 24 * time.Hour
	if newSettings.PeerLoginExpiration > halfYearLimit {
		return nil, status.Errorf(status.InvalidArgument, "peer login expiration can't be larger than 180 days")
	}

	if newSettings.PeerLoginExpiration < time.Hour {
		return nil, status.Errorf(status.InvalidArgument, "peer login expiration can't be smaller than one hour")
	}

	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.HasAdminPower() {
		return nil, status.Errorf(status.PermissionDenied, "user is not allowed to update account")
	}

	err = am.integratedPeerValidator.ValidateExtraSettings(newSettings.Extra, account.Settings.Extra, account.Peers, userID, accountID)
	if err != nil {
		return nil, err
	}

	oldSettings := account.Settings
	if oldSettings.PeerLoginExpirationEnabled != newSettings.PeerLoginExpirationEnabled {
		event := activity.AccountPeerLoginExpirationEnabled
		if !newSettings.PeerLoginExpirationEnabled {
			event = activity.AccountPeerLoginExpirationDisabled
			am.peerLoginExpiry.Cancel([]string{accountID})
		} else {
			am.checkAndSchedulePeerLoginExpiration(account)
		}
		am.StoreEvent(userID, accountID, accountID, event, nil)
	}

	if oldSettings.PeerLoginExpiration != newSettings.PeerLoginExpiration {
		am.StoreEvent(userID, accountID, accountID, activity.AccountPeerLoginExpirationDurationUpdated, nil)
		am.checkAndSchedulePeerLoginExpiration(account)
	}

	updatedAccount := account.UpdateSettings(newSettings)
	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	return updatedAccount, nil
}

func (am *DefaultAccountManager) peerLoginExpirationJob(accountID string) func() (time.Duration, bool) {
	return func() (time.Duration, bool) {
		unlock := am.Store.AcquireAccountWriteLock(accountID)
		defer unlock()

		account, err := am.Store.GetAccount(accountID)
		if err != nil {
			log.Errorf("failed getting account %s expiring peers", account.Id)
			return account.GetNextPeerExpiration()
		}

		expiredPeers := account.GetExpiredPeers()
		var peerIDs []string
		for _, peer := range expiredPeers {
			peerIDs = append(peerIDs, peer.ID)
		}

		log.Debugf("discovered %d peers to expire for account %s", len(peerIDs), account.Id)

		if err := am.expireAndUpdatePeers(account, expiredPeers); err != nil {
			log.Errorf("failed updating account peers while expiring peers for account %s", account.Id)
			return account.GetNextPeerExpiration()
		}

		return account.GetNextPeerExpiration()
	}
}

func (am *DefaultAccountManager) checkAndSchedulePeerLoginExpiration(account *Account) {
	am.peerLoginExpiry.Cancel([]string{account.Id})
	if nextRun, ok := account.GetNextPeerExpiration(); ok {
		go am.peerLoginExpiry.Schedule(nextRun, account.Id, am.peerLoginExpirationJob(account.Id))
	}
}

// newAccount creates a new Account with a generated ID and generated default setup keys.
// If ID is already in use (due to collision) we try one more time before returning error
func (am *DefaultAccountManager) newAccount(userID, domain string) (*Account, error) {
	for i := 0; i < 2; i++ {
		accountId := xid.New().String()

		_, err := am.Store.GetAccount(accountId)
		statusErr, _ := status.FromError(err)
		switch {
		case err == nil:
			log.Warnf("an account with ID already exists, retrying...")
			continue
		case statusErr.Type() == status.NotFound:
			newAccount := newAccountWithId(accountId, userID, domain)
			am.StoreEvent(userID, newAccount.Id, accountId, activity.AccountCreated, nil)
			return newAccount, nil
		default:
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
	log.Infof("%d entries received from IdP management", len(userData))

	// If the Identity Provider does not support writing AppMetadata,
	// in cases like this, we expect it to return all users in an "unset" field.
	// We iterate over the users in the "unset" field, look up their AccountID in our store, and
	// update their AppMetadata with the AccountID.
	if unsetData, ok := userData[idp.UnsetAccountID]; ok {
		for _, user := range unsetData {
			accountID, err := am.Store.GetAccountByUser(user.ID)
			if err == nil {
				data := userData[accountID.Id]
				if data == nil {
					data = make([]*idp.UserData, 0, 1)
				}

				user.AppMetadata.WTAccountID = accountID.Id

				userData[accountID.Id] = append(data, user)
			}
		}
	}
	delete(userData, idp.UnsetAccountID)

	rcvdUsers := 0
	for accountID, users := range userData {
		rcvdUsers += len(users)
		err = am.cacheManager.Set(am.ctx, accountID, users, cacheStore.WithExpiration(cacheEntryExpiration()))
		if err != nil {
			return err
		}
	}
	log.Infof("warmed up IDP cache with %d entries for %d accounts", rcvdUsers, len(userData))
	return nil
}

// DeleteAccount deletes an account and all its users from local store and from the remote IDP if the requester is an admin and account owner
func (am *DefaultAccountManager) DeleteAccount(accountID, userID string) error {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()
	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return err
	}

	if !user.HasAdminPower() {
		return status.Errorf(status.PermissionDenied, "user is not allowed to delete account")
	}

	if user.Role != UserRoleOwner {
		return status.Errorf(status.PermissionDenied, "user is not allowed to delete account. Only account owner can delete account")
	}
	for _, otherUser := range account.Users {
		if otherUser.IsServiceUser {
			continue
		}

		if otherUser.Id == userID {
			continue
		}

		deleteUserErr := am.deleteRegularUser(account, userID, otherUser.Id)
		if deleteUserErr != nil {
			return deleteUserErr
		}
	}

	err = am.deleteRegularUser(account, userID, userID)
	if err != nil {
		log.Errorf("failed deleting user %s. error: %s", userID, err)
		return err
	}

	err = am.Store.DeleteAccount(account)
	if err != nil {
		log.Errorf("failed deleting account %s. error: %s", accountID, err)
		return err
	}
	// cancel peer login expiry job
	am.peerLoginExpiry.Cancel([]string{account.Id})

	log.Debugf("account %s deleted", accountID)
	return nil
}

// GetAccountByUserOrAccountID looks for an account by user or accountID, if no account is provided and
// userID doesn't have an account associated with it, one account is created
// domain is used to create a new account if no account is found
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
	accountIDString := fmt.Sprintf("%v", accountID)

	account, err := am.Store.GetAccount(accountIDString)
	if err != nil {
		return nil, err
	}

	userData, err := am.idpManager.GetAccount(accountIDString)
	if err != nil {
		return nil, err
	}
	log.Debugf("%d entries received from IdP management", len(userData))

	dataMap := make(map[string]*idp.UserData, len(userData))
	for _, datum := range userData {
		dataMap[datum.ID] = datum
	}

	matchedUserData := make([]*idp.UserData, 0)
	for _, user := range account.Users {
		if user.IsServiceUser {
			continue
		}
		datum, ok := dataMap[user.Id]
		if !ok {
			log.Warnf("user %s not found in IDP", user.Id)
			continue
		}
		matchedUserData = append(matchedUserData, datum)
	}
	return matchedUserData, nil
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

	return nil, nil //nolint:nilnil
}

// lookupUserInCache looks up user in the IdP cache and returns it. If the user wasn't found, the function returns nil
func (am *DefaultAccountManager) lookupUserInCache(userID string, account *Account) (*idp.UserData, error) {
	users := make(map[string]userLoggedInOnce, len(account.Users))
	// ignore service users and users provisioned by integrations than are never logged in
	for _, user := range account.Users {
		if user.IsServiceUser {
			continue
		}
		if user.Issued == UserIssuedIntegration {
			continue
		}
		users[user.Id] = userLoggedInOnce(!user.LastLogin.IsZero())
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

	// add extra check on external cache manager. We may get to this point when the user is not yet findable in IDP,
	// or it didn't have its metadata updated with am.addAccountIDToIDPAppMeta
	user, err := account.FindUser(userID)
	if err != nil {
		log.Errorf("failed finding user %s in account %s", userID, account.Id)
		return nil, err
	}

	key := user.IntegrationReference.CacheKey(account.Id, userID)
	ud, err := am.externalCacheManager.Get(am.ctx, key)
	if err != nil {
		log.Debugf("failed to get externalCache for key: %s, error: %s", key, err)
	}

	return ud, nil
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

func (am *DefaultAccountManager) lookupCache(accountUsers map[string]userLoggedInOnce, accountID string) ([]*idp.UserData, error) {
	var data []*idp.UserData
	var err error

	maxAttempts := 2

	data, err = am.getAccountFromCache(accountID, false)
	if err != nil {
		return nil, err
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if am.isCacheFresh(accountUsers, data) {
			return data, nil
		}

		if attempt > 1 {
			time.Sleep(200 * time.Millisecond)
		}

		log.Infof("refreshing cache for account %s", accountID)
		data, err = am.refreshCache(accountID)
		if err != nil {
			return nil, err
		}

		if attempt == maxAttempts {
			log.Warnf("cache for account %s reached maximum refresh attempts (%d)", accountID, maxAttempts)
		}
	}

	return data, nil
}

// isCacheFresh checks if the cache is refreshed already by comparing the accountUsers with the cache data by user count and user invite status
func (am *DefaultAccountManager) isCacheFresh(accountUsers map[string]userLoggedInOnce, data []*idp.UserData) bool {
	userDataMap := make(map[string]*idp.UserData, len(data))
	for _, datum := range data {
		userDataMap[datum.ID] = datum
	}

	// the accountUsers ID list of non integration users from store, we check if cache has all of them
	// as result of for loop knownUsersCount will have number of users are not presented in the cashed
	knownUsersCount := len(accountUsers)
	for user, loggedInOnce := range accountUsers {
		if datum, ok := userDataMap[user]; ok {
			// check if the matching user data has a pending invite and if the user has logged in once, forcing the cache to be refreshed
			if datum.AppMetadata.WTPendingInvite != nil && *datum.AppMetadata.WTPendingInvite && loggedInOnce == true { //nolint:gosimple
				log.Infof("user %s has a pending invite and has logged in once, cache invalid", user)
				return false
			}
			knownUsersCount--
			continue
		}
		log.Debugf("cache doesn't know about %s user", user)
	}

	// if we know users that are not yet in cache more likely cache is outdated
	if knownUsersCount > 0 {
		log.Infof("cache invalid. Users unknown to the cache: %d", knownUsersCount)
		return false
	}

	return true
}

func (am *DefaultAccountManager) removeUserFromCache(accountID, userID string) error {
	data, err := am.getAccountFromCache(accountID, false)
	if err != nil {
		return err
	}

	for i, datum := range data {
		if datum.ID == userID {
			data = append(data[:i], data[i+1:]...)
			break
		}
	}

	return am.cacheManager.Set(am.ctx, accountID, data, cacheStore.WithExpiration(cacheEntryExpiration()))
}

// updateAccountDomainAttributes updates the account domain attributes and then, saves the account
func (am *DefaultAccountManager) updateAccountDomainAttributes(account *Account, claims jwtclaims.AuthorizationClaims,
	primaryDomain bool,
) error {

	if claims.Domain != "" {
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
	} else {
		log.Errorf("claims don't contain a valid domain, skipping domain attributes update. Received claims: %v", claims)
	}

	err := am.Store.SaveAccount(account)
	if err != nil {
		return err
	}
	return nil
}

// handleExistingUserAccount handles existing User accounts and update its domain attributes.
func (am *DefaultAccountManager) handleExistingUserAccount(
	existingAcc *Account,
	primaryDomain bool,
	claims jwtclaims.AuthorizationClaims,
) error {
	err := am.updateAccountDomainAttributes(existingAcc, claims, primaryDomain)
	if err != nil {
		return err
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
	if claims.UserId == "" {
		return nil, fmt.Errorf("user ID is empty")
	}
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

	am.StoreEvent(claims.UserId, claims.UserId, account.Id, activity.UserJoined, nil)

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
			am.StoreEvent(userID, userID, account.Id, activity.UserJoined, nil)
		}()
	}

	return nil
}

// MarkPATUsed marks a personal access token as used
func (am *DefaultAccountManager) MarkPATUsed(tokenID string) error {

	user, err := am.Store.GetUserByTokenID(tokenID)
	if err != nil {
		return err
	}

	account, err := am.Store.GetAccountByUser(user.Id)
	if err != nil {
		return err
	}

	unlock := am.Store.AcquireAccountWriteLock(account.Id)
	defer unlock()

	account, err = am.Store.GetAccountByUser(user.Id)
	if err != nil {
		return err
	}

	pat, ok := account.Users[user.Id].PATs[tokenID]
	if !ok {
		return fmt.Errorf("token not found")
	}

	pat.LastUsed = time.Now().UTC()

	return am.Store.SaveAccount(account)
}

// GetAccountFromPAT returns Account and User associated with a personal access token
func (am *DefaultAccountManager) GetAccountFromPAT(token string) (*Account, *User, *PersonalAccessToken, error) {
	if len(token) != PATLength {
		return nil, nil, nil, fmt.Errorf("token has wrong length")
	}

	prefix := token[:len(PATPrefix)]
	if prefix != PATPrefix {
		return nil, nil, nil, fmt.Errorf("token has wrong prefix")
	}
	secret := token[len(PATPrefix) : len(PATPrefix)+PATSecretLength]
	encodedChecksum := token[len(PATPrefix)+PATSecretLength : len(PATPrefix)+PATSecretLength+PATChecksumLength]

	verificationChecksum, err := base62.Decode(encodedChecksum)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("token checksum decoding failed: %w", err)
	}

	secretChecksum := crc32.ChecksumIEEE([]byte(secret))
	if secretChecksum != verificationChecksum {
		return nil, nil, nil, fmt.Errorf("token checksum does not match")
	}

	hashedToken := sha256.Sum256([]byte(token))
	encodedHashedToken := b64.StdEncoding.EncodeToString(hashedToken[:])
	tokenID, err := am.Store.GetTokenIDByHashedToken(encodedHashedToken)
	if err != nil {
		return nil, nil, nil, err
	}

	user, err := am.Store.GetUserByTokenID(tokenID)
	if err != nil {
		return nil, nil, nil, err
	}

	account, err := am.Store.GetAccountByUser(user.Id)
	if err != nil {
		return nil, nil, nil, err
	}

	pat := user.PATs[tokenID]
	if pat == nil {
		return nil, nil, nil, fmt.Errorf("personal access token not found")
	}

	return account, user, pat, nil
}

// GetAccountFromToken returns an account associated with this token
func (am *DefaultAccountManager) GetAccountFromToken(claims jwtclaims.AuthorizationClaims) (*Account, *User, error) {
	if claims.UserId == "" {
		return nil, nil, fmt.Errorf("user ID is empty")
	}
	if am.singleAccountMode && am.singleAccountModeDomain != "" {
		// This section is mostly related to self-hosted installations.
		// We override incoming domain claims to group users under a single account.
		claims.Domain = am.singleAccountModeDomain
		claims.DomainCategory = PrivateCategory
		log.Debugf("overriding JWT Domain and DomainCategory claims since single account mode is enabled")
	}

	newAcc, err := am.getAccountWithAuthorizationClaims(claims)
	if err != nil {
		return nil, nil, err
	}
	unlock := am.Store.AcquireAccountWriteLock(newAcc.Id)
	alreadyUnlocked := false
	defer func() {
		if !alreadyUnlocked {
			unlock()
		}
	}()

	account, err := am.Store.GetAccount(newAcc.Id)
	if err != nil {
		return nil, nil, err
	}

	user := account.Users[claims.UserId]
	if user == nil {
		// this is not really possible because we got an account by user ID
		return nil, nil, status.Errorf(status.NotFound, "user %s not found", claims.UserId)
	}

	if !user.IsServiceUser && claims.Invited {
		err = am.redeemInvite(account, claims.UserId)
		if err != nil {
			return nil, nil, err
		}
	}

	if account.Settings.JWTGroupsEnabled {
		if account.Settings.JWTGroupsClaimName == "" {
			log.Errorf("JWT groups are enabled but no claim name is set")
			return account, user, nil
		}
		if claim, ok := claims.Raw[account.Settings.JWTGroupsClaimName]; ok {
			if slice, ok := claim.([]interface{}); ok {
				var groupsNames []string
				for _, item := range slice {
					if g, ok := item.(string); ok {
						groupsNames = append(groupsNames, g)
					} else {
						log.Errorf("JWT claim %q is not a string: %v", account.Settings.JWTGroupsClaimName, item)
					}
				}

				oldGroups := make([]string, len(user.AutoGroups))
				copy(oldGroups, user.AutoGroups)
				// if groups were added or modified, save the account
				if account.SetJWTGroups(claims.UserId, groupsNames) {
					if account.Settings.GroupsPropagationEnabled {
						if user, err := account.FindUser(claims.UserId); err == nil {
							addNewGroups := difference(user.AutoGroups, oldGroups)
							removeOldGroups := difference(oldGroups, user.AutoGroups)
							account.UserGroupsAddToPeers(claims.UserId, addNewGroups...)
							account.UserGroupsRemoveFromPeers(claims.UserId, removeOldGroups...)
							account.Network.IncSerial()
							if err := am.Store.SaveAccount(account); err != nil {
								log.Errorf("failed to save account: %v", err)
							} else {
								am.updateAccountPeers(account)
								unlock()
								alreadyUnlocked = true
								for _, g := range addNewGroups {
									if group := account.GetGroup(g); group != nil {
										am.StoreEvent(user.Id, user.Id, account.Id, activity.GroupAddedToUser,
											map[string]any{
												"group":           group.Name,
												"group_id":        group.ID,
												"is_service_user": user.IsServiceUser,
												"user_name":       user.ServiceUserName})
									}
								}
								for _, g := range removeOldGroups {
									if group := account.GetGroup(g); group != nil {
										am.StoreEvent(user.Id, user.Id, account.Id, activity.GroupRemovedFromUser,
											map[string]any{
												"group":           group.Name,
												"group_id":        group.ID,
												"is_service_user": user.IsServiceUser,
												"user_name":       user.ServiceUserName})
									}
								}
							}
						}
					} else {
						if err := am.Store.SaveAccount(account); err != nil {
							log.Errorf("failed to save account: %v", err)
						}
					}
				}
			} else {
				log.Debugf("JWT claim %q is not a string array", account.Settings.JWTGroupsClaimName)
			}
		} else {
			log.Debugf("JWT claim %q not found", account.Settings.JWTGroupsClaimName)
		}
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
	log.Tracef("getting account with authorization claims. User ID: \"%s\", Account ID: \"%s\", Domain: \"%s\", Domain Category: \"%s\"",
		claims.UserId, claims.AccountId, claims.Domain, claims.DomainCategory)
	if claims.UserId == "" {
		return nil, fmt.Errorf("user ID is empty")
	}
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
		if accountFromID.DomainCategory == PrivateCategory || claims.DomainCategory != PrivateCategory || accountFromID.Domain != claims.Domain {
			return accountFromID, nil
		}
	}

	start := time.Now()
	unlock := am.Store.AcquireGlobalLock()
	defer unlock()
	log.Debugf("Acquired global lock in %s for user %s", time.Since(start), claims.UserId)

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
		unlockAccount := am.Store.AcquireAccountWriteLock(account.Id)
		defer unlockAccount()
		account, err = am.Store.GetAccountByUser(claims.UserId)
		if err != nil {
			return nil, err
		}
		// If there is no primary domain account yet, we set the account as primary for the domain. Otherwise,
		// we compare the account's ID with the domain account ID, and if they don't match, we set the account as
		// non-primary account for the domain. We don't merge accounts at this stage, because of cases when a domain
		// was previously unclassified or classified as public so N users that logged int that time, has they own account
		// and peers that shouldn't be lost.
		primaryDomain := domainAccount == nil || account.Id == domainAccount.Id

		err = am.handleExistingUserAccount(account, primaryDomain, claims)
		if err != nil {
			return nil, err
		}
		return account, nil
	} else if s, ok := status.FromError(err); ok && s.Type() == status.NotFound {
		if domainAccount != nil {
			unlockAccount := am.Store.AcquireAccountWriteLock(domainAccount.Id)
			defer unlockAccount()
			domainAccount, err = am.Store.GetAccountByPrivateDomain(claims.Domain)
			if err != nil {
				return nil, err
			}
		}
		return am.handleNewUserAccount(domainAccount, claims)
	} else {
		// other error
		return nil, err
	}
}

func (am *DefaultAccountManager) SyncAndMarkPeer(peerPubKey string, realIP net.IP) (*nbpeer.Peer, *NetworkMap, error) {
	accountID, err := am.Store.GetAccountIDByPeerPubKey(peerPubKey)
	if err != nil {
		if errStatus, ok := status.FromError(err); ok && errStatus.Type() == status.NotFound {
			return nil, nil, status.Errorf(status.Unauthenticated, "peer not registered")
		}
		return nil, nil, err
	}

	unlock := am.Store.AcquireAccountReadLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, nil, err
	}

	peer, netMap, err := am.SyncPeer(PeerSync{WireGuardPubKey: peerPubKey}, account)
	if err != nil {
		return nil, nil, err
	}

	err = am.MarkPeerConnected(peerPubKey, true, realIP, account)
	if err != nil {
		log.Warnf("failed marking peer as connected %s %v", peerPubKey, err)
	}

	return peer, netMap, nil
}

func (am *DefaultAccountManager) CancelPeerRoutines(peer *nbpeer.Peer) error {
	accountID, err := am.Store.GetAccountIDByPeerPubKey(peer.Key)
	if err != nil {
		if errStatus, ok := status.FromError(err); ok && errStatus.Type() == status.NotFound {
			return status.Errorf(status.Unauthenticated, "peer not registered")
		}
		return err
	}

	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	err = am.MarkPeerConnected(peer.Key, false, nil, account)
	if err != nil {
		log.Warnf("failed marking peer as connected %s %v", peer.Key, err)
	}

	return nil

}

// GetAllConnectedPeers returns connected peers based on peersUpdateManager.GetAllConnectedPeers()
func (am *DefaultAccountManager) GetAllConnectedPeers() (map[string]struct{}, error) {
	return am.peersUpdateManager.GetAllConnectedPeers(), nil
}

// HasConnectedChannel returns true if peers has channel in update manager, otherwise false
func (am *DefaultAccountManager) HasConnectedChannel(peerID string) bool {
	return am.peersUpdateManager.HasChannel(peerID)
}

var invalidDomainRegexp = regexp.MustCompile(`^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$`)

func isDomainValid(domain string) bool {
	return invalidDomainRegexp.MatchString(domain)
}

// GetDNSDomain returns the configured dnsDomain
func (am *DefaultAccountManager) GetDNSDomain() string {
	return am.dnsDomain
}

// CheckUserAccessByJWTGroups checks if the user has access, particularly in cases where the admin enabled JWT
// group propagation and set the list of groups with access permissions.
func (am *DefaultAccountManager) CheckUserAccessByJWTGroups(claims jwtclaims.AuthorizationClaims) error {
	account, _, err := am.GetAccountFromToken(claims)
	if err != nil {
		return err
	}

	// Ensures JWT group synchronization to the management is enabled before,
	// filtering access based on the allowed groups.
	if account.Settings != nil && account.Settings.JWTGroupsEnabled {
		if allowedGroups := account.Settings.JWTAllowGroups; len(allowedGroups) > 0 {
			userJWTGroups := make([]string, 0)

			if claim, ok := claims.Raw[account.Settings.JWTGroupsClaimName]; ok {
				if claimGroups, ok := claim.([]interface{}); ok {
					for _, g := range claimGroups {
						if group, ok := g.(string); ok {
							userJWTGroups = append(userJWTGroups, group)
						}
					}
				}
			}

			if !userHasAllowedGroup(allowedGroups, userJWTGroups) {
				return fmt.Errorf("user does not belong to any of the allowed JWT groups")
			}
		}
	}

	return nil
}

func (am *DefaultAccountManager) onPeersInvalidated(accountID string) {
	log.Debugf("validated peers has been invalidated for account %s", accountID)
	updatedAccount, err := am.Store.GetAccount(accountID)
	if err != nil {
		log.Errorf("failed to get account %s: %v", accountID, err)
		return
	}
	am.updateAccountPeers(updatedAccount)
}

func (am *DefaultAccountManager) FindExistingPostureCheck(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error) {
	return am.Store.GetPostureCheckByChecksDefinition(accountID, checks)
}

// addAllGroup to account object if it doesn't exist
func addAllGroup(account *Account) error {
	if len(account.Groups) == 0 {
		allGroup := &nbgroup.Group{
			ID:     xid.New().String(),
			Name:   "All",
			Issued: nbgroup.GroupIssuedAPI,
		}
		for _, peer := range account.Peers {
			allGroup.Peers = append(allGroup.Peers, peer.ID)
		}
		account.Groups = map[string]*nbgroup.Group{allGroup.ID: allGroup}

		id := xid.New().String()

		defaultPolicy := &Policy{
			ID:          id,
			Name:        DefaultRuleName,
			Description: DefaultRuleDescription,
			Enabled:     true,
			Rules: []*PolicyRule{
				{
					ID:            id,
					Name:          DefaultRuleName,
					Description:   DefaultRuleDescription,
					Enabled:       true,
					Sources:       []string{allGroup.ID},
					Destinations:  []string{allGroup.ID},
					Bidirectional: true,
					Protocol:      PolicyRuleProtocolALL,
					Action:        PolicyTrafficActionAccept,
				},
			},
		}

		account.Policies = []*Policy{defaultPolicy}
	}
	return nil
}

// newAccountWithId creates a new Account with a default SetupKey (doesn't store in a Store) and provided id
func newAccountWithId(accountID, userID, domain string) *Account {
	log.Debugf("creating new account")

	network := NewNetwork(true)
	peers := make(map[string]*nbpeer.Peer)
	users := make(map[string]*User)
	routes := make(map[route.ID]*route.Route)
	setupKeys := map[string]*SetupKey{}
	nameServersGroups := make(map[string]*nbdns.NameServerGroup)
	users[userID] = NewOwnerUser(userID)
	dnsSettings := DNSSettings{
		DisabledManagementGroups: make([]string, 0),
	}
	log.Debugf("created new account %s", accountID)

	acc := &Account{
		Id:               accountID,
		CreatedAt:        time.Now().UTC(),
		SetupKeys:        setupKeys,
		Network:          network,
		Peers:            peers,
		Users:            users,
		CreatedBy:        userID,
		Domain:           domain,
		Routes:           routes,
		NameServerGroups: nameServersGroups,
		DNSSettings:      dnsSettings,
		Settings: &Settings{
			PeerLoginExpirationEnabled: true,
			PeerLoginExpiration:        DefaultPeerLoginExpiration,
			GroupsPropagationEnabled:   true,
			RegularUsersViewBlocked:    true,
		},
	}

	if err := addAllGroup(acc); err != nil {
		log.Errorf("error adding all group to account %s: %v", acc.Id, err)
	}
	return acc
}

// userHasAllowedGroup checks if a user belongs to any of the allowed groups.
func userHasAllowedGroup(allowedGroups []string, userGroups []string) bool {
	for _, userGroup := range userGroups {
		for _, allowedGroup := range allowedGroups {
			if userGroup == allowedGroup {
				return true
			}
		}
	}
	return false
}
