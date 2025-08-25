package types

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/domain"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/route"
)

const (
	defaultTTL                      = 300
	DefaultPeerLoginExpiration      = 24 * time.Hour
	DefaultPeerInactivityExpiration = 10 * time.Minute

	PublicCategory  = "public"
	PrivateCategory = "private"
	UnknownCategory = "unknown"

	// firewallRuleMinPortRangesVer defines the minimum peer version that supports port range rules.
	firewallRuleMinPortRangesVer = "0.48.0"
)

type LookupMap map[string]struct{}

// AccountMeta is a struct that contains a stripped down version of the Account object.
// It doesn't carry any peers, groups, policies, or routes, etc. Just some metadata (e.g. ID, created by, created at, etc).
type AccountMeta struct {
	// AccountId is the unique identifier of the account
	AccountID      string `gorm:"column:id"`
	CreatedAt      time.Time
	CreatedBy      string
	Domain         string
	DomainCategory string
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
	Groups                 map[string]*Group                 `gorm:"-"`
	GroupsG                []Group                           `json:"-" gorm:"foreignKey:AccountID;references:id"`
	Policies               []*Policy                         `gorm:"foreignKey:AccountID;references:id"`
	Routes                 map[route.ID]*route.Route         `gorm:"-"`
	RoutesG                []route.Route                     `json:"-" gorm:"foreignKey:AccountID;references:id"`
	NameServerGroups       map[string]*nbdns.NameServerGroup `gorm:"-"`
	NameServerGroupsG      []nbdns.NameServerGroup           `json:"-" gorm:"foreignKey:AccountID;references:id"`
	DNSSettings            DNSSettings                       `gorm:"embedded;embeddedPrefix:dns_settings_"`
	PostureChecks          []*posture.Checks                 `gorm:"foreignKey:AccountID;references:id"`
	// Settings is a dictionary of Account settings
	Settings         *Settings                        `gorm:"embedded;embeddedPrefix:settings_"`
	Networks         []*networkTypes.Network          `gorm:"foreignKey:AccountID;references:id"`
	NetworkRouters   []*routerTypes.NetworkRouter     `gorm:"foreignKey:AccountID;references:id"`
	NetworkResources []*resourceTypes.NetworkResource `gorm:"foreignKey:AccountID;references:id"`
	Onboarding       AccountOnboarding                `gorm:"foreignKey:AccountID;references:id;constraint:OnDelete:CASCADE"`
}

// Subclass used in gorm to only load network and not whole account
type AccountNetwork struct {
	Network *Network `gorm:"embedded;embeddedPrefix:network_"`
}

// AccountDNSSettings used in gorm to only load dns settings and not whole account
type AccountDNSSettings struct {
	DNSSettings DNSSettings `gorm:"embedded;embeddedPrefix:dns_settings_"`
}

// Subclass used in gorm to only load settings and not whole account
type AccountSettings struct {
	Settings *Settings `gorm:"embedded;embeddedPrefix:settings_"`
}

type AccountOnboarding struct {
	AccountID             string `gorm:"primaryKey"`
	OnboardingFlowPending bool
	SignupFormPending     bool
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// IsEqual compares two AccountOnboarding objects and returns true if they are equal
func (o AccountOnboarding) IsEqual(onboarding AccountOnboarding) bool {
	return o.OnboardingFlowPending == onboarding.OnboardingFlowPending &&
		o.SignupFormPending == onboarding.SignupFormPending
}

// GetRoutesByPrefixOrDomains return list of routes by account and route prefix
func (a *Account) GetRoutesByPrefixOrDomains(prefix netip.Prefix, domains domain.List) []*route.Route {
	var routes []*route.Route
	for _, r := range a.Routes {
		dynamic := r.IsDynamic()
		if dynamic && r.Domains.PunycodeString() == domains.PunycodeString() ||
			!dynamic && r.Network.String() == prefix.String() {
			routes = append(routes, r)
		}
	}

	return routes
}

// GetGroup returns a group by ID if exists, nil otherwise
func (a *Account) GetGroup(groupID string) *Group {
	return a.Groups[groupID]
}

func AddPeerLabelsToAccount(ctx context.Context, account *Account, peerLabels LookupMap) {
	for _, peer := range account.Peers {
		label, err := GetPeerHostLabel(peer.Name, peerLabels)
		if err != nil {
			log.WithContext(ctx).Errorf("got an error while generating a peer host label. Peer name %s, error: %v. Trying with the peer's meta hostname", peer.Name, err)
			label, err = GetPeerHostLabel(peer.Meta.Hostname, peerLabels)
			if err != nil {
				log.WithContext(ctx).Errorf("got another error while generating a peer host label with hostname. Peer hostname %s, error: %v. Skipping", peer.Meta.Hostname, err)
				continue
			}
		}
		peer.DNSLabel = label
		peerLabels[label] = struct{}{}
	}
}

func GetPeerHostLabel(name string, peerLabels LookupMap) (string, error) {
	label, err := nbdns.GetParsedDomainLabel(name)
	if err != nil {
		return "", err
	}

	uniqueLabel := getUniqueHostLabel(label, peerLabels)
	if uniqueLabel == "" {
		return "", fmt.Errorf("couldn't find a unique valid label for %s, parsed label %s", name, label)
	}
	return uniqueLabel, nil
}

// getUniqueHostLabel look for a unique host label, and if doesn't find add a suffix up to 999
func getUniqueHostLabel(name string, peerLabels LookupMap) string {
	_, found := peerLabels[name]
	if !found {
		return name
	}
	for i := 1; i < 1000; i++ {
		nameWithSuffix := name + "-" + strconv.Itoa(i)
		_, found = peerLabels[nameWithSuffix]
		if !found {
			return nameWithSuffix
		}
	}
	return ""
}

func (a *Account) GetPeersCustomZone(ctx context.Context, dnsDomain string) nbdns.CustomZone {
	var merr *multierror.Error

	if dnsDomain == "" {
		log.WithContext(ctx).Error("no dns domain is set, returning empty zone")
		return nbdns.CustomZone{}
	}

	customZone := nbdns.CustomZone{
		Domain:  dns.Fqdn(dnsDomain),
		Records: make([]nbdns.SimpleRecord, 0, len(a.Peers)),
	}

	domainSuffix := "." + dnsDomain

	var sb strings.Builder
	for _, peer := range a.Peers {
		if peer.DNSLabel == "" {
			merr = multierror.Append(merr, fmt.Errorf("peer %s has an empty DNS label", peer.Name))
			continue
		}

		sb.Grow(len(peer.DNSLabel) + len(domainSuffix))
		sb.WriteString(peer.DNSLabel)
		sb.WriteString(domainSuffix)

		customZone.Records = append(customZone.Records, nbdns.SimpleRecord{
			Name:  sb.String(),
			Type:  int(dns.TypeA),
			Class: nbdns.DefaultClass,
			TTL:   defaultTTL,
			RData: peer.IP.String(),
		})
		sb.Reset()

		for _, extraLabel := range peer.ExtraDNSLabels {
			sb.Grow(len(extraLabel) + len(domainSuffix))
			sb.WriteString(extraLabel)
			sb.WriteString(domainSuffix)

			customZone.Records = append(customZone.Records, nbdns.SimpleRecord{
				Name:  sb.String(),
				Type:  int(dns.TypeA),
				Class: nbdns.DefaultClass,
				TTL:   defaultTTL,
				RData: peer.IP.String(),
			})
			sb.Reset()
		}

	}

	go func() {
		if merr != nil {
			log.WithContext(ctx).Errorf("error generating custom zone for account %s: %v", a.Id, merr)
		}
	}()

	return customZone
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

// GetInactivePeers returns peers that have been expired by inactivity
func (a *Account) GetInactivePeers() []*nbpeer.Peer {
	var peers []*nbpeer.Peer
	for _, inactivePeer := range a.GetPeersWithInactivity() {
		inactive, _ := inactivePeer.SessionExpired(a.Settings.PeerInactivityExpiration)
		if inactive {
			peers = append(peers, inactivePeer)
		}
	}
	return peers
}

// GetNextInactivePeerExpiration returns the minimum duration in which the next peer of the account will expire if it was found.
// If there is no peer that expires this function returns false and a duration of 0.
// This function only considers peers that haven't been expired yet and that are not connected.
func (a *Account) GetNextInactivePeerExpiration() (time.Duration, bool) {
	peersWithExpiry := a.GetPeersWithInactivity()
	if len(peersWithExpiry) == 0 {
		return 0, false
	}
	var nextExpiry *time.Duration
	for _, peer := range peersWithExpiry {
		if peer.Status.LoginExpired || peer.Status.Connected {
			continue
		}
		_, duration := peer.SessionExpired(a.Settings.PeerInactivityExpiration)
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

// GetPeersWithInactivity eturns a list of peers that have Peer.InactivityExpirationEnabled set to true and that were added by a user
func (a *Account) GetPeersWithInactivity() []*nbpeer.Peer {
	peers := make([]*nbpeer.Peer, 0)
	for _, peer := range a.Peers {
		if peer.InactivityExpirationEnabled && peer.AddedWithSSOLogin() {
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

	for i, r := range a.NetworkRouters {
		if r.Peer == peerID {
			a.NetworkRouters = append(a.NetworkRouters[:i], a.NetworkRouters[i+1:]...)
			break
		}
	}

	delete(a.Peers, peerID)
	a.Network.IncSerial()
}

func (a *Account) DeleteResource(resourceID string) {
	// delete resource from groups
	for _, g := range a.Groups {
		for i, pk := range g.Resources {
			if pk.ID == resourceID {
				g.Resources = append(g.Resources[:i], g.Resources[i+1:]...)
				break
			}
		}
	}
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
func (a *Account) FindGroupByName(groupName string) (*Group, error) {
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

func (a *Account) GetTakenIPs() []net.IP {
	var takenIps []net.IP
	for _, existingPeer := range a.Peers {
		takenIps = append(takenIps, existingPeer.IP)
	}

	return takenIps
}

func (a *Account) GetPeerDNSLabels() LookupMap {
	existingLabels := make(LookupMap)
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

	groups := map[string]*Group{}
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

	nets := []*networkTypes.Network{}
	for _, network := range a.Networks {
		nets = append(nets, network.Copy())
	}

	networkRouters := []*routerTypes.NetworkRouter{}
	for _, router := range a.NetworkRouters {
		networkRouters = append(networkRouters, router.Copy())
	}

	networkResources := []*resourceTypes.NetworkResource{}
	for _, resource := range a.NetworkResources {
		networkResources = append(networkResources, resource.Copy())
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
		Networks:               nets,
		NetworkRouters:         networkRouters,
		NetworkResources:       networkResources,
		Onboarding:             a.Onboarding,
	}
}

func (a *Account) GetMeta() *AccountMeta {
	return &AccountMeta{
		AccountID:      a.Id,
		CreatedBy:      a.CreatedBy,
		CreatedAt:      a.CreatedAt,
		Domain:         a.Domain,
		DomainCategory: a.DomainCategory,
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

// GetPeer looks up a Peer by ID
func (a *Account) GetPeer(peerID string) *nbpeer.Peer {
	return a.Peers[peerID]
}

// UserGroupsAddToPeers adds groups to all peers of user
func (a *Account) UserGroupsAddToPeers(userID string, groups ...string) map[string][]string {
	groupUpdates := make(map[string][]string)

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

		oldPeers := group.Peers

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

		groupUpdates[gid] = util.Difference(group.Peers, oldPeers)
	}

	return groupUpdates
}

// UserGroupsRemoveFromPeers removes groups from all peers of user
func (a *Account) UserGroupsRemoveFromPeers(userID string, groups ...string) map[string][]string {
	groupUpdates := make(map[string][]string)

	for _, gid := range groups {
		group, ok := a.Groups[gid]
		if !ok || group.Name == "All" {
			continue
		}

		oldPeers := group.Peers

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
		groupUpdates[gid] = util.Difference(oldPeers, group.Peers)
	}

	return groupUpdates
}

func (a *Account) GetPostureChecks(postureChecksID string) *posture.Checks {
	for _, postureChecks := range a.PostureChecks {
		if postureChecks.ID == postureChecksID {
			return postureChecks
		}
	}
	return nil
}

// getNetworkResourceGroups retrieves all groups associated with the given network resource.
func (a *Account) getNetworkResourceGroups(resourceID string) []*Group {
	var networkResourceGroups []*Group

	for _, group := range a.Groups {
		for _, resource := range group.Resources {
			if resource.ID == resourceID {
				networkResourceGroups = append(networkResourceGroups, group)
			}
		}
	}

	return networkResourceGroups
}

// GetResourcePoliciesMap returns a map of networks resource IDs and their associated policies.
func (a *Account) GetResourcePoliciesMap() map[string][]*Policy {
	resourcePolicies := make(map[string][]*Policy)
	for _, resource := range a.NetworkResources {
		if !resource.Enabled {
			continue
		}

		resourceAppliedPolicies := a.GetPoliciesForNetworkResource(resource.ID)
		resourcePolicies[resource.ID] = resourceAppliedPolicies
	}
	return resourcePolicies
}

// getNetworkResources filters and returns a list of network resources associated with the given network ID.
func (a *Account) getNetworkResources(networkID string) []*resourceTypes.NetworkResource {
	var resources []*resourceTypes.NetworkResource
	for _, resource := range a.NetworkResources {
		if resource.NetworkID == networkID {
			resources = append(resources, resource)
		}
	}
	return resources
}

// GetPoliciesForNetworkResource retrieves the list of policies that apply to a specific network resource.
// A policy is deemed applicable if its destination groups include any of the given network resource groups
// or if its destination resource explicitly matches the provided resource.
func (a *Account) GetPoliciesForNetworkResource(resourceId string) []*Policy {
	var resourceAppliedPolicies []*Policy

	networkResourceGroups := a.getNetworkResourceGroups(resourceId)

	for _, policy := range a.Policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			if rule.DestinationResource.ID == resourceId {
				resourceAppliedPolicies = append(resourceAppliedPolicies, policy)
				break
			}

			for _, group := range networkResourceGroups {
				if slices.Contains(rule.Destinations, group.ID) {
					resourceAppliedPolicies = append(resourceAppliedPolicies, policy)
					break
				}
			}
		}
	}

	return resourceAppliedPolicies
}

func (a *Account) GetPoliciesAppliedInNetwork(networkID string) []string {
	networkResources := a.getNetworkResources(networkID)

	policiesIDs := map[string]struct{}{}
	for _, resource := range networkResources {
		resourceAppliedPolicies := a.GetPoliciesForNetworkResource(resource.ID)
		for _, policy := range resourceAppliedPolicies {
			policiesIDs[policy.ID] = struct{}{}
		}
	}

	result := make([]string, 0, len(policiesIDs))
	for id := range policiesIDs {
		result = append(result, id)
	}

	return result
}

func (a *Account) GetResourceRoutersMap() map[string]map[string]*routerTypes.NetworkRouter {
	routers := make(map[string]map[string]*routerTypes.NetworkRouter)

	for _, router := range a.NetworkRouters {
		if !router.Enabled {
			continue
		}

		if routers[router.NetworkID] == nil {
			routers[router.NetworkID] = make(map[string]*routerTypes.NetworkRouter)
		}

		if router.Peer != "" {
			routers[router.NetworkID][router.Peer] = router
			continue
		}

		for _, peerGroup := range router.PeerGroups {
			g := a.Groups[peerGroup]
			if g != nil {
				for _, peerID := range g.Peers {
					routers[router.NetworkID][peerID] = router
				}
			}
		}
	}

	return routers
}

// AddAllGroup to account object if it doesn't exist
func (a *Account) AddAllGroup(disableDefaultPolicy bool) error {
	if len(a.Groups) == 0 {
		allGroup := &Group{
			ID:     xid.New().String(),
			Name:   "All",
			Issued: GroupIssuedAPI,
		}
		for _, peer := range a.Peers {
			allGroup.Peers = append(allGroup.Peers, peer.ID)
		}
		a.Groups = map[string]*Group{allGroup.ID: allGroup}

		if disableDefaultPolicy {
			return nil
		}

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

		a.Policies = []*Policy{defaultPolicy}
	}
	return nil
}
