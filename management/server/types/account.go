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
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/domain"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/telemetry"
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
)

type LookupMap map[string]struct{}

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
	Settings *Settings `gorm:"embedded;embeddedPrefix:settings_"`

	Networks         []*networkTypes.Network          `gorm:"foreignKey:AccountID;references:id"`
	NetworkRouters   []*routerTypes.NetworkRouter     `gorm:"foreignKey:AccountID;references:id"`
	NetworkResources []*resourceTypes.NetworkResource `gorm:"foreignKey:AccountID;references:id"`
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

// GetRoutesToSync returns the enabled routes for the peer ID and the routes
// from the ACL peers that have distribution groups associated with the peer ID.
// Please mind, that the returned route.Route objects will contain Peer.Key instead of Peer.ID.
func (a *Account) GetRoutesToSync(ctx context.Context, peerID string, aclPeers []*nbpeer.Peer) []*route.Route {
	routes, peerDisabledRoutes := a.getRoutingPeerRoutes(ctx, peerID)
	peerRoutesMembership := make(LookupMap)
	for _, r := range append(routes, peerDisabledRoutes...) {
		peerRoutesMembership[string(r.GetHAUniqueID())] = struct{}{}
	}

	groupListMap := a.GetPeerGroups(peerID)
	for _, peer := range aclPeers {
		activeRoutes, _ := a.getRoutingPeerRoutes(ctx, peer.ID)
		groupFilteredRoutes := a.filterRoutesByGroups(activeRoutes, groupListMap)
		filteredRoutes := a.filterRoutesFromPeersOfSameHAGroup(groupFilteredRoutes, peerRoutesMembership)
		routes = append(routes, filteredRoutes...)
	}

	return routes
}

// filterRoutesFromPeersOfSameHAGroup filters and returns a list of routes that don't share the same HA route membership
func (a *Account) filterRoutesFromPeersOfSameHAGroup(routes []*route.Route, peerMemberships LookupMap) []*route.Route {
	var filteredRoutes []*route.Route
	for _, r := range routes {
		_, found := peerMemberships[string(r.GetHAUniqueID())]
		if !found {
			filteredRoutes = append(filteredRoutes, r)
		}
	}
	return filteredRoutes
}

// filterRoutesByGroups returns a list with routes that have distribution groups in the group's map
func (a *Account) filterRoutesByGroups(routes []*route.Route, groupListMap LookupMap) []*route.Route {
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

// getRoutingPeerRoutes returns the enabled and disabled lists of routes that the given routing peer serves
// Please mind, that the returned route.Route objects will contain Peer.Key instead of Peer.ID.
// If the given is not a routing peer, then the lists are empty.
func (a *Account) getRoutingPeerRoutes(ctx context.Context, peerID string) (enabledRoutes []*route.Route, disabledRoutes []*route.Route) {

	peer := a.GetPeer(peerID)
	if peer == nil {
		log.WithContext(ctx).Errorf("peer %s that doesn't exist under account %s", peerID, a.Id)
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
		for _, groupID := range r.PeerGroups {
			group := a.GetGroup(groupID)
			if group == nil {
				log.WithContext(ctx).Errorf("route %s has peers group %s that doesn't exist under account %s", r.ID, groupID, a.Id)
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

// GetPeerNetworkMap returns the networkmap for the given peer ID.
func (a *Account) GetPeerNetworkMap(
	ctx context.Context,
	peerID string,
	peersCustomZone nbdns.CustomZone,
	validatedPeersMap map[string]struct{},
	resourcePolicies map[string][]*Policy,
	routers map[string]map[string]*routerTypes.NetworkRouter,
	metrics *telemetry.AccountManagerMetrics,
) *NetworkMap {
	start := time.Now()

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

	aclPeers, firewallRules := a.GetPeerConnectionResources(ctx, peerID, validatedPeersMap)
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

	routesUpdate := a.GetRoutesToSync(ctx, peerID, peersToConnect)
	routesFirewallRules := a.GetPeerRoutesFirewallRules(ctx, peerID, validatedPeersMap)
	isRouter, networkResourcesRoutes, sourcePeers := a.GetNetworkResourcesRoutesToSync(ctx, peerID, resourcePolicies, routers)
	var networkResourcesFirewallRules []*RouteFirewallRule
	if isRouter {
		networkResourcesFirewallRules = a.GetPeerNetworkResourceFirewallRules(ctx, peer, validatedPeersMap, networkResourcesRoutes, resourcePolicies)
	}
	peersToConnectIncludingRouters := a.addNetworksRoutingPeers(networkResourcesRoutes, peer, peersToConnect, expiredPeers, isRouter, sourcePeers)

	dnsManagementStatus := a.getPeerDNSManagementStatus(peerID)
	dnsUpdate := nbdns.Config{
		ServiceEnable: dnsManagementStatus,
	}

	if dnsManagementStatus {
		var zones []nbdns.CustomZone

		if peersCustomZone.Domain != "" {
			zones = append(zones, peersCustomZone)
		}
		dnsUpdate.CustomZones = zones
		dnsUpdate.NameServerGroups = getPeerNSGroups(a, peerID)
	}

	nm := &NetworkMap{
		Peers:               peersToConnectIncludingRouters,
		Network:             a.Network.Copy(),
		Routes:              slices.Concat(networkResourcesRoutes, routesUpdate),
		DNSConfig:           dnsUpdate,
		OfflinePeers:        expiredPeers,
		FirewallRules:       firewallRules,
		RoutesFirewallRules: slices.Concat(networkResourcesFirewallRules, routesFirewallRules),
	}

	if metrics != nil {
		objectCount := int64(len(peersToConnect) + len(expiredPeers) + len(routesUpdate) + len(firewallRules))
		metrics.CountNetworkMapObjects(objectCount)
		metrics.CountGetPeerNetworkMapDuration(time.Since(start))

		if objectCount > 5000 {
			log.WithContext(ctx).Tracef("account: %s has a total resource count of %d objects, "+
				"peers to connect: %d, expired peers: %d, routes: %d, firewall rules: %d",
				a.Id, objectCount, len(peersToConnect), len(expiredPeers), len(routesUpdate), len(firewallRules))
		}
	}

	return nm
}

func (a *Account) addNetworksRoutingPeers(
	networkResourcesRoutes []*route.Route,
	peer *nbpeer.Peer,
	peersToConnect []*nbpeer.Peer,
	expiredPeers []*nbpeer.Peer,
	isRouter bool,
	sourcePeers map[string]struct{},
) []*nbpeer.Peer {

	networkRoutesPeers := make(map[string]struct{}, len(networkResourcesRoutes))
	for _, r := range networkResourcesRoutes {
		networkRoutesPeers[r.PeerID] = struct{}{}
	}

	delete(sourcePeers, peer.ID)
	delete(networkRoutesPeers, peer.ID)

	for _, existingPeer := range peersToConnect {
		delete(sourcePeers, existingPeer.ID)
		delete(networkRoutesPeers, existingPeer.ID)
	}
	for _, expPeer := range expiredPeers {
		delete(sourcePeers, expPeer.ID)
		delete(networkRoutesPeers, expPeer.ID)
	}

	missingPeers := make(map[string]struct{}, len(sourcePeers)+len(networkRoutesPeers))
	if isRouter {
		for p := range sourcePeers {
			missingPeers[p] = struct{}{}
		}
	}
	for p := range networkRoutesPeers {
		missingPeers[p] = struct{}{}
	}

	for p := range missingPeers {
		if missingPeer := a.Peers[p]; missingPeer != nil {
			peersToConnect = append(peersToConnect, missingPeer)
		}
	}

	return peersToConnect
}

func getPeerNSGroups(account *Account, peerID string) []*nbdns.NameServerGroup {
	groupList := account.GetPeerGroups(peerID)

	var peerNSGroups []*nbdns.NameServerGroup

	for _, nsGroup := range account.NameServerGroups {
		if !nsGroup.Enabled {
			continue
		}
		for _, gID := range nsGroup.Groups {
			_, found := groupList[gID]
			if found {
				if !peerIsNameserver(account.GetPeer(peerID), nsGroup) {
					peerNSGroups = append(peerNSGroups, nsGroup.Copy())
					break
				}
			}
		}
	}

	return peerNSGroups
}

// peerIsNameserver returns true if the peer is a nameserver for a nsGroup
func peerIsNameserver(peer *nbpeer.Peer, nsGroup *nbdns.NameServerGroup) bool {
	for _, ns := range nsGroup.NameServers {
		if peer.IP.Equal(ns.IP.AsSlice()) {
			return true
		}
	}
	return false
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

func (a *Account) getPeerDNSManagementStatus(peerID string) bool {
	peerGroups := a.GetPeerGroups(peerID)
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

func (a *Account) GetPeerGroups(peerID string) LookupMap {
	groupList := make(LookupMap)
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

// GetPeerConnectionResources for a given peer
//
// This function returns the list of peers and firewall rules that are applicable to a given peer.
func (a *Account) GetPeerConnectionResources(ctx context.Context, peerID string, validatedPeersMap map[string]struct{}) ([]*nbpeer.Peer, []*FirewallRule) {
	generateResources, getAccumulatedResources := a.connResourcesGenerator(ctx)
	for _, policy := range a.Policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			sourcePeers, peerInSources := a.getAllPeersFromGroups(ctx, rule.Sources, peerID, policy.SourcePostureChecks, validatedPeersMap)
			destinationPeers, peerInDestinations := a.getAllPeersFromGroups(ctx, rule.Destinations, peerID, nil, validatedPeersMap)

			if rule.Bidirectional {
				if peerInSources {
					generateResources(rule, destinationPeers, FirewallRuleDirectionIN)
				}
				if peerInDestinations {
					generateResources(rule, sourcePeers, FirewallRuleDirectionOUT)
				}
			}

			if peerInSources {
				generateResources(rule, destinationPeers, FirewallRuleDirectionOUT)
			}

			if peerInDestinations {
				generateResources(rule, sourcePeers, FirewallRuleDirectionIN)
			}
		}
	}

	return getAccumulatedResources()
}

// connResourcesGenerator returns generator and accumulator function which returns the result of generator calls
//
// The generator function is used to generate the list of peers and firewall rules that are applicable to a given peer.
// It safe to call the generator function multiple times for same peer and different rules no duplicates will be
// generated. The accumulator function returns the result of all the generator calls.
func (a *Account) connResourcesGenerator(ctx context.Context) (func(*PolicyRule, []*nbpeer.Peer, int), func() ([]*nbpeer.Peer, []*FirewallRule)) {
	rulesExists := make(map[string]struct{})
	peersExists := make(map[string]struct{})
	rules := make([]*FirewallRule, 0)
	peers := make([]*nbpeer.Peer, 0)

	all, err := a.GetGroupAll()
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get group all: %v", err)
		all = &Group{}
	}

	return func(rule *PolicyRule, groupPeers []*nbpeer.Peer, direction int) {
			isAll := (len(all.Peers) - 1) == len(groupPeers)
			for _, peer := range groupPeers {
				if peer == nil {
					continue
				}

				if _, ok := peersExists[peer.ID]; !ok {
					peers = append(peers, peer)
					peersExists[peer.ID] = struct{}{}
				}

				fr := FirewallRule{
					PeerIP:    peer.IP.String(),
					Direction: direction,
					Action:    string(rule.Action),
					Protocol:  string(rule.Protocol),
				}

				if isAll {
					fr.PeerIP = "0.0.0.0"
				}

				ruleID := rule.ID + fr.PeerIP + strconv.Itoa(direction) +
					fr.Protocol + fr.Action + strings.Join(rule.Ports, ",")
				if _, ok := rulesExists[ruleID]; ok {
					continue
				}
				rulesExists[ruleID] = struct{}{}

				if len(rule.Ports) == 0 {
					rules = append(rules, &fr)
					continue
				}

				for _, port := range rule.Ports {
					pr := fr // clone rule and add set new port
					pr.Port = port
					rules = append(rules, &pr)
				}
			}
		}, func() ([]*nbpeer.Peer, []*FirewallRule) {
			return peers, rules
		}
}

// getAllPeersFromGroups for given peer ID and list of groups
//
// Returns a list of peers from specified groups that pass specified posture checks
// and a boolean indicating if the supplied peer ID exists within these groups.
//
// Important: Posture checks are applicable only to source group peers,
// for destination group peers, call this method with an empty list of sourcePostureChecksIDs
func (a *Account) getAllPeersFromGroups(ctx context.Context, groups []string, peerID string, sourcePostureChecksIDs []string, validatedPeersMap map[string]struct{}) ([]*nbpeer.Peer, bool) {
	peerInGroups := false
	uniquePeerIDs := a.getUniquePeerIDsFromGroupsIDs(ctx, groups)
	filteredPeers := make([]*nbpeer.Peer, 0, len(uniquePeerIDs))
	for _, p := range uniquePeerIDs {
		peer, ok := a.Peers[p]
		if !ok || peer == nil {
			continue
		}

		// validate the peer based on policy posture checks applied
		isValid := a.validatePostureChecksOnPeer(ctx, sourcePostureChecksIDs, peer.ID)
		if !isValid {
			continue
		}

		if _, ok := validatedPeersMap[peer.ID]; !ok {
			continue
		}

		if peer.ID == peerID {
			peerInGroups = true
			continue
		}

		filteredPeers = append(filteredPeers, peer)
	}

	return filteredPeers, peerInGroups
}

// validatePostureChecksOnPeer validates the posture checks on a peer
func (a *Account) validatePostureChecksOnPeer(ctx context.Context, sourcePostureChecksID []string, peerID string) bool {
	peer, ok := a.Peers[peerID]
	if !ok && peer == nil {
		return false
	}

	for _, postureChecksID := range sourcePostureChecksID {
		postureChecks := a.GetPostureChecks(postureChecksID)
		if postureChecks == nil {
			continue
		}

		for _, check := range postureChecks.GetChecks() {
			isValid, err := check.Check(ctx, *peer)
			if err != nil {
				log.WithContext(ctx).Debugf("an error occurred check %s: on peer: %s :%s", check.Name(), peer.ID, err.Error())
			}
			if !isValid {
				return false
			}
		}
	}
	return true
}

func (a *Account) GetPostureChecks(postureChecksID string) *posture.Checks {
	for _, postureChecks := range a.PostureChecks {
		if postureChecks.ID == postureChecksID {
			return postureChecks
		}
	}
	return nil
}

// GetPeerRoutesFirewallRules gets the routes firewall rules associated with a routing peer ID for the account.
func (a *Account) GetPeerRoutesFirewallRules(ctx context.Context, peerID string, validatedPeersMap map[string]struct{}) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0, len(a.Routes))

	enabledRoutes, _ := a.getRoutingPeerRoutes(ctx, peerID)
	for _, route := range enabledRoutes {
		// If no access control groups are specified, accept all traffic.
		if len(route.AccessControlGroups) == 0 {
			defaultPermit := getDefaultPermit(route)
			routesFirewallRules = append(routesFirewallRules, defaultPermit...)
			continue
		}

		distributionPeers := a.getDistributionGroupsPeers(route)

		for _, accessGroup := range route.AccessControlGroups {
			policies := GetAllRoutePoliciesFromGroups(a, []string{accessGroup})
			rules := a.getRouteFirewallRules(ctx, peerID, policies, route, validatedPeersMap, distributionPeers)
			routesFirewallRules = append(routesFirewallRules, rules...)
		}
	}

	return routesFirewallRules
}

func (a *Account) getRouteFirewallRules(ctx context.Context, peerID string, policies []*Policy, route *route.Route, validatedPeersMap map[string]struct{}, distributionPeers map[string]struct{}) []*RouteFirewallRule {
	var fwRules []*RouteFirewallRule
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			rulePeers := a.getRulePeers(rule, policy.SourcePostureChecks, peerID, distributionPeers, validatedPeersMap)
			rules := generateRouteFirewallRules(ctx, route, rule, rulePeers, FirewallRuleDirectionIN)
			fwRules = append(fwRules, rules...)
		}
	}
	return fwRules
}

func (a *Account) getRulePeers(rule *PolicyRule, postureChecks []string, peerID string, distributionPeers map[string]struct{}, validatedPeersMap map[string]struct{}) []*nbpeer.Peer {
	distPeersWithPolicy := make(map[string]struct{})
	for _, id := range rule.Sources {
		group := a.Groups[id]
		if group == nil {
			continue
		}

		for _, pID := range group.Peers {
			if pID == peerID {
				continue
			}
			_, distPeer := distributionPeers[pID]
			_, valid := validatedPeersMap[pID]
			if distPeer && valid && a.validatePostureChecksOnPeer(context.Background(), postureChecks, pID) {
				distPeersWithPolicy[pID] = struct{}{}
			}
		}
	}

	distributionGroupPeers := make([]*nbpeer.Peer, 0, len(distPeersWithPolicy))
	for pID := range distPeersWithPolicy {
		peer := a.Peers[pID]
		if peer == nil {
			continue
		}
		distributionGroupPeers = append(distributionGroupPeers, peer)
	}
	return distributionGroupPeers
}

func (a *Account) getDistributionGroupsPeers(route *route.Route) map[string]struct{} {
	distPeers := make(map[string]struct{})
	for _, id := range route.Groups {
		group := a.Groups[id]
		if group == nil {
			continue
		}

		for _, pID := range group.Peers {
			distPeers[pID] = struct{}{}
		}
	}
	return distPeers
}

func getDefaultPermit(route *route.Route) []*RouteFirewallRule {
	var rules []*RouteFirewallRule

	sources := []string{"0.0.0.0/0"}
	if route.Network.Addr().Is6() {
		sources = []string{"::/0"}
	}
	rule := RouteFirewallRule{
		SourceRanges: sources,
		Action:       string(PolicyTrafficActionAccept),
		Destination:  route.Network.String(),
		Protocol:     string(PolicyRuleProtocolALL),
		Domains:      route.Domains,
		IsDynamic:    route.IsDynamic(),
	}

	rules = append(rules, &rule)

	// dynamic routes always contain an IPv4 placeholder as destination, hence we must add IPv6 rules additionally
	if route.IsDynamic() {
		ruleV6 := rule
		ruleV6.SourceRanges = []string{"::/0"}
		rules = append(rules, &ruleV6)
	}

	return rules
}

// GetAllRoutePoliciesFromGroups retrieves route policies associated with the specified access control groups
// and returns a list of policies that have rules with destinations matching the specified groups.
func GetAllRoutePoliciesFromGroups(account *Account, accessControlGroups []string) []*Policy {
	routePolicies := make([]*Policy, 0)
	for _, groupID := range accessControlGroups {
		group, ok := account.Groups[groupID]
		if !ok {
			continue
		}

		for _, policy := range account.Policies {
			for _, rule := range policy.Rules {
				exist := slices.ContainsFunc(rule.Destinations, func(groupID string) bool {
					return groupID == group.ID
				})
				if exist {
					routePolicies = append(routePolicies, policy)
					continue
				}
			}
		}
	}

	return routePolicies
}

// GetPeerNetworkResourceFirewallRules gets the network resources firewall rules associated with a routing peer ID for the account.
func (a *Account) GetPeerNetworkResourceFirewallRules(ctx context.Context, peer *nbpeer.Peer, validatedPeersMap map[string]struct{}, routes []*route.Route, resourcePolicies map[string][]*Policy) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0)

	for _, route := range routes {
		if route.Peer != peer.Key {
			continue
		}
		resourceAppliedPolicies := resourcePolicies[route.GetResourceID()]
		distributionPeers := getPoliciesSourcePeers(resourceAppliedPolicies, a.Groups)

		rules := a.getRouteFirewallRules(ctx, peer.ID, resourceAppliedPolicies, route, validatedPeersMap, distributionPeers)
		for _, rule := range rules {
			if len(rule.SourceRanges) > 0 {
				routesFirewallRules = append(routesFirewallRules, rule)
			}
		}
	}

	return routesFirewallRules
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

// GetNetworkResourcesRoutesToSync returns network routes for syncing with a specific peer and its ACL peers.
func (a *Account) GetNetworkResourcesRoutesToSync(ctx context.Context, peerID string, resourcePolicies map[string][]*Policy, routers map[string]map[string]*routerTypes.NetworkRouter) (bool, []*route.Route, map[string]struct{}) {
	var isRoutingPeer bool
	var routes []*route.Route
	allSourcePeers := make(map[string]struct{}, len(a.Peers))

	for _, resource := range a.NetworkResources {
		if !resource.Enabled {
			continue
		}

		var addSourcePeers bool

		networkRoutingPeers, exists := routers[resource.NetworkID]
		if exists {
			if router, ok := networkRoutingPeers[peerID]; ok {
				isRoutingPeer, addSourcePeers = true, true
				routes = append(routes, a.getNetworkResourcesRoutes(resource, peerID, router, resourcePolicies)...)
			}
		}

		addedResourceRoute := false
		for _, policy := range resourcePolicies[resource.ID] {
			peers := a.getUniquePeerIDsFromGroupsIDs(ctx, policy.SourceGroups())
			if addSourcePeers {
				for _, pID := range a.getPostureValidPeers(peers, policy.SourcePostureChecks) {
					allSourcePeers[pID] = struct{}{}
				}
			} else if slices.Contains(peers, peerID) && a.validatePostureChecksOnPeer(ctx, policy.SourcePostureChecks, peerID) {
				// add routes for the resource if the peer is in the distribution group
				for peerId, router := range networkRoutingPeers {
					routes = append(routes, a.getNetworkResourcesRoutes(resource, peerId, router, resourcePolicies)...)
				}
				addedResourceRoute = true
			}
			if addedResourceRoute {
				break
			}
		}
	}

	return isRoutingPeer, routes, allSourcePeers
}

func (a *Account) getPostureValidPeers(inputPeers []string, postureChecksIDs []string) []string {
	var dest []string
	for _, peerID := range inputPeers {
		if a.validatePostureChecksOnPeer(context.Background(), postureChecksIDs, peerID) {
			dest = append(dest, peerID)
		}
	}
	return dest
}

func (a *Account) getUniquePeerIDsFromGroupsIDs(ctx context.Context, groups []string) []string {
	peerIDs := make(map[string]struct{}, len(groups)) // we expect at least one peer per group as initial capacity
	for _, groupID := range groups {
		group := a.GetGroup(groupID)
		if group == nil {
			log.WithContext(ctx).Warnf("group %s doesn't exist under account %s, will continue map generation without it", groupID, a.Id)
			continue
		}

		if group.IsGroupAll() || len(groups) == 1 {
			return group.Peers
		}

		for _, peerID := range group.Peers {
			peerIDs[peerID] = struct{}{}
		}
	}

	ids := make([]string, 0, len(peerIDs))
	for peerID := range peerIDs {
		ids = append(ids, peerID)
	}

	return ids
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

// getNetworkResourcesRoutes convert the network resources list to routes list.
func (a *Account) getNetworkResourcesRoutes(resource *resourceTypes.NetworkResource, peerId string, router *routerTypes.NetworkRouter, resourcePolicies map[string][]*Policy) []*route.Route {
	resourceAppliedPolicies := resourcePolicies[resource.ID]

	var routes []*route.Route
	// distribute the resource routes only if there is policy applied to it
	if len(resourceAppliedPolicies) > 0 {
		peer := a.GetPeer(peerId)
		if peer != nil {
			routes = append(routes, resource.ToRoute(peer, router))
		}
	}

	return routes
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

// getPoliciesSourcePeers collects all unique peers from the source groups defined in the given policies.
func getPoliciesSourcePeers(policies []*Policy, groups map[string]*Group) map[string]struct{} {
	sourcePeers := make(map[string]struct{})

	for _, policy := range policies {
		for _, rule := range policy.Rules {
			for _, sourceGroup := range rule.Sources {
				group := groups[sourceGroup]
				if group == nil {
					continue
				}

				for _, peer := range group.Peers {
					sourcePeers[peer] = struct{}{}
				}
			}
		}
	}

	return sourcePeers
}
