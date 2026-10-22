package server

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/status"
)

// GetRoute gets a route object from account and route IDs
func (am *DefaultAccountManager) GetRoute(ctx context.Context, accountID string, routeID route.ID, userID string) (*route.Route, error) {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Routes, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetRouteByID(ctx, store.LockingStrengthNone, accountID, string(routeID))
}

// maxRouteCountries is the most countries a route can name, like the 32 domains a route can have.
const maxRouteCountries = 32

// checkRoutePrefixOrDomainsExistForPeers checks if a route with a given destination exists for a single peer or multiple peer groups.
func checkRoutePrefixOrDomainsExistForPeers(ctx context.Context, transaction store.Store, accountID string, checkRoute *route.Route, groupsMap map[string]*types.Group) error {
	// routes can have both peer and peer_groups
	routesWithPrefix, err := getRoutesByDestination(ctx, transaction, accountID, checkRoute)
	if err != nil {
		return err
	}

	// lets remember all the peers and the peer groups from routesWithPrefix
	seenPeers := make(map[string]bool)
	seenPeerGroups := make(map[string]bool)

	for _, prefixRoute := range routesWithPrefix {
		// we skip route(s) with the same network ID as we want to allow updating of the existing route
		// when creating a new route routeID is newly generated so nothing will be skipped
		if checkRoute.ID == prefixRoute.ID {
			continue
		}

		if prefixRoute.Peer != "" {
			seenPeers[string(prefixRoute.ID)] = true
		}

		peerGroupsMap, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, prefixRoute.PeerGroups)
		if err != nil {
			return err
		}

		for _, groupID := range prefixRoute.PeerGroups {
			seenPeerGroups[groupID] = true

			group, ok := peerGroupsMap[groupID]
			if !ok || group == nil {
				return status.Errorf(
					status.InvalidArgument, "failed to add route with %s - peer group %s doesn't exist",
					getRouteDescriptor(checkRoute), groupID,
				)
			}

			for _, pID := range group.Peers {
				seenPeers[pID] = true
			}
		}
	}

	if peerID := checkRoute.Peer; peerID != "" {
		// check that peerID exists and is not in any route as single peer or part of the group
		_, err = transaction.GetPeerByID(context.Background(), store.LockingStrengthNone, accountID, peerID)
		if err != nil {
			return status.Errorf(status.InvalidArgument, "peer with ID %s not found", peerID)
		}

		if _, ok := seenPeers[peerID]; ok {
			return status.Errorf(status.AlreadyExists,
				"failed to add route with %s - peer %s already has this route", getRouteDescriptor(checkRoute), peerID)
		}
	}

	// check that peerGroupIDs are not in any route peerGroups list
	for _, groupID := range checkRoute.PeerGroups {
		group := groupsMap[groupID] // we validated the group existence before entering this function, no need to check again.
		if _, ok := seenPeerGroups[groupID]; ok {
			return status.Errorf(
				status.AlreadyExists, "failed to add route with %s - peer group %s already has this route",
				getRouteDescriptor(checkRoute), group.Name)
		}

		// check that the peers from peerGroupIDs groups are not the same peers we saw in routesWithPrefix
		peersMap, err := transaction.GetPeersByIDs(ctx, store.LockingStrengthNone, accountID, group.Peers)
		if err != nil {
			return err
		}

		for _, id := range group.Peers {
			if _, ok := seenPeers[id]; ok {
				peer, ok := peersMap[id]
				if !ok || peer == nil {
					return status.Errorf(status.InvalidArgument, "peer with ID %s not found", id)
				}

				return status.Errorf(status.AlreadyExists,
					"failed to add route with %s - peer %s from the group %s already has this route",
					getRouteDescriptor(checkRoute), peer.Name, group.Name)
			}
		}
	}

	return nil
}

func getRouteDescriptor(r *route.Route) string {
	switch {
	case len(r.Countries) > 0:
		return fmt.Sprintf("countries [%s]", strings.Join(r.Countries, ", "))
	case len(r.Domains) > 0:
		return fmt.Sprintf("domains [%s]", r.Domains.SafeString())
	default:
		return fmt.Sprintf("prefix %s", r.Network.String())
	}
}

// routeDestination identifies what a route routes, so routes to the same destination are found.
// Domain and country routes share a placeholder network, so their own lists identify them.
func routeDestination(r *route.Route) string {
	switch {
	case len(r.Countries) > 0:
		return "countries:" + strings.Join(r.Countries, ",")
	case len(r.Domains) > 0:
		return "domains:" + r.Domains.PunycodeString()
	default:
		return r.Network.String()
	}
}

// CreateRoute creates and saves a copy of routeToCreate with a new ID.
func (am *DefaultAccountManager) CreateRoute(ctx context.Context, accountID, userID string, routeToCreate *route.Route) (*route.Route, error) {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Routes, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	if routeToCreate == nil {
		return nil, status.Errorf(status.InvalidArgument, "route provided is nil")
	}

	if len(routeToCreate.Domains) > 0 && routeToCreate.Network.IsValid() {
		return nil, status.Errorf(status.InvalidArgument, "domains and network should not be provided at the same time")
	}

	var newRoute *route.Route
	var snap *affectedpeers.Snapshot
	var change affectedpeers.Change

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		newRoute = routeToCreate.Copy()
		newRoute.ID = route.ID(xid.New().String())
		newRoute.AccountID = accountID

		if err = validateRoute(ctx, transaction, accountID, newRoute); err != nil {
			return err
		}

		if err = am.checkRouteCountries(newRoute.Countries); err != nil {
			return err
		}

		newRoute.PublicID = xid.New().String()

		if err = transaction.SaveRoute(ctx, newRoute); err != nil {
			return err
		}

		change = affectedpeers.Change{Routes: []*route.Route{newRoute}}
		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, userID, string(newRoute.ID), accountID, activity.RouteCreated, newRoute.EventMeta())

	am.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return newRoute, nil
}

// SaveRoute saves route
func (am *DefaultAccountManager) SaveRoute(ctx context.Context, accountID, userID string, routeToSave *route.Route) error {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Routes, operations.Update)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var oldRoute *route.Route
	var snap *affectedpeers.Snapshot
	var change affectedpeers.Change

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err = validateRoute(ctx, transaction, accountID, routeToSave); err != nil {
			return err
		}

		if err = am.checkRouteCountries(routeToSave.Countries); err != nil {
			return err
		}

		oldRoute, err = transaction.GetRouteByID(ctx, store.LockingStrengthUpdate, accountID, string(routeToSave.ID))
		if err != nil {
			return err
		}

		routeToSave.AccountID = accountID
		routeToSave.PublicID = oldRoute.PublicID

		if err = transaction.SaveRoute(ctx, routeToSave); err != nil {
			return err
		}

		change = affectedpeers.Change{Routes: []*route.Route{routeToSave, oldRoute}}
		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, string(routeToSave.ID), accountID, activity.RouteUpdated, routeToSave.EventMeta())

	am.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return nil
}

// DeleteRoute deletes route with routeID
func (am *DefaultAccountManager) DeleteRoute(ctx context.Context, accountID string, routeID route.ID, userID string) error {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Routes, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var rt *route.Route
	var snap *affectedpeers.Snapshot
	var change affectedpeers.Change

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		rt, err = transaction.GetRouteByID(ctx, store.LockingStrengthUpdate, accountID, string(routeID))
		if err != nil {
			return err
		}

		// Load before delete: pre-state captures everyone referencing the route.
		change = affectedpeers.Change{Routes: []*route.Route{rt}}
		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return err
		}

		if err = transaction.DeleteRoute(ctx, accountID, string(routeID)); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return fmt.Errorf("failed to delete route %s: %w", routeID, err)
	}

	am.StoreEvent(ctx, userID, string(rt.ID), accountID, activity.RouteRemoved, rt.EventMeta())

	am.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return nil
}

// ListRoutes returns a list of routes from account
func (am *DefaultAccountManager) ListRoutes(ctx context.Context, accountID, userID string) ([]*route.Route, error) {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Routes, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetAccountRoutes(ctx, store.LockingStrengthNone, accountID)
}

func validateRoute(ctx context.Context, transaction store.Store, accountID string, routeToSave *route.Route) error {
	if routeToSave == nil {
		return status.Errorf(status.InvalidArgument, "route provided is nil")
	}

	if routeToSave.Metric < route.MinMetric || routeToSave.Metric > route.MaxMetric {
		return status.Errorf(status.InvalidArgument, "metric should be between %d and %d", route.MinMetric, route.MaxMetric)
	}

	if utf8.RuneCountInString(string(routeToSave.NetID)) > route.MaxNetIDChar || routeToSave.NetID == "" {
		return status.Errorf(status.InvalidArgument, "identifier should be between 1 and %d", route.MaxNetIDChar)
	}

	if err := validateRouteDestination(routeToSave); err != nil {
		return err
	}

	if routeToSave.Peer != "" && len(routeToSave.PeerGroups) != 0 {
		return status.Errorf(status.InvalidArgument, "peer with ID and peer groups should not be provided at the same time")
	}

	groupsMap, err := validateRouteGroups(ctx, transaction, accountID, routeToSave)
	if err != nil {
		return err
	}

	return checkRoutePrefixOrDomainsExistForPeers(ctx, transaction, accountID, routeToSave, groupsMap)
}

// validateRouteDestination checks that a route has exactly one of network, domains and countries,
// and gives domain and country routes the placeholder network.
func validateRouteDestination(r *route.Route) error {
	if len(r.Countries) > 0 {
		return validateCountryRoute(r)
	}

	if len(r.Domains) > 0 && r.Network.IsValid() {
		return status.Errorf(status.InvalidArgument, "domains and network should not be provided at the same time")
	}

	if len(r.Domains) == 0 && !r.Network.IsValid() {
		return status.Errorf(status.InvalidArgument, "invalid Prefix")
	}

	if len(r.Domains) > 0 {
		r.Network = getPlaceholderIP()
	}
	return nil
}

// validateCountryRoute normalizes the countries of a country route to sorted, unique upper-case
// codes, so the same countries in another order are the same destination.
func validateCountryRoute(r *route.Route) error {
	if len(r.Domains) > 0 || r.Network.IsValid() {
		return status.Errorf(status.InvalidArgument, "countries should not be provided together with network or domains")
	}

	if len(r.Countries) > maxRouteCountries {
		return status.Errorf(status.InvalidArgument, "a route can have at most %d countries", maxRouteCountries)
	}

	countries := make([]string, 0, len(r.Countries))
	for _, country := range r.Countries {
		country = strings.ToUpper(country)
		if !geolocation.IsCountryCode(country) {
			return status.Errorf(status.InvalidArgument, "invalid country code %q", country)
		}
		countries = append(countries, country)
	}
	slices.Sort(countries)

	r.Countries = slices.Compact(countries)
	r.NetworkType = route.CountryNetwork
	r.Network = getPlaceholderIP()
	return nil
}

// checkRouteCountries checks that the geolocation service runs and knows every country of a route.
func (am *DefaultAccountManager) checkRouteCountries(countries []string) error {
	if len(countries) == 0 {
		return nil
	}

	if am.geo == nil {
		return status.Errorf(status.PreconditionFailed, "country routes need the geolocation service, which is disabled")
	}

	known, err := am.geo.GetAllCountries()
	if err != nil {
		return status.Errorf(status.Internal, "failed to get the known countries")
	}

	for _, country := range countries {
		if !slices.ContainsFunc(known, func(c geolocation.Country) bool {
			return strings.EqualFold(c.CountryISOCode, country)
		}) {
			return status.Errorf(status.InvalidArgument, "unknown country %q", country)
		}
	}
	return nil
}

// validateRouteGroups validates the route groups and returns the validated groups map.
func validateRouteGroups(ctx context.Context, transaction store.Store, accountID string, routeToSave *route.Route) (map[string]*types.Group, error) {
	groupsToValidate := slices.Concat(routeToSave.Groups, routeToSave.PeerGroups, routeToSave.AccessControlGroups)
	groupsMap, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, groupsToValidate)
	if err != nil {
		return nil, err
	}

	if len(routeToSave.PeerGroups) > 0 {
		if err = validateGroups(routeToSave.PeerGroups, groupsMap); err != nil {
			return nil, err
		}
	}

	if len(routeToSave.AccessControlGroups) > 0 {
		if err = validateGroups(routeToSave.AccessControlGroups, groupsMap); err != nil {
			return nil, err
		}
	}

	if err = validateGroups(routeToSave.Groups, groupsMap); err != nil {
		return nil, err
	}

	return groupsMap, nil
}

// getPlaceholderIP returns a placeholder IP address for the route if domains or countries are used
func getPlaceholderIP() netip.Prefix {
	// Using an IP from the documentation range to minimize impact in case older clients try to set a route
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, 0}), 32)
}

// getRoutesByDestination returns the routes of an account that route the same destination as checkRoute.
func getRoutesByDestination(ctx context.Context, transaction store.Store, accountID string, checkRoute *route.Route) ([]*route.Route, error) {
	accountRoutes, err := transaction.GetAccountRoutes(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	destination := routeDestination(checkRoute)
	routes := make([]*route.Route, 0)
	for _, r := range accountRoutes {
		if routeDestination(r) == destination {
			routes = append(routes, r)
		}
	}

	return routes, nil
}
