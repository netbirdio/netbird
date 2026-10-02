package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/routemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

type selectRoute struct {
	NetID         route.NetID
	Network       netip.Prefix
	Domains       domain.List
	Selected      bool
	extraNetworks []netip.Prefix
}

// ListNetworks returns a list of all available networks.
func (s *Server) ListNetworks(context.Context, *proto.ListNetworksRequest) (*proto.ListNetworksResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.checkNetworksDisabled() {
		return nil, gstatus.Errorf(codes.Unavailable, errNetworksDisabled)
	}

	if s.connectClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	engine := s.connectClient.Engine()
	if engine == nil {
		return nil, fmt.Errorf("not connected")
	}

	routeMgr := engine.GetRouteManager()
	if routeMgr == nil {
		return nil, fmt.Errorf("no route manager")
	}

	routesMap := routeMgr.GetClientRoutesWithNetID()
	routeSelector := routeMgr.GetRouteSelector()

	v6ExitMerged := route.V6ExitMergeSet(routesMap)

	var routes []*selectRoute
	for id, rt := range routesMap {
		if len(rt) == 0 {
			continue
		}
		// Skip v6 exit nodes that are merged into their v4 counterpart.
		if _, ok := v6ExitMerged[id]; ok {
			continue
		}

		r := &selectRoute{
			NetID:    id,
			Network:  rt[0].Network,
			Domains:  rt[0].Domains,
			Selected: routeSelector.IsSelected(id),
		}

		// Merge paired v6 exit node prefix into this entry.
		v6ID := route.NetID(string(id) + route.V6ExitSuffix)
		if _, ok := v6ExitMerged[v6ID]; ok && len(routesMap[v6ID]) > 0 {
			r.extraNetworks = []netip.Prefix{routesMap[v6ID][0].Network}
		}

		routes = append(routes, r)
	}

	sort.Slice(routes, func(i, j int) bool {
		iPrefix := routes[i].Network.Bits()
		jPrefix := routes[j].Network.Bits()

		if iPrefix == jPrefix {
			iAddr := routes[i].Network.Addr()
			jAddr := routes[j].Network.Addr()
			if iAddr == jAddr {
				return routes[i].NetID < routes[j].NetID
			}
			return iAddr.String() < jAddr.String()
		}
		return iPrefix < jPrefix
	})

	resolvedDomains := s.statusRecorder.GetResolvedDomainsStates()
	var pbRoutes []*proto.Network
	for _, route := range routes {
		rangeStr := route.Network.String()
		for _, extra := range route.extraNetworks {
			rangeStr += ", " + extra.String()
		}
		pbRoute := &proto.Network{
			ID:          string(route.NetID),
			Range:       rangeStr,
			Domains:     route.Domains.ToSafeStringList(),
			ResolvedIPs: map[string]*proto.IPList{},
			Selected:    route.Selected,
		}

		// Group resolved IPs by their parent domain
		domainMap := map[domain.Domain][]string{}

		for resolvedDomain, info := range resolvedDomains {
			// Check if this resolved domain's parent is in our route's domains
			if slices.Contains(route.Domains, info.ParentDomain) {
				ips := make([]string, 0, len(info.Prefixes))
				for _, prefix := range info.Prefixes {
					ips = append(ips, prefix.Addr().String())
				}
				domainMap[resolvedDomain] = ips
			}
		}

		// Convert to proto format
		for domain, ips := range domainMap {
			pbRoute.ResolvedIPs[domain.SafeString()] = &proto.IPList{
				Ips: ips,
			}
		}

		pbRoutes = append(pbRoutes, pbRoute)
	}

	return &proto.ListNetworksResponse{
		Routes: pbRoutes,
	}, nil
}

// SelectNetworks selects specific networks based on the client request.
func (s *Server) SelectNetworks(_ context.Context, req *proto.SelectNetworksRequest) (*proto.SelectNetworksResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.checkNetworksDisabled() {
		return nil, gstatus.Errorf(codes.Unavailable, errNetworksDisabled)
	}

	if s.connectClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	engine := s.connectClient.Engine()
	if engine == nil {
		return nil, fmt.Errorf("not connected")
	}

	routeManager := engine.GetRouteManager()
	if routeManager == nil {
		return nil, fmt.Errorf("no route manager")
	}

	var err error
	if req.GetAll() {
		routeManager.SelectAllRoutes()
	} else {
		err = routeManager.SelectRoutes(toNetIDs(req.GetNetworkIDs()), req.GetAppend())
	}

	if selectionApplied(err) {
		s.publishSelectionEvent("Network selection changed", req)
	}

	if err != nil {
		return nil, err
	}

	return &proto.SelectNetworksResponse{}, nil
}

// DeselectNetworks deselects specific networks based on the client request.
func (s *Server) DeselectNetworks(_ context.Context, req *proto.SelectNetworksRequest) (*proto.SelectNetworksResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.checkNetworksDisabled() {
		return nil, gstatus.Errorf(codes.Unavailable, errNetworksDisabled)
	}

	if s.connectClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	engine := s.connectClient.Engine()
	if engine == nil {
		return nil, fmt.Errorf("not connected")
	}

	routeManager := engine.GetRouteManager()
	if routeManager == nil {
		return nil, fmt.Errorf("no route manager")
	}

	var err error
	if req.GetAll() {
		routeManager.DeselectAllRoutes()
	} else {
		err = routeManager.DeselectRoutes(toNetIDs(req.GetNetworkIDs()))
	}

	if selectionApplied(err) {
		s.publishSelectionEvent("Network deselection changed", req)
	}

	if err != nil {
		return nil, err
	}

	return &proto.SelectNetworksResponse{}, nil
}

// selectionApplied reports whether a select/deselect request changed the
// selection. A partial failure (an unknown ID mixed with valid ones) still
// applies the valid IDs, so it counts as applied; only ErrNoRoutesApplied
// means the request left the selection untouched.
func selectionApplied(err error) bool {
	return !errors.Is(err, routemanager.ErrNoRoutesApplied)
}

// publishSelectionEvent reports a network selection or deselection change,
// with the request's networks, append flag, and all flag as metadata.
func (s *Server) publishSelectionEvent(title string, req *proto.SelectNetworksRequest) {
	s.statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_SYSTEM,
		title,
		"",
		map[string]string{
			"networks": strings.Join(req.GetNetworkIDs(), ", "),
			"append":   fmt.Sprint(req.GetAppend()),
			"all":      fmt.Sprint(req.GetAll()),
		},
	)
}

func toNetIDs(routes []string) []route.NetID {
	var netIDs []route.NetID
	for _, rt := range routes {
		netIDs = append(netIDs, route.NetID(rt))
	}
	return netIDs
}
