package server

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

type selectRoute struct {
	NetID    route.NetID
	Network  netip.Prefix
	Domains  domain.List
	Selected bool
}

// ListNetworks returns a list of all available networks.
func (s *Server) ListNetworks(context.Context, *proto.ListNetworksRequest) (*proto.ListNetworksResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

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

	var routes []*selectRoute
	for id, rt := range routesMap {
		if len(rt) == 0 {
			continue
		}
		route := &selectRoute{
			NetID:    id,
			Network:  rt[0].Network,
			Domains:  rt[0].Domains,
			Selected: routeSelector.IsSelected(id),
		}
		routes = append(routes, route)
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
		pbRoute := &proto.Network{
			ID:          string(route.NetID),
			Range:       route.Network.String(),
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

	routeSelector := routeManager.GetRouteSelector()
	if req.GetAll() {
		routeSelector.SelectAllRoutes()
	} else {
		routes := toNetIDs(req.GetNetworkIDs())
		netIdRoutes := maps.Keys(routeManager.GetClientRoutesWithNetID())
		if err := routeSelector.SelectRoutes(routes, req.GetAppend(), netIdRoutes); err != nil {
			return nil, fmt.Errorf("select routes: %w", err)
		}
	}
	routeManager.TriggerSelection(routeManager.GetClientRoutes())

	s.statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_SYSTEM,
		"Network selection changed",
		"",
		map[string]string{
			"networks": strings.Join(req.GetNetworkIDs(), ", "),
			"append":   fmt.Sprint(req.GetAppend()),
			"all":      fmt.Sprint(req.GetAll()),
		},
	)

	return &proto.SelectNetworksResponse{}, nil
}

// DeselectNetworks deselects specific networks based on the client request.
func (s *Server) DeselectNetworks(_ context.Context, req *proto.SelectNetworksRequest) (*proto.SelectNetworksResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

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

	routeSelector := routeManager.GetRouteSelector()
	if req.GetAll() {
		routeSelector.DeselectAllRoutes()
	} else {
		routes := toNetIDs(req.GetNetworkIDs())
		netIdRoutes := maps.Keys(routeManager.GetClientRoutesWithNetID())
		if err := routeSelector.DeselectRoutes(routes, netIdRoutes); err != nil {
			return nil, fmt.Errorf("deselect routes: %w", err)
		}
	}
	routeManager.TriggerSelection(routeManager.GetClientRoutes())

	s.statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_SYSTEM,
		"Network deselection changed",
		"",
		map[string]string{
			"networks": strings.Join(req.GetNetworkIDs(), ", "),
			"append":   fmt.Sprint(req.GetAppend()),
			"all":      fmt.Sprint(req.GetAll()),
		},
	)

	return &proto.SelectNetworksResponse{}, nil
}

func toNetIDs(routes []string) []route.NetID {
	var netIDs []route.NetID
	for _, rt := range routes {
		netIDs = append(netIDs, route.NetID(rt))
	}
	return netIDs
}
