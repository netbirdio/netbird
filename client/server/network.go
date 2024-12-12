package server

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/route"
)

type selectRoute struct {
	NetID    route.NetID
	Network  netip.Prefix
	Domains  domain.List
	Selected bool
}

// ListRoutes returns a list of all available routes.
func (s *Server) ListRoutes(context.Context, *proto.ListRoutesRequest) (*proto.ListRoutesResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.connectClient == nil {
		return nil, fmt.Errorf("not connected")
	}

	engine := s.connectClient.Engine()
	if engine == nil {
		return nil, fmt.Errorf("not connected")
	}

	routesMap := engine.GetRouteManager().GetClientRoutesWithNetID()
	routeSelector := engine.GetRouteManager().GetRouteSelector()

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
	var pbRoutes []*proto.Route
	for _, route := range routes {
		pbRoute := &proto.Route{
			ID:          string(route.NetID),
			Network:     route.Network.String(),
			Domains:     route.Domains.ToSafeStringList(),
			ResolvedIPs: map[string]*proto.IPList{},
			Selected:    route.Selected,
		}

		for _, domain := range route.Domains {
			if prefixes, exists := resolvedDomains[domain]; exists {
				var ipStrings []string
				for _, prefix := range prefixes {
					ipStrings = append(ipStrings, prefix.Addr().String())
				}
				pbRoute.ResolvedIPs[string(domain)] = &proto.IPList{
					Ips: ipStrings,
				}
			}
		}
		pbRoutes = append(pbRoutes, pbRoute)
	}

	return &proto.ListRoutesResponse{
		Routes: pbRoutes,
	}, nil
}

// SelectRoutes selects specific routes based on the client request.
func (s *Server) SelectRoutes(_ context.Context, req *proto.SelectRoutesRequest) (*proto.SelectRoutesResponse, error) {
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
	routeSelector := routeManager.GetRouteSelector()
	if req.GetAll() {
		routeSelector.SelectAllRoutes()
	} else {
		routes := toNetIDs(req.GetRouteIDs())
		netIdRoutes := maps.Keys(routeManager.GetClientRoutesWithNetID())
		if err := routeSelector.SelectRoutes(routes, req.GetAppend(), netIdRoutes); err != nil {
			return nil, fmt.Errorf("select routes: %w", err)
		}
	}
	routeManager.TriggerSelection(routeManager.GetClientRoutes())

	return &proto.SelectRoutesResponse{}, nil
}

// DeselectRoutes deselects specific routes based on the client request.
func (s *Server) DeselectRoutes(_ context.Context, req *proto.SelectRoutesRequest) (*proto.SelectRoutesResponse, error) {
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
	routeSelector := routeManager.GetRouteSelector()
	if req.GetAll() {
		routeSelector.DeselectAllRoutes()
	} else {
		routes := toNetIDs(req.GetRouteIDs())
		netIdRoutes := maps.Keys(routeManager.GetClientRoutesWithNetID())
		if err := routeSelector.DeselectRoutes(routes, netIdRoutes); err != nil {
			return nil, fmt.Errorf("deselect routes: %w", err)
		}
	}
	routeManager.TriggerSelection(routeManager.GetClientRoutes())

	return &proto.SelectRoutesResponse{}, nil
}

func toNetIDs(routes []string) []route.NetID {
	var netIDs []route.NetID
	for _, rt := range routes {
		netIDs = append(netIDs, route.NetID(rt))
	}
	return netIDs
}
