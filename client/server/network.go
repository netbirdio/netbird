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

	routesMap := engine.GetClientRoutesWithNetID()
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
	var pbRoutes []*proto.Network
	for _, route := range routes {
		pbRoute := &proto.Network{
			ID:          string(route.NetID),
			Range:       route.Network.String(),
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
	routeSelector := routeManager.GetRouteSelector()
	if req.GetAll() {
		routeSelector.SelectAllRoutes()
	} else {
		routes := toNetIDs(req.GetNetworkIDs())
		if err := routeSelector.SelectRoutes(routes, req.GetAppend(), maps.Keys(engine.GetClientRoutesWithNetID())); err != nil {
			return nil, fmt.Errorf("select routes: %w", err)
		}
	}
	routeManager.TriggerSelection(engine.GetClientRoutes())

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
	routeSelector := routeManager.GetRouteSelector()
	if req.GetAll() {
		routeSelector.DeselectAllRoutes()
	} else {
		routes := toNetIDs(req.GetNetworkIDs())
		if err := routeSelector.DeselectRoutes(routes, maps.Keys(engine.GetClientRoutesWithNetID())); err != nil {
			return nil, fmt.Errorf("deselect routes: %w", err)
		}
	}
	routeManager.TriggerSelection(engine.GetClientRoutes())

	return &proto.SelectNetworksResponse{}, nil
}

func toNetIDs(routes []string) []route.NetID {
	var netIDs []route.NetID
	for _, rt := range routes {
		netIDs = append(netIDs, route.NetID(rt))
	}
	return netIDs
}
