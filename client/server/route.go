package server

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/route"
)

type selectRoute struct {
	HaUniqueID route.HAUniqueID
	Network    netip.Prefix
	Selected   bool
}

// ListRoutes returns a list of all available routes.
func (s *Server) ListRoutes(ctx context.Context, req *proto.ListRoutesRequest) (*proto.ListRoutesResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.engine == nil {
		return nil, fmt.Errorf("not connected")
	}

	routesMap := s.engine.GetClientRoutesWithNetID()
	routeSelector := s.engine.GetRouteManager().GetRouteSelector()

	var routes []*selectRoute
	for id, rt := range routesMap {
		if len(rt) == 0 {
			continue
		}
		route := &selectRoute{
			HaUniqueID: id,
			Network:    rt[0].Network,
			Selected:   routeSelector.IsSelected(id),
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
				return routes[i].HaUniqueID < routes[j].HaUniqueID
			}
			return iAddr.String() < jAddr.String()
		}
		return iPrefix < jPrefix
	})

	var pbRoutes []*proto.Route
	for _, route := range routes {
		pbRoutes = append(pbRoutes, &proto.Route{
			ID:       string(route.HaUniqueID),
			Network:  route.Network.String(),
			Selected: route.Selected,
		})
	}

	return &proto.ListRoutesResponse{
		Routes: pbRoutes,
	}, nil
}

// SelectRoutes selects specific routes based on the client request.
func (s *Server) SelectRoutes(_ context.Context, req *proto.SelectRoutesRequest) (*proto.SelectRoutesResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	routeManager := s.engine.GetRouteManager()
	routeSelector := routeManager.GetRouteSelector()
	if req.GetAll() {
		routeSelector.SelectAllRoutes()
	} else {
		routes := toHAUniqueIDs(req.GetRouteIDs())
		if err := routeSelector.SelectRoutes(routes, req.GetAppend(), maps.Keys(s.engine.GetClientRoutesWithNetID())); err != nil {
			return nil, fmt.Errorf("select routes: %w", err)
		}
	}
	routeManager.TriggerSelection(s.engine.GetClientRoutes())

	return &proto.SelectRoutesResponse{}, nil
}

// DeselectRoutes deselects specific routes based on the client request.
func (s *Server) DeselectRoutes(_ context.Context, req *proto.SelectRoutesRequest) (*proto.SelectRoutesResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	routeManager := s.engine.GetRouteManager()
	routeSelector := routeManager.GetRouteSelector()
	if req.GetAll() {
		routeSelector.DeselectAllRoutes()
	} else {
		routes := toHAUniqueIDs(req.GetRouteIDs())
		if err := routeSelector.DeselectRoutes(routes, maps.Keys(s.engine.GetClientRoutesWithNetID())); err != nil {
			return nil, fmt.Errorf("deselect routes: %w", err)
		}
	}
	routeManager.TriggerSelection(s.engine.GetClientRoutes())

	return &proto.SelectRoutesResponse{}, nil
}

func toHAUniqueIDs(routes []string) []route.HAUniqueID {
	var haUniqueIDs []route.HAUniqueID
	for _, rt := range routes {
		haUniqueIDs = append(haUniqueIDs, route.HAUniqueID(rt))
	}
	return haUniqueIDs
}
