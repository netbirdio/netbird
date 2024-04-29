package server

import (
	"context"
	"fmt"
	"sort"

	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/route"
)

// ListRoutes returns a list of all available routes.
func (s *Server) ListRoutes(ctx context.Context, req *proto.ListRoutesRequest) (*proto.ListRoutesResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.engine == nil {
		return nil, fmt.Errorf("not connected")
	}

	routesMap := s.engine.GetClientRoutesWithNetID()
	routeSelector := s.engine.GetRouteManager().GetRouteSelector()

	var routes []*route.Route
	for id, rt := range routesMap {
		if len(rt) == 0 {
			continue
		}
		rt[0].ID = id
		routes = append(routes, rt[0])
	}

	sort.Slice(routes, func(i, j int) bool {
		iPrefix := routes[i].Network.Bits()
		jPrefix := routes[j].Network.Bits()

		if iPrefix == jPrefix {
			iAddr := routes[i].Network.Addr()
			jAddr := routes[j].Network.Addr()
			if iAddr == jAddr {
				return routes[i].ID < routes[j].ID
			}
			return iAddr.String() < jAddr.String()
		}
		return iPrefix < jPrefix
	})

	var pbRoutes []*proto.Route
	for _, route := range routes {
		pbRoutes = append(pbRoutes, &proto.Route{
			ID:       route.ID,
			Network:  route.Network.String(),
			Selected: routeSelector.IsSelected(route.ID),
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
		if err := routeSelector.SelectRoutes(req.GetRouteIDs(), req.GetAppend(), maps.Keys(s.engine.GetClientRoutesWithNetID())); err != nil {
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
		if err := routeSelector.DeselectRoutes(req.GetRouteIDs(), maps.Keys(s.engine.GetClientRoutesWithNetID())); err != nil {
			return nil, fmt.Errorf("deselect routes: %w", err)
		}
	}
	routeManager.TriggerSelection(s.engine.GetClientRoutes())

	return &proto.SelectRoutesResponse{}, nil
}
