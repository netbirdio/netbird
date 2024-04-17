package server

import (
	"context"
	"fmt"

	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/proto"
)

// ListRoutes returns a list of all available routes.
func (s *Server) ListRoutes(context.Context, *proto.ListRoutesRequest) (*proto.ListRoutesResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.engine == nil {
		return nil, fmt.Errorf("not connected")
	}

	routes := s.engine.GetRoutes()
	var pbRoutes []*proto.Route
	for id, rt := range routes {
		if len(rt) == 0 {
			continue
		}

		pbRoutes = append(pbRoutes, &proto.Route{
			ID:       id,
			Network:  rt[0].Network.String(),
			Selected: s.routeSelector.IsSelected(id),
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

	if req.GetAll() {
		s.routeSelector.SelectAllRoutes()
	} else {
		if err := s.routeSelector.SelectRoutes(req.GetRouteIDs(), req.GetAppend(), maps.Keys(s.engine.GetRoutes())); err != nil {
			return nil, fmt.Errorf("select routes: %w", err)
		}
	}

	return &proto.SelectRoutesResponse{}, nil
}

// DeselectRoutes deselects specific routes based on the client request.
func (s *Server) DeselectRoutes(_ context.Context, req *proto.SelectRoutesRequest) (*proto.SelectRoutesResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if req.GetAll() {
		s.routeSelector.DeselectAllRoutes()
	} else {
		if err := s.routeSelector.DeselectRoutes(req.GetRouteIDs(), maps.Keys(s.engine.GetRoutes())); err != nil {
			return nil, fmt.Errorf("deselect routes: %w", err)
		}
	}

	return &proto.SelectRoutesResponse{}, nil
}
