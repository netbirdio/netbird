package server

import (
	"context"

	"github.com/netbirdio/netbird/client/proto"
)

// GetProfiles returns a list of all available profiles.
func (s *Server) GetProfiles(context.Context, *proto.GetProfilesRequest) (*proto.GetProfilesResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	mockProfiles := []*proto.Profile{
		{
			Name:     "default",
			Selected: true,
		},
		{
			Name:     "work",
			Selected: false,
		},
		{
			Name:     "home",
			Selected: false,
		},
	}

	return &proto.GetProfilesResponse{
		Profiles: mockProfiles,
	}, nil
}
