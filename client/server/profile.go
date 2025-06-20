package server

import (
	"context"
	"strings"

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

// CreateProfile creates a new profile with the specified name.
func (s *Server) CreateProfile(ctx context.Context, req *proto.CreateProfileRequest) (*proto.CreateProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return &proto.CreateProfileResponse{
		Success: true,
		Error:   "",
	}, nil
}

// SwitchProfile switches the current profile to the one specified in the request.
func (s *Server) SwitchProfile(ctx context.Context, req *proto.SwitchProfileRequest) (*proto.SwitchProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return &proto.SwitchProfileResponse{
		Success: true,
		Error:   "",
	}, nil
}

// RemoveProfile removes the specified profile from the server.
func (s *Server) RemoveProfile(ctx context.Context, req *proto.RemoveProfileRequest) (*proto.RemoveProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return &proto.RemoveProfileResponse{
		Success: true,
		Error:   "",
	}, nil
}

// sanitazeUsername sanitizes the username by removing any invalid characters
func sanitazeUsername(username string) string {
	// Remove invalid characters for a username in a file path
	return strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
			return -1 // remove this character
		}
		return r
	}, username)
}
