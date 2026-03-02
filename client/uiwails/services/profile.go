//go:build !(linux && 386)

package services

import (
	"context"
	"fmt"
	"os/user"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// ProfileService exposes profile management to the Wails frontend.
type ProfileService struct {
	grpcClient GRPCClientIface
}

// NewProfileService creates a new ProfileService.
func NewProfileService(g GRPCClientIface) *ProfileService {
	return &ProfileService{grpcClient: g}
}

// ProfileInfo is a serializable view of a profile.
type ProfileInfo struct {
	Name     string `json:"name"`
	IsActive bool   `json:"isActive"`
}

// ActiveProfileInfo holds information about the currently active profile.
type ActiveProfileInfo struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
	Email       string `json:"email"`
}

// ListProfiles returns all profiles for the current OS user.
func (s *ProfileService) ListProfiles() ([]ProfileInfo, error) {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	currUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("get current user: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := conn.ListProfiles(ctx, &proto.ListProfilesRequest{
		Username: currUser.Username,
	})
	if err != nil {
		return nil, fmt.Errorf("list profiles rpc: %w", err)
	}

	profiles := make([]ProfileInfo, 0, len(resp.Profiles))
	for _, p := range resp.Profiles {
		profiles = append(profiles, ProfileInfo{
			Name:     p.Name,
			IsActive: p.IsActive,
		})
	}
	return profiles, nil
}

// GetActiveProfile returns the currently active profile.
func (s *ProfileService) GetActiveProfile() (*ActiveProfileInfo, error) {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := conn.GetActiveProfile(ctx, &proto.GetActiveProfileRequest{})
	if err != nil {
		return nil, fmt.Errorf("get active profile rpc: %w", err)
	}

	return &ActiveProfileInfo{
		ProfileName: resp.ProfileName,
		Username:    resp.Username,
	}, nil
}

// SwitchProfile switches to the named profile.
func (s *ProfileService) SwitchProfile(profileName string) error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	currUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := conn.SwitchProfile(ctx, &proto.SwitchProfileRequest{
		ProfileName: &profileName,
		Username:    &currUser.Username,
	}); err != nil {
		log.Errorf("SwitchProfile rpc failed: %v", err)
		return fmt.Errorf("switch profile: %w", err)
	}

	return nil
}

// AddProfile creates a new profile with the given name.
func (s *ProfileService) AddProfile(profileName string) error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	currUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := conn.AddProfile(ctx, &proto.AddProfileRequest{
		ProfileName: profileName,
		Username:    currUser.Username,
	}); err != nil {
		log.Errorf("AddProfile rpc failed: %v", err)
		return fmt.Errorf("add profile: %w", err)
	}

	return nil
}

// RemoveProfile removes the named profile.
func (s *ProfileService) RemoveProfile(profileName string) error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	currUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := conn.RemoveProfile(ctx, &proto.RemoveProfileRequest{
		ProfileName: profileName,
		Username:    currUser.Username,
	}); err != nil {
		log.Errorf("RemoveProfile rpc failed: %v", err)
		return fmt.Errorf("remove profile: %w", err)
	}

	return nil
}

// Logout deregisters the named profile.
func (s *ProfileService) Logout(profileName string) error {
	conn, err := s.grpcClient.GetClient(3 * time.Second)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	currUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	username := currUser.Username
	if _, err := conn.Logout(ctx, &proto.LogoutRequest{
		ProfileName: &profileName,
		Username:    &username,
	}); err != nil {
		log.Errorf("Logout rpc failed: %v", err)
		return fmt.Errorf("logout: %w", err)
	}

	return nil
}
