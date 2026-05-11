//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"os/user"

	"github.com/netbirdio/netbird/client/proto"
)

// Profile is one named daemon profile.
type Profile struct {
	Name     string `json:"name"`
	IsActive bool   `json:"isActive"`
}

// ProfileRef identifies a profile by name+username.
type ProfileRef struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

// ActiveProfile is the result of GetActiveProfile.
type ActiveProfile struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

// Profiles groups the daemon RPCs that manage named profiles.
type Profiles struct {
	conn DaemonConn
}

func NewProfiles(conn DaemonConn) *Profiles {
	return &Profiles{conn: conn}
}

// Username returns the OS username the daemon expects for profile lookups.
// The frontend calls this once at boot and reuses the result.
func (s *Profiles) Username() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

func (s *Profiles) List(ctx context.Context, username string) ([]Profile, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return nil, err
	}
	resp, err := cli.ListProfiles(ctx, &proto.ListProfilesRequest{Username: username})
	if err != nil {
		return nil, err
	}
	out := make([]Profile, 0, len(resp.GetProfiles()))
	for _, p := range resp.GetProfiles() {
		out = append(out, Profile{Name: p.GetName(), IsActive: p.GetIsActive()})
	}
	return out, nil
}

func (s *Profiles) GetActive(ctx context.Context) (ActiveProfile, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return ActiveProfile{}, err
	}
	resp, err := cli.GetActiveProfile(ctx, &proto.GetActiveProfileRequest{})
	if err != nil {
		return ActiveProfile{}, err
	}
	return ActiveProfile{
		ProfileName: resp.GetProfileName(),
		Username:    resp.GetUsername(),
	}, nil
}

func (s *Profiles) Switch(ctx context.Context, p ProfileRef) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	req := &proto.SwitchProfileRequest{}
	if p.ProfileName != "" {
		req.ProfileName = ptrStr(p.ProfileName)
	}
	if p.Username != "" {
		req.Username = ptrStr(p.Username)
	}
	_, err = cli.SwitchProfile(ctx, req)
	return err
}

func (s *Profiles) Add(ctx context.Context, p ProfileRef) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.AddProfile(ctx, &proto.AddProfileRequest{
		ProfileName: p.ProfileName,
		Username:    p.Username,
	})
	return err
}

func (s *Profiles) Remove(ctx context.Context, p ProfileRef) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.RemoveProfile(ctx, &proto.RemoveProfileRequest{
		ProfileName: p.ProfileName,
		Username:    p.Username,
	})
	return err
}
