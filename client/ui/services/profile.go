//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"os/user"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

type Profile struct {
	Name     string `json:"name"`
	IsActive bool   `json:"isActive"`
	// Email is read from the user-owned per-profile state file (CLI writes it
	// after SSO login), not via ListProfiles: the daemon runs as root and can't
	// reach it, while the UI runs as the logged-in user.
	Email string `json:"email"`
}

type ProfileRef struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

type ActiveProfile struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

type Profiles struct {
	conn DaemonConn
}

func NewProfiles(conn DaemonConn) *Profiles {
	return &Profiles{conn: conn}
}

// Username returns the OS username the daemon expects for profile lookups.
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
	pm := profilemanager.NewProfileManager()
	out := make([]Profile, 0, len(resp.GetProfiles()))
	for _, p := range resp.GetProfiles() {
		prof := Profile{Name: p.GetName(), IsActive: p.GetIsActive()}
		if state, err := pm.GetProfileState(p.GetName()); err == nil {
			prof.Email = state.Email
		}
		out = append(out, prof)
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
