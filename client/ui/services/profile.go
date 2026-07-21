//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"os/user"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

type Profile struct {
	// ID is the daemon-generated on-disk identity of the profile. Display
	// names can collide and be renamed, so the ID is the stable handle the
	// daemon resolves switch/remove/logout requests against.
	ID       string `json:"id"`
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
	// ID is the active profile's stable on-disk identity. Use it (not the
	// display name) as the handle for daemon requests and active-profile
	// comparisons, since names can collide.
	ID          string `json:"id"`
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

// RenameProfileParams selects a profile by handle and carries its new display
// name.
type RenameProfileParams struct {
	// Handle selects the profile to rename: an exact ID, a unique ID prefix,
	// or a unique display name. The daemon resolves it server-side.
	Handle string `json:"handle"`
	// NewName is the new free-form display name. The daemon sanitizes it
	// (strips control characters, trims, caps length) but keeps spaces, emoji,
	// punctuation, and non-ASCII letters.
	NewName string `json:"newName"`

	Username string `json:"username"`
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
		prof := Profile{ID: p.GetId(), Name: p.GetName(), IsActive: p.GetIsActive()}
		if state, err := pm.GetProfileState(profilemanager.ID(p.GetId())); err == nil {
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
		ID:          resp.GetId(),
		ProfileName: resp.GetProfileName(),
		Username:    resp.GetUsername(),
	}, nil
}

// Switch sends a profile switch to the daemon and returns the resolved
// on-disk ID of the now-active profile. ProfileName is treated as a handle
// (exact ID, unique ID prefix, or unique display name); the daemon resolves
// it server-side and echoes back the canonical ID.
func (s *Profiles) Switch(ctx context.Context, p ProfileRef) (string, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return "", err
	}
	req := &proto.SwitchProfileRequest{}
	if p.ProfileName != "" {
		req.ProfileName = ptrStr(p.ProfileName)
	}
	if p.Username != "" {
		req.Username = ptrStr(p.Username)
	}
	resp, err := cli.SwitchProfile(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.GetId(), nil
}

// Add creates a profile with the given display name and returns its
// daemon-generated on-disk ID, so callers can address the new profile by ID
// (e.g. to write config or switch to it) without re-resolving the name.
func (s *Profiles) Add(ctx context.Context, p ProfileRef) (string, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return "", err
	}
	resp, err := cli.AddProfile(ctx, &proto.AddProfileRequest{
		ProfileName: p.ProfileName,
		Username:    p.Username,
	})
	if err != nil {
		return "", err
	}
	return resp.GetId(), nil
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

// Rename changes a profile's display name. The on-disk ID is unaffected, so
// the active profile and any ID-based references stay valid (the default
// profile can be renamed too — only its display name changes). Returns the
// profile's previous display name as confirmation.
func (s *Profiles) Rename(ctx context.Context, p RenameProfileParams) (string, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return "", err
	}
	resp, err := cli.RenameProfile(ctx, &proto.RenameProfileRequest{
		Username:       p.Username,
		Handle:         p.Handle,
		NewProfileName: p.NewName,
	})
	if err != nil {
		return "", err
	}
	return resp.GetOldProfileName(), nil
}
