//go:build android

package android

import (
	"github.com/netbirdio/netbird/client/mobile"
)

const (
	// Android uses a single user context per app.
	androidUsername = "android"
)

// Profile represents a profile for gomobile.
type Profile struct {
	ID   string
	Name string
	// Email is the account this profile last logged in with, "" if it never
	// completed an SSO login. Kept across logouts; cleared when the profile is
	// removed. See client/mobile/profile_state.go.
	Email    string
	IsActive bool
}

// ProfileArray wraps profiles for gomobile compatibility (gomobile cannot
// bind Go slices directly).
type ProfileArray struct {
	items []*Profile
}

// Length returns the number of profiles.
func (p *ProfileArray) Length() int {
	return len(p.items)
}

// Get returns the profile at index i, or nil if out of range.
func (p *ProfileArray) Get(i int) *Profile {
	if i < 0 || i >= len(p.items) {
		return nil
	}
	return p.items[i]
}

// ProfileManager adapts the shared mobile profile manager (client/mobile) to
// gomobile-friendly types. See that package for the on-disk layout and
// semantics.
type ProfileManager struct {
	impl *mobile.ProfileManager
}

// NewProfileManager creates a new profile manager for Android. configDir is
// the app's files directory.
func NewProfileManager(configDir string) *ProfileManager {
	return &ProfileManager{impl: mobile.NewProfileManager(configDir, androidUsername)}
}

// ListProfiles returns all available profiles, including the default profile,
// with their active status set.
func (pm *ProfileManager) ListProfiles() (*ProfileArray, error) {
	profiles, err := pm.impl.ListProfiles()
	if err != nil {
		return nil, err
	}

	items := make([]*Profile, 0, len(profiles))
	for i := range profiles {
		items = append(items, fromMobileProfile(&profiles[i]))
	}
	return &ProfileArray{items: items}, nil
}

// GetActiveProfile returns the currently active profile.
func (pm *ProfileManager) GetActiveProfile() (*Profile, error) {
	p, err := pm.impl.GetActiveProfile()
	if err != nil {
		return nil, err
	}
	return fromMobileProfile(p), nil
}

// SwitchProfile records the given profile ID as the active profile. The caller
// must stop the VPN tunnel before switching.
func (pm *ProfileManager) SwitchProfile(id string) error {
	return pm.impl.SwitchProfile(id)
}

// AddProfile creates a new profile with the given display name and a
// generated ID.
func (pm *ProfileManager) AddProfile(profileName string) error {
	_, err := pm.impl.AddProfile(profileName)
	return err
}

// RenameProfile changes the display name of the profile identified by id. The
// on-disk filename (the ID) is left unchanged.
func (pm *ProfileManager) RenameProfile(id string, newName string) error {
	return pm.impl.RenameProfile(id, newName)
}

// LogoutProfile clears authentication data for a profile, forcing a re-login.
// The management URL and other settings are preserved.
func (pm *ProfileManager) LogoutProfile(id string) error {
	return pm.impl.LogoutProfile(id)
}

// RemoveProfile deletes a profile. The default profile and the active profile
// cannot be removed.
func (pm *ProfileManager) RemoveProfile(id string) error {
	return pm.impl.RemoveProfile(id)
}

// GetConfigPath returns the config file path for the given profile ID. Java
// should call this instead of constructing paths with Preferences.configFile().
func (pm *ProfileManager) GetConfigPath(id string) (string, error) {
	return pm.impl.GetConfigPath(id)
}

// GetStateFilePath returns the state file path for the given profile ID. Java
// should call this instead of constructing paths with Preferences.stateFile().
func (pm *ProfileManager) GetStateFilePath(id string) (string, error) {
	return pm.impl.GetStateFilePath(id)
}

// GetActiveConfigPath returns the config file path for the currently active
// profile.
func (pm *ProfileManager) GetActiveConfigPath() (string, error) {
	return pm.impl.GetActiveConfigPath()
}

// GetActiveStateFilePath returns the state file path for the currently active
// profile.
func (pm *ProfileManager) GetActiveStateFilePath() (string, error) {
	return pm.impl.GetActiveStateFilePath()
}

func fromMobileProfile(p *mobile.Profile) *Profile {
	return &Profile{ID: p.ID, Name: p.Name, Email: p.Email, IsActive: p.IsActive}
}
