//go:build ios

package NetBirdSDK

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

const (
	// iOS-specific config filename for the default profile (matches the
	// Swift GlobalConstants.configFileName, and the desktop netbird.cfg
	// rather than default.json).
	defaultConfigFilename = "netbird.cfg"
	// Subdirectory for non-default profiles (must match the Swift profiles
	// directory layout).
	profilesSubdir = "profiles"
	// iOS uses a single user context per app (a non-empty username is
	// required by ServiceManager for non-default profiles).
	iosUsername = "ios"
)

// Profile represents a profile for gomobile.
type Profile struct {
	ID       string
	Name     string
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

/*

<App Group container>/                          ← configDir parameter
├── netbird.cfg                                 ← Default profile config
├── state.json                                  ← Default profile state
├── active_profile.json                         ← Active profile tracker (JSON with ID + Username)
└── profiles/                                   ← Subdirectory for non-default profiles
    ├── 4c5f5c8198c3989cffb5b5394f5a7ae0.json       ← ID profile config
    └── 4c5f5c8198c3989cffb5b5394f5a7ae0.state.json ← ID profile state
*/

// ProfileManager manages profiles for iOS. It wraps the internal
// profilemanager.ServiceManager to provide iOS-specific path handling and a
// gomobile-friendly API. All profile identity is ID-based; the human-readable
// name lives inside the profile config's Name field.
type ProfileManager struct {
	configDir  string
	serviceMgr *profilemanager.ServiceManager
}

// NewProfileManager creates a new profile manager for iOS. configDir is the
// App Group shared container path that both the app and the network extension
// can reach.
func NewProfileManager(configDir string) *ProfileManager {
	// The default profile is stored in the root configDir, not under profiles/.
	defaultConfigPath := filepath.Join(configDir, defaultConfigFilename)

	// Point the package globals at the app-provided container, overriding the
	// desktop defaults set in profilemanager's init().
	profilemanager.DefaultConfigPathDir = configDir
	profilemanager.DefaultConfigPath = defaultConfigPath
	profilemanager.ActiveProfileStatePath = filepath.Join(configDir, "active_profile.json")

	// Non-default profiles live in the profiles/ subdirectory. Passing it
	// explicitly avoids touching the global config-dir override.
	profilesDir := filepath.Join(configDir, profilesSubdir)
	serviceMgr := profilemanager.NewServiceManagerWithProfilesDir(defaultConfigPath, profilesDir)

	return &ProfileManager{
		configDir:  configDir,
		serviceMgr: serviceMgr,
	}
}

// ListProfiles returns all available profiles, including the default profile,
// with their active status set.
func (pm *ProfileManager) ListProfiles() (*ProfileArray, error) {
	internalProfiles, err := pm.serviceMgr.ListProfiles(iosUsername)
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}

	var profiles []*Profile
	for _, p := range internalProfiles {
		profiles = append(profiles, &Profile{
			ID:       p.ID.String(),
			Name:     p.Name,
			IsActive: p.IsActive,
		})
	}

	return &ProfileArray{items: profiles}, nil
}

// GetActiveProfile returns the currently active profile, resolving its ID to
// the full profile so callers get the real display name.
func (pm *ProfileManager) GetActiveProfile() (*Profile, error) {
	activeState, err := pm.serviceMgr.GetActiveProfileState()
	if err != nil {
		return nil, fmt.Errorf("get active profile: %w", err)
	}

	prof, err := pm.serviceMgr.ResolveProfile(activeState.ID.String(), iosUsername)
	if err != nil {
		return nil, fmt.Errorf("resolve active profile %q: %w", activeState.ID, err)
	}
	return &Profile{ID: prof.ID.String(), Name: prof.Name, IsActive: true}, nil
}

// SwitchProfile records the given profile ID as the active profile. The caller
// must stop the VPN tunnel before switching.
func (pm *ProfileManager) SwitchProfile(id string) error {
	if err := pm.serviceMgr.SetActiveProfileState(&profilemanager.ActiveProfileState{
		ID:       profilemanager.ID(id),
		Username: iosUsername,
	}); err != nil {
		return fmt.Errorf("switch profile: %w", err)
	}

	log.Infof("switched to profile: %s", id)
	return nil
}

// AddProfile creates a new profile with the given display name and a
// generated ID. It returns the created profile so the caller learns the ID.
func (pm *ProfileManager) AddProfile(displayName string) (*Profile, error) {
	profile, err := pm.serviceMgr.AddProfile(displayName, iosUsername)
	if err != nil {
		return nil, fmt.Errorf("add profile: %w", err)
	}

	log.Infof("created new profile: %s", profile.ID)
	return &Profile{ID: profile.ID.String(), Name: profile.Name, IsActive: false}, nil
}

// RenameProfile changes the display name of the profile identified by id. The
// on-disk filename (the ID) is left unchanged.
func (pm *ProfileManager) RenameProfile(id string, newName string) error {
	if err := pm.serviceMgr.RenameProfile(profilemanager.ID(id), iosUsername, newName); err != nil {
		return fmt.Errorf("rename profile: %w", err)
	}

	log.Infof("renamed profile %s to %q", id, newName)
	return nil
}

// LogoutProfile clears authentication data for a profile by removing its
// private key and SSH key from the config, forcing a re-login. The management
// URL and other settings are preserved.
func (pm *ProfileManager) LogoutProfile(id string) error {
	configPath, err := pm.getProfileConfigPath(id)
	if err != nil {
		return err
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("profile %q does not exist", id)
	}

	config, err := profilemanager.ReadConfig(configPath)
	if err != nil {
		return fmt.Errorf("read profile config: %w", err)
	}

	config.PrivateKey = ""
	config.SSHKey = ""

	if err := profilemanager.WriteOutConfig(configPath, config); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	log.Infof("logged out from profile: %s", id)
	return nil
}

// RemoveProfile deletes a profile. The default profile and the active profile
// cannot be removed.
func (pm *ProfileManager) RemoveProfile(id string) error {
	if err := pm.serviceMgr.RemoveProfile(profilemanager.ID(id), iosUsername); err != nil {
		return fmt.Errorf("remove profile: %w", err)
	}

	log.Infof("removed profile: %s", id)
	return nil
}

// getProfileConfigPath returns the config file path for a profile ID. The
// default profile uses netbird.cfg in the root configDir; other profiles use
// <id>.json in the profiles/ subdirectory.
func (pm *ProfileManager) getProfileConfigPath(id string) (string, error) {
	if !profilemanager.IsValidProfileFilenameStem(profilemanager.ID(id)) {
		return "", fmt.Errorf("id %q is not valid", id)
	}

	if id == profilemanager.DefaultProfileName {
		return filepath.Join(pm.configDir, defaultConfigFilename), nil
	}

	profilesDir := filepath.Join(pm.configDir, profilesSubdir)
	return filepath.Join(profilesDir, id+".json"), nil
}

// GetConfigPath returns the config file path for the given profile ID. Swift
// should call this instead of constructing paths itself.
func (pm *ProfileManager) GetConfigPath(id string) (string, error) {
	return pm.getProfileConfigPath(id)
}

// GetStateFilePath returns the state file path for the given profile ID.
func (pm *ProfileManager) GetStateFilePath(id string) (string, error) {
	if id == "" || id == profilemanager.DefaultProfileName {
		return filepath.Join(pm.configDir, "state.json"), nil
	}

	if !profilemanager.IsValidProfileFilenameStem(profilemanager.ID(id)) {
		return "", fmt.Errorf("id %q is not valid", id)
	}

	profilesDir := filepath.Join(pm.configDir, profilesSubdir)
	return filepath.Join(profilesDir, id+".state.json"), nil
}

// GetActiveConfigPath returns the config file path for the currently active
// profile.
func (pm *ProfileManager) GetActiveConfigPath() (string, error) {
	activeProfile, err := pm.GetActiveProfile()
	if err != nil {
		return "", fmt.Errorf("get active profile: %w", err)
	}
	return pm.GetConfigPath(activeProfile.ID)
}

// GetActiveStateFilePath returns the state file path for the currently active
// profile.
func (pm *ProfileManager) GetActiveStateFilePath() (string, error) {
	activeProfile, err := pm.GetActiveProfile()
	if err != nil {
		return "", fmt.Errorf("get active profile: %w", err)
	}
	return pm.GetStateFilePath(activeProfile.ID)
}
