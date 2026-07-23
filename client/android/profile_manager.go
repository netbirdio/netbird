//go:build android

package android

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

const (
	// Android-specific config filename (different from desktop default.json)
	defaultConfigFilename = "netbird.cfg"
	// Subdirectory for non-default profiles (must match Java Preferences.java)
	profilesSubdir = "profiles"
	// Android uses a single user context per app (non-empty username required by ServiceManager)
	androidUsername = "android"
)

// Profile represents a profile for gomobile
type Profile struct {
	ID       string
	Name     string
	IsActive bool
}

// ProfileArray wraps profiles for gomobile compatibility
type ProfileArray struct {
	items []*Profile
}

// Length returns the number of profiles
func (p *ProfileArray) Length() int {
	return len(p.items)
}

// Get returns the profile at index i
func (p *ProfileArray) Get(i int) *Profile {
	if i < 0 || i >= len(p.items) {
		return nil
	}
	return p.items[i]
}

/*

/data/data/io.netbird.client/files/           ← configDir parameter
├── netbird.cfg                                 ← Default profile config
├── state.json                                  ← Default profile state
├── active_profile.json                         ← Active profile tracker (JSON with Name + Username)
└── profiles/                                   ← Subdirectory for non-default profiles
    ├── work.json                              			← Legacy work profile config
    ├── work.state.json                        			← Legacy work profile state
    ├── 4c5f5c8198c3989cffb5b5394f5a7ae0.json  			← ID profile config
    ├── 4c5f5c8198c3989cffb5b5394f5a7ae0.state.json ← ID profile state
*/

// ProfileManager manages profiles for Android
// It wraps the internal profilemanager to provide Android-specific behavior
type ProfileManager struct {
	configDir  string
	serviceMgr *profilemanager.ServiceManager
}

// NewProfileManager creates a new profile manager for Android
func NewProfileManager(configDir string) *ProfileManager {
	// Set the default config path for Android (stored in root configDir, not profiles/)
	defaultConfigPath := filepath.Join(configDir, defaultConfigFilename)

	// Set global paths for Android
	profilemanager.DefaultConfigPathDir = configDir
	profilemanager.DefaultConfigPath = defaultConfigPath
	profilemanager.ActiveProfileStatePath = filepath.Join(configDir, "active_profile.json")

	// Create ServiceManager with profiles/ subdirectory
	// This avoids modifying the global ConfigDirOverride for profile listing
	profilesDir := filepath.Join(configDir, profilesSubdir)
	serviceMgr := profilemanager.NewServiceManagerWithProfilesDir(defaultConfigPath, profilesDir)

	return &ProfileManager{
		configDir:  configDir,
		serviceMgr: serviceMgr,
	}
}

// ListProfiles returns all available profiles
func (pm *ProfileManager) ListProfiles() (*ProfileArray, error) {
	// Use ServiceManager (looks in profiles/ directory, checks active_profile.json for IsActive)
	internalProfiles, err := pm.serviceMgr.ListProfiles(androidUsername)
	if err != nil {
		return nil, fmt.Errorf("failed to list profiles: %w", err)
	}

	// Convert internal profiles to Android Profile type
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

// GetActiveProfile returns the currently active profile name
func (pm *ProfileManager) GetActiveProfile() (*Profile, error) {
	// Use ServiceManager to stay consistent with ListProfiles
	// ServiceManager uses active_profile.json
	activeState, err := pm.serviceMgr.GetActiveProfileState()
	if err != nil {
		return nil, fmt.Errorf("failed to get active profile: %w", err)
	}

	// ActiveProfileState only stores the ID (and username), not the display
	// name. Resolve the ID to the full profile so callers get the real Name.
	prof, err := pm.serviceMgr.ResolveProfile(activeState.ID.String(), androidUsername)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve active profile %q: %w", activeState.ID, err)
	}
	return &Profile{ID: prof.ID.String(), Name: prof.Name, IsActive: true}, nil
}

// SwitchProfile switches to a different profile
func (pm *ProfileManager) SwitchProfile(id string) error {
	// Use ServiceManager to stay consistent with ListProfiles
	// ServiceManager uses active_profile.json
	err := pm.serviceMgr.SetActiveProfileState(&profilemanager.ActiveProfileState{
		ID:       profilemanager.ID(id),
		Username: androidUsername,
	})
	if err != nil {
		return fmt.Errorf("failed to switch profile: %w", err)
	}

	log.Infof("switched to profile: %s", id)
	return nil
}

// AddProfile creates a new profile
func (pm *ProfileManager) AddProfile(profileName string) error {
	// Use ServiceManager (creates profile in profiles/ directory)
	profile, err := pm.serviceMgr.AddProfile(profileName, androidUsername, nil)
	if err != nil {
		return fmt.Errorf("failed to add profile: %w", err)
	}

	log.Infof("created new profile: %s", profile.ID)
	return nil
}

// LogoutProfile logs out from a profile (clears authentication)
func (pm *ProfileManager) LogoutProfile(id string) error {
	configPath, err := pm.getProfileConfigPath(id)
	if err != nil {
		return err
	}

	if !profilemanager.IsValidProfileFilenameStem(profilemanager.ID(id)) {
		return fmt.Errorf("id '%s' is not valid", id)
	}

	// Check if profile exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("profile '%s' does not exist", id)
	}

	// Read current config using internal profilemanager
	config, err := profilemanager.ReadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to read profile config: %w", err)
	}

	// Clear authentication by removing private key and SSH key
	config.PrivateKey = ""
	config.SSHKey = ""

	// Save config using internal profilemanager
	if err := profilemanager.WriteOutConfig(configPath, config); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	log.Infof("logged out from profile: %s", id)
	return nil
}

// RemoveProfile deletes a profile
func (pm *ProfileManager) RemoveProfile(id string) error {
	// Use ServiceManager (removes profile from profiles/ directory)
	if err := pm.serviceMgr.RemoveProfile(profilemanager.ID(id), androidUsername); err != nil {
		return fmt.Errorf("failed to remove profile: %w", err)
	}

	log.Infof("removed profile: %s", id)
	return nil
}

// getProfileConfigPath returns the config file path for a profile
// This is needed for Android-specific path handling (netbird.cfg for default profile)
func (pm *ProfileManager) getProfileConfigPath(id string) (string, error) {
	if !profilemanager.IsValidProfileFilenameStem(profilemanager.ID(id)) {
		return "", fmt.Errorf("id %q is not valid", id)
	}

	if id == profilemanager.DefaultProfileName {
		// Android uses netbird.cfg for default profile instead of default.json
		// Default profile is stored in root configDir, not in profiles/
		return filepath.Join(pm.configDir, defaultConfigFilename), nil
	}

	profilesDir := filepath.Join(pm.configDir, profilesSubdir)
	return filepath.Join(profilesDir, id+".json"), nil
}

// GetConfigPath returns the config file path for a given profile id
// Java should call this instead of constructing paths with Preferences.configFile()
func (pm *ProfileManager) GetConfigPath(id string) (string, error) {
	return pm.getProfileConfigPath(id)
}

// GetStateFilePath returns the state file path for a given profile
// Java should call this instead of constructing paths with Preferences.stateFile()
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

// GetActiveConfigPath returns the config file path for the currently active profile
// Java should call this instead of Preferences.getActiveProfileName() + Preferences.configFile()
func (pm *ProfileManager) GetActiveConfigPath() (string, error) {
	activeProfile, err := pm.GetActiveProfile()
	if err != nil {
		return "", fmt.Errorf("failed to get active profile: %w", err)
	}
	return pm.GetConfigPath(activeProfile.ID)
}

// GetActiveStateFilePath returns the state file path for the currently active profile
// Java should call this instead of Preferences.getActiveProfileName() + Preferences.stateFile()
func (pm *ProfileManager) GetActiveStateFilePath() (string, error) {
	activeProfile, err := pm.GetActiveProfile()
	if err != nil {
		return "", fmt.Errorf("failed to get active profile: %w", err)
	}
	return pm.GetStateFilePath(activeProfile.ID)
}
