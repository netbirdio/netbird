//go:build ios

package NetBirdSDK

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// iOS profile storage layout (mirrors the Android layout so the shared
// profilemanager.ServiceManager behaves identically on both platforms):
//
//	<container>/                                  ← configDir parameter (App Group root)
//	├── netbird.cfg                               ← default profile config
//	├── state.json                                ← default profile state
//	├── active_profile.json                       ← active profile tracker {"name": <id>, "username": "ios"}
//	└── profiles/                                 ← non-default profiles
//	    ├── <id>.json                             ← profile config (holds the display "Name")
//	    └── <id>.state.json                       ← profile state
//
// The ProfileLayoutMigration in NetbirdKit moves the legacy directory-per-name
// layout into this shape before NewProfileManager ever runs.

const (
	// iosDefaultConfigFilename is the default profile config name. Must match
	// GlobalConstants.configFileName on the Swift side ("netbird.cfg").
	iosDefaultConfigFilename = "netbird.cfg"
	// iosDefaultStateFilename is the default profile state name. Must match
	// GlobalConstants.stateFileName on the Swift side ("state.json").
	iosDefaultStateFilename = "state.json"
	// iosProfilesSubdir holds non-default profile files.
	iosProfilesSubdir = "profiles"
	// iosUsername is the single user context the app runs under. The value is
	// written into active_profile.json's "username" field and is required to be
	// non-empty for non-default profiles by ServiceManager.SetActiveProfileState.
	// Must match the value the migration writes ("ios").
	iosUsername = "ios"
)

// Profile represents a profile for gomobile. gomobile exposes the exported
// fields as id_/name/isActive on the Swift side.
type Profile struct {
	ID       string
	Name     string
	IsActive bool
}

// ProfileArray wraps a profile slice for gomobile (which cannot bind Go slices
// directly; callers iterate with Length()/Get()).
type ProfileArray struct {
	items []*Profile
}

// Length returns the number of profiles.
func (p *ProfileArray) Length() int {
	return len(p.items)
}

// Get returns the profile at index i, or nil if i is out of range.
func (p *ProfileArray) Get(i int) *Profile {
	if i < 0 || i >= len(p.items) {
		return nil
	}
	return p.items[i]
}

// ProfileManager manages profiles for iOS. It wraps the internal
// profilemanager.ServiceManager, which owns all profile identity (the on-disk
// filename is the ID, the display name lives inside the config JSON).
type ProfileManager struct {
	configDir  string
	serviceMgr *profilemanager.ServiceManager
}

// NewProfileManager creates a profile manager rooted at configDir (the App
// Group shared container). gomobile maps this to a nullable Swift initializer.
func NewProfileManager(configDir string) *ProfileManager {
	defaultConfigPath := filepath.Join(configDir, iosDefaultConfigFilename)

	// Point the package-level paths at the iOS container. The default profile
	// lives in the root configDir (not under profiles/).
	profilemanager.DefaultConfigPathDir = configDir
	profilemanager.DefaultConfigPath = defaultConfigPath
	profilemanager.ActiveProfileStatePath = filepath.Join(configDir, "active_profile.json")

	// A fixed profiles directory avoids mutating the global ConfigDirOverride;
	// the ServiceManager then ignores the username when resolving the directory.
	profilesDir := filepath.Join(configDir, iosProfilesSubdir)
	serviceMgr := profilemanager.NewServiceManagerWithProfilesDir(defaultConfigPath, profilesDir)

	return &ProfileManager{
		configDir:  configDir,
		serviceMgr: serviceMgr,
	}
}

// ListProfiles returns all available profiles, including the default, with
// their active status and resolved display names.
func (pm *ProfileManager) ListProfiles() (*ProfileArray, error) {
	internalProfiles, err := pm.serviceMgr.ListProfiles(iosUsername)
	if err != nil {
		return nil, fmt.Errorf("failed to list profiles: %w", err)
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

// GetActiveProfile returns the currently active profile with its display name
// resolved. ActiveProfileState only records the ID, so the ID is resolved to a
// full profile to recover the Name.
func (pm *ProfileManager) GetActiveProfile() (*Profile, error) {
	activeState, err := pm.serviceMgr.GetActiveProfileState()
	if err != nil {
		return nil, fmt.Errorf("failed to get active profile: %w", err)
	}

	prof, err := pm.serviceMgr.ResolveProfile(activeState.ID.String(), iosUsername)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve active profile %q: %w", activeState.ID, err)
	}

	return &Profile{ID: prof.ID.String(), Name: prof.Name, IsActive: true}, nil
}

// AddProfile creates a new profile with displayName and returns it. The
// returned profile carries the freshly generated ID, which callers must use
// for all follow-up operations (the ID is NOT the display name).
func (pm *ProfileManager) AddProfile(displayName string) (*Profile, error) {
	prof, err := pm.serviceMgr.AddProfile(displayName, iosUsername)
	if err != nil {
		return nil, fmt.Errorf("failed to add profile: %w", err)
	}

	log.Infof("created new profile: %s", prof.ID)
	return &Profile{ID: prof.ID.String(), Name: prof.Name, IsActive: false}, nil
}

// SwitchProfile records the given profile ID as the active profile. Callers
// must stop the VPN before switching.
func (pm *ProfileManager) SwitchProfile(id string) error {
	if err := pm.serviceMgr.SetActiveProfileState(&profilemanager.ActiveProfileState{
		ID:       profilemanager.ID(id),
		Username: iosUsername,
	}); err != nil {
		return fmt.Errorf("failed to switch profile: %w", err)
	}

	log.Infof("switched to profile: %s", id)
	return nil
}

// RenameProfile changes a profile's display name. The on-disk ID (filename) is
// unchanged. There is no ServiceManager rename, so this edits the Name field of
// the config JSON in place.
func (pm *ProfileManager) RenameProfile(id, newName string) error {
	if id == profilemanager.DefaultProfileName {
		return fmt.Errorf("cannot rename the default profile")
	}
	if !profilemanager.IsValidProfileFilenameStem(profilemanager.ID(id)) {
		return fmt.Errorf("invalid profile ID: %q", id)
	}

	newName = strings.TrimSpace(newName)
	if newName == "" {
		return fmt.Errorf("profile name must not be empty")
	}
	if newName == profilemanager.DefaultProfileName {
		return fmt.Errorf("cannot use reserved profile name: %s", profilemanager.DefaultProfileName)
	}

	configPath, err := pm.getProfileConfigPath(id)
	if err != nil {
		return err
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("profile %q does not exist", id)
	}

	config, err := profilemanager.ReadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to read profile config: %w", err)
	}

	config.Name = newName

	if err := profilemanager.WriteOutConfig(configPath, config); err != nil {
		return fmt.Errorf("failed to write profile config: %w", err)
	}

	log.Infof("renamed profile %q to %q", id, newName)
	return nil
}

// RemoveProfile deletes a profile. The default and the active profile cannot be
// removed.
func (pm *ProfileManager) RemoveProfile(id string) error {
	if err := pm.serviceMgr.RemoveProfile(profilemanager.ID(id), iosUsername); err != nil {
		return fmt.Errorf("failed to remove profile: %w", err)
	}

	log.Infof("removed profile: %s", id)
	return nil
}

// LogoutProfile clears a profile's authentication (private key and SSH key),
// forcing re-login. The management URL is preserved in the config.
func (pm *ProfileManager) LogoutProfile(id string) error {
	if !profilemanager.IsValidProfileFilenameStem(profilemanager.ID(id)) {
		return fmt.Errorf("invalid profile ID: %q", id)
	}

	configPath, err := pm.getProfileConfigPath(id)
	if err != nil {
		return err
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("profile %q does not exist", id)
	}

	config, err := profilemanager.ReadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to read profile config: %w", err)
	}

	config.PrivateKey = ""
	config.SSHKey = ""

	if err := profilemanager.WriteOutConfig(configPath, config); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	log.Infof("logged out from profile: %s", id)
	return nil
}

// GetConfigPath returns the config file path for a given profile ID.
func (pm *ProfileManager) GetConfigPath(id string) (string, error) {
	return pm.getProfileConfigPath(id)
}

// GetStateFilePath returns the state file path for a given profile ID.
func (pm *ProfileManager) GetStateFilePath(id string) (string, error) {
	if id == "" || id == profilemanager.DefaultProfileName {
		return filepath.Join(pm.configDir, iosDefaultStateFilename), nil
	}

	profilesDir := filepath.Join(pm.configDir, iosProfilesSubdir)
	return filepath.Join(profilesDir, id+".state.json"), nil
}

// GetActiveConfigPath returns the config file path for the active profile.
func (pm *ProfileManager) GetActiveConfigPath() (string, error) {
	activeProfile, err := pm.GetActiveProfile()
	if err != nil {
		return "", fmt.Errorf("failed to get active profile: %w", err)
	}
	return pm.GetConfigPath(activeProfile.ID)
}

// GetActiveStateFilePath returns the state file path for the active profile.
func (pm *ProfileManager) GetActiveStateFilePath() (string, error) {
	activeProfile, err := pm.GetActiveProfile()
	if err != nil {
		return "", fmt.Errorf("failed to get active profile: %w", err)
	}
	return pm.GetStateFilePath(activeProfile.ID)
}

// getProfileConfigPath returns the config file path for a profile ID. The
// default profile lives in the root configDir as netbird.cfg; everything else
// lives under profiles/ as <id>.json.
func (pm *ProfileManager) getProfileConfigPath(id string) (string, error) {
	if id == "" || id == profilemanager.DefaultProfileName {
		return filepath.Join(pm.configDir, iosDefaultConfigFilename), nil
	}

	profilesDir := filepath.Join(pm.configDir, iosProfilesSubdir)
	return filepath.Join(profilesDir, id+".json"), nil
}
