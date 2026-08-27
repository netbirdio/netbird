// Package mobile holds the profile manager implementation shared by the
// Android and iOS gomobile bindings. The platform packages (client/android,
// client/ios/NetBirdSDK) only adapt this API to gomobile-friendly types.
package mobile

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

const (
	// Config filename of the default profile, stored at the configDir root.
	// Both platforms use netbird.cfg (matching the desktop netbird.cfg rather
	// than default.json); the app-side path constants must match.
	defaultConfigFilename = "netbird.cfg"
	// Subdirectory of configDir holding non-default profiles.
	profilesSubdir = "profiles"
)

/*

<configDir>/                                    ← app-writable config root
├── netbird.cfg                                 ← Default profile config
├── netbird.account.json                        ← Default profile account email (see profile_state.go)
├── state.json                                  ← Default profile state
├── active_profile.json                         ← Active profile tracker (JSON with ID + Username)
└── profiles/                                   ← Subdirectory for non-default profiles
    ├── 4c5f5c8198c3989cffb5b5394f5a7ae0.json              ← Profile config (filename = ID)
    ├── 4c5f5c8198c3989cffb5b5394f5a7ae0.state.json        ← Profile state
    ├── 4c5f5c8198c3989cffb5b5394f5a7ae0.account.json      ← Profile account email
    └── 4c5f5c8198c3989cffb5b5394f5a7ae0.prefs.json        ← Profile preferences
*/

// Profile is the platform-independent profile view handed to the bindings.
type Profile struct {
	ID   string
	Name string
	// Email is the account this profile last logged in with, "" if it never
	// completed an SSO login. Kept across logouts; cleared when the profile is
	// removed. See profile_state.go.
	Email    string
	IsActive bool
}

// ProfileManager manages profiles for the mobile platforms. It wraps the
// internal profilemanager.ServiceManager with mobile-specific path handling.
// All profile identity is ID-based; the human-readable name lives inside the
// profile config's Name field.
type ProfileManager struct {
	configDir  string
	username   string
	serviceMgr *profilemanager.ServiceManager
}

// NewProfileManager creates a profile manager rooted at configDir, the
// app-writable directory that every process of the app can reach. username is
// the platform's fixed single-user context (a non-empty username is required
// by ServiceManager for non-default profiles).
func NewProfileManager(configDir, username string) *ProfileManager {
	// The default profile is stored in the root configDir, not under profiles/.
	defaultConfigPath := filepath.Join(configDir, defaultConfigFilename)

	// Point the package globals at the app-provided directory, overriding the
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
		username:   username,
		serviceMgr: serviceMgr,
	}
}

// ListProfiles returns all available profiles, including the default profile,
// with their active status set.
func (pm *ProfileManager) ListProfiles() ([]Profile, error) {
	internalProfiles, err := pm.serviceMgr.ListProfiles(pm.username)
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}

	profiles := make([]Profile, 0, len(internalProfiles))
	for _, p := range internalProfiles {
		profiles = append(profiles, Profile{
			ID:       p.ID.String(),
			Name:     p.Name,
			Email:    pm.profileEmail(p.ID.String()),
			IsActive: p.IsActive,
		})
	}

	return profiles, nil
}

// GetActiveProfile returns the currently active profile, resolving its ID to
// the full profile so callers get the real display name.
func (pm *ProfileManager) GetActiveProfile() (*Profile, error) {
	activeState, err := pm.serviceMgr.GetActiveProfileState()
	if err != nil {
		return nil, fmt.Errorf("get active profile: %w", err)
	}

	prof, err := pm.serviceMgr.ResolveProfile(activeState.ID.String(), pm.username)
	if err != nil {
		return nil, fmt.Errorf("resolve active profile %q: %w", activeState.ID, err)
	}
	return &Profile{
		ID:       prof.ID.String(),
		Name:     prof.Name,
		Email:    pm.profileEmail(prof.ID.String()),
		IsActive: true,
	}, nil
}

// SwitchProfile records the given profile ID as the active profile. The caller
// must stop the VPN tunnel before switching.
func (pm *ProfileManager) SwitchProfile(id string) error {
	if err := pm.serviceMgr.SetActiveProfileState(&profilemanager.ActiveProfileState{
		ID:       profilemanager.ID(id),
		Username: pm.username,
	}); err != nil {
		return fmt.Errorf("switch profile: %w", err)
	}

	log.Infof("switched to profile: %s", id)
	return nil
}

// AddProfile creates a new profile with the given display name and a
// generated ID. It returns the created profile so the caller learns the ID.
func (pm *ProfileManager) AddProfile(displayName string) (*Profile, error) {
	profile, err := pm.serviceMgr.AddProfile(displayName, pm.username)
	if err != nil {
		return nil, fmt.Errorf("add profile: %w", err)
	}

	log.Infof("created new profile: %s", profile.ID)
	return &Profile{ID: profile.ID.String(), Name: profile.Name, IsActive: false}, nil
}

// RenameProfile changes the display name of the profile identified by id. The
// on-disk filename (the ID) is left unchanged.
func (pm *ProfileManager) RenameProfile(id string, newName string) error {
	if err := pm.serviceMgr.RenameProfile(profilemanager.ID(id), pm.username, newName); err != nil {
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

	// The stored account email is kept on purpose, matching the desktop and CLI
	// logout semantics: the next login passes it as the login_hint so the IdP
	// preselects the account. Removing the profile is what deletes it.
	log.Infof("logged out from profile: %s", id)
	return nil
}

// RemoveProfile deletes a profile. The default profile and the active profile
// cannot be removed.
func (pm *ProfileManager) RemoveProfile(id string) error {
	configPath, err := pm.getProfileConfigPath(id)
	if err != nil {
		return err
	}

	if err := pm.serviceMgr.RemoveProfile(profilemanager.ID(id), pm.username); err != nil {
		return fmt.Errorf("remove profile: %w", err)
	}

	// The account file is this package's, not the ServiceManager's, so it must
	// go here. The default profile has a fixed filename, so a recreated one
	// would otherwise inherit the deleted profile's email as its login_hint.
	// Not fatal: the profile itself is gone.
	if err := removeProfileEmail(configPath); err != nil {
		log.Warnf("failed to remove stored account email for profile %s: %v", id, err)
	}

	log.Infof("removed profile: %s", id)
	return nil
}

// ProfilePrefs returns the namespaced per-profile preference store of the
// profile identified by id.
func (pm *ProfileManager) ProfilePrefs(id string) (*profilemanager.Prefs, error) {
	prefs, err := pm.serviceMgr.ProfilePrefs(profilemanager.ID(id), pm.username)
	if err != nil {
		return nil, fmt.Errorf("resolve profile prefs: %w", err)
	}
	return prefs, nil
}

// GetConfigPath returns the config file path for the given profile ID. The
// platform code should call this instead of constructing paths itself.
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

// profileEmail returns the account email recorded for a profile. Display-only,
// so an unresolvable path degrades to "" rather than an error.
func (pm *ProfileManager) profileEmail(id string) string {
	configPath, err := pm.getProfileConfigPath(id)
	if err != nil {
		return ""
	}
	return ReadProfileEmail(configPath)
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
