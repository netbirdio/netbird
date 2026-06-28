package profilemanager

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	log "github.com/sirupsen/logrus"
)

const (
	DefaultProfileName         = "default"
	defaultProfileName         = DefaultProfileName // Keep for backward compatibility
	activeProfileStateFilename = "active_profile.txt"
)

type Profile struct {
	// ID is the on-disk filename stem (without .json). For new profiles
	// it is a 32-char hex string; legacy profiles created before the
	// ID-keyed layout keep their original name as their ID. The reserved
	// value "default" identifies the special default profile.
	ID ID
	// Name is the human-readable display name. Falls back to ID when the
	// underlying JSON has no "name" field set.
	Name string
	// Path is the absolute path to the profile JSON. Populated by the
	// loader so callers do not have to reconstruct it from ID + dir.
	Path     string
	IsActive bool
}

func (p *Profile) FilePath() (string, error) {
	if p.Path != "" {
		return p.Path, nil
	}

	id := p.ID
	if id == "" {
		id = ID(p.Name)
	}
	if id == "" {
		return "", fmt.Errorf("profile ID is empty")
	}

	if id == defaultProfileName {
		return DefaultConfigPath, nil
	}

	if !IsValidProfileFilenameStem(id) {
		return "", fmt.Errorf("invalid profile ID: %q", id)
	}

	username, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user: %w", err)
	}

	configDir, err := getConfigDirForUser(username.Username)
	if err != nil {
		return "", fmt.Errorf("failed to get config directory for user %s: %w", username.Username, err)
	}

	return filepath.Join(configDir, id.String()+".json"), nil
}

func (p *Profile) IsDefault() bool {
	if p.ID != "" {
		return p.ID == defaultProfileName
	}
	return p.Name == defaultProfileName
}

type ProfileManager struct {
	mu sync.Mutex
}

func NewProfileManager() *ProfileManager {
	return &ProfileManager{}
}

// GetActiveProfile returns the active profile as recorded in the local
// user state file. Only ID is populated.
func (pm *ProfileManager) GetActiveProfile() (*Profile, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	id := pm.getActiveProfileState()
	return &Profile{ID: id}, nil
}

// SwitchProfile records the given profile ID as active in the local user
// state file.
func (pm *ProfileManager) SwitchProfile(id ID) error {
	if id != defaultProfileName && !IsValidProfileFilenameStem(id) {
		return fmt.Errorf("invalid profile ID: %q", id)
	}

	if err := pm.setActiveProfileState(id); err != nil {
		return fmt.Errorf("failed to switch profile: %w", err)
	}
	return nil
}

// sanitizeProfileName sanitizes the username by removing any invalid characters and spaces.
func sanitizeProfileName(name string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' {
			return r
		}
		// drop everything else
		return -1
	}, name)
}

func (pm *ProfileManager) getActiveProfileState() ID {

	configDir, err := getConfigDir()
	if err != nil {
		log.Warnf("failed to get config directory: %v", err)
		return defaultProfileName
	}

	statePath := filepath.Join(configDir, activeProfileStateFilename)

	prof, err := os.ReadFile(statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("failed to read active profile state: %v", err)
		} else {
			if err := pm.setActiveProfileState(defaultProfileName); err != nil {
				log.Warnf("failed to set default profile state: %v", err)
			}
		}
		return defaultProfileName
	}
	profileName := strings.TrimSpace(string(prof))

	if profileName == "" {
		log.Warnf("active profile state is empty, using default profile: %s", defaultProfileName)
		return defaultProfileName
	}

	return ID(profileName)
}

func (pm *ProfileManager) setActiveProfileState(id ID) error {

	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	statePath := filepath.Join(configDir, activeProfileStateFilename)

	err = os.WriteFile(statePath, []byte(id), 0600)
	if err != nil {
		return fmt.Errorf("failed to write active profile state: %w", err)
	}

	return nil
}

// GetLoginHint retrieves the email from the active profile to use as login_hint.
func GetLoginHint() string {
	pm := NewProfileManager()
	activeProf, err := pm.GetActiveProfile()
	if err != nil {
		log.Debugf("failed to get active profile for login hint: %v", err)
		return ""
	}

	profileState, err := pm.GetProfileState(activeProf.ID)
	if err != nil {
		log.Debugf("failed to get profile state for login hint: %v", err)
		return ""
	}

	return profileState.Email
}
