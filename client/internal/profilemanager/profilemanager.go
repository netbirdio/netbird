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
	Name     string
	IsActive bool
}

func (p *Profile) FilePath() (string, error) {
	if p.Name == "" {
		return "", fmt.Errorf("active profile name is empty")
	}

	if p.Name == defaultProfileName {
		return DefaultConfigPath, nil
	}

	username, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user: %w", err)
	}

	configDir, err := getConfigDirForUser(username.Username)
	if err != nil {
		return "", fmt.Errorf("failed to get config directory for user %s: %w", username.Username, err)
	}

	return filepath.Join(configDir, p.Name+".json"), nil
}

func (p *Profile) IsDefault() bool {
	return p.Name == defaultProfileName
}

type ProfileManager struct {
	mu sync.Mutex
}

func NewProfileManager() *ProfileManager {
	return &ProfileManager{}
}

func (pm *ProfileManager) GetActiveProfile() (*Profile, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	prof := pm.getActiveProfileState()
	return &Profile{Name: prof}, nil
}

func (pm *ProfileManager) SwitchProfile(profileName string) error {
	profileName = sanitizeProfileName(profileName)

	if err := pm.setActiveProfileState(profileName); err != nil {
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

func (pm *ProfileManager) getActiveProfileState() string {

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

	return profileName
}

func (pm *ProfileManager) setActiveProfileState(profileName string) error {

	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	statePath := filepath.Join(configDir, activeProfileStateFilename)

	err = os.WriteFile(statePath, []byte(profileName), 0600)
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

	profileState, err := pm.GetProfileState(activeProf.Name)
	if err != nil {
		log.Debugf("failed to get profile state for login hint: %v", err)
		return ""
	}

	return profileState.Email
}
