package profilemanager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util"
)

const (
	defaultProfileName = "default"
)

type Profile struct {
	Name     string
	Email    string
	IsActive bool
}

type ProfileManager struct {
	mu sync.Mutex
}

func NewProfileManager() *ProfileManager {
	return &ProfileManager{}
}

func (pm *ProfileManager) AddProfile(profile Profile) error {
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	// TODO(hakan): sanitize profile name
	profPath := filepath.Join(configDir, profile.Name+".json")
	if fileExists(profPath) {
		return ErrProfileAlreadyExists
	}

	cfg, err := createNewConfig(ConfigInput{ConfigPath: profPath})
	if err != nil {
		return fmt.Errorf("failed to create new config: %w", err)
	}

	err = util.WriteJsonWithRestrictedPermission(context.Background(), profPath, cfg)
	if err != nil {
		return fmt.Errorf("failed to write profile config: %w", err)
	}

	return nil
}

func (pm *ProfileManager) RemoveProfile(profileName string) error {
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	profPath := filepath.Join(configDir, profileName+".json")
	if !fileExists(profPath) {
		return ErrProfileNotFound
	}

	activeProf, err := pm.GetActiveProfile()
	if err != nil && !errors.Is(err, ErrNoActiveProfile) {
		return fmt.Errorf("failed to get active profile: %w", err)
	}

	if activeProf != nil && activeProf.Name == profileName {
		return fmt.Errorf("cannot remove active profile: %s", profileName)
	}

	err = util.RemoveJson(profPath)
	if err != nil {
		return fmt.Errorf("failed to remove profile config: %w", err)
	}
	return nil
}

func (pm *ProfileManager) GetActiveProfile() (*Profile, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	prof := pm.getActiveProfileState()
	return &Profile{Name: prof}, nil
}

func (pm *ProfileManager) ListProfiles() ([]Profile, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get config directory: %w", err)
	}

	files, err := util.ListFiles(configDir, "*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to list profile files: %w", err)
	}

	var activeProfName string
	activeProf, err := pm.GetActiveProfile()
	if err == nil {
		activeProfName = activeProf.Name
	}

	var profiles []Profile
	// add default profile always
	profiles = append(profiles, Profile{Name: "default", IsActive: activeProfName == "" || activeProfName == "default"})
	for _, file := range files {
		profileName := strings.TrimSuffix(filepath.Base(file), ".json")
		var isActive bool
		if activeProfName != "" && activeProfName == profileName {
			isActive = true
		}
		profiles = append(profiles, Profile{Name: profileName, IsActive: isActive})
	}

	return profiles, nil
}

func (pm *ProfileManager) SwitchProfile(profileName string) error {
	if err := pm.setActiveProfileState(profileName); err != nil {
		return fmt.Errorf("failed to switch profile: %w", err)
	}

	// TODO(hakan): implement the logic to switch the profile in the application

	return nil
}

// sanitazeUsername sanitizes the username by removing any invalid characters
func sanitazeUsername(username string) string {
	// Remove invalid characters for a username in a file path
	return strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
			return -1 // remove this character
		}
		return r
	}, username)
}

func (pm *ProfileManager) getActiveProfileState() string {

	configDir, err := getConfigDir()
	if err != nil {
		log.Warnf("failed to get config directory: %v", err)
		return defaultProfileName
	}

	statePath := filepath.Join(configDir, "active_profile.txt")

	prof, err := os.ReadFile(statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("failed to read active profile state: %v", err)
		} else {
			pm.setActiveProfileState(defaultProfileName)
		}
		return defaultProfileName
	}
	profileName := strings.TrimSpace(string(prof))

	if profileName == "" {
		log.Warnf("active profile state is empty, using default profile: %s", defaultProfileName)
		return defaultProfileName
	}
	if !fileExists(filepath.Join(configDir, profileName+".json")) {
		log.Warnf("active profile %s does not exist, using default profile: %s", profileName, defaultProfileName)
		return defaultProfileName
	}
	return profileName
}

func (pm *ProfileManager) setActiveProfileState(profileName string) error {

	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	profPath := filepath.Join(configDir, profileName+".json")
	if !fileExists(profPath) {
		return fmt.Errorf("profile %s does not exist", profileName)
	}

	statePath := filepath.Join(configDir, "active_profile.txt")

	err = os.WriteFile(statePath, []byte(profileName), 0644)
	if err != nil {
		return fmt.Errorf("failed to write active profile state: %w", err)
	}

	return nil
}
