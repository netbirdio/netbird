package profilemanager

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/netbirdio/netbird/util"
)

type Profile struct {
	Name     string
	Email    string
	IsActive bool
}

type ProfileManager struct {
	mu            sync.Mutex
	activeProfile *Profile
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

	if activeProf.Name == profileName {
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

	if pm.activeProfile == nil {
		return nil, ErrNoActiveProfile
	}

	return pm.activeProfile, nil
}

func (pm *ProfileManager) SetActiveProfile(profileName string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.activeProfile = &Profile{Name: profileName}
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
	profiles = append(profiles, Profile{Name: "default", IsActive: activeProfName == "default"})
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

// TODO(hakan): implement
func (pm *ProfileManager) SwitchProfile(profileName string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if the profile exists
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	profPath := filepath.Join(configDir, profileName+".json")
	if !fileExists(profPath) {
		return ErrProfileNotFound
	}

	// Set the active profile
	pm.activeProfile = &Profile{Name: profileName}
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
