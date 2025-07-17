package profilemanager

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util"
)

const (
	defaultProfileName         = "default"
	activeProfileStateFilename = "active_profile.txt"
)

type Profile struct {
	Name     string
	IsActive bool
}

func (p *Profile) FilePath() (string, error) {
	if p.Name == defaultProfileName {
		return defaultConfigPath, nil
	}

	configDir, err := getConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config directory: %w", err)
	}

	profPath := filepath.Join(configDir, p.Name+".json")
	return profPath, nil
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

func (pm *ProfileManager) RemoveProfile(profileName string) error {
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	profileName = sanitazeProfileName(profileName)

	if profileName == defaultProfileName {
		return fmt.Errorf("cannot remove profile with reserved name: %s", defaultProfileName)
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

	var filtered []string
	for _, file := range files {
		if strings.HasSuffix(file, "state.json") {
			continue // skip state files
		}
		filtered = append(filtered, file)
	}
	sort.Strings(filtered)

	var activeProfName string
	activeProf, err := pm.GetActiveProfile()
	if err == nil {
		activeProfName = activeProf.Name
	}

	var profiles []Profile
	// add default profile always
	profiles = append(profiles, Profile{Name: defaultProfileName, IsActive: activeProfName == "" || activeProfName == defaultProfileName})
	for _, file := range filtered {
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
	profileName = sanitazeProfileName(profileName)

	if err := pm.setActiveProfileState(profileName); err != nil {
		return fmt.Errorf("failed to switch profile: %w", err)
	}
	return nil
}

// sanitazeProfileName sanitizes the username by removing any invalid characters and spaces.
func sanitazeProfileName(profileName string) string {
	return strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' || r == ' ' {
			return -1 // remove this character
		}
		return r
	}, profileName)
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
	if profileName != defaultProfileName && !fileExists(filepath.Join(configDir, profileName+".json")) {
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

	if profileName != defaultProfileName {
		profPath := filepath.Join(configDir, profileName+".json")
		if !fileExists(profPath) {
			return fmt.Errorf("profile %s does not exist", profileName)
		}
	}

	statePath := filepath.Join(configDir, activeProfileStateFilename)

	err = os.WriteFile(statePath, []byte(profileName), 0600)
	if err != nil {
		return fmt.Errorf("failed to write active profile state: %w", err)
	}

	return nil
}
