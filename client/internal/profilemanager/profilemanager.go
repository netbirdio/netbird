package profilemanager

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/netbirdio/netbird/util"
)

type Profile struct {
	Name  string
	Email string
}

type ProfileManager struct {
}

func NewProfileManager() *ProfileManager {
	return &ProfileManager{}
}

func (pm *ProfileManager) AddProfile(profile Profile) error {
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	profPath := filepath.Join(configDir, profile.Name+".json")
	if fileExists(profPath) {
		return ErrProfileAlreadyExists
	}

}

func getConfigDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	configDir = filepath.Join(configDir, "netbird")
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return "", err
		}
	}

	return configDir, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// createNewConfig creates a new config generating a new Wireguard key and saving to file
func createNewConfig(input ConfigInput) (*Config, error) {
	config := &Config{
		// defaults to false only for new (post 0.26) configurations
		ServerSSHAllowed: util.False(),
	}

	if _, err := config.apply(input); err != nil {
		return nil, err
	}

	return config, nil
}
