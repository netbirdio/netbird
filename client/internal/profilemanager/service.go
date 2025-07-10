package profilemanager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util"
)

var (
	oldDefaultConfigPathDir = ""
	oldDefaultConfigPath    = ""

	DefaultConfigPathDir   = ""
	defaultConfigPath      = ""
	ActiveProfileStatePath = ""
)

var (
	ErrorOldDefaultConfigNotFound = errors.New("old default config not found")
)

func init() {

	DefaultConfigPathDir = "/var/lib/netbird/"
	oldDefaultConfigPathDir = "/etc/netbird/"

	switch runtime.GOOS {
	case "windows":
		oldDefaultConfigPathDir = filepath.Join(os.Getenv("PROGRAMDATA"), "Netbird")
		DefaultConfigPathDir = oldDefaultConfigPathDir

	case "freebsd":
		oldDefaultConfigPathDir = "/var/db/netbird/"
		DefaultConfigPathDir = oldDefaultConfigPathDir
	}

	oldDefaultConfigPath = filepath.Join(oldDefaultConfigPathDir, "config.json")
	defaultConfigPath = filepath.Join(DefaultConfigPathDir, "default.json")
	ActiveProfileStatePath = filepath.Join(DefaultConfigPathDir, "active_profile.json")
}

type ActiveProfileState struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type ServiceManager struct{}

func (s *ServiceManager) CopyDefaultProfileIfNotExists() (bool, error) {

	if err := os.MkdirAll(DefaultConfigPathDir, 0600); err != nil {
		return false, fmt.Errorf("failed to create default config path directory: %w", err)
	}

	// check if default profile exists
	if _, err := os.Stat(defaultConfigPath); !os.IsNotExist(err) {
		// default profile already exists
		log.Debugf("default profile already exists at %s, skipping copy", defaultConfigPath)
		return false, nil
	}

	// check old default profile
	if _, err := os.Stat(oldDefaultConfigPath); os.IsNotExist(err) {
		// old default profile does not exist, nothing to copy
		return false, ErrorOldDefaultConfigNotFound
	}

	// copy old default profile to new location
	if err := os.Rename(oldDefaultConfigPath, defaultConfigPath); err != nil {
		return false, errors.New("failed to copy old default profile to new location: " + err.Error())
	}

	// set permissions for the new default profile
	if err := os.Chmod(defaultConfigPath, 0600); err != nil {
		log.Warnf("failed to set permissions for default profile: %v", err)
	}

	if err := s.SetActiveProfileState(&ActiveProfileState{
		Name: "default",
		Path: defaultConfigPath,
	}); err != nil {
		log.Errorf("failed to set active profile state: %v", err)
		return false, fmt.Errorf("failed to set active profile state: %w", err)
	}

	return true, nil
}

func (s *ServiceManager) CreateDefaultProfile() error {
	_, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath: defaultConfigPath,
	})

	if err != nil {
		return fmt.Errorf("failed to create default profile: %w", err)
	}

	log.Infof("default profile created at %s", defaultConfigPath)
	return nil
}

func (s *ServiceManager) GetActiveProfileState() (*ActiveProfileState, error) {
	_, err := os.Stat(ActiveProfileStatePath)
	if err != nil {
		if os.IsNotExist(err) {
			if err := s.SetActiveProfileStateToDefault(); err != nil {
				return nil, fmt.Errorf("failed to set active profile to default: %w", err)
			}
			return &ActiveProfileState{
				Name: "default",
				Path: defaultConfigPath,
			}, nil
		} else {
			return nil, fmt.Errorf("failed to stat active profile state path %s: %w", ActiveProfileStatePath, err)
		}
	}

	var activeProfile ActiveProfileState
	if _, err := util.ReadJson(ActiveProfileStatePath, &activeProfile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := s.SetActiveProfileStateToDefault(); err != nil {
				return nil, fmt.Errorf("failed to set active profile to default: %w", err)
			}
			return &ActiveProfileState{
				Name: "default",
				Path: defaultConfigPath,
			}, nil
		} else {
			return nil, fmt.Errorf("failed to read active profile state: %w", err)
		}
	}

	if activeProfile.Name == "" || activeProfile.Path == "" {
		if err := s.SetActiveProfileStateToDefault(); err != nil {
			return nil, fmt.Errorf("failed to set active profile to default: %w", err)
		}
		return &ActiveProfileState{
			Name: "default",
			Path: defaultConfigPath,
		}, nil
	}

	return &activeProfile, nil

}

func (s *ServiceManager) SetActiveProfileState(a *ActiveProfileState) error {
	if a == nil || a.Name == "" || a.Path == "" {
		return errors.New("invalid active profile state")
	}

	if err := util.WriteJsonWithRestrictedPermission(context.Background(), ActiveProfileStatePath, a); err != nil {
		return fmt.Errorf("failed to write active profile state: %w", err)
	}

	log.Infof("active profile set to %s at %s", a.Name, a.Path)
	return nil
}

func (s *ServiceManager) SetActiveProfileStateToDefault() error {
	return s.SetActiveProfileState(&ActiveProfileState{
		Name: "default",
		Path: defaultConfigPath,
	})
}

func (s *ServiceManager) DefaultProfilePath() string {
	return defaultConfigPath
}
