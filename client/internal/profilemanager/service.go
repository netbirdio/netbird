package profilemanager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util"
)

var (
	oldDefaultConfigPathDir = ""
	oldDefaultConfigPath    = ""

	DefaultConfigPathDir   = ""
	DefaultConfigPath      = ""
	ActiveProfileStatePath = ""
)

var (
	ErrorOldDefaultConfigNotFound = errors.New("old default config not found")
)

func init() {

	DefaultConfigPathDir = "/var/lib/netbird/"
	oldDefaultConfigPathDir = "/etc/netbird/"

	if stateDir := os.Getenv("NB_STATE_DIR"); stateDir != "" {
		DefaultConfigPathDir = stateDir
	} else {
		switch runtime.GOOS {
		case "windows":
			oldDefaultConfigPathDir = filepath.Join(os.Getenv("PROGRAMDATA"), "Netbird")
			DefaultConfigPathDir = oldDefaultConfigPathDir

		case "freebsd":
			oldDefaultConfigPathDir = "/var/db/netbird/"
			DefaultConfigPathDir = oldDefaultConfigPathDir
		}
	}

	oldDefaultConfigPath = filepath.Join(oldDefaultConfigPathDir, "config.json")
	DefaultConfigPath = filepath.Join(DefaultConfigPathDir, "default.json")
	ActiveProfileStatePath = filepath.Join(DefaultConfigPathDir, "active_profile.json")
}

type ActiveProfileState struct {
	Name     string `json:"name"`
	Username string `json:"username"`
}

func (a *ActiveProfileState) FilePath() (string, error) {
	if a.Name == "" {
		return "", fmt.Errorf("active profile name is empty")
	}

	if a.Name == defaultProfileName {
		return DefaultConfigPath, nil
	}

	configDir, err := getConfigDirForUser(a.Username)
	if err != nil {
		return "", fmt.Errorf("failed to get config directory for user %s: %w", a.Username, err)
	}

	return filepath.Join(configDir, a.Name+".json"), nil
}

type ServiceManager struct {
	profilesDir string // If set, overrides ConfigDirOverride for profile operations
}

func NewServiceManager(defaultConfigPath string) *ServiceManager {
	if defaultConfigPath != "" {
		DefaultConfigPath = defaultConfigPath
	}
	return &ServiceManager{}
}

// NewServiceManagerWithProfilesDir creates a ServiceManager with a specific profiles directory
// This allows setting the profiles directory without modifying the global ConfigDirOverride
func NewServiceManagerWithProfilesDir(defaultConfigPath string, profilesDir string) *ServiceManager {
	if defaultConfigPath != "" {
		DefaultConfigPath = defaultConfigPath
	}
	return &ServiceManager{
		profilesDir: profilesDir,
	}
}

func (s *ServiceManager) CopyDefaultProfileIfNotExists() (bool, error) {

	if err := os.MkdirAll(DefaultConfigPathDir, 0600); err != nil {
		return false, fmt.Errorf("failed to create default config path directory: %w", err)
	}

	// check if default profile exists
	if _, err := os.Stat(DefaultConfigPath); !os.IsNotExist(err) {
		// default profile already exists
		log.Debugf("default profile already exists at %s, skipping copy", DefaultConfigPath)
		return false, nil
	}

	// check old default profile
	if _, err := os.Stat(oldDefaultConfigPath); os.IsNotExist(err) {
		// old default profile does not exist, nothing to copy
		return false, ErrorOldDefaultConfigNotFound
	}

	// copy old default profile to new location
	if err := copyFile(oldDefaultConfigPath, DefaultConfigPath, 0600); err != nil {
		return false, fmt.Errorf("copy default profile from %s to %s: %w", oldDefaultConfigPath, DefaultConfigPath, err)
	}

	// set permissions for the new default profile
	if err := os.Chmod(DefaultConfigPath, 0600); err != nil {
		log.Warnf("failed to set permissions for default profile: %v", err)
	}

	return true, nil
}

// copyFile copies the contents of src to dst and sets dst's file mode to perm.
func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source file %s: %w", src, err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open target file %s: %w", dst, err)
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy data to %s: %w", dst, err)
	}

	return nil
}

func (s *ServiceManager) CreateDefaultProfile() error {
	_, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath: DefaultConfigPath,
	})

	if err != nil {
		return fmt.Errorf("failed to create default profile: %w", err)
	}

	log.Infof("default profile created at %s", DefaultConfigPath)
	return nil
}

func (s *ServiceManager) GetActiveProfileState() (*ActiveProfileState, error) {
	if err := s.setDefaultActiveState(); err != nil {
		return nil, fmt.Errorf("failed to set default active profile state: %w", err)
	}
	var activeProfile ActiveProfileState
	if _, err := util.ReadJson(ActiveProfileStatePath, &activeProfile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := s.SetActiveProfileStateToDefault(); err != nil {
				return nil, fmt.Errorf("failed to set active profile to default: %w", err)
			}
			return &ActiveProfileState{
				Name:     "default",
				Username: "",
			}, nil
		} else {
			return nil, fmt.Errorf("failed to read active profile state: %w", err)
		}
	}

	if activeProfile.Name == "" {
		if err := s.SetActiveProfileStateToDefault(); err != nil {
			return nil, fmt.Errorf("failed to set active profile to default: %w", err)
		}
		return &ActiveProfileState{
			Name:     "default",
			Username: "",
		}, nil
	}

	return &activeProfile, nil

}

func (s *ServiceManager) setDefaultActiveState() error {
	_, err := os.Stat(ActiveProfileStatePath)
	if err != nil {
		if os.IsNotExist(err) {
			if err := s.SetActiveProfileStateToDefault(); err != nil {
				return fmt.Errorf("failed to set active profile to default: %w", err)
			}
		} else {
			return fmt.Errorf("failed to stat active profile state path %s: %w", ActiveProfileStatePath, err)
		}
	}

	return nil
}

func (s *ServiceManager) SetActiveProfileState(a *ActiveProfileState) error {
	if a == nil || a.Name == "" {
		return errors.New("invalid active profile state")
	}

	if a.Name != defaultProfileName && a.Username == "" {
		return fmt.Errorf("username must be set for non-default profiles, got: %s", a.Name)
	}

	if err := util.WriteJsonWithRestrictedPermission(context.Background(), ActiveProfileStatePath, a); err != nil {
		return fmt.Errorf("failed to write active profile state: %w", err)
	}

	log.Infof("active profile set to %s for %s", a.Name, a.Username)
	return nil
}

func (s *ServiceManager) SetActiveProfileStateToDefault() error {
	return s.SetActiveProfileState(&ActiveProfileState{
		Name:     "default",
		Username: "",
	})
}

func (s *ServiceManager) DefaultProfilePath() string {
	return DefaultConfigPath
}

func (s *ServiceManager) AddProfile(profileName, username string) error {
	configDir, err := s.getConfigDir(username)
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	profileName = sanitizeProfileName(profileName)

	if profileName == defaultProfileName {
		return fmt.Errorf("cannot create profile with reserved name: %s", defaultProfileName)
	}

	profPath := filepath.Join(configDir, profileName+".json")
	if fileExists(profPath) {
		return ErrProfileAlreadyExists
	}

	cfg, err := createNewConfig(ConfigInput{ConfigPath: profPath})
	if err != nil {
		return fmt.Errorf("failed to create new config: %w", err)
	}

	err = util.WriteJson(context.Background(), profPath, cfg)
	if err != nil {
		return fmt.Errorf("failed to write profile config: %w", err)
	}

	return nil
}

func (s *ServiceManager) RemoveProfile(profileName, username string) error {
	configDir, err := s.getConfigDir(username)
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	profileName = sanitizeProfileName(profileName)

	if profileName == defaultProfileName {
		return fmt.Errorf("cannot remove profile with reserved name: %s", defaultProfileName)
	}
	profPath := filepath.Join(configDir, profileName+".json")
	if !fileExists(profPath) {
		return ErrProfileNotFound
	}

	activeProf, err := s.GetActiveProfileState()
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

func (s *ServiceManager) ListProfiles(username string) ([]Profile, error) {
	configDir, err := s.getConfigDir(username)
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
	activeProf, err := s.GetActiveProfileState()
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

// GetStatePath returns the path to the state file based on the operating system
// It returns an empty string if the path cannot be determined.
func (s *ServiceManager) GetStatePath() string {
	if path := os.Getenv("NB_DNS_STATE_FILE"); path != "" {
		return path
	}

	defaultStatePath := filepath.Join(DefaultConfigPathDir, "state.json")

	activeProf, err := s.GetActiveProfileState()
	if err != nil {
		log.Warnf("failed to get active profile state: %v", err)
		return defaultStatePath
	}

	if activeProf.Name == defaultProfileName {
		return defaultStatePath
	}

	configDir, err := s.getConfigDir(activeProf.Username)
	if err != nil {
		log.Warnf("failed to get config directory for user %s: %v", activeProf.Username, err)
		return defaultStatePath
	}

	return filepath.Join(configDir, activeProf.Name+".state.json")
}

// getConfigDir returns the profiles directory, using profilesDir if set, otherwise getConfigDirForUser
func (s *ServiceManager) getConfigDir(username string) (string, error) {
	if s.profilesDir != "" {
		return s.profilesDir, nil
	}

	return getConfigDirForUser(username)
}
