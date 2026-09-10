package profilemanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/util"
)

var (
	oldDefaultConfigPathDir = ""
	oldDefaultConfigPath    = ""

	DefaultConfigPathDir   = ""
	DefaultConfigPath      = ""
	ActiveProfileStatePath = ""

	DefaultProfilePathDir = "profiles.v1"

	ErrorOldDefaultConfigNotFound = errors.New("old default config not found")
)

// ErrAmbiguousHandle is returned when a profile handle (ID prefix or name)
// matches more than one profile. Callers can render Candidates to help the
// user disambiguate.
type ErrAmbiguousHandle struct {
	Handle     string
	Candidates []Profile
	Kind       AmbiguityKind
}

// AmbiguityKind describes which matcher produced the ambiguity, so callers
// can tailor the error message.
type AmbiguityKind int

const (
	AmbiguityKindIDPrefix AmbiguityKind = iota
	AmbiguityKindName
)

// profileMeta is the minimal slice of a profile JSON we need, so we avoid
// reading all fields
type profileMeta struct {
	Name string
}

// nolint:unused
type ownerMeta struct {
	Owners []string
}

func (e *ErrAmbiguousHandle) Error() string {
	switch e.Kind {
	case AmbiguityKindIDPrefix:
		return fmt.Sprintf("ID prefix %q is ambiguous (matches %d profiles)", e.Handle, len(e.Candidates))
	default:
		return fmt.Sprintf("name %q is ambiguous (%d profiles share this name)", e.Handle, len(e.Candidates))
	}
}

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
	// ID is the on-disk filename stem of the active profile. The JSON tag stays
	// as "name" for backwards compatibility with active state files written
	// before the ID-based config files. Legacy values were profile names, which
	// were also the legacy filename stems, so they still resolve to the correct
	// file on disk.
	ID       ID     `json:"name"`
	Username string `json:"username"`
}

func (a *ActiveProfileState) FilePath() (string, error) {
	if a.ID == "" {
		return "", fmt.Errorf("active profile ID is empty")
	}

	if a.ID == defaultProfileName {
		return DefaultConfigPath, nil
	}

	if !IsValidProfileFilenameStem(a.ID) {
		return "", fmt.Errorf("invalid profile ID: %q", a.ID)
	}

	configDir, err := getConfigDirForUserLegacy(a.Username)
	if err != nil {
		return "", fmt.Errorf("failed to get config directory for user %s: %w", a.Username, err)
	}

	return filepath.Join(configDir, a.ID.String()+".json"), nil
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
				ID:       defaultProfileName,
				Username: "",
			}, nil
		} else {
			return nil, fmt.Errorf("failed to read active profile state: %w", err)
		}
	}

	if activeProfile.ID == "" {
		if err := s.SetActiveProfileStateToDefault(); err != nil {
			return nil, fmt.Errorf("failed to set active profile to default: %w", err)
		}
		return &ActiveProfileState{
			ID:       defaultProfileName,
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
	if a == nil || a.ID == "" {
		return errors.New("invalid active profile state")
	}

	if a.ID != defaultProfileName && a.Username == "" {
		return fmt.Errorf("username must be set for non-default profiles, got: %s", a.ID)
	}

	if a.ID != defaultProfileName && !IsValidProfileFilenameStem(a.ID) {
		return fmt.Errorf("invalid profile ID: %q", a.ID)
	}

	if err := util.WriteJsonWithRestrictedPermission(context.Background(), ActiveProfileStatePath, a); err != nil {
		return fmt.Errorf("failed to write active profile state: %w", err)
	}

	log.Infof("active profile set to %s for %s", a.ID, a.Username)
	return nil
}

func (s *ServiceManager) SetActiveProfileStateToDefault() error {
	return s.SetActiveProfileState(&ActiveProfileState{
		ID:       defaultProfileName,
		Username: "",
	})
}

func (s *ServiceManager) DefaultProfilePath() string {
	return DefaultConfigPath
}

// AddProfile creates a new profile with a generated ID. The user-supplied
// displayName is stored inside the JSON's name field, the on-disk filename
// uses the generated ID.
//
// The returned Profile carries the freshly-generated ID so callers can
// show it to the user (and so the gRPC AddProfileResponse can include
// it).
func (s *ServiceManager) AddProfile(displayName string, callerId *ipcauth.Identity) (*Profile, error) {
	configDir, err := s.getConfigDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get config directory: %w", err)
	}

	displayName, err = sanitizeDisplayName(displayName)
	if err != nil {
		return nil, fmt.Errorf("invalid profile name: %w", err)
	}

	id, err := generateProfileID()
	if err != nil {
		return nil, fmt.Errorf("generate profile id: %w", err)
	}

	profPath := filepath.Join(configDir, id.String()+".json")
	cfg, err := createNewConfig(ConfigInput{ConfigPath: profPath, Owner: callerId})
	if err != nil {
		return nil, fmt.Errorf("failed to create new config: %w", err)
	}
	cfg.Name = displayName

	if err := util.WriteJson(context.Background(), profPath, cfg); err != nil {
		return nil, fmt.Errorf("failed to write profile config: %w", err)
	}

	return &Profile{
		ID:   id,
		Name: displayName,
		Path: profPath,
	}, nil
}

func (s *ServiceManager) RenameProfile(id ID, userID ipcauth.Identity, newName string) error {
	displayName, err := sanitizeDisplayName(newName)
	if err != nil {
		return fmt.Errorf("invalid profile name: %w", err)
	}

	if !IsValidProfileFilenameStem(id) {
		return fmt.Errorf("invalid profile ID: %q", id)
	}

	profiles, err := s.loadAllProfilesForIdentity(userID)
	if err != nil {
		return fmt.Errorf("load profiles: %w", err)
	}

	var target *Profile
	for i := range profiles {
		if profiles[i].ID == id {
			target = &profiles[i]
			break
		}
	}
	if target == nil {
		return ErrProfileNotFound
	}

	data, err := os.ReadFile(target.Path)
	if err != nil {
		return err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	cfg.Name = displayName

	if err := util.WriteJson(context.Background(), target.Path, cfg); err != nil {
		return fmt.Errorf("failed to write profile name: %w", err)
	}
	return nil
}

// RemoveProfile deletes the profile identified by id. Callers must have
// already resolved any user-supplied handle to a concrete ID via
// ResolveProfile.
func (s *ServiceManager) RemoveProfile(id ID, userID ipcauth.Identity) error {
	if id == defaultProfileName {
		defaultName := readProfileName(DefaultConfigPath)
		if defaultName == "" {
			defaultName = defaultProfileName
		}
		return fmt.Errorf("cannot remove default profile with name: %s", defaultName)
	}
	if !IsValidProfileFilenameStem(id) {
		return fmt.Errorf("invalid profile ID: %q", id)
	}

	profiles, err := s.loadAllProfilesForIdentity(userID)
	if err != nil {
		return fmt.Errorf("load profiles: %w", err)
	}

	var target *Profile
	for i := range profiles {
		if profiles[i].ID == id {
			target = &profiles[i]
			break
		}
	}
	if target == nil {
		return ErrProfileNotFound
	}

	activeProf, err := s.GetActiveProfileState()
	if err != nil && !errors.Is(err, ErrNoActiveProfile) {
		return fmt.Errorf("failed to get active profile: %w", err)
	}
	if activeProf != nil && activeProf.ID == id {
		return fmt.Errorf("cannot remove active profile: %s", id)
	}

	if err := util.RemoveJson(target.Path); err != nil {
		return fmt.Errorf("failed to remove profile config: %w", err)
	}

	stateFile := filepath.Join(filepath.Dir(target.Path), id.String()+".state.json")
	if err := os.Remove(stateFile); err != nil && !os.IsNotExist(err) {
		log.Warnf("failed to remove profile state file %s: %v", stateFile, err)
	}

	prefsFile := filepath.Join(filepath.Dir(target.Path), id.String()+prefsFileSuffix)
	if err := removePrefsFile(prefsFile); err != nil && !os.IsNotExist(err) {
		log.Warnf("failed to remove profile prefs file %s: %v", prefsFile, err)
	}

	return nil
}

// ListProfiles returns every profile for the given user, including the
// default profile, with IsActive flags set.
func (s *ServiceManager) ListProfiles(userID ipcauth.Identity) ([]Profile, error) {
	return s.loadAllProfilesForIdentity(userID)
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
		if errors.Is(err, syscall.ENOSYS) {
			log.Debugf("active profile state unavailable on this platform: %v", err)
		} else {
			log.Warnf("failed to get active profile state: %v", err)
		}
		return defaultStatePath
	}

	if activeProf.ID == defaultProfileName {
		return defaultStatePath
	}

	if !IsValidProfileFilenameStem(activeProf.ID) {
		log.Warnf("invalid active profile ID %q, using default state path", activeProf.ID)
		return defaultStatePath
	}

	configDir, err := s.getConfigDirLegacy(activeProf.Username)
	if err != nil {
		log.Warnf("failed to get config directory for user %s: %v", activeProf.Username, err)
		return defaultStatePath
	}

	return filepath.Join(configDir, activeProf.ID.String()+".state.json")
}

// getConfigDirLegacy returns the profiles directory, using profilesDir if set, otherwise getConfigDirForUser
func (s *ServiceManager) getConfigDirLegacy(username string) (string, error) {
	if s.profilesDir != "" {
		return s.profilesDir, nil
	}

	return getConfigDirForUserLegacy(username)
}

func (s *ServiceManager) getConfigDir() (string, error) {
	if s.profilesDir != "" {
		return s.profilesDir, nil
	}

	if ConfigDirOverride != "" {
		return ConfigDirOverride, nil
	}

	configDir := filepath.Join(DefaultConfigPathDir, DefaultProfilePathDir)
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return "", err
		}
	}

	return configDir, nil
}

// loadAllProfiles returns every profile visible to the daemon for the
// given user, including the default profile. The returned slice is sorted
// by ID for a stable display order.
//
// Each Profile is fully populated: ID is the filename stem, Name comes
// from the JSON's "name" field (falling back to the filename stem when absent)
// and Path is built from a basename read off disk.
func (s *ServiceManager) loadAllProfilesForIdentity(userID ipcauth.Identity) ([]Profile, error) {
	allProfiles, err := s.loadAllProfiles()
	if err != nil {
		return nil, err
	}

	accessible := make([]Profile, 0, len(allProfiles))
	for _, p := range allProfiles {
		if p.AccessibleBy(userID) {
			accessible = append(accessible, p)
		}
	}

	return accessible, nil
}

func (s *ServiceManager) loadAllProfiles() ([]Profile, error) {
	_, activeIsDefault := s.activeProfileID()
	defaultName := readProfileName(DefaultConfigPath)
	if defaultName == "" {
		defaultName = defaultProfileName
	}

	// The default profile is not seeded with an owner: it starts unowned, and
	// the first claim stamps it like any other profile.
	defaultOwners, err := readProfileOwners(DefaultConfigPath)
	if err != nil {
		return nil, err
	}
	profiles := []Profile{{
		ID:       defaultProfileName,
		Name:     defaultName,
		Path:     DefaultConfigPath,
		IsActive: activeIsDefault,
		Owners:   defaultOwners,
	}}

	configPathDir, err := os.ReadDir(DefaultConfigPathDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return profiles, nil
		}
		return nil, fmt.Errorf("read profile directory: %w", err)
	}

	var fileProfiles []Profile
	for _, entry := range configPathDir {
		if entry.IsDir() {
			legacyUsernameProfiles, err := s.getProfilesFromDirectory(filepath.Join(DefaultConfigPathDir, entry.Name()))
			if err != nil {
				return nil, err
			}
			fileProfiles = append(fileProfiles, legacyUsernameProfiles...)
		}
	}

	sort.Slice(fileProfiles, func(i, j int) bool {
		if fileProfiles[i].Name != fileProfiles[j].Name {
			return fileProfiles[i].Name < fileProfiles[j].Name
		}
		// Sort tie-break on ID so duplicate names always render in the same order.
		return fileProfiles[i].ID < fileProfiles[j].ID
	})
	profiles = append(profiles, fileProfiles...)
	return profiles, nil
}

func (s *ServiceManager) getProfilesFromDirectory(configDir string) ([]Profile, error) {
	activeID, _ := s.activeProfileID()
	entries, err := os.ReadDir(configDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Profile{}, nil
		}
		return nil, fmt.Errorf("read profile directory: %w", err)
	}

	var fileProfiles []Profile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		base := entry.Name()
		if !strings.HasSuffix(base, ".json") {
			continue
		}
		if strings.HasSuffix(base, ".state.json") {
			continue
		}
		stem := ID(strings.TrimSuffix(base, ".json"))
		if stem == defaultProfileName {
			// default lives at the top-level config dir, not under /<user>
			continue
		}
		if !IsValidProfileFilenameStem(ID(stem)) {
			continue
		}
		path := filepath.Join(configDir, base)
		name := readProfileName(path)
		if name == "" {
			name = stem.String()
		}

		owners, err := readProfileOwners(path)
		if err != nil {
			log.Warnf("reading profile owner failed for %s: %v", path, err)
			continue
		}
		fileProfiles = append(fileProfiles, Profile{
			ID:       stem,
			Name:     name,
			Path:     path,
			IsActive: stem == ID(activeID),
			Owners:   owners,
		})
	}
	return fileProfiles, nil
}

// readProfileName parses just the "name" field from the profile Json.
func readProfileName(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var meta profileMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return ""
	}
	return meta.Name
}

// readProfileOwners parses the owner principals from a profile JSON. Owners stay
// principals so they are never mistaken for a kernel-attested caller.
//
// Only the first entry is read. The field is a list on disk so multiple owners
// can be added later without a format change, but multiple owners are not
// supported yet.
func readProfileOwners(path string) ([]ipcauth.Principal, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var meta ownerMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	if len(meta.Owners) == 0 {
		return nil, nil
	}

	principal, ok := ipcauth.ParsePrincipal(meta.Owners[0])
	if !ok {
		// An entry that cannot be parsed is not trusted, and it is not an
		// absence of ownership either: the profile records an owner that cannot
		// be matched against anyone.
		return nil, fmt.Errorf("unparseable owner %q in %s", meta.Owners[0], path)
	}
	return []ipcauth.Principal{principal}, nil
}

// nolint: unused,unusedfunc
func StampOwner(path string, owner ipcauth.Identity) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	cfg.Owners = []string{ipcauth.OwnerPrincipalForIdentity(owner)}

	if err := util.WriteJson(context.Background(), path, cfg); err != nil {
		return fmt.Errorf("failed to write profile owner: %w", err)
	}
	return nil
}

// activeProfileID returns the currently-active profile's ID. The second
// return value is true when the active profile is the default one.
func (s *ServiceManager) activeProfileID() (ID, bool) {
	state, err := s.GetActiveProfileState()
	if err != nil || state == nil {
		return defaultProfileName, true
	}
	if state.ID == "" || state.ID == defaultProfileName {
		return defaultProfileName, true
	}
	return state.ID, false
}

// ResolveProfile turns a user-supplied handle into a Profile. Resolution
// precedence is: exact ID match, then unique exact name, then unique ID
// prefix. Ambiguous matches return *ErrAmbiguousHandle so callers can
// surface the candidates.
func (s *ServiceManager) ResolveProfile(handle string, userID ipcauth.Identity) (*Profile, error) {
	if handle == "" {
		return nil, fmt.Errorf("profile handle is empty")
	}

	profiles, err := s.loadAllProfilesForIdentity(userID)
	if err != nil {
		return nil, err
	}

	for i := range profiles {
		if profiles[i].ID == ID(handle) {
			return &profiles[i], nil
		}
	}

	var nameMatches []Profile
	for i := range profiles {
		if profiles[i].Name == handle {
			nameMatches = append(nameMatches, profiles[i])
		}
	}
	if len(nameMatches) == 1 {
		return &nameMatches[0], nil
	}
	if len(nameMatches) > 1 {
		return nil, &ErrAmbiguousHandle{
			Handle:     handle,
			Candidates: nameMatches,
			Kind:       AmbiguityKindName,
		}
	}

	// ID prefix match. Skip the default profile so `select d` does not
	// accidentally pick it via prefix.
	var prefixMatches []Profile
	for i := range profiles {
		if profiles[i].ID == defaultProfileName {
			continue
		}
		if strings.HasPrefix(profiles[i].ID.String(), handle) {
			prefixMatches = append(prefixMatches, profiles[i])
		}
	}
	if len(prefixMatches) == 1 {
		return &prefixMatches[0], nil
	}
	if len(prefixMatches) > 1 {
		return nil, &ErrAmbiguousHandle{
			Handle:     handle,
			Candidates: prefixMatches,
			Kind:       AmbiguityKindIDPrefix,
		}
	}

	return nil, ErrProfileNotFound
}
