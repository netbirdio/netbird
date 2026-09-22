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
	"strconv"
	"strings"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/getent"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/util"
)

// EnvDisableDefaultProfileClaim turns off the console-user claim of an unowned
// default profile. The profile then stays unowned until a privileged caller
// records an owner.
const EnvDisableDefaultProfileClaim = "NB_DISABLE_DEFAULT_PROFILE_CLAIM"

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

// HandleMatch is the set of profiles a handle matched and which matcher found
// them. Kind only carries meaning when more than one profile matched.
type HandleMatch struct {
	Profiles []Profile
	Kind     AmbiguityKind
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
	Name   string
	Owners []string
}

// Config JSON keys on disk.
const (
	ownersFieldName = "Owners"
	nameFieldName   = "Name"
)

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
	ID ID `json:"name"`

	// Username records which per-username directory a pre-migration profile's
	// file lives in. It is a hint for reconstructing that path, not a statement
	// about who owns the profile: ownership lives in the profile's own JSON, as
	// typed principals. Profiles in the shared directory leave it empty, and
	// the field goes away once no per-username directory is left.
	Username string `json:"username"`
}

// FilePath rebuilds the profile's path from the per-username layout.
//
// Prefer ServiceManager.ActiveProfilePath: this reconstruction only holds for a
// profile that predates the ID-keyed layout, since a profile created after it
// lives in the shared directory instead, under no username at all.
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

// ActiveProfilePath returns the config file of the profile the active-profile
// state points at.
//
// The path is looked up through the loader rather than rebuilt from the
// recorded username, because a profile's directory is no longer a function of
// who owns it: profiles created since the ID-keyed layout share one directory,
// and only pre-migration ones sit under a per-username one. The username
// survives as a tiebreaker for the single case that still needs one, a legacy
// ID being a display name that two users can each hold.
//
// A state that points at a profile with no file yet still yields the path that
// file would have, so a caller reads "not created yet" from a stat rather than
// from an error.
func (s *ServiceManager) ActiveProfilePath(a *ActiveProfileState) (string, error) {
	if a == nil || a.ID == "" {
		return "", fmt.Errorf("active profile ID is empty")
	}
	if a.ID == defaultProfileName {
		return DefaultConfigPath, nil
	}
	if !IsValidProfileFilenameStem(a.ID) {
		return "", fmt.Errorf("invalid profile ID: %q", a.ID)
	}

	profiles, err := s.loadAllProfiles()
	if err != nil {
		return "", fmt.Errorf("load profiles: %w", err)
	}

	var matches []Profile
	for _, p := range profiles {
		if p.ID == a.ID {
			matches = append(matches, p)
		}
	}

	if len(matches) == 0 {
		// Nothing on disk under that ID, so the legacy layout is the only
		// guess left for where the file would go.
		return a.FilePath()
	}

	if len(matches) == 1 {
		return matches[0].Path, nil
	}

	// Migration gives every profile an ID no other profile holds, so getting
	// here means it has not run yet or did not finish. Until it does, the
	// recorded account name is the only thing telling namesakes apart, and
	// picking the wrong one would point the daemon at another user's config.
	// State written before the field held a directory recorded the raw account
	// name, which the old layout sanitized on its way to becoming one.
	for _, want := range []string{a.Username, sanitizeProfileName(a.Username)} {
		if want == "" {
			continue
		}
		for _, p := range matches {
			if filepath.Base(filepath.Dir(p.Path)) == want {
				return p.Path, nil
			}
		}
	}

	// Nothing left to tell them apart, so this fails rather than guesses.
	return "", fmt.Errorf("%w: %d profiles hold the ID %q and the active profile state does not say which account's directory it is in",
		ErrAmbiguousActiveProfile, len(matches), a.ID)
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

// activeStateMu serializes every access to the active profile state file,
// reads included.
// The path is a package-level global that every ServiceManager in the process
// shares, so the lock is package level too.
var activeStateMu sync.Mutex

// GetActiveProfileState returns the profile the daemon is on, seeding the state
// with the default profile when there is nothing on disk yet.
func (s *ServiceManager) GetActiveProfileState() (*ActiveProfileState, error) {
	activeStateMu.Lock()
	defer activeStateMu.Unlock()

	return s.readActiveProfileState()
}

// readActiveProfileState is GetActiveProfileState with activeStateMu held.
func (s *ServiceManager) readActiveProfileState() (*ActiveProfileState, error) {
	if err := s.seedActiveState(); err != nil {
		return nil, fmt.Errorf("failed to set default active profile state: %w", err)
	}
	var activeProfile ActiveProfileState
	if _, err := util.ReadJson(ActiveProfileStatePath, &activeProfile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := s.writeDefaultActiveProfileState(); err != nil {
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
		if err := s.writeDefaultActiveProfileState(); err != nil {
			return nil, fmt.Errorf("failed to set active profile to default: %w", err)
		}
		return &ActiveProfileState{
			ID:       defaultProfileName,
			Username: "",
		}, nil
	}

	return &activeProfile, nil

}

// seedActiveState writes the default state when the file is not there yet.
// Called with activeStateMu held.
func (s *ServiceManager) seedActiveState() error {
	_, err := os.Stat(ActiveProfileStatePath)
	if err != nil {
		if os.IsNotExist(err) {
			if err := s.writeDefaultActiveProfileState(); err != nil {
				return fmt.Errorf("failed to set active profile to default: %w", err)
			}
		} else {
			return fmt.Errorf("failed to stat active profile state path %s: %w", ActiveProfileStatePath, err)
		}
	}

	return nil
}

// SetActiveProfileState records a as the profile the daemon is on.
func (s *ServiceManager) SetActiveProfileState(a *ActiveProfileState) error {
	activeStateMu.Lock()
	defer activeStateMu.Unlock()

	return s.writeActiveProfileState(a)
}

// writeActiveProfileState is SetActiveProfileState with activeStateMu held.
func (s *ServiceManager) writeActiveProfileState(a *ActiveProfileState) error {
	if a == nil || a.ID == "" {
		return errors.New("invalid active profile state")
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

// SetActiveProfileStateToDefault points the daemon at the default profile.
func (s *ServiceManager) SetActiveProfileStateToDefault() error {
	activeStateMu.Lock()
	defer activeStateMu.Unlock()

	return s.writeDefaultActiveProfileState()
}

// writeDefaultActiveProfileState is SetActiveProfileStateToDefault with
// activeStateMu held.
func (s *ServiceManager) writeDefaultActiveProfileState() error {
	return s.writeActiveProfileState(&ActiveProfileState{
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
	cfg, err := createNewConfig(ConfigInput{ConfigPath: profPath, Owner: callerId, Name: displayName})
	if err != nil {
		return nil, fmt.Errorf("failed to create new config: %w", err)
	}

	if err := util.WriteJsonWithRestrictedPermission(context.Background(), profPath, cfg); err != nil {
		return nil, fmt.Errorf("failed to write profile config: %w", err)
	}

	return &Profile{
		ID:   id,
		Name: displayName,
		Path: profPath,
	}, nil
}

func (s *ServiceManager) RenameProfile(id ID, newName string) error {
	displayName, err := sanitizeDisplayName(newName)
	if err != nil {
		return fmt.Errorf("invalid profile name: %w", err)
	}

	if !IsValidProfileFilenameStem(id) {
		return fmt.Errorf("invalid profile ID: %q", id)
	}

	target, err := s.ProfileByID(id)
	if err != nil {
		return err
	}

	return writeProfileName(target.Path, displayName)
}

// RemoveProfile deletes the profile identified by id. Callers must have already
// turned any user-supplied handle into a concrete ID, which is what the
// authorization gate does before a handler runs.
func (s *ServiceManager) RemoveProfile(id ID) error {
	if id == defaultProfileName {
		defaultName := defaultProfileName
		if defaultProfile, err := parseDefaultProfile(); err == nil {
			defaultName = defaultProfile.Name
		}
		return fmt.Errorf("cannot remove default profile with name: %s", defaultName)
	}
	if !IsValidProfileFilenameStem(id) {
		return fmt.Errorf("invalid profile ID: %q", id)
	}

	target, err := s.ProfileByID(id)
	if err != nil {
		return err
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

// ListProfiles returns every profile for the given user
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

	configPath, err := s.ActiveProfilePath(activeProf)
	if err != nil {
		log.Warnf("failed to resolve the active profile's path: %v", err)
		return defaultStatePath
	}

	return filepath.Join(filepath.Dir(configPath), activeProf.ID.String()+".state.json")
}

// getConfigDirLegacy returns the profiles directory, using profilesDir if set, otherwise getConfigDirForUser
func (s *ServiceManager) getConfigDirLegacy(username string) (string, error) {
	if s.profilesDir != "" {
		return s.profilesDir, nil
	}

	return getConfigDirForUserLegacy(username)
}

func (s *ServiceManager) getConfigDir() (string, error) {
	configDir := s.profilesDirPath()
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return "", err
		}
	}

	return configDir, nil
}

// profilesDirPath returns the directory new profiles are written to without
// creating it, so a read path can name it without leaving a directory behind.
func (s *ServiceManager) profilesDirPath() string {
	if s.profilesDir != "" {
		return s.profilesDir
	}

	if ConfigDirOverride != "" {
		return ConfigDirOverride
	}

	return filepath.Join(DefaultConfigPathDir, DefaultProfilePathDir)
}

// loadAllProfiles returns every profile accessible by a given kernel attested
// user. The returned slice is sorted by ID for a stable display order.
//
// Each Profile is fully populated: ID is the filename stem, Name comes
// from the JSON's "name" field (falling back to the filename stem when absent)
// and Path is built from a basename read off disk.
func (s *ServiceManager) loadAllProfilesForIdentity(userID ipcauth.Identity) ([]Profile, error) {
	if !userID.Known() {
		return []Profile{}, nil
	}
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

var (
	legacyDirMu    sync.Mutex
	legacyDirCache = map[string]string{}
)

// ClaimLegacyProfiles stamps the caller on every unowned profile in the
// directory their own user name produced before the ownership model.
//
// Ownership lives in the file now, so the directory name is only a leftover.
// Flattening is a separate step we are doing in the future. Moving it would
// pull the state file out from under an engine that captured its path at
// connect time.
func (s *ServiceManager) ClaimLegacyProfiles(id ipcauth.Identity) {
	// A privileged caller reaches every profile already and an internal load
	// has no caller, so neither should leave an owner behind.
	if ipcauth.IsPrivilegedCaller(id) {
		return
	}

	profiles, err := s.loadAllProfiles()
	if err != nil {
		log.Warnf("could not load all profiles: %v", err)
		return
	}

	if !hasUnownedLegacyProfile(profiles) {
		return
	}

	dir, ok := legacyDirForIdentity(id)
	if !ok {
		return
	}

	principal := ipcauth.OwnerPrincipalForIdentity(id)
	parsed, ok := ipcauth.ParsePrincipal(principal)
	if !ok {
		log.Warnf("not claiming legacy profiles, %q is not a usable owner", principal)
		return
	}

	for i := range profiles {
		p := &profiles[i]
		if len(p.Owners) > 0 || p.LegacyUserDir == "" || p.LegacyUserDir != dir {
			continue
		}

		if err := StampOwner(p.Path, id); err != nil {
			log.Warnf("could not claim legacy profile %s for %s: %v", p.Path, principal, err)
			continue
		}

		p.Owners = []ipcauth.Principal{parsed}
		log.Infof("claimed legacy profile %s for %s, its directory is named after that account", p.Path, principal)
	}
}

func (s *ServiceManager) ClaimDefaultProfileIfNeeded(id ipcauth.Identity) {
	if !id.Known() || ipcauth.IsPrivilegedCaller(id) || defaultProfileClaimDisabled() {
		return
	}

	profiles, err := s.loadAllProfiles()
	if err != nil {
		log.Warnf("could not load all profiles: %v", err)
		return
	}

	var unowned bool
	var p *Profile
	for i := range profiles {
		p = &profiles[i]
		if p.ID == defaultProfileName && len(p.Owners) == 0 {
			unowned = true
			break
		}
	}

	if unowned && isConsoleUser(id) {
		principal := ipcauth.OwnerPrincipalForIdentity(id)
		parsed, ok := ipcauth.ParsePrincipal(principal)
		if !ok {
			log.Warnf("not claiming default profile, %q is not a usable owner", principal)
			return
		}
		if err := StampOwner(p.Path, id); err != nil {
			log.Warnf("could not claim default profile %s for %#v: %v", p.Path, id, err)
			return
		}
		p.Owners = []ipcauth.Principal{parsed}
		log.Infof("claimed default profile %s for %s", p.Path, principal)
	}
}

// isConsoleUser is a variable so a test can decide whether a caller is at the
// console without the machine running the test having a seat of its own.
var isConsoleUser = ipcauth.IsConsoleUser

// logDefaultClaimDisabledOrError keeps the notice to once per process, since the claim
// path runs on every profile load. It also logs a parse failure once.
var logDefaultClaimDisabledOrError sync.Once

// defaultProfileClaimDisabled reports whether the environment turns off the
// console-user claim of the default profile.
func defaultProfileClaimDisabled() bool {
	val := os.Getenv(EnvDisableDefaultProfileClaim)
	if val == "" {
		return false
	}
	disabled, err := strconv.ParseBool(val)
	if err != nil {
		logDefaultClaimDisabledOrError.Do(func() {
			log.Warnf("failed to parse %s: %v", EnvDisableDefaultProfileClaim, err)
		})
		return false
	}
	if disabled {
		logDefaultClaimDisabledOrError.Do(func() {
			log.Infof("%s is set, the default profile stays unowned and reachable only by a privileged caller until an owner is recorded another way", EnvDisableDefaultProfileClaim)
		})
	}
	return disabled
}

func hasUnownedLegacyProfile(profiles []Profile) bool {
	for i := range profiles {
		if profiles[i].LegacyUserDir != "" && len(profiles[i].Owners) == 0 {
			return true
		}
	}
	return false
}

// legacyDirForIdentity is a variable so a test can supply an account name
// without depending on the host's user database.
var legacyDirForIdentity = resolveLegacyDir

// resolveLegacyDir returns the per-username directory the old layout would have
// created for a caller, and whether there is one.
//
// Successes are cached for the process, failures are not, so a directory
// service that is briefly unreachable does not lock its users out until the
// daemon restarts.
func resolveLegacyDir(id ipcauth.Identity) (string, bool) {
	key := ipcauth.OwnerPrincipalForIdentity(id)

	legacyDirMu.Lock()
	cached, hit := legacyDirCache[key]
	legacyDirMu.Unlock()
	if hit {
		return cached, cached != ""
	}

	lookup := strconv.FormatUint(uint64(id.UID), 10)
	if id.IsWindows() {
		lookup = id.SID
	}

	u, err := getent.LookupUserID(lookup)
	if err != nil {
		log.Warnf("cannot resolve %s to an account name, its legacy profiles stay unowned: %v", key, err)
		return "", false
	}

	dir := sanitizeProfileName(u.Username)

	legacyDirMu.Lock()
	legacyDirCache[key] = dir
	legacyDirMu.Unlock()

	return dir, dir != ""
}

func (s *ServiceManager) loadAllProfiles() ([]Profile, error) {
	_, activeIsDefault := s.activeProfileID()

	var profiles []Profile
	defaultProfile, err := parseDefaultProfile()
	if err != nil {
		log.Warnf("leaving the default profile out of the listing: %v", err)
	} else {
		defaultProfile.IsActive = activeIsDefault
		profiles = append(profiles, defaultProfile)
	}

	dirs, err := s.profileDirs()
	if err != nil {
		return nil, err
	}

	var fileProfiles []Profile
	for _, dir := range dirs {
		dirProfiles, err := s.getProfilesFromDirectory(dir)
		if err != nil {
			return nil, err
		}
		fileProfiles = append(fileProfiles, dirProfiles...)
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

// profileDir is one directory the loader scans. legacyUser is the sanitized
// username it is named after, empty for the directory profiles go to now.
type profileDir struct {
	path       string
	legacyUser string
}

// profileDirs lists the directories a profile can live in: the one new profiles
// go to, plus every per-username directory left from before the ID-keyed
// layout. The first is not necessarily under DefaultConfigPathDir, since a
// ServiceManager can be pointed at a directory of its own, which is what the
// mobile bindings do.
//
// The default profile is not in any of them: it sits at DefaultConfigPath.
func (s *ServiceManager) profileDirs() ([]profileDir, error) {
	dirs := []profileDir{{path: s.profilesDirPath()}}

	entries, err := os.ReadDir(DefaultConfigPathDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read profile directory: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == DefaultProfilePathDir {
			continue
		}
		// Every other subdirectory is named after the account that created the
		// profiles in it. The dot in profiles.v1 is what keeps them apart,
		// since sanitizeProfileName drops dots.
		dirs = append(dirs, profileDir{
			path:       filepath.Join(DefaultConfigPathDir, entry.Name()),
			legacyUser: entry.Name(),
		})
	}

	// The profiles directory is usually one of the subdirectories above, so
	// without this a profile would be read twice.
	// Guard for mobile subdirectories.
	seen := make(map[string]bool, len(dirs))
	unique := dirs[:0]
	for _, dir := range dirs {
		if seen[dir.path] {
			continue
		}
		seen[dir.path] = true
		unique = append(unique, dir)
	}
	return unique, nil
}

func (s *ServiceManager) getProfilesFromDirectory(dir profileDir) ([]Profile, error) {
	configDir := dir.path
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
		profile, err := parseProfileFile(filepath.Join(configDir, base), dir.legacyUser)
		if err != nil {
			log.Warnf("leaving profile %s out of the listing: %v", base, err)
			continue
		}
		profile.IsActive = profile.ID == ID(activeID)

		fileProfiles = append(fileProfiles, profile)
	}
	return fileProfiles, nil
}

// parseProfile turns one file on disk into a Profile. It is the only place that
// conversion happens, so a listing and a single lookup cannot drift on what a
// profile file means, and it reads the file once rather than once per field.
//
// The ID is given rather than taken from the filename. Every profile but one is
// named after its ID; the default profile's file is named by the platform, and
// the mobile bindings call it netbird.cfg.
//
// IsActive is left to the caller: it depends on which profile the daemon is on
// rather than on the file, and a caller listing many profiles already knows it.
func parseProfile(path string, id ID, legacyUser string) (Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}

	var meta profileMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return Profile{}, fmt.Errorf("parse profile %s: %w", path, err)
	}

	owners, err := parseOwners(meta.Owners)
	if err != nil {
		return Profile{}, fmt.Errorf("could not parse owner for path: %s: %w", path, err)
	}

	// The name falls back to the ID, which is what a legacy profile written
	// before the field existed has.
	name := meta.Name
	if name == "" {
		name = id.String()
	}

	return Profile{
		ID:            id,
		Name:          name,
		Path:          path,
		Owners:        owners,
		LegacyUserDir: legacyUser,
	}, nil
}

// parseProfileFile reads a profile whose ID is its filename stem, which is
// every profile except the default one.
func parseProfileFile(path, legacyUser string) (Profile, error) {
	stem := ID(strings.TrimSuffix(filepath.Base(path), ".json"))
	if !IsValidProfileFilenameStem(stem) {
		return Profile{}, fmt.Errorf("invalid profile ID: %q", stem)
	}
	return parseProfile(path, stem, legacyUser)
}

// parseDefaultProfile reads the default profile, which is the one profile that
// is allowed not to exist yet: the daemon writes it on first run, and a file
// that is not there is unowned rather than unreadable. Every listing before the
// first run would otherwise fail.
func parseDefaultProfile() (Profile, error) {
	profile, err := parseProfile(DefaultConfigPath, defaultProfileName, "")
	if errors.Is(err, os.ErrNotExist) {
		return Profile{
			ID:   defaultProfileName,
			Name: defaultProfileName,
			Path: DefaultConfigPath,
		}, nil
	}
	return profile, err
}

// parseOwners turns the recorded owners into principals. Owners stay principals
// so they are never mistaken for a kernel-attested caller.
//
// Only the first entry is read. The field is a list on disk so multiple owners
// can be added later without a format change, but multiple owners are not
// supported yet.
func parseOwners(owners []string) ([]ipcauth.Principal, error) {
	if len(owners) == 0 {
		return nil, nil
	}

	principal, ok := ipcauth.ParsePrincipal(owners[0])
	if !ok {
		// An entry that cannot be parsed is not trusted, and it is not an
		// absence of ownership either: the profile records an owner that cannot
		// be matched against anyone.
		return nil, fmt.Errorf("unparseable owner %q", owners[0])
	}
	return []ipcauth.Principal{principal}, nil
}

// ClaimProfile records a principal as a profile's sole owner, replacing whoever
// is recorded now.
//
// The principal comes from an administrator rather than from the kernel, so it
// is never turned into an Identity on the way and it is validated here.
func (s *ServiceManager) ClaimProfile(p *Profile, principal ipcauth.Principal) error {
	if err := principal.Validate(); err != nil {
		return fmt.Errorf("claim %s: %w", p.ID, err)
	}

	path, err := p.FilePath()
	if err != nil {
		return fmt.Errorf("profile path: %w", err)
	}
	if err := stampPrincipal(path, principal.String()); err != nil {
		return fmt.Errorf("claim %s for %s: %w", p.ID, principal, err)
	}
	p.Owners = []ipcauth.Principal{principal}
	log.Infof("claimed profile %s for %s", path, principal)
	return nil
}

// StampOwner records a caller as a profile's owner, replacing whoever is
// recorded now.
func StampOwner(path string, owner ipcauth.Identity) error {
	if !owner.Known() {
		return fmt.Errorf("cannot stamp owner that is not verified by the kernel")
	}
	return stampPrincipal(path, ipcauth.OwnerPrincipalForIdentity(owner))
}

// stampPrincipal records an owner principal directly. Migration needs this: it
// resolves an account name rather than a caller, and a name the kernel never
// vouched for must not become an Identity on the way.
func stampPrincipal(path, principal string) error {
	return setProfileField(path, ownersFieldName, []string{principal})
}

// writeProfileName sets a profile's display name. Renaming does it on request,
// migration does it to move a name out of a filename that is about to change.
func writeProfileName(path, name string) error {
	return setProfileField(path, nameFieldName, name)
}

// setProfileField replaces one top-level key of a profile's JSON and leaves the
// rest of the document as it found it.
func setProfileField(path, field string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	doc := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	if doc == nil {
		return fmt.Errorf("profile %s holds no object to set %s on", path, field)
	}

	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s of %s: %w", field, path, err)
	}

	// Decoding matches keys case-insensitively
	for k := range doc {
		if k != field && strings.EqualFold(k, field) {
			delete(doc, k)
		}
	}
	doc[field] = raw

	if err := util.WriteJsonWithRestrictedPermission(context.Background(), path, doc); err != nil {
		return fmt.Errorf("write profile %s: %w", path, err)
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

// MatchProfiles returns every profile a user-supplied handle matches, at the
// highest precedence tier that matched at all: exact ID, then exact name, then
// ID prefix. It answers existence and nothing else, so choosing between several
// matches is left to the caller that knows who is asking.
func (s *ServiceManager) MatchProfiles(handle string) (HandleMatch, error) {
	if handle == "" {
		return HandleMatch{}, fmt.Errorf("profile handle is empty")
	}

	profiles, err := s.loadAllProfiles()
	if err != nil {
		return HandleMatch{}, err
	}

	// A legacy ID is a display name two accounts can hold in their own profile
	// directories, so even an exact ID can match more than one file.
	var idMatches []Profile
	for i := range profiles {
		if profiles[i].ID == ID(handle) {
			idMatches = append(idMatches, profiles[i])
		}
	}
	if len(idMatches) > 0 {
		return HandleMatch{Profiles: idMatches, Kind: AmbiguityKindName}, nil
	}

	var nameMatches []Profile
	for i := range profiles {
		if profiles[i].Name == handle {
			nameMatches = append(nameMatches, profiles[i])
		}
	}
	if len(nameMatches) > 0 {
		return HandleMatch{Profiles: nameMatches, Kind: AmbiguityKindName}, nil
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
	if len(prefixMatches) > 0 {
		return HandleMatch{Profiles: prefixMatches, Kind: AmbiguityKindIDPrefix}, nil
	}

	return HandleMatch{}, ErrProfileNotFound
}

// ProfileByPath returns the profile stored at this path.
func (s *ServiceManager) ProfileByPath(path string) (*Profile, error) {
	if path == "" {
		return nil, fmt.Errorf("profile path is empty")
	}

	legacyUser, ok, err := s.profileDirOf(path)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("path %q is not in a profile directory", path)
	}

	if filepath.Clean(path) == filepath.Clean(DefaultConfigPath) {
		defaultProfile, err := parseDefaultProfile()
		if err != nil {
			return nil, err
		}
		return &defaultProfile, nil
	}

	profile, err := parseProfileFile(path, legacyUser)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrProfileNotFound
	}
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

// profileDirOf reports whether a path is a profile file in one of the
// directories profiles live in, and which legacy account's directory that is.
func (s *ServiceManager) profileDirOf(path string) (legacyUser string, ok bool, err error) {
	clean := filepath.Clean(path)
	if clean == filepath.Clean(DefaultConfigPath) {
		return "", true, nil
	}

	dirs, err := s.profileDirs()
	if err != nil {
		return "", false, err
	}

	parent := filepath.Dir(clean)
	for _, dir := range dirs {
		if filepath.Clean(dir.path) == parent {
			return dir.legacyUser, true, nil
		}
	}
	return "", false, nil
}

// ProfileByID returns the first profile with this ID, reading only the files
// that could hold it rather than every profile on the machine.
//
// A legacy ID is a display name and two accounts can hold the same one in their
// own directories, so a caller that might be looking at somebody else's
// namesake wants ProfileByPath instead.
func (s *ServiceManager) ProfileByID(id ID) (*Profile, error) {
	if id == "" {
		return nil, fmt.Errorf("profile ID is empty")
	}
	if id == defaultProfileName {
		defaultProfile, err := parseDefaultProfile()
		if err != nil {
			return nil, err
		}
		return &defaultProfile, nil
	}
	if !IsValidProfileFilenameStem(id) {
		return nil, fmt.Errorf("invalid profile ID: %q", id)
	}

	dirs, err := s.profileDirs()
	if err != nil {
		return nil, err
	}

	for _, dir := range dirs {
		path := filepath.Join(dir.path, id.String()+".json")
		profile, err := parseProfile(path, id, dir.legacyUser)
		switch {
		case err == nil:
			return &profile, nil
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			log.Warnf("skipping profile %s: %v", path, err)
		}
	}

	return nil, ErrProfileNotFound
}
