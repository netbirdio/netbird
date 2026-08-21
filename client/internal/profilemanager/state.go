package profilemanager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/netbirdio/netbird/util"
)

type ProfileState struct {
	Email string `json:"email"`
}

// GetProfileState reads the per-profile state file keyed by profile ID.
// The state file lives in the user's config directory. Legacy state files
// keyed by the old profile name remain readable.
func (pm *ProfileManager) GetProfileState(id ID) (*ProfileState, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return nil, fmt.Errorf("get config directory: %w", err)
	}

	if id != defaultProfileName && !IsValidProfileFilenameStem(id) {
		return nil, fmt.Errorf("invalid profile ID: %q", id)
	}

	stateFile := filepath.Join(configDir, id.String()+".state.json")
	stateFileExists, err := fileExists(stateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to check if profile state file exists: %w", err)
	}
	if !stateFileExists {
		return nil, errors.New("profile state file does not exist")
	}

	var state ProfileState
	_, err = util.ReadJson(stateFile, &state)
	if err != nil {
		return nil, fmt.Errorf("read profile state: %w", err)
	}

	return &state, nil
}

// SetProfileState writes the state file of the profile identified by id. Prefer
// it over SetActiveProfileState whenever the caller knows which profile the data
// belongs to: an SSO login spans seconds of user interaction, and the active
// profile can change during it, which would file the account email under
// whichever profile happened to be active when the flow returned.
func (pm *ProfileManager) SetProfileState(id ID, state *ProfileState) error {
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("get config directory: %w", err)
	}

	if id == "" {
		return fmt.Errorf("empty profile ID")
	}
	if id != defaultProfileName && !IsValidProfileFilenameStem(id) {
		return fmt.Errorf("invalid profile ID: %q", id)
	}

	stateFile := filepath.Join(configDir, id.String()+".state.json")
	if err := util.WriteJsonWithRestrictedPermission(context.Background(), stateFile, state); err != nil {
		return fmt.Errorf("write profile state: %w", err)
	}

	return nil
}

// SetActiveProfileState writes the state file of whichever profile is active at
// call time. Use SetProfileState when the target profile is known.
func (pm *ProfileManager) SetActiveProfileState(state *ProfileState) error {
	activeProf, err := pm.GetActiveProfile()
	if err != nil {
		if errors.Is(err, ErrNoActiveProfile) {
			return fmt.Errorf("no active profile set: %w", err)
		}
		return fmt.Errorf("get active profile: %w", err)
	}

	return pm.SetProfileState(activeProf.ID, state)
}

// RemoveProfileState deletes the per-profile state file (which holds the
// account email used for the SSO login hint and the UI display). Called after
// profile removal; logout keeps the file so the next login can pass the email
// as the login_hint. The state file only stores the email, so deleting it is
// equivalent to clearing it; the next SSO login recreates it. A missing file
// is not an error.
func (pm *ProfileManager) RemoveProfileState(profileName string) error {
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("get config directory: %w", err)
	}

	stateFile := filepath.Join(configDir, profileName+".state.json")
	if err := os.Remove(stateFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove profile state: %w", err)
	}

	return nil
}
