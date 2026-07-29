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

func (pm *ProfileManager) SetActiveProfileState(state *ProfileState) error {
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("get config directory: %w", err)
	}

	activeProf, err := pm.GetActiveProfile()
	if err != nil {
		if errors.Is(err, ErrNoActiveProfile) {
			return fmt.Errorf("no active profile set: %w", err)
		}
		return fmt.Errorf("get active profile: %w", err)
	}

	id := activeProf.ID
	if id != defaultProfileName && !IsValidProfileFilenameStem(id) {
		return fmt.Errorf("invalid active profile ID: %q", id)
	}

	stateFile := filepath.Join(configDir, id.String()+".state.json")
	err = util.WriteJsonWithRestrictedPermission(context.Background(), stateFile, state)
	if err != nil {
		return fmt.Errorf("write profile state: %w", err)
	}

	return nil
}

// RemoveProfileState deletes the per-profile state file (which holds the
// account email used for the SSO login hint and the UI display). Called after
// a successful logout so a logged-out profile no longer shows a stale account
// email. The state file only stores the email, so deleting it is equivalent to
// clearing it; the next SSO login recreates it. A missing file is not an error.
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
