package profilemanager

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/netbirdio/netbird/util"
)

type ProfileState struct {
	Email string `json:"email"`
}

func (pm *ProfileManager) GetProfileState(profileName string) (*ProfileState, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return nil, fmt.Errorf("get config directory: %w", err)
	}

	stateFile := filepath.Join(configDir, profileName+".state.json")
	if !fileExists(stateFile) {
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

	stateFile := filepath.Join(configDir, activeProf.Name+".state.json")
	err = util.WriteJsonWithRestrictedPermission(context.Background(), stateFile, state)
	if err != nil {
		return fmt.Errorf("write profile state: %w", err)
	}

	return nil
}
