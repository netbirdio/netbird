//go:build android

package android

import (
	"fmt"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

type prefsStore interface {
	Get(namespace string, v any) (bool, error)
	Put(namespace string, v any) error
}

type profilePrefs struct {
	prefs *profilemanager.Prefs
}

func newProfilePrefs(configDir, profileID string) (*profilePrefs, error) {
	if configDir == "" || profileID == "" {
		return nil, fmt.Errorf("profile prefs require a config dir and profile ID")
	}
	pm := NewProfileManager(configDir)
	prefs, err := pm.serviceMgr.ProfilePrefs(profilemanager.ID(profileID), androidUsername)
	if err != nil {
		return nil, fmt.Errorf("resolve profile prefs: %w", err)
	}
	return &profilePrefs{prefs: prefs}, nil
}

func (p *profilePrefs) Get(namespace string, v any) (bool, error) {
	return p.prefs.Get(namespace, v)
}

func (p *profilePrefs) Put(namespace string, v any) error {
	return p.prefs.Put(namespace, v)
}
