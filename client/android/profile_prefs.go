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
	prefs, err := NewProfileManager(configDir).impl.ProfilePrefs(profileID)
	if err != nil {
		return nil, err
	}
	return &profilePrefs{prefs: prefs}, nil
}

func (p *profilePrefs) Get(namespace string, v any) (bool, error) {
	return p.prefs.Get(namespace, v)
}

func (p *profilePrefs) Put(namespace string, v any) error {
	return p.prefs.Put(namespace, v)
}
