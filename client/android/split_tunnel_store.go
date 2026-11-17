//go:build android

package android

const splitTunnelNamespace = "split-tunnel"

// SplitTunnelStore reads and writes a profile's split tunnelling settings.
type SplitTunnelStore struct {
	prefs prefsStore
}

// NewSplitTunnelStore opens the split tunnelling store of the given profile.
func NewSplitTunnelStore(configDir, profileID string) (*SplitTunnelStore, error) {
	prefs, err := newProfilePrefs(configDir, profileID)
	if err != nil {
		return nil, err
	}
	return &SplitTunnelStore{prefs: prefs}, nil
}

// Load returns the stored settings, or settings that carry every application
// when the profile has none saved.
func (s *SplitTunnelStore) Load() (*SplitTunnelSettings, error) {
	var section splitTunnelSection
	if _, err := s.prefs.Get(splitTunnelNamespace, &section); err != nil {
		return nil, err
	}
	return settingsFromSection(section), nil
}

// Save replaces the stored settings.
func (s *SplitTunnelStore) Save(settings *SplitTunnelSettings) error {
	return s.prefs.Put(splitTunnelNamespace, sectionFromSettings(settings))
}
