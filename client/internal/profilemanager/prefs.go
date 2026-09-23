package profilemanager

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/netbirdio/netbird/util"
)

const prefsFileSuffix = ".prefs.json"

var prefsMu sync.Mutex

// Prefs is a namespaced per-profile preference store backed by a single JSON
// file next to the profile config; it is deleted together with the profile.
type Prefs struct {
	path string
}

// ProfilePrefs returns the preference store of the profile identified by id.
func (s *ServiceManager) ProfilePrefs(id ID, username string) (*Prefs, error) {
	if !IsValidProfileFilenameStem(id) {
		return nil, fmt.Errorf("invalid profile ID: %q", id)
	}
	if id == defaultProfileName {
		return &Prefs{path: filepath.Join(filepath.Dir(DefaultConfigPath), id.String()+prefsFileSuffix)}, nil
	}
	configDir, err := s.getConfigDir(username)
	if err != nil {
		return nil, fmt.Errorf("get config directory for user %s: %w", username, err)
	}
	return &Prefs{path: filepath.Join(configDir, id.String()+prefsFileSuffix)}, nil
}

// Get unmarshals the namespace section into v and reports whether it exists.
func (p *Prefs) Get(namespace string, v any) (bool, error) {
	if namespace == "" {
		return false, fmt.Errorf("empty prefs namespace")
	}

	prefsMu.Lock()
	defer prefsMu.Unlock()

	sections, err := readPrefsFile(p.path)
	if err != nil {
		return false, err
	}
	raw, ok := sections[namespace]
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return false, fmt.Errorf("decode prefs namespace %q: %w", namespace, err)
	}
	return true, nil
}

// Put stores v as the namespace section, replacing any previous value.
func (p *Prefs) Put(namespace string, v any) error {
	if namespace == "" {
		return fmt.Errorf("empty prefs namespace")
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode prefs namespace %q: %w", namespace, err)
	}

	prefsMu.Lock()
	defer prefsMu.Unlock()

	sections, err := readPrefsFile(p.path)
	if err != nil {
		return err
	}
	sections[namespace] = raw
	return writePrefsFile(p.path, sections)
}

// Remove deletes the namespace section; a missing one is not an error.
func (p *Prefs) Remove(namespace string) error {
	if namespace == "" {
		return fmt.Errorf("empty prefs namespace")
	}

	prefsMu.Lock()
	defer prefsMu.Unlock()

	sections, err := readPrefsFile(p.path)
	if err != nil {
		return err
	}
	if _, ok := sections[namespace]; !ok {
		return nil
	}
	delete(sections, namespace)
	return writePrefsFile(p.path, sections)
}

func removePrefsFile(path string) error {
	prefsMu.Lock()
	defer prefsMu.Unlock()
	return os.Remove(path)
}

func readPrefsFile(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]json.RawMessage{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read prefs: %w", err)
	}

	sections := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &sections); err != nil {
		return nil, fmt.Errorf("decode prefs: %w", err)
	}
	return sections, nil
}

func writePrefsFile(path string, sections map[string]json.RawMessage) error {
	if err := util.WriteJsonWithRestrictedPermission(context.Background(), path, sections); err != nil {
		return fmt.Errorf("write prefs: %w", err)
	}
	return nil
}
