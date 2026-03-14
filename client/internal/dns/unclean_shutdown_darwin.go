//go:build !ios

package dns

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
)

type ShutdownState struct {
	InterfaceName string   `json:"interface_name,omitempty"`
	CreatedKeys   []string `json:"created_keys,omitempty"`
}

// UnmarshalJSON implements custom JSON unmarshaling to handle backward compatibility.
// Old versions serialized CreatedKeys without JSON tags (as "CreatedKeys" in JSON),
// while the new format uses "created_keys". This ensures both formats are handled.
func (s *ShutdownState) UnmarshalJSON(data []byte) error {
	type Alias ShutdownState
	aux := &Alias{}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	*s = ShutdownState(*aux)

	// If CreatedKeys is empty, try legacy format (no JSON tags, PascalCase keys)
	if len(s.CreatedKeys) == 0 {
		var legacy struct {
			CreatedKeys []string `json:"CreatedKeys"`
		}
		if err := json.Unmarshal(data, &legacy); err == nil && len(legacy.CreatedKeys) > 0 {
			s.CreatedKeys = legacy.CreatedKeys
		}
	}

	return nil
}

func (s *ShutdownState) Name() string {
	return "dns_state"
}

func (s *ShutdownState) Cleanup() error {
	var manager *systemConfigurator
	if s.InterfaceName != "" {
		var err error
		manager, err = newHostManager(s.InterfaceName)
		if err != nil {
			return fmt.Errorf("create host manager: %w", err)
		}
	} else {
		// State from an older version without interface name.
		// Create a bare configurator so discoverExistingKeys() can find and
		// remove legacy non-scoped scutil keys (e.g. NetBird-Match/DNS).
		log.Warn("dns shutdown state has no interface name, falling back to legacy scutil key discovery")
		manager = &systemConfigurator{
			createdKeys: make(map[string]struct{}),
		}
	}

	for _, key := range s.CreatedKeys {
		manager.createdKeys[key] = struct{}{}
	}

	if err := manager.restoreUncleanShutdownDNS(); err != nil {
		return fmt.Errorf("restore unclean shutdown dns: %w", err)
	}

	return nil
}
