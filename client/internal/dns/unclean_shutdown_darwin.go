//go:build !ios

package dns

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// ShutdownState persists DNS cleanup state after an unclean shutdown.
// It scopes cleanup to a single host interface.
type ShutdownState struct {
	InterfaceName string `json:"interface_name,omitempty"`
	// CreatedKeys is untagged so default marshaling emits the PascalCase field name "CreatedKeys".
	// Older binaries serialized this field with no JSON tag (also PascalCase),
	// so they can still read state written by this version.
	CreatedKeys []string
}

// UnmarshalJSON accepts canonical PascalCase "CreatedKeys" and snake_case "created_keys"
// written by some intermediate builds.
// Canonical presence wins: if "CreatedKeys" occurs in the input object at all
// (including explicit null or empty array), "created_keys" is never consulted.
func (s *ShutdownState) UnmarshalJSON(data []byte) error {
	type Alias ShutdownState
	aux := &Alias{}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	*s = ShutdownState(*aux)

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}

	if _, present := fields["CreatedKeys"]; present {
		return nil
	}

	raw, present := fields["created_keys"]
	if !present {
		return nil
	}
	var snakeCaseKeys []string
	if err := json.Unmarshal(raw, &snakeCaseKeys); err != nil {
		return err
	}
	s.CreatedKeys = snakeCaseKeys

	return nil
}

func (s *ShutdownState) Name() string {
	return "dns_state"
}

// Cleanup removes DNS keys left by an unclean shutdown.
// It cannot recover state if the state file itself was lost.
func (s *ShutdownState) Cleanup() error {
	if s.InterfaceName != "" {
		// Scoped discovery never probes legacy global keys,
		// leaving concurrent older instances alone.
		manager, err := newHostManager(s.InterfaceName)
		if err != nil {
			return fmt.Errorf("create host manager: %w", err)
		}
		for _, key := range s.CreatedKeys {
			manager.createdKeys[key] = struct{}{}
		}
		if err := manager.restoreUncleanShutdownDNS(); err != nil {
			return fmt.Errorf("restore unclean shutdown dns: %w", err)
		}
		return nil
	}

	log.Warn("dns shutdown state has no interface name, falling back to legacy scutil key discovery")
	manager := &systemConfigurator{
		createdKeys: make(map[string]struct{}),
	}
	for _, key := range s.CreatedKeys {
		manager.createdKeys[key] = struct{}{}
	}
	legacyKeys, err := discoverLegacyDNSKeys()
	if err != nil {
		return fmt.Errorf("discover legacy DNS keys: %w", err)
	}
	for _, key := range legacyKeys {
		manager.createdKeys[key] = struct{}{}
	}

	if err := manager.restoreUncleanShutdownDNS(); err != nil {
		return fmt.Errorf("restore unclean shutdown dns: %w", err)
	}

	return nil
}
