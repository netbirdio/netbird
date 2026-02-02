//go:build !ios

package dns

import (
	"fmt"
)

type ShutdownState struct {
	InterfaceName string   `json:"interface_name,omitempty"`
	CreatedKeys   []string `json:"created_keys,omitempty"`
}

func (s *ShutdownState) Name() string {
	return "dns_state"
}

func (s *ShutdownState) Cleanup() error {
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
