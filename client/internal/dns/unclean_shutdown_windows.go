package dns

import (
	"fmt"
)

type ShutdownState struct {
	Guid string
}

func (s *ShutdownState) Name() string {
	return "dns_state"
}

func (s *ShutdownState) Cleanup() error {
	manager, err := newHostManagerWithGuid(s.Guid)
	if err != nil {
		return fmt.Errorf("create host manager: %w", err)
	}

	if err := manager.restoreUncleanShutdownDNS(); err != nil {
		return fmt.Errorf("restore unclean shutdown dns: %w", err)
	}

	return nil
}
