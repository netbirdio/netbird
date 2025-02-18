package dns

import (
	"fmt"
)

type ShutdownState struct {
	Guid string
	GPO  bool
}

func (s *ShutdownState) Name() string {
	return "dns_state"
}

func (s *ShutdownState) Cleanup() error {
	manager := &registryConfigurator{
		guid: s.Guid,
		gpo:  s.GPO,
	}

	if err := manager.restoreUncleanShutdownDNS(); err != nil {
		return fmt.Errorf("restore unclean shutdown dns: %w", err)
	}

	return nil
}
