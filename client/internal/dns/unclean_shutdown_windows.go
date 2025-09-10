package dns

import (
	"fmt"
)

type ShutdownState struct {
	Guid           string
	GPO            bool
	NRPTEntryCount int
}

func (s *ShutdownState) Name() string {
	return "dns_state"
}

func (s *ShutdownState) Cleanup() error {
	manager := &registryConfigurator{
		guid:           s.Guid,
		gpo:            s.GPO,
		nrptEntryCount: s.NRPTEntryCount,
	}

	if err := manager.restoreUncleanShutdownDNS(); err != nil {
		return fmt.Errorf("restore unclean shutdown dns: %w", err)
	}

	return nil
}
