package dns

import (
	"context"
)

type ShutdownState struct{}

func (s *ShutdownState) Name() string {
	return "dns_state"
}

func (s *ShutdownState) Cleanup() error {
	return nil
}

func (s *ShutdownState) RestoreUncleanShutdownConfigs(context.Context) error {
	return nil
}
