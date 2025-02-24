package dns

import (
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

type androidHostManager struct {
}

func newHostManager() (*androidHostManager, error) {
	return &androidHostManager{}, nil
}

func (a androidHostManager) applyDNSConfig(HostDNSConfig, *statemanager.Manager) error {
	return nil
}

func (a androidHostManager) restoreHostDNS() error {
	return nil
}

func (a androidHostManager) supportCustomPort() bool {
	return false
}

func (a androidHostManager) string() string {
	return "none"
}
