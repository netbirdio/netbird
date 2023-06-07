package dns

import (
	"github.com/netbirdio/netbird/iface"
)

type androidHostManager struct {
}

func newHostManager(wgInterface *iface.WGIface) (hostManager, error) {
	return &androidHostManager{}, nil
}

func (a androidHostManager) applyDNSConfig(config hostDNSConfig) error {
	return nil
}

func (a androidHostManager) restoreHostDNS() error {
	return nil
}

func (a androidHostManager) supportCustomPort() bool {
	return false
}
