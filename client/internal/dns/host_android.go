package dns

import "net/netip"

type androidHostManager struct {
}

func newHostManager() (hostManager, error) {
	return &androidHostManager{}, nil
}

func (a androidHostManager) applyDNSConfig(config HostDNSConfig) error {
	return nil
}

func (a androidHostManager) restoreHostDNS() error {
	return nil
}

func (a androidHostManager) supportCustomPort() bool {
	return false
}

func (a androidHostManager) restoreUncleanShutdownDNS(*netip.Addr) error {
	return nil
}
