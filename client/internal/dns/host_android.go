package dns

type androidHostManager struct {
}

func newHostManager(wgInterface WGIface) (hostManager, error) {
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
