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

func (a androidHostManager) restoreUncleanShutdownBackup() error {
	return nil
}

func CheckUncleanShutdown(_ string) error {
	return nil
}
