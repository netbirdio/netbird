package dns

type iosHostManager struct {
	dnsManager IosDnsManager
	config     HostDNSConfig
}

func newHostManager(wgInterface WGIface, dnsManager IosDnsManager) (hostManager, error) {
	return &iosHostManager{
		dnsManager: dnsManager,
	}, nil
}

func (a iosHostManager) applyDNSConfig(config HostDNSConfig) error {
	a.dnsManager.applyDns("bla")
	return nil
}

func (a iosHostManager) restoreHostDNS() error {
	return nil
}

func (a iosHostManager) supportCustomPort() bool {
	return false
}
