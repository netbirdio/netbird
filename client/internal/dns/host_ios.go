package dns

import (
	"encoding/json"
	"fmt"
)

type iosHostManager struct {
	dnsManager IosDnsManager
	config     HostDNSConfig
}

func newHostManager(dnsManager IosDnsManager) (hostManager, error) {
	return &iosHostManager{
		dnsManager: dnsManager,
	}, nil
}

func (a iosHostManager) applyDNSConfig(config HostDNSConfig) error {
	jsonData, err := json.Marshal(config)
	if err != nil {
		return err
	}
	a.dnsManager.ApplyDns(fmt.Sprint(jsonData))
	return nil
}

func (a iosHostManager) restoreHostDNS() error {
	return nil
}

func (a iosHostManager) supportCustomPort() bool {
	return false
}
