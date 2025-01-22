package dns

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

type iosHostManager struct {
	dnsManager IosDnsManager
	config     HostDNSConfig
}

func newHostManager(dnsManager IosDnsManager) (*iosHostManager, error) {
	return &iosHostManager{
		dnsManager: dnsManager,
	}, nil
}

func (a iosHostManager) applyDNSConfig(config HostDNSConfig, _ *statemanager.Manager) error {
	jsonData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	jsonString := string(jsonData)
	log.Debugf("Applying DNS settings: %s", jsonString)
	a.dnsManager.ApplyDns(jsonString)
	return nil
}

func (a iosHostManager) restoreHostDNS() error {
	return nil
}

func (a iosHostManager) supportCustomPort() bool {
	return false
}

func (a iosHostManager) string() string {
	return "none"
}
