package dns

import (
	"fmt"
	nbdns "github.com/netbirdio/netbird/dns"
)

type hostManager interface {
	applyDNSConfig() error
	restoreHostDNS() error
}

func isRootZoneDomain(domain string) bool {
	return domain == nbdns.RootZone || domain == ""
}

type mockHostConfigurator struct {
	applyDNSConfigFunc func() error
	restoreHostDNSFunc func() error
}

func (m *mockHostConfigurator) applyDNSConfig() error {
	if m.applyDNSConfigFunc != nil {
		return m.applyDNSConfigFunc()
	}
	return fmt.Errorf("method applyDNSSettings is not implemented")
}

func (m *mockHostConfigurator) restoreHostDNS() error {
	if m.restoreHostDNSFunc != nil {
		return m.restoreHostDNSFunc()
	}
	return fmt.Errorf("method restoreHostDNS is not implemented")
}

func newNoopHostMocker() hostManager {
	return &mockHostConfigurator{
		applyDNSConfigFunc: func() error { return nil },
		restoreHostDNSFunc: func() error { return nil },
	}
}
