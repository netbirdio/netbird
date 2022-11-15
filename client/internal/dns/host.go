package dns

import (
	"fmt"
	nbdns "github.com/netbirdio/netbird/dns"
)

type hostManager interface {
	applyDNSSettings(domains []string, ip string, port int) error
	addSearchDomain(domain string, ip string, port int) error
	removeDomainSettings(domains []string) error
	removeDNSSettings() error
}

func isRootZoneDomain(domain string) bool {
	return domain == nbdns.RootZone || domain == ""
}

type mockHostConfigurator struct {
	applyDNSSettingsFunc     func(domains []string, ip string, port int) error
	addSearchDomainFunc      func(domain string, ip string, port int) error
	removeDomainSettingsFunc func(domains []string) error
	removeDNSSettingsFunc    func() error
}

func (m *mockHostConfigurator) applyDNSSettings(domains []string, ip string, port int) error {
	if m.applyDNSSettingsFunc != nil {
		return m.applyDNSSettingsFunc(domains, ip, port)
	}
	return fmt.Errorf("method applyDNSSettings is not implemented")
}

func (m *mockHostConfigurator) addSearchDomain(domain string, ip string, port int) error {
	if m.addSearchDomainFunc != nil {
		return m.addSearchDomainFunc(domain, ip, port)
	}
	return fmt.Errorf("method addSearchDomain is not implemented")
}

func (m *mockHostConfigurator) removeDomainSettings(domains []string) error {
	if m.removeDomainSettingsFunc != nil {
		return m.removeDomainSettingsFunc(domains)
	}
	return fmt.Errorf("method removeDomainSettings is not implemented")
}

func (m *mockHostConfigurator) removeDNSSettings() error {
	if m.removeDNSSettingsFunc != nil {
		return m.removeDNSSettingsFunc()
	}
	return fmt.Errorf("method removeDNSSettings is not implemented")
}

func newNoopHostMocker() hostManager {
	return &mockHostConfigurator{
		applyDNSSettingsFunc:     func(domains []string, ip string, port int) error { return nil },
		addSearchDomainFunc:      func(domain string, ip string, port int) error { return nil },
		removeDomainSettingsFunc: func(domains []string) error { return nil },
		removeDNSSettingsFunc:    func() error { return nil },
	}
}
