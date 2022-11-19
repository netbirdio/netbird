package dns

import (
	"fmt"
	nbdns "github.com/netbirdio/netbird/dns"
	"strings"
)

type hostManager interface {
	applyDNSConfig(config hostDNSConfig) error
	restoreHostDNS() error
}

type hostDNSConfig struct {
	domains    []domainConfig
	routeAll   bool
	serverIP   string
	serverPort int
}

type domainConfig struct {
	domain    string
	matchOnly bool
}

type mockHostConfigurator struct {
	applyDNSConfigFunc func(config hostDNSConfig) error
	restoreHostDNSFunc func() error
}

func (m *mockHostConfigurator) applyDNSConfig(config hostDNSConfig) error {
	if m.applyDNSConfigFunc != nil {
		return m.applyDNSConfigFunc(config)
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
		applyDNSConfigFunc: func(config hostDNSConfig) error { return nil },
		restoreHostDNSFunc: func() error { return nil },
	}
}

func isRootZoneDomain(domain string) bool {
	return domain == nbdns.RootZone || domain == ""
}

func dnsConfigToHostDNSConfig(dnsConfig nbdns.Config, ip string, port int) hostDNSConfig {
	config := hostDNSConfig{
		routeAll:   false,
		serverIP:   ip,
		serverPort: port,
	}
	for _, nsConfig := range dnsConfig.NameServerGroups {
		if nsConfig.Primary {
			config.routeAll = true
		}

		for _, domain := range nsConfig.Domains {
			config.domains = append(config.domains, domainConfig{
				domain:    strings.TrimSuffix(domain, "."),
				matchOnly: true,
			})
		}
	}

	for _, customZone := range dnsConfig.CustomZones {
		config.domains = append(config.domains, domainConfig{
			domain:    strings.TrimSuffix(customZone.Domain, "."),
			matchOnly: false,
		})
	}

	return config
}
