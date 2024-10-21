package dns

import (
	"fmt"
	"net/netip"
	"strings"

	nbdns "github.com/netbirdio/netbird/dns"
)

type hostManager interface {
	applyDNSConfig(config HostDNSConfig) error
	restoreHostDNS() error
	supportCustomPort() bool
	restoreUncleanShutdownDNS(storedDNSAddress *netip.Addr) error
}

type SystemDNSSettings struct {
	Domains    []string
	ServerIP   string
	ServerPort int
}

type HostDNSConfig struct {
	Domains    []DomainConfig `json:"domains"`
	RouteAll   bool           `json:"routeAll"`
	ServerIP   string         `json:"serverIP"`
	ServerPort int            `json:"serverPort"`
}

type DomainConfig struct {
	Disabled  bool   `json:"disabled"`
	Domain    string `json:"domain"`
	MatchOnly bool   `json:"matchOnly"`
}

type mockHostConfigurator struct {
	applyDNSConfigFunc            func(config HostDNSConfig) error
	restoreHostDNSFunc            func() error
	supportCustomPortFunc         func() bool
	restoreUncleanShutdownDNSFunc func(*netip.Addr) error
}

func (m *mockHostConfigurator) applyDNSConfig(config HostDNSConfig) error {
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

func (m *mockHostConfigurator) supportCustomPort() bool {
	if m.supportCustomPortFunc != nil {
		return m.supportCustomPortFunc()
	}
	return false
}

func (m *mockHostConfigurator) restoreUncleanShutdownDNS(storedDNSAddress *netip.Addr) error {
	if m.restoreUncleanShutdownDNSFunc != nil {
		return m.restoreUncleanShutdownDNSFunc(storedDNSAddress)
	}
	return fmt.Errorf("method restoreUncleanShutdownDNS is not implemented")
}

func newNoopHostMocker() hostManager {
	return &mockHostConfigurator{
		applyDNSConfigFunc:            func(config HostDNSConfig) error { return nil },
		restoreHostDNSFunc:            func() error { return nil },
		supportCustomPortFunc:         func() bool { return true },
		restoreUncleanShutdownDNSFunc: func(*netip.Addr) error { return nil },
	}
}

func dnsConfigToHostDNSConfig(dnsConfig nbdns.Config, ip string, port int) HostDNSConfig {
	config := HostDNSConfig{
		RouteAll:   false,
		ServerIP:   ip,
		ServerPort: port,
	}
	for _, nsConfig := range dnsConfig.NameServerGroups {
		if len(nsConfig.NameServers) == 0 {
			continue
		}
		if nsConfig.Primary && nsConfig.Enabled {
			config.RouteAll = true
		}

		for _, domain := range nsConfig.Domains {
			config.Domains = append(config.Domains, DomainConfig{
				Domain:    strings.TrimSuffix(domain, "."),
				Disabled:  !nsConfig.Enabled,
				MatchOnly: !nsConfig.SearchDomainsEnabled,
			})
		}
	}

	for _, customZone := range dnsConfig.CustomZones {
		config.Domains = append(config.Domains, DomainConfig{
			Domain:    strings.TrimSuffix(customZone.Domain, "."),
			MatchOnly: false,
		})
	}

	return config
}
