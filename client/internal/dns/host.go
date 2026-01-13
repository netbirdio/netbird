package dns

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbdns "github.com/netbirdio/netbird/dns"
)

type hostManager interface {
	applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error
	restoreHostDNS() error
	supportCustomPort() bool
	string() string
}

type SystemDNSSettings struct {
	Domains    []string
	ServerIP   netip.Addr
	ServerPort int
}

type HostDNSConfig struct {
	Domains    []DomainConfig `json:"domains"`
	RouteAll   bool           `json:"routeAll"`
	ServerIP   netip.Addr     `json:"serverIP"`
	ServerPort int            `json:"serverPort"`
}

type DomainConfig struct {
	Disabled  bool   `json:"disabled"`
	Domain    string `json:"domain"`
	MatchOnly bool   `json:"matchOnly"`
}

type mockHostConfigurator struct {
	applyDNSConfigFunc            func(config HostDNSConfig, stateManager *statemanager.Manager) error
	restoreHostDNSFunc            func() error
	supportCustomPortFunc         func() bool
	restoreUncleanShutdownDNSFunc func(*netip.Addr) error
	stringFunc                    func() string
}

func (m *mockHostConfigurator) applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error {
	if m.applyDNSConfigFunc != nil {
		return m.applyDNSConfigFunc(config, stateManager)
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

func (m *mockHostConfigurator) string() string {
	if m.stringFunc != nil {
		return m.stringFunc()
	}
	return "mock"
}

func newNoopHostMocker() hostManager {
	return &mockHostConfigurator{
		applyDNSConfigFunc:            func(config HostDNSConfig, stateManager *statemanager.Manager) error { return nil },
		restoreHostDNSFunc:            func() error { return nil },
		supportCustomPortFunc:         func() bool { return true },
		restoreUncleanShutdownDNSFunc: func(*netip.Addr) error { return nil },
	}
}

func dnsConfigToHostDNSConfig(dnsConfig nbdns.Config, ip netip.Addr, port int) HostDNSConfig {
	config := HostDNSConfig{
		RouteAll:   false,
		ServerIP:   ip,
		ServerPort: port,
	}
	for _, nsConfig := range dnsConfig.NameServerGroups {
		if len(nsConfig.NameServers) == 0 {
			continue
		}
		if nsConfig.Primary {
			config.RouteAll = true
		}

		for _, domain := range nsConfig.Domains {
			config.Domains = append(config.Domains, DomainConfig{
				Domain:    strings.ToLower(dns.Fqdn(domain)),
				MatchOnly: !nsConfig.SearchDomainsEnabled,
			})
		}
	}

	for _, customZone := range dnsConfig.CustomZones {
		config.Domains = append(config.Domains, DomainConfig{
			Domain:    strings.ToLower(dns.Fqdn(customZone.Domain)),
			MatchOnly: customZone.SearchDomainDisabled,
		})
	}

	return config
}

type noopHostConfigurator struct{}

func (n noopHostConfigurator) applyDNSConfig(HostDNSConfig, *statemanager.Manager) error {
	return nil
}

func (n noopHostConfigurator) restoreHostDNS() error {
	return nil
}

func (n noopHostConfigurator) supportCustomPort() bool {
	return true
}

func (n noopHostConfigurator) string() string {
	return "noop"
}
