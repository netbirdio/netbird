package dns

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/domain"
)

var ErrRouteAllWithoutNameserverGroup = fmt.Errorf("unable to configure DNS for this peer using file manager without a nameserver group with all domains configured")

const (
	ipv4ReverseZone = ".in-addr.arpa."
	ipv6ReverseZone = ".ip6.arpa."
)

type hostManager interface {
	applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error
	restoreHostDNS() error
	supportCustomPort() bool
	string() string
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
	Disabled  bool          `json:"disabled"`
	Domain    domain.Domain `json:"domain"`
	MatchOnly bool          `json:"matchOnly"`
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
		if nsConfig.Primary {
			config.RouteAll = true
		}

		for _, d := range nsConfig.Domains {
			d := strings.ToLower(dns.Fqdn(d.PunycodeString()))
			config.Domains = append(config.Domains, DomainConfig{
				Domain:    domain.Domain(d),
				MatchOnly: !nsConfig.SearchDomainsEnabled,
			})
		}
	}

	for _, customZone := range dnsConfig.CustomZones {
		d := strings.ToLower(dns.Fqdn(customZone.Domain))
		matchOnly := strings.HasSuffix(d, ipv4ReverseZone) || strings.HasSuffix(d, ipv6ReverseZone)
		config.Domains = append(config.Domains, DomainConfig{
			Domain:    domain.Domain(d),
			MatchOnly: matchOnly,
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
