package dns

import (
	"fmt"
	"io"
	"net/netip"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
)

const (
	dnsPolicyConfigMatchPath            = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\NetBird-Match`
	dnsPolicyConfigVersionKey           = "Version"
	dnsPolicyConfigVersionValue         = 2
	dnsPolicyConfigNameKey              = "Name"
	dnsPolicyConfigGenericDNSServersKey = "GenericDNSServers"
	dnsPolicyConfigConfigOptionsKey     = "ConfigOptions"
	dnsPolicyConfigConfigOptionsValue   = 0x8
)

const (
	interfaceConfigPath          = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
	interfaceConfigNameServerKey = "NameServer"
	interfaceConfigSearchListKey = "SearchList"
)

type registryConfigurator struct {
	guid       string
	routingAll bool
}

func newHostManager(wgInterface WGIface) (hostManager, error) {
	guid, err := wgInterface.GetInterfaceGUIDString()
	if err != nil {
		return nil, err
	}
	return newHostManagerWithGuid(guid)
}

func newHostManagerWithGuid(guid string) (hostManager, error) {
	return &registryConfigurator{
		guid: guid,
	}, nil
}

func (r *registryConfigurator) supportCustomPort() bool {
	return false
}

func (r *registryConfigurator) applyDNSConfig(config HostDNSConfig) error {
	var err error
	if config.RouteAll {
		err = r.addDNSSetupForAll(config.ServerIP)
		if err != nil {
			return fmt.Errorf("add dns setup: %w", err)
		}
	} else if r.routingAll {
		err = r.deleteInterfaceRegistryKeyProperty(interfaceConfigNameServerKey)
		if err != nil {
			return fmt.Errorf("delete interface registry key property: %w", err)
		}
		r.routingAll = false
		log.Infof("removed %s as main DNS forwarder for this peer", config.ServerIP)
	}

	// create a file for unclean shutdown detection
	if err := createUncleanShutdownIndicator(r.guid); err != nil {
		log.Errorf("failed to create unclean shutdown file: %s", err)
	}

	var (
		searchDomains []string
		matchDomains  []string
	)

	for _, dConf := range config.Domains {
		if dConf.Disabled {
			continue
		}
		if !dConf.MatchOnly {
			searchDomains = append(searchDomains, dConf.Domain)
		}
		matchDomains = append(matchDomains, "."+dConf.Domain)
	}

	if len(matchDomains) != 0 {
		err = r.addDNSMatchPolicy(matchDomains, config.ServerIP)
	} else {
		err = removeRegistryKeyFromDNSPolicyConfig(dnsPolicyConfigMatchPath)
	}
	if err != nil {
		return fmt.Errorf("add dns match policy: %w", err)
	}

	err = r.updateSearchDomains(searchDomains)
	if err != nil {
		return fmt.Errorf("update search domains: %w", err)
	}

	return nil
}

func (r *registryConfigurator) addDNSSetupForAll(ip string) error {
	err := r.setInterfaceRegistryKeyStringValue(interfaceConfigNameServerKey, ip)
	if err != nil {
		return fmt.Errorf("adding dns setup for all failed with error: %w", err)
	}
	r.routingAll = true
	log.Infof("configured %s:53 as main DNS forwarder for this peer", ip)
	return nil
}

func (r *registryConfigurator) addDNSMatchPolicy(domains []string, ip string) error {
	_, err := registry.OpenKey(registry.LOCAL_MACHINE, dnsPolicyConfigMatchPath, registry.QUERY_VALUE)
	if err == nil {
		err = registry.DeleteKey(registry.LOCAL_MACHINE, dnsPolicyConfigMatchPath)
		if err != nil {
			return fmt.Errorf("unable to remove existing key from registry, key: HKEY_LOCAL_MACHINE\\%s, error: %w", dnsPolicyConfigMatchPath, err)
		}
	}

	regKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, dnsPolicyConfigMatchPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("unable to create registry key, key: HKEY_LOCAL_MACHINE\\%s, error: %w", dnsPolicyConfigMatchPath, err)
	}

	err = regKey.SetDWordValue(dnsPolicyConfigVersionKey, dnsPolicyConfigVersionValue)
	if err != nil {
		return fmt.Errorf("unable to set registry value for %s, error: %w", dnsPolicyConfigVersionKey, err)
	}

	err = regKey.SetStringsValue(dnsPolicyConfigNameKey, domains)
	if err != nil {
		return fmt.Errorf("unable to set registry value for %s, error: %w", dnsPolicyConfigNameKey, err)
	}

	err = regKey.SetStringValue(dnsPolicyConfigGenericDNSServersKey, ip)
	if err != nil {
		return fmt.Errorf("unable to set registry value for %s, error: %w", dnsPolicyConfigGenericDNSServersKey, err)
	}

	err = regKey.SetDWordValue(dnsPolicyConfigConfigOptionsKey, dnsPolicyConfigConfigOptionsValue)
	if err != nil {
		return fmt.Errorf("unable to set registry value for %s, error: %w", dnsPolicyConfigConfigOptionsKey, err)
	}

	log.Infof("added %d match domains to the state. Domain list: %s", len(domains), domains)

	return nil
}

func (r *registryConfigurator) restoreHostDNS() error {
	if err := removeRegistryKeyFromDNSPolicyConfig(dnsPolicyConfigMatchPath); err != nil {
		log.Errorf("remove registry key from dns policy config: %s", err)
	}

	if err := r.deleteInterfaceRegistryKeyProperty(interfaceConfigSearchListKey); err != nil {
		return fmt.Errorf("remove interface registry key: %w", err)
	}

	if err := removeUncleanShutdownIndicator(); err != nil {
		log.Errorf("failed to remove unclean shutdown file: %s", err)
	}

	return nil
}

func (r *registryConfigurator) updateSearchDomains(domains []string) error {
	err := r.setInterfaceRegistryKeyStringValue(interfaceConfigSearchListKey, strings.Join(domains, ","))
	if err != nil {
		return fmt.Errorf("adding search domain failed with error: %w", err)
	}

	log.Infof("updated the search domains in the registry with %d domains. Domain list: %s", len(domains), domains)

	return nil
}

func (r *registryConfigurator) setInterfaceRegistryKeyStringValue(key, value string) error {
	regKey, err := r.getInterfaceRegistryKey()
	if err != nil {
		return fmt.Errorf("get interface registry key: %w", err)
	}
	defer closer(regKey)

	err = regKey.SetStringValue(key, value)
	if err != nil {
		return fmt.Errorf("applying key %s with value \"%s\" for interface failed with error: %w", key, value, err)
	}

	return nil
}

func (r *registryConfigurator) deleteInterfaceRegistryKeyProperty(propertyKey string) error {
	regKey, err := r.getInterfaceRegistryKey()
	if err != nil {
		return fmt.Errorf("get interface registry key: %w", err)
	}
	defer closer(regKey)

	err = regKey.DeleteValue(propertyKey)
	if err != nil {
		return fmt.Errorf("deleting registry key %s for interface failed with error: %w", propertyKey, err)
	}

	return nil
}

func (r *registryConfigurator) getInterfaceRegistryKey() (registry.Key, error) {
	var regKey registry.Key

	regKeyPath := interfaceConfigPath + "\\" + r.guid

	regKey, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return regKey, fmt.Errorf("unable to open the interface registry key, key: HKEY_LOCAL_MACHINE\\%s, error: %w", regKeyPath, err)
	}

	return regKey, nil
}

func (r *registryConfigurator) restoreUncleanShutdownDNS(*netip.Addr) error {
	if err := r.restoreHostDNS(); err != nil {
		return fmt.Errorf("restoring dns via registry: %w", err)
	}
	return nil
}

func removeRegistryKeyFromDNSPolicyConfig(regKeyPath string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyPath, registry.QUERY_VALUE)
	if err == nil {
		defer closer(k)
		err = registry.DeleteKey(registry.LOCAL_MACHINE, regKeyPath)
		if err != nil {
			return fmt.Errorf("unable to remove existing key from registry, key: HKEY_LOCAL_MACHINE\\%s, error: %w", regKeyPath, err)
		}
	}
	return nil
}

func closer(closer io.Closer) {
	if err := closer.Close(); err != nil {
		log.Errorf("failed to close: %s", err)
	}
}
