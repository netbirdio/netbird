package dns

import (
	"fmt"
	"github.com/netbirdio/netbird/iface"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"strings"
)

const (
	dnsPolicyConfigMatchPath            = "SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig\\NetBird-Match"
	dnsPolicyConfigVersionKey           = "Version"
	dnsPolicyConfigVersionValue         = 2
	dnsPolicyConfigNameKey              = "Name"
	dnsPolicyConfigGenericDNSServersKey = "GenericDNSServers"
	dnsPolicyConfigConfigOptionsKey     = "ConfigOptions"
	dnsPolicyConfigConfigOptionsValue   = 0x8
)

const (
	interfaceConfigPath          = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"
	interfaceConfigNameServerKey = "NameServer"
	interfaceConfigSearchListKey = "SearchList"
	tcpipParametersPath          = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
)

type registryConfigurator struct {
	luid                  winipcfg.LUID
	routingAll            bool
	existingSearchDomains []string
}

func newHostManager(wgInterface *iface.WGIface) hostManager {
	windowsDevice := wgInterface.Interface.(*driver.Adapter)
	luid := windowsDevice.LUID()
	return &registryConfigurator{
		luid: luid,
	}
}

func (r *registryConfigurator) applyDNSConfig(config hostDNSConfig) error {
	var err error
	if config.routeAll {
		err = r.addDNSSetupForAll(config.serverIP)
		if err != nil {
			return err
		}
	} else if r.routingAll {
		err = r.deleteInterfaceRegistryKeyProperty(interfaceConfigNameServerKey)
		if err != nil {
			return err
		}
		r.routingAll = false
		log.Infof("removed %s as main DNS forwarder for this peer", config.serverIP)
	}

	var (
		searchDomains []string
		matchDomains  []string
	)

	for _, dConf := range config.domains {
		if !dConf.matchOnly {
			searchDomains = append(searchDomains, dConf.domain)
		}
		matchDomains = append(matchDomains, "."+dConf.domain)
	}

	if len(matchDomains) != 0 {
		err = r.addDNSMatchPolicy(matchDomains, config.serverIP)
	} else {
		err = removeRegistryKeyFromDNSPolicyConfig(dnsPolicyConfigMatchPath)
	}
	if err != nil {
		return err
	}

	err = r.updateSearchDomains(searchDomains)
	if err != nil {
		return err
	}

	return nil
}

func (r *registryConfigurator) addDNSSetupForAll(ip string) error {
	err := r.setInterfaceRegistryKeyStringValue(interfaceConfigNameServerKey, ip)
	if err != nil {
		return fmt.Errorf("adding dns setup for all failed with error: %s", err)
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
			return fmt.Errorf("unable to remove existing key from registry, key: HKEY_LOCAL_MACHINE\\%s, error: %s", dnsPolicyConfigMatchPath, err)
		}
	}

	regKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, dnsPolicyConfigMatchPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("unable to create registry key, key: HKEY_LOCAL_MACHINE\\%s, error: %s", dnsPolicyConfigMatchPath, err)
	}

	err = regKey.SetDWordValue(dnsPolicyConfigVersionKey, dnsPolicyConfigVersionValue)
	if err != nil {
		return fmt.Errorf("unable to set registry value for %s, error: %s", dnsPolicyConfigVersionKey, err)
	}

	err = regKey.SetStringsValue(dnsPolicyConfigNameKey, domains)
	if err != nil {
		return fmt.Errorf("unable to set registry value for %s, error: %s", dnsPolicyConfigNameKey, err)
	}

	err = regKey.SetStringValue(dnsPolicyConfigGenericDNSServersKey, ip)
	if err != nil {
		return fmt.Errorf("unable to set registry value for %s, error: %s", dnsPolicyConfigGenericDNSServersKey, err)
	}

	err = regKey.SetDWordValue(dnsPolicyConfigConfigOptionsKey, dnsPolicyConfigConfigOptionsValue)
	if err != nil {
		return fmt.Errorf("unable to set registry value for %s, error: %s", dnsPolicyConfigConfigOptionsKey, err)
	}

	log.Infof("added %d match domains to the state. Domain list: %s", len(domains), domains)

	return nil
}

func (r *registryConfigurator) restoreHostDNS() error {
	err := removeRegistryKeyFromDNSPolicyConfig(dnsPolicyConfigMatchPath)
	if err != nil {
		log.Error(err)
	}

	return r.updateSearchDomains([]string{})
}

func (r *registryConfigurator) updateSearchDomains(domains []string) error {
	value, err := getLocalMachineRegistryKeyStringValue(tcpipParametersPath, interfaceConfigSearchListKey)
	if err != nil {
		return fmt.Errorf("unable to get current search domains failed with error: %s", err)
	}

	valueList := strings.Split(value, ",")
	setExisting := false
	if len(r.existingSearchDomains) == 0 {
		r.existingSearchDomains = valueList
		setExisting = true
	}

	if len(domains) == 0 && setExisting {
		log.Infof("added %d search domains to the registry. Domain list: %s", len(domains), domains)
		return nil
	}

	newList := append(r.existingSearchDomains, domains...)

	err = setLocalMachineRegistryKeyStringValue(tcpipParametersPath, interfaceConfigSearchListKey, strings.Join(newList, ","))
	if err != nil {
		return fmt.Errorf("adding search domain failed with error: %s", err)
	}

	log.Infof("updated the search domains in the registry with %d domains. Domain list: %s", len(domains), domains)

	return nil
}

func (r *registryConfigurator) setInterfaceRegistryKeyStringValue(key, value string) error {
	regKey, err := r.getInterfaceRegistryKey()
	if err != nil {
		return err
	}
	defer regKey.Close()

	err = regKey.SetStringValue(key, value)
	if err != nil {
		return fmt.Errorf("applying key %s with value \"%s\" for interface failed with error: %s", key, value, err)
	}

	return nil
}

func (r *registryConfigurator) deleteInterfaceRegistryKeyProperty(propertyKey string) error {
	regKey, err := r.getInterfaceRegistryKey()
	if err != nil {
		return err
	}
	defer regKey.Close()

	err = regKey.DeleteValue(propertyKey)
	if err != nil {
		return fmt.Errorf("deleting registry key %s for interface failed with error: %s", propertyKey, err)
	}

	return nil
}

func (r *registryConfigurator) getInterfaceRegistryKey() (registry.Key, error) {
	var regKey registry.Key

	guid, err := r.luid.GUID()
	if err != nil {
		return regKey, fmt.Errorf("unable to get interface GUID, error: %s", err)
	}

	regKeyPath := interfaceConfigPath + "\\" + guid.String()

	regKey, err = registry.OpenKey(registry.LOCAL_MACHINE, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return regKey, fmt.Errorf("unable to open the interface registry key, key: HKEY_LOCAL_MACHINE\\%s, error: %s", regKeyPath, err)
	}

	return regKey, nil
}

func removeRegistryKeyFromDNSPolicyConfig(regKeyPath string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyPath, registry.QUERY_VALUE)
	if err == nil {
		k.Close()
		err = registry.DeleteKey(registry.LOCAL_MACHINE, regKeyPath)
		if err != nil {
			return fmt.Errorf("unable to remove existing key from registry, key: HKEY_LOCAL_MACHINE\\%s, error: %s", regKeyPath, err)
		}
	}
	return nil
}

func getLocalMachineRegistryKeyStringValue(keyPath, key string) (string, error) {
	regKey, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("unable to open existing key from registry, key path: HKEY_LOCAL_MACHINE\\%s, error: %s", keyPath, err)
	}
	defer regKey.Close()

	val, _, err := regKey.GetStringValue(key)
	if err != nil {
		return "", fmt.Errorf("getting %s value for key path HKEY_LOCAL_MACHINE\\%s failed with error: %s", key, keyPath, err)
	}

	return val, nil
}

func setLocalMachineRegistryKeyStringValue(keyPath, key, value string) error {
	regKey, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("unable to open existing key from registry, key path: HKEY_LOCAL_MACHINE\\%s, error: %s", keyPath, err)
	}
	defer regKey.Close()

	err = regKey.SetStringValue(key, value)
	if err != nil {
		return fmt.Errorf("setting %s value %s for key path HKEY_LOCAL_MACHINE\\%s failed with error: %s", key, value, keyPath, err)
	}

	return nil
}
