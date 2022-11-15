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
	dnsPolicyConfigPathFormat           = "SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig\\NetBird-%s"
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
	luid               winipcfg.LUID
	createdKeys        map[string]struct{}
	addedSearchDomains map[string]struct{}
}

func newHostManager(wgInterface *iface.WGIface) hostManager {
	windowsDevice := wgInterface.Interface.(*driver.Adapter)
	luid := windowsDevice.LUID()
	return &registryConfigurator{
		luid:               luid,
		createdKeys:        make(map[string]struct{}),
		addedSearchDomains: make(map[string]struct{}),
	}
}

func (r *registryConfigurator) applyDNSSettings(domains []string, ip string, _ int) error {
	var err error
	for _, domain := range domains {
		if isRootZoneDomain(domain) {
			err = r.addDNSSetupForAll(ip)
			if err != nil {
				log.Error(err)
			}
			continue
		}
		err = r.addDNSStateForDomain(domain, ip)
		if err != nil {
			log.Error(err)
		}
	}
	return nil
}

func (r *registryConfigurator) addDNSSetupForAll(ip string) error {
	err := r.setInterfaceRegistryKeyStringValue(interfaceConfigNameServerKey, ip)
	if err != nil {
		return fmt.Errorf("adding dns setup for all failed with error: %s", err)
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

func (r *registryConfigurator) addDNSStateForDomain(domain, ip string) error {
	regKeyPath := getRegistryKeyPath(dnsPolicyConfigPathFormat, domain)

	_, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyPath, registry.QUERY_VALUE)
	if err == nil {
		err = registry.DeleteKey(registry.LOCAL_MACHINE, regKeyPath)
		if err != nil {
			return fmt.Errorf("unable to remove existing key from registry, key: HKEY_LOCAL_MACHINE\\%s, error: %s", regKeyPath, err)
		}
	}
	regKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("unable to create registry key, key: HKEY_LOCAL_MACHINE\\%s, error: %s", regKeyPath, err)
	}

	err = regKey.SetDWordValue(dnsPolicyConfigVersionKey, dnsPolicyConfigVersionValue)
	if err != nil {
		return fmt.Errorf("unable to set registry value for %s, error: %s", dnsPolicyConfigVersionKey, err)
	}

	prefixDotedDomain := "." + domain

	err = regKey.SetStringsValue(dnsPolicyConfigNameKey, []string{prefixDotedDomain})
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

	r.createdKeys[regKeyPath] = struct{}{}

	return nil
}

func (r *registryConfigurator) addSearchDomain(domain string, ip string, port int) error {
	value, err := getLocalMachineRegistryKeyStringValue(tcpipParametersPath, interfaceConfigSearchListKey)
	if err != nil {
		return fmt.Errorf("unable to get current search domains failed with error: %s", err)
	}

	valueList := strings.Split(value, ",")
	for _, existingDomain := range valueList {
		if existingDomain == domain {
			log.Debugf("not adding domain %s to the search list. Already exist", domain)
			return nil
		}
	}

	valueList = append(valueList, domain)

	err = setLocalMachineRegistryKeyStringValue(tcpipParametersPath, interfaceConfigSearchListKey, strings.Join(valueList, ","))
	if err != nil {
		return fmt.Errorf("adding search domain failed with error: %s", err)
	}

	r.addedSearchDomains[domain] = struct{}{}

	return nil
}

func (r *registryConfigurator) removeDomainSettings(domains []string) error {
	var err error
	for _, domain := range domains {
		if isRootZoneDomain(domain) {
			err = r.deleteInterfaceRegistryKey(interfaceConfigNameServerKey)
			if err != nil {
				log.Error(err)
			}
			continue
		}

		regKeyPath := getRegistryKeyPath(dnsPolicyConfigPathFormat, domain)
		err = removeRegistryKeyFromDNSPolicyConfig(regKeyPath)
		if err != nil {
			log.Error(err)
			continue
		}

		delete(r.createdKeys, regKeyPath)
	}
	return nil
}

func (r *registryConfigurator) removeDNSSettings() error {
	for key := range r.createdKeys {
		err := removeRegistryKeyFromDNSPolicyConfig(key)
		if err != nil {
			log.Error(err)
		}
	}

	value, err := getLocalMachineRegistryKeyStringValue(tcpipParametersPath, interfaceConfigSearchListKey)
	if err != nil {
		return fmt.Errorf("unable to get current search domains failed with error: %s", err)
	}

	existingValueList := strings.Split(value, ",")
	var newValueList []string
	for _, existingDomain := range existingValueList {
		_, found := r.addedSearchDomains[existingDomain]
		if !found {
			newValueList = append(newValueList, existingDomain)
		}
	}

	return setLocalMachineRegistryKeyStringValue(tcpipParametersPath, interfaceConfigSearchListKey, strings.Join(newValueList, ","))
}

func getRegistryKeyPath(format, input string) string {
	return fmt.Sprintf(format, input)
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

func (r *registryConfigurator) deleteInterfaceRegistryKey(key string) error {
	regKey, err := r.getInterfaceRegistryKey()
	if err != nil {
		return err
	}
	defer regKey.Close()

	err = regKey.DeleteValue(key)
	if err != nil {
		return fmt.Errorf("deleting key %s for interface failed with error: %s", key, err)
	}

	return nil
}
