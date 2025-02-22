package dns

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

var (
	userenv = syscall.NewLazyDLL("userenv.dll")

	// https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-refreshpolicyex
	refreshPolicyExFn = userenv.NewProc("RefreshPolicyEx")
)

const (
	dnsPolicyConfigMatchPath    = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\NetBird-Match`
	gpoDnsPolicyRoot            = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`
	gpoDnsPolicyConfigMatchPath = gpoDnsPolicyRoot + `\DnsPolicyConfig\NetBird-Match`

	dnsPolicyConfigVersionKey           = "Version"
	dnsPolicyConfigVersionValue         = 2
	dnsPolicyConfigNameKey              = "Name"
	dnsPolicyConfigGenericDNSServersKey = "GenericDNSServers"
	dnsPolicyConfigConfigOptionsKey     = "ConfigOptions"
	dnsPolicyConfigConfigOptionsValue   = 0x8

	interfaceConfigPath          = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
	interfaceConfigNameServerKey = "NameServer"
	interfaceConfigSearchListKey = "SearchList"

	// RP_FORCE: Reapply all policies even if no policy change was detected
	rpForce = 0x1
)

type registryConfigurator struct {
	guid       string
	routingAll bool
	gpo        bool
}

func newHostManager(wgInterface WGIface) (*registryConfigurator, error) {
	guid, err := wgInterface.GetInterfaceGUIDString()
	if err != nil {
		return nil, err
	}

	var useGPO bool
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, gpoDnsPolicyRoot, registry.QUERY_VALUE)
	if err != nil {
		log.Debugf("failed to open GPO DNS policy root: %v", err)
	} else {
		closer(k)
		useGPO = true
		log.Infof("detected GPO DNS policy configuration, using policy store")
	}

	return &registryConfigurator{
		guid: guid,
		gpo:  useGPO,
	}, nil
}

func (r *registryConfigurator) supportCustomPort() bool {
	return false
}

func (r *registryConfigurator) applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error {
	if config.RouteAll {
		if err := r.addDNSSetupForAll(config.ServerIP); err != nil {
			return fmt.Errorf("add dns setup: %w", err)
		}
	} else if r.routingAll {
		if err := r.deleteInterfaceRegistryKeyProperty(interfaceConfigNameServerKey); err != nil {
			return fmt.Errorf("delete interface registry key property: %w", err)
		}
		r.routingAll = false
		log.Infof("removed %s as main DNS forwarder for this peer", config.ServerIP)
	}

	if err := stateManager.UpdateState(&ShutdownState{Guid: r.guid, GPO: r.gpo}); err != nil {
		log.Errorf("failed to update shutdown state: %s", err)
	}

	var searchDomains, matchDomains []string
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
		if err := r.addDNSMatchPolicy(matchDomains, config.ServerIP); err != nil {
			return fmt.Errorf("add dns match policy: %w", err)
		}
	} else {
		if err := r.removeDNSMatchPolicies(); err != nil {
			return fmt.Errorf("remove dns match policies: %w", err)
		}
	}

	if err := r.updateSearchDomains(searchDomains); err != nil {
		return fmt.Errorf("update search domains: %w", err)
	}

	return nil
}

func (r *registryConfigurator) addDNSSetupForAll(ip string) error {
	if err := r.setInterfaceRegistryKeyStringValue(interfaceConfigNameServerKey, ip); err != nil {
		return fmt.Errorf("adding dns setup for all failed: %w", err)
	}
	r.routingAll = true
	log.Infof("configured %s:53 as main DNS forwarder for this peer", ip)
	return nil
}

func (r *registryConfigurator) addDNSMatchPolicy(domains []string, ip string) error {
	// if the gpo key is present, we need to put our DNS settings there, otherwise our config might be ignored
	// see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnrpt/8cc31cb9-20cb-4140-9e85-3e08703b4745
	if r.gpo {
		if err := r.configureDNSPolicy(gpoDnsPolicyConfigMatchPath, domains, ip); err != nil {
			return fmt.Errorf("configure GPO DNS policy: %w", err)
		}

		if err := r.configureDNSPolicy(dnsPolicyConfigMatchPath, domains, ip); err != nil {
			return fmt.Errorf("configure local DNS policy: %w", err)
		}

		if err := refreshGroupPolicy(); err != nil {
			log.Warnf("failed to refresh group policy: %v", err)
		}
	} else {
		if err := r.configureDNSPolicy(dnsPolicyConfigMatchPath, domains, ip); err != nil {
			return fmt.Errorf("configure local DNS policy: %w", err)
		}
	}

	log.Infof("added %d match domains. Domain list: %s", len(domains), domains)
	return nil
}

// configureDNSPolicy handles the actual configuration of a DNS policy at the specified path
func (r *registryConfigurator) configureDNSPolicy(policyPath string, domains []string, ip string) error {
	if err := removeRegistryKeyFromDNSPolicyConfig(policyPath); err != nil {
		return fmt.Errorf("remove existing dns policy: %w", err)
	}

	regKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, policyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("create registry key HKEY_LOCAL_MACHINE\\%s: %w", policyPath, err)
	}
	defer closer(regKey)

	if err := regKey.SetDWordValue(dnsPolicyConfigVersionKey, dnsPolicyConfigVersionValue); err != nil {
		return fmt.Errorf("set %s: %w", dnsPolicyConfigVersionKey, err)
	}

	if err := regKey.SetStringsValue(dnsPolicyConfigNameKey, domains); err != nil {
		return fmt.Errorf("set %s: %w", dnsPolicyConfigNameKey, err)
	}

	if err := regKey.SetStringValue(dnsPolicyConfigGenericDNSServersKey, ip); err != nil {
		return fmt.Errorf("set %s: %w", dnsPolicyConfigGenericDNSServersKey, err)
	}

	if err := regKey.SetDWordValue(dnsPolicyConfigConfigOptionsKey, dnsPolicyConfigConfigOptionsValue); err != nil {
		return fmt.Errorf("set %s: %w", dnsPolicyConfigConfigOptionsKey, err)
	}

	return nil
}

func (r *registryConfigurator) string() string {
	return "registry"
}

func (r *registryConfigurator) updateSearchDomains(domains []string) error {
	if err := r.setInterfaceRegistryKeyStringValue(interfaceConfigSearchListKey, strings.Join(domains, ",")); err != nil {
		return fmt.Errorf("update search domains: %w", err)
	}
	log.Infof("updated search domains: %s", domains)
	return nil
}

func (r *registryConfigurator) setInterfaceRegistryKeyStringValue(key, value string) error {
	regKey, err := r.getInterfaceRegistryKey()
	if err != nil {
		return fmt.Errorf("get interface registry key: %w", err)
	}
	defer closer(regKey)

	if err := regKey.SetStringValue(key, value); err != nil {
		return fmt.Errorf("set key %s=%s: %w", key, value, err)
	}
	return nil
}

func (r *registryConfigurator) deleteInterfaceRegistryKeyProperty(propertyKey string) error {
	regKey, err := r.getInterfaceRegistryKey()
	if err != nil {
		return fmt.Errorf("get interface registry key: %w", err)
	}
	defer closer(regKey)

	if err := regKey.DeleteValue(propertyKey); err != nil {
		return fmt.Errorf("delete registry key %s: %w", propertyKey, err)
	}
	return nil
}

func (r *registryConfigurator) getInterfaceRegistryKey() (registry.Key, error) {
	regKeyPath := interfaceConfigPath + "\\" + r.guid
	regKey, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return regKey, fmt.Errorf("open HKEY_LOCAL_MACHINE\\%s: %w", regKeyPath, err)
	}
	return regKey, nil
}

func (r *registryConfigurator) restoreHostDNS() error {
	if err := r.removeDNSMatchPolicies(); err != nil {
		log.Errorf("remove dns match policies: %s", err)
	}

	if err := r.deleteInterfaceRegistryKeyProperty(interfaceConfigSearchListKey); err != nil {
		return fmt.Errorf("remove interface registry key: %w", err)
	}

	return nil
}

func (r *registryConfigurator) removeDNSMatchPolicies() error {
	var merr *multierror.Error
	if err := removeRegistryKeyFromDNSPolicyConfig(dnsPolicyConfigMatchPath); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove local registry key: %w", err))
	}

	if err := removeRegistryKeyFromDNSPolicyConfig(gpoDnsPolicyConfigMatchPath); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove GPO registry key: %w", err))
	}

	if err := refreshGroupPolicy(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("refresh group policy: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *registryConfigurator) restoreUncleanShutdownDNS() error {
	return r.restoreHostDNS()
}

func removeRegistryKeyFromDNSPolicyConfig(regKeyPath string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyPath, registry.QUERY_VALUE)
	if err != nil {
		log.Debugf("failed to open HKEY_LOCAL_MACHINE\\%s: %v", regKeyPath, err)
		return nil
	}

	closer(k)
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, regKeyPath); err != nil {
		return fmt.Errorf("delete HKEY_LOCAL_MACHINE\\%s: %w", regKeyPath, err)
	}

	return nil
}

func refreshGroupPolicy() error {
	// refreshPolicyExFn.Call() panics if the func is not found
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Recovered from panic: %v", r)
		}
	}()

	ret, _, err := refreshPolicyExFn.Call(
		// bMachine = TRUE (computer policy)
		uintptr(1),
		// dwOptions = RP_FORCE
		uintptr(rpForce),
	)

	if ret == 0 {
		if err != nil && !errors.Is(err, syscall.Errno(0)) {
			return fmt.Errorf("RefreshPolicyEx failed: %w", err)
		}
		return fmt.Errorf("RefreshPolicyEx failed")
	}

	return nil
}

func closer(closer io.Closer) {
	if err := closer.Close(); err != nil {
		log.Errorf("failed to close: %s", err)
	}
}
