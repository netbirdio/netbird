package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

var (
	userenv = syscall.NewLazyDLL("userenv.dll")
	dnsapi  = syscall.NewLazyDLL("dnsapi.dll")

	// https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-refreshpolicyex
	refreshPolicyExFn = userenv.NewProc("RefreshPolicyEx")

	dnsFlushResolverCacheFn = dnsapi.NewProc("DnsFlushResolverCache")
)

const (
	dnsPolicyConfigMatchPath    = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\NetBird-Match`
	gpoDnsPolicyRoot            = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	gpoDnsPolicyConfigMatchPath = gpoDnsPolicyRoot + `\NetBird-Match`

	dnsPolicyConfigVersionKey           = "Version"
	dnsPolicyConfigVersionValue         = 2
	dnsPolicyConfigNameKey              = "Name"
	dnsPolicyConfigGenericDNSServersKey = "GenericDNSServers"
	dnsPolicyConfigConfigOptionsKey     = "ConfigOptions"
	dnsPolicyConfigConfigOptionsValue   = 0x8

	interfaceConfigPath          = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
	interfaceConfigNameServerKey = "NameServer"
	interfaceConfigSearchListKey = "SearchList"

	// Network interface DNS registration settings
	disableDynamicUpdateKey           = "DisableDynamicUpdate"
	registrationEnabledKey            = "RegistrationEnabled"
	maxNumberOfAddressesToRegisterKey = "MaxNumberOfAddressesToRegister"

	// NetBIOS/WINS settings
	netbtInterfacePath = `SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces`
	netbiosOptionsKey  = "NetbiosOptions"

	// NetBIOS option values: 0 = from DHCP, 1 = enabled, 2 = disabled
	netbiosFromDHCP = 0
	netbiosEnabled  = 1
	netbiosDisabled = 2

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

	configurator := &registryConfigurator{
		guid: guid,
		gpo:  useGPO,
	}

	if err := configurator.configureInterface(); err != nil {
		log.Errorf("failed to configure interface settings: %v", err)
	}

	return configurator, nil
}

func (r *registryConfigurator) supportCustomPort() bool {
	return false
}

func (r *registryConfigurator) configureInterface() error {
	var merr *multierror.Error

	if err := r.disableDNSRegistrationForInterface(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("disable DNS registration: %w", err))
	}

	if err := r.disableWINSForInterface(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("disable WINS: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *registryConfigurator) disableDNSRegistrationForInterface() error {
	regKey, err := r.getInterfaceRegistryKey()
	if err != nil {
		return fmt.Errorf("get interface registry key: %w", err)
	}
	defer closer(regKey)

	var merr *multierror.Error

	if err := regKey.SetDWordValue(disableDynamicUpdateKey, 1); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("set %s: %w", disableDynamicUpdateKey, err))
	}

	if err := regKey.SetDWordValue(registrationEnabledKey, 0); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("set %s: %w", registrationEnabledKey, err))
	}

	if err := regKey.SetDWordValue(maxNumberOfAddressesToRegisterKey, 0); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("set %s: %w", maxNumberOfAddressesToRegisterKey, err))
	}

	if merr == nil || len(merr.Errors) == 0 {
		log.Infof("disabled DNS registration for interface %s", r.guid)
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *registryConfigurator) disableWINSForInterface() error {
	netbtKeyPath := fmt.Sprintf(`%s\Tcpip_%s`, netbtInterfacePath, r.guid)

	regKey, err := registry.OpenKey(registry.LOCAL_MACHINE, netbtKeyPath, registry.SET_VALUE)
	if err != nil {
		regKey, _, err = registry.CreateKey(registry.LOCAL_MACHINE, netbtKeyPath, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf("create NetBT interface key %s: %w", netbtKeyPath, err)
		}
	}
	defer closer(regKey)

	// NetbiosOptions: 2 = disabled
	if err := regKey.SetDWordValue(netbiosOptionsKey, netbiosDisabled); err != nil {
		return fmt.Errorf("set %s: %w", netbiosOptionsKey, err)
	}

	log.Infof("disabled WINS/NetBIOS for interface %s", r.guid)
	return nil
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
			searchDomains = append(searchDomains, strings.TrimSuffix(dConf.Domain, "."))
		}
		matchDomains = append(matchDomains, "."+strings.TrimSuffix(dConf.Domain, "."))
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

	go r.flushDNSCache()

	return nil
}

func (r *registryConfigurator) addDNSSetupForAll(ip netip.Addr) error {
	if err := r.setInterfaceRegistryKeyStringValue(interfaceConfigNameServerKey, ip.String()); err != nil {
		return fmt.Errorf("adding dns setup for all failed: %w", err)
	}
	r.routingAll = true
	log.Infof("configured %s:53 as main DNS forwarder for this peer", ip)
	return nil
}

func (r *registryConfigurator) addDNSMatchPolicy(domains []string, ip netip.Addr) error {
	// if the gpo key is present, we need to put our DNS settings there, otherwise our config might be ignored
	// see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnrpt/8cc31cb9-20cb-4140-9e85-3e08703b4745
	if r.gpo {
		if err := r.configureDNSPolicy(gpoDnsPolicyConfigMatchPath, domains, ip); err != nil {
			return fmt.Errorf("configure GPO DNS policy: %w", err)
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
func (r *registryConfigurator) configureDNSPolicy(policyPath string, domains []string, ip netip.Addr) error {
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

	if err := regKey.SetStringValue(dnsPolicyConfigGenericDNSServersKey, ip.String()); err != nil {
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

func (r *registryConfigurator) registerDNS() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// nolint:misspell
	cmd := exec.CommandContext(ctx, "ipconfig", "/registerdns")
	out, err := cmd.CombinedOutput()

	if err != nil {
		log.Errorf("failed to register DNS: %v, output: %s", err, out)
		return
	}

	log.Info("registered DNS names")
}

func (r *registryConfigurator) flushDNSCache() {
	r.registerDNS()

	// dnsFlushResolverCacheFn.Call() may panic if the func is not found
	defer func() {
		if rec := recover(); rec != nil {
			log.Errorf("Recovered from panic in flushDNSCache: %v", rec)
		}
	}()

	ret, _, err := dnsFlushResolverCacheFn.Call()
	if ret == 0 {
		if err != nil && !errors.Is(err, syscall.Errno(0)) {
			log.Errorf("DnsFlushResolverCache failed: %v", err)
			return
		}
		log.Errorf("DnsFlushResolverCache failed")
		return
	}

	log.Info("flushed DNS cache")
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

	go r.flushDNSCache()

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
