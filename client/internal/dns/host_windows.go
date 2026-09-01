package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/internal/winregistry"
)

var (
	userenv = syscall.NewLazyDLL("userenv.dll")
	dnsapi  = syscall.NewLazyDLL("dnsapi.dll")

	// https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-refreshpolicyex
	refreshPolicyExFn = userenv.NewProc("RefreshPolicyEx")

	dnsFlushResolverCacheFn = dnsapi.NewProc("DnsFlushResolverCache")
)

// Registry locations of the host DNS configuration this package programs,
// exported so a diagnostic reader reports the same locations that are written.
const (
	// NRPTKeyPrefix starts the name of every NRPT rule key this client creates:
	// the match rules, the catch-all, and the .local exemption. Cleanup
	// enumerates by this prefix, so a new kind of rule is removed by existing
	// code as long as its key starts here.
	NRPTKeyPrefix = "NetBird-"

	// nrptMatchKeyName names the match-domain rules. Older versions used
	// different layouts under the same name: a single unsuffixed key, then one
	// key per domain, now one key per batch of domains.
	nrptMatchKeyName = NRPTKeyPrefix + "Match"

	// DNSPolicyConfigRoot holds the NRPT rules of the local policy store.
	DNSPolicyConfigRoot = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`

	// GPODNSPolicyConfigRoot holds the NRPT rules of the group policy store,
	// which takes precedence over the local one when it is present.
	GPODNSPolicyConfigRoot = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`

	// InterfaceConfigPath and InterfaceConfigPathV6 hold the per-interface DNS
	// settings, keyed by interface GUID, in separate hives per address family.
	InterfaceConfigPath   = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
	InterfaceConfigPathV6 = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`
)

const (
	dnsPolicyConfigMatchPath    = DNSPolicyConfigRoot + `\` + nrptMatchKeyName
	gpoDnsPolicyConfigMatchPath = GPODNSPolicyConfigRoot + `\` + nrptMatchKeyName

	dnsPolicyConfigExemptLocalPath    = DNSPolicyConfigRoot + `\` + NRPTKeyPrefix + `ExemptLocal`
	gpoDnsPolicyConfigExemptLocalPath = GPODNSPolicyConfigRoot + `\` + NRPTKeyPrefix + `ExemptLocal`

	nrptCatchAllNamespace = "."
	// nrptLocalNamespace is reserved for multicast DNS by RFC 6762: a unicast
	// resolver must not answer for it. The catch-all rule would hand it to us
	// anyway, so it gets an exemption rule of its own.
	nrptLocalNamespace = ".local"

	// envLegacyDNSResolution restores the pre-catch-all behaviour: the adapter's
	// NameServer alone, leaving the OS free to query other adapters' resolvers in
	// parallel. An escape hatch for setups that depend on a resolver of theirs
	// still being reachable while connected, at the cost of the leak and of the
	// race the catch-all rule exists to close.
	envLegacyDNSResolution = "NB_USE_LEGACY_DNS_RESOLUTION"

	dnsPolicyConfigVersionKey           = "Version"
	dnsPolicyConfigVersionValue         = 2
	dnsPolicyConfigNameKey              = "Name"
	dnsPolicyConfigGenericDNSServersKey = "GenericDNSServers"
	dnsPolicyConfigConfigOptionsKey     = "ConfigOptions"
	dnsPolicyConfigConfigOptionsValue   = 0x8

	nrptMaxDomainsPerRule = 50

	interfaceConfigNameServerKey  = "NameServer"
	interfaceConfigDhcpNameSrvKey = "DhcpNameServer"
	interfaceConfigSearchListKey  = "SearchList"

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
	guid            string
	routingAll      bool
	gpo             bool
	origNameservers []netip.Addr
}

func newHostManager(wgInterface WGIface) (*registryConfigurator, error) {
	guid, err := wgInterface.GetInterfaceGUIDString()
	if err != nil {
		return nil, err
	}

	var useGPO bool
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, GPODNSPolicyConfigRoot, registry.QUERY_VALUE)
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

	origNameservers, err := configurator.captureOriginalNameservers()
	switch {
	case err != nil:
		log.Warnf("capture original nameservers from non-WG adapters: %v", err)
	case len(origNameservers) == 0:
		log.Warnf("no original nameservers captured from non-WG adapters; DNS fallback will be empty")
	default:
		log.Debugf("captured %d original nameservers from non-WG adapters: %v", len(origNameservers), origNameservers)
	}
	configurator.origNameservers = origNameservers

	if err := configurator.configureInterface(); err != nil {
		log.Errorf("failed to configure interface settings: %v", err)
	}

	return configurator, nil
}

// captureOriginalNameservers reads DNS addresses from every Tcpip(6) interface
// registry key except the WG adapter. v4 and v6 servers live in separate
// hives (Tcpip vs Tcpip6) keyed by the same interface GUID.
func (r *registryConfigurator) captureOriginalNameservers() ([]netip.Addr, error) {
	seen := make(map[netip.Addr]struct{})
	var out []netip.Addr
	var merr *multierror.Error
	for _, root := range []string{InterfaceConfigPath, InterfaceConfigPathV6} {
		addrs, err := r.captureFromTcpipRoot(root)
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf("%s: %w", root, err))
			continue
		}
		for _, addr := range addrs {
			if _, dup := seen[addr]; dup {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	return out, nberrors.FormatErrorOrNil(merr)
}

func (r *registryConfigurator) captureFromTcpipRoot(rootPath string) ([]netip.Addr, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, rootPath, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("open key: %w", err)
	}
	defer closer(root)

	guids, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("read subkeys: %w", err)
	}

	var out []netip.Addr
	for _, guid := range guids {
		if strings.EqualFold(guid, r.guid) {
			continue
		}
		out = append(out, readInterfaceNameservers(rootPath, guid)...)
	}
	return out, nil
}

func readInterfaceNameservers(rootPath, guid string) []netip.Addr {
	keyPath := rootPath + "\\" + guid
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer closer(k)

	// Static NameServer wins over DhcpNameServer for actual resolution.
	for _, name := range []string{interfaceConfigNameServerKey, interfaceConfigDhcpNameSrvKey} {
		raw, _, err := k.GetStringValue(name)
		if err != nil || raw == "" {
			continue
		}
		if out := parseRegistryNameservers(raw); len(out) > 0 {
			return out
		}
	}
	return nil
}

func parseRegistryNameservers(raw string) []netip.Addr {
	var out []netip.Addr
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		addr, err := netip.ParseAddr(strings.TrimSpace(field))
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsValid() || addr.IsUnspecified() {
			continue
		}
		// Drop unzoned link-local: not routable without a scope id. If
		// the user wrote "fe80::1%eth0" ParseAddr preserves the zone.
		if addr.IsLinkLocalUnicast() && addr.Zone() == "" {
			continue
		}
		out = append(out, addr)
	}
	return out
}

func (r *registryConfigurator) getOriginalNameservers() []netip.Addr {
	return slices.Clone(r.origNameservers)
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
	// Clear every rule the previous apply installed before installing any new
	// one, including a leftover catch-all: removal is unconditional so a rule
	// from an earlier run cannot survive into a config that no longer wants it.
	if err := r.removeDNSMatchPolicies(); err != nil {
		log.Errorf("cleanup old dns match policies: %s", err)
	}

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

	r.updateState(stateManager)

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

	// The root namespace is a match domain like any other: it just happens to
	// match every name. Without it the adapter's NameServer only adds one more
	// resolver to the set Windows queries in parallel, keeping whichever answer
	// comes back first — which leaks every query to the local network and lets a
	// resolver other than ours answer for a name we are authoritative for.
	if config.RouteAll {
		if parseBoolEnv(envLegacyDNSResolution) {
			log.Infof("%s is set, leaving DNS resolution shared with the other adapters' resolvers instead of forcing it through %s", envLegacyDNSResolution, config.ServerIP)
		} else {
			matchDomains = append(matchDomains, nrptCatchAllNamespace)
			log.Infof("routing every namespace through %s: DNS resolution is now exclusive to NetBird", config.ServerIP)

			if err := r.addDNSExemptLocalPolicy(); err != nil {
				return fmt.Errorf("add dns exempt policy: %w", err)
			}
		}
	}

	if len(matchDomains) != 0 {
		if err := r.addDNSMatchPolicy(matchDomains, config.ServerIP); err != nil {
			return fmt.Errorf("add dns match policy: %w", err)
		}
	}

	r.updateState(stateManager)

	if err := r.updateSearchDomains(searchDomains); err != nil {
		return fmt.Errorf("update search domains: %w", err)
	}

	go r.flushDNSCache()

	return nil
}

func (r *registryConfigurator) updateState(stateManager *statemanager.Manager) {
	if err := stateManager.UpdateState(&ShutdownState{
		Guid: r.guid,
		GPO:  r.gpo,
	}); err != nil {
		log.Errorf("failed to update shutdown state: %s", err)
	}
}

func (r *registryConfigurator) addDNSSetupForAll(ip netip.Addr) error {
	if err := r.setInterfaceRegistryKeyStringValue(interfaceConfigNameServerKey, ip.String()); err != nil {
		return fmt.Errorf("adding dns setup for all failed: %w", err)
	}
	r.routingAll = true
	log.Infof("configured %s:%d as main DNS forwarder for this peer", ip, DefaultPort)
	return nil
}

func (r *registryConfigurator) addDNSMatchPolicy(domains []string, ip netip.Addr) error {
	// if the gpo key is present, we need to put our DNS settings there, otherwise our config might be ignored
	// see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnrpt/8cc31cb9-20cb-4140-9e85-3e08703b4745

	// We need to batch domains into chunks and create one NRPT rule per batch.
	ruleIndex := 0
	for i := 0; i < len(domains); i += nrptMaxDomainsPerRule {
		end := i + nrptMaxDomainsPerRule
		if end > len(domains) {
			end = len(domains)
		}
		batchDomains := domains[i:end]

		localPath := fmt.Sprintf("%s-%d", dnsPolicyConfigMatchPath, ruleIndex)
		gpoPath := fmt.Sprintf("%s-%d", gpoDnsPolicyConfigMatchPath, ruleIndex)

		if err := r.configureDNSPolicy(localPath, batchDomains, ip); err != nil {
			return fmt.Errorf("configure DNS Local policy for rule %d: %w", ruleIndex, err)
		}

		if r.gpo {
			if err := r.configureDNSPolicy(gpoPath, batchDomains, ip); err != nil {
				return fmt.Errorf("configure gpo DNS policy for rule %d: %w", ruleIndex, err)
			}
		}

		log.Debugf("added NRPT rule %d with %d domains", ruleIndex, len(batchDomains))
		ruleIndex++
	}

	if r.gpo {
		if err := refreshGroupPolicy(); err != nil {
			log.Warnf("failed to refresh group policy: %v", err)
		}
	}

	log.Infof("added %d NRPT rules for %d domains", ruleIndex, len(domains))
	return nil
}

// addDNSExemptLocalPolicy carves .local back out of the catch-all. RFC 6762
// reserves it for multicast DNS, so forwarding those names to a unicast
// upstream answers NXDOMAIN for hosts that do exist - printers, NAS boxes, and
// anything else announcing itself on the link - and the answer is authoritative
// enough that Windows stops looking. A rule naming the namespace with no
// servers hands it back to the DNS client untouched. A more specific rule still
// wins, so a match domain under .local keeps going through us.
func (r *registryConfigurator) addDNSExemptLocalPolicy() error {
	var noServers netip.Addr

	if err := r.configureDNSPolicy(dnsPolicyConfigExemptLocalPath, []string{nrptLocalNamespace}, noServers); err != nil {
		return fmt.Errorf("configure exempt policy for %s: %w", nrptLocalNamespace, err)
	}

	if r.gpo {
		if err := r.configureDNSPolicy(gpoDnsPolicyConfigExemptLocalPath, []string{nrptLocalNamespace}, noServers); err != nil {
			return fmt.Errorf("configure gpo exempt policy for %s: %w", nrptLocalNamespace, err)
		}
		if err := refreshGroupPolicy(); err != nil {
			log.Warnf("failed to refresh group policy: %v", err)
		}
	}

	log.Infof("added NRPT exemption for %s, leaving it to the OS resolver", nrptLocalNamespace)
	return nil
}

// configureDNSPolicy writes one NRPT rule. An invalid ip writes an exemption
// rule: the namespace with an empty server list, which tells the DNS client to
// resolve those names the way it would without any rule at all.
//
// The empty string is the whole difference, and it has to be written: dropping
// the value and clearing ConfigOptions instead produces a rule Windows treats
// as a no-op, keeps out of Get-DnsClientNrptPolicy -Effective, and ignores in
// favour of the catch-all. 0x8 says the server list is the meaningful part of
// the rule, and an empty list then means "no server, resolve normally".
func (r *registryConfigurator) configureDNSPolicy(policyPath string, domains []string, ip netip.Addr) error {
	if err := removeRegistryKeyFromDNSPolicyConfig(policyPath); err != nil {
		return fmt.Errorf("remove existing dns policy: %w", err)
	}

	regKey, _, err := winregistry.CreateVolatileKey(registry.LOCAL_MACHINE, policyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("create volatile registry key HKEY_LOCAL_MACHINE\\%s: %w", policyPath, err)
	}
	defer closer(regKey)

	if err := regKey.SetDWordValue(dnsPolicyConfigVersionKey, dnsPolicyConfigVersionValue); err != nil {
		return fmt.Errorf("set %s: %w", dnsPolicyConfigVersionKey, err)
	}

	if err := regKey.SetStringsValue(dnsPolicyConfigNameKey, domains); err != nil {
		return fmt.Errorf("set %s: %w", dnsPolicyConfigNameKey, err)
	}

	var servers string
	if ip.IsValid() {
		servers = ip.String()
	}
	if err := regKey.SetStringValue(dnsPolicyConfigGenericDNSServersKey, servers); err != nil {
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
		if !errors.Is(err, syscall.Errno(0)) {
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
	regKeyPath := InterfaceConfigPath + "\\" + r.guid
	regKey, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return regKey, fmt.Errorf("open HKEY_LOCAL_MACHINE\\%s: %w", regKeyPath, err)
	}
	return regKey, nil
}

func (r *registryConfigurator) restoreHostDNS() error {
	// Propagated, unlike in applyDNSConfig: there we are about to write fresh
	// rules over whatever survived, here we are leaving, and a rule left behind
	// keeps sending every query to an address that is about to disappear.
	if err := r.removeDNSMatchPolicies(); err != nil {
		return fmt.Errorf("remove dns match policies: %w", err)
	}

	if err := r.deleteInterfaceRegistryKeyProperty(interfaceConfigSearchListKey); err != nil {
		return fmt.Errorf("remove interface registry key: %w", err)
	}

	go r.flushDNSCache()

	return nil
}

// removeDNSMatchPolicies deletes every NRPT rule this client may have created,
// from the local and the GPO policy store. The rules are found by enumerating
// the registry, the only authoritative record of what was written. Cleanup must
// not depend on a rule count: the in-memory one is scoped to a single
// registryConfigurator and the persisted one is deleted on every clean
// disconnect, and a rule left behind keeps resolving names over an interface
// that is gone, until reboot discards the volatile key.
func (r *registryConfigurator) removeDNSMatchPolicies() error {
	var merr *multierror.Error

	for _, root := range []string{DNSPolicyConfigRoot, GPODNSPolicyConfigRoot} {
		names, err := listNRPTRuleKeys(root)
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf("list rule keys under %s: %w", root, err))
			continue
		}

		for _, name := range names {
			path := root + `\` + name
			if err := removeRegistryKeyFromDNSPolicyConfig(path); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("remove entry %s: %w", path, err))
			}
		}
	}

	if err := refreshGroupPolicy(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("refresh group policy: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *registryConfigurator) restoreUncleanShutdownDNS() error {
	return r.restoreHostDNS()
}

// listNRPTRuleKeys returns the names of our NRPT rule keys under a policy store
// root. An absent root holds nothing to clean up, which is the normal state of
// the GPO store on a machine without DNS Client policy.
func listNRPTRuleKeys(root string) ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.ENUMERATE_SUB_KEYS)
	switch {
	case errors.Is(err, registry.ErrNotExist), errors.Is(err, syscall.ERROR_PATH_NOT_FOUND):
		// the GPO store is absent on a machine without DNS client policy
		log.Debugf("HKEY_LOCAL_MACHINE\\%s does not exist", root)
		return nil, nil
	case err != nil:
		// any other failure has to reach the caller: reporting no rules would
		// report a successful cleanup while leaving the rules in place
		return nil, fmt.Errorf("open HKEY_LOCAL_MACHINE\\%s: %w", root, err)
	}
	defer closer(k)

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("read subkey names: %w", err)
	}

	var ruleKeys []string
	for _, name := range names {
		// registry key names are case insensitive
		if strings.HasPrefix(strings.ToLower(name), strings.ToLower(NRPTKeyPrefix)) {
			ruleKeys = append(ruleKeys, name)
		}
	}

	return ruleKeys, nil
}

func removeRegistryKeyFromDNSPolicyConfig(regKeyPath string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyPath, registry.QUERY_VALUE)
	switch {
	case errors.Is(err, registry.ErrNotExist), errors.Is(err, syscall.ERROR_PATH_NOT_FOUND):
		// nothing to remove, which is the normal case for a rule this config
		// never installed
		log.Debugf("HKEY_LOCAL_MACHINE\\%s does not exist", regKeyPath)
		return nil
	case err != nil:
		// anything else has to reach the caller: reporting success here would
		// leave the rule in force while claiming it was removed, which is how a
		// stale rule outlives the interface it points at
		return fmt.Errorf("open HKEY_LOCAL_MACHINE\\%s: %w", regKeyPath, err)
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
		if !errors.Is(err, syscall.Errno(0)) {
			return fmt.Errorf("RefreshPolicyEx failed: %w", err)
		}
		return fmt.Errorf("RefreshPolicyEx failed")
	}

	return nil
}

func parseBoolEnv(key string) bool {
	val := os.Getenv(key)
	if val == "" {
		return false
	}

	parsed, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s=%q: %v", key, val, err)
		return false
	}
	return parsed
}

func closer(closer io.Closer) {
	if err := closer.Close(); err != nil {
		log.Errorf("failed to close: %s", err)
	}
}
