//go:build (linux && !android) || freebsd

package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbversion "github.com/netbirdio/netbird/version"
)

const (
	networkManagerDest                                                              = "org.freedesktop.NetworkManager"
	networkManagerDbusObjectNode                                                    = "/org/freedesktop/NetworkManager"
	networkManagerDbusDNSManagerInterface                                           = "org.freedesktop.NetworkManager.DnsManager"
	networkManagerDbusDNSManagerObjectNode                                          = networkManagerDbusObjectNode + "/DnsManager"
	networkManagerDbusDNSManagerModeProperty                                        = networkManagerDbusDNSManagerInterface + ".Mode"
	networkManagerDbusDNSManagerRcManagerProperty                                   = networkManagerDbusDNSManagerInterface + ".RcManager"
	networkManagerDbusVersionProperty                                               = "org.freedesktop.NetworkManager.Version"
	networkManagerDbusGetDeviceByIPIfaceMethod                                      = networkManagerDest + ".GetDeviceByIpIface"
	networkManagerDbusDeviceInterface                                               = "org.freedesktop.NetworkManager.Device"
	networkManagerDbusDeviceGetAppliedConnectionMethod                              = networkManagerDbusDeviceInterface + ".GetAppliedConnection"
	networkManagerDbusDeviceReapplyMethod                                           = networkManagerDbusDeviceInterface + ".Reapply"
	networkManagerDbusDeviceDeleteMethod                                            = networkManagerDbusDeviceInterface + ".Delete"
	networkManagerDbusDeviceIp4ConfigProperty                                       = networkManagerDbusDeviceInterface + ".Ip4Config"
	networkManagerDbusDeviceIp6ConfigProperty                                       = networkManagerDbusDeviceInterface + ".Ip6Config"
	networkManagerDbusDeviceIfaceProperty                                           = networkManagerDbusDeviceInterface + ".Interface"
	networkManagerDbusGetDevicesMethod                                              = networkManagerDest + ".GetDevices"
	networkManagerDbusIp4ConfigInterface                                            = "org.freedesktop.NetworkManager.IP4Config"
	networkManagerDbusIp6ConfigInterface                                            = "org.freedesktop.NetworkManager.IP6Config"
	networkManagerDbusIp4ConfigNameserverDataProperty                               = networkManagerDbusIp4ConfigInterface + ".NameserverData"
	networkManagerDbusIp4ConfigNameserversProperty                                  = networkManagerDbusIp4ConfigInterface + ".Nameservers"
	networkManagerDbusIp6ConfigNameserversProperty                                  = networkManagerDbusIp6ConfigInterface + ".Nameservers"
	networkManagerDbusDefaultBehaviorFlag              networkManagerConfigBehavior = 0
	networkManagerDbusIPv4Key                                                       = "ipv4"
	networkManagerDbusIPv6Key                                                       = "ipv6"
	networkManagerDbusDNSKey                                                        = "dns"
	networkManagerDbusDNSSearchKey                                                  = "dns-search"
	networkManagerDbusDNSPriorityKey                                                = "dns-priority"

	// dns priority doc https://wiki.gnome.org/Projects/NetworkManager/DNS
	networkManagerDbusPrimaryDNSPriority       int32 = -500
	networkManagerDbusWithMatchDomainPriority  int32 = 0
	networkManagerDbusSearchDomainOnlyPriority int32 = 50
)

var supportedNetworkManagerVersionConstraints = []string{
	">= 1.16, < 1.27",
	">= 1.44, < 1.45",
}

type networkManagerDbusConfigurator struct {
	dbusLinkObject  dbus.ObjectPath
	routingAll      bool
	ifaceName       string
	origNameservers []netip.Addr
}

// the types below are based on dbus specification, each field is mapped to a dbus type
// see https://dbus.freedesktop.org/doc/dbus-specification.html#basic-types for more details on dbus types
// see https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Device.html on Network Manager input types

// networkManagerConnSettings maps to a (a{sa{sv}}) dbus output from GetAppliedConnection and input for Reapply methods
type networkManagerConnSettings map[string]map[string]dbus.Variant

// networkManagerConfigVersion maps to a (t) dbus output from GetAppliedConnection and input for Reapply methods
type networkManagerConfigVersion uint64

// networkManagerConfigBehavior maps to a (u) dbus input for GetAppliedConnection and Reapply methods
type networkManagerConfigBehavior uint32

// cleanDeprecatedSettings cleans deprecated settings that still returned by
// the GetAppliedConnection methods but can't be reApplied
func (s networkManagerConnSettings) cleanDeprecatedSettings() {
	for _, key := range []string{"addresses", "routes"} {
		delete(s[networkManagerDbusIPv4Key], key)
		delete(s[networkManagerDbusIPv6Key], key)
	}
}

func newNetworkManagerDbusConfigurator(wgInterface string) (*networkManagerDbusConfigurator, error) {
	obj, closeConn, err := getDbusObject(networkManagerDest, networkManagerDbusObjectNode)
	if err != nil {
		return nil, fmt.Errorf("get nm dbus: %w", err)
	}
	defer closeConn()
	var s string
	err = obj.Call(networkManagerDbusGetDeviceByIPIfaceMethod, dbusDefaultFlag, wgInterface).Store(&s)
	if err != nil {
		return nil, fmt.Errorf("call: %w", err)
	}

	log.Debugf("got network manager dbus Link Object: %s from net interface %s", s, wgInterface)

	c := &networkManagerDbusConfigurator{
		dbusLinkObject: dbus.ObjectPath(s),
		ifaceName:      wgInterface,
	}

	origNameservers, err := c.captureOriginalNameservers()
	switch {
	case err != nil:
		log.Warnf("capture original nameservers from NetworkManager: %v", err)
	case len(origNameservers) == 0:
		log.Warnf("no original nameservers captured from non-WG NetworkManager devices; DNS fallback will be empty")
	default:
		log.Debugf("captured %d original nameservers from non-WG NetworkManager devices: %v", len(origNameservers), origNameservers)
	}
	c.origNameservers = origNameservers
	return c, nil
}

// captureOriginalNameservers reads DNS servers from every NM device's
// IP4Config / IP6Config except our WG device.
func (n *networkManagerDbusConfigurator) captureOriginalNameservers() ([]netip.Addr, error) {
	devices, err := networkManagerListDevices()
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}

	seen := make(map[netip.Addr]struct{})
	var out []netip.Addr
	for _, dev := range devices {
		if dev == n.dbusLinkObject {
			continue
		}
		ifaceName := readNetworkManagerDeviceInterface(dev)
		for _, addr := range readNetworkManagerDeviceDNS(dev) {
			addr = addr.Unmap()
			if !addr.IsValid() || addr.IsUnspecified() {
				continue
			}
			// IP6Config.Nameservers is a byte slice without zone info;
			// reattach the device's interface name so a captured fe80::…
			// stays routable.
			if addr.IsLinkLocalUnicast() && ifaceName != "" {
				addr = addr.WithZone(ifaceName)
			}
			if _, dup := seen[addr]; dup {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	return out, nil
}

func readNetworkManagerDeviceInterface(devicePath dbus.ObjectPath) string {
	obj, closeConn, err := getDbusObject(networkManagerDest, devicePath)
	if err != nil {
		return ""
	}
	defer closeConn()
	v, err := obj.GetProperty(networkManagerDbusDeviceIfaceProperty)
	if err != nil {
		return ""
	}
	s, _ := v.Value().(string)
	return s
}

func networkManagerListDevices() ([]dbus.ObjectPath, error) {
	obj, closeConn, err := getDbusObject(networkManagerDest, networkManagerDbusObjectNode)
	if err != nil {
		return nil, fmt.Errorf("dbus NetworkManager: %w", err)
	}
	defer closeConn()
	var devs []dbus.ObjectPath
	if err := obj.Call(networkManagerDbusGetDevicesMethod, dbusDefaultFlag).Store(&devs); err != nil {
		return nil, err
	}
	return devs, nil
}

func readNetworkManagerDeviceDNS(devicePath dbus.ObjectPath) []netip.Addr {
	obj, closeConn, err := getDbusObject(networkManagerDest, devicePath)
	if err != nil {
		return nil
	}
	defer closeConn()

	var out []netip.Addr
	if path := readNetworkManagerConfigPath(obj, networkManagerDbusDeviceIp4ConfigProperty); path != "" {
		out = append(out, readIPv4ConfigDNS(path)...)
	}
	if path := readNetworkManagerConfigPath(obj, networkManagerDbusDeviceIp6ConfigProperty); path != "" {
		out = append(out, readIPv6ConfigDNS(path)...)
	}
	return out
}

func readNetworkManagerConfigPath(obj dbus.BusObject, property string) dbus.ObjectPath {
	v, err := obj.GetProperty(property)
	if err != nil {
		return ""
	}
	path, ok := v.Value().(dbus.ObjectPath)
	if !ok || path == "/" {
		return ""
	}
	return path
}

func readIPv4ConfigDNS(path dbus.ObjectPath) []netip.Addr {
	obj, closeConn, err := getDbusObject(networkManagerDest, path)
	if err != nil {
		return nil
	}
	defer closeConn()

	// NameserverData (NM 1.13+) carries strings; older NMs only expose the
	// legacy uint32 Nameservers property.
	if out := readIPv4NameserverData(obj); len(out) > 0 {
		return out
	}
	return readIPv4LegacyNameservers(obj)
}

func readIPv4NameserverData(obj dbus.BusObject) []netip.Addr {
	v, err := obj.GetProperty(networkManagerDbusIp4ConfigNameserverDataProperty)
	if err != nil {
		return nil
	}
	entries, ok := v.Value().([]map[string]dbus.Variant)
	if !ok {
		return nil
	}
	var out []netip.Addr
	for _, entry := range entries {
		addrVar, ok := entry["address"]
		if !ok {
			continue
		}
		s, ok := addrVar.Value().(string)
		if !ok {
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func readIPv4LegacyNameservers(obj dbus.BusObject) []netip.Addr {
	v, err := obj.GetProperty(networkManagerDbusIp4ConfigNameserversProperty)
	if err != nil {
		return nil
	}
	raw, ok := v.Value().([]uint32)
	if !ok {
		return nil
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, n := range raw {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], n)
		out = append(out, netip.AddrFrom4(b))
	}
	return out
}

func readIPv6ConfigDNS(path dbus.ObjectPath) []netip.Addr {
	obj, closeConn, err := getDbusObject(networkManagerDest, path)
	if err != nil {
		return nil
	}
	defer closeConn()
	v, err := obj.GetProperty(networkManagerDbusIp6ConfigNameserversProperty)
	if err != nil {
		return nil
	}
	raw, ok := v.Value().([][]byte)
	if !ok {
		return nil
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, b := range raw {
		if a, ok := netip.AddrFromSlice(b); ok {
			out = append(out, a)
		}
	}
	return out
}

func (n *networkManagerDbusConfigurator) getOriginalNameservers() []netip.Addr {
	return slices.Clone(n.origNameservers)
}

func (n *networkManagerDbusConfigurator) supportCustomPort() bool {
	return false
}

func (n *networkManagerDbusConfigurator) applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error {
	connSettings, configVersion, err := n.getAppliedConnectionSettings()
	if err != nil {
		return fmt.Errorf("retrieving the applied connection settings, error: %w", err)
	}

	connSettings.cleanDeprecatedSettings()

	ipKey := networkManagerDbusIPv4Key
	staleKey := networkManagerDbusIPv6Key
	if config.ServerIP.Is6() {
		ipKey = networkManagerDbusIPv6Key
		staleKey = networkManagerDbusIPv4Key
		raw := config.ServerIP.As16()
		connSettings[ipKey][networkManagerDbusDNSKey] = dbus.MakeVariant([][]byte{raw[:]})
	} else {
		convDNSIP := binary.LittleEndian.Uint32(config.ServerIP.AsSlice())
		connSettings[ipKey][networkManagerDbusDNSKey] = dbus.MakeVariant([]uint32{convDNSIP})
	}

	// Clear stale DNS settings from the opposite address family to avoid
	// leftover entries if the server IP family changed.
	if staleSettings, ok := connSettings[staleKey]; ok {
		delete(staleSettings, networkManagerDbusDNSKey)
		delete(staleSettings, networkManagerDbusDNSPriorityKey)
		delete(staleSettings, networkManagerDbusDNSSearchKey)
	}
	var (
		searchDomains []string
		matchDomains  []string
	)
	for _, dConf := range config.Domains {
		if dConf.Disabled {
			continue
		}
		if dConf.MatchOnly {
			matchDomains = append(matchDomains, "~."+dConf.Domain)
			continue
		}
		searchDomains = append(searchDomains, dConf.Domain)
	}

	newDomainList := append(searchDomains, matchDomains...) //nolint:gocritic

	priority := networkManagerDbusSearchDomainOnlyPriority
	switch {
	case config.RouteAll:
		priority = networkManagerDbusPrimaryDNSPriority
		newDomainList = append(newDomainList, "~.")
		if !n.routingAll {
			log.Infof("configured %s:%d as main DNS forwarder for this peer", config.ServerIP, config.ServerPort)
		}
	case len(matchDomains) > 0:
		priority = networkManagerDbusWithMatchDomainPriority
	}

	if priority != networkManagerDbusPrimaryDNSPriority && n.routingAll {
		log.Infof("removing %s:%d as main DNS forwarder for this peer", config.ServerIP, config.ServerPort)
		n.routingAll = false
	}

	connSettings[ipKey][networkManagerDbusDNSPriorityKey] = dbus.MakeVariant(priority)
	connSettings[ipKey][networkManagerDbusDNSSearchKey] = dbus.MakeVariant(newDomainList)

	state := &ShutdownState{
		ManagerType: networkManager,
		WgIface:     n.ifaceName,
	}
	if err := stateManager.UpdateState(state); err != nil {
		log.Errorf("failed to update shutdown state: %s", err)
	}

	log.Infof("adding %d search domains and %d match domains. Search list: %s , Match list: %s", len(searchDomains), len(matchDomains), searchDomains, matchDomains)
	err = n.reApplyConnectionSettings(connSettings, configVersion)
	if err != nil {
		return fmt.Errorf("reapplying the connection with new settings, error: %w", err)
	}
	return nil
}

func (n *networkManagerDbusConfigurator) restoreHostDNS() error {
	// once the interface is gone network manager cleans all config associated with it
	if err := n.deleteConnectionSettings(); err != nil {
		return fmt.Errorf("delete connection settings: %w", err)
	}

	return nil
}

func (n *networkManagerDbusConfigurator) string() string {
	return "network-manager"
}

func (n *networkManagerDbusConfigurator) getAppliedConnectionSettings() (networkManagerConnSettings, networkManagerConfigVersion, error) {
	obj, closeConn, err := getDbusObject(networkManagerDest, n.dbusLinkObject)
	if err != nil {
		return nil, 0, fmt.Errorf("attempting to retrieve the applied connection settings, err: %w", err)
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	var (
		connSettings  networkManagerConnSettings
		configVersion networkManagerConfigVersion
	)

	err = obj.CallWithContext(ctx, networkManagerDbusDeviceGetAppliedConnectionMethod, dbusDefaultFlag,
		networkManagerDbusDefaultBehaviorFlag).Store(&connSettings, &configVersion)
	if err != nil {
		return nil, 0, fmt.Errorf("calling GetAppliedConnection method with context, err: %w", err)
	}

	return connSettings, configVersion, nil
}

func (n *networkManagerDbusConfigurator) reApplyConnectionSettings(connSettings networkManagerConnSettings, configVersion networkManagerConfigVersion) error {
	obj, closeConn, err := getDbusObject(networkManagerDest, n.dbusLinkObject)
	if err != nil {
		return fmt.Errorf("attempting to retrieve the applied connection settings, err: %w", err)
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	err = obj.CallWithContext(ctx, networkManagerDbusDeviceReapplyMethod, dbusDefaultFlag,
		connSettings, configVersion, networkManagerDbusDefaultBehaviorFlag).Store()
	if err != nil {
		return fmt.Errorf("calling ReApply method with context, err: %w", err)
	}

	return nil
}

func (n *networkManagerDbusConfigurator) deleteConnectionSettings() error {
	obj, closeConn, err := getDbusObject(networkManagerDest, n.dbusLinkObject)
	if err != nil {
		return fmt.Errorf("attempting to retrieve the applied connection settings, err: %w", err)
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	// this call is required to remove the device for DNS cleanup, even if it fails
	err = obj.CallWithContext(ctx, networkManagerDbusDeviceDeleteMethod, dbusDefaultFlag).Store()
	if err != nil {
		var dbusErr dbus.Error
		if errors.As(err, &dbusErr) && dbusErr.Name == dbus.ErrMsgUnknownMethod.Name {
			// interface is gone already
			return nil
		}
		return fmt.Errorf("calling delete method with context, err: %s", err)
	}

	return nil
}

func (n *networkManagerDbusConfigurator) restoreUncleanShutdownDNS(netip.Addr) error {
	if err := n.restoreHostDNS(); err != nil {
		return fmt.Errorf("restoring dns via network-manager: %w", err)
	}
	return nil
}

func isNetworkManagerSupported() bool {
	return isNetworkManagerSupportedVersion() && isNetworkManagerSupportedMode()
}

func isNetworkManagerSupportedMode() bool {
	var mode string
	err := getNetworkManagerDNSProperty(networkManagerDbusDNSManagerModeProperty, &mode)
	if err != nil {
		log.Error(err)
		return false
	}
	switch mode {
	case "dnsmasq", "unbound", "systemd-resolved":
		return true
	default:
		var rcManager string
		err = getNetworkManagerDNSProperty(networkManagerDbusDNSManagerRcManagerProperty, &rcManager)
		if err != nil {
			log.Error(err)
			return false
		}
		if rcManager == "unmanaged" {
			return false
		}
	}
	return true
}

func getNetworkManagerDNSProperty(property string, store any) error {
	obj, closeConn, err := getDbusObject(networkManagerDest, networkManagerDbusDNSManagerObjectNode)
	if err != nil {
		return fmt.Errorf("attempting to retrieve the network manager dns manager object, error: %w", err)
	}
	defer closeConn()

	v, e := obj.GetProperty(property)
	if e != nil {
		return fmt.Errorf("getting property %s: %w", property, e)
	}

	return v.Store(store)
}

func isNetworkManagerSupportedVersion() bool {
	obj, closeConn, err := getDbusObject(networkManagerDest, networkManagerDbusObjectNode)
	if err != nil {
		log.Errorf("got error while attempting to get the network manager object, err: %s", err)
		return false
	}

	defer closeConn()

	value, err := obj.GetProperty(networkManagerDbusVersionProperty)
	if err != nil {
		log.Errorf("unable to retrieve network manager mode, got error: %s", err)
		return false
	}
	versionValue, err := parseVersion(value.Value().(string))
	if err != nil {
		log.Errorf("nm: parse version: %s", err)
		return false
	}

	var supported bool
	for _, constraint := range supportedNetworkManagerVersionConstraints {
		constr, err := version.NewConstraint(constraint)
		if err != nil {
			log.Errorf("nm: create constraint: %s", err)
			return false
		}

		if met := constr.Check(versionValue); met {
			supported = true
			break
		}
	}

	log.Debugf("network manager constraints [%s] met: %t", strings.Join(supportedNetworkManagerVersionConstraints, " | "), supported)
	return supported
}

func parseVersion(inputVersion string) (*version.Version, error) {
	if inputVersion == "" || !nbversion.SemverRegexp.MatchString(inputVersion) {
		return nil, fmt.Errorf("couldn't parse the provided version: Not SemVer")
	}

	verObj, err := version.NewVersion(inputVersion)
	if err != nil {
		return nil, err
	}

	return verObj, nil
}
