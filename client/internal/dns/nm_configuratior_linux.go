package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/godbus/dbus/v5"
	"github.com/miekg/dns"
	"github.com/netbirdio/netbird/iface"
	log "github.com/sirupsen/logrus"
	"net/netip"
	"time"
)

const (
	networkManagerDest                                                              = "org.freedesktop.NetworkManager"
	networkManagerDbusObjectNode                                                    = "/org/freedesktop/NetworkManager"
	networkManagerDbusGetDeviceByIpIfaceMethod                                      = networkManagerDest + ".GetDeviceByIpIface"
	networkManagerDbusDeviceInterface                                               = "org.freedesktop.NetworkManager.Device"
	networkManagerDbusDeviceGetAppliedConnectionMethod                              = networkManagerDbusDeviceInterface + ".GetAppliedConnection"
	networkManagerDbusDeviceReapplyMethod                                           = networkManagerDbusDeviceInterface + ".Reapply"
	networkManagerDbusDefaultBehaviorFlag              networkManagerConfigBehavior = 0
	networkManagerDbusIPv4Key                                                       = "ipv4"
	networkManagerDbusIPv6Key                                                       = "ipv6"
	networkManagerDbusDNSKey                                                        = "dns"
	networkManagerDbusDNSSearchKey                                                  = "dns-search"
	networkManagerDbusDNSPriorityKey                                                = "dns-priority"

	// dns priority doc https://wiki.gnome.org/Projects/NetworkManager/DNS
	networkManagerDbusPrimaryDNSPriority       int32 = -2147483648
	networkManagerDbusWithMatchDomainPriority  int32 = 0
	networkManagerDbusSearchDomainOnlyPriority int32 = 50
	networkManagerDbusSearchDefaultPriority    int32 = 100
)

type networkManagerDbusConfigurator struct {
	dbusLinkObject dbus.ObjectPath
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

func newNetworkManagerDbusConfigurator(wgInterface *iface.WGIface) hostManager {
	obj, closeConn, err := getDbusObject(networkManagerDest, networkManagerDbusObjectNode)
	if err != nil {
		// todo add proper error handling
		panic(err)
	}
	defer closeConn()
	var s string
	err = obj.Call(networkManagerDbusGetDeviceByIpIfaceMethod, dbusDefaultFlag, wgInterface.GetName()).Store(&s)
	if err != nil {
		// todo add proper error handling
		panic(err)
	}

	log.Debugf("got network manager dbus Link Object: %s from net interface %s", s, wgInterface.GetName())

	return &networkManagerDbusConfigurator{
		dbusLinkObject: dbus.ObjectPath(s),
	}
}

func (n *networkManagerDbusConfigurator) applyDNSSettings(domains []string, ip string, port int) error {
	connSettings, configVersion, err := n.getAppliedConnectionSettings()
	if err != nil {
		return fmt.Errorf("got an error while retrieving the applied connection settings, error: %s", err)
	}

	connSettings.cleanDeprecatedSettings()
	// todo remove this
	_, found := connSettings[networkManagerDbusIPv4Key]["routes"]
	if found {
		panic("removing deprecated settings didn't work")
	}

	dnsIP := netip.MustParseAddr(ip)
	convDNSIP := binary.LittleEndian.Uint32(dnsIP.AsSlice())
	connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSKey] = dbus.MakeVariant([]uint32{convDNSIP})

	priority := networkManagerDbusSearchDomainOnlyPriority
	if len(domains) > 1 {
		priority = networkManagerDbusWithMatchDomainPriority
	}

	var newDomainList []string

	for _, domain := range domains {
		if isRootZoneDomain(domain) {
			priority = networkManagerDbusPrimaryDNSPriority
			newDomainList = append(newDomainList, "~.")
			continue
		}
		newDomainList = append(newDomainList, "~."+dns.Fqdn(domain))
	}
	connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSPriorityKey] = dbus.MakeVariant(priority)
	connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSSearchKey] = dbus.MakeVariant(newDomainList)

	err = n.reApplyConnectionSettings(connSettings, configVersion)
	if err != nil {
		log.Errorf("got an error while reapplying the connection with new settings, error: %s", err)
	}
	return nil
}

func (n *networkManagerDbusConfigurator) addSearchDomain(domain string, _ string, _ int) error {
	connSettings, configVersion, err := n.getAppliedConnectionSettings()
	if err != nil {
		return fmt.Errorf("got an error while retrieving the applied connection settings, error: %s", err)
	}

	connSettings.cleanDeprecatedSettings()

	currentDomainsVariant := connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSSearchKey]
	currentDomainsInt := currentDomainsVariant.Value()
	currentDomains := currentDomainsInt.([]string)

	fqdnDomain := dns.Fqdn(domain)
	matchOnlyDomain := "~." + fqdnDomain
	var newDomainList []string
	for _, currDomain := range currentDomains {
		if currDomain != fqdnDomain && currDomain != matchOnlyDomain {
			newDomainList = append(newDomainList, currDomain)
		}
	}

	newDomainList = append(newDomainList, fqdnDomain)

	connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSSearchKey] = dbus.MakeVariant(newDomainList)

	err = n.reApplyConnectionSettings(connSettings, configVersion)
	if err != nil {
		log.Errorf("got an error while reapplying the connection with new search domain settings, error: %s", err)
	}
	return nil
}
func (n *networkManagerDbusConfigurator) removeDomainSettings(domains []string) error {
	connSettings, configVersion, err := n.getAppliedConnectionSettings()
	if err != nil {
		return fmt.Errorf("got an error while retrieving the applied connection settings, error: %s", err)
	}

	connSettings.cleanDeprecatedSettings()

	currentDomainsVariant := connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSSearchKey]
	currentDomainsInt := currentDomainsVariant.Value()
	currentDomains := currentDomainsInt.([]string)

	currentMap := make(map[string]struct{})
	for _, currentDomain := range currentDomains {
		currentMap[currentDomain] = struct{}{}
	}

	for _, domain := range domains {
		fqdnDomain := dns.Fqdn(domain)
		matchOnlyDomain := "~." + fqdnDomain
		_, found := currentMap[fqdnDomain]
		if found {
			delete(currentMap, fqdnDomain)
			continue
		}
		_, found = currentMap[matchOnlyDomain]
		if found {
			delete(currentMap, matchOnlyDomain)
		}
	}

	priority := networkManagerDbusSearchDomainOnlyPriority
	if len(currentMap) > 1 {
		priority = networkManagerDbusWithMatchDomainPriority
	}

	var newDomainList []string
	for domainLeft := range currentMap {
		if domainLeft == "~." {
			priority = networkManagerDbusPrimaryDNSPriority
		}
		newDomainList = append(newDomainList, domainLeft)
	}

	connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSPriorityKey] = dbus.MakeVariant(priority)
	connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSSearchKey] = dbus.MakeVariant(newDomainList)

	err = n.reApplyConnectionSettings(connSettings, configVersion)
	if err != nil {
		log.Errorf("got an error while reapplying settings after removing domains, error: %s", err)
	}
	return nil
}
func (n *networkManagerDbusConfigurator) removeDNSSettings() error {
	connSettings, configVersion, err := n.getAppliedConnectionSettings()
	if err != nil {
		return fmt.Errorf("got an error while retrieving the applied connection settings, error: %s", err)
	}

	connSettings.cleanDeprecatedSettings()

	connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSKey] = dbus.MakeVariant([]uint32{})
	connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSPriorityKey] = dbus.MakeVariant(networkManagerDbusSearchDefaultPriority)
	connSettings[networkManagerDbusIPv4Key][networkManagerDbusDNSSearchKey] = dbus.MakeVariant([]string{})

	err = n.reApplyConnectionSettings(connSettings, configVersion)
	if err != nil {
		log.Errorf("got an error while reapplying removed settings, error: %s", err)
	}

	return nil
}

func (n *networkManagerDbusConfigurator) getAppliedConnectionSettings() (networkManagerConnSettings, networkManagerConfigVersion, error) {
	obj, closeConn, err := getDbusObject(networkManagerDest, n.dbusLinkObject)
	if err != nil {
		return nil, 0, fmt.Errorf("got error while attempting to retrieve the applied connection settings, err: %s", err)
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
		return nil, 0, fmt.Errorf("got error while calling command with context, err: %s", err)
	}

	return connSettings, configVersion, nil
}

func (n *networkManagerDbusConfigurator) reApplyConnectionSettings(connSettings networkManagerConnSettings, configVersion networkManagerConfigVersion) error {
	obj, closeConn, err := getDbusObject(networkManagerDest, n.dbusLinkObject)
	if err != nil {
		return fmt.Errorf("got error while attempting to retrieve the applied connection settings, err: %s", err)
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	err = obj.CallWithContext(ctx, networkManagerDbusDeviceReapplyMethod, dbusDefaultFlag,
		connSettings, configVersion, networkManagerDbusDefaultBehaviorFlag).Store()
	if err != nil {
		return fmt.Errorf("got error while calling command with context, err: %s", err)
	}

	return nil
}
