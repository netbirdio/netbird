//go:build !android

package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbdns "github.com/netbirdio/netbird/dns"
)

const (
	systemdDbusManagerInterface            = "org.freedesktop.resolve1.Manager"
	systemdResolvedDest                    = "org.freedesktop.resolve1"
	systemdDbusObjectNode                  = "/org/freedesktop/resolve1"
	systemdDbusGetLinkMethod               = systemdDbusManagerInterface + ".GetLink"
	systemdDbusFlushCachesMethod           = systemdDbusManagerInterface + ".FlushCaches"
	systemdDbusResolvConfModeProperty      = systemdDbusManagerInterface + ".ResolvConfMode"
	systemdDbusLinkInterface               = "org.freedesktop.resolve1.Link"
	systemdDbusRevertMethodSuffix          = systemdDbusLinkInterface + ".Revert"
	systemdDbusSetDNSMethodSuffix          = systemdDbusLinkInterface + ".SetDNS"
	setDNSExMethodName                     = "SetDNSEx"
	systemdDbusSetDNSExMethodSuffix        = systemdDbusLinkInterface + "." + setDNSExMethodName
	systemdDbusSetDefaultRouteMethodSuffix = systemdDbusLinkInterface + ".SetDefaultRoute"
	systemdDbusSetDomainsMethodSuffix      = systemdDbusLinkInterface + ".SetDomains"
	systemdDbusSetDNSSECMethodSuffix       = systemdDbusLinkInterface + ".SetDNSSEC"
	systemdDbusSetDNSOverTLSMethodSuffix   = systemdDbusLinkInterface + ".SetDNSOverTLS"
	systemdDbusResolvConfModeForeign       = "foreign"

	dbusErrorUnknownObject = "org.freedesktop.DBus.Error.UnknownObject"

	dnsSecDisabled = "no"
)

type systemdDbusConfigurator struct {
	dbusLinkObject dbus.ObjectPath
	ifaceName      string
	wgIndex        int
	// supportsDNSEx reports whether resolved exposes SetDNSEx on the link, which
	// is the only way to hand it a resolver port. SetDNS carries the address
	// alone, so on older resolved a resolver off port 53 cannot be advertised.
	supportsDNSEx   bool
	origNameservers []netip.Addr
}

const (
	systemdDbusLinkDNSProperty          = systemdDbusLinkInterface + ".DNS"
	systemdDbusLinkDefaultRouteProperty = systemdDbusLinkInterface + ".DefaultRoute"
)

// the types below are based on dbus specification, each field is mapped to a dbus type
// see https://dbus.freedesktop.org/doc/dbus-specification.html#basic-types for more details on dbus types
// see https://www.freedesktop.org/software/systemd/man/org.freedesktop.resolve1.html on resolve1 input types
// systemdDbusDNSInput maps to a (iay) dbus input for SetDNS method
type systemdDbusDNSInput struct {
	Family  int32
	Address []byte
}

// systemdDbusDNSInputEx maps to a (iayqs) dbus input for the SetDNSEx method,
// which takes a port and a server name on top of the address SetDNS accepts. A
// zero port means the default, and an empty name means no name is pinned for
// DNS-over-TLS validation.
type systemdDbusDNSInputEx struct {
	Family  int32
	Address []byte
	Port    uint16
	Name    string
}

// systemdDbusLinkDomainsInput maps to a (sb) dbus input for SetDomains method
type systemdDbusLinkDomainsInput struct {
	Domain    string
	MatchOnly bool
}

func newSystemdDbusConfigurator(wgInterface string) (*systemdDbusConfigurator, error) {
	iface, err := net.InterfaceByName(wgInterface)
	if err != nil {
		return nil, fmt.Errorf("get interface: %w", err)
	}

	obj, closeConn, err := getDbusObject(systemdResolvedDest, systemdDbusObjectNode)
	if err != nil {
		return nil, fmt.Errorf("get dbus resolved dest: %w", err)
	}
	defer closeConn()

	var s string
	err = obj.Call(systemdDbusGetLinkMethod, dbusDefaultFlag, iface.Index).Store(&s)
	if err != nil {
		return nil, fmt.Errorf("get dbus link method: %w", err)
	}

	log.Debugf("got dbus Link interface: %s from net interface %s and index %d", s, iface.Name, iface.Index)

	c := &systemdDbusConfigurator{
		dbusLinkObject: dbus.ObjectPath(s),
		ifaceName:      wgInterface,
		wgIndex:        iface.Index,
	}

	c.supportsDNSEx = c.hasDNSExMethod()
	if !c.supportsDNSEx {
		log.Infof("systemd-resolved does not expose %s; a DNS resolver on a port other than %d cannot be advertised to it",
			setDNSExMethodName, DefaultPort)
	}

	origNameservers, err := c.captureOriginalNameservers()
	switch {
	case err != nil:
		log.Warnf("capture original nameservers from systemd-resolved: %v", err)
	case len(origNameservers) == 0:
		log.Warnf("no original nameservers captured from systemd-resolved default-route links; DNS fallback will be empty")
	default:
		log.Debugf("captured %d original nameservers from systemd-resolved default-route links: %v", len(origNameservers), origNameservers)
	}
	c.origNameservers = origNameservers
	return c, nil
}

// captureOriginalNameservers reads per-link DNS from systemd-resolved for
// every default-route link except our own WG link. Non-default-route links
// (VPNs, docker bridges) are skipped because their upstreams wouldn't
// actually serve host queries.
func (s *systemdDbusConfigurator) captureOriginalNameservers() ([]netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	seen := make(map[netip.Addr]struct{})
	var out []netip.Addr
	for _, iface := range ifaces {
		if !s.isCandidateLink(iface) {
			continue
		}
		linkPath, err := getSystemdLinkPath(iface.Index)
		if err != nil || !isSystemdLinkDefaultRoute(linkPath) {
			continue
		}
		for _, addr := range readSystemdLinkDNS(linkPath) {
			addr = normalizeSystemdAddr(addr, iface.Name)
			if !addr.IsValid() {
				continue
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

func (s *systemdDbusConfigurator) isCandidateLink(iface net.Interface) bool {
	if iface.Index == s.wgIndex {
		return false
	}
	if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
		return false
	}
	return true
}

// normalizeSystemdAddr unmaps v4-mapped-v6, drops unspecified, and reattaches
// the link's iface name as zone for link-local v6 (Link.DNS strips it).
// Returns the zero Addr to signal "skip this entry".
func normalizeSystemdAddr(addr netip.Addr, ifaceName string) netip.Addr {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() {
		return netip.Addr{}
	}
	if addr.IsLinkLocalUnicast() {
		return addr.WithZone(ifaceName)
	}
	return addr
}

func getSystemdLinkPath(ifIndex int) (dbus.ObjectPath, error) {
	obj, closeConn, err := getDbusObject(systemdResolvedDest, systemdDbusObjectNode)
	if err != nil {
		return "", fmt.Errorf("dbus resolve1: %w", err)
	}
	defer closeConn()
	var p string
	if err := obj.Call(systemdDbusGetLinkMethod, dbusDefaultFlag, int32(ifIndex)).Store(&p); err != nil {
		return "", err
	}
	return dbus.ObjectPath(p), nil
}

func isSystemdLinkDefaultRoute(linkPath dbus.ObjectPath) bool {
	obj, closeConn, err := getDbusObject(systemdResolvedDest, linkPath)
	if err != nil {
		return false
	}
	defer closeConn()
	v, err := obj.GetProperty(systemdDbusLinkDefaultRouteProperty)
	if err != nil {
		return false
	}
	b, ok := v.Value().(bool)
	return ok && b
}

func readSystemdLinkDNS(linkPath dbus.ObjectPath) []netip.Addr {
	obj, closeConn, err := getDbusObject(systemdResolvedDest, linkPath)
	if err != nil {
		return nil
	}
	defer closeConn()
	v, err := obj.GetProperty(systemdDbusLinkDNSProperty)
	if err != nil {
		return nil
	}
	entries, ok := v.Value().([][]any)
	if !ok {
		return nil
	}
	var out []netip.Addr
	for _, entry := range entries {
		if len(entry) < 2 {
			continue
		}
		raw, ok := entry[1].([]byte)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(raw)
		if !ok {
			continue
		}
		out = append(out, addr)
	}
	return out
}

func (s *systemdDbusConfigurator) getOriginalNameservers() []netip.Addr {
	return slices.Clone(s.origNameservers)
}

func (s *systemdDbusConfigurator) supportCustomPort() bool {
	return s.supportsDNSEx
}

// hasDNSExMethod reports whether resolved exposes SetDNSEx on the link
// interface. It was added in systemd 240; before that, resolved has no way to
// accept a resolver port.
func (s *systemdDbusConfigurator) hasDNSExMethod() bool {
	obj, closeConn, err := getDbusObject(systemdResolvedDest, s.dbusLinkObject)
	if err != nil {
		log.Debugf("failed to get dbus link object for introspection: %v", err)
		return false
	}
	defer closeConn()

	node, err := introspect.Call(obj)
	if err != nil {
		log.Debugf("failed to introspect systemd-resolved link: %v", err)
		return false
	}

	for _, iface := range node.Interfaces {
		if iface.Name != systemdDbusLinkInterface {
			continue
		}
		return slices.ContainsFunc(iface.Methods, func(m introspect.Method) bool {
			return m.Name == setDNSExMethodName
		})
	}

	return false
}

// dnsServerMethod picks the resolved method that can carry the resolver's
// address and port, and builds its input. SetDNS takes the address alone, so a
// resolver on a port other than 53 needs SetDNSEx; the caller is expected to
// have checked supportCustomPort before asking for one.
func (s *systemdDbusConfigurator) dnsServerMethod(config HostDNSConfig) (string, any) {
	family := int32(unix.AF_INET)
	if config.ServerIP.Is6() {
		family = unix.AF_INET6
	}

	if config.ServerPort == DefaultPort || !s.supportsDNSEx {
		return systemdDbusSetDNSMethodSuffix, []systemdDbusDNSInput{{
			Family:  family,
			Address: config.ServerIP.AsSlice(),
		}}
	}

	return systemdDbusSetDNSExMethodSuffix, []systemdDbusDNSInputEx{{
		Family:  family,
		Address: config.ServerIP.AsSlice(),
		Port:    uint16(config.ServerPort),
	}}
}

func (s *systemdDbusConfigurator) applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error {
	method, input := s.dnsServerMethod(config)
	if err := s.callLinkMethod(method, input); err != nil {
		return fmt.Errorf("set interface DNS server %s:%d: %w", config.ServerIP, config.ServerPort, err)
	}

	// We don't support dnssec. On some machines this is default on so we explicitly set it to off
	if err := s.callLinkMethod(systemdDbusSetDNSSECMethodSuffix, dnsSecDisabled); err != nil {
		log.Warnf("failed to set DNSSEC to 'no': %v", err)
	}

	// We don't support DNSOverTLS. On some machines this is default on so we explicitly set it to off
	if err := s.callLinkMethod(systemdDbusSetDNSOverTLSMethodSuffix, dnsSecDisabled); err != nil {
		log.Warnf("failed to set DNSOverTLS to 'no': %v", err)
	}

	var (
		searchDomains []string
		matchDomains  []string
		domainsInput  []systemdDbusLinkDomainsInput
	)
	for _, dConf := range config.Domains {
		if dConf.Disabled {
			continue
		}
		domainsInput = append(domainsInput, systemdDbusLinkDomainsInput{
			Domain:    dConf.Domain,
			MatchOnly: dConf.MatchOnly,
		})

		if dConf.MatchOnly {
			matchDomains = append(matchDomains, dConf.Domain)
			continue
		}
		searchDomains = append(searchDomains, dConf.Domain)
	}

	if config.RouteAll {
		if err := s.callLinkMethod(systemdDbusSetDefaultRouteMethodSuffix, true); err != nil {
			return fmt.Errorf("set link as default dns router: %w", err)
		}
		domainsInput = append(domainsInput, systemdDbusLinkDomainsInput{
			Domain:    nbdns.RootZone,
			MatchOnly: true,
		})
		log.Infof("configured %s:%d as main DNS forwarder for this peer", config.ServerIP, config.ServerPort)
	} else {
		if err := s.callLinkMethod(systemdDbusSetDefaultRouteMethodSuffix, false); err != nil {
			return fmt.Errorf("remove link as default dns router: %w", err)
		}
	}

	state := &ShutdownState{
		ManagerType: systemdManager,
		WgIface:     s.ifaceName,
	}
	if err := stateManager.UpdateState(state); err != nil {
		log.Errorf("failed to update shutdown state: %s", err)
	}

	log.Infof("adding %d search domains and %d match domains. Search list: %s , Match list: %s", len(searchDomains), len(matchDomains), searchDomains, matchDomains)
	if err := s.setDomainsForInterface(domainsInput); err != nil {
		log.Error("failed to set domains for interface: ", err)
	}

	if err := s.flushDNSCache(); err != nil {
		log.Errorf("failed to flush DNS cache: %v", err)
	}

	return nil
}

func (s *systemdDbusConfigurator) string() string {
	return "dbus"
}

func (s *systemdDbusConfigurator) setDomainsForInterface(domainsInput []systemdDbusLinkDomainsInput) error {
	err := s.callLinkMethod(systemdDbusSetDomainsMethodSuffix, domainsInput)
	if err != nil {
		return fmt.Errorf("setting domains configuration failed with error: %w", err)
	}

	return nil
}

func (s *systemdDbusConfigurator) restoreHostDNS() error {
	log.Infof("reverting link settings and flushing cache")
	if !isDbusListenerRunning(systemdResolvedDest, s.dbusLinkObject) {
		return nil
	}

	// this call is required for DNS cleanup, even if it fails
	err := s.callLinkMethod(systemdDbusRevertMethodSuffix, nil)
	if err != nil {
		var dbusErr dbus.Error
		if errors.As(err, &dbusErr) && dbusErr.Name == dbusErrorUnknownObject {
			// interface is gone already
			return nil
		}
		return fmt.Errorf("unable to revert link configuration, got error: %w", err)
	}

	if err := s.flushDNSCache(); err != nil {
		log.Errorf("failed to flush DNS cache: %v", err)
	}

	return nil
}

func (s *systemdDbusConfigurator) flushDNSCache() error {
	obj, closeConn, err := getDbusObject(systemdResolvedDest, systemdDbusObjectNode)
	if err != nil {
		return fmt.Errorf("attempting to retrieve the object %s, err: %w", systemdDbusObjectNode, err)
	}
	defer closeConn()
	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	err = obj.CallWithContext(ctx, systemdDbusFlushCachesMethod, dbusDefaultFlag).Store()
	if err != nil {
		return fmt.Errorf("calling the FlushCaches method with context, err: %w", err)
	}

	return nil
}

func (s *systemdDbusConfigurator) callLinkMethod(method string, value any) error {
	obj, closeConn, err := getDbusObject(systemdResolvedDest, s.dbusLinkObject)
	if err != nil {
		return fmt.Errorf("attempting to retrieve the object, err: %w", err)
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	if value != nil {
		err = obj.CallWithContext(ctx, method, dbusDefaultFlag, value).Store()
	} else {
		err = obj.CallWithContext(ctx, method, dbusDefaultFlag).Store()
	}

	if err != nil {
		return fmt.Errorf("calling command with context, err: %w", err)
	}

	return nil
}

func (s *systemdDbusConfigurator) restoreUncleanShutdownDNS(netip.Addr) error {
	if err := s.restoreHostDNS(); err != nil {
		return fmt.Errorf("restoring dns via systemd: %w", err)
	}
	return nil
}

func getSystemdDbusProperty(property string, store any) error {
	obj, closeConn, err := getDbusObject(systemdResolvedDest, systemdDbusObjectNode)
	if err != nil {
		return fmt.Errorf("attempting to retrieve the systemd dns manager object, error: %w", err)
	}
	defer closeConn()

	v, e := obj.GetProperty(property)
	if e != nil {
		return fmt.Errorf("getting property %s: %w", property, e)
	}

	return v.Store(store)
}

func isSystemdResolvedRunning() bool {
	return isDbusListenerRunning(systemdResolvedDest, systemdDbusObjectNode)
}

func isSystemdResolveConfMode() bool {
	if !isDbusListenerRunning(systemdResolvedDest, systemdDbusObjectNode) {
		return false
	}

	var value string
	if err := getSystemdDbusProperty(systemdDbusResolvConfModeProperty, &value); err != nil {
		log.Errorf("got an error while checking systemd resolv conf mode, error: %s", err)
		return false
	}

	if value == systemdDbusResolvConfModeForeign {
		return true
	}

	return false
}
