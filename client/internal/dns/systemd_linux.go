//go:build !android

package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/godbus/dbus/v5"
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
	systemdDbusSetDefaultRouteMethodSuffix = systemdDbusLinkInterface + ".SetDefaultRoute"
	systemdDbusSetDomainsMethodSuffix      = systemdDbusLinkInterface + ".SetDomains"
	systemdDbusSetDNSSECMethodSuffix       = systemdDbusLinkInterface + ".SetDNSSEC"
	systemdDbusResolvConfModeForeign       = "foreign"

	dbusErrorUnknownObject = "org.freedesktop.DBus.Error.UnknownObject"

	dnsSecDisabled = "no"
)

type systemdDbusConfigurator struct {
	dbusLinkObject dbus.ObjectPath
	ifaceName      string
}

// the types below are based on dbus specification, each field is mapped to a dbus type
// see https://dbus.freedesktop.org/doc/dbus-specification.html#basic-types for more details on dbus types
// see https://www.freedesktop.org/software/systemd/man/org.freedesktop.resolve1.html on resolve1 input types
// systemdDbusDNSInput maps to a (iay) dbus input for SetDNS method
type systemdDbusDNSInput struct {
	Family  int32
	Address []byte
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

	return &systemdDbusConfigurator{
		dbusLinkObject: dbus.ObjectPath(s),
		ifaceName:      wgInterface,
	}, nil
}

func (s *systemdDbusConfigurator) supportCustomPort() bool {
	return true
}

func (s *systemdDbusConfigurator) applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error {
	defaultLinkInput := systemdDbusDNSInput{
		Family:  unix.AF_INET,
		Address: config.ServerIP.AsSlice(),
	}
	if err := s.callLinkMethod(systemdDbusSetDNSMethodSuffix, []systemdDbusDNSInput{defaultLinkInput}); err != nil {
		return fmt.Errorf("set interface DNS server %s:%d: %w", config.ServerIP, config.ServerPort, err)
	}

	// We don't support dnssec. On some machines this is default on so we explicitly set it to off
	if err := s.callLinkMethod(systemdDbusSetDNSSECMethodSuffix, dnsSecDisabled); err != nil {
		log.Warnf("failed to set DNSSEC to 'no': %v", err)
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

func (s *systemdDbusConfigurator) restoreUncleanShutdownDNS(*netip.Addr) error {
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
