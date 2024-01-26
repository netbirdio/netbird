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
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

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
	systemdDbusResolvConfModeForeign       = "foreign"

	dbusErrorUnknownObject = "org.freedesktop.DBus.Error.UnknownObject"
)

type systemdDbusConfigurator struct {
	dbusLinkObject dbus.ObjectPath
	routingAll     bool
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

func newSystemdDbusConfigurator(wgInterface string) (hostManager, error) {
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
	}, nil
}

func (s *systemdDbusConfigurator) supportCustomPort() bool {
	return true
}

func (s *systemdDbusConfigurator) applyDNSConfig(config HostDNSConfig) error {
	parsedIP, err := netip.ParseAddr(config.ServerIP)
	if err != nil {
		return fmt.Errorf("unable to parse ip address, error: %w", err)
	}
	ipAs4 := parsedIP.As4()
	defaultLinkInput := systemdDbusDNSInput{
		Family:  unix.AF_INET,
		Address: ipAs4[:],
	}
	err = s.callLinkMethod(systemdDbusSetDNSMethodSuffix, []systemdDbusDNSInput{defaultLinkInput})
	if err != nil {
		return fmt.Errorf("setting the interface DNS server %s:%d failed with error: %w", config.ServerIP, config.ServerPort, err)
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
			Domain:    dns.Fqdn(dConf.Domain),
			MatchOnly: dConf.MatchOnly,
		})

		if dConf.MatchOnly {
			matchDomains = append(matchDomains, dConf.Domain)
			continue
		}
		searchDomains = append(searchDomains, dConf.Domain)
	}

	if config.RouteAll {
		log.Infof("configured %s:%d as main DNS forwarder for this peer", config.ServerIP, config.ServerPort)
		err = s.callLinkMethod(systemdDbusSetDefaultRouteMethodSuffix, true)
		if err != nil {
			return fmt.Errorf("setting link as default dns router, failed with error: %w", err)
		}
		domainsInput = append(domainsInput, systemdDbusLinkDomainsInput{
			Domain:    nbdns.RootZone,
			MatchOnly: true,
		})
		s.routingAll = true
	} else if s.routingAll {
		log.Infof("removing %s:%d as main DNS forwarder for this peer", config.ServerIP, config.ServerPort)
	}

	// create a backup for unclean shutdown detection before adding domains, as these might end up in the resolv.conf file.
	// The file content itself is not important for systemd restoration
	if err := createUncleanShutdownIndicator(defaultResolvConfPath, systemdManager, parsedIP.String()); err != nil {
		log.Errorf("failed to create unclean shutdown resolv.conf backup: %s", err)
	}

	log.Infof("adding %d search domains and %d match domains. Search list: %s , Match list: %s", len(searchDomains), len(matchDomains), searchDomains, matchDomains)
	err = s.setDomainsForInterface(domainsInput)
	if err != nil {
		log.Error(err)
	}
	return nil
}

func (s *systemdDbusConfigurator) setDomainsForInterface(domainsInput []systemdDbusLinkDomainsInput) error {
	err := s.callLinkMethod(systemdDbusSetDomainsMethodSuffix, domainsInput)
	if err != nil {
		return fmt.Errorf("setting domains configuration failed with error: %w", err)
	}
	return s.flushCaches()
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

	if err := removeUncleanShutdownIndicator(); err != nil {
		log.Errorf("failed to remove unclean shutdown resolv.conf backup: %s", err)
	}

	return s.flushCaches()
}

func (s *systemdDbusConfigurator) flushCaches() error {
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
