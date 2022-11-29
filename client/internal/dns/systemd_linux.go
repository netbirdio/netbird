package dns

import (
	"context"
	"fmt"
	"github.com/godbus/dbus/v5"
	"github.com/miekg/dns"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/iface"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"time"
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

func newSystemdDbusConfigurator(wgInterface *iface.WGIface) (hostManager, error) {
	iface, err := net.InterfaceByName(wgInterface.GetName())
	if err != nil {
		return nil, err
	}

	obj, closeConn, err := getDbusObject(systemdResolvedDest, systemdDbusObjectNode)
	if err != nil {
		return nil, err
	}
	defer closeConn()

	var s string
	err = obj.Call(systemdDbusGetLinkMethod, dbusDefaultFlag, iface.Index).Store(&s)
	if err != nil {
		return nil, err
	}

	log.Debugf("got dbus Link interface: %s from net interface %s and index %d", s, iface.Name, iface.Index)

	return &systemdDbusConfigurator{
		dbusLinkObject: dbus.ObjectPath(s),
	}, nil
}

func (s *systemdDbusConfigurator) applyDNSConfig(config hostDNSConfig) error {
	parsedIP := netip.MustParseAddr(config.serverIP).As4()
	defaultLinkInput := systemdDbusDNSInput{
		Family:  unix.AF_INET,
		Address: parsedIP[:],
	}
	err := s.callLinkMethod(systemdDbusSetDNSMethodSuffix, []systemdDbusDNSInput{defaultLinkInput})
	if err != nil {
		return fmt.Errorf("setting the interface DNS server %s:%d failed with error: %s", config.serverIP, config.serverPort, err)
	}

	var (
		searchDomains []string
		matchDomains  []string
		domainsInput  []systemdDbusLinkDomainsInput
	)
	for _, dConf := range config.domains {
		domainsInput = append(domainsInput, systemdDbusLinkDomainsInput{
			Domain:    dns.Fqdn(dConf.domain),
			MatchOnly: dConf.matchOnly,
		})

		if dConf.matchOnly {
			matchDomains = append(matchDomains, dConf.domain)
			continue
		}
		searchDomains = append(searchDomains, dConf.domain)
	}

	if config.routeAll {
		log.Infof("configured %s:%d as main DNS forwarder for this peer", config.serverIP, config.serverPort)
		err = s.callLinkMethod(systemdDbusSetDefaultRouteMethodSuffix, true)
		if err != nil {
			return fmt.Errorf("setting link as default dns router, failed with error: %s", err)
		}
		domainsInput = append(domainsInput, systemdDbusLinkDomainsInput{
			Domain:    nbdns.RootZone,
			MatchOnly: true,
		})
		s.routingAll = true
	} else if s.routingAll {
		log.Infof("removing %s:%d as main DNS forwarder for this peer", config.serverIP, config.serverPort)
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
		return fmt.Errorf("setting domains configuration failed with error: %s", err)
	}
	return s.flushCaches()
}

func (s *systemdDbusConfigurator) restoreHostDNS() error {
	log.Infof("reverting link settings and flushing cache")
	if !isDbusListenerRunning(systemdResolvedDest, s.dbusLinkObject) {
		return nil
	}
	err := s.callLinkMethod(systemdDbusRevertMethodSuffix, nil)
	if err != nil {
		return fmt.Errorf("unable to revert link configuration, got error: %s", err)
	}
	return s.flushCaches()
}

func (s *systemdDbusConfigurator) flushCaches() error {
	obj, closeConn, err := getDbusObject(systemdResolvedDest, systemdDbusObjectNode)
	if err != nil {
		return fmt.Errorf("got error while attempting to retrieve the object %s, err: %s", systemdDbusObjectNode, err)
	}
	defer closeConn()
	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	err = obj.CallWithContext(ctx, systemdDbusFlushCachesMethod, dbusDefaultFlag).Store()
	if err != nil {
		return fmt.Errorf("got error while calling the FlushCaches method with context, err: %s", err)
	}

	return nil
}

func (s *systemdDbusConfigurator) callLinkMethod(method string, value any) error {
	obj, closeConn, err := getDbusObject(systemdResolvedDest, s.dbusLinkObject)
	if err != nil {
		return fmt.Errorf("got error while attempting to retrieve the object, err: %s", err)
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
		return fmt.Errorf("got error while calling command with context, err: %s", err)
	}

	return nil
}

func getSystemdDbusProperty(property string, store any) error {
	obj, closeConn, err := getDbusObject(systemdResolvedDest, systemdDbusObjectNode)
	if err != nil {
		return fmt.Errorf("got error while attempting to retrieve the systemd dns manager object, error: %s", err)
	}
	defer closeConn()

	v, e := obj.GetProperty(property)
	if e != nil {
		return fmt.Errorf("got an error getting property %s: %v", property, e)
	}

	return v.Store(store)
}
