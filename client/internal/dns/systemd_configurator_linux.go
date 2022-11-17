package dns

import (
	"context"
	"fmt"
	"github.com/godbus/dbus/v5"
	"github.com/miekg/dns"
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
	systemdDbusLinkInterface               = "org.freedesktop.resolve1.Link"
	systemdDbusRevertMethodSuffix          = systemdDbusLinkInterface + ".Revert"
	systemdDbusSetDNSMethodSuffix          = systemdDbusLinkInterface + ".SetDNS"
	systemdDbusSetDefaultRouteMethodSuffix = systemdDbusLinkInterface + ".SetDefaultRoute"
	systemdDbusSetDomainsMethodSuffix      = systemdDbusLinkInterface + ".SetDomains"
)

type systemdDbusConfigurator struct {
	dbusLinkObject       dbus.ObjectPath
	createdLinkedDomains map[string]systemdDbusLinkDomainsInput
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

func newSystemdDbusConfigurator(wgInterface *iface.WGIface) hostManager {
	iface, err := net.InterfaceByName(wgInterface.GetName())
	if err != nil {
		// todo add proper error handling
		panic(err)
	}

	obj, closeConn, err := getDbusObject(systemdResolvedDest, systemdDbusObjectNode)
	if err != nil {
		// todo add proper error handling
		panic(err)
	}
	defer closeConn()
	var s string
	err = obj.Call(systemdDbusGetLinkMethod, dbusDefaultFlag, iface.Index).Store(&s)
	if err != nil {
		// todo add proper error handling
		panic(err)
	}

	log.Debugf("got dbus Link interface: %s from net interface %s and index %d", s, iface.Name, iface.Index)

	return &systemdDbusConfigurator{
		dbusLinkObject:       dbus.ObjectPath(s),
		createdLinkedDomains: make(map[string]systemdDbusLinkDomainsInput),
	}
}

func (s *systemdDbusConfigurator) applyDNSSettings(domains []string, ip string, port int) error {
	parsedIP := netip.MustParseAddr(ip).As4()
	defaultLinkInput := systemdDbusDNSInput{
		Family:  unix.AF_INET,
		Address: parsedIP[:],
	}
	err := s.callLinkMethod(systemdDbusSetDNSMethodSuffix, []systemdDbusDNSInput{defaultLinkInput})
	if err != nil {
		return fmt.Errorf("setting the interface DNS server %s:%d failed with error: %s", ip, port, err)
	}

	var domainsInput []systemdDbusLinkDomainsInput

	for _, domain := range domains {
		if isRootZoneDomain(domain) {
			err = s.callLinkMethod(systemdDbusSetDefaultRouteMethodSuffix, true)
			if err != nil {
				log.Errorf("setting link as default dns router, failed with error: %s", err)
			}
		}
		domainsInput = append(domainsInput, systemdDbusLinkDomainsInput{
			Domain:    dns.Fqdn(domain),
			MatchOnly: true,
		})
	}
	err = s.addDNSStateForDomain(domainsInput)
	if err != nil {
		log.Error(err)
	}
	return nil
}

func (s *systemdDbusConfigurator) addDNSStateForDomain(domainsInput []systemdDbusLinkDomainsInput) error {
	err := s.callLinkMethod(systemdDbusSetDomainsMethodSuffix, domainsInput)
	if err != nil {
		return fmt.Errorf("setting domains configuration failed with error: %s", err)
	}
	for _, input := range domainsInput {
		s.createdLinkedDomains[input.Domain] = input
	}
	return nil
}

func (s *systemdDbusConfigurator) addSearchDomain(domain string, ip string, port int) error {
	var newDomainsInput []systemdDbusLinkDomainsInput

	fqdnDomain := dns.Fqdn(domain)

	existingDomain, found := s.createdLinkedDomains[fqdnDomain]
	if found && !existingDomain.MatchOnly {
		return nil
	}

	delete(s.createdLinkedDomains, fqdnDomain)
	for _, existingInput := range s.createdLinkedDomains {
		newDomainsInput = append(newDomainsInput, existingInput)
	}

	newDomainsInput = append(newDomainsInput, systemdDbusLinkDomainsInput{
		Domain:    fqdnDomain,
		MatchOnly: false,
	})

	err := s.addDNSStateForDomain(newDomainsInput)
	if err != nil {
		return fmt.Errorf("setting domains configuration with search domain %s failed with error: %s", domain, err)
	}

	return s.flushCaches()
}
func (s *systemdDbusConfigurator) removeDomainSettings(domains []string) error {
	var err error
	for _, domain := range domains {
		if isRootZoneDomain(domain) {
			err = s.callLinkMethod(systemdDbusSetDefaultRouteMethodSuffix, false)
			if err != nil {
				log.Errorf("setting link as non default dns router, failed with error: %s", err)
			}
			break
		}
	}

	// cleaning the configuration as it gets rebuild
	emptyList := make([]systemdDbusLinkDomainsInput, 0)

	err = s.callLinkMethod(systemdDbusSetDomainsMethodSuffix, emptyList)
	if err != nil {
		log.Error(err)
	}

	s.createdLinkedDomains = make(map[string]systemdDbusLinkDomainsInput)

	return s.flushCaches()
}
func (s *systemdDbusConfigurator) removeDNSSettings() error {
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

	err = obj.CallWithContext(ctx, method, dbusDefaultFlag, value).Store()
	if err != nil {
		return fmt.Errorf("got error while calling command with context, err: %s", err)
	}

	return nil
}
